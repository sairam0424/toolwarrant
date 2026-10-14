//go:build e2e

package e2e

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/testcert"
)

// The certificate material and the live-document helpers of scenario Q (TLS
// and client certificates on the processor link, D19, limit L11). Every key
// and certificate is made by internal/testcert when the scenario runs and
// written owner-only under the work directory; nothing is in the tree.
const (
	// tlsDirName is the directory under the work directory that holds the
	// material; tlsDirMode keeps it owner-only, as the files are.
	tlsDirName             = "tls"
	tlsDirMode os.FileMode = 0o700
	// garbageRootName is a file that holds no certificate, named as the root
	// of a block: the pinned binary's --validate-only accepts it (emit
	// TestGatewayValidateOnlyOpensBackendTLSFiles), so only the handshake can
	// refuse it.
	garbageRootName = "garbage.pem"
	// tlsBlockField is the processor policy the block lives in, as both the
	// emitted file and the live document spell it.
	tlsBlockField = "backendTLS"
	// privateKeyMarker is the PEM label every private key testcert writes
	// carries; a live document that holds it inlined a key (limit L18 would
	// widen), so the answer is searched for it and never printed.
	privateKeyMarker = "PRIVATE KEY"
)

// tlsLab is the material of scenario Q: one authority signs the processor's
// server certificate (the gateway's root), another signs the gateway's client
// certificate (the processor's --tls-client-ca), a third signed nothing either
// side presents, and one file is not a certificate at all.
type tlsLab struct {
	// procCert and procKey are the processor's certificate and key (serve
	// --tls-cert, --tls-key), with the DNS name testcert.ServerName.
	procCert, procKey string
	// clientCA is the authority of the gateway's client certificate (serve
	// --tls-client-ca); otherCA signed nothing the gateway presents.
	clientCA, otherCA string
	// gwCert and gwKey are the gateway's client certificate and key (the
	// block's cert and key); root is the authority of the processor's
	// certificate (the block's root); garbageRoot holds no certificate.
	gwCert, gwKey, root, garbageRoot string
}

// newTLSLab writes the material under workdir/tls.
func newTLSLab(t *testing.T, s *stack) tlsLab {
	t.Helper()
	dir := filepath.Join(s.h.workdir, tlsDirName)
	if err := os.Mkdir(dir, tlsDirMode); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	procCA := testcert.NewAuthority(t, "toolwarrant e2e processor ca")
	gwCA := testcert.NewAuthority(t, "toolwarrant e2e gateway ca")
	otherCA := testcert.NewAuthority(t, "toolwarrant e2e other ca")
	lab := tlsLab{garbageRoot: filepath.Join(dir, garbageRootName)}
	lab.procCert, lab.procKey = procCA.Server(t).Write(t, dir, "processor")
	lab.root = procCA.Write(t, dir, "processor-ca")
	lab.gwCert, lab.gwKey = gwCA.Client(t, "agentgateway").Write(t, dir, "gateway")
	lab.clientCA = gwCA.Write(t, dir, "gateway-ca")
	lab.otherCA = otherCA.Write(t, dir, "other-ca")
	if err := os.WriteFile(lab.garbageRoot, []byte("not a certificate\n"), testcert.FileMode); err != nil {
		t.Fatalf("write %s: %v", lab.garbageRoot, err)
	}
	return lab
}

// spec is the --processor-tls value for mock with the given root.
func (l tlsLab) spec(root string) string {
	return "mock=cert=" + l.gwCert + ",key=" + l.gwKey + ",root=" + root + ",hostname=" + testcert.ServerName
}

// serveFlags are the three serve flags with the given client authority.
func (l tlsLab) serveFlags(clientCA string) []string {
	return []string{"--tls-cert", l.procCert, "--tls-key", l.procKey, "--tls-client-ca", clientCA}
}

// emittedValues are the four values the block carries, by field, for the
// comparison with what the admin API renders.
func (l tlsLab) emittedValues() map[string]string {
	return map[string]string{"cert": l.gwCert, "key": l.gwKey, "root": l.root, "hostname": testcert.ServerName}
}

// liveProcessorTLS returns the backendTLS object of the first processor of the
// route of server in a live document, decoded generically.
func liveProcessorTLS(doc []byte, server string) (map[string]any, error) {
	_, routes, err := liveRoutes(doc)
	if err != nil {
		return nil, err
	}
	processors, err := liveProcessors(routes, server)
	if err != nil {
		return nil, err
	}
	if len(processors) == 0 {
		return nil, fmt.Errorf("the live route %s carries no processor", server)
	}
	first, _ := processors[0].(map[string]any)
	policies, _ := first[policiesKey].(map[string]any)
	block, ok := policies[tlsBlockField].(map[string]any)
	if !ok {
		return nil, errors.New("the live processor of route " + server + " renders no " + tlsBlockField + " object under " + policiesKey)
	}
	return block, nil
}

// withTLSField returns a live document with one field set inside the
// backendTLS block of the first processor of the route of server; every other
// field goes back as the gateway reported it.
func withTLSField(doc []byte, server, key string, value any) ([]byte, error) {
	cfg, routes, err := liveRoutes(doc)
	if err != nil {
		return nil, err
	}
	processors, err := liveProcessors(routes, server)
	if err != nil {
		return nil, err
	}
	if len(processors) == 0 {
		return nil, fmt.Errorf("the live route %s carries no processor", server)
	}
	first, _ := processors[0].(map[string]any)
	policies, _ := first[policiesKey].(map[string]any)
	block, ok := policies[tlsBlockField].(map[string]any)
	if !ok {
		return nil, errors.New("the live processor of route " + server + " renders no " + tlsBlockField + " object to edit")
	}
	block[key] = value
	return json.Marshal(cfg)
}

// awaitLiveTLSField polls the admin API until the backendTLS block of the
// route of server does (want true) or does not (want false) carry key, and
// reports whether that happened within the reload wait.
func (s *stack) awaitLiveTLSField(t *testing.T, server, key string, want bool) bool {
	t.Helper()
	return pollUntil(reloadWait, func() bool {
		block, err := liveProcessorTLS(s.liveConfig(t), server)
		if err != nil {
			return false
		}
		_, has := block[key]
		return has == want
	})
}

// describeRendered says what the admin API rendered for one field without
// printing it: the emitted value, a string holding a PEM private key, another
// string of a given size, or something that is not a string.
func describeRendered(v any, want string) string {
	str, ok := v.(string)
	switch {
	case !ok:
		return fmt.Sprintf("a %T value", v)
	case str == want:
		return "the emitted value"
	case strings.Contains(str, privateKeyMarker):
		return fmt.Sprintf("a %d-byte string holding a PEM private key", len(str))
	}
	return fmt.Sprintf("a %d-byte string that is not the emitted value", len(str))
}

// describeLiveTLS renders the keys of a live backendTLS block and, for each,
// what describeRendered says against the emitted values.
func describeLiveTLS(block map[string]any, emitted map[string]string) (keys []string, fields string) {
	for k := range block {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+": "+describeRendered(block[k], emitted[k]))
	}
	return keys, strings.Join(parts, "; ")
}
