package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/emit"
)

// The backendTLS block of a processor entry, read and compared by the canary
// (limit L11, D19): agentgateway v1.6.0 dials the processor with TLS when the
// entry carries processors[].policies.backendTLS. The reader was pinned before
// internal/emit wrote the block, so these tests still hand-build the emitted
// block and the live JSON in the shape the v1.6.0 schema documents (`policies:
// backendTLS: {}` under a `host:` processor), and TestEmittedConfigReadsWhatEmitWrites
// reads the block emit writes since D19; end-to-end scenario Q compares the
// real emitted block with what the running gateway renders in GET /api/config
// and records the rendering in docs/decisions.md D19.

// The four backendTLS values the tests write on both sides: paths on the
// gateway host and the name the processor's certificate is verified against.
const (
	tlsCertPath = "/etc/toolwarrant/gateway.pem"
	tlsKeyPath  = "/etc/toolwarrant/gateway-key.pem"
	tlsRootPath = "/etc/toolwarrant/processor-ca.pem"
	tlsHostname = "toolwarrant-processor"
)

// tlsBlock is the backendTLS block as emit will write it under a processor
// entry: policies at indent 8, backendTLS at indent 10, the four fields at
// indent 12, every value double-quoted as emit's quote writes plain ASCII.
func tlsBlock(cert, key, root, hostname string) string {
	return "        policies:\n          backendTLS:\n" +
		"            cert: " + strconv.Quote(cert) + "\n" +
		"            key: " + strconv.Quote(key) + "\n" +
		"            root: " + strconv.Quote(root) + "\n" +
		"            hostname: " + strconv.Quote(hostname) + "\n"
}

// liveTLS is the backendTLS object as the admin API would render it, with
// extra (", key: value" pairs, or "") appended inside the object.
func liveTLS(t *testing.T, cert, key, root, hostname, extra string) string {
	t.Helper()
	return `{"cert": ` + jsonString(t, cert) + `, "key": ` + jsonString(t, key) + `, "root": ` + jsonString(t, root) + `, "hostname": ` + jsonString(t, hostname) + extra + `}`
}

// jsonString encodes s as a JSON string, so a hostile value survives the trip
// through the live document.
func jsonString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// withProcessorTLS inserts block into the one processor entry of the emitted
// file at cfg, where emit will write it (after the requestHeaders filter,
// before metadata and methods), and reseals the header so that the file still
// passes emit.Verify: the canary compares only a file whose body matches its
// header, and the header is unkeyed by design (limit L19).
func withProcessorTLS(t *testing.T, cfg, block string) {
	t.Helper()
	file := readFile(t, cfg)
	anchor := "        metadata:\n"
	if !strings.Contains(file, anchor) {
		anchor = "        methods:\n"
	}
	if strings.Count(file, anchor) != 1 {
		t.Fatalf("the emitted file does not hold exactly one %q:\n%s", anchor, file)
	}
	sealed := reseal(t, strings.Replace(file, anchor, block+anchor, 1))
	if _, ok := emit.Verify([]byte(sealed)); !ok {
		t.Fatal("the resealed file does not pass emit.Verify")
	}
	if err := os.WriteFile(cfg, []byte(sealed), 0o600); err != nil {
		t.Fatal(err)
	}
}

// policiesDoc is the fixture's live document with a policies object inserted
// into the processor entry before its requestHeaders filter.
func (c *cli) policiesDoc(upstreamURL, policies string) string {
	c.t.Helper()
	return c.adminDoc(upstreamURL, `"requestHeaders": {`, `"policies": `+policies+`, "requestHeaders": {`)
}

// Limit L11: the backendTLS block under a processor's policies is read from
// the emitted file and from the live document and compared field by field,
// so a live entry that lost the block (the link is plaintext again), gained
// one the file does not carry, or trusts another root or name is
// LIVE-CONFIG-MISMATCH, while the same block on both sides is a match. The
// values are paths on the gateway host and a name, not secrets, so the lines
// show them, escaped.
func TestLiveComparisonComparesTheProcessorTLS(t *testing.T) {
	c, u, gw, cfg := liveFixture(t)
	withProcessorTLS(t, cfg, tlsBlock(tlsCertPath, tlsKeyPath, tlsRootPath, tlsHostname))
	wantContains(t, "emitted file", readFile(t, cfg), "        policies:\n          backendTLS:\n", `hostname: "`+tlsHostname+`"`)
	same := `{"backendTLS": ` + liveTLS(t, tlsCertPath, tlsKeyPath, tlsRootPath, tlsHostname, "") + `}`
	healthy := c.live.admin.serve(http.StatusOK, c.policiesDoc(u.url(), same))
	wantContains(t, "healthy", c.ok("verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", healthy.hostPort(), "--no-probe"), verdictOK+": ", "live configuration matches the emitted file")

	const missing = "processor backendTLS: the live processor has none while the emitted file carries it; the gateway dials this processor without TLS"
	cases := map[string]struct {
		policies string
		want     []string
	}{
		"live has none": {"", []string{missing}},
		"other root": {`{"backendTLS": ` + liveTLS(t, tlsCertPath, tlsKeyPath, "/tmp/ca.pem", tlsHostname, "") + `}`,
			[]string{"processor backendTLS root: emitted " + tlsRootPath + ", live /tmp/ca.pem"}},
		"other name": {`{"backendTLS": ` + liveTLS(t, tlsCertPath, tlsKeyPath, tlsRootPath, "other.example", "") + `}`,
			[]string{"processor backendTLS hostname: emitted " + tlsHostname + ", live other.example"}},
		"client certificate dropped": {`{"backendTLS": {"root": ` + jsonString(t, tlsRootPath) + `, "hostname": ` + jsonString(t, tlsHostname) + `}}`,
			[]string{"processor backendTLS cert: emitted " + tlsCertPath + ", live (none)", "processor backendTLS key: emitted " + tlsKeyPath + ", live (none)"}},
		"empty block": {`{"backendTLS": {}}`, []string{
			"processor backendTLS cert: emitted " + tlsCertPath + ", live (none)", "processor backendTLS key: emitted " + tlsKeyPath + ", live (none)",
			"processor backendTLS root: emitted " + tlsRootPath + ", live (none)", "processor backendTLS hostname: emitted " + tlsHostname + ", live (none)"}},
		"hostile name": {`{"backendTLS": ` + liveTLS(t, tlsCertPath, tlsKeyPath, tlsRootPath, tlsHostname+esc+"[31m", "") + `}`,
			[]string{`processor backendTLS hostname: emitted ` + tlsHostname + `, live ` + tlsHostname + `\u{001B}[31m`}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			doc := c.adminDoc(u.url())
			if tc.policies != "" {
				doc = c.policiesDoc(u.url(), tc.policies)
			}
			admin := c.live.admin.serve(http.StatusOK, doc)
			r := c.sub(t).fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", admin.hostPort(), "--no-probe")
			for _, want := range tc.want {
				wantContains(t, "stdout", r.stdout, verdictLiveConfig+" s1: "+want)
			}
			wantNotContains(t, "stdout", r.stdout, verdictOK, esc)
			wantContains(t, "stderr", r.stderr, "differs from the emitted file in "+strconv.Itoa(len(tc.want))+" place(s)")
		})
	}

	// The other direction: a file without the block against a live entry
	// that carries one.
	c.liveEmit(cfg)
	admin := c.live.admin.serve(http.StatusOK, c.policiesDoc(u.url(), same))
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", admin.hostPort(), "--no-probe")
	wantContains(t, "stdout", r.stdout, verdictLiveConfig+" s1: processor backendTLS: the live processor carries backendTLS the emitted file does not")
	wantNotContains(t, "stdout", r.stdout, verdictOK)
	wantContains(t, "stderr", r.stderr, "differs from the emitted file in 1 place(s)")
}

// The block's other fields (insecure, insecureHost, alpn, subjectAltNames,
// keyExchangeGroups, spiffe) and the other policies the v1.6.0 schema accepts
// beside backendTLS (requestHeaderModifier, transformations, backendAuth) are
// nothing emit writes: a live entry carrying one is one LIVE-CONFIG-MISMATCH
// line naming it, with the key escaped and the value never shown. insecure
// turns certificate verification off, backendAuth sends a credential to the
// processor and transformations rewrite the hook, so each is a change to the
// link the comparison must not call a match.
func TestLiveComparisonReportsAnInsecureTLSFlag(t *testing.T) {
	c, u, gw, cfg := liveFixture(t)
	withProcessorTLS(t, cfg, tlsBlock(tlsCertPath, tlsKeyPath, tlsRootPath, tlsHostname))
	inside := func(extra string) string {
		return `{"backendTLS": ` + liveTLS(t, tlsCertPath, tlsKeyPath, tlsRootPath, tlsHostname, extra) + `}`
	}
	beside := func(policy string) string {
		return `{"backendTLS": ` + liveTLS(t, tlsCertPath, tlsKeyPath, tlsRootPath, tlsHostname, "") + `, ` + policy + `}`
	}
	const linkNote = "; the gateway applies it to the link to this processor"
	cases := map[string]struct {
		policies, want string
	}{
		"insecure":              {inside(`, "insecure": true`), "processor 1: backendTLS field insecure: not in the emitted file"},
		"insecureHost":          {inside(`, "insecureHost": true`), "processor 1: backendTLS field insecureHost: not in the emitted file"},
		"alpn":                  {inside(`, "alpn": ["h2"]`), "processor 1: backendTLS field alpn: not in the emitted file"},
		"subjectAltNames":       {inside(`, "subjectAltNames": ["spiffe://td/ns/x/sa/y"]`), "processor 1: backendTLS field subjectAltNames: not in the emitted file"},
		"keyExchangeGroups":     {inside(`, "keyExchangeGroups": ["X25519"]`), "processor 1: backendTLS field keyExchangeGroups: not in the emitted file"},
		"spiffe":                {inside(`, "spiffe": {}`), "processor 1: backendTLS field spiffe: not in the emitted file"},
		"escaped key":           {inside(`, "ins\u001bsecure": true`), `processor 1: backendTLS field ins\u{001B}secure: not in the emitted file`},
		"requestHeaderModifier": {beside(`"requestHeaderModifier": {"set": {"x-tenant": "evil"}}`), "processor 1: policy requestHeaderModifier: not in the emitted file" + linkNote},
		"transformations":       {beside(`"transformations": {"request": {"body": "\"x\""}}`), "processor 1: policy transformations: not in the emitted file" + linkNote},
		"backendAuth":           {beside(`"backendAuth": {"key": {"file": "/etc/toolwarrant/token"}}`), "processor 1: policy backendAuth: not in the emitted file" + linkNote},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			admin := c.live.admin.serve(http.StatusOK, c.policiesDoc(u.url(), tc.policies))
			r := c.sub(t).fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", admin.hostPort(), "--no-probe")
			wantContains(t, "stdout", r.stdout, verdictLiveConfig+" s1: "+tc.want)
			wantNotContains(t, "stdout", r.stdout, verdictOK, esc, "evil", "/etc/toolwarrant/token")
			wantContains(t, "stderr", r.stderr, "differs from the emitted file in 1 place(s)")
		})
	}
}
