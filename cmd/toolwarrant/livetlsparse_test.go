package main

import (
	"encoding/json"
	"maps"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/emit"
)

// The emitted-file reader is pinned to the backendTLS block as emit will write
// it (policies at indent 8, backendTLS at indent 10, four quoted fields at
// indent 12, between the requestHeaders filter and the metadata): the block is
// read into the processor's tls map, a processor without it keeps a nil map,
// the metadata after the block is still hashed and the methods still read, a
// policy beside backendTLS that emit never writes is not taken for TLS
// fields, and a value emit could not have written (an unquoted scalar, the
// schema's insecure: true, a list, a second block) is refused rather than
// guessed at. The live side reads the same four fields from
// policies.backendTLS and keeps the map nil for an absent, null or empty
// policies object and for a null block.
func TestEmittedConfigReadsTheProcessorTLS(t *testing.T) {
	t.Parallel()
	secret := plant("shared")
	out, err := emit.AgentGateway(emit.Input{ListenPort: 8080, Servers: []emit.Server{
		{Name: "alpha", URL: "http://127.0.0.1:3001/mcp", ProcessorAddr: "127.0.0.1:9001", Secret: secret, ApprovedTools: []string{"a"}},
		{Name: "beta", URL: "http://127.0.0.1:3002/mcp", ProcessorAddr: "127.0.0.1:9002", Secret: secret, ApprovedTools: []string{"b"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	file := string(out.YAML)
	const metadata = "        metadata:\n"
	if strings.Count(file, metadata) != 2 {
		t.Fatalf("the emitted file does not hold two metadata blocks:\n%s", file)
	}
	want := map[string]string{keyTLSCert: tlsCertPath, keyTLSKey: tlsKeyPath, keyTLSRoot: tlsRootPath, keyTLSHostname: tlsHostname}
	// Only the first entry, alpha's, gets the block.
	doc, err := emittedConfig([]byte(strings.Replace(file, metadata, tlsBlock(tlsCertPath, tlsKeyPath, tlsRootPath, tlsHostname)+metadata, 1)))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := emittedConfig(out.YAML)
	if err != nil {
		t.Fatal(err)
	}
	a, b, pa := firstProcessor(t, doc, "alpha"), firstProcessor(t, doc, "beta"), firstProcessor(t, plain, "alpha")
	if !maps.Equal(a.tls, want) {
		t.Errorf("alpha tls %q, want %q", a.tls, want)
	}
	if b.tls != nil || pa.tls != nil {
		t.Errorf("an entry without the block carries one: beta %q, plain alpha %q", b.tls, pa.tls)
	}
	if a.metadataHash == "" || a.metadataHash != pa.metadataHash || describeMethods(a.methods) != describeMethods(pa.methods) ||
		describeList(a.disallowed) != describeList(pa.disallowed) || describeList(a.allowed) != describeList(pa.allowed) || a.host != pa.host {
		t.Errorf("the block changed the rest of the entry:\nwith    %+v\nwithout %+v", a, pa)
	}
	for k, v := range a.tls {
		if strings.Contains(k, canary) || strings.Contains(v, canary) {
			t.Errorf("the shared secret was read into the tls block: %q=%q", k, v)
		}
	}
	emittedTLSShapes(t, file, metadata, want)
	liveTLSShapes(t, want)
}

// firstProcessor is the one processor of the named route.
func firstProcessor(t *testing.T, doc configDoc, route string) processorConfig {
	t.Helper()
	rc, n := doc.route(route)
	if n != 1 || len(rc.processors) != 1 {
		t.Fatalf("route %s: %d route(s), processors %+v", route, n, rc.processors)
	}
	return rc.processors[0]
}

// emittedTLSShapes runs the block's shapes through the reader: accepted ones
// with the map they yield, refused ones with the error they name.
func emittedTLSShapes(t *testing.T, file, anchor string, want map[string]string) {
	t.Helper()
	block := tlsBlock(tlsCertPath, tlsKeyPath, tlsRootPath, tlsHostname)
	const other = "          requestHeaderModifier:\n            set:\n              x-tenant: \"evil\"\n"
	cases := map[string]struct {
		block   string
		wantTLS map[string]string
		wantErr string
	}{
		"policies without backendTLS": {"        policies:\n" + other, nil, ""},
		"policy beside the block":     {block + other, want, ""},
		"policy before the block":     {"        policies:\n" + other + "          backendTLS:\n            hostname: \"h\"\n", map[string]string{keyTLSHostname: "h"}, ""},
		"empty block":                 {"        policies:\n          backendTLS:\n", map[string]string{}, ""},
		"escaped hostname":            {"        policies:\n          backendTLS:\n            hostname: \"h\\u001b\"\n", map[string]string{keyTLSHostname: "h" + esc}, ""},
		"unquoted path":               {"        policies:\n          backendTLS:\n            cert: /etc/x\n", nil, "unquoted scalar"},
		"insecure flag":               {block + "            insecure: true\n", nil, "unquoted scalar"},
		"alpn list":                   {block + "            alpn:\n            - \"h2\"\n", nil, "unquoted scalar"},
		"block twice":                 {block + "          backendTLS:\n", nil, "lists backendTLS twice for processor 127.0.0.1:9001"},
	}
	for name, tc := range cases {
		doc, err := emittedConfig([]byte(strings.Replace(file, anchor, tc.block+anchor, 1)))
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: error %v, want one naming %q", name, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		got := firstProcessor(t, doc, "alpha").tls
		if (got == nil) != (tc.wantTLS == nil) || !maps.Equal(got, tc.wantTLS) {
			t.Errorf("%s: tls %q (nil %v), want %q (nil %v)", name, got, got == nil, tc.wantTLS, tc.wantTLS == nil)
		}
		if beta := firstProcessor(t, doc, "beta"); beta.tls != nil {
			t.Errorf("%s: the block leaked into the next entry: %q", name, beta.tls)
		}
	}
}

// liveTLSShapes decodes one live processor entry per shape of its policies
// and checks the map the comparison gets.
func liveTLSShapes(t *testing.T, want map[string]string) {
	t.Helper()
	empty := map[string]string{keyTLSCert: "", keyTLSKey: "", keyTLSRoot: "", keyTLSHostname: ""}
	cases := map[string]struct {
		doc  string
		want map[string]string
	}{
		"absent":         {`{"host": "h"}`, nil},
		"null policies":  {`{"policies": null}`, nil},
		"empty policies": {`{"policies": {}}`, nil},
		"null block":     {`{"policies": {"backendTLS": null}}`, nil},
		"empty block":    {`{"policies": {"backendTLS": {}}}`, empty},
		"partial block":  {`{"policies": {"backendTLS": {"root": "/r", "hostname": "h"}}}`, map[string]string{keyTLSCert: "", keyTLSKey: "", keyTLSRoot: "/r", keyTLSHostname: "h"}},
		"full block":     {`{"policies": {"backendTLS": ` + liveTLS(t, tlsCertPath, tlsKeyPath, tlsRootPath, tlsHostname, `, "insecure": true`) + `}}`, want},
	}
	for name, tc := range cases {
		var p liveProcessorDoc
		if err := json.Unmarshal([]byte(tc.doc), &p); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := p.config().tls
		if (got == nil) != (tc.want == nil) || !maps.Equal(got, tc.want) {
			t.Errorf("%s: tls %q (nil %v), want %q (nil %v)", name, got, got == nil, tc.want, tc.want == nil)
		}
	}
	// A policies value that is not an object cannot be the pinned shape: the
	// whole document is refused, never read around.
	live := `{"routes": [{"name": "s1", "policies": {"mcpGuardrails": {"processors": [{"host": "h", "policies": "x"}]}}}]}`
	if _, err := decodeLiveConfig([]byte(live)); err == nil || !strings.Contains(err.Error(), "not the configuration JSON") {
		t.Errorf("policies as a scalar: %v", err)
	}
}

// Unit view of the comparison: a live processor identical in host, kind,
// failureMode, methods, filter and metadata but without the backendTLS block
// differs from the emitted one in exactly one line, and so does one that
// gained a block the file does not carry; an empty block differs from no block
// in that one line and from a full block in four; equal blocks differ in
// nothing; differing fields are one line each, in file order, with both values
// shown and escaped. The shape walk accepts the four fields and reports a
// block that is not an object as a whole.
func TestCompareProcessorsSeesAMissingBackendTLS(t *testing.T) {
	t.Parallel()
	with := processorConfig{host: "127.0.0.1:9001", kind: "remote", failureMode: "failClosed", methods: map[string]string{"tools/list": "response"},
		allowed: []string{":method"}, metadataHash: "abc", tls: map[string]string{keyTLSCert: tlsCertPath, keyTLSKey: tlsKeyPath, keyTLSRoot: tlsRootPath, keyTLSHostname: tlsHostname}}
	without, empty := with, with
	without.tls, empty.tls = nil, map[string]string{}
	other := with
	other.tls = map[string]string{keyTLSCert: tlsCertPath, keyTLSKey: tlsKeyPath, keyTLSRoot: "/tmp/ca.pem", keyTLSHostname: tlsHostname + esc}
	check := func(name string, emitted, live processorConfig, want ...string) {
		t.Helper()
		got := compareProcessors([]processorConfig{emitted}, []processorConfig{live})
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s:\n%s\nwant:\n%s", name, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
		wantNotContains(t, name, strings.Join(got, "\n"), esc)
	}
	none := func(k, emitted string) string { return tlsFieldPrefix + k + ": emitted " + emitted + ", live (none)" }
	check("equal blocks", with, with)
	check("neither side has one", without, without)
	check("live has none", with, without, tlsLiveMissing)
	check("live gained one", without, with, tlsLiveExtra)
	check("empty against none", empty, without, tlsLiveMissing)
	check("none against empty", without, empty, tlsLiveExtra)
	check("empty live block", with, empty, none(keyTLSCert, tlsCertPath), none(keyTLSKey, tlsKeyPath), none(keyTLSRoot, tlsRootPath), none(keyTLSHostname, tlsHostname))
	check("other root, hostile name", with, other,
		tlsFieldPrefix+"root: emitted "+tlsRootPath+", live /tmp/ca.pem",
		tlsFieldPrefix+`hostname: emitted `+tlsHostname+`, live `+tlsHostname+`\u{001B}`)
	check("hostile emitted side", other, with,
		tlsFieldPrefix+"root: emitted /tmp/ca.pem, live "+tlsRootPath,
		tlsFieldPrefix+`hostname: emitted `+tlsHostname+`\u{001B}, live `+tlsHostname)
	if diffs := compareProcessorTLS(nil, nil); diffs != nil {
		t.Errorf("compareProcessorTLS(nil, nil) = %q", diffs)
	}
	shape := processorShape()
	full := `{"policies": {"backendTLS": ` + liveTLS(t, tlsCertPath, tlsKeyPath, tlsRootPath, tlsHostname, "") + `}}`
	if lines := shape.foreign(json.RawMessage(full), "processor 1: "); len(lines) != 0 {
		t.Errorf("the four fields are foreign to the shape: %q", lines)
	}
	cases := map[string]string{
		`{"policies": {"backendTLS": "x"}}`:                              "processor 1: backendTLS not an object as in the emitted file",
		`{"policies": {"backendTLS": {"insecureHost": true}}}`:           "processor 1: backendTLS field insecureHost: not in the emitted file",
		`{"policies": {"backendAuth": {"key": {"file": "/etc/token"}}}}`: "processor 1: policy backendAuth: not in the emitted file" + foreignLinkPolicyNote,
	}
	for doc, want := range cases {
		if got := strings.Join(shape.foreign(json.RawMessage(doc), "processor 1: "), "\n"); got != want {
			t.Errorf("%s: %q, want %q", doc, got, want)
		}
	}
}
