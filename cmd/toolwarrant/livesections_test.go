package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/emit"
)

// bindsSection is a deprecated-form listener on its own port with a route to
// the fixture's upstream that carries no processor and allows every tool name,
// as the gateway's own JSON would render it. agentgateway v1.6.0 reads
// fourteen top-level sections; the emitted file carries three.
func bindsSection(upstreamURL string) string {
	return `"binds": [{"port": 3005, "listeners": [{"name": "open", "routes": [{"name": "s1-open",` +
		` "policies": {"mcpAuthorization": {"rules": [{"allow": "true"}]}},` +
		` "backends": [{"mcp": {"targets": [{"name": "s1", "mcp": {"host": "` + upstreamURL + `"}}]}}]}]}]}],`
}

// Fourth review (cli-docs-1, D14 i): the comparison read the gateways map and
// the routes list of GET /api/config and nothing else, so a binds section with
// a processor-less allow-all listener on another port, or a top-level mcp
// shortcut, compared as a match with exit 0. Every non-empty section the file
// does not carry is now one LIVE-CONFIG-MISMATCH line; an empty or null one
// binds nothing and is not reported.
func TestLiveComparisonReportsASectionTheFileDoesNotCarry(t *testing.T) {
	t.Parallel()
	c, u, gw, cfg := liveFixture(t)
	const sectionLine = ": not in the emitted file; it may bind ports and routes the comparison cannot see"
	cases := map[string]struct {
		extra string
		want  []string
	}{
		"binds": {bindsSection(u.url()), []string{"section binds" + sectionLine}},
		"mcp":   {`"mcp": {"port": 3006, "targets": [{"name": "s1", "mcp": {"host": "` + u.url() + `"}}]},`, []string{"section mcp" + sectionLine}},
		"several": {`"binds": [{"port": 3005}], "policies": {"x": 1}, "tcpRoutes": [{"name": "t"}],`,
			[]string{"section binds" + sectionLine, "section policies" + sectionLine, "section tcpRoutes" + sectionLine}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			admin := c.live.admin.serve(http.StatusOK, c.adminDoc(u.url(), `"gateways": {`, tc.extra+` "gateways": {`))
			r := c.sub(t).fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", admin.hostPort(), "--no-probe")
			for _, want := range tc.want {
				wantContains(t, "stdout", r.stdout, verdictLiveConfig+" s1: "+want)
			}
			wantNotContains(t, "stdout", r.stdout, verdictOK, u.url())
			wantContains(t, "stderr", r.stderr, "differs from the emitted file in")
		})
	}
	admin := c.live.admin.serve(http.StatusOK, c.adminDoc(u.url(), `"gateways": {`, `"binds": [], "policies": {}, "llm": null, "gateways": {`))
	out := c.ok("verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", admin.hostPort(), "--no-probe")
	wantContains(t, "empty sections", out, verdictOK, "live configuration matches the emitted file")
}

// The config block is compared too (D14 i): a moved admin API, a stats
// listener gone (the gateway then binds its wildcard default) or a readiness
// probe elsewhere is a difference the routes never show.
func TestLiveComparisonComparesTheConfigListeners(t *testing.T) {
	t.Parallel()
	c, u, gw, cfg := liveFixture(t)
	cases := map[string]struct {
		old, repl, want string
	}{
		"admin moved":     {`"adminAddr": "` + c.live.admin.hostPort() + `"`, `"adminAddr": "0.0.0.0:15000"`, "config adminAddr: emitted " + c.live.admin.hostPort() + ", live 0.0.0.0:15000"},
		"stats gone":      {`"statsAddr": "127.0.0.1:15020",`, ``, "config statsAddr: emitted 127.0.0.1:15020, live (none)"},
		"readiness moved": {`"readinessAddr": "127.0.0.1:15021"`, `"readinessAddr": "[::]:15021"`, "config readinessAddr: emitted 127.0.0.1:15021, live [::]:15021"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			admin := c.live.admin.serve(http.StatusOK, c.adminDoc(u.url(), tc.old, tc.repl))
			r := c.sub(t).fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", admin.hostPort(), "--no-probe")
			wantContains(t, "stdout", r.stdout, verdictLiveConfig+" s1: "+tc.want)
			wantContains(t, "stderr", r.stderr, "differs from the emitted file in 1 place(s)")
		})
	}
	if diffs := compareListeners(listenerConfig{adminAddr: "off"}, listenerConfig{adminAddr: "off"}); len(diffs) != 0 {
		t.Errorf("equal listeners differ: %q", diffs)
	}
}

// Fourth review (cli-docs-4, processor-emit-7): every processor entry emit
// writes carries a requestHeaders filter so a client's credentials do not ride
// each hook to the processor (limit L11), and the comparison never read it, so
// a live entry with the filter removed compared as the same fields. The two
// lists are now compared, and the healthy fixture carries the block.
func TestLiveComparisonComparesTheRequestHeaderFilter(t *testing.T) {
	t.Parallel()
	c, u, gw, cfg := liveFixture(t)
	file := readFile(t, cfg)
	wantContains(t, "emitted file", file, "requestHeaders:", `"authorization"`, `"proxy-authorization"`)
	block := "\"requestHeaders\": {\n                \"allowed\": [\n                  \":method\"\n                ],\n                \"disallowed\": [\n                  \"authorization\",\n                  \"cookie\",\n                  \"proxy-authorization\"\n                ]\n              },"
	cases := map[string]struct {
		old, repl string
		want      []string
	}{
		"filter removed": {block, ``, []string{
			"processor requestHeaders allowed: emitted :method, live (none)",
			"processor requestHeaders disallowed: emitted authorization,cookie,proxy-authorization, live (none)"}},
		"cookie allowed again": {`"cookie",` + "\n", ``, []string{"processor requestHeaders disallowed: emitted authorization,cookie,proxy-authorization, live authorization,proxy-authorization"}},
		"allow list widened":   {`":method"`, `":method", "authorization"`, []string{"processor requestHeaders allowed: emitted :method, live :method,authorization"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			admin := c.live.admin.serve(http.StatusOK, c.adminDoc(u.url(), tc.old, tc.repl))
			r := c.sub(t).fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", admin.hostPort(), "--no-probe")
			for _, want := range tc.want {
				wantContains(t, "stdout", r.stdout, verdictLiveConfig+" s1: "+want)
			}
			wantNotContains(t, "stdout", r.stdout, verdictOK)
		})
	}
}

// Unit view of the same gap, as the processor-emit reviewer wrote it: a live
// document identical in host, kind, failureMode and methods but without the
// filter must differ from a freshly emitted file.
func TestCompareDocumentsSeesAMissingRequestHeaderFilter(t *testing.T) {
	t.Parallel()
	out, err := emit.AgentGateway(emit.Input{ListenPort: 3000, Servers: []emit.Server{{
		Name: "mock", URL: "http://127.0.0.1:3001/mcp", ProcessorAddr: "127.0.0.1:9001", ApprovedTools: []string{"echo"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	emitted, err := emittedConfig(out.YAML)
	if err != nil {
		t.Fatal(err)
	}
	live := `{"config":{"adminAddr":"127.0.0.1:15000","statsAddr":"127.0.0.1:15020","readinessAddr":"127.0.0.1:15021"},` +
		`"gateways":{"toolwarrant":{"port":3000,"bindAddress":"127.0.0.1"}},` +
		`"routes":[{"name":"mock","gateways":"toolwarrant","matches":[{"path":{"exact":"/mock/mcp"}}],` +
		`"policies":{"mcpAuthorization":{"rules":[{"allow":"mcp.tool.name == \"echo\""}]},` +
		`"mcpGuardrails":{"processors":[{"host":"127.0.0.1:9001","kind":"remote","failureMode":"failClosed",` +
		`"methods":{"tools/call":"request","tools/list":"response"}}]}},` +
		`"backends":[{"mcp":{"targets":[{"name":"mock","mcp":{"host":"http://127.0.0.1:3001/mcp"}}]}}]}]}`
	doc, err := decodeLiveConfig([]byte(live))
	if err != nil {
		t.Fatal(err)
	}
	diffs := compareDocuments(emitted, doc.config(), "mock", "/mock/mcp")
	if len(diffs) != 2 || !strings.Contains(diffs[0], "requestHeaders allowed") || !strings.Contains(diffs[1], "requestHeaders disallowed") {
		t.Errorf("a live processor without the filter: %q", diffs)
	}
	withFilter := strings.Replace(live, `"failureMode":"failClosed",`, `"failureMode":"failClosed","requestHeaders":{"allowed":[":method"],"disallowed":["authorization","cookie","proxy-authorization"]},`, 1)
	doc, err = decodeLiveConfig([]byte(withFilter))
	if err != nil {
		t.Fatal(err)
	}
	if diffs := compareDocuments(emitted, doc.config(), "mock", "/mock/mcp"); len(diffs) != 0 {
		t.Errorf("a live processor with the filter differs: %q", diffs)
	}
}

// The processor metadata carries the shared secret, so it is compared by the
// hash of its canonical form and no value, nor the hash, is ever printed
// (D14 i): a live entry that lost it, gained it or holds another value is
// reported in words only.
func TestLiveComparisonComparesTheProcessorMetadataWithoutShowingIt(t *testing.T) {
	t.Parallel()
	c, u := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	g := newUpstream(t, map[string]string{"echo": echoV1})
	gw := g.url() + routePath
	c.live = newLiveLab(t, g.url())
	cfg := filepath.Join(t.TempDir(), "gateway.yaml")
	secret := plant("shared-secret-value")
	c.env["TW_SECRET"] = secret
	c.liveEmit(cfg, "--secret-env", "TW_SECRET")
	wantContains(t, "emitted file", readFile(t, cfg), "metadata:")
	withMeta := func(value string) string {
		quoted, err := json.Marshal(`"` + value + `"`)
		if err != nil {
			t.Fatal(err)
		}
		return c.adminDoc(u.url(), `"methods": {`, `"metadata": {"toolwarrant_secret": `+string(quoted)+`}, "methods": {`)
	}
	const withheld = " (values withheld: the metadata carries the processor secret)"
	cases := map[string]struct {
		doc  string
		want string
	}{
		"live has none":      {c.adminDoc(u.url()), "processor metadata: the live processor has none while the emitted file carries it" + withheld},
		"live holds another": {withMeta("other-secret-value"), "processor metadata: the live metadata differs from the emitted file" + withheld},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			admin := c.live.admin.serve(http.StatusOK, tc.doc)
			r := c.sub(t).fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", admin.hostPort(), "--no-probe")
			wantContains(t, "stdout", r.stdout, verdictLiveConfig+" s1: "+tc.want)
			wantNotContains(t, "stdout", r.stdout+r.stderr, canary, "other-secret", "sha256 ")
		})
	}
	healthy := c.live.admin.serve(http.StatusOK, withMeta(secret))
	wantContains(t, "equal metadata", c.ok("verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", healthy.hostPort(), "--no-probe"), verdictOK)

	// The other direction: a file without a secret against a live entry that
	// carries metadata.
	c.liveEmit(cfg)
	admin := c.live.admin.serve(http.StatusOK, withMeta(secret))
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", admin.hostPort(), "--no-probe")
	wantContains(t, "stdout", r.stdout, verdictLiveConfig+" s1: processor metadata: the live processor carries metadata the emitted file does not"+withheld)
	wantNotContains(t, "stdout", r.stdout+r.stderr, canary)
}

// The emitted-file reader is pinned to the filter and metadata lines emit
// writes today: the two header lists are read in file order, the listeners
// come from the config block, and the metadata leaves only its hash behind,
// the same hash for the same block whatever the order of its keys.
func TestEmittedConfigReadsTheHeaderFilterAndHashesTheMetadata(t *testing.T) {
	t.Parallel()
	secret := plant("shared")
	in := emit.Input{ListenPort: 8080, Servers: []emit.Server{{Name: "alpha", URL: "http://127.0.0.1:3001/mcp", ProcessorAddr: "127.0.0.1:9001", Secret: secret, ApprovedTools: []string{"a"}}}}
	out, err := emit.AgentGateway(in)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := emittedConfig(out.YAML)
	if err != nil {
		t.Fatal(err)
	}
	if doc.listeners != (listenerConfig{adminAddr: emit.DefaultAdminAddr, statsAddr: emit.DefaultStatsAddr, readinessAddr: emit.DefaultReadinessAddr}) || len(doc.extraSections) != 0 {
		t.Errorf("listeners %+v, extra sections %q", doc.listeners, doc.extraSections)
	}
	rc, _ := doc.route("alpha")
	if len(rc.processors) != 1 {
		t.Fatalf("processors: %+v", rc.processors)
	}
	p := rc.processors[0]
	if describeList(p.allowed) != ":method" || describeList(p.disallowed) != "authorization,cookie,proxy-authorization" {
		t.Errorf("filter: allowed %q, disallowed %q", p.allowed, p.disallowed)
	}
	want := metadataDigest(map[string]string{emit.SecretMetadataKey: `"` + secret + `"`})
	if p.metadataHash == "" || p.metadataHash != want || strings.Contains(p.metadataHash, canary) {
		t.Errorf("metadata hash %q, want %q", p.metadataHash, want)
	}
	if describeMethods(p.methods) != "tools/call=request,tools/list=response" {
		t.Errorf("methods: %q", p.methods)
	}
	in.Servers[0].Secret = ""
	out, err = emit.AgentGateway(in)
	if err != nil {
		t.Fatal(err)
	}
	doc, err = emittedConfig(out.YAML)
	if err != nil {
		t.Fatal(err)
	}
	if rc, _ := doc.route("alpha"); rc.processors[0].metadataHash != "" {
		t.Errorf("a processor without metadata has hash %q", rc.processors[0].metadataHash)
	}
	if metadataDigest(map[string]string{"a": "1", "b": "2"}) != metadataDigest(map[string]string{"b": "2", "a": "1"}) || metadataDigest(nil) != "" {
		t.Error("metadataDigest depends on key order or hashes an empty block")
	}
	if diffs := compareMetadata("x", "y"); len(diffs) != 1 || !strings.Contains(diffs[0], "differs") {
		t.Errorf("compareMetadata(x, y) = %q", diffs)
	}
	if !sectionHasContent(json.RawMessage(`"x"`)) || sectionHasContent(json.RawMessage(`null`)) || sectionHasContent(json.RawMessage(`{}`)) || !sectionHasContent(json.RawMessage(`[1]`)) {
		t.Error("sectionHasContent misjudges a scalar, null, an empty object or a list")
	}
}

// The mixed document is one the pinned gateway loads: the emitted file plus a
// binds section with a listener on another port and a processor-less route to
// the upstream passes --validate-only (the only mode the binary may be run in
// here), so the evasion is not refused at load time and the canary is the
// control. Whether the running gateway serves the extra listener and how its
// admin API renders the section is for the end-to-end harness to pin. Skips
// loudly without the binary.
func TestGatewayAcceptsAMixedGatewaysAndBindsDocument(t *testing.T) {
	t.Parallel()
	bin := realGatewayBinary(t)
	c, u := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	cfg := filepath.Join(t.TempDir(), "gateway.yaml")
	c.ok("emit", "--out", cfg)
	mixed := readFile(t, cfg) +
		"binds:\n- port: 3005\n  listeners:\n  - name: open\n    routes:\n    - name: s1-open\n      policies:\n        mcpAuthorization:\n          rules:\n          - allow: \"true\"\n" +
		"      backends:\n      - mcp:\n          targets:\n          - name: s1\n            mcp:\n              host: \"" + u.url() + "\"\n"
	file := filepath.Join(t.TempDir(), "mixed.yaml")
	if err := os.WriteFile(file, []byte(mixed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateWithGateway(t.Context(), bin, file); err != nil {
		t.Fatalf("the gateway refused the mixed document, so the evasion would not load: %v", err)
	}
}
