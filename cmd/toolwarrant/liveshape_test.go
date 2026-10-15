package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fifth review (cli-docs-1, D15 i): the --admin help, README L18, SECURITY.md
// and the threat model promised that "nothing the file does not carry may
// exist" in the live configuration and that every emitted route is present
// "with the same fields", while the comparison read a fixed set of fields
// inside the known sections and json.Unmarshal dropped every other key.
// agentgateway v1.6.0 accepts 32 route policies (extProc, requestMirror,
// transformations and urlRewrite among them), a route backend of another kind
// next to the mcp one, and 37 config fields, so a live route that gained one
// of those compared as a match and the canary printed OK with exit 0. Every
// key inside a known section that the emitted file cannot carry is now one
// LIVE-CONFIG-MISMATCH line.
func TestLiveComparisonReportsWhatTheFileCannotCarryInsideAKnownSection(t *testing.T) {
	t.Parallel()
	c, u, gw, cfg := liveFixture(t)
	cases := map[string]struct {
		old, repl string
		want      []string
	}{
		// An external body processor in the path after the mcpGuardrails hook.
		"extProc policy": {`"policies": {`, `"policies": {"extProc": {"backend": "127.0.0.1:4444", "failureMode": "failOpen"},`,
			[]string{"policy extProc: not in the emitted file; the gateway applies it to this route"}},
		// Every request, arguments and client headers included, copied to a
		// host of the attacker's choice.
		"requestMirror policy": {`"policies": {`, `"policies": {"requestMirror": {"backend": {"host": "127.0.0.1:4444"}, "percentage": 100},`,
			[]string{"policy requestMirror: not in the emitted file; the gateway applies it to this route"}},
		"transformations policy": {`"policies": {`, `"policies": {"transformations": {"response": {"body": "\"x\""}},`,
			[]string{"policy transformations: not in the emitted file; the gateway applies it to this route"}},
		"urlRewrite policy": {`"policies": {`, `"policies": {"urlRewrite": {"path": {"full": "/other"}},`,
			[]string{"policy urlRewrite: not in the emitted file; the gateway applies it to this route"}},
		// A second backend of another kind sharing the route's traffic; the
		// target count stays one, so only the shape check sees it.
		"extra host backend": {`"backends": [`, `"backends": [{"host": "127.0.0.1:4444", "weight": 50},`,
			[]string{"backend 1: field host: not in the emitted file", "backend 1: field weight: not in the emitted file"}},
		"extra config key": {`"config": {`, `"config": {"mcp": {"sessionTtl": "1s"},`,
			[]string{"config mcp: not in the emitted file"}},
		"extra route field": {`"gateways": "toolwarrant",`, `"gateways": "toolwarrant", "hostnames": ["evil.example"],`,
			[]string{"field hostnames: not in the emitted file"}},
		"match on more than the path": {`"matches": [`, `"matches": [{"path": {"exact": "/s1/mcp"}, "method": "POST"}], "was": [`,
			[]string{"match 1: field method: not in the emitted file", "field was: not in the emitted file"}},
		"path with a second condition": {`"exact": "/s1/mcp"`, `"exact": "/s1/mcp", "regex": ".*"`,
			[]string{"match 1: path field regex: not in the emitted file"}},
		"extra gateway field": {`"bindAddress": "127.0.0.1"`, `"bindAddress": "127.0.0.1", "hostname": "evil.example"`,
			[]string{"gateway toolwarrant: field hostname: not in the emitted file"}},
		"extra processor field": {`"kind": "remote",`, `"kind": "remote", "timeout": "1s",`,
			[]string{"processor 1: field timeout: not in the emitted file"}},
		"extra header filter field": {`"allowed": [`, `"required": ["x-evil"], "allowed": [`,
			[]string{"processor 1: requestHeaders field required: not in the emitted file"}},
		"extra target field": {`"host": "` + u.url() + `"`, `"host": "` + u.url() + `", "path": "/other"`,
			[]string{"backend 1: target 1: mcp field path: not in the emitted file"}},
		"extra rule field": {`"allow": "mcp.tool.name == \"echo\""`, `"allow": "mcp.tool.name == \"echo\"", "deny": "false"`,
			[]string{"allow rule 1: field deny: not in the emitted file"}},
		"escaped key": {`"policies": {`, `"policies": {"ext\u001b[31mProc": {},`,
			[]string{`policy ext\u{001B}[31mProc: not in the emitted file`}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			admin := c.live.admin.serve(http.StatusOK, c.adminDoc(u.url(), tc.old, tc.repl))
			r := c.sub(t).fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", admin.hostPort(), "--no-probe")
			for _, want := range tc.want {
				wantContains(t, "stdout", r.stdout, verdictLiveConfig+" s1: "+want)
			}
			wantNotContains(t, "stdout", r.stdout, verdictOK+": ", u.url(), "\x1b")
			wantContains(t, "stderr", r.stderr, "differs from the emitted file in", "place(s), listed above")
		})
	}
	// The recorded shape of the real gateway, unchanged, still matches: the
	// walk accepts exactly what the pinned document carries.
	healthy := c.live.admin.serve(http.StatusOK, c.adminDoc(u.url()))
	wantContains(t, "healthy", c.ok("verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", healthy.hostPort(), "--no-probe"), verdictOK+": ", "live configuration matches the emitted file")
}

// The same gap at the unit level, as the reviewer wrote it: a live route that
// is the emitted one plus an extProc policy, a requestMirror policy and a
// non-mcp backend, under a config block with an extra field, yields exactly
// the four lines about them and nothing else; the same document without them
// yields none.
func TestCompareDocumentsReportsAPolicyOrBackendTheFileCannotCarry(t *testing.T) {
	t.Parallel()
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	cfg := filepath.Join(t.TempDir(), "gateway.yaml")
	c.ok("emit", "--out", cfg)
	emitted, err := emittedConfig([]byte(readFile(t, cfg)))
	if err != nil {
		t.Fatal(err)
	}
	const extraConfig = `"mcp": {"sessionTtl": "1s"},`
	const extraPolicies = `"extProc": {"backend": "127.0.0.1:4444"}, "requestMirror": {"backend": {"host": "127.0.0.1:4444"}, "percentage": 100},`
	const extraBackend = `{"host": "127.0.0.1:4444", "weight": 50},`
	live := `{"config": {` + extraConfig + `"adminAddr": "127.0.0.1:15000", "statsAddr": "127.0.0.1:15020", "readinessAddr": "127.0.0.1:15021"},` +
		`"gateways": {"toolwarrant": {"port": 3000, "bindAddress": "127.0.0.1"}},` +
		`"routes": [{"name": "s1", "gateways": "toolwarrant", "matches": [{"path": {"exact": "/s1/mcp"}}],` +
		` "policies": {` + extraPolicies +
		`  "mcpAuthorization": {"rules": [{"allow": "mcp.tool.name == \"echo\""}]},` +
		`  "mcpGuardrails": {"processors": [{"host": "127.0.0.1:9001", "kind": "remote", "failureMode": "failClosed",` +
		`   "requestHeaders": {"allowed": [":method"], "disallowed": ["authorization", "cookie", "proxy-authorization"]},` +
		`   "methods": {"tools/call": "request", "tools/list": "response"}}]}},` +
		` "backends": [` + extraBackend + `{"mcp": {"targets": [{"name": "s1", "mcp": {"host": "` + emitted.routes[0].backendHosts[0] + `"}}]}}]}]}`
	doc, err := decodeLiveConfig([]byte(live))
	if err != nil {
		t.Fatal(err)
	}
	diffs := compareDocuments(emitted, doc.config(), "s1", "/s1/mcp")
	// Route keys are walked in sorted order, so the backends come first.
	want := []string{
		"config mcp: not in the emitted file",
		"backend 1: field host: not in the emitted file",
		"backend 1: field weight: not in the emitted file",
		"policy extProc: not in the emitted file; the gateway applies it to this route",
		"policy requestMirror: not in the emitted file; the gateway applies it to this route",
	}
	if strings.Join(diffs, "\n") != strings.Join(want, "\n") {
		t.Errorf("differences:\n%s\nwant:\n%s", strings.Join(diffs, "\n"), strings.Join(want, "\n"))
	}
	plain := strings.NewReplacer(extraConfig, "", extraPolicies, "", extraBackend, "").Replace(live)
	if doc, err = decodeLiveConfig([]byte(plain)); err != nil {
		t.Fatal(err)
	}
	if diffs := compareDocuments(emitted, doc.config(), "s1", "/s1/mcp"); len(diffs) != 0 {
		t.Errorf("the same document without the extras differs: %q", diffs)
	}
	// A route the file does not carry is reported once, as a whole, and a
	// gateway the file does not carry likewise: their fields are not listed.
	other := strings.Replace(plain, `"name": "s1"`, `"name": "s9"`, 1)
	other = strings.Replace(other, `"toolwarrant": {"port": 3000`, `"open": {"port": 3001, "listeners": []`, 1)
	if doc, err = decodeLiveConfig([]byte(other)); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(compareDocuments(emitted, doc.config(), "s1", "/s1/mcp"), "\n")
	wantContains(t, "renamed route and gateway", all, "route s9: not in the emitted file", "gateway open: not in the emitted file")
	wantNotContains(t, "renamed route and gateway", all, "policy ", "field listeners")
}

// The walk itself: an absent or null value has nothing to report, a free map
// (methods, metadata) is read by value and not walked, a value that is not
// the container the shape expects is reported as a whole rather than passed,
// and list elements are numbered from one.
func TestShapeWalkFailsClosedOnWhatItCannotRead(t *testing.T) {
	t.Parallel()
	route := routeShape()
	for name, doc := range map[string]string{
		"absent": ``, "null": `null`, "empty": `{}`,
		"null containers": `{"matches": null, "policies": null, "backends": null}`,
		"free maps":       `{"policies": {"mcpGuardrails": {"processors": [{"methods": {"x": "y"}, "metadata": {"a": {"b": 1}}}]}}}`,
	} {
		if lines := route.foreign(json.RawMessage(doc), ""); len(lines) != 0 {
			t.Errorf("%s: %q", name, lines)
		}
	}
	cases := map[string]struct {
		doc  string
		want []string
	}{
		"scalar where an object is expected":      {`{"policies": "x"}`, []string{notAnObject}},
		"scalar where a named object is expected": {`{"matches": [{"path": 3}]}`, []string{"match 1: path " + notAnObject}},
		"object where a list is expected":         {`{"matches": {"path": {"exact": "/x"}}}`, []string{"matches: not a list as in the emitted file"}},
		"second element numbered":                 {`{"backends": [{"mcp": {"targets": []}}, {"host": "h"}]}`, []string{"backend 2: field host: not in the emitted file"}},
		"nested location":                         {`{"policies": {"mcpGuardrails": {"processors": [{}, {"requestHeaders": {"set": 1}}]}}}`, []string{"processor 2: requestHeaders field set: not in the emitted file"}},
		"keys sorted":                             {`{"z": 1, "a": 2}`, []string{"field a: not in the emitted file", "field z: not in the emitted file"}},
	}
	for name, tc := range cases {
		if got := route.foreign(json.RawMessage(tc.doc), ""); strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
	if got := foreignGateways(json.RawMessage(`[]`)); len(got[""]) != 1 || got[""][0] != "gateways: "+notAnObject {
		t.Errorf("gateways as a list: %q", got)
	}
	if got := foreignGateways(json.RawMessage(`{"a": {"port": 1}, "b": {"tls": {}}}`)); len(got) != 1 || len(got["b"]) != 1 || got["b"][0] != "gateway b: field tls: not in the emitted file" {
		t.Errorf("gateways: %q", got)
	}
	if got := foreignRoutes(json.RawMessage(`{}`)); len(got) != 1 || got[0][0] != "routes: "+notAnObject {
		t.Errorf("routes as an object: %q", got)
	}
	if got := foreignRoutes(nil); got != nil {
		t.Errorf("absent routes: %q", got)
	}
	if got := compareGateways(map[string]gatewayConfig{}, map[string]gatewayConfig{}, map[string][]string{"": {"x"}}); len(got) != 1 || got[0] != "x" {
		t.Errorf("gateways section line: %q", got)
	}
}

// The pinned binary accepts each shape in --validate-only (the only mode it
// may run in here), so the evasion is not refused at load time and the canary
// is the control; whether the running gateway applies them to an MCP route is
// for the end-to-end harness to pin. Skips loudly without the binary.
func TestGatewayAcceptsExtraRoutePoliciesAndBackends(t *testing.T) {
	t.Parallel()
	bin := realGatewayBinary(t)
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	cfg := filepath.Join(t.TempDir(), "gateway.yaml")
	c.ok("emit", "--out", cfg)
	yaml := readFile(t, cfg)
	const policies = "  policies:\n"
	if strings.Count(yaml, policies) != 1 || strings.Count(yaml, "  backends:\n") != 1 || strings.Count(yaml, "config:\n") != 1 {
		t.Fatalf("the emitted file does not hold exactly one policies, backends and config block:\n%s", yaml)
	}
	variants := map[string]string{
		"extProc":         strings.Replace(yaml, policies, policies+"    extProc:\n      backend: \"127.0.0.1:4444\"\n      failureMode: \"failOpen\"\n", 1),
		"requestMirror":   strings.Replace(yaml, policies, policies+"    requestMirror:\n      backend:\n        host: \"127.0.0.1:4444\"\n      percentage: 100\n", 1),
		"transformations": strings.Replace(yaml, policies, policies+"    transformations:\n      response:\n        body: \"\\\"x\\\"\"\n", 1),
		"urlRewrite":      strings.Replace(yaml, policies, policies+"    urlRewrite:\n      path:\n        full: \"/other\"\n", 1),
		"host backend":    strings.Replace(yaml, "  backends:\n", "  backends:\n  - host: \"127.0.0.1:4444\"\n    weight: 50\n", 1),
		"config mcp":      strings.Replace(yaml, "config:\n", "config:\n  mcp:\n    sessionTtl: \"1h\"\n", 1),
	}
	for name, doc := range variants {
		file := filepath.Join(t.TempDir(), "variant.yaml")
		if err := os.WriteFile(file, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := validateWithGateway(t.Context(), bin, file); err != nil {
			t.Errorf("%s: the gateway refused the document, so this shape would not load: %v", name, err)
		}
	}
}
