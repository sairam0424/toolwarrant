package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// routePath is the path emit gives the fixture's route, which the canary's
// --url must carry for the live comparison (D13 e).
const routePath = "/s1/mcp"

// adminDoc is testdata/admin_config.json, the shape GET /api/config returned
// on the real gateway, with its pinned values replaced by the ones the
// fixture's emitted file holds, so the live configuration can be made to
// agree with the file or to differ from it in exactly one place. Every
// replacement must hit, so a stale testdata file fails loudly.
func adminDoc(t *testing.T, upstreamURL string, edits ...string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "admin_config.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	replace := func(old, repl string) {
		if !strings.Contains(doc, old) {
			t.Fatalf("the live configuration lacks %q:\n%s", old, doc)
		}
		doc = strings.ReplaceAll(doc, old, repl)
	}
	replace(`"mock"`, `"s1"`)
	replace(`"/mock/mcp"`, `"`+routePath+`"`)
	replace(`"port": 63902`, `"port": 3000`)
	replace(`"127.0.0.1:63941"`, `"127.0.0.1:9001"`)
	replace(`mcp.tool.name == \"add\" || mcp.tool.name == \"echo\"`, `mcp.tool.name == \"echo\"`)
	replace(`"http://127.0.0.1:63905/mcp"`, `"`+upstreamURL+`"`)
	for i := 0; i+1 < len(edits); i += 2 {
		replace(edits[i], edits[i+1])
	}
	return doc
}

// adminAPI serves one fixed answer at the admin API's config path and counts
// the requests it saw.
type adminAPI struct {
	srv  *httptest.Server
	hits atomic.Int64
}

func serveAdmin(t *testing.T, status int, body string) *adminAPI {
	t.Helper()
	a := &adminAPI{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.hits.Add(1)
		if r.URL.Path != adminConfigPath || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", mediaJSON)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

// hostPort is the admin API as emit --admin-addr and verify-gateway --admin
// take it.
func (a *adminAPI) hostPort() string { return strings.TrimPrefix(a.srv.URL, "http://") }

// liveFixture is the fixture with echo approved, a stand-in gateway serving
// it at the route's path, and the emitted file.
func liveFixture(t *testing.T) (c *cli, u *upstream, gatewayURL, cfg string) {
	t.Helper()
	c, u = fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	g := newUpstream(t, map[string]string{"echo": echoV1})
	cfg = filepath.Join(t.TempDir(), "gateway.yaml")
	c.ok("emit", "--out", cfg)
	return c, u, g.url() + routePath, cfg
}

// Decision D12 and D13 (e): with --admin the configuration the gateway is
// running is compared with the emitted file as a whole document, and every
// difference is LIVE-CONFIG-MISMATCH with exit 1; a processor-less route in
// steady state looks exactly like that. The fixture is the shape the real
// gateway returned.
func TestVerifyGatewayComparesTheLiveConfigurationWithTheEmittedFile(t *testing.T) {
	c, u, gw, cfg := liveFixture(t)
	healthy := serveAdmin(t, http.StatusOK, adminDoc(t, u.url()))
	out := c.ok("verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", healthy.hostPort())
	wantContains(t, "stdout", out, verdictOK+": the gateway serves 1 tool(s), 1 approved and current; live configuration matches the emitted file; id-less tools/call rejected by the gateway")
	wantNotContains(t, "stdout", out, verdictLiveConfig)
	out = c.ok("verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", healthy.srv.URL+"/")
	wantContains(t, "stdout as url", out, "live configuration matches the emitted file")
	if healthy.hits.Load() != 2 {
		t.Errorf("admin API hits = %d, want one per check", healthy.hits.Load())
	}
	out = c.ok("verify-gateway", "--server", "s1", "--url", gw, "--config", cfg)
	wantContains(t, "stdout without --admin", out, "live configuration not compared (no --admin)")

	cases := map[string]struct {
		old, repl string
		want      []string
	}{
		"bind address":       {`"bindAddress": "127.0.0.1"`, `"bindAddress": "0.0.0.0"`, []string{"gateway toolwarrant: bind address: emitted 127.0.0.1, live 0.0.0.0"}},
		"serving port":       {`"port": 3000`, `"port": 3001`, []string{"gateway toolwarrant: serving port: emitted 3000, live 3001"}},
		"match path":         {`"` + routePath + `"`, `"/s1/mcp-parked"`, []string{"match path: emitted /s1/mcp, live /s1/mcp-parked"}},
		"prefix match":       {`"exact": "` + routePath + `"`, `"pathPrefix": "/"`, []string{"match path: emitted /s1/mcp, live (not an exact path)"}},
		"allow rule":         {`mcp.tool.name == \"echo\"`, `true`, []string{`allow rule: emitted mcp.tool.name == "echo", live true`}},
		"no allow rule":      {`"mcpAuthorization"`, `"mcpAuthorizationGone"`, []string{"allow rules: emitted 1, live 0"}},
		"processor host":     {`"127.0.0.1:9001"`, `"127.0.0.1:9999"`, []string{"processor host: emitted 127.0.0.1:9001, live 127.0.0.1:9999"}},
		"processor kind":     {`"kind": "remote"`, `"kind": "local"`, []string{"processor kind: emitted remote, live local"}},
		"failure mode":       {`"failClosed"`, `"failOpen"`, []string{"processor failureMode: emitted failClosed, live failOpen"}},
		"methods":            {`"tools/call": "request",`, ``, []string{"processor methods: emitted tools/call=request,tools/list=response, live tools/list=response"}},
		"no processor":       {`"mcpGuardrails"`, `"mcpGuardrailsGone"`, []string{"processor: the live route has none (emitted 127.0.0.1:9001); every new session on this route is served by the allow rule alone"}},
		"unknown gateway":    {`"gateways": "toolwarrant"`, `"gateways": "other"`, []string{"gateway: emitted toolwarrant, live other"}},
		"no route":           {`"routes": [`, `"routes": [], "was": [`, []string{"route s1: not in the live configuration; its path /s1/mcp is served by nothing or by another route"}},
		"another upstream":   {`"` + u.url() + `"`, `"http://127.0.0.1:1/mcp?q=` + plant("query") + `"`, []string{"backend host: the live route points at another upstream (values withheld"}},
		"no backend targets": {`"targets"`, `"targetsGone"`, []string{"backend targets: emitted 1, live 0"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			admin := serveAdmin(t, http.StatusOK, adminDoc(t, u.url(), tc.old, tc.repl))
			r := c.sub(t).fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", admin.hostPort())
			for _, want := range tc.want {
				wantContains(t, "stdout", r.stdout, verdictLiveConfig+" s1: "+want)
			}
			wantNotContains(t, "stdout", r.stdout, verdictOK, canary, "q=")
			wantContains(t, "stderr", r.stderr, "differs from the emitted file in", "place(s), listed above", "find out who changed it")
			wantNotContains(t, "stderr", r.stderr, canary, "q=")
		})
	}
}

// Third review (cli-docs-1): a live document that keeps the server's route
// byte for byte, parks it on another path and adds a route under another name
// that owns the client's path with the allow rule copied and no processor
// compared as a match, so the path a client uses was served without the
// processor (the F3 fail-open case the check exists for) and the canary said
// OK. The whole-document comparison names the parked path, the added route
// and the path two routes match.
func TestLiveComparisonCatchesAShadowRouteThatOwnsThePath(t *testing.T) {
	c, u, gw, cfg := liveFixture(t)
	shadow := `{"name": "s1-shadow", "gateways": "toolwarrant", "matches": [{"path": {"exact": "` + routePath + `"}}],` +
		` "policies": {"mcpAuthorization": {"rules": [{"allow": "mcp.tool.name == \"echo\""}]}},` +
		` "backends": [{"mcp": {"targets": [{"name": "s1", "mcp": {"host": "` + u.url() + `"}}]}}]},`
	doc := adminDoc(t, u.url(), `"`+routePath+`"`, `"/s1/mcp-parked"`, `"routes": [`, `"routes": [`+shadow)
	admin := serveAdmin(t, http.StatusOK, doc)
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", admin.hostPort(), "--no-probe")
	wantContains(t, "stdout", r.stdout,
		verdictLiveConfig+" s1: match path: emitted /s1/mcp, live /s1/mcp-parked",
		verdictLiveConfig+" s1: route s1-shadow: not in the emitted file (gateway toolwarrant, path /s1/mcp); the gateway serves it without the emitted guards")
	wantNotContains(t, "stdout", r.stdout, verdictOK, u.url())
	wantContains(t, "stderr", r.stderr, "differs from the emitted file in 2 place(s)")
}

// The same class (cli-docs-1, second shape): a second gateway bound to every
// interface on another port, with a copy of the route that has no processor
// and an allow rule that matches everything.
func TestLiveComparisonCatchesAnAddedOpenGateway(t *testing.T) {
	c, u, gw, cfg := liveFixture(t)
	open := `{"name": "s1-open", "gateways": "open", "matches": [{"path": {"exact": "` + routePath + `"}}],` +
		` "policies": {"mcpAuthorization": {"rules": [{"allow": "true"}]}},` +
		` "backends": [{"mcp": {"targets": [{"name": "s1", "mcp": {"host": "` + u.url() + `"}}]}}]},`
	doc := adminDoc(t, u.url(),
		`"gateways": {`, `"gateways": {"open": {"port": 3001, "bindAddress": "0.0.0.0"},`,
		`"routes": [`, `"routes": [`+open)
	admin := serveAdmin(t, http.StatusOK, doc)
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", admin.hostPort(), "--no-probe")
	wantContains(t, "stdout", r.stdout,
		verdictLiveConfig+" s1: gateway open: not in the emitted file (live bind address 0.0.0.0, serving port 3001); every route attached to it is served without the emitted guards",
		verdictLiveConfig+" s1: route s1-open: not in the emitted file (gateway open, path /s1/mcp); the gateway serves it without the emitted guards",
		verdictLiveConfig+" s1: path /s1/mcp: matched by 2 live routes (s1-open, s1); which one the gateway serves cannot be told")
	wantNotContains(t, "stdout", r.stdout, verdictOK)
	wantContains(t, "stderr", r.stderr, "differs from the emitted file in 3 place(s)")
}

// Third review (processor-emit-2): a route added through the admin API, on the
// same path with the allow rule copied and no processor, or on another path
// with no rule and no processor, is reported whether it comes first or second
// in the document.
func TestLiveComparisonReportsAnAddedRoute(t *testing.T) {
	c, u, gw, cfg := liveFixture(t)
	added := map[string]struct {
		route string
		want  []string
	}{
		"same path, allow rule copied, no processor": {`{"name": "s1-open", "gateways": "toolwarrant", "matches": [{"path": {"exact": "` + routePath + `"}}],` +
			` "policies": {"mcpAuthorization": {"rules": [{"allow": "mcp.tool.name == \"echo\""}]}},` +
			` "backends": [{"mcp": {"targets": [{"name": "s1", "mcp": {"host": "` + u.url() + `"}}]}}]}`,
			[]string{"route s1-open: not in the emitted file (gateway toolwarrant, path /s1/mcp)", "path /s1/mcp: matched by 2 live routes"}},
		"another path, no rule, no processor": {`{"name": "crawl", "gateways": "toolwarrant", "matches": [{"path": {"exact": "/s1/mcp2"}}],` +
			` "backends": [{"mcp": {"targets": [{"name": "s1", "mcp": {"host": "` + u.url() + `"}}]}}]}`,
			[]string{"route crawl: not in the emitted file (gateway toolwarrant, path /s1/mcp2)"}},
	}
	for name, tc := range added {
		for _, first := range []bool{true, false} {
			t.Run(name+" first="+map[bool]string{true: "yes", false: "no"}[first], func(t *testing.T) {
				var doc string
				if first {
					doc = adminDoc(t, u.url(), `"routes": [`, `"routes": [`+tc.route+`,`)
				} else {
					doc = adminDoc(t, u.url(), "\n  ]\n}", ","+tc.route+"\n  ]\n}")
				}
				admin := serveAdmin(t, http.StatusOK, doc)
				r := c.sub(t).fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", admin.hostPort(), "--no-probe")
				for _, want := range tc.want {
					wantContains(t, "stdout", r.stdout, verdictLiveConfig+" s1: "+want)
				}
				wantNotContains(t, "stdout", r.stdout, verdictOK)
			})
		}
	}
}

// The listing must test the route the file emits for the server: a --url on
// another path is a difference of its own, and the one difference reported
// when the live document is otherwise the emitted one.
func TestLiveComparisonChecksTheURLPath(t *testing.T) {
	c, u, gw, cfg := liveFixture(t)
	admin := serveAdmin(t, http.StatusOK, adminDoc(t, u.url()))
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", strings.TrimSuffix(gw, routePath)+"/s1/other", "--config", cfg, "--admin", admin.hostPort(), "--no-probe")
	wantContains(t, "stdout", r.stdout, verdictLiveConfig+" s1: the path of --url (/s1/other) is not the match of the emitted route (/s1/mcp); the listing above tested another route")
	wantContains(t, "stderr", r.stderr, "differs from the emitted file in 1 place(s)")
	// Without --admin the path is not checked: the canary then compares the
	// catalog with whatever route it was pointed at.
	wantContains(t, "without --admin", c.ok("verify-gateway", "--server", "s1", "--url", strings.TrimSuffix(gw, routePath), "--config", cfg, "--no-probe"), verdictOK)
}

// An admin API the canary cannot reach or read is an error, never OK, and
// the comparison does not even run against a file that is not what emit
// wrote or that cannot be read: the check already fails as CONFIG-EDITED.
func TestVerifyGatewayLiveComparisonFailsClosed(t *testing.T) {
	c, u, gw, cfg := liveFixture(t)
	verify := func(admin string) result {
		return c.run("verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", admin)
	}
	closed := serveAdmin(t, http.StatusOK, "{}")
	closed.srv.Close()
	for name, tc := range map[string]struct {
		admin string
		want  string
	}{
		"unreachable": {closed.hostPort(), "admin api: connection refused"},
		"not json":    {serveAdmin(t, http.StatusOK, "<html>admin</html>").hostPort(), "admin api: the answer is not the configuration JSON"},
		"http 500":    {serveAdmin(t, http.StatusInternalServerError, "{}").hostPort(), "admin api: http status 500"},
		"too large":   {serveAdmin(t, http.StatusOK, strings.Repeat(" ", adminMaxBody+1)).hostPort(), "admin api: the configuration is larger than the cap"},
		"wrong path":  {serveAdmin(t, http.StatusOK, "{}").srv.URL + "/elsewhere", "admin api: http status 404"},
	} {
		r := verify(tc.admin)
		if r.code != exitFailure {
			t.Errorf("%s: exit %d, want %d\n%s", name, r.code, exitFailure, r.stdout)
		}
		wantContains(t, name, r.stderr, tc.want)
		wantNotContains(t, name, r.stdout, verdictOK)
	}
	// An empty document has neither the gateway nor the route:
	// LIVE-CONFIG-MISMATCH, not OK.
	r := verify(serveAdmin(t, http.StatusOK, "{}").hostPort())
	if r.code != exitFailure {
		t.Errorf("empty document: exit %d", r.code)
	}
	wantContains(t, "empty document", r.stdout, verdictLiveConfig+" s1: gateway toolwarrant: not in the live configuration", verdictLiveConfig+" s1: route s1: not in the live configuration")

	// A file that is not what emit wrote: CONFIG-EDITED, and the admin API
	// is never asked.
	untouched := serveAdmin(t, http.StatusOK, adminDoc(t, u.url()))
	edited := strings.Replace(readFile(t, cfg), "failClosed", "failOpen", 1)
	if err := os.WriteFile(cfg, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	r = verify(untouched.hostPort())
	if r.code != exitFailure {
		t.Errorf("edited file: exit %d", r.code)
	}
	wantContains(t, "edited file", r.stdout, verdictConfigEdited)
	wantNotContains(t, "edited file", r.stdout, verdictLiveConfig, verdictOK)
	if err := os.Remove(cfg); err != nil {
		t.Fatal(err)
	}
	r = verify(untouched.hostPort())
	wantContains(t, "missing file", r.stdout, verdictConfigEdited, "could not be read")
	if untouched.hits.Load() != 0 {
		t.Errorf("the admin API was asked %d time(s) although the file failed its check", untouched.hits.Load())
	}

	// A file without a route for the server: an error, not a match.
	c.ok("emit", "--out", cfg)
	c.ok("server", "add", "s2", u.url(), "--allow-private")
	r = c.run("verify-gateway", "--server", "s2", "--url", gw, "--config", cfg, "--admin", untouched.hostPort())
	if r.code != exitFailure {
		t.Errorf("server without a route: exit %d", r.code)
	}
	wantContains(t, "server without a route", r.stderr, "has no route for server s2", "run emit again")
}

// The shadow-route document is one the pinned gateway loads: the emitted file
// with the route parked and a processor-less route appended passes the
// binary's own --validate-only (the only mode the binary may be run in here),
// so the evasion is not refused at load time and the canary is the control.
// Skips loudly without the binary.
func TestGatewayAcceptsTheShadowRouteDocument(t *testing.T) {
	bin := realGatewayBinary(t)
	c, u := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	cfg := filepath.Join(t.TempDir(), "gateway.yaml")
	c.ok("emit", "--out", cfg)
	yaml := readFile(t, cfg)
	if !strings.Contains(yaml, `exact: "/s1/mcp"`) {
		t.Fatalf("the emitted file has no exact match for /s1/mcp:\n%s", yaml)
	}
	shadow := strings.Replace(yaml, `exact: "/s1/mcp"`, `exact: "/s1/mcp-parked"`, 1) +
		"- name: \"s1-shadow\"\n  gateways: \"toolwarrant\"\n  matches:\n  - path:\n      exact: \"/s1/mcp\"\n" +
		"  policies:\n    mcpAuthorization:\n      rules:\n      - allow: \"mcp.tool.name == \\\"echo\\\"\"\n" +
		"  backends:\n  - mcp:\n      targets:\n      - name: \"s1\"\n        mcp:\n          host: \"" + u.url() + "\"\n"
	file := filepath.Join(t.TempDir(), "shadow.yaml")
	if err := os.WriteFile(file, []byte(shadow), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateWithGateway(t.Context(), bin, file); err != nil {
		t.Fatalf("the gateway refused the shadow-route document, so the evasion would not load: %v", err)
	}
}
