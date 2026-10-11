package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/emit"
	"github.com/sairam0424/toolwarrant/internal/fetch"
)

// adminDoc is testdata/admin_config.json, the shape GET /api/config returned
// on the real gateway, with its pinned values replaced by the ones the
// fixture's emitted file holds, so the live configuration can be made to
// agree with the file or to differ from it in exactly one field. Every
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
	replace(`"/mock/mcp"`, `"/s1/mcp"`)
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

// Decision D12: with --admin the configuration the gateway is running is
// compared with the emitted file, field by field, and every difference is
// LIVE-CONFIG-MISMATCH with exit 1; a processor-less route in steady state
// looks exactly like that. The fixture is the shape the real gateway returned.
func TestVerifyGatewayComparesTheLiveConfigurationWithTheEmittedFile(t *testing.T) {
	c, u := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	g := newUpstream(t, map[string]string{"echo": echoV1})
	cfg := filepath.Join(t.TempDir(), "gateway.yaml")
	c.ok("emit", "--out", cfg)
	healthy := serveAdmin(t, http.StatusOK, adminDoc(t, u.url()))
	out := c.ok("verify-gateway", "--server", "s1", "--url", g.url(), "--config", cfg, "--admin", healthy.hostPort())
	wantContains(t, "stdout", out, verdictOK+": the gateway serves 1 tool(s), 1 approved and current; live configuration matches the emitted file; id-less tools/call rejected by the gateway")
	wantNotContains(t, "stdout", out, verdictLiveConfig)
	out = c.ok("verify-gateway", "--server", "s1", "--url", g.url(), "--config", cfg, "--admin", healthy.srv.URL+"/")
	wantContains(t, "stdout as url", out, "live configuration matches the emitted file")
	if healthy.hits.Load() != 2 {
		t.Errorf("admin API hits = %d, want one per check", healthy.hits.Load())
	}
	out = c.ok("verify-gateway", "--server", "s1", "--url", g.url(), "--config", cfg)
	wantContains(t, "stdout without --admin", out, "live configuration not compared (no --admin)")

	cases := map[string]struct {
		old, repl string
		want      []string
	}{
		"bind address":       {`"bindAddress": "127.0.0.1"`, `"bindAddress": "0.0.0.0"`, []string{"bind address: emitted 127.0.0.1, live 0.0.0.0"}},
		"serving port":       {`"port": 3000`, `"port": 3001`, []string{"serving port: emitted 3000, live 3001"}},
		"allow rule":         {`mcp.tool.name == \"echo\"`, `true`, []string{`allow rule: emitted mcp.tool.name == "echo", live true`}},
		"no allow rule":      {`"mcpAuthorization"`, `"mcpAuthorizationGone"`, []string{"allow rules: emitted 1, live 0"}},
		"processor host":     {`"127.0.0.1:9001"`, `"127.0.0.1:9999"`, []string{"processor host: emitted 127.0.0.1:9001, live 127.0.0.1:9999"}},
		"processor kind":     {`"kind": "remote"`, `"kind": "local"`, []string{"processor kind: emitted remote, live local"}},
		"failure mode":       {`"failClosed"`, `"failOpen"`, []string{"processor failureMode: emitted failClosed, live failOpen"}},
		"methods":            {`"tools/call": "request",`, ``, []string{"processor methods: emitted tools/call=request,tools/list=response, live tools/list=response"}},
		"no processor":       {`"mcpGuardrails"`, `"mcpGuardrailsGone"`, []string{"processor: the live route has none (emitted 127.0.0.1:9001); every new session on this route is served by the allow rule alone"}},
		"unknown gateway":    {`"gateways": "toolwarrant"`, `"gateways": "other"`, []string{"bind address: emitted 127.0.0.1, live (none)", "serving port: emitted 3000, live (none)"}},
		"no route":           {`"routes": [`, `"routes": [], "was": [`, []string{"the live configuration has no route for the server (or lists it twice)"}},
		"another upstream":   {`"` + u.url() + `"`, `"http://127.0.0.1:1/mcp?q=` + plant("query") + `"`, []string{"backend host: the live route points at another upstream (values withheld"}},
		"no backend targets": {`"targets"`, `"targetsGone"`, []string{"backend targets: emitted 1, live 0"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			admin := serveAdmin(t, http.StatusOK, adminDoc(t, u.url(), tc.old, tc.repl))
			r := c.sub(t).fail(exitFailure, "verify-gateway", "--server", "s1", "--url", g.url(), "--config", cfg, "--admin", admin.hostPort())
			for _, want := range tc.want {
				wantContains(t, "stdout", r.stdout, verdictLiveConfig+" s1: "+want)
			}
			wantNotContains(t, "stdout", r.stdout, verdictOK, canary, "q=")
			wantContains(t, "stderr", r.stderr, "differs from the emitted file in", "place(s), listed above", "find out who changed it")
			wantNotContains(t, "stderr", r.stderr, canary, "q=")
		})
	}
}

// An admin API the canary cannot reach or read is an error, never OK, and
// the comparison does not even run against a file that is not what emit
// wrote or that cannot be read: the check already fails as CONFIG-EDITED.
func TestVerifyGatewayLiveComparisonFailsClosed(t *testing.T) {
	c, u := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	g := newUpstream(t, map[string]string{"echo": echoV1})
	cfg := filepath.Join(t.TempDir(), "gateway.yaml")
	c.ok("emit", "--out", cfg)
	verify := func(admin string) result {
		return c.run("verify-gateway", "--server", "s1", "--url", g.url(), "--config", cfg, "--admin", admin)
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
	// An empty document has no route: LIVE-CONFIG-MISMATCH, not OK.
	r := verify(serveAdmin(t, http.StatusOK, "{}").hostPort())
	if r.code != exitFailure {
		t.Errorf("empty document: exit %d", r.code)
	}
	wantContains(t, "empty document", r.stdout, verdictLiveConfig+" s1: the live configuration has no route")

	// A file that is not what emit wrote: CONFIG-EDITED, and the admin API
	// is never asked.
	untouched := serveAdmin(t, http.StatusOK, adminDoc(t, u.url()))
	edited := strings.Replace(readFile(t, cfg), "failClosed", "failOpen", 1)
	if err := os.WriteFile(cfg, []byte(edited), 0o644); err != nil {
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
	r = c.run("verify-gateway", "--server", "s2", "--url", g.url(), "--config", cfg, "--admin", untouched.hostPort())
	if r.code != exitFailure {
		t.Errorf("server without a route: exit %d", r.code)
	}
	wantContains(t, "server without a route", r.stderr, "has no route for server s2", "run emit again")
}

// The skip reasons of the live comparison, which only the --every summary
// lines show, and the comparison's own refusal of an unreadable file.
func TestCompareLiveSkipsWhatItCannotTrust(t *testing.T) {
	v := &verifier{admin: "http://127.0.0.1:1", server: "s1"}
	var res verdicts
	if err := v.compareLive(context.Background(), nil, &res); err != nil || res.live.skipped != liveSkippedUnreadable || res.live.compared {
		t.Errorf("nil file: %v %+v", err, res.live)
	}
	res = verdicts{configEdited: true}
	if err := v.compareLive(context.Background(), []byte("x"), &res); err != nil || res.live.skipped != liveSkippedEdited {
		t.Errorf("edited file: %v %+v", err, res.live)
	}
	res = verdicts{}
	if err := v.compareLive(context.Background(), []byte("routes:\n- name: x\n"), &res); err == nil || !strings.Contains(err.Error(), "unquoted scalar") {
		t.Errorf("unparseable file: %v", err)
	}
	none := &verifier{}
	if err := none.compareLive(context.Background(), nil, &res); err != nil || res.live.compared || res.live.skipped != "" || res.live.diffs != nil {
		t.Errorf("without --admin: %v %+v", err, res.live)
	}
	wantContains(t, "skipped summaries", verdicts{live: liveCheck{skipped: liveSkippedEdited}}.summary(), "not what emit wrote")
	wantContains(t, "skipped summaries", verdicts{live: liveCheck{skipped: liveSkippedUnreadable}}.summary(), "could not be read")
}

// The emitted-file reader is pinned to what internal/emit writes today: a
// freshly emitted file with a shared secret and two servers yields exactly
// the fields the comparison needs, and never the secret.
func TestEmittedRouteReadsWhatEmitWrites(t *testing.T) {
	out, err := emit.AgentGateway(emit.Input{ListenPort: 8080, BindAddress: "::1", Servers: []emit.Server{
		{Name: "beta", URL: "http://127.0.0.1:3002/mcp?q=" + plant("query"), ProcessorAddr: "127.0.0.1:9002", Secret: plant("shared"), ApprovedTools: []string{"b"}},
		{Name: "alpha", URL: "http://127.0.0.1:3001/mcp", ProcessorAddr: "127.0.0.1:9001", Secret: plant("shared"), ApprovedTools: []string{"x", "a"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	rc, err := emittedRoute(out.YAML, "alpha")
	if err != nil || !rc.found {
		t.Fatalf("route alpha: %v %+v", err, rc)
	}
	if rc.bindAddress != "::1" || rc.port != "8080" || len(rc.rules) != 1 || rc.rules[0] != `mcp.tool.name == "a" || mcp.tool.name == "x"` {
		t.Errorf("gateway and rule: %+v", rc)
	}
	if len(rc.processors) != 1 || rc.processors[0].host != "127.0.0.1:9001" || rc.processors[0].kind != "remote" || rc.processors[0].failureMode != "failClosed" ||
		describeMethods(rc.processors[0].methods) != "tools/call=request,tools/list=response" {
		t.Errorf("processor: %+v", rc.processors)
	}
	if len(rc.backendHosts) != 1 || rc.backendHosts[0] != "http://127.0.0.1:3001/mcp" {
		t.Errorf("backends: %q", rc.backendHosts)
	}
	beta, err := emittedRoute(out.YAML, "beta")
	if err != nil || len(beta.backendHosts) != 1 || !strings.Contains(beta.backendHosts[0], plant("query")) || len(beta.processors) != 1 || beta.processors[0].host != "127.0.0.1:9002" {
		t.Errorf("route beta: %v %+v", err, beta)
	}
	for _, p := range beta.processors {
		for k, v := range p.methods {
			if strings.Contains(k, canary) || strings.Contains(v, canary) {
				t.Errorf("the shared secret was read into the methods: %q=%q", k, v)
			}
		}
	}
	if gamma, err := emittedRoute(out.YAML, "gamma"); err != nil || gamma.found {
		t.Errorf("absent route: %v %+v", err, gamma)
	}
	for name, file := range map[string]string{
		"route twice":     "routes:\n- name: \"x\"\n- name: \"x\"\n",
		"unquoted scalar": "routes:\n- name: x\n",
		"bad escape":      "routes:\n- name: \"x\\q\"\n",
		"unquoted bind":   "gateways:\n  toolwarrant:\n    bindAddress: 127.0.0.1\n",
	} {
		if _, err := emittedRoute([]byte(file), "x"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCompareRoutesNamesEveryDifference(t *testing.T) {
	proc := processorConfig{host: "h:1", kind: "remote", failureMode: "failClosed", methods: map[string]string{"tools/list": "response"}}
	emitted := routeConfig{found: true, bindAddress: "127.0.0.1", port: "3000", rules: []string{"r"}, processors: []processorConfig{proc}, backendHosts: []string{"u"}}
	if diffs := compareRoutes(emitted, emitted); len(diffs) != 0 {
		t.Errorf("identical routes differ: %q", diffs)
	}
	two := emitted
	two.processors = []processorConfig{proc, proc}
	if diffs := compareRoutes(emitted, two); len(diffs) != 1 || diffs[0] != "processors: emitted 1, live 2" {
		t.Errorf("two processors: %q", diffs)
	}
	hostile := emitted
	hostile.rules = []string{"r" + esc + "[31m"}
	diffs := compareRoutes(emitted, hostile)
	if len(diffs) != 1 || !strings.Contains(diffs[0], `\u{001B}`) || strings.Contains(diffs[0], esc) {
		t.Errorf("hostile rule: %q", diffs)
	}
	if got := describeMethods(nil); got != noneShown {
		t.Errorf("describeMethods(nil) = %q", got)
	}
	doc := liveConfigDoc{Routes: []liveRouteDoc{{Name: "x"}, {Name: "x"}}}
	if rc := liveRoute(doc, "x"); rc.found {
		t.Error("a route listed twice was taken as found")
	}
	if rc := liveRoute(liveConfigDoc{Routes: []liveRouteDoc{{Name: "x", Gateways: "none"}}}, "x"); !rc.found || rc.port != "" || rc.bindAddress != "" || rc.rules != nil || rc.processors != nil {
		t.Errorf("route without gateway or policies: %+v", rc)
	}
	client, err := fetch.NewClient(fetch.Policy{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetchLiveConfig(context.Background(), client, "http://127.0.0.1:1"); err == nil || !strings.HasPrefix(err.Error(), "admin api: ") {
		t.Errorf("unreachable admin api: %v", err)
	}
	if _, err := fetchLiveConfig(context.Background(), client, "::bad url"); err == nil {
		t.Error("bad admin url accepted")
	}
}
