package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/emit"
)

// The live-comparison fixture: the admin API stand-in, the lab that pairs a
// gateway stand-in with it, and the emit that writes their ports into the file
// (D13 e, D17 i).

// routePath is the path emit gives the fixture's route, which the canary's
// --url must carry for the live comparison (D13 e).
const routePath = "/s1/mcp"

// Pinned values of testdata/admin_config.json that the fixture replaces, and
// the defaults a plain emit writes, used when a test has no live lab.
const (
	pinnedGatewayPort  = `"port": 63902`
	pinnedAdminAddr    = emit.DefaultAdminAddr
	defaultGatewayPort = "3000" // defaultListenPort as a string; TestLiveFixtureDefaultsMatchEmit pins the pair
)

// adminDocFor is testdata/admin_config.json, the shape GET /api/config
// returned on the real gateway, with its pinned values replaced by the ones
// the emitted file holds (gatewayPort as the serving port, adminAddr as the
// admin API), so the live configuration can be made to agree with the file or
// to differ from it in exactly one place. Every replacement must hit, so a
// stale testdata file fails loudly.
func adminDocFor(t *testing.T, upstreamURL, gatewayPort, adminAddr string, edits ...string) string {
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
	replace(pinnedGatewayPort, `"port": `+gatewayPort)
	replace(`"`+pinnedAdminAddr+`"`, `"`+adminAddr+`"`)
	replace(`"127.0.0.1:63941"`, `"127.0.0.1:9001"`)
	replace(`mcp.tool.name == \"add\" || mcp.tool.name == \"echo\"`, `mcp.tool.name == \"echo\"`)
	replace(`"http://127.0.0.1:63905/mcp"`, `"`+upstreamURL+`"`)
	for i := 0; i+1 < len(edits); i += 2 {
		replace(edits[i], edits[i+1])
	}
	return doc
}

// adminDoc is adminDocFor with the live lab's port and admin address, or with
// the defaults a plain emit writes when the test has no lab.
func (c *cli) adminDoc(upstreamURL string, edits ...string) string {
	c.t.Helper()
	if c.live == nil {
		return adminDocFor(c.t, upstreamURL, defaultGatewayPort, pinnedAdminAddr, edits...)
	}
	return adminDocFor(c.t, upstreamURL, c.live.gatewayPort, c.live.admin.hostPort(), edits...)
}

// adminAnswer is what the admin stand-in says at the config path.
type adminAnswer struct {
	status int
	body   string
}

// adminAPI serves one answer at the admin API's config path, swappable in
// place so that a test can change the live document without moving the admin
// API to another port (the comparison holds --admin against the emitted
// adminAddr, D17 i), and counts the requests it saw since the answer was set.
type adminAPI struct {
	srv    *httptest.Server
	hits   atomic.Int64
	answer atomic.Pointer[adminAnswer]
}

// newAdminAPI starts an admin stand-in that answers 404 until serve is called.
func newAdminAPI(t *testing.T) *adminAPI {
	t.Helper()
	a := &adminAPI{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.hits.Add(1)
		answer := a.answer.Load()
		if answer == nil || r.URL.Path != adminConfigPath || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", mediaJSON)
		w.WriteHeader(answer.status)
		_, _ = io.WriteString(w, answer.body)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

// serve sets the answer, resets the hit count and returns the stand-in.
func (a *adminAPI) serve(status int, body string) *adminAPI {
	a.answer.Store(&adminAnswer{status: status, body: body})
	a.hits.Store(0)
	return a
}

// serveAdmin starts a stand-in of its own on a port of its own, for the tests
// about an admin API the canary cannot read, or one that is not the gateway's.
func serveAdmin(t *testing.T, status int, body string) *adminAPI {
	t.Helper()
	return newAdminAPI(t).serve(status, body)
}

// hostPort is the admin API as emit --admin-addr and verify-gateway --admin
// take it.
func (a *adminAPI) hostPort() string { return strings.TrimPrefix(a.srv.URL, "http://") }

// liveLab is the pair of addresses the live comparison holds the canary's own
// flags against (D17 i): the stand-in gateway's serving port and the admin
// stand-in. liveEmit writes both into the emitted file and adminDoc renders
// the live document with both, so a healthy fixture compares as a match and a
// test swaps the admin API's answer in place.
type liveLab struct {
	gatewayPort string
	admin       *adminAPI
}

// newLiveLab records the stand-in gateway's port and starts the admin
// stand-in.
func newLiveLab(t *testing.T, gatewayURL string) *liveLab {
	t.Helper()
	return &liveLab{gatewayPort: urlPort(t, gatewayURL), admin: newAdminAPI(t)}
}

// urlPort is the port of a stand-in's URL.
func urlPort(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil || u.Port() == "" {
		t.Fatalf("stand-in URL %q has no port: %v", rawURL, err)
	}
	return u.Port()
}

// liveEmit emits the file at cfg with the live lab's serving port and admin
// address, so a canary pointed at both stand-ins compares as a match; extra
// flags are appended.
func (c *cli) liveEmit(cfg string, extra ...string) string {
	c.t.Helper()
	args := []string{"emit", "--out", cfg, "--listen-port", c.live.gatewayPort, "--admin-addr", c.live.admin.hostPort()}
	return c.ok(append(args, extra...)...)
}

// liveFixture is the fixture with echo approved, a stand-in gateway serving
// it at the route's path, the admin stand-in and the emitted file carrying
// both stand-ins' addresses.
func liveFixture(t *testing.T) (c *cli, u *upstream, gatewayURL, cfg string) {
	t.Helper()
	c, u = fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	g := newUpstream(t, map[string]string{"echo": echoV1})
	c.live = newLiveLab(t, g.url())
	cfg = filepath.Join(t.TempDir(), "gateway.yaml")
	c.liveEmit(cfg)
	return c, u, g.url() + routePath, cfg
}
