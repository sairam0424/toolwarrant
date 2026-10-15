package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// editLiveDoc decodes the admin document, lets edit change it and encodes it
// again, so a test can change one nested value without string replacement
// (the route name and the target name read the same in the fixture).
func editLiveDoc(t *testing.T, doc string, edit func(root map[string]any)) string {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal([]byte(doc), &root); err != nil {
		t.Fatal(err)
	}
	edit(root)
	out, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// firstTarget returns the first MCP target object of the first backend of the
// first route of the live document.
func firstTarget(t *testing.T, root map[string]any) map[string]any {
	t.Helper()
	routes, _ := root["routes"].([]any)
	if len(routes) == 0 {
		t.Fatal("no routes in the live document")
	}
	route, _ := routes[0].(map[string]any)
	backends, _ := route["backends"].([]any)
	if len(backends) == 0 {
		t.Fatal("no backends in the live route")
	}
	backend, _ := backends[0].(map[string]any)
	mcp, _ := backend["mcp"].(map[string]any)
	targets, _ := mcp["targets"].([]any)
	if len(targets) == 0 {
		t.Fatal("no targets in the live backend")
	}
	target, _ := targets[0].(map[string]any)
	return target
}

// Seventh review (canary-3, D17 i): the --admin help, README, SECURITY.md,
// operations.md and threat-model rows 18 and 26 said every live backend must
// be "the one mcp backend with the emitted target", but the live decoder read
// targets[].mcp.host only, the emitted-file parser read the host line only,
// and the shape walk listed the target's name as a key the file carries, so
// nothing compared it: a live document whose target was renamed through the
// admin API compared as a match. The processor accepts a hook only for its
// configured target (service_names), so such a route serves nothing while the
// operator is pointed at the allow rule or limit L2 by the MISSING lines. The
// name is now read on both sides and compared; it is the server name, so it
// is shown.
func TestLiveComparisonComparesTheBackendTargetName(t *testing.T) {
	t.Parallel()
	c, u, gw, cfg := liveFixture(t)
	renamed := editLiveDoc(t, c.adminDoc(u.url()), func(root map[string]any) {
		target := firstTarget(t, root)
		if target["name"] != "s1" {
			t.Fatalf("the fixture's target is %v, want s1", target["name"])
		}
		target["name"] = "someone-else"
	})
	if !strings.Contains(renamed, `"name":"someone-else"`) {
		t.Fatalf("the edit did not land:\n%s", renamed)
	}
	admin := c.live.admin.serve(http.StatusOK, renamed)
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", admin.hostPort(), "--no-probe")
	wantContains(t, "stdout", r.stdout, verdictLiveConfig+" s1: backend target name: emitted s1, live someone-else")
	wantNotContains(t, "stdout", r.stdout, verdictOK, u.url())
	wantContains(t, "stderr", r.stderr, "differs from the emitted file in 1 place(s)")

	// A target without a name, and the unchanged document, at the unit level:
	// the name is one more field of the target, the host stays withheld.
	emitted := route("s1", "toolwarrant", "/s1/mcp")
	emitted.backendTargets = []string{"s1"}
	live := emitted
	live.backendTargets = nil
	if diffs := compareTargets(emitted, live); len(diffs) != 1 || diffs[0] != "backend target name: emitted s1, live (none)" {
		t.Errorf("target without a name: %q", diffs)
	}
	live.backendTargets = []string{"s1"}
	live.backendHosts = []string{"http://127.0.0.1:2/mcp?q=" + plant("query")}
	diffs := compareTargets(emitted, live)
	if len(diffs) != 1 || !strings.HasPrefix(diffs[0], "backend host: the live route points at another upstream") || strings.Contains(diffs[0], canary) {
		t.Errorf("other host: %q", diffs)
	}
	if diffs := compareTargets(emitted, emitted); len(diffs) != 0 {
		t.Errorf("identical targets differ: %q", diffs)
	}
	// The real gateway's rendering carries the name where the fixture has
	// it, so the healthy document still compares as a match.
	healthy := c.live.admin.serve(http.StatusOK, c.adminDoc(u.url()))
	wantContains(t, "healthy", c.ok("verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", healthy.hostPort(), "--no-probe"), verdictOK+": ", "live configuration matches the emitted file")
}

// Seventh review (canary-4, D17 i): the comparison bound the listing to the
// emitted route by the path of --url alone, so a canary pointed at another
// listener (a second gateway instance, a staging port, a copy of the file
// running elsewhere) listed through one gateway, asked another admin API and
// printed "live configuration matches the emitted file" for a gateway it
// never touched. The port of --url is now held against the emitted gateway's
// serving port and the port of --admin against the emitted adminAddr, each
// difference one LIVE-CONFIG-MISMATCH line; the hosts too when the emitted
// address is a loopback one, since a listing that left the host cannot have
// reached a loopback listener.
func TestLiveComparisonHoldsTheURLAndAdminPortsAgainstTheEmittedFile(t *testing.T) {
	t.Parallel()
	c, u, gw, cfg := liveFixture(t)
	admin := c.live.admin.serve(http.StatusOK, c.adminDoc(u.url()))
	other := newUpstream(t, map[string]string{"echo": echoV1})
	otherURL := other.url() + routePath
	otherPort := urlPort(t, other.url())
	if otherPort == c.live.gatewayPort {
		t.Fatal("the two stand-ins share a port")
	}
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", otherURL, "--config", cfg, "--admin", admin.hostPort(), "--no-probe")
	wantContains(t, "stdout", r.stdout, verdictLiveConfig+" s1: the port of --url ("+otherPort+") is not the serving port of the emitted gateway toolwarrant ("+c.live.gatewayPort+"); the listing above went through another listener")
	wantNotContains(t, "stdout", r.stdout, verdictOK)
	wantContains(t, "stderr", r.stderr, "differs from the emitted file in 1 place(s)")

	elsewhere := serveAdmin(t, http.StatusOK, c.adminDoc(u.url()))
	r = c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", elsewhere.hostPort(), "--no-probe")
	wantContains(t, "stdout", r.stdout, verdictLiveConfig+" s1: the port of --admin ("+urlPort(t, elsewhere.srv.URL)+") is not the port of the emitted adminAddr ("+admin.hostPort()+"); the live configuration above came from another admin API")
	wantNotContains(t, "stdout", r.stdout, verdictOK)
	wantContains(t, "stderr", r.stderr, "differs from the emitted file in 1 place(s)")

	// The right ports through either stand-in compare as a match, and without
	// --admin nothing is held against the file.
	wantContains(t, "healthy", c.ok("verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", admin.hostPort(), "--no-probe"), verdictOK+": ", "live configuration matches the emitted file")
	wantContains(t, "without --admin", c.ok("verify-gateway", "--server", "s1", "--url", otherURL, "--config", cfg, "--no-probe"), verdictOK+": ")
}

// The unit view of the address rule: a default port is read from the scheme,
// a host other than loopback is a difference only against a loopback emitted
// address, an adminAddr that is off names the other process, and a URL that
// does not parse or an emitted file without the route adds nothing.
func TestCompareCanaryAddresses(t *testing.T) {
	t.Parallel()
	emitted := configDoc{
		listeners: listenerConfig{adminAddr: "127.0.0.1:15000"},
		gateways:  map[string]gatewayConfig{"toolwarrant": {bindAddress: "127.0.0.1", port: "3000"}},
		routes:    []routeConfig{route("s1", "toolwarrant", "/s1/mcp")},
	}
	cases := map[string]struct {
		url, admin string
		emitted    configDoc
		want       []string
	}{
		"match":                  {"http://127.0.0.1:3000/s1/mcp", "http://127.0.0.1:15000", emitted, nil},
		"loopback name alias":    {"http://localhost:3000/s1/mcp", "http://localhost:15000", emitted, nil},
		"other loopback literal": {"http://127.0.0.2:3000/s1/mcp", "http://127.0.0.1:15000", emitted, []string{"the host of --url (127.0.0.2) is not the emitted bind address (127.0.0.1); the listing above went through another host"}},
		"ipv6 loopback literal":  {"http://127.0.0.1:3000/s1/mcp", "http://[::1]:15000", emitted, []string{"the host of --admin (::1) is not the host of the emitted adminAddr (127.0.0.1:15000); the live configuration above came from another admin API"}},
		"no admin":               {"http://127.0.0.1:3000/s1/mcp", "", emitted, nil},
		"default http port":      {"http://127.0.0.1/s1/mcp", "http://127.0.0.1:15000", emitted, []string{"the port of --url (80) is not the serving port of the emitted gateway toolwarrant (3000); the listing above went through another listener"}},
		"default https port":     {"https://127.0.0.1/s1/mcp", "http://127.0.0.1:15000", emitted, []string{"the port of --url (443) is not the serving port"}},
		"other url port":         {"http://127.0.0.1:3001/s1/mcp", "http://127.0.0.1:15000", emitted, []string{"the port of --url (3001) is not the serving port of the emitted gateway toolwarrant (3000)"}},
		"other url host":         {"http://10.0.0.5:3000/s1/mcp", "http://127.0.0.1:15000", emitted, []string{"the host of --url (10.0.0.5) is not the emitted bind address (127.0.0.1); the listing above went through another host"}},
		"other url name":         {"http://gateway.example:3000/s1/mcp", "http://127.0.0.1:15000", emitted, []string{"the host of --url (gateway.example) is not a loopback address like the emitted bind address (127.0.0.1); the listing above went through another host"}},
		"other admin port":       {"http://127.0.0.1:3000/s1/mcp", "http://127.0.0.1:15001", emitted, []string{"the port of --admin (15001) is not the port of the emitted adminAddr (127.0.0.1:15000); the live configuration above came from another admin API"}},
		"other admin host":       {"http://127.0.0.1:3000/s1/mcp", "http://10.0.0.5:15000", emitted, []string{"the host of --admin (10.0.0.5) is not the host of the emitted adminAddr (127.0.0.1:15000); the live configuration above came from another admin API"}},
		"other admin name":       {"http://127.0.0.1:3000/s1/mcp", "http://admin.example:15000", emitted, []string{"the host of --admin (admin.example) is not a loopback address like the emitted adminAddr (127.0.0.1:15000); the live configuration above came from another admin API"}},
		"both wrong":             {"http://10.0.0.5:3001/s1/mcp", "http://10.0.0.5:15001", emitted, []string{"the port of --url (3001)", "the host of --url (10.0.0.5)", "the port of --admin (15001)", "the host of --admin (10.0.0.5)"}},
		"unparseable url":        {"::bad", "http://127.0.0.1:15000", emitted, nil},
		"hostile emitted value": {"http://127.0.0.1:3000/s1/mcp", "http://127.0.0.1:15000", func() configDoc {
			d := emitted
			d.gateways = map[string]gatewayConfig{"toolwarrant": {bindAddress: "127.0.0.1", port: "3000" + esc}}
			return d
		}(), []string{`the port of --url (3000) is not the serving port of the emitted gateway toolwarrant (3000\u{001B}); the listing above went through another listener`}},
		"admin off": {"http://127.0.0.1:3000/s1/mcp", "http://127.0.0.1:15000", func() configDoc {
			d := emitted
			d.listeners = listenerConfig{adminAddr: "off"}
			return d
		}(), []string{"the emitted file sets adminAddr to off, so no admin API of that gateway answered --admin (127.0.0.1:15000); the live configuration above came from another process"}},
		"wildcard bind, other host": {"http://10.0.0.5:3000/s1/mcp", "http://127.0.0.1:15000", func() configDoc {
			d := emitted
			d.gateways = map[string]gatewayConfig{"toolwarrant": {bindAddress: "0.0.0.0", port: "3000"}}
			return d
		}(), nil},
		"ipv6 wildcard bind, loopback literal": {"http://127.0.0.1:3000/s1/mcp", "http://127.0.0.1:15000", func() configDoc {
			d := emitted
			d.gateways = map[string]gatewayConfig{"toolwarrant": {bindAddress: "::", port: "3000"}}
			return d
		}(), nil},
		"no route": {"http://10.0.0.5:3001/s1/mcp", "http://10.0.0.5:15001", configDoc{gateways: emitted.gateways}, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			diffs := compareCanaryAddresses(tc.emitted, "s1", tc.url, tc.admin)
			if len(diffs) != len(tc.want) {
				t.Errorf("got %d difference(s), want %d:\n%s", len(diffs), len(tc.want), strings.Join(diffs, "\n"))
			}
			all := strings.Join(diffs, "\n")
			for _, want := range tc.want {
				wantContains(t, "diffs", all, want)
			}
			wantNotContains(t, "diffs", all, esc)
		})
	}
}
