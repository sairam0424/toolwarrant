package main

import (
	"context"
	"maps"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/emit"
	"github.com/sairam0424/toolwarrant/internal/fetch"
)

// The emitted-file reader is pinned to what internal/emit writes today: a
// freshly emitted file with a shared secret and two servers, one of them with
// the backendTLS block, yields every gateway and every route with exactly the
// fields the comparison needs, and never the secret.
func TestEmittedConfigReadsWhatEmitWrites(t *testing.T) {
	out, err := emit.AgentGateway(emit.Input{ListenPort: 8080, BindAddress: "::1", Servers: []emit.Server{
		{Name: "beta", URL: "http://127.0.0.1:3002/mcp?q=" + plant("query"), ProcessorAddr: "127.0.0.1:9002", Secret: plant("shared"), ApprovedTools: []string{"b"}},
		{Name: "alpha", URL: "http://127.0.0.1:3001/mcp", ProcessorAddr: "127.0.0.1:9001", Secret: plant("shared"), ApprovedTools: []string{"x", "a"},
			TLS: &emit.ProcessorTLS{Cert: tlsCertPath, Key: tlsKeyPath, Root: tlsRootPath, Hostname: tlsHostname}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := emittedConfig(out.YAML)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.gateways) != 1 || doc.gateways["toolwarrant"] != (gatewayConfig{bindAddress: "::1", port: "8080"}) {
		t.Errorf("gateways: %+v", doc.gateways)
	}
	if len(doc.routes) != 2 || doc.routes[0].name != "alpha" || doc.routes[1].name != "beta" {
		t.Fatalf("routes: %+v", doc.routes)
	}
	rc, n := doc.route("alpha")
	if n != 1 || rc.gateway != "toolwarrant" || joinPaths(rc.paths) != "/alpha/mcp" || len(rc.rules) != 1 || rc.rules[0] != `mcp.tool.name == "a" || mcp.tool.name == "x"` {
		t.Errorf("route alpha: %d %+v", n, rc)
	}
	if len(rc.processors) != 1 || rc.processors[0].host != "127.0.0.1:9001" || rc.processors[0].kind != "remote" || rc.processors[0].failureMode != "failClosed" ||
		describeMethods(rc.processors[0].methods) != "tools/call=request,tools/list=response" {
		t.Errorf("processor: %+v", rc.processors)
	}
	// The block emit writes for alpha (D19) is read as the four fields the
	// comparison compares, and beta's entry, emitted without one, keeps a nil
	// map, so a file without the block compares as it did before the block
	// was read (TestEmittedConfigReadsTheProcessorTLS pins the hand-built
	// shapes; this is the real emitted block).
	wantTLS := map[string]string{keyTLSCert: tlsCertPath, keyTLSKey: tlsKeyPath, keyTLSRoot: tlsRootPath, keyTLSHostname: tlsHostname}
	if len(rc.processors) == 1 && !maps.Equal(rc.processors[0].tls, wantTLS) {
		t.Errorf("the emitted backendTLS block reads as %q, want %q", rc.processors[0].tls, wantTLS)
	}
	if !strings.Contains(string(out.YAML), tlsBlock(tlsCertPath, tlsKeyPath, tlsRootPath, tlsHostname)+"        metadata:\n") {
		t.Errorf("emit does not write the block where the reader expects it:\n%s", out.YAML)
	}
	if len(rc.backendHosts) != 1 || rc.backendHosts[0] != "http://127.0.0.1:3001/mcp" || len(rc.backendTargets) != 1 || rc.backendTargets[0] != "alpha" {
		t.Errorf("backends: %q %q", rc.backendTargets, rc.backendHosts)
	}
	beta, n := doc.route("beta")
	if n != 1 || len(beta.backendHosts) != 1 || !strings.Contains(beta.backendHosts[0], plant("query")) || len(beta.processors) != 1 || beta.processors[0].host != "127.0.0.1:9002" || beta.processors[0].tls != nil {
		t.Errorf("route beta: %d %+v", n, beta)
	}
	for _, p := range beta.processors {
		for k, v := range p.methods {
			if strings.Contains(k, canary) || strings.Contains(v, canary) {
				t.Errorf("the shared secret was read into the methods: %q=%q", k, v)
			}
		}
	}
	if _, n := doc.route("gamma"); n != 0 {
		t.Errorf("absent route found %d time(s)", n)
	}
	if _, err := emittedRouteOf(doc, "gamma"); err == nil || !strings.Contains(err.Error(), "has no route for server gamma") {
		t.Errorf("absent route: %v", err)
	}
	for name, file := range map[string]string{
		"route twice":           "routes:\n- name: \"x\"\n- name: \"x\"\n",
		"gateway twice":         "gateways:\n  toolwarrant:\n    port: 1\n  toolwarrant:\n    port: 2\n",
		"unquoted scalar":       "routes:\n- name: x\n",
		"bad escape":            "routes:\n- name: \"x\\q\"\n",
		"unquoted bind":         "gateways:\n  toolwarrant:\n    bindAddress: 127.0.0.1\n",
		"item outside routes":   "config:\n- name: \"x\"\n",
		"key outside a gateway": "gateways:\n    port: 1\n",
		"unquoted gateway ref":  "routes:\n- name: \"x\"\n  gateways: toolwarrant\n",
		"unquoted path":         "routes:\n- name: \"x\"\n  matches:\n  - path:\n      exact: /x/mcp\n",
	} {
		if _, err := emittedConfig([]byte(file)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// route is a routeConfig for the comparison tests.
func route(name, gateway, path string, processors ...processorConfig) routeConfig {
	return routeConfig{name: name, gateway: gateway, paths: []string{path}, rules: []string{`mcp.tool.name == "echo"`}, processors: processors, backendHosts: []string{"http://127.0.0.1:1/mcp"}}
}

// Decision D13 (e): the comparison covers the whole document and names every
// difference once, with every live value escaped and no backend host shown.
func TestCompareDocumentsNamesEveryDifference(t *testing.T) {
	proc := processorConfig{host: "127.0.0.1:9001", kind: "remote", failureMode: "failClosed", methods: map[string]string{"tools/list": "response"}}
	emitted := configDoc{gateways: map[string]gatewayConfig{"toolwarrant": {bindAddress: "127.0.0.1", port: "3000"}},
		routes: []routeConfig{route("s1", "toolwarrant", "/s1/mcp", proc), route("s2", "toolwarrant", "/s2/mcp", proc)}}
	if diffs := compareDocuments(emitted, emitted, "s1", "/s1/mcp"); len(diffs) != 0 {
		t.Errorf("identical documents differ: %q", diffs)
	}
	cases := map[string]struct {
		live    func() configDoc
		urlPath string
		want    []string
	}{
		"gateway missing": {func() configDoc { d := emitted; d.gateways = map[string]gatewayConfig{}; return d }, "/s1/mcp",
			[]string{"gateway toolwarrant: not in the live configuration (emitted bind address 127.0.0.1, serving port 3000)"}},
		"gateway added": {func() configDoc {
			d := emitted
			d.gateways = map[string]gatewayConfig{"toolwarrant": emitted.gateways["toolwarrant"], "open": {bindAddress: "0.0.0.0", port: "3001"}}
			return d
		}, "/s1/mcp", []string{"gateway open: not in the emitted file (live bind address 0.0.0.0, serving port 3001); every route attached to it is served without the emitted guards"}},
		"gateway fields": {func() configDoc {
			d := emitted
			d.gateways = map[string]gatewayConfig{"toolwarrant": {bindAddress: "0.0.0.0", port: ""}}
			return d
		}, "/s1/mcp", []string{"gateway toolwarrant: bind address: emitted 127.0.0.1, live 0.0.0.0", "gateway toolwarrant: serving port: emitted 3000, live (none)"}},
		"route missing": {func() configDoc { d := emitted; d.routes = emitted.routes[:1]; return d }, "/s1/mcp",
			[]string{"route s2: not in the live configuration; its path /s2/mcp is served by nothing or by another route"}},
		"route twice": {func() configDoc {
			d := emitted
			d.routes = append(append([]routeConfig{}, emitted.routes...), emitted.routes[0])
			return d
		}, "/s1/mcp",
			[]string{"route s1: listed 2 times in the live configuration, so which one the gateway serves cannot be told", "path /s1/mcp: matched by 2 live routes (s1, s1)"}},
		"route added without a processor": {func() configDoc {
			d := emitted
			d.routes = append(append([]routeConfig{}, emitted.routes...), route("s1-shadow", "toolwarrant", "/s1/mcp"))
			return d
		}, "/s1/mcp", []string{"route s1-shadow: not in the emitted file (gateway toolwarrant, path /s1/mcp); the gateway serves it without the emitted guards", "path /s1/mcp: matched by 2 live routes (s1, s1-shadow)"}},
		"own route moved": {func() configDoc {
			d := emitted
			moved := route("s1", "other", "/s1/mcp-parked", proc)
			d.routes = []routeConfig{moved, emitted.routes[1]}
			return d
		}, "/s1/mcp", []string{"gateway: emitted toolwarrant, live other", "match path: emitted /s1/mcp, live /s1/mcp-parked"}},
		"other route edited": {func() configDoc {
			d := emitted
			edited := route("s2", "toolwarrant", "/s2/mcp")
			d.routes = []routeConfig{emitted.routes[0], edited}
			return d
		}, "/s1/mcp", []string{"route s2: processor: the live route has none (emitted 127.0.0.1:9001); every new session on this route is served by the allow rule alone"}},
		"prefix match": {func() configDoc {
			d := emitted
			prefixed := route("s1", "toolwarrant", nonExactPath, proc)
			d.routes = []routeConfig{prefixed, emitted.routes[1]}
			return d
		}, "/s1/mcp", []string{"match path: emitted /s1/mcp, live (not an exact path)"}},
		"url on another path": {func() configDoc { return emitted }, "/s1/other",
			[]string{"the path of --url (/s1/other) is not the match of the emitted route (/s1/mcp); the listing above tested another route"}},
		"url without a path": {func() configDoc { return emitted }, "",
			[]string{"the path of --url ((none)) is not the match of the emitted route (/s1/mcp)"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			diffs := compareDocuments(emitted, tc.live(), "s1", tc.urlPath)
			if len(diffs) != len(tc.want) {
				t.Errorf("got %d difference(s), want %d:\n%s", len(diffs), len(tc.want), strings.Join(diffs, "\n"))
			}
			for _, want := range tc.want {
				wantContains(t, "diffs", strings.Join(diffs, "\n"), want)
			}
		})
	}
}

// Live values are hostile until escaped, a route listed twice in the live
// document is never taken as the compared one, and the admin API client fails
// closed on an address it cannot reach.
func TestCompareRoutesEscapesAndFailsClosed(t *testing.T) {
	proc := processorConfig{host: "h:1", kind: "remote", failureMode: "failClosed", methods: map[string]string{"tools/list": "response"}}
	emitted := route("s1", "toolwarrant", "/s1/mcp", proc)
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
	hostile.paths = []string{"/s1/mcp" + esc + "[0m"}
	diffs := compareRoutes(emitted, hostile)
	if len(diffs) != 2 || !strings.Contains(diffs[0], `\u{001B}`) || !strings.Contains(diffs[1], `\u{001B}`) || strings.Contains(strings.Join(diffs, ""), esc) {
		t.Errorf("hostile route: %q", diffs)
	}
	live := configDoc{gateways: map[string]gatewayConfig{}, routes: []routeConfig{{name: "s1" + esc}, {name: "x"}, {name: "x"}}}
	all := strings.Join(compareDocuments(configDoc{gateways: map[string]gatewayConfig{}}, live, "s1", "/s1/mcp"), "\n")
	wantContains(t, "escaped names", all, `route s1\u{001B}: not in the emitted file`, "route x: not in the emitted file")
	wantNotContains(t, "escaped names", all, esc)
	if got := describeMethods(nil); got != noneShown {
		t.Errorf("describeMethods(nil) = %q", got)
	}
	doc := liveConfigDoc{Routes: []liveRouteDoc{{Name: "x"}, {Name: "x"}}}
	if _, n := doc.config().route("x"); n != 2 {
		t.Errorf("a route listed twice was counted %d time(s)", n)
	}
	bare := liveConfigDoc{Routes: []liveRouteDoc{{Name: "x", Gateways: "none"}}}.config()
	if rc, n := bare.route("x"); n != 1 || rc.gateway != "none" || rc.paths != nil || rc.rules != nil || rc.processors != nil {
		t.Errorf("route without matches or policies: %d %+v", n, rc)
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
	if got := routePathOf("http://127.0.0.1:3000/s1/mcp?x=1"); got != "/s1/mcp" {
		t.Errorf("routePathOf = %q", got)
	}
	if got := routePathOf("::bad"); got != "::bad" {
		t.Errorf("routePathOf(bad) = %q", got)
	}
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
	if err := v.compareLive(context.Background(), []byte("routes:\n- name: \"s1\"\n- name: \"s1\"\n"), &res); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("route twice: %v", err)
	}
	none := &verifier{}
	if err := none.compareLive(context.Background(), nil, &res); err != nil || res.live.compared || res.live.skipped != "" || res.live.diffs != nil {
		t.Errorf("without --admin: %v %+v", err, res.live)
	}
	wantContains(t, "skipped summaries", verdicts{live: liveCheck{skipped: liveSkippedEdited}}.summary(), "not what emit wrote")
	wantContains(t, "skipped summaries", verdicts{live: liveCheck{skipped: liveSkippedUnreadable}}.summary(), "could not be read")
}
