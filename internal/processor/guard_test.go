package processor

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// mustStruct builds an arbitrary metadata_context.
func mustStruct(t *testing.T, fields map[string]any) *structpb.Struct {
	t.Helper()
	md, err := structpb.NewStruct(fields)
	if err != nil {
		t.Fatalf("structpb.NewStruct: %v", err)
	}
	return md
}

// testSecret is the shared value the tests configure; it is assembled at run
// time so no test file carries a credential-shaped literal.
func testSecret() string {
	return strings.Join([]string{"unit", "test", "shared", "value"}, "-")
}

// withSecret configures the processor to require testSecret on every hook.
func withSecret(c *Config) { c.Secret = testSecret() }

// D2: the gateway names the backend a hook is about in service_names, and one
// processor address belongs to exactly one upstream. A hook about any other
// backend, about several or about none is refused before the catalog is read,
// and leaves no evidence behind. Before D2 every one of these was judged with
// this server's approvals.
func TestAdmit_HooksAboutAnotherBackendAreDenied(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	cases := map[string][]string{
		"no service names":   nil,
		"empty list":         {},
		"another backend":    {"other"},
		"this and another":   {testServer, "other"},
		"this backend twice": {testServer, testServer},
		"empty name":         {""},
		"case variant":       {strings.ToUpper(testServer)},
		"longer name":        {testServer + "2"},
	}
	for name, services := range cases {
		t.Run(name, func(t *testing.T) {
			src := newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)})
			s, _ := newTestServer(src)

			req := &api.McpRequest{Method: methodToolsCall, ServiceNames: services, McpRequest: []byte(`{"name":"echo"}`)}
			res := call(t, s, req)
			requireRefused(t, res, api.AuthorizationError_PERMISSION_DENIED, causeWrongBackend)
			if got := res.GetError().GetReason(); got != "tools/call denied: wrong backend" {
				t.Errorf("call reason = %q", got)
			}
			resp := &api.McpResponse{Method: methodToolsList, ServiceNames: services, McpResponse: listBody("", echoV1)}
			e := requireListDenied(t, listVia(t, s, resp), api.AuthorizationError_PERMISSION_DENIED)
			if got := e.GetReason(); got != "tools/list denied: wrong backend" {
				t.Errorf("list reason = %q", got)
			}

			st := s.Stats()
			if st.WrongBackend != 2 || st.CallsDenied != 1 || st.ListsDenied != 1 || st.CallsAllowed != 0 || st.ListsServed != 0 {
				t.Errorf("stats = %+v", st)
			}
			if g, sn := src.calls(); g != 0 || sn != 0 {
				t.Errorf("a hook about another backend read the catalog (%d generation, %d snapshot calls)", g, sn)
			}
			if _, ok := s.observedDigest("echo"); ok {
				t.Error("a list for another backend left evidence behind")
			}
		})
	}
}

// Only the first mismatch is logged, at Debug, with the exact value the
// gateway sent, so an operator can fix Target without the log being flooded.
func TestAdmit_FirstWrongBackendIsLoggedOnce(t *testing.T) {
	s, logs := newTestServer(newFakeSource(nil))
	req := &api.McpRequest{Method: methodToolsCall, ServiceNames: []string{"other\nbackend", "x"}, McpRequest: []byte(`{"name":"echo"}`)}
	for i := 0; i < 5; i++ {
		requireRefused(t, call(t, s, req), api.AuthorizationError_PERMISSION_DENIED, causeWrongBackend)
	}
	out := logs.String()
	if n := strings.Count(out, `level=DEBUG msg="hook names another backend"`); n != 1 {
		t.Errorf("the first mismatch should be logged exactly once at Debug, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, `other\\nbackend`) || !strings.Contains(out, `target="\"mock\""`) {
		t.Errorf("the log should carry the quoted names and the target:\n%s", out)
	}
	// Five denials and one debug line: a name cannot inject a sixth record.
	if lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n"); len(lines) != 6 {
		t.Errorf("got %d log lines, want 6:\n%s", len(lines), out)
	}
}

// Target overrides the server name when the gateway's route calls the backend
// something else; the server's own name is then the wrong backend.
func TestAdmit_TargetMayDifferFromTheServerName(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}), func(c *Config) { c.Target = "route-7" })

	requireRefused(t, call(t, s, callReq("echo")), api.AuthorizationError_PERMISSION_DENIED, causeWrongBackend)
	req := &api.McpRequest{Method: methodToolsCall, ServiceNames: []string{"route-7"}, McpRequest: []byte(`{"name":"echo"}`)}
	requireAllowed(t, call(t, s, req))
	resp := &api.McpResponse{Method: methodToolsList, ServiceNames: []string{"route-7"}, McpResponse: listBody("", echoV1)}
	if got := servedNames(t, listVia(t, s, resp)); len(got) != 1 || got[0] != "echo" {
		t.Fatalf("served %v, want [echo]", got)
	}
}

// Methods the processor does not judge pass whatever service_names says: the
// backend only matters for a decision this processor makes.
func TestAdmit_PassThroughMethodsIgnoreServiceNames(t *testing.T) {
	src := newFakeSource(nil)
	s, _ := newTestServer(src)
	for _, services := range [][]string{nil, {"other"}, {testServer, "other"}} {
		res, err := s.CheckRequest(context.Background(), &api.McpRequest{Method: "initialize", ServiceNames: services})
		if err != nil || res.GetPass() == nil {
			t.Errorf("initialize with service_names %q: %v, %v; want Pass", services, res, err)
		}
		rr, err := s.CheckResponse(context.Background(), &api.McpResponse{Method: "resources/list", ServiceNames: services, McpResponse: []byte(`{}`)})
		if err != nil || rr.GetPass() == nil {
			t.Errorf("resources/list with service_names %q: %v, %v; want Pass", services, rr, err)
		}
	}
	if st := s.Stats(); st.WrongBackend != 0 {
		t.Errorf("stats = %+v", st)
	}
}

// The reviewers' reproduction. Two upstreams, one processor started for
// "alpha"; the route for "beta" points at the same processor (which the
// emitter now refuses, but a hand-written gateway configuration still can) and
// reports service_names=["beta"]. beta's echo is unapproved, alpha's is
// approved and crawled. Before D2 the beta call passed at cold start and again
// whenever alpha's clients had listed last.
func TestAdmit_AnotherRoutesCallNeverRidesOnThisServersApproval(t *testing.T) {
	alphaEcho := tool("echo", "alpha's harmless echo")
	betaEcho := tool("echo", "beta's echo: exfiltrates ~/.ssh")
	dAlpha, dBeta := mustDigest(t, alphaEcho), mustDigest(t, betaEcho)
	alpha := newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(dAlpha)})
	s, _ := newTestServer(alpha, func(c *Config) { c.Server = "alpha" })

	// The catalog's view of beta, which a correctly wired processor would use.
	beta := catalog.Snapshot{Server: "beta", Tools: map[string]catalog.ToolPolicy{"echo": policy(lifecycle.PendingReview, "", dBeta)}}
	if beta.Serves("echo", dBeta) {
		t.Fatal("setup: beta's echo must not be servable")
	}
	callOn := func(route string) *api.McpRequestResult {
		return call(t, s, &api.McpRequest{Method: methodToolsCall, ServiceNames: []string{route}, McpRequest: []byte(`{"name":"echo","arguments":{}}`)})
	}
	listOn := func(route string, def []byte) *api.McpResponseResult {
		return listVia(t, s, &api.McpResponse{Method: methodToolsList, ServiceNames: []string{route}, McpResponse: listBody("", def)})
	}

	// 1. Cold start: a call on beta's route before any list.
	requireRefused(t, callOn("beta"), api.AuthorizationError_PERMISSION_DENIED, causeWrongBackend)
	// 2. beta's own list is refused, not filtered with alpha's approvals.
	requireListDenied(t, listOn("beta", betaEcho), api.AuthorizationError_PERMISSION_DENIED)
	// 3. alpha's clients list (the normal traffic); beta's call stays refused.
	if got := servedNames(t, listOn("alpha", alphaEcho)); len(got) != 1 || got[0] != "echo" {
		t.Fatalf("alpha's list served %v", got)
	}
	requireRefused(t, callOn("beta"), api.AuthorizationError_PERMISSION_DENIED, causeWrongBackend)
	requireAllowed(t, callOn("alpha"))
	if st := s.Stats(); st.WrongBackend != 3 || st.CallsAllowed != 1 {
		t.Errorf("stats = %+v", st)
	}
}

// D8: with Config.Secret set, every hook must carry the value as the string
// field SecretMetadataKey of its metadata_context, where the gateway puts the
// CEL string literal from the processor's metadata entry. Anything else is
// somebody else's hook: refused before the catalog or the payload is touched,
// including methods the processor would otherwise pass through.
func TestAdmit_SharedSecretIsRequiredOnEveryHook(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	want := testSecret()
	cases := map[string]*structpb.Struct{
		"no metadata":           nil,
		"empty metadata":        mustStruct(t, map[string]any{}),
		"wrong value":           secretMeta(t, "wrong"),
		"empty value":           secretMeta(t, ""),
		"a prefix of the value": secretMeta(t, want[:5]),
		"the value plus a byte": secretMeta(t, want+"x"),
		"a number":              secretMeta(t, 42),
		"null":                  secretMeta(t, nil),
		"the value in a list":   secretMeta(t, []any{want}),
		"under another key":     mustStruct(t, map[string]any{"other_key": want}),
	}
	for name, md := range cases {
		t.Run(name, func(t *testing.T) {
			src := newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)})
			s, _ := newTestServer(src, withSecret)

			req := callReq("echo")
			req.MetadataContext = md
			requireRefused(t, call(t, s, req), api.AuthorizationError_PERMISSION_DENIED, causeUnauthenticated)
			resp := listMsg(listBody("", echoV1))
			resp.MetadataContext = md
			e := requireListDenied(t, listVia(t, s, resp), api.AuthorizationError_PERMISSION_DENIED)
			if !strings.Contains(e.GetReason(), string(causeUnauthenticated)) {
				t.Errorf("list reason = %q", e.GetReason())
			}
			other, err := s.CheckRequest(context.Background(), &api.McpRequest{Method: "initialize", MetadataContext: md})
			if err != nil || other.GetError() == nil || other.GetError().GetCode() != api.AuthorizationError_PERMISSION_DENIED {
				t.Errorf("initialize without the shared value: %v, %v; want PERMISSION_DENIED", other, err)
			} else if got := other.GetError().GetReason(); got != "hook denied: "+string(causeUnauthenticated) {
				t.Errorf("reason = %q", got)
			}

			if st := s.Stats(); st.Unauthenticated != 3 || st.CallsDenied != 1 || st.ListsDenied != 1 || st.WrongBackend != 0 {
				t.Errorf("stats = %+v", st)
			}
			if g, sn := src.calls(); g != 0 || sn != 0 {
				t.Errorf("an unauthenticated hook read the catalog (%d generation, %d snapshot calls)", g, sn)
			}
			if _, ok := s.observedDigest("echo"); ok {
				t.Error("an unauthenticated list left evidence behind")
			}
		})
	}
}

func TestAdmit_TheRightSecretAdmitsTheHook(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}), withSecret)

	resp := listMsg(listBody("", echoV1))
	resp.MetadataContext = secretMeta(t, testSecret())
	if got := servedNames(t, listVia(t, s, resp)); len(got) != 1 || got[0] != "echo" {
		t.Fatalf("served %v, want [echo]", got)
	}
	req := callReq("echo")
	req.MetadataContext = secretMeta(t, testSecret())
	requireAllowed(t, call(t, s, req))
	other, err := s.CheckRequest(context.Background(), &api.McpRequest{Method: "initialize", MetadataContext: secretMeta(t, testSecret())})
	if err != nil || other.GetPass() == nil {
		t.Errorf("initialize with the shared value: %v, %v; want Pass", other, err)
	}
	// Other metadata the gateway adds does not matter.
	req.MetadataContext = mustStruct(t, map[string]any{SecretMetadataKey: testSecret(), "trace": "abc", "n": 1})
	requireAllowed(t, call(t, s, req))
	if st := s.Stats(); st.Unauthenticated != 0 || st.CallsAllowed != 2 || st.ListsServed != 1 {
		t.Errorf("stats = %+v", st)
	}
}

// Without a configured value the metadata is not looked at, which is only safe
// on a listener nobody but the gateway can reach (see Serve).
func TestAdmit_NoSecretConfiguredMeansNoCheck(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}))
	req := callReq("echo")
	req.MetadataContext = secretMeta(t, "anything")
	requireAllowed(t, call(t, s, req))
	requireAllowed(t, call(t, s, callReq("echo")))
	if st := s.Stats(); st.Unauthenticated != 0 {
		t.Errorf("stats = %+v", st)
	}
}

// The shared value is checked before the backend name, so a caller without it
// learns nothing about which backend this processor guards.
func TestAdmit_SecretIsCheckedBeforeTheBackend(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	s, logs := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}), withSecret)
	req := &api.McpRequest{Method: methodToolsCall, ServiceNames: []string{"other"}, McpRequest: []byte(`{"name":"echo"}`)}
	requireRefused(t, call(t, s, req), api.AuthorizationError_PERMISSION_DENIED, causeUnauthenticated)
	if st := s.Stats(); st.Unauthenticated != 1 || st.WrongBackend != 0 {
		t.Errorf("stats = %+v", st)
	}
	if strings.Contains(logs.String(), "another backend") {
		t.Errorf("the backend was examined before the shared value:\n%s", logs.String())
	}
}
