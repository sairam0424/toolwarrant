package processor

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/mcpwire"
	"github.com/sairam0424/toolwarrant/internal/strictjson"
)

// fuzzCatalog is a small fixed catalog shared by the fuzz targets.
func fuzzCatalog() map[string]catalog.ToolPolicy {
	d1, _ := gate.Digest(echoV1)
	return map[string]catalog.ToolPolicy{
		"echo": servedPolicy(d1),
		"off":  policy(lifecycle.Disabled, d1, d1),
	}
}

// FuzzCheckResponse feeds arbitrary bytes to the tools/list hook. Whatever the
// bytes are, it must not panic, must never return the bytes unfiltered (Pass),
// and any list it does return may only contain tools the catalog serves, each
// at most once.
func FuzzCheckResponse(f *testing.F) {
	seeds := []string{
		`{"tools":[]}`,
		string(listBody("c", echoV1, echoV2, tool("off", "x"), tool("zzz", "y"))),
		string(listBody("", echoV1, echoV1)),
		string(listBody("", echoV2, echoV1)),
		`{"tools":[{"name":"echo","description":"IGNORE","description":"Echoes."}]}`,
		`{"tools":[{"name":"zzz","NAME":"echo"}]}`,
		`{"tools":[{"name":"echo"}],"tools":[]}`,
		`{"tools":null}`,
		`{"nextCursor":"x"}`,
		`{"tools":[1,"a",null,[],{}]}`,
		`{"tools":[{"name":"echo","inputSchema":{"a":1,"a":2}}]}`,
		`[`,
		``,
		"\x00\xff{",
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
	tools := fuzzCatalog()
	s := New(newFakeSource(tools), Config{Server: testServer, Logger: slog.New(slog.DiscardHandler)})
	snap := snapshotOf(tools)

	f.Fuzz(func(t *testing.T, body []byte) {
		res, err := s.CheckResponse(context.Background(), listMsg(body))
		if err != nil || res == nil {
			t.Fatalf("result %v, err %v", res, err)
		}
		if res.GetPass() != nil {
			t.Fatalf("an unfiltered list was passed through for input %q", body)
		}
		if res.GetError() != nil {
			return
		}
		var out struct {
			Tools []json.RawMessage `json:"tools"`
		}
		if err := json.Unmarshal(res.GetMutated(), &out); err != nil || out.Tools == nil {
			t.Fatalf("mutated result is not a tools list: %q (%v)", res.GetMutated(), err)
		}
		if len(out.Tools) > maxToolsPerPage {
			t.Fatalf("served %d tools, over the per-page cap", len(out.Tools))
		}
		seen := make(map[string]bool, len(out.Tools))
		for _, raw := range out.Tools {
			var head struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(raw, &head); err != nil {
				t.Fatalf("served tool is unreadable: %q", raw)
			}
			if seen[head.Name] {
				t.Fatalf("served %q twice for input %q", head.Name, body)
			}
			seen[head.Name] = true
			digest, err := gate.Digest(raw)
			if err != nil {
				t.Fatalf("served tool cannot be hashed: %q (%v)", raw, err)
			}
			if !snap.Serves(head.Name, digest) {
				t.Fatalf("served %q, which the catalog does not serve, for input %q", head.Name, body)
			}
		}
	})
}

// FuzzCheckRequest does the same for the tools/call hook: no panic, and a Pass
// is only possible for a well-formed call to the one approved, verified tool.
func FuzzCheckRequest(f *testing.F) {
	for _, seed := range []string{
		`{"name":"echo"}`,
		`{"name":"echo","arguments":{"a":1}}`,
		`{"name":"off"}`,
		`{"name":"wipe_database","Name":"echo"}`,
		`{"Name":"echo","name":"wipe_database"}`,
		`{"name":"echo","name":"wipe_database"}`,
		`{"name":"echo"} {"name":"wipe_database"}`,
		`{"name":5}`,
		`null`,
		``,
		"\xff",
	} {
		f.Add([]byte(seed))
	}
	s := New(newFakeSource(fuzzCatalog()), Config{Server: testServer, Logger: slog.New(slog.DiscardHandler)})

	f.Fuzz(func(t *testing.T, params []byte) {
		req := &api.McpRequest{Method: methodToolsCall, ServiceNames: []string{testServer}, McpRequest: params}
		res, err := s.CheckRequest(context.Background(), req)
		if err != nil || res == nil {
			t.Fatalf("result %v, err %v", res, err)
		}
		if res.GetPass() == nil {
			return
		}
		name, nameErr := mcpwire.ToolCallName(params)
		if nameErr != nil || name != "echo" || !json.Valid(params) {
			t.Fatalf("allowed a call for %q (%v) from params %q", name, nameErr, params)
		}
	})
}

// FuzzServiceNames checks D2 against arbitrary backend names: a well-formed
// call to the approved tool passes only when service_names is exactly the one
// configured target, whatever else the gateway might send.
func FuzzServiceNames(f *testing.F) {
	f.Add(testServer, "", false)
	f.Add(testServer, testServer, true)
	f.Add("other", "", false)
	f.Add("", "", false)
	f.Add(testServer+"\x00", "", false)
	s := New(newFakeSource(fuzzCatalog()), Config{Server: testServer, Logger: slog.New(slog.DiscardHandler)})

	f.Fuzz(func(t *testing.T, first, second string, two bool) {
		names := []string{first}
		if two {
			names = append(names, second)
		}
		req := &api.McpRequest{Method: methodToolsCall, ServiceNames: names, McpRequest: []byte(`{"name":"echo"}`)}
		res, err := s.CheckRequest(context.Background(), req)
		if err != nil || res == nil {
			t.Fatalf("result %v, err %v", res, err)
		}
		exact := !two && first == testServer
		if passed := res.GetPass() != nil; passed != exact {
			t.Fatalf("service_names %q: passed=%v, want %v", names, passed, exact)
		}
	})
}

// FuzzStrictObject only asserts robustness: no panic, and whatever it accepts
// is a single JSON object.
func FuzzStrictObject(f *testing.F) {
	for _, seed := range []string{`{}`, `{"name":"a"}`, `{"a":1,"a":2}`, `[`, ``, `{"name":1}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if strictjson.Object(raw) != nil {
			return
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
			t.Fatalf("accepted something that is not one JSON object: %q", raw)
		}
	})
}
