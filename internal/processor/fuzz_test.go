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
// and any list it does return may only contain tools the catalog serves.
func FuzzCheckResponse(f *testing.F) {
	seeds := []string{
		`{"tools":[]}`,
		string(listBody("c", echoV1, echoV2, tool("off", "x"), tool("zzz", "y"))),
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
		res, err := s.CheckResponse(context.Background(), &api.McpResponse{Method: "tools/list", McpResponse: body})
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
		for _, raw := range out.Tools {
			var head struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(raw, &head); err != nil {
				t.Fatalf("served tool is unreadable: %q", raw)
			}
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
		res, err := s.CheckRequest(context.Background(), &api.McpRequest{Method: "tools/call", McpRequest: params})
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

// FuzzVerifyKeys only asserts robustness: no panic, and whatever it accepts is
// a single JSON object.
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
