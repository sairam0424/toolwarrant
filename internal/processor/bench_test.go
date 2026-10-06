package processor

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
	"github.com/sairam0424/toolwarrant/internal/gate"
)

// benchTool is a realistic tool definition of roughly 0.9 KB, the size the
// seam measurements used, so the numbers compare with seam/RESULTS.md.
func benchTool(i int) []byte {
	desc := strings.Repeat("Does one useful thing and reports the result. ", 12)
	return []byte(fmt.Sprintf(
		`{"name":"tool_%03d","description":%s,"inputSchema":{"type":"object","properties":{`+
			`"query":{"type":"string","description":"what to look for"},`+
			`"limit":{"type":"integer","minimum":1,"maximum":100},`+
			`"cursor":{"type":"string"},"verbose":{"type":"boolean"}},"required":["query"]},`+
			`"annotations":{"readOnlyHint":true,"idempotentHint":true}}`, i, q(desc)))
}

// BenchmarkCheckResponse100Tools measures one fully approved 100-tool page:
// 100 digests, 100 catalog lookups and one re-encode.
func BenchmarkCheckResponse100Tools(b *testing.B) {
	const n = 100
	tools := make([][]byte, n)
	policies := make(map[string]catalog.ToolPolicy, n)
	for i := 0; i < n; i++ {
		tools[i] = benchTool(i)
		d, err := gate.Digest(tools[i])
		if err != nil {
			b.Fatal(err)
		}
		policies[fmt.Sprintf("tool_%03d", i)] = servedPolicy(d)
	}
	s := New(newFakeSource(policies), Config{Server: testServer, Logger: slog.New(slog.DiscardHandler)})
	req := &api.McpResponse{Method: "tools/list", McpResponse: listBody("next", tools...)}
	ctx := context.Background()

	b.ReportAllocs()
	b.SetBytes(int64(len(req.McpResponse)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := s.CheckResponse(ctx, req)
		if err != nil || res.GetMutated() == nil {
			b.Fatalf("result %v, err %v", res, err)
		}
	}
}

// BenchmarkCheckRequest is the per-call cost on the hot path.
func BenchmarkCheckRequest(b *testing.B) {
	d, err := gate.Digest(echoV1)
	if err != nil {
		b.Fatal(err)
	}
	s := New(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d)}),
		Config{Server: testServer, Logger: slog.New(slog.DiscardHandler)})
	req := callReq("echo")
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if res, err := s.CheckRequest(ctx, req); err != nil || res.GetPass() == nil {
			b.Fatalf("result %v, err %v", res, err)
		}
	}
}
