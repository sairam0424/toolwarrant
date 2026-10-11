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

// benchCatalog builds n approved tools and the policy that serves them.
func benchCatalog(b *testing.B, n int) ([][]byte, map[string]catalog.ToolPolicy) {
	b.Helper()
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
	return tools, policies
}

func benchServer(policies map[string]catalog.ToolPolicy) *Server {
	return New(newFakeSource(policies), Config{Server: testServer, Logger: slog.New(slog.DiscardHandler)})
}

// BenchmarkCheckResponse100Tools measures one fully approved 100-tool page:
// two passes over 100 names, 100 digests, 100 catalog lookups and one
// re-encode.
func BenchmarkCheckResponse100Tools(b *testing.B) {
	tools, policies := benchCatalog(b, 100)
	s := benchServer(policies)
	req := listMsg(listBody("next", tools...))
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

// BenchmarkCheckResponse10kUnknownTools measures the two-pass filter on the
// cheapest hostile page: the per-page cap of tiny tools the catalog does not
// know, plus one approved tool. Pass one reads names only; pass two hides every
// unknown tool without hashing it, so the cost is parsing, twice.
func BenchmarkCheckResponse10kUnknownTools(b *testing.B) {
	tools := make([][]byte, 0, maxToolsPerPage)
	for i := 0; i < maxToolsPerPage-1; i++ {
		tools = append(tools, []byte(fmt.Sprintf(`{"name":"u%d"}`, i)))
	}
	tools = append(tools, echoV1)
	d, err := gate.Digest(echoV1)
	if err != nil {
		b.Fatal(err)
	}
	s := benchServer(map[string]catalog.ToolPolicy{"echo": servedPolicy(d)})
	req := listMsg(listBody("", tools...))
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

// BenchmarkCheckResponseDuplicateDenied measures a page refused in pass one:
// 100 approved tools with the first name repeated at the end, so the page is
// denied after the name scan and nothing is hashed.
func BenchmarkCheckResponseDuplicateDenied(b *testing.B) {
	tools, policies := benchCatalog(b, 100)
	page := append(append([][]byte{}, tools...), tools[0])
	s := benchServer(policies)
	req := listMsg(listBody("", page...))
	ctx := context.Background()

	b.ReportAllocs()
	b.SetBytes(int64(len(req.McpResponse)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := s.CheckResponse(ctx, req)
		if err != nil || res.GetError() == nil {
			b.Fatalf("result %v, err %v", res, err)
		}
	}
}

// BenchmarkCheckResponse100ToolsUncached is the same page through a one-entry
// digest cache, so every tool misses and is canonicalised: the per-page cost
// before F4, kept as the control the cached number is compared with.
func BenchmarkCheckResponse100ToolsUncached(b *testing.B) {
	tools, policies := benchCatalog(b, 100)
	s := benchServer(policies)
	s.digests = newDigestCache(1)
	req := listMsg(listBody("next", tools...))
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
	s := benchServer(map[string]catalog.ToolPolicy{"echo": servedPolicy(d)})
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

// Compile-time use of the hook message types the benchmarks build.
var _ *api.McpResponse = listMsg(nil)

// overCapTinyPage is a tools/list page of about one mebibyte of tiny unique
// entries, about seven times maxToolsPerPage: the cheapest page an upstream can
// send that the processor must refuse. The fourth review used it to measure
// what one denied hook allocates.
func overCapTinyPage() []byte {
	var sb strings.Builder
	sb.WriteString(`{"tools":[`)
	for i := 0; sb.Len() < 1<<20; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"name":"n%d"}`, i)
	}
	sb.WriteString("]}")
	return []byte(sb.String())
}

// BenchmarkCheckResponseOverCapTinyNames measures one hook on overCapTinyPage.
// Before D14(g) the whole tools array was materialised before the per-page cap
// was checked and the hook allocated about eighteen times the payload; now the
// scan stops at the cap before any name is read, so B/op is the figure
// limits.go states for a refused page.
func BenchmarkCheckResponseOverCapTinyNames(b *testing.B) {
	d, err := gate.Digest(echoV1)
	if err != nil {
		b.Fatal(err)
	}
	s := benchServer(map[string]catalog.ToolPolicy{"echo": servedPolicy(d)})
	req := listMsg(overCapTinyPage())
	ctx := context.Background()

	b.ReportAllocs()
	b.SetBytes(int64(len(req.McpResponse)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := s.CheckResponse(ctx, req)
		if err != nil || res.GetError() == nil {
			b.Fatalf("result %v, err %v", res, err)
		}
	}
}
