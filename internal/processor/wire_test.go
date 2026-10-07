package processor

import (
	"encoding/base64"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
)

// The gateway evaluates each processors[].metadata entry as CEL once per
// request and sends the results as metadata_context, "one field per config
// key" (the proto comment; .cache/ref/config.md, processors[].metadata). emit
// writes the entry SecretMetadataKey as a CEL string literal, so what reaches
// the processor is a google.protobuf.Struct with one string field of that
// name. These tests build exactly that message in the two shapes the proto
// defines, protobuf JSON and the binary form gRPC carries, so the path from
// the wire to the secret check is covered without running the gateway.

// b64 renders bytes the way protobuf JSON renders a bytes field.
func b64(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

// wireCall is the protobuf JSON of a tools/call hook for the guarded route;
// meta is the metadata_context member, or "" for none.
func wireCall(meta string) string {
	return `{"service_names":[` + q(testServer) + `],"method":"tools/call"` + member("metadata_context", meta) +
		`,"mcp_request":` + q(b64([]byte(`{"name":"echo","arguments":{}}`))) + `}`
}

// wireList is the protobuf JSON of a tools/list hook carrying one page.
func wireList(meta string, page []byte) string {
	return `{"service_names":[` + q(testServer) + `],"method":"tools/list"` + member("metadata_context", meta) +
		`,"mcp_response":` + q(b64(page)) + `}`
}

func member(key, value string) string {
	if value == "" {
		return ""
	}
	return `,` + q(key) + `:` + value
}

// metaWith is a metadata_context with one string field.
func metaWith(key, value string) string {
	return `{` + q(key) + `:` + q(value) + `}`
}

func decodeCall(t *testing.T, wire string) *api.McpRequest {
	t.Helper()
	var req api.McpRequest
	if err := protojson.Unmarshal([]byte(wire), &req); err != nil {
		t.Fatalf("protojson.Unmarshal(%s): %v", wire, err)
	}
	return &req
}

func decodeList(t *testing.T, wire string) *api.McpResponse {
	t.Helper()
	var resp api.McpResponse
	if err := protojson.Unmarshal([]byte(wire), &resp); err != nil {
		t.Fatalf("protojson.Unmarshal(%s): %v", wire, err)
	}
	return &resp
}

// roundTrip re-encodes a message in the binary wire form gRPC carries and
// decodes it again through the generated code.
func roundTrip(t *testing.T, in, out proto.Message) {
	t.Helper()
	wire, err := proto.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(wire, out); err != nil {
		t.Fatal(err)
	}
}

// D8 on the wire: the secret is read from metadata_context, field 3 of both
// McpRequest and McpResponse, in both encodings.
func TestWire_SecretIsReadFromMetadataContextOnBothHooks(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	src := newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)})
	s, _ := newTestServer(src, withSecret)
	meta := metaWith(SecretMetadataKey, testSecret())

	req := decodeCall(t, wireCall(meta))
	requireAllowed(t, call(t, s, req))
	resp := decodeList(t, wireList(meta, listBody("", echoV1)))
	if got := servedNames(t, listVia(t, s, resp)); len(got) != 1 || got[0] != "echo" {
		t.Fatalf("served %v, want [echo]", got)
	}

	var binReq api.McpRequest
	roundTrip(t, req, &binReq)
	requireAllowed(t, call(t, s, &binReq))
	var binResp api.McpResponse
	roundTrip(t, resp, &binResp)
	if got := servedNames(t, listVia(t, s, &binResp)); len(got) != 1 || got[0] != "echo" {
		t.Fatalf("served %v over the binary shape, want [echo]", got)
	}
	if st := s.Stats(); st.Unauthenticated != 0 || st.CallsAllowed != 2 || st.ListsServed != 2 {
		t.Errorf("stats = %+v", st)
	}
}

// What the gateway would send under a wrong configuration is refused before
// the catalog is read: no metadata at all, an empty Struct, the value under
// another key, and the CEL literal delivered unevaluated (the quotes emit
// writes for CEL still around the value).
func TestWire_MetadataWithoutTheSecretIsRefused(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	cases := map[string]string{
		"no metadata_context":    "",
		"empty metadata_context": `{}`,
		"under another key":      metaWith("secret", testSecret()),
		"the CEL literal itself": metaWith(SecretMetadataKey, `"`+testSecret()+`"`),
		"a different value":      metaWith(SecretMetadataKey, testSecret()+"x"),
	}
	for name, meta := range cases {
		t.Run(name, func(t *testing.T) {
			src := newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)})
			s, _ := newTestServer(src, withSecret)
			requireRefused(t, call(t, s, decodeCall(t, wireCall(meta))), api.AuthorizationError_PERMISSION_DENIED, causeUnauthenticated)
			requireListDenied(t, listVia(t, s, decodeList(t, wireList(meta, listBody("", echoV1)))), api.AuthorizationError_PERMISSION_DENIED)
			if st := s.Stats(); st.Unauthenticated != 2 || st.CallsAllowed != 0 || st.ListsServed != 0 {
				t.Errorf("stats = %+v", st)
			}
			if g, sn := src.calls(); g != 0 || sn != 0 {
				t.Errorf("an unauthenticated hook read the catalog (%d generation, %d snapshot calls)", g, sn)
			}
		})
	}
}

// The key is shared with internal/emit, which writes the same literal under
// processors[].metadata; changing either side alone would lock the gateway
// out of its own processor.
func TestWire_SecretMetadataKeyIsTheOneEmitWrites(t *testing.T) {
	if SecretMetadataKey != "toolwarrant_secret" {
		t.Fatalf("SecretMetadataKey = %q; emit writes toolwarrant_secret", SecretMetadataKey)
	}
}
