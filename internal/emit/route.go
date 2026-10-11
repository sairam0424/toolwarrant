package emit

// Route path pieces: a server is served at "/<Name>/mcp".
const (
	routePathPrefix = "/"
	routePathSuffix = "/mcp"
)

// The request-header filter written under every processor entry
// (processors[].requestHeaders). agentgateway forwards the HTTP headers of
// the client's MCP call to the processor in McpRequest.headers, after this
// filter; with no filter it forwards every header and every pseudo-header, so
// a client's bearer token or cookie would ride each hook across the
// gateway-to-processor link, which is plaintext gRPC (limit L11). The
// processor reads no header at all, so the allow list names one pseudo-header
// that carries nothing (an empty allow list means "forward everything", so a
// non-empty one is the only way to say "nothing"), and the deny list names
// the three credential headers as well, so that the file states what must
// never cross even to a reader who does not know what an allow list means to
// the gateway, and keeps saying it if a later gateway version read the allow
// list differently. The names are lowercase: the gateway matches
// pseudo-headers exactly and ordinary names case-insensitively.
const (
	forwardedPseudoHeader = ":method"
	headerAuthorization   = "authorization"
	headerCookie          = "cookie"
	headerProxyAuth       = "proxy-authorization"
)

// deniedHeaders is the deny list in file order. It is a function so that the
// package holds no mutable slice.
func deniedHeaders() []string {
	return []string{headerAuthorization, headerCookie, headerProxyAuth}
}

// writeRoute appends one route block. Every route names the gateway, so a
// route without that line is refused by the gateway rather than attached to a
// default. The allow rule is written unconditionally and comes first in the
// policies so a reader sees it.
func writeRoute(w *yamlWriter, s Server, allowed []string) {
	w.line(0, "- name: "+quote(s.Name))
	w.line(2, "gateways: "+quote(gatewayName))
	w.line(2, "matches:")
	w.line(2, "- path:")
	w.line(6, "exact: "+quote(routePath(s.Name)))
	w.line(2, "policies:")
	w.line(4, "mcpAuthorization:")
	w.line(6, "rules:")
	w.line(6, "- allow: "+quote(allowExpression(allowed)))
	w.line(4, "mcpGuardrails:")
	w.line(6, "processors:")
	writeProcessor(w, s)
	w.line(2, "backends:")
	w.line(2, "- mcp:")
	w.line(6, "targets:")
	w.line(6, "- name: "+quote(s.Name))
	w.line(8, "mcp:")
	w.line(10, "host: "+quote(s.URL))
}

// writeProcessor appends the one processor entry of a route: the address,
// failClosed, the request-header filter, the optional secret and the two
// hooked methods. The secret is a CEL string literal inside a YAML scalar,
// quoted once per layer, exactly like the tool names inside the allow rule.
// The filter comes before the metadata so the unconditional fields stay
// together and the secret line, when present, is still followed by methods.
func writeProcessor(w *yamlWriter, s Server) {
	w.line(6, "- host: "+quote(s.ProcessorAddr))
	w.line(8, "kind: "+quote("remote"))
	w.line(8, "failureMode: "+quote("failClosed"))
	w.line(8, "requestHeaders:")
	w.line(10, "allowed:")
	w.line(10, "- "+quote(forwardedPseudoHeader))
	w.line(10, "disallowed:")
	for _, name := range deniedHeaders() {
		w.line(10, "- "+quote(name))
	}
	if s.Secret != "" {
		w.line(8, "metadata:")
		w.line(10, SecretMetadataKey+": "+quote(quote(s.Secret)))
	}
	w.line(8, "methods:")
	w.line(10, "tools/call: "+quote("request"))
	w.line(10, "tools/list: "+quote("response"))
}

func routePath(name string) string {
	return routePathPrefix + name + routePathSuffix
}
