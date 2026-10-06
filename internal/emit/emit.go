// Package emit turns the catalog's approvals into agentgateway v1.6.0
// configuration. It is the only place that knows the gateway's config schema.
//
// The emitted file is defence in depth behind the toolwarrant processor, not
// the guard itself. The processor compares every served definition with the
// approved digest; the file only decides which routes exist, which tool names
// the gateway may show on each route, and which processor the gateway must
// consult. Within that role the file is built so that it cannot be weaker than
// intended:
//
//   - Every route carries an explicit mcpAuthorization allow rule, because in
//     agentgateway an empty rule set, or one that holds only deny rules, means
//     allow-all. A server with no approved tools gets an allow rule that can
//     never match, not an absent one.
//   - Every route names exactly one processor with failureMode failClosed, and
//     one processor address belongs to exactly one server, so a processor can
//     refuse hooks that name any other target.
//   - Every string that comes from the catalog is written as an escaped,
//     double-quoted scalar, so it cannot add keys, lines or CEL syntax.
//   - The gateway's admin, stats and readiness listeners are pinned to
//     loopback instead of the default wildcard binds.
//   - The header records the SHA-256 of the body and Verify tells an edited
//     file from a fresh one. The gateway reloads an edited file with a single
//     log line, and a route whose processor entry was removed fails open for
//     every new session, so the owner of the file must check it.
//
// What this package cannot do. The route bind listens on every interface: the
// schema has no bind address (binds[] accepts only port, protocol, listeners,
// tunnelProtocol and mode), so the operator must firewall the listen port or
// run the gateway in a private network. The CEL rules are checked for syntax
// by the gateway's --validate-only mode, which the tests run; their runtime
// effect (which methods they filter, how mcp.tool.name binds) is observable
// only with the gateway running as a server and is covered by the end-to-end
// test in cmd, not here. Processor addresses are limited to host:port: the
// schema describes processors[].host as "Hostname or IP address" and documents
// no unix:// or https:// form (--validate-only accepts both, but it also
// accepts unknown CEL variables, so that proves nothing); TLS towards a
// processor is the separate processors[].policies.backendTLS block, which this
// version does not write. The three listener addresses are constants, so the
// file does not support a second gateway on the same host or a metrics
// scraper on another host, and editing it by hand fails Verify. A secret is
// written into the file in clear, so a file that carries one must be readable
// by the gateway alone.
package emit

import (
	"slices"
	"strconv"
	"strings"
)

// Server is one upstream MCP server as the gateway should expose it.
type Server struct {
	// Name is the route name, the backend target name and therefore the target
	// the processor sees in every hook; the server is reachable at
	// "/<Name>/mcp". It must match ^[a-z0-9][a-z0-9_-]{0,62}$.
	Name string
	// URL is the upstream MCP endpoint (http or https).
	URL string
	// ProcessorAddr is the host:port of the toolwarrant ExtMCP processor that
	// enforces strict mode for this upstream. Every server needs its own,
	// because a processor serves exactly one target and denies the rest.
	ProcessorAddr string
	// Secret, when set, is sent to the processor with every hook as the
	// metadata entry SecretMetadataKey, so the processor can refuse hooks that
	// do not come from this gateway. It must be MinSecretLen-MaxSecretLen bytes
	// of printable ASCII. Empty means no secret is sent.
	Secret string
	// ApprovedTools are the names whose current definition is approved.
	// Order and duplicates do not matter.
	ApprovedTools []string
}

// Input is everything the emitter needs; the result depends on nothing else.
type Input struct {
	// ListenPort is the single port the gateway binds.
	ListenPort int
	// Servers lists the upstreams, in any order.
	Servers []Server
}

// Skipped records an approved tool that was left out of the allow rule
// because its name cannot be written safely. The tool stays hidden, which is
// the safe direction; the caller should surface it to an operator.
type Skipped struct {
	Server string
	Tool   string
	Reason string
}

// Output is the generated configuration plus what had to be left out.
type Output struct {
	// YAML is the gateway config, byte-for-byte deterministic for a given set
	// of servers regardless of input order.
	YAML []byte
	// BodyHash is the lowercase hex SHA-256 recorded in the header: the digest
	// of everything that follows the header. Verify recomputes it from a file.
	BodyHash string
	// Skipped lists approved tools that were not emitted, sorted by server
	// then tool.
	Skipped []Skipped
}

// SecretMetadataKey is the processor metadata entry that carries
// Server.Secret. The processor reads the same key, so the two sides cannot
// drift apart.
const SecretMetadataKey = "toolwarrant_secret"

const (
	generatedHeader = "# Generated by toolwarrant. Do not edit by hand: changes are overwritten\n" +
		"# the next time approvals change.\n" +
		"# yaml-language-server: $schema=https://agentgateway.dev/schema/config\n"
	routePathPrefix = "/"
	routePathSuffix = "/mcp"
)

// Loopback addresses for the gateway's own listeners. Left unset, agentgateway
// binds stats to [::]:15020 and readiness to [::]:15021, which exposes metrics
// and health on every interface of the host. They are process-level settings;
// whether a reload moves them has not been observed, so plan a gateway restart
// when they change.
const (
	adminAddr     = "127.0.0.1:15000"
	statsAddr     = "127.0.0.1:15020"
	readinessAddr = "127.0.0.1:15021"
)

// AgentGateway renders the gateway configuration for in. It validates all
// input first and returns an error wrapping ErrInvalidInput without producing
// any output if anything is wrong. The input is not modified.
func AgentGateway(in Input) (Output, error) {
	servers, err := validate(in)
	if err != nil {
		return Output{}, err
	}
	var w yamlWriter
	writeConfig(&w)
	w.line(0, "binds:")
	w.line(0, "- port: "+strconv.Itoa(in.ListenPort))
	w.line(2, "listeners:")
	w.line(2, "- routes:")

	var skipped []Skipped
	for _, s := range servers {
		plan := classifyTools(s.Name, s.ApprovedTools)
		skipped = append(skipped, plan.skipped...)
		writeRoute(&w, s, plan.allowed)
	}
	file, digest := seal(w.bytes())
	return Output{YAML: file, BodyHash: digest, Skipped: skipped}, nil
}

// writeConfig pins the gateway's own listeners to loopback. It comes first in
// the body so a reader sees where the gateway listens before what it serves.
func writeConfig(w *yamlWriter) {
	w.line(0, "config:")
	w.line(2, "adminAddr: "+quote(adminAddr))
	w.line(2, "statsAddr: "+quote(statsAddr))
	w.line(2, "readinessAddr: "+quote(readinessAddr))
}

// writeRoute appends one route block. The allow rule is written
// unconditionally and comes first in the policies so a reader sees it. The
// secret is a CEL string literal inside a YAML scalar, quoted once per layer,
// exactly like the tool names inside the allow rule.
func writeRoute(w *yamlWriter, s Server, allowed []string) {
	w.line(4, "- name: "+quote(s.Name))
	w.line(6, "matches:")
	w.line(6, "- path:")
	w.line(10, "exact: "+quote(routePath(s.Name)))
	w.line(6, "policies:")
	w.line(8, "mcpAuthorization:")
	w.line(10, "rules:")
	w.line(10, "- allow: "+quote(allowExpression(allowed)))
	w.line(8, "mcpGuardrails:")
	w.line(10, "processors:")
	w.line(10, "- host: "+quote(s.ProcessorAddr))
	w.line(12, "kind: "+quote("remote"))
	w.line(12, "failureMode: "+quote("failClosed"))
	if s.Secret != "" {
		w.line(12, "metadata:")
		w.line(14, SecretMetadataKey+": "+quote(quote(s.Secret)))
	}
	w.line(12, "methods:")
	w.line(14, "tools/call: "+quote("request"))
	w.line(14, "tools/list: "+quote("response"))
	w.line(6, "backends:")
	w.line(6, "- mcp:")
	w.line(10, "targets:")
	w.line(10, "- name: "+quote(s.Name))
	w.line(12, "mcp:")
	w.line(14, "host: "+quote(s.URL))
}

func routePath(name string) string {
	return routePathPrefix + name + routePathSuffix
}

// sortServers orders servers by name. Names are unique by now, so the order
// is total and the output does not depend on the caller's ordering.
func sortServers(servers []Server) {
	slices.SortFunc(servers, func(a, b Server) int { return strings.Compare(a.Name, b.Name) })
}
