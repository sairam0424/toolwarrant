// Package emit turns the catalog's approvals into agentgateway v1.6.0
// configuration. It is the only place that knows the gateway's config schema.
//
// The emitted file is defence in depth behind the toolwarrant processor, not
// the guard itself. The processor compares every served definition with the
// approved digest; the file only decides where the gateway listens, which
// routes exist, which tool names the gateway may show on each route, and
// which processor the gateway must consult. Within that role the file is
// built so that it cannot be weaker than intended:
//
//   - The serving port is bound to loopback (DefaultBindAddress) unless the
//     input says otherwise. Seam finding F2 showed that any unguarded reach to
//     the gateway is a complete bypass and that a gateway bind listens on
//     every interface by default; a wildcard address is written only when
//     Input.AllowAllInterfaces confirms it, and Output.Warning then says so.
//   - Every route carries an explicit mcpAuthorization allow rule, because in
//     agentgateway an empty rule set, or one that holds only deny rules, means
//     allow-all. A server with no approved tools gets an allow rule that can
//     never match, not an absent one.
//   - Every route names exactly one processor with failureMode failClosed, and
//     one processor address belongs to exactly one server, so a processor can
//     refuse hooks that name any other target.
//   - Every string that comes from the catalog is written as an escaped,
//     double-quoted scalar, so it cannot add keys, lines or CEL syntax. A
//     dollar sign is always written as its \u0024 escape, because the gateway
//     substitutes environment variables ($NAME, ${NAME}) into the raw file
//     text before parsing it: a raw name would be replaced by whatever the
//     gateway's environment holds or, when unset, make it refuse the file.
//   - Server names and upstream URLs are held to the gateway's own rules, and
//     a little more, so that a file this package writes is one the gateway
//     loads. The gateway keeps serving its previous configuration when a
//     reload fails, so a refused file would silently freeze every route.
//   - The gateway's admin, stats and readiness listeners are always written,
//     on loopback by default (DefaultAdminAddr, DefaultStatsAddr,
//     DefaultReadinessAddr). A listener other hosts can reach needs
//     Input.AllowAllInterfaces and adds a line to Output.Warning; the admin
//     API can be turned off with Input.DisableAdmin.
//   - The header records the SHA-256 of the body and Verify tells an edited
//     file from a fresh one. This is an unkeyed integrity check: it catches
//     accidental and careless edits, including a removed processor block, not
//     an attacker who rewrites the hash line as well. The body hash the
//     emitter returns (and the CLI prints) is what an operator records
//     elsewhere and compares against later; a dropped guard is caught for
//     certain only by listing through the gateway in a fresh session.
//
// # The admin API
//
// agentgateway's admin listener has no authentication. GET /api/config
// returns the running configuration, POST /api/config replaces it and
// rewrites the watched file (keeping this package's header lines, so the
// recorded hash no longer matches the body), /config_dump returns the loaded
// configuration with every processor secret in clear, and /logging changes
// the log level. Whoever can connect to that listener decides what the
// gateway serves, exactly like whoever reaches the processor without the
// shared secret: the admin listener is part of the gateway's trusted
// computing base. A loopback bind therefore means "every local user of this
// host", not "nobody". On a host with other local users, turn the admin API
// off with Input.DisableAdmin, or run the gateway in its own network
// namespace or container. The stats and readiness listeners expose metrics
// and health only and cannot be turned off here. Unix-socket listeners, which
// the schema also allows, are not written: the socket's permissions would be
// the gateway process's umask, which this package cannot pin, and
// DisableAdmin is the stronger control. The three listeners are process-level
// settings; whether a reload moves them has not been observed, so plan a
// gateway restart when they change.
//
// # Shape of the file
//
// The file uses the schema's gateways form: the binds form is marked
// deprecated in the v1.6.0 schema and has no bind address. One gateway, named
// toolwarrant, declares the port and the address; every route attaches to it
// by name. For an Input with ListenPort 3000 and every address left at its
// default the body is, with one route block per server in name order:
//
//	config:
//	  adminAddr: "127.0.0.1:15000"
//	  statsAddr: "127.0.0.1:15020"
//	  readinessAddr: "127.0.0.1:15021"
//	gateways:
//	  toolwarrant:
//	    port: 3000
//	    bindAddress: "127.0.0.1"
//	routes:
//	- name: "<server>"
//	  gateways: "toolwarrant"
//	  matches:
//	  - path:
//	      exact: "/<server>/mcp"
//	  policies:
//	    mcpAuthorization:
//	      rules:
//	      - allow: "mcp.tool.name == \"<tool>\" || mcp.tool.name == \"<tool>\""
//	    mcpGuardrails:
//	      processors:
//	      - host: "<processor host:port>"
//	        kind: "remote"
//	        failureMode: "failClosed"
//	        metadata:
//	          toolwarrant_secret: "\"<secret>\""
//	        methods:
//	          tools/call: "request"
//	          tools/list: "response"
//	  backends:
//	  - mcp:
//	      targets:
//	      - name: "<server>"
//	        mcp:
//	          host: "<upstream URL>"
//
// The allow rule is the literal "false" when the server has no approved tool;
// the metadata block is present only when Server.Secret is set; the bind
// address and the listener addresses are written in canonical form (an IPv6
// listener as "[::1]:15000"); adminAddr is the literal "off" when
// Input.DisableAdmin is set. Four comment lines precede the body: the
// generated-file warning (two lines), the schema hint, and
// "# toolwarrant-sha256: <hex>" with the digest of the body. The gateways form
// changes nothing under a route: the v1.6.0 schema documents the same fields
// under routes[] as under binds[].listeners[].routes[], plus routes[].gateways,
// so every policy toolwarrant relies on is attached per route exactly as
// before. The config block is independent of the gateways form: adminAddr,
// statsAddr and readinessAddr are process-level listeners, and the schema's
// config.gateway is an xDS identity that is not written.
//
// # What this package cannot do
//
// The gateway's --validate-only mode, which the tests run, proves that the
// file parses, that bindAddress is read as an IP literal, that the listener
// addresses parse and that "off" is read as a switch, that every route's
// gateways reference resolves, that the CEL rules are well formed, and that
// the names and URLs this package refuses are refused by the gateway too (or
// are refused here on purpose). It proves nothing about runtime: that the
// sockets really are bound to those addresses, that the routes attached by
// name are served, which methods the rules filter and how mcp.tool.name binds
// are observable only with the gateway running as a server, and are covered
// by the end-to-end test (package e2e), not here. --validate-only also
// accepts two listeners on one port, so the emitter refuses that itself.
// Processor addresses are limited to host:port: the schema describes
// processors[].host as "Hostname or IP address" and documents no unix:// or
// https:// form (--validate-only accepts both, but it also accepts unknown
// CEL variables, so that proves nothing); TLS towards a processor is the
// separate processors[].policies.backendTLS block, which this version does
// not write. The gateway name is a constant, and editing the file by hand
// fails Verify. A secret is written into the file in clear, so a file that
// carries one must be readable by the gateway alone.
package emit

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Server is one upstream MCP server as the gateway should expose it.
type Server struct {
	// Name is the route name, the backend target name and therefore the target
	// the processor sees in every hook; the server is reachable at
	// "/<Name>/mcp". It must match ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ and be at
	// most 63 bytes. That is agentgateway's own MCP target rule (the Gateway
	// API SectionName pattern, in which '_' and '+' are reserved MCP
	// delimiters and a name cannot start or end with '-'), minus the '.' the
	// gateway would accept: one boring alphabet serves the route path, the
	// processor's target check, file names and audit subjects alike.
	Name string
	// URL is the upstream MCP endpoint (http or https). Every byte must be a
	// letter, a digit or one of the RFC 3986 characters -._~:/?#[]@!$&'()*+,;=
	// and %, because the gateway's URI parser refuses anything else.
	URL string
	// ProcessorAddr is the host:port of the toolwarrant ExtMCP processor that
	// enforces strict mode for this upstream. Every server needs its own,
	// because a processor serves exactly one target and denies the rest. A
	// host that is not "localhost" or a loopback literal adds a line to
	// Output.Warning: the hooks then cross the network.
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
	// ListenPort is the single port the gateway binds for serving. It must
	// differ from the ports of the admin, stats and readiness listeners.
	ListenPort int
	// BindAddress is the IPv4 or IPv6 literal the gateway binds ListenPort on.
	// Empty means DefaultBindAddress; "::1" is the IPv6 loopback. A wildcard
	// ("0.0.0.0" or "::") is refused unless AllowAllInterfaces is set, because
	// every route then becomes reachable from the network (seam finding F2).
	// Host names, host:port forms, zones ("fe80::1%en0"), IPv4-mapped IPv6,
	// IPv6 link-local, multicast and broadcast addresses are refused. The
	// address is written in canonical form ("0:0:0:0:0:0:0:1" becomes "::1").
	BindAddress string
	// AllowAllInterfaces permits a wildcard BindAddress and permits an
	// AdminAddr, StatsAddr or ReadinessAddr that is not loopback. It is a
	// permission, not a request: with loopback addresses it changes nothing.
	// Every exposure it unlocks adds a line to Output.Warning.
	AllowAllInterfaces bool
	// AdminAddr is the host:port of the gateway's admin API, DefaultAdminAddr
	// when empty. The host must be an IP literal under the BindAddress rules
	// and must be loopback unless AllowAllInterfaces is set, because the API
	// has no authentication (see the package documentation). An IPv6 address
	// is written in brackets, "[::1]:15000". Host names, including
	// "localhost", are refused: a name is not a safe way to say loopback.
	AdminAddr string
	// DisableAdmin writes adminAddr "off", the gateway's own switch for "no
	// admin listener", instead of an address. It cannot be combined with a
	// non-empty AdminAddr: the two contradict each other and the input is
	// refused. The stats and readiness listeners cannot be turned off.
	DisableAdmin bool
	// StatsAddr is the host:port of the gateway's metrics listener,
	// DefaultStatsAddr when empty, under the same rules as AdminAddr.
	StatsAddr string
	// ReadinessAddr is the host:port of the gateway's readiness probe,
	// DefaultReadinessAddr when empty, under the same rules as AdminAddr.
	ReadinessAddr string
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
	// It is the value an operator records elsewhere, because the header alone
	// cannot prove anything to a reader who distrusts the file.
	BodyHash string
	// Skipped lists approved tools that were not emitted, sorted by server
	// then tool.
	Skipped []Skipped
	// Warning is empty, or one or more lines of printable ASCII separated by
	// "\n" and without a trailing newline, each a notice about an exposure the
	// input asked for: the serving socket when its bind address is not
	// loopback; each admin, stats or readiness listener that is not loopback;
	// and each server whose processor address is not loopback (its hooks then
	// cross the network, and serve refuses such a listener unless it is
	// explicitly allowed and carries a shared secret), in that order, servers
	// by name. The input was valid; the CLI should print every line so that
	// the exposure is a decision, not a surprise.
	Warning string
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

// AgentGateway renders the gateway configuration for in. It validates all
// input first and returns an error wrapping ErrInvalidInput without producing
// any output if anything is wrong. The input is not modified.
func AgentGateway(in Input) (Output, error) {
	v, err := validate(in)
	if err != nil {
		return Output{}, err
	}
	var w yamlWriter
	writeConfig(&w, v.listeners)
	writeGateway(&w, v.bind, in.ListenPort)
	w.line(0, "routes:")

	var skipped []Skipped
	for _, s := range v.servers {
		plan := classifyTools(s.Name, s.ApprovedTools)
		skipped = append(skipped, plan.skipped...)
		writeRoute(&w, s, plan.allowed)
	}
	file, digest := seal(w.bytes())
	return Output{YAML: file, BodyHash: digest, Skipped: skipped, Warning: buildWarning(v, in.ListenPort)}, nil
}

// writeConfig declares the gateway's own listeners. It comes first in the
// body so a reader sees where the gateway listens before what it serves, and
// every listener is written even at its default, because the gateway's own
// defaults for stats and readiness are wildcard binds.
func writeConfig(w *yamlWriter, listeners []listener) {
	w.line(0, "config:")
	for _, l := range listeners {
		w.line(2, l.key+": "+quote(l.text()))
	}
}

// writeGateway declares the one gateway the routes attach to: the serving
// port and the address it is bound to, in canonical form so that two
// spellings of one address give one file.
func writeGateway(w *yamlWriter, bind netip.Addr, port int) {
	w.line(0, "gateways:")
	w.line(2, gatewayName+":")
	w.line(4, "port: "+strconv.Itoa(port))
	w.line(4, "bindAddress: "+quote(bind.String()))
}

// writeRoute appends one route block. Every route names the gateway, so a
// route without that line is refused by the gateway rather than attached to a
// default. The allow rule is written unconditionally and comes first in the
// policies so a reader sees it. The secret is a CEL string literal inside a
// YAML scalar, quoted once per layer, exactly like the tool names inside the
// allow rule.
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
	w.line(6, "- host: "+quote(s.ProcessorAddr))
	w.line(8, "kind: "+quote("remote"))
	w.line(8, "failureMode: "+quote("failClosed"))
	if s.Secret != "" {
		w.line(8, "metadata:")
		w.line(10, SecretMetadataKey+": "+quote(quote(s.Secret)))
	}
	w.line(8, "methods:")
	w.line(10, "tools/call: "+quote("request"))
	w.line(10, "tools/list: "+quote("response"))
	w.line(2, "backends:")
	w.line(2, "- mcp:")
	w.line(6, "targets:")
	w.line(6, "- name: "+quote(s.Name))
	w.line(8, "mcp:")
	w.line(10, "host: "+quote(s.URL))
}

func routePath(name string) string {
	return routePathPrefix + name + routePathSuffix
}

// sortServers orders servers by name. Names are unique by now, so the order
// is total and the output does not depend on the caller's ordering.
func sortServers(servers []Server) {
	slices.SortFunc(servers, func(a, b Server) int { return strings.Compare(a.Name, b.Name) })
}
