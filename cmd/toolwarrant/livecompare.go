package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// metadataWithheld closes every metadata difference line: the block carries
// the processor secret, so neither side's value, nor a hash an attacker could
// test guesses against, is ever shown.
const metadataWithheld = " (values withheld: the metadata carries the processor secret)"

// metadataDigest is the SHA-256 of a processor's metadata in canonical form
// (keys in order, each key and value terminated by a NUL byte), or "" when
// there is none, so an absent block and an empty one compare equal and two
// equal blocks hash the same whatever order they were written in. Both sides
// of the comparison reduce their metadata to it and keep nothing else.
func metadataDigest(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	h := sha256.New()
	for _, k := range sortedKeys(m) {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(m[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// compareDocuments names every way in which the configuration the gateway is
// running differs from the emitted file, over the whole document (D13 e,
// D14 i, D15 i): no non-empty top-level section the file does not carry may
// be present, the config block must declare the same listeners and nothing
// else, every emitted gateway and route must be present exactly once with the
// same fields and match path and with no field, policy, match condition or
// backend the file cannot carry, nothing the file does not carry may exist,
// no path may appear twice, and the path of --url must be the emitted route's
// match for --server. The third review showed why one route is not enough: a
// live document that keeps the server's route intact, parks it on another
// path and adds a processor-less route owning the client's path compared as a
// match; the fourth showed a binds section with a listener on another port
// that the comparison never read; the fifth showed an extProc or
// requestMirror policy and a second backend inside the compared route that
// the pinned decoder dropped. Every value shown is escaped; backend hosts and
// processor metadata are never shown, because an upstream URL may carry a
// credential and the metadata carries the secret.
func compareDocuments(emitted, live configDoc, server, urlPath string) []string {
	var diffs []string
	diffs = append(diffs, extraSections(live.extraSections)...)
	diffs = append(diffs, compareListeners(emitted.listeners, live.listeners)...)
	diffs = append(diffs, live.foreignConfig...)
	diffs = append(diffs, compareGateways(emitted.gateways, live.gateways, live.foreignGateways)...)
	diffs = append(diffs, compareRouteSets(emitted, live, server)...)
	diffs = append(diffs, duplicatePaths(live.routes)...)
	diffs = append(diffs, compareURLPath(emitted, server, urlPath)...)
	return diffs
}

// extraSections names every top-level section of the live document that the
// emitted file does not carry. agentgateway loads the binds form, a top-level
// mcp shortcut and more next to the gateways form, so such a section may
// bind a port and route clients to the upstream with no processor and no
// allow rule in a place the rest of the comparison cannot see.
func extraSections(names []string) []string {
	var diffs []string
	for _, name := range names {
		diffs = append(diffs, fmt.Sprintf("section %s: not in the emitted file; it may bind ports and routes the comparison cannot see", cell(name)))
	}
	return diffs
}

// compareListeners requires the gateway's own listeners to be where the file
// put them: a moved admin API is one verify-gateway --admin no longer watches,
// and a stats or readiness listener on another address may be one every host
// can reach.
func compareListeners(emitted, live listenerConfig) []string {
	var diffs []string
	diffs = appendDiff(diffs, "config "+keyAdminAddr, emitted.adminAddr, live.adminAddr)
	diffs = appendDiff(diffs, "config "+keyStatsAddr, emitted.statsAddr, live.statsAddr)
	diffs = appendDiff(diffs, "config "+keyReadinessAddr, emitted.readinessAddr, live.readinessAddr)
	return diffs
}

// compareGateways requires the live gateways to be exactly the emitted ones,
// each with the same bind address and port and with no field the file cannot
// carry (foreign, by gateway name; D15 i): a gateway the file does not carry
// serves every route attached to it without the emitted guards, and one with
// listeners of its own serves something the comparison cannot see. A gateway
// that is not in the emitted file is reported once, as a whole.
func compareGateways(emitted, live map[string]gatewayConfig, foreign map[string][]string) []string {
	var diffs []string
	diffs = append(diffs, foreign[""]...)
	for _, name := range sortedKeys(emitted) {
		e := emitted[name]
		l, ok := live[name]
		if !ok {
			diffs = append(diffs, fmt.Sprintf("gateway %s: not in the live configuration (emitted bind address %s, serving port %s)", cell(name), shown(e.bindAddress), shown(e.port)))
			continue
		}
		diffs = appendDiff(diffs, "gateway "+cell(name)+": bind address", e.bindAddress, l.bindAddress)
		diffs = appendDiff(diffs, "gateway "+cell(name)+": serving port", e.port, l.port)
		diffs = append(diffs, foreign[name]...)
	}
	for _, name := range sortedKeys(live) {
		if _, ok := emitted[name]; ok {
			continue
		}
		l := live[name]
		diffs = append(diffs, fmt.Sprintf("gateway %s: not in the emitted file (live bind address %s, serving port %s); every route attached to it is served without the emitted guards", cell(name), shown(l.bindAddress), shown(l.port)))
	}
	return diffs
}

// compareRouteSets requires the live routes to be exactly the emitted ones by
// name, each present once and with the same fields. The server's own route
// keeps its lines unprefixed, because the verdict line already names the
// server; every other route is named.
func compareRouteSets(emitted, live configDoc, server string) []string {
	var diffs []string
	emittedNames := map[string]bool{}
	for _, e := range emitted.routes {
		emittedNames[e.name] = true
		l, n := live.route(e.name)
		switch {
		case n == 0:
			diffs = append(diffs, fmt.Sprintf("route %s: not in the live configuration; its path %s is served by nothing or by another route", cell(e.name), shown(joinPaths(e.paths))))
		case n > 1:
			diffs = append(diffs, fmt.Sprintf("route %s: listed %d times in the live configuration, so which one the gateway serves cannot be told", cell(e.name), n))
		default:
			prefix := ""
			if e.name != server {
				prefix = "route " + cell(e.name) + ": "
			}
			for _, d := range compareRoutes(e, l) {
				diffs = append(diffs, prefix+d)
			}
		}
	}
	for _, l := range live.routes {
		if !emittedNames[l.name] {
			diffs = append(diffs, fmt.Sprintf("route %s: not in the emitted file (gateway %s, path %s); the gateway serves it without the emitted guards", cell(l.name), shown(l.gateway), shown(joinPaths(l.paths))))
		}
	}
	return diffs
}

// duplicatePaths names every exact path that more than one live route
// matches: which route the gateway picks for a client is not something the
// canary can tell, and the other one may carry no processor.
func duplicatePaths(routes []routeConfig) []string {
	owners := map[string][]string{}
	for _, r := range routes {
		for _, p := range r.paths {
			if p != nonExactPath {
				owners[p] = append(owners[p], cell(r.name))
			}
		}
	}
	var diffs []string
	for _, p := range sortedKeys(owners) {
		if names := owners[p]; len(names) > 1 {
			diffs = append(diffs, fmt.Sprintf("path %s: matched by %d live routes (%s); which one the gateway serves cannot be told", cell(p), len(names), strings.Join(names, ", ")))
		}
	}
	return diffs
}

// compareURLPath checks that the route the canary listed through is the one
// the file emits for the server: a --url on another path tests another route,
// whatever the document says about this one. A missing emitted route is
// reported by the caller before the comparison runs.
func compareURLPath(emitted configDoc, server, urlPath string) []string {
	e, n := emitted.route(server)
	if n != 1 {
		return nil
	}
	if len(e.paths) == 1 && e.paths[0] == urlPath {
		return nil
	}
	return []string{fmt.Sprintf("the path of --url (%s) is not the match of the emitted route (%s); the listing above tested another route", shown(urlPath), shown(joinPaths(e.paths)))}
}

// compareRoutes names every field in which one live route differs from the
// emitted route of the same name, then everything the live route carries that
// the emitted file cannot (D15 i): a policy such as extProc or requestMirror,
// a match condition beyond the exact path, a backend of another kind, a field
// of the route, a processor or a target that emit never writes.
func compareRoutes(emitted, live routeConfig) []string {
	var diffs []string
	diffs = appendDiff(diffs, "gateway", emitted.gateway, live.gateway)
	diffs = appendDiff(diffs, "match path", joinPaths(emitted.paths), joinPaths(live.paths))
	diffs = append(diffs, compareRules(emitted.rules, live.rules)...)
	diffs = append(diffs, compareProcessors(emitted.processors, live.processors)...)
	diffs = append(diffs, compareTargets(emitted, live)...)
	diffs = append(diffs, live.foreign...)
	return diffs
}

// appendDiff adds a line when two scalar values differ.
func appendDiff(diffs []string, field, emitted, live string) []string {
	if emitted == live {
		return diffs
	}
	return append(diffs, fmt.Sprintf("%s: emitted %s, live %s", field, shown(emitted), shown(live)))
}

// shown renders a value for a difference line.
func shown(v string) string {
	if v == "" {
		return noneShown
	}
	return textdiff.Escape(v)
}

// joinPaths renders a route's match paths; emit writes exactly one.
func joinPaths(paths []string) string {
	return strings.Join(paths, ",")
}

// sortedKeys is the keys of a map in a fixed order, so difference lines come
// out the same on every run.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// compareRules compares the allow rules; emit writes exactly one.
func compareRules(emitted, live []string) []string {
	if len(emitted) != len(live) {
		return []string{fmt.Sprintf("allow rules: emitted %d, live %d", len(emitted), len(live))}
	}
	var diffs []string
	for i := range emitted {
		diffs = appendDiff(diffs, "allow rule", emitted[i], live[i])
	}
	return diffs
}

// compareProcessors compares the processors field by field; a live route
// without one is the F3 case the canary exists for. The request-header filter
// is compared list by list (fourth review cli-docs-4, processor-emit-7): an
// entry stripped of it forwards every client header, bearer tokens and
// cookies included, to the processor again (limit L11). The metadata is
// compared by the hash of its canonical form and never shown. The backendTLS
// block under the entry's policies is compared by presence and then field by
// field (livetls.go): an entry stripped of it is dialled in plaintext again.
func compareProcessors(emitted, live []processorConfig) []string {
	switch {
	case len(live) == 0 && len(emitted) > 0:
		return []string{fmt.Sprintf("processor: the live route has none (emitted %s); every new session on this route is served by the allow rule alone", shown(emitted[0].host))}
	case len(emitted) != len(live):
		return []string{fmt.Sprintf("processors: emitted %d, live %d", len(emitted), len(live))}
	}
	var diffs []string
	for i := range emitted {
		diffs = appendDiff(diffs, "processor host", emitted[i].host, live[i].host)
		diffs = appendDiff(diffs, "processor kind", emitted[i].kind, live[i].kind)
		diffs = appendDiff(diffs, "processor failureMode", emitted[i].failureMode, live[i].failureMode)
		diffs = appendDiff(diffs, "processor methods", describeMethods(emitted[i].methods), describeMethods(live[i].methods))
		diffs = appendDiff(diffs, "processor requestHeaders allowed", describeList(emitted[i].allowed), describeList(live[i].allowed))
		diffs = appendDiff(diffs, "processor requestHeaders disallowed", describeList(emitted[i].disallowed), describeList(live[i].disallowed))
		diffs = append(diffs, compareProcessorTLS(emitted[i].tls, live[i].tls)...)
		diffs = append(diffs, compareMetadata(emitted[i].metadataHash, live[i].metadataHash)...)
	}
	return diffs
}

// compareMetadata reports a metadata block that differs between the two sides
// without showing either: which side has one, or that both have one and they
// are not the same.
func compareMetadata(emitted, live string) []string {
	switch {
	case emitted == live:
		return nil
	case live == "":
		return []string{"processor metadata: the live processor has none while the emitted file carries it" + metadataWithheld}
	case emitted == "":
		return []string{"processor metadata: the live processor carries metadata the emitted file does not" + metadataWithheld}
	}
	return []string{"processor metadata: the live metadata differs from the emitted file" + metadataWithheld}
}

// compareTargets compares the backend targets in order: the name, which is
// the server name and may be shown, and the host, which is never shown. The
// name matters because the processor accepts a hook only for its configured
// target (service_names): a route whose target was renamed through the admin
// API serves nothing, and until the seventh review the comparison called it a
// match (canary-3, D17 i).
func compareTargets(emitted, live routeConfig) []string {
	if len(emitted.backendHosts) != len(live.backendHosts) {
		return []string{fmt.Sprintf("backend targets: emitted %d, live %d", len(emitted.backendHosts), len(live.backendHosts))}
	}
	var diffs []string
	for i := range emitted.backendHosts {
		diffs = appendDiff(diffs, "backend target name", nameAt(emitted.backendTargets, i), nameAt(live.backendTargets, i))
		if emitted.backendHosts[i] != live.backendHosts[i] {
			diffs = append(diffs, "backend host: the live route points at another upstream (values withheld: an upstream URL may carry a credential)")
		}
	}
	return diffs
}

// nameAt is the i-th target name, "" when a side read fewer names than hosts.
func nameAt(names []string, i int) string {
	if i < len(names) {
		return names[i]
	}
	return ""
}

// describeMethods renders a processor's method map in a fixed order, for a
// difference line. The result is escaped once more by shown.
func describeMethods(m map[string]string) string {
	if len(m) == 0 {
		return noneShown
	}
	parts := make([]string, 0, len(m))
	for _, k := range sortedKeys(m) {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
}

// describeList renders a header list in file order for a difference line; a
// nil list (no filter at all) and an empty one both read as none, because the
// gateway forwards everything in either case.
func describeList(items []string) string {
	if len(items) == 0 {
		return noneShown
	}
	return strings.Join(items, ",")
}
