package main

import (
	"encoding/json"
	"strconv"
)

// The parts of the live document the emitted file can carry (D15 i). The
// fifth review found the comparison reading a fixed set of fields inside the
// three known sections while json.Unmarshal dropped every other key, so a live
// route that gained an extProc or requestMirror policy, a second backend of
// another kind, a match on more than its path, or a config field the file
// never writes compared as a match and the canary printed OK: agentgateway
// v1.6.0 accepts 32 route policies and 37 config fields, and its admin API
// takes any of them. Every object of the live document is now walked against
// the keys emit writes, and every key the file cannot carry is one difference
// line, so the comparison fails closed on what it cannot read instead of
// ignoring it.

// Phrases of a line about something the emitted file cannot carry.
const (
	foreignSuffix         = ": not in the emitted file"
	foreignPolicyNote     = "; the gateway applies it to this route"
	foreignLinkPolicyNote = "; the gateway applies it to the link to this processor"
	notAnObject           = "not an object as in the emitted file"
	notAList              = ": not a list as in the emitted file"
	labelField            = "field"
	labelPolicy           = "policy"
)

// shape is what the emitted file can carry at one place of the live document:
// the keys of an object, each with the shape of its value (nil for a scalar or
// a free map the comparison reads by value, or ignores), or the shape of every
// element of a list.
type shape struct {
	// label names a key the file cannot carry in the difference line: "field",
	// "policy", "mcpGuardrails field".
	label string
	// prefix names the object this shape describes when it sits inside a
	// list element ("path ", "mcp ", "requestHeaders "), written before the
	// label of a key the file cannot carry so that a line says where the key
	// sits; it is not carried into deeper levels.
	prefix string
	// note closes the line about a key the file cannot carry when the plain
	// suffix does not say enough (a policy is applied, not just present).
	note string
	// keys are the keys of an object that the file can carry.
	keys map[string]*shape
	// item names one element of a list in the difference line ("match",
	// "backend"); "" for an object. list names the whole list in the line
	// about a value that is not one.
	item, list string
	// each is the shape of every element of a list.
	each *shape
}

// foreign names every key under raw that the emitted file cannot carry, each
// located by at ("", "match 1: ", "backend 1: target 1: "). An absent value
// has nothing to report; a value that is not the container the shape expects
// is reported as a whole, because a comparison that cannot read a place must
// not call it equal. Keys are escaped, values are never shown.
func (s *shape) foreign(raw json.RawMessage, at string) []string {
	switch {
	case len(raw) == 0:
		return nil
	case s.keys != nil:
		return s.foreignKeys(raw, at)
	case s.item != "":
		return s.foreignItems(raw, at)
	}
	return nil
}

// foreignKeys walks one object: every key the shape does not list is a line,
// every key it lists with a shape of its own is walked.
func (s *shape) foreignKeys(raw json.RawMessage, at string) []string {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return []string{at + s.prefix + notAnObject}
	}
	var out []string
	for _, k := range sortedKeys(obj) {
		child, known := s.keys[k]
		if !known {
			out = append(out, at+s.prefix+s.label+" "+cell(k)+foreignSuffix+s.note)
			continue
		}
		if child != nil {
			out = append(out, child.foreign(obj[k], at)...)
		}
	}
	return out
}

// foreignItems walks one list, numbering its elements from one as the
// difference lines do.
func (s *shape) foreignItems(raw json.RawMessage, at string) []string {
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return []string{at + s.list + notAList}
	}
	var out []string
	for i, item := range items {
		out = append(out, s.each.foreign(item, at+s.item+" "+strconv.Itoa(i+1)+": ")...)
	}
	return out
}

// configShape is the config block as emit writes it: the three listener
// addresses and nothing else. agentgateway v1.6.0 accepts 34 more fields
// there (its session and mcp blocks, xds and local-xds sources, logging,
// tracing, worker threads and the rest), none of which the file carries.
func configShape() *shape {
	return &shape{label: sectionConfig, keys: map[string]*shape{keyAdminAddr: nil, keyStatsAddr: nil, keyReadinessAddr: nil}}
}

// gatewayShape is one gateway as emit writes it: its serving port and bind
// address. A gateway with listeners or a hostname of its own serves something
// the comparison cannot see.
func gatewayShape() *shape {
	return &shape{label: labelField, keys: map[string]*shape{keyPort: nil, keyBindAddress: nil}}
}

// routeShape is one route as emit writes it: name, gateway reference, one
// match on an exact path, the mcpAuthorization and mcpGuardrails policies, and
// one mcp backend with one target. The keys mirror the pinned liveRouteDoc
// struct and testdata/admin_config.json, which the real gateway rendered.
func routeShape() *shape {
	return &shape{label: labelField, keys: map[string]*shape{
		"name":     nil,
		"gateways": nil,
		"matches": {item: "match", list: "matches", each: &shape{label: labelField, keys: map[string]*shape{
			"path": {prefix: "path ", label: labelField, keys: map[string]*shape{"exact": nil}},
		}}},
		"policies": {label: labelPolicy, note: foreignPolicyNote, keys: map[string]*shape{
			"mcpAuthorization": {label: "mcpAuthorization field", keys: map[string]*shape{
				"rules": {item: "allow rule", list: "rules", each: &shape{label: labelField, keys: map[string]*shape{"allow": nil}}},
			}},
			"mcpGuardrails": {label: "mcpGuardrails field", keys: map[string]*shape{
				"processors": {item: "processor", list: "processors", each: processorShape()},
			}},
		}},
		"backends": {item: "backend", list: "backends", each: &shape{label: labelField, keys: map[string]*shape{
			"mcp": {prefix: "mcp ", label: labelField, keys: map[string]*shape{
				"targets": {item: "target", list: "targets", each: &shape{label: labelField, keys: map[string]*shape{
					"name": nil,
					"mcp":  {prefix: "mcp ", label: labelField, keys: map[string]*shape{"host": nil}},
				}}},
			}},
		}}},
	}}
}

// processorShape is one mcpGuardrails processor as emit writes it. The
// methods and metadata maps carry keys the operator chooses and are compared
// by value, so they are not walked. Under policies the file carries one
// backendTLS block with cert, key, root and hostname (limit L11): the v1.6.0
// schema accepts insecure, insecureHost, alpn, subjectAltNames,
// keyExchangeGroups and spiffe inside the block, which turn verification off
// or move the trust elsewhere, and requestHeaderModifier, transformations and
// backendAuth beside it, which rewrite the hook or send a credential to the
// processor; each is one line, since the comparison cannot read what any of
// them does to the link.
func processorShape() *shape {
	return &shape{label: labelField, keys: map[string]*shape{
		"host": nil, "kind": nil, "failureMode": nil, "methods": nil, "metadata": nil,
		"requestHeaders": {prefix: "requestHeaders ", label: labelField, keys: map[string]*shape{"allowed": nil, "disallowed": nil}},
		policiesBlock: {label: labelPolicy, note: foreignLinkPolicyNote, keys: map[string]*shape{
			tlsBlockName: {prefix: tlsBlockName + " ", label: labelField, keys: map[string]*shape{keyTLSCert: nil, keyTLSKey: nil, keyTLSRoot: nil, keyTLSHostname: nil}},
		}},
	}}
}

// foreignGateways walks every gateway of the live document and returns, by
// gateway name, the lines about keys the emitted file cannot carry.
func foreignGateways(raw json.RawMessage) map[string][]string {
	out := map[string][]string{}
	if len(raw) == 0 {
		return out
	}
	var gateways map[string]json.RawMessage
	if json.Unmarshal(raw, &gateways) != nil {
		out[""] = []string{sectionGateways + ": " + notAnObject}
		return out
	}
	for name, gw := range gateways {
		if lines := gatewayShape().foreign(gw, "gateway "+cell(name)+": "); len(lines) > 0 {
			out[name] = lines
		}
	}
	return out
}

// foreignRoutes walks every route of the live document and returns, by route
// index, the lines about keys the emitted file cannot carry.
func foreignRoutes(raw json.RawMessage) [][]string {
	if len(raw) == 0 {
		return nil
	}
	var routes []json.RawMessage
	if json.Unmarshal(raw, &routes) != nil {
		return [][]string{{sectionRoutes + ": " + notAnObject}}
	}
	out := make([][]string, len(routes))
	for i, r := range routes {
		out[i] = routeShape().foreign(r, "")
	}
	return out
}
