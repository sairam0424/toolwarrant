//go:build e2e

package e2e

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
)

// Helpers over the live configuration document for the sections and the
// processor fields the fifth round added to the comparison. Every mutation
// decodes the document generically and encodes it again, so each field the
// gateway reported goes back exactly as it was.

// liveSections returns the sorted top-level keys of a live configuration
// document: which of the gateway's sections it renders.
func liveSections(doc []byte) ([]string, error) {
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(doc, &cfg); err != nil {
		return nil, fmt.Errorf("the live configuration is not a JSON object: %w", err)
	}
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

// withSection returns a live configuration document with one top-level
// section added or replaced.
func withSection(doc []byte, name string, value any) ([]byte, error) {
	var cfg map[string]any
	if err := json.Unmarshal(doc, &cfg); err != nil {
		return nil, fmt.Errorf("the live configuration is not a JSON object: %w", err)
	}
	cfg[name] = value
	return json.Marshal(cfg)
}

// mcpTarget is one MCP backend target as the gateway's schema names it.
func mcpTarget(name, upstreamURL string) any {
	return map[string]any{"name": name, "mcp": map[string]any{"host": upstreamURL}}
}

// mcpBackends is a route's backends array with one MCP target.
func mcpBackends(name, upstreamURL string) any {
	return []any{map[string]any{"mcp": map[string]any{"targets": []any{mcpTarget(name, upstreamURL)}}}}
}

// bindsValue is a binds section: one listener on port with one route named
// openRouteName on openRoutePath, an allow-all rule, no processor and the
// given upstream as its target, the document the fourth review loaded with
// --validate-only next to the emitted gateway.
func bindsValue(port int, upstreamURL string) any {
	route := map[string]any{
		"name":      openRouteName,
		"matches":   pathMatch(openRoutePath),
		policiesKey: map[string]any{authorizationField: map[string]any{"rules": []any{map[string]any{"allow": "true"}}}},
		"backends":  mcpBackends("mock", upstreamURL),
	}
	listener := map[string]any{"name": openListenerName, "routes": []any{route}}
	return []any{map[string]any{"port": port, "listeners": []any{listener}}}
}

// mcpValue is the top-level mcp shortcut: one MCP listener on port with the
// given upstream as its target.
func mcpValue(port int, upstreamURL string) any {
	return map[string]any{"port": port, "targets": []any{mcpTarget("mock", upstreamURL)}}
}

// liveProcessors returns the mcpGuardrails processors of the route of server
// in a decoded live document, nil when the route carries no processor.
func liveProcessors(routes []any, server string) ([]any, error) {
	route, err := routeNamed(routes, server)
	if err != nil {
		return nil, err
	}
	policies, _ := route[policiesKey].(map[string]any)
	guardrails, _ := policies[guardrailsField].(map[string]any)
	processors, _ := guardrails["processors"].([]any)
	return processors, nil
}

// liveProcessorHasHeaderFilter reports whether the first processor of the
// route of server carries a requestHeaders field in a live document.
func liveProcessorHasHeaderFilter(doc []byte, server string) (bool, error) {
	_, routes, err := liveRoutes(doc)
	if err != nil {
		return false, err
	}
	processors, err := liveProcessors(routes, server)
	if err != nil {
		return false, err
	}
	if len(processors) == 0 {
		return false, fmt.Errorf("the live route %s carries no processor", server)
	}
	first, _ := processors[0].(map[string]any)
	_, has := first[headerFilterField]
	return has, nil
}

// withoutHeaderFilter returns a live document with requestHeaders deleted from
// every processor of the route of server.
func withoutHeaderFilter(doc []byte, server string) ([]byte, error) {
	cfg, routes, err := liveRoutes(doc)
	if err != nil {
		return nil, err
	}
	processors, err := liveProcessors(routes, server)
	if err != nil {
		return nil, err
	}
	removed := 0
	for _, p := range processors {
		if entry, _ := p.(map[string]any); entry != nil {
			if _, has := entry[headerFilterField]; has {
				delete(entry, headerFilterField)
				removed++
			}
		}
	}
	if removed == 0 {
		return nil, errors.New("no processor of the live route carried a " + headerFilterField + " filter")
	}
	return json.Marshal(cfg)
}

// awaitLiveSection polls the admin API until the live document does (want
// true) or does not (want false) render the named top-level section, and
// reports whether that happened within the reload wait; the caller decides
// what a section the gateway never renders means.
func (s *stack) awaitLiveSection(t *testing.T, name string, want bool) bool {
	t.Helper()
	return pollUntil(reloadWait, func() bool {
		sections, err := liveSections(s.liveConfig(t))
		if err != nil {
			return false
		}
		has := false
		for _, k := range sections {
			has = has || k == name
		}
		return has == want
	})
}

// awaitLiveHeaderFilter polls the admin API until the first processor of the
// route of server has (want true) or lacks (want false) the request-header
// filter, so a scenario knows the gateway applied a replacement before it
// checks anything.
func (s *stack) awaitLiveHeaderFilter(t *testing.T, server string, want bool) {
	t.Helper()
	var last string
	ok := pollUntil(reloadWait, func() bool {
		has, err := liveProcessorHasHeaderFilter(s.liveConfig(t), server)
		if err != nil {
			last = err.Error()
			return false
		}
		last = fmt.Sprintf("%s present: %v", headerFilterField, has)
		return has == want
	})
	if !ok {
		t.Fatalf("the live processor of route %s did not reach %s present=%v within %s; last observation: %s\n%s", server, headerFilterField, want, reloadWait, last, s.logHints())
	}
}

// awaitLiveDocument polls the admin API until the live configuration decodes
// to the same value as want, whatever order the gateway renders keys in, so a
// restore is known to have taken effect in every section before the next
// step starts.
func (s *stack) awaitLiveDocument(t *testing.T, want []byte) {
	t.Helper()
	var wantValue any
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("the document to restore is not JSON: %v", err)
	}
	var last string
	ok := pollUntil(reloadWait, func() bool {
		live := s.liveConfig(t)
		var liveValue any
		if err := json.Unmarshal(live, &liveValue); err != nil {
			last = err.Error()
			return false
		}
		sections, _ := liveSections(live)
		last = fmt.Sprintf("sections %v, %d bytes", sections, len(live))
		return reflect.DeepEqual(liveValue, wantValue)
	})
	if !ok {
		t.Fatalf("the live configuration did not return to the original document within %s; last observation: %s\n%s", reloadWait, last, s.logHints())
	}
}
