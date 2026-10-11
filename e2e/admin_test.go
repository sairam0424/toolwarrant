//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
)

// The admin API of agentgateway v1.6.0 as scenario P drives it. GET
// /api/config returns the configuration the gateway is running as JSON in the
// shape of the loaded file (cmd/toolwarrant/testdata/admin_config.json pins
// what the e2e harness recorded); POST /api/config takes the same document
// back and answers 415 to anything but Content-Type application/json, which
// the harness learnt by posting the YAML first. The API has no authentication
// (limit L18), which is what the scenario demonstrates.
const (
	adminConfigPath    = "/api/config"
	adminMaxBody       = 4 << 20
	mediaJSON          = "application/json"
	policiesKey        = "policies"
	guardrailsField    = "mcpGuardrails"
	authorizationField = "mcpAuthorization"
)

// adminURL is the base URL of the gateway's admin API.
func (s *stack) adminURL() string { return "http://" + s.adminAddr() }

// liveConfig fetches the configuration the gateway is running.
func (s *stack) liveConfig(t *testing.T) []byte {
	t.Helper()
	status, body := s.adminDo(t, http.MethodGet, nil, "")
	if status != http.StatusOK {
		t.Fatalf("GET %s: status %d: %.300s", adminConfigPath, status, body)
	}
	return body
}

// postLiveConfig replaces the running configuration through the admin API
// with a JSON document and returns the gateway's status code and answer.
func (s *stack) postLiveConfig(t *testing.T, doc []byte) (int, []byte) {
	t.Helper()
	return s.adminDo(t, http.MethodPost, doc, mediaJSON)
}

// adminDo performs one request against /api/config and reads the bounded
// answer. The answer may hold a processor secret in clear, so callers print
// its size or a short prefix, never the whole of it.
func (s *stack) adminDo(t *testing.T, method string, body []byte, contentType string) (int, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.adminURL()+adminConfigPath, reader)
	if err != nil {
		t.Fatalf("%s %s: %v", method, adminConfigPath, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, adminConfigPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, adminMaxBody))
	if err != nil {
		t.Fatalf("%s %s: read answer: %v", method, adminConfigPath, err)
	}
	return resp.StatusCode, data
}

// liveRouteHasProcessor reports whether the route of server carries an
// mcpGuardrails processor in a live configuration document.
func liveRouteHasProcessor(doc []byte, server string) (bool, error) {
	var cfg struct {
		Routes []struct {
			Name     string `json:"name"`
			Policies struct {
				McpGuardrails *struct {
					Processors []json.RawMessage `json:"processors"`
				} `json:"mcpGuardrails"`
			} `json:"policies"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(doc, &cfg); err != nil {
		return false, fmt.Errorf("the live configuration is not the expected JSON: %w", err)
	}
	for _, r := range cfg.Routes {
		if r.Name == server {
			return r.Policies.McpGuardrails != nil && len(r.Policies.McpGuardrails.Processors) > 0, nil
		}
	}
	return false, fmt.Errorf("the live configuration has no route named %q", server)
}

// withoutGuardrails returns a live configuration document with the
// mcpGuardrails policy removed from every route: the processor-less copy a
// local user of the gateway host could post (limit L18). The document is
// decoded generically so that every other field goes back exactly as the
// gateway reported it.
func withoutGuardrails(doc []byte) ([]byte, error) {
	var cfg map[string]any
	if err := json.Unmarshal(doc, &cfg); err != nil {
		return nil, fmt.Errorf("the live configuration is not a JSON object: %w", err)
	}
	routes, ok := cfg["routes"].([]any)
	if !ok {
		return nil, fmt.Errorf("the live configuration has no routes array")
	}
	removed := 0
	for _, r := range routes {
		route, _ := r.(map[string]any)
		policies, _ := route[policiesKey].(map[string]any)
		if _, has := policies[guardrailsField]; has {
			delete(policies, guardrailsField)
			removed++
		}
	}
	if removed == 0 {
		return nil, fmt.Errorf("no route of the live configuration carried an %s policy", guardrailsField)
	}
	return json.Marshal(cfg)
}

// awaitLiveProcessor polls the admin API until the route of server has (want
// true) or lacks (want false) a processor, so a scenario knows the gateway
// applied a replacement before it measures anything. A bounded poll is used
// because the gateway applies a posted configuration asynchronously.
func (s *stack) awaitLiveProcessor(t *testing.T, server string, want bool) {
	t.Helper()
	var last string
	ok := pollUntil(reloadWait, func() bool {
		has, err := liveRouteHasProcessor(s.liveConfig(t), server)
		if err != nil {
			last = err.Error()
			return false
		}
		last = fmt.Sprintf("processor present: %v", has)
		return has == want
	})
	if !ok {
		t.Fatalf("the live configuration of route %s did not reach processor present=%v within %s; last observation: %s\n%s", server, want, reloadWait, last, s.logHints())
	}
}

// routeCount is how many routes a live configuration document carries.
func routeCount(doc []byte) (int, error) {
	var cfg struct {
		Routes []json.RawMessage `json:"routes"`
	}
	if err := json.Unmarshal(doc, &cfg); err != nil {
		return 0, fmt.Errorf("the live configuration is not the expected JSON: %w", err)
	}
	return len(cfg.Routes), nil
}

// awaitLiveRouteCount polls the admin API until the gateway runs exactly n
// routes, so a scenario knows that a posted document with a route added or
// taken away was applied before it checks anything.
func (s *stack) awaitLiveRouteCount(t *testing.T, n int) {
	t.Helper()
	var last string
	ok := pollUntil(reloadWait, func() bool {
		got, err := routeCount(s.liveConfig(t))
		if err != nil {
			last = err.Error()
			return false
		}
		last = fmt.Sprintf("%d route(s)", got)
		return got == n
	})
	if !ok {
		t.Fatalf("the live configuration did not reach %d route(s) within %s; last observation: %s\n%s", n, reloadWait, last, s.logHints())
	}
}

// liveRoutes decodes a live configuration document generically and returns
// it with its routes array, so that a mutation puts every other field back
// exactly as the gateway reported it.
func liveRoutes(doc []byte) (map[string]any, []any, error) {
	var cfg map[string]any
	if err := json.Unmarshal(doc, &cfg); err != nil {
		return nil, nil, fmt.Errorf("the live configuration is not a JSON object: %w", err)
	}
	routes, ok := cfg["routes"].([]any)
	if !ok {
		return nil, nil, errors.New("the live configuration has no routes array")
	}
	return cfg, routes, nil
}

// routeNamed finds the route of server in a decoded routes array.
func routeNamed(routes []any, server string) (map[string]any, error) {
	for _, r := range routes {
		if route, _ := r.(map[string]any); route["name"] == server {
			return route, nil
		}
	}
	return nil, fmt.Errorf("the live configuration has no route named %q", server)
}

// exactPath is the one exact path match of a decoded route.
func exactPath(route map[string]any) (string, error) {
	matches, _ := route["matches"].([]any)
	if len(matches) != 1 {
		return "", fmt.Errorf("route %v has %d matches, want 1", route["name"], len(matches))
	}
	m, _ := matches[0].(map[string]any)
	p, _ := m["path"].(map[string]any)
	exact, ok := p["exact"].(string)
	if !ok || exact == "" {
		return "", fmt.Errorf("route %v has no exact path match", route["name"])
	}
	return exact, nil
}

// pathMatch is the matches array of a route with one exact path.
func pathMatch(path string) []any {
	return []any{map[string]any{"path": map[string]any{"exact": path}}}
}

// withExtraRoute returns a live configuration document with one route added
// next to the route of server: on path, with no allow rule and no processor,
// attached to the same gateway and pointing at the same upstream. The
// server's own route is untouched, which is why a comparison that read that
// route alone saw nothing (finding processor-emit-2).
func withExtraRoute(doc []byte, server, name, path string) ([]byte, error) {
	cfg, routes, err := liveRoutes(doc)
	if err != nil {
		return nil, err
	}
	base, err := routeNamed(routes, server)
	if err != nil {
		return nil, err
	}
	extra := map[string]any{"name": name, "gateways": base["gateways"], "matches": pathMatch(path), "backends": base["backends"]}
	cfg["routes"] = append(append([]any(nil), routes...), extra)
	return json.Marshal(cfg)
}

// withShadowRoute returns a live configuration document in which the route of
// server keeps every field but its match, which moves to parked, and a route
// named shadow owns the server's client path with the allow rule copied and
// no processor (finding cli-docs-1). The named route is what the file emitted
// apart from its path, so a comparison of its fields alone passed while the
// path a client uses was served by the allow rule alone.
func withShadowRoute(doc []byte, server, shadow, parked string) ([]byte, error) {
	cfg, routes, err := liveRoutes(doc)
	if err != nil {
		return nil, err
	}
	base, err := routeNamed(routes, server)
	if err != nil {
		return nil, err
	}
	clientPath, err := exactPath(base)
	if err != nil {
		return nil, err
	}
	moved := map[string]any{}
	for k, v := range base {
		moved[k] = v
	}
	moved["matches"] = pathMatch(parked)
	policies, _ := base[policiesKey].(map[string]any)
	rule, has := policies[authorizationField]
	if !has {
		return nil, fmt.Errorf("route %s carries no %s policy to copy", server, authorizationField)
	}
	sh := map[string]any{"name": shadow, "gateways": base["gateways"], "matches": pathMatch(clientPath), "backends": base["backends"],
		policiesKey: map[string]any{authorizationField: rule}}
	out := make([]any, 0, len(routes)+1)
	for _, r := range routes {
		if route, _ := r.(map[string]any); route["name"] == server {
			out = append(out, moved)
			continue
		}
		out = append(out, r)
	}
	cfg["routes"] = append(out, sh)
	return json.Marshal(cfg)
}
