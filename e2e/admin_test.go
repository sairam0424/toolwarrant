//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
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
	adminConfigPath = "/api/config"
	adminMaxBody    = 4 << 20
	mediaJSON       = "application/json"
	policiesKey     = "policies"
	guardrailsField = "mcpGuardrails"
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
