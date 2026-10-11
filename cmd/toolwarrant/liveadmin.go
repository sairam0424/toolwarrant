package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// The admin API as the comparison reads it.
const (
	// adminConfigPath is the admin API endpoint that returns the
	// configuration agentgateway v1.6.0 is running, as JSON in the shape of
	// the file it loaded (config, gateways, routes). The e2e harness recorded
	// the shape on the real gateway and testdata/admin_config.json pins it.
	adminConfigPath = "/api/config"
	// adminMaxBody bounds the live configuration read from the admin API.
	adminMaxBody = 4 << 20
	// noneShown stands for an absent value in a difference line.
	noneShown = "(none)"
)

// liveConfigDoc is the pinned subset of GET /api/config: the gateways with
// their bind and port, and every route with its policies and backends. Fields
// the comparison does not read are left out; an unknown field in the answer
// is ignored, a missing one compares as empty.
type liveConfigDoc struct {
	Gateways map[string]struct {
		Port        int    `json:"port"`
		BindAddress string `json:"bindAddress"`
	} `json:"gateways"`
	Routes []liveRouteDoc `json:"routes"`
}

// liveRouteDoc is one route of the live configuration.
type liveRouteDoc struct {
	Name     string `json:"name"`
	Gateways string `json:"gateways"`
	Policies struct {
		McpAuthorization *struct {
			Rules []struct {
				Allow string `json:"allow"`
			} `json:"rules"`
		} `json:"mcpAuthorization"`
		McpGuardrails *struct {
			Processors []struct {
				Host        string            `json:"host"`
				Kind        string            `json:"kind"`
				FailureMode string            `json:"failureMode"`
				Methods     map[string]string `json:"methods"`
			} `json:"processors"`
		} `json:"mcpGuardrails"`
	} `json:"policies"`
	Backends []struct {
		Mcp struct {
			Targets []struct {
				Mcp struct {
					Host string `json:"host"`
				} `json:"mcp"`
			} `json:"targets"`
		} `json:"mcp"`
	} `json:"backends"`
}

// fetchLiveConfig reads the configuration the gateway is running from its
// admin API. Errors carry a class, never the response text: the live
// configuration holds the processor secret in clear.
func fetchLiveConfig(ctx context.Context, client *http.Client, admin string) (liveConfigDoc, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, admin+adminConfigPath, nil)
	if err != nil {
		return liveConfigDoc{}, fmt.Errorf("admin api: build request: %w", err)
	}
	req.Header.Set("Accept", mediaJSON)
	resp, err := client.Do(req)
	if err != nil {
		return liveConfigDoc{}, fmt.Errorf("admin api: %s", scrubCrawlError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return liveConfigDoc{}, fmt.Errorf("admin api: http status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, adminMaxBody+1))
	if err != nil {
		return liveConfigDoc{}, fmt.Errorf("admin api: %s", scrubCrawlError(err))
	}
	if len(body) > adminMaxBody {
		return liveConfigDoc{}, errors.New("admin api: the configuration is larger than the cap")
	}
	var doc liveConfigDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return liveConfigDoc{}, errors.New("admin api: the answer is not the configuration JSON")
	}
	return doc, nil
}

// liveRoute reduces the live configuration to the route of server. A route
// listed twice is reported as absent: the comparison cannot know which one
// the gateway serves.
func liveRoute(doc liveConfigDoc, server string) routeConfig {
	var rc routeConfig
	matches := 0
	var route liveRouteDoc
	for _, r := range doc.Routes {
		if r.Name == server {
			matches++
			route = r
		}
	}
	if matches != 1 {
		return rc
	}
	rc.found = true
	if gw, ok := doc.Gateways[route.Gateways]; ok {
		rc.bindAddress, rc.port = gw.BindAddress, strconv.Itoa(gw.Port)
	}
	if route.Policies.McpAuthorization != nil {
		for _, r := range route.Policies.McpAuthorization.Rules {
			rc.rules = append(rc.rules, r.Allow)
		}
	}
	if route.Policies.McpGuardrails != nil {
		for _, p := range route.Policies.McpGuardrails.Processors {
			rc.processors = append(rc.processors, processorConfig{host: p.Host, kind: p.Kind, failureMode: p.FailureMode, methods: p.Methods})
		}
	}
	for _, b := range route.Backends {
		for _, t := range b.Mcp.Targets {
			rc.backendHosts = append(rc.backendHosts, t.Mcp.Host)
		}
	}
	return rc
}

// compareRoutes names every field in which the configuration the gateway is
// running differs from the emitted file. Values are escaped; backend hosts
// are never shown, because an upstream URL may carry a credential.
func compareRoutes(emitted, live routeConfig) []string {
	if !live.found {
		return []string{"the live configuration has no route for the server (or lists it twice); its path is served by nothing or by another route"}
	}
	var diffs []string
	diffs = appendDiff(diffs, "bind address", emitted.bindAddress, live.bindAddress)
	diffs = appendDiff(diffs, "serving port", emitted.port, live.port)
	diffs = append(diffs, compareRules(emitted.rules, live.rules)...)
	diffs = append(diffs, compareProcessors(emitted.processors, live.processors)...)
	diffs = append(diffs, compareHosts(emitted.backendHosts, live.backendHosts)...)
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

// compareProcessors compares the processors; a live route without one is the
// F3 case the canary exists for.
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
	}
	return diffs
}

// compareHosts compares the backend hosts without showing them.
func compareHosts(emitted, live []string) []string {
	if len(emitted) != len(live) {
		return []string{fmt.Sprintf("backend targets: emitted %d, live %d", len(emitted), len(live))}
	}
	var diffs []string
	for i := range emitted {
		if emitted[i] != live[i] {
			diffs = append(diffs, "backend host: the live route points at another upstream (values withheld: an upstream URL may carry a credential)")
		}
	}
	return diffs
}

// describeMethods renders a processor's method map in a fixed order, for a
// difference line. The result is escaped once more by shown.
func describeMethods(m map[string]string) string {
	if len(m) == 0 {
		return noneShown
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
}
