package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
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
	// nonExactPath stands for a live route match that is not an exact path
	// (a prefix, a regex, or no path at all): it cannot equal an emitted match
	// and it still owns whatever it matches.
	nonExactPath = "(not an exact path)"
)

// liveConfigDoc is the pinned subset of GET /api/config: the gateways with
// their bind and port, and every route with its matches, policies and
// backends. Fields the comparison does not read are left out; an unknown
// field in the answer is ignored, a missing one compares as empty.
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
	Matches  []struct {
		Path struct {
			Exact string `json:"exact"`
		} `json:"path"`
	} `json:"matches"`
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

// config reduces the live document to the shape the comparison works on:
// every gateway and every route, in document order, nothing dropped. A port
// of zero means the gateway declared none.
func (d liveConfigDoc) config() configDoc {
	out := configDoc{gateways: map[string]gatewayConfig{}}
	for name, gw := range d.Gateways {
		port := ""
		if gw.Port != 0 {
			port = strconv.Itoa(gw.Port)
		}
		out.gateways[name] = gatewayConfig{bindAddress: gw.BindAddress, port: port}
	}
	for _, r := range d.Routes {
		out.routes = append(out.routes, r.config())
	}
	return out
}

// config reduces one live route to the compared fields.
func (r liveRouteDoc) config() routeConfig {
	rc := routeConfig{name: r.Name, gateway: r.Gateways}
	for _, m := range r.Matches {
		if m.Path.Exact == "" {
			rc.paths = append(rc.paths, nonExactPath)
			continue
		}
		rc.paths = append(rc.paths, m.Path.Exact)
	}
	if r.Policies.McpAuthorization != nil {
		for _, rule := range r.Policies.McpAuthorization.Rules {
			rc.rules = append(rc.rules, rule.Allow)
		}
	}
	if r.Policies.McpGuardrails != nil {
		for _, p := range r.Policies.McpGuardrails.Processors {
			rc.processors = append(rc.processors, processorConfig{host: p.Host, kind: p.Kind, failureMode: p.FailureMode, methods: p.Methods})
		}
	}
	for _, b := range r.Backends {
		for _, t := range b.Mcp.Targets {
			rc.backendHosts = append(rc.backendHosts, t.Mcp.Host)
		}
	}
	return rc
}
