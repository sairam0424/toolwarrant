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

// knownSections are the top-level sections the emitted file carries and the
// comparison reads. agentgateway v1.6.0 loads eleven more (binds,
// frontendPolicies, policies, workloads, services, backends, routeGroups,
// tcpRoutes, llm, mcp, ui); any of them in the live document may bind ports
// and routes the comparison cannot see, so each is a difference of its own
// (D14 i). A list, not a map, so the package holds no mutable state.
func knownSections() []string { return []string{sectionConfig, sectionGateways, sectionRoutes} }

// liveConfigDoc is the pinned subset of GET /api/config: the config block
// with the gateway's own listeners, the gateways with their bind and port,
// every route with its matches, policies and backends, and the names of the
// other top-level sections that are not empty. A field the comparison does
// not read inside a known section is ignored, a missing one compares as
// empty.
type liveConfigDoc struct {
	Config struct {
		AdminAddr     string `json:"adminAddr"`
		StatsAddr     string `json:"statsAddr"`
		ReadinessAddr string `json:"readinessAddr"`
	} `json:"config"`
	Gateways map[string]struct {
		Port        int    `json:"port"`
		BindAddress string `json:"bindAddress"`
	} `json:"gateways"`
	Routes []liveRouteDoc `json:"routes"`
	// extraSections are the top-level keys other than the known ones whose
	// value is not empty, in document order of first appearance.
	extraSections []string
}

// liveProcessorDoc is one mcpGuardrails processor of a live route. The
// request-header filter is a pointer so that an entry without one stays nil,
// and the metadata is kept raw so that its values are hashed, never decoded
// into a message.
type liveProcessorDoc struct {
	Host           string            `json:"host"`
	Kind           string            `json:"kind"`
	FailureMode    string            `json:"failureMode"`
	Methods        map[string]string `json:"methods"`
	RequestHeaders *struct {
		Allowed    []string `json:"allowed"`
		Disallowed []string `json:"disallowed"`
	} `json:"requestHeaders"`
	Metadata map[string]json.RawMessage `json:"metadata"`
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
			Processors []liveProcessorDoc `json:"processors"`
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
	return decodeLiveConfig(body)
}

// decodeLiveConfig reads the whole document twice: once generically, to see
// every top-level section the gateway loaded, and once into the pinned shape.
// A document that is not a JSON object is refused as a whole.
func decodeLiveConfig(body []byte) (liveConfigDoc, error) {
	var sections map[string]json.RawMessage
	if err := json.Unmarshal(body, &sections); err != nil || sections == nil {
		return liveConfigDoc{}, errors.New("admin api: the answer is not the configuration JSON")
	}
	var doc liveConfigDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return liveConfigDoc{}, errors.New("admin api: the answer is not the configuration JSON")
	}
	known := map[string]bool{}
	for _, name := range knownSections() {
		known[name] = true
	}
	for _, name := range sortedKeys(sections) {
		if !known[name] && sectionHasContent(sections[name]) {
			doc.extraSections = append(doc.extraSections, name)
		}
	}
	return doc, nil
}

// sectionHasContent reports whether a top-level section carries anything: a
// null, an empty object or an empty array binds nothing and is not reported;
// everything else is.
func sectionHasContent(raw json.RawMessage) bool {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return true
	}
	switch x := v.(type) {
	case nil:
		return false
	case map[string]any:
		return len(x) > 0
	case []any:
		return len(x) > 0
	}
	return true
}

// config reduces the live document to the shape the comparison works on:
// the listeners, every gateway and every route, in document order, nothing
// dropped, plus the names of the sections the file does not carry. A port of
// zero means the gateway declared none.
func (d liveConfigDoc) config() configDoc {
	out := configDoc{
		listeners:     listenerConfig{adminAddr: d.Config.AdminAddr, statsAddr: d.Config.StatsAddr, readinessAddr: d.Config.ReadinessAddr},
		gateways:      map[string]gatewayConfig{},
		extraSections: d.extraSections,
	}
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
			rc.processors = append(rc.processors, p.config())
		}
	}
	for _, b := range r.Backends {
		for _, t := range b.Mcp.Targets {
			rc.backendHosts = append(rc.backendHosts, t.Mcp.Host)
		}
	}
	return rc
}

// config reduces one live processor to the compared fields. The header lists
// stay nil when the entry carries no filter; a metadata value that is a JSON
// string is hashed as that string (the emitted file writes each value as a
// quoted scalar, which the gateway renders back as a string), anything else
// as its compact JSON text.
func (p liveProcessorDoc) config() processorConfig {
	pc := processorConfig{host: p.Host, kind: p.Kind, failureMode: p.FailureMode, methods: p.Methods}
	if p.RequestHeaders != nil {
		pc.allowed = append([]string{}, p.RequestHeaders.Allowed...)
		pc.disallowed = append([]string{}, p.RequestHeaders.Disallowed...)
	}
	meta := map[string]string{}
	for k, raw := range p.Metadata {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			s = string(raw)
		}
		meta[k] = s
	}
	pc.metadataHash = metadataDigest(meta)
	return pc
}
