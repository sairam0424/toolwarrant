package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// The emitted file as the comparison reads it. The file is toolwarrant's own
// output, two-space indented with every scalar written by emit's quote, so a
// line-based reader is enough and no YAML library is needed. The indentation
// constants are the ones internal/emit writes with; a change there must
// change these, which the test against a freshly emitted file catches.
const (
	indentGatewayName = 2
	indentGatewayKey  = 4
	indentRouteField  = 2
	indentRouteItem   = 6
	indentProcessor   = 8
	indentProcessorKV = 10
	sectionGateways   = "gateways"
	sectionRoutes     = "routes"
	keyPort           = "port"
	keyBindAddress    = "bindAddress"
	keyKind           = "kind"
	keyFailureMode    = "failureMode"
	keyMethods        = "methods:"
	routeItemPrefix   = "- name: "
	gatewayRefPrefix  = "gateways: "
	exactPathPrefix   = "exact: "
	allowItemPrefix   = "- allow: "
	hostItemPrefix    = "- host: "
	hostKeyPrefix     = "host: "
	keyValueSep       = ": "
	noRoute           = -1
)

// gatewayConfig is one gateway of the configuration: where it listens.
type gatewayConfig struct {
	bindAddress, port string
}

// processorConfig is one mcpGuardrails processor of a route.
type processorConfig struct {
	host, kind, failureMode string
	methods                 map[string]string
}

// routeConfig is one route of the gateway configuration reduced to the fields
// the canary compares between the file emit wrote and the configuration the
// gateway is running: its name, the gateway it attaches to, the exact paths it
// matches, the allow rules, the processors and the backend hosts. Both sides
// take this shape so that a comparison names the field that differs rather
// than two documents.
type routeConfig struct {
	name, gateway string
	paths         []string
	rules         []string
	processors    []processorConfig
	backendHosts  []string
}

// configDoc is a whole gateway configuration as the canary compares it: every
// gateway by name and every route in document order. The comparison is over
// the whole document (D13 e), because a route or a gateway the file does not
// carry serves clients without the emitted guards however intact the
// server's own route is.
type configDoc struct {
	gateways map[string]gatewayConfig
	routes   []routeConfig
}

// route returns the route named name and how many routes carry that name; a
// name listed twice is reported as such, because the comparison cannot know
// which one the gateway serves.
func (d configDoc) route(name string) (routeConfig, int) {
	var found routeConfig
	n := 0
	for _, r := range d.routes {
		if r.name == name {
			found = r
			n++
		}
	}
	return found, n
}

// emittedParser walks the lines of an emitted file.
type emittedParser struct {
	doc       configDoc
	section   string
	gateway   string // the gateway whose keys are being read, in the gateways section
	route     int    // index of the route being read, noRoute outside one
	proc      *processorConfig
	inMethods bool
}

// emittedConfig reads every gateway and route of an emitted file. A file that
// is not shaped the way emit writes returns an error, because guessing at it
// could make the live configuration look like a match.
func emittedConfig(file []byte) (configDoc, error) {
	p := &emittedParser{doc: configDoc{gateways: map[string]gatewayConfig{}}, route: noRoute}
	for _, raw := range strings.Split(string(file), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		var err error
		switch {
		case indent == 0:
			err = p.topLevel(line)
		case p.section == sectionGateways:
			err = p.gatewayLine(indent, line)
		case p.route != noRoute:
			err = p.routeLine(indent, line)
		}
		if err != nil {
			return configDoc{}, err
		}
	}
	return p.doc, nil
}

// topLevel handles a section key or a route item.
func (p *emittedParser) topLevel(line string) error {
	p.proc, p.inMethods, p.gateway = nil, false, ""
	if !strings.HasPrefix(line, routeItemPrefix) {
		p.section, p.route = strings.TrimSuffix(line, ":"), noRoute
		return nil
	}
	if p.section != sectionRoutes {
		return fmt.Errorf("the emitted file holds a list item outside the routes section: %s", textdiff.Escape(line))
	}
	name, err := unquoteScalar(strings.TrimPrefix(line, routeItemPrefix))
	if err != nil {
		return err
	}
	if _, n := p.doc.route(name); n > 0 {
		return fmt.Errorf("the emitted file lists route %s twice", cell(name))
	}
	p.doc.routes = append(p.doc.routes, routeConfig{name: name})
	p.route = len(p.doc.routes) - 1
	return nil
}

// gatewayLine reads a gateway's name, then its serving port and bind address.
func (p *emittedParser) gatewayLine(indent int, line string) error {
	switch indent {
	case indentGatewayName:
		name := strings.TrimSuffix(line, ":")
		if _, dup := p.doc.gateways[name]; dup {
			return fmt.Errorf("the emitted file lists gateway %s twice", cell(name))
		}
		p.gateway = name
		p.doc.gateways[name] = gatewayConfig{}
	case indentGatewayKey:
		if p.gateway == "" {
			return fmt.Errorf("the emitted file holds a gateway key outside a gateway: %s", textdiff.Escape(line))
		}
		gw := p.doc.gateways[p.gateway]
		key, value, _ := strings.Cut(line, keyValueSep)
		switch key {
		case keyPort:
			gw.port = value
		case keyBindAddress:
			v, err := unquoteScalar(value)
			if err != nil {
				return err
			}
			gw.bindAddress = v
		}
		p.doc.gateways[p.gateway] = gw
	}
	return nil
}

// routeLine reads one line inside the current route: the gateway it attaches
// to, the exact path, the allow rule, a processor and its fields, or the
// backend host. The secret, when present, sits under metadata at the same
// indentation as the methods and is neither read nor compared.
func (p *emittedParser) routeLine(indent int, line string) error {
	rc := &p.doc.routes[p.route]
	switch {
	case indent == indentRouteField && strings.HasPrefix(line, gatewayRefPrefix):
		p.proc, p.inMethods = nil, false
		return setQuoted(&rc.gateway, strings.TrimPrefix(line, gatewayRefPrefix))
	case indent == indentRouteItem && strings.HasPrefix(line, exactPathPrefix):
		return appendQuoted(&rc.paths, strings.TrimPrefix(line, exactPathPrefix))
	case indent == indentRouteItem && strings.HasPrefix(line, allowItemPrefix):
		return appendQuoted(&rc.rules, strings.TrimPrefix(line, allowItemPrefix))
	case indent == indentRouteItem && strings.HasPrefix(line, hostItemPrefix):
		host, err := unquoteScalar(strings.TrimPrefix(line, hostItemPrefix))
		if err != nil {
			return err
		}
		rc.processors = append(rc.processors, processorConfig{host: host, methods: map[string]string{}})
		p.proc, p.inMethods = &rc.processors[len(rc.processors)-1], false
	case indent == indentProcessor && p.proc != nil:
		return p.processorLine(line)
	case indent == indentProcessorKV && p.inMethods && p.proc != nil:
		key, value, _ := strings.Cut(line, keyValueSep)
		v, err := unquoteScalar(value)
		if err != nil {
			return err
		}
		p.proc.methods[key] = v
	case indent == indentProcessorKV && strings.HasPrefix(line, hostKeyPrefix):
		return appendQuoted(&rc.backendHosts, strings.TrimPrefix(line, hostKeyPrefix))
	case indent < indentProcessor:
		p.proc, p.inMethods = nil, false
	}
	return nil
}

// processorLine reads one field of the current processor.
func (p *emittedParser) processorLine(line string) error {
	if line == keyMethods {
		p.inMethods = true
		return nil
	}
	p.inMethods = false
	key, value, _ := strings.Cut(line, keyValueSep)
	switch key {
	case keyKind:
		return setQuoted(&p.proc.kind, value)
	case keyFailureMode:
		return setQuoted(&p.proc.failureMode, value)
	}
	return nil
}

// setQuoted unquotes a scalar into dst.
func setQuoted(dst *string, quoted string) error {
	v, err := unquoteScalar(quoted)
	if err != nil {
		return err
	}
	*dst = v
	return nil
}

// appendQuoted unquotes a scalar and appends it.
func appendQuoted(list *[]string, quoted string) error {
	v, err := unquoteScalar(quoted)
	if err != nil {
		return err
	}
	*list = append(*list, v)
	return nil
}

// unquoteScalar reads a double-quoted scalar as emit's quote wrote it. The
// escapes emit uses (backslash, double quote, \uXXXX, \UXXXXXXXX) are the ones
// a Go string literal uses, so strconv does the work.
func unquoteScalar(s string) (string, error) {
	if !strings.HasPrefix(s, `"`) {
		return "", fmt.Errorf("the emitted file holds an unquoted scalar where emit writes a quoted one: %s", textdiff.Escape(s))
	}
	v, err := strconv.Unquote(s)
	if err != nil {
		return "", fmt.Errorf("the emitted file holds a scalar emit could not have written: %w", err)
	}
	return v, nil
}

// emittedRouteOf is the route of server in an emitted file, or an error when
// the file has no such route or lists it twice: a canary with no emitted route
// to compare against must not report that the live one matches.
func emittedRouteOf(doc configDoc, server string) (routeConfig, error) {
	rc, n := doc.route(server)
	switch n {
	case 1:
		return rc, nil
	case 0:
		return routeConfig{}, fmt.Errorf("the file named by --config has no route for server %s; run emit again before comparing the live configuration with it", cell(server))
	}
	return routeConfig{}, errors.New("the emitted file lists the route twice")
}
