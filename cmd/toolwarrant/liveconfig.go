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
	indentGatewayKey  = 4
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
	allowItemPrefix   = "- allow: "
	hostItemPrefix    = "- host: "
	hostKeyPrefix     = "host: "
	keyValueSep       = ": "
)

// processorConfig is one mcpGuardrails processor of a route.
type processorConfig struct {
	host, kind, failureMode string
	methods                 map[string]string
}

// routeConfig is what one route of the gateway configuration says about a
// server, reduced to the fields the canary compares between the file emit
// wrote and the configuration the gateway is running: the bind address and
// port of the gateway the route attaches to, the allow rules, the processors
// and the backend hosts. Both sides take this shape so that a comparison
// names the field that differs rather than two documents.
type routeConfig struct {
	found        bool
	bindAddress  string
	port         string
	rules        []string
	processors   []processorConfig
	backendHosts []string
}

// emittedParser walks the lines of an emitted file.
type emittedParser struct {
	rc        routeConfig
	section   string
	inRoute   bool
	proc      *processorConfig
	inMethods bool
}

// emittedRoute reads the route of server and its gateway from an emitted file.
// A file without a route for the server returns found false; a file that is
// not shaped the way emit writes returns an error, because guessing at it
// could make the live configuration look like a match.
func emittedRoute(file []byte, server string) (routeConfig, error) {
	p := &emittedParser{}
	for _, raw := range strings.Split(string(file), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		var err error
		switch {
		case indent == 0:
			err = p.topLevel(line, server)
		case p.section == sectionGateways && indent == indentGatewayKey:
			err = p.gatewayLine(line)
		case p.inRoute:
			err = p.routeLine(indent, line)
		}
		if err != nil {
			return routeConfig{}, err
		}
	}
	return p.rc, nil
}

// topLevel handles a section key or a route item.
func (p *emittedParser) topLevel(line, server string) error {
	p.proc, p.inMethods = nil, false
	if !strings.HasPrefix(line, routeItemPrefix) {
		p.section, p.inRoute = strings.TrimSuffix(line, ":"), false
		return nil
	}
	name, err := unquoteScalar(strings.TrimPrefix(line, routeItemPrefix))
	if err != nil {
		return err
	}
	p.inRoute = p.section == sectionRoutes && name == server
	if p.inRoute {
		if p.rc.found {
			return errors.New("the emitted file lists the route twice")
		}
		p.rc.found = true
	}
	return nil
}

// gatewayLine reads the serving port and the bind address.
func (p *emittedParser) gatewayLine(line string) error {
	key, value, _ := strings.Cut(line, keyValueSep)
	switch key {
	case keyPort:
		p.rc.port = value
	case keyBindAddress:
		v, err := unquoteScalar(value)
		if err != nil {
			return err
		}
		p.rc.bindAddress = v
	}
	return nil
}

// routeLine reads one line inside the wanted route: the allow rule, a
// processor and its fields, or the backend host. The secret, when present,
// sits under metadata at the same indentation as the methods and is neither
// read nor compared.
func (p *emittedParser) routeLine(indent int, line string) error {
	switch {
	case indent == indentRouteItem && strings.HasPrefix(line, allowItemPrefix):
		return appendQuoted(&p.rc.rules, strings.TrimPrefix(line, allowItemPrefix))
	case indent == indentRouteItem && strings.HasPrefix(line, hostItemPrefix):
		host, err := unquoteScalar(strings.TrimPrefix(line, hostItemPrefix))
		if err != nil {
			return err
		}
		p.rc.processors = append(p.rc.processors, processorConfig{host: host, methods: map[string]string{}})
		p.proc, p.inMethods = &p.rc.processors[len(p.rc.processors)-1], false
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
		return appendQuoted(&p.rc.backendHosts, strings.TrimPrefix(line, hostKeyPrefix))
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
	case keyKind, keyFailureMode:
		v, err := unquoteScalar(value)
		if err != nil {
			return err
		}
		if key == keyKind {
			p.proc.kind = v
		} else {
			p.proc.failureMode = v
		}
	}
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
