package main

import (
	"fmt"
	"net"
	"net/url"
)

// The canary's own addresses held against the emitted file (D17 i). Until the
// seventh review the live comparison bound the listing to the file by the
// path of --url alone: a canary pointed at a second gateway instance, a
// staging port or a copy of the file running elsewhere listed through one
// listener and asked another admin API, and printed "live configuration
// matches the emitted file" for a gateway it never touched (canary-4). Ports
// are compared always; hosts only when the emitted one is a loopback address,
// because a port-forward or a non-loopback bind makes a host difference
// legitimate while a listing that left the host cannot have reached a
// loopback listener.

// Default ports of the URL schemes the canary accepts, for a --url or --admin
// without an explicit port.
const (
	schemeHTTP       = "http"
	schemeHTTPS      = "https"
	defaultPortHTTP  = "80"
	defaultPortHTTPS = "443"
)

// compareCanaryAddresses names every way in which --url and --admin point
// elsewhere than the emitted file: the port of --url against the serving port
// of the gateway the server's route attaches to, the port of --admin against
// the emitted adminAddr, and each host against a loopback emitted address. An
// emitted file that has no such route or gateway, or a --url that does not
// parse, is reported by the other comparisons and adds nothing here.
func compareCanaryAddresses(emitted configDoc, server, rawURL, adminURL string) []string {
	var diffs []string
	rc, n := emitted.route(server)
	if n != 1 {
		return nil
	}
	if gw, ok := emitted.gateways[rc.gateway]; ok {
		diffs = append(diffs, compareURLListener(rawURL, rc.gateway, gw)...)
	}
	if adminURL != "" {
		diffs = append(diffs, compareAdminListener(adminURL, emitted.listeners.adminAddr)...)
	}
	return diffs
}

// compareURLListener holds the host and port of --url against the emitted
// gateway's bind address and serving port.
func compareURLListener(rawURL, gatewayName string, gw gatewayConfig) []string {
	host, port, ok := hostPortOfURL(rawURL)
	if !ok {
		return nil
	}
	var diffs []string
	if port != gw.port {
		diffs = append(diffs, fmt.Sprintf("the port of --url (%s) is not the serving port of the emitted gateway %s (%s); the listing above went through another listener", shown(port), cell(gatewayName), shown(gw.port)))
	}
	if isLoopbackHost(gw.bindAddress) && !isLoopbackHost(host) {
		diffs = append(diffs, fmt.Sprintf("the host of --url (%s) is not a loopback address like the emitted bind address (%s); the listing above went through another host", shown(host), shown(gw.bindAddress)))
	}
	return diffs
}

// compareAdminListener holds the host and port of --admin against the emitted
// adminAddr. An emitted adminAddr that is not a host:port (off, or absent)
// means the file describes a gateway without an admin API, so whoever
// answered --admin was not that gateway.
func compareAdminListener(adminURL, emittedAdmin string) []string {
	host, port, ok := hostPortOfURL(adminURL)
	if !ok {
		return nil
	}
	emittedHost, emittedPort, err := net.SplitHostPort(emittedAdmin)
	if err != nil {
		return []string{fmt.Sprintf("the emitted file sets adminAddr to %s, so no admin API of that gateway answered --admin (%s); the live configuration above came from another process", shown(emittedAdmin), shown(net.JoinHostPort(host, port)))}
	}
	var diffs []string
	if port != emittedPort {
		diffs = append(diffs, fmt.Sprintf("the port of --admin (%s) is not the port of the emitted adminAddr (%s); the live configuration above came from another admin API", shown(port), shown(emittedAdmin)))
	}
	if isLoopbackHost(emittedHost) && !isLoopbackHost(host) {
		diffs = append(diffs, fmt.Sprintf("the host of --admin (%s) is not a loopback address like the emitted adminAddr (%s); the live configuration above came from another admin API", shown(host), shown(emittedAdmin)))
	}
	return diffs
}

// hostPortOfURL is the host and the port of a URL, the port defaulted by
// scheme when the URL names none; false for a URL that does not parse or has
// no host, which the listing or the admin fetch reports on its own.
func hostPortOfURL(raw string) (host, port string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", false
	}
	host, port = u.Hostname(), u.Port()
	if port == "" {
		switch u.Scheme {
		case schemeHTTP:
			port = defaultPortHTTP
		case schemeHTTPS:
			port = defaultPortHTTPS
		}
	}
	return host, port, true
}
