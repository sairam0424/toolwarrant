package main

// The emitted file as the comparison reads it. The file is toolwarrant's own
// output, two-space indented with every scalar written by emit's quote, so a
// line-based reader is enough and no YAML library is needed. The indentation
// constants are the ones internal/emit writes with; a change there must
// change these, which the test against a freshly emitted file catches.
const (
	indentConfigKey   = 2
	indentGatewayName = 2
	indentGatewayKey  = 4
	indentRouteField  = 2
	indentRouteItem   = 6
	indentProcessor   = 8
	indentProcessorKV = 10
	sectionConfig     = "config"
	sectionGateways   = "gateways"
	sectionRoutes     = "routes"
	keyPort           = "port"
	keyBindAddress    = "bindAddress"
	keyAdminAddr      = "adminAddr"
	keyStatsAddr      = "statsAddr"
	keyReadinessAddr  = "readinessAddr"
	keyKind           = "kind"
	keyFailureMode    = "failureMode"
	keyMethods        = "methods:"
	keyRequestHeaders = "requestHeaders:"
	keyMetadata       = "metadata:"
	keyAllowed        = "allowed:"
	keyDisallowed     = "disallowed:"
	routeItemPrefix   = "- name: "
	// targetItemPrefix opens one MCP backend target inside the route's
	// backends block, at indent 6; the route item of the same text sits at
	// indent 0, so the indent tells them apart (seventh review canary-3).
	targetItemPrefix   = routeItemPrefix
	gatewayRefPrefix   = "gateways: "
	exactPathPrefix    = "exact: "
	allowItemPrefix    = "- allow: "
	hostItemPrefix     = "- host: "
	hostKeyPrefix      = "host: "
	listItemPrefix     = "- "
	keyValueSep        = ": "
	noRoute            = -1
	procSectionNone    = ""
	procSectionMethods = "methods"
	procSectionHeaders = "requestHeaders"
	procSectionAllowed = "allowed"
	procSectionDenied  = "disallowed"
	procSectionMeta    = "metadata"
)
