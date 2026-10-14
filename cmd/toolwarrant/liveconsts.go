package main

// The emitted file as the comparison reads it. The file is toolwarrant's own
// output, two-space indented with every scalar written by emit's quote, so a
// line-based reader is enough and no YAML library is needed. The indentation
// constants are the ones internal/emit writes with; a change there must
// change these, which the test against a freshly emitted file catches. The
// backendTLS block (processors[].policies.backendTLS, limit L11) is read at
// the place and indentation emit will write it, ahead of emit writing it, so
// that the canary never calls a live block a match it cannot read.
const (
	indentConfigKey    = 2
	indentGatewayName  = 2
	indentGatewayKey   = 4
	indentRouteField   = 2
	indentRouteItem    = 6
	indentProcessor    = 8
	indentProcessorKV  = 10
	indentProcessorTLS = 12
	sectionConfig      = "config"
	sectionGateways    = "gateways"
	sectionRoutes      = "routes"
	keyPort            = "port"
	keyBindAddress     = "bindAddress"
	keyAdminAddr       = "adminAddr"
	keyStatsAddr       = "statsAddr"
	keyReadinessAddr   = "readinessAddr"
	keyKind            = "kind"
	keyFailureMode     = "failureMode"
	keyMethods         = "methods:"
	keyRequestHeaders  = "requestHeaders:"
	keyMetadata        = "metadata:"
	keyAllowed         = "allowed:"
	keyDisallowed      = "disallowed:"
	// policiesBlock and tlsBlockName are the keys of the processor's
	// policies object and of its backendTLS block as both the emitted file
	// and the live document spell them; keyPolicies and keyBackendTLS are
	// their block openers in the file.
	policiesBlock   = "policies"
	tlsBlockName    = "backendTLS"
	keyPolicies     = policiesBlock + ":"
	keyBackendTLS   = tlsBlockName + ":"
	keyTLSCert      = "cert"
	keyTLSKey       = "key"
	keyTLSRoot      = "root"
	keyTLSHostname  = "hostname"
	routeItemPrefix = "- name: "
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
	// procSectionPolicies is open between the processor's policies: line
	// and the next indent-8 key; procSectionTLS while its backendTLS: block
	// is being read, so that indent-12 lines reach the TLS fields only there.
	procSectionPolicies = policiesBlock
	procSectionTLS      = tlsBlockName
)
