package emit

import (
	"errors"
	"fmt"
)

// The backendTLS block of a processor entry (D19). agentgateway v1.6.0 dials
// a processor with TLS when its entry carries
// processors[].policies.backendTLS: cert and key name the PEM client
// certificate and private key the gateway presents, root the PEM bundle it
// verifies the processor's certificate against, and hostname the name it
// verifies that certificate under and sends as SNI. The three paths are read
// by the gateway process on the gateway host; the emitter writes them and
// never opens them. The gateway's --validate-only does open them
// (TestGatewayValidateOnlyOpensBackendTLSFiles), so an emit that validates
// with the gateway binary needs the three files at those paths on the host
// that emits.
const (
	policiesKey    = "policies"
	backendTLSKey  = "backendTLS"
	tlsCertKey     = "cert"
	tlsKeyKey      = "key"
	tlsRootKey     = "root"
	tlsHostnameKey = "hostname"
	// maxTLSPathLen bounds each path: PATH_MAX on Linux, and more than any
	// certificate store needs. The bound keeps a hostile flag value from
	// putting kilobytes into the file.
	maxTLSPathLen = 4096
	// tlsPathPrefix is what every path must start with. The gateway reads a
	// relative path from its own working directory, which the emitter cannot
	// know and the gateway's service manager may change; an absolute path
	// names one file on the gateway host.
	tlsPathPrefix = '/'
)

// ProcessorTLS is the gateway's side of TLS on the link to one processor: the
// four fields of the processors[].policies.backendTLS block the emitter
// writes (D19). All four are required, so that a block always says which
// certificate the gateway presents (the processor's --tls-client-ca verifies
// it; owner decision O-2), which authority it trusts for the processor's
// certificate, and under which name: a block with a root but no client
// certificate, or with no hostname, is one the gateway's own validation
// accepts, so the rule is the emitter's. The fields are paths on the gateway
// host and a DNS name, not secrets, so the emitter may show them in errors.
type ProcessorTLS struct {
	// Cert is the absolute path, on the gateway host, of the PEM certificate
	// chain the gateway presents to the processor as its client certificate.
	Cert string
	// Key is the absolute path, on the gateway host, of the PEM private key
	// of Cert. The gateway reads it; the emitter never does.
	Key string
	// Root is the absolute path, on the gateway host, of the PEM bundle of
	// the authority that signed the processor's certificate (serve
	// --tls-cert).
	Root string
	// Hostname is the DNS name the gateway verifies the processor's
	// certificate under and sends as SNI: the name the certificate carries as
	// a subject alternative name (the processor's --tls-cert). An IP literal
	// is refused, so that one certificate shape, a DNS name in the SAN, is
	// the documented one.
	Hostname string
}

// validateProcessorTLS checks one block, or accepts nil as "no TLS": every
// field present, every path absolute, bounded and printable ASCII, the
// hostname a DNS name. Nothing here reads a file: the paths are the gateway
// host's, and the emitter may run elsewhere.
func validateProcessorTLS(t *ProcessorTLS) error {
	if t == nil {
		return nil
	}
	for _, f := range []struct{ key, path string }{{tlsCertKey, t.Cert}, {tlsKeyKey, t.Key}, {tlsRootKey, t.Root}} {
		if err := validateTLSPath(f.key, f.path); err != nil {
			return err
		}
	}
	return validateTLSHostname(t.Hostname)
}

// validateTLSPath requires a non-empty absolute path of printable ASCII within
// maxTLSPathLen. A relative path is refused rather than resolved: the gateway
// would read it from its own working directory, which is not the emitter's.
func validateTLSPath(key, path string) error {
	switch {
	case path == "":
		return fmt.Errorf("%s %s is required: every field of the block names what the gateway presents, trusts and verifies", backendTLSKey, key)
	case len(path) > maxTLSPathLen:
		return fmt.Errorf("%s %s is longer than %d bytes", backendTLSKey, key, maxTLSPathLen)
	case !isPrintableASCII(path):
		return fmt.Errorf("%s %s must be printable ASCII", backendTLSKey, key)
	case path[0] != tlsPathPrefix:
		return fmt.Errorf("%s %s %s is not an absolute path: the gateway reads a relative path from its own working directory; name the file on the gateway host from /", backendTLSKey, key, shown(path))
	}
	return nil
}

// validateTLSHostname requires the DNS name the processor's certificate
// carries: printable ASCII within the host length, matching hostPattern, and
// neither an IP literal nor a numeric spelling the resolver would read as one
// (isNumericHost, the rule refuseAmbiguousHost applies to processor hosts).
// The gateway's own validation accepts an empty, missing or numeric hostname;
// the rule is the emitter's, so that the certificate shape is one.
func validateTLSHostname(host string) error {
	switch {
	case host == "":
		return errors.New(backendTLSKey + " " + tlsHostnameKey + " is required: it is the name the gateway verifies the processor's certificate under and sends as SNI")
	case len(host) > maxHostLen:
		return fmt.Errorf("%s %s is longer than %d bytes", backendTLSKey, tlsHostnameKey, maxHostLen)
	case !isPrintableASCII(host):
		return fmt.Errorf("%s %s must be printable ASCII", backendTLSKey, tlsHostnameKey)
	case isNumericHost(host), isIPLiteral(host):
		return fmt.Errorf("%s %s %s is an IP address or a numeric spelling: the gateway verifies the processor's certificate under this name and sends it as SNI, so it must be the DNS name the certificate carries", backendTLSKey, tlsHostnameKey, shown(host))
	case !hostPattern.MatchString(host):
		return fmt.Errorf("%s %s %s is not a DNS name", backendTLSKey, tlsHostnameKey, shown(host))
	}
	return nil
}

// writeProcessorTLS appends the policies block of a processor entry with its
// one backendTLS block: policies at the entry's field indent, backendTLS one
// level in, the four fields one level further, every value through quote.
// The canary reads the block at exactly these indents (cmd/toolwarrant
// livetls.go), so a change here is a change there.
func writeProcessorTLS(w *yamlWriter, t *ProcessorTLS) {
	w.line(8, policiesKey+":")
	w.line(10, backendTLSKey+":")
	w.line(12, tlsCertKey+": "+quote(t.Cert))
	w.line(12, tlsKeyKey+": "+quote(t.Key))
	w.line(12, tlsRootKey+": "+quote(t.Root))
	w.line(12, tlsHostnameKey+": "+quote(t.Hostname))
}
