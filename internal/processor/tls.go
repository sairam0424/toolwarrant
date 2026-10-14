package processor

import (
	"crypto/tls"
	"errors"
)

var (
	// errTLSNoCertificate means Config.TLS carries nothing the server could
	// present, so every handshake would fail; Serve refuses to start rather
	// than listen on a port the gateway can never use.
	errTLSNoCertificate = errors.New("processor: tls configuration carries no server certificate")

	// errTLSNoClientCAs means Config.TLS requires a verified client
	// certificate but names no authority to verify it against. crypto/tls
	// would then verify against the system roots, so any certificate a public
	// authority issued would pass as the gateway; the processor fails closed
	// instead (D19 planned).
	errTLSNoClientCAs = errors.New("processor: tls requires a verified client certificate but names no client certificate authority")
)

// hardenTLS returns a copy of c whose minimum protocol version is TLS 1.3, or
// nil for nil. The caller's configuration is never written to; the copy is
// what Serve hands to the transport. 1.3 is the floor because the link carries
// every decision the gateway acts on and nothing on it needs an older peer:
// the gateway's rustls client speaks 1.3 (D19 planned). A caller that asked for
// a higher minimum keeps it.
func hardenTLS(c *tls.Config) *tls.Config {
	if c == nil {
		return nil
	}
	hardened := c.Clone()
	if hardened.MinVersion < tls.VersionTLS13 {
		hardened.MinVersion = tls.VersionTLS13
	}
	return hardened
}

// checkTLS refuses a TLS configuration the listener could not serve safely: no
// certificate to present, or client verification against no authority.
func checkTLS(c *tls.Config) error {
	switch {
	case c == nil:
		return nil
	case len(c.Certificates) == 0 && c.GetCertificate == nil && c.GetConfigForClient == nil:
		return errTLSNoCertificate
	case c.ClientAuth == tls.RequireAndVerifyClientCert && c.ClientCAs == nil:
		return errTLSNoClientCAs
	}
	return nil
}

// verifiesClients reports whether the listener authenticates the gateway by a
// certificate: TLS is on and every connection must present a certificate that
// ClientCAs signed. RequireAnyClientCert and VerifyClientCertIfGiven do not
// count, since the first accepts any certificate and the second accepts none,
// so neither says who is on the other end.
func (s *Server) verifiesClients() bool {
	return s.tlsConf != nil && s.tlsConf.ClientAuth == tls.RequireAndVerifyClientCert
}
