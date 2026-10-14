package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// TLS on the processor listener (D19, owner decision O-2). The three
// files are operator-given paths and go through readRegularFile like every
// other file the CLI opens by path; the private key must be owner-only, as the
// database is, because whoever reads it can stand in for the processor.
const (
	// maxTLSFileBytes bounds the certificate, key and CA files serve reads. A
	// PEM chain is a few kilobytes; the bound only stops a planted file from
	// being read without limit.
	maxTLSFileBytes = 1 << 20
	// keySharedBits are the permission bits that give group or others any
	// access to the private key: the catalog's rule for the database file.
	keySharedBits   os.FileMode = 0o077
	flagTLSCert                 = "--tls-cert"
	flagTLSKey                  = "--tls-key"
	flagTLSClientCA             = "--tls-client-ca"
)

// tlsFlags is what the operator said about TLS on the listener: the
// certificate and key the processor presents, and the authority whose client
// certificates it requires.
type tlsFlags struct {
	cert     string
	key      string
	clientCA string
}

// bindTLSFlags registers the three serve flags on fs.
func bindTLSFlags(fs *flag.FlagSet) *tlsFlags {
	f := &tlsFlags{}
	fs.StringVar(&f.cert, "tls-cert", "", "PEM certificate chain the processor presents; with --tls-key, hooks arrive over TLS 1.3 instead of plaintext (the gateway side is its backendTLS block)")
	fs.StringVar(&f.key, "tls-key", "", "PEM private key for --tls-cert; a regular file that group and others cannot read")
	fs.StringVar(&f.clientCA, "tls-client-ca", "", "PEM certificate authority; every connection must then present a client certificate this authority signed, which authenticates the hooks and satisfies the non-loopback rule in place of --secret-env")
	return f
}

// enabled reports whether any TLS flag was given.
func (f *tlsFlags) enabled() bool { return f.cert != "" || f.key != "" || f.clientCA != "" }

// requiresClient reports whether every connection must present a verified
// client certificate.
func (f *tlsFlags) requiresClient() bool { return f.clientCA != "" }

// check applies the usage rules: certificate and key both or neither, a client
// authority only with both, and no TLS on a unix socket, which its file
// permissions guard and which the gateway dials in plaintext. Each is a usage
// error because the fix is a flag.
func (f *tlsFlags) check(c *command, listen string) error {
	if !f.enabled() {
		return nil
	}
	if (f.cert == "") != (f.key == "") {
		return &usageError{msg: flagTLSCert + " and " + flagTLSKey + " go together: give both or neither", cmd: c}
	}
	if f.cert == "" {
		return &usageError{msg: flagTLSClientCA + " needs " + flagTLSCert + " and " + flagTLSKey + ": a client certificate can only be required on a TLS listener", cmd: c}
	}
	if strings.HasPrefix(listen, unixPrefix) {
		return &usageError{msg: "the TLS flags are refused with --listen unix:: a unix socket is guarded by its file permissions and the gateway dials it in plaintext; listen on a TCP address or drop the TLS flags", cmd: c}
	}
	return nil
}

// load reads the files and builds the listener's TLS configuration, or nil
// when no TLS flag was given. A file that is missing, not a regular file, too
// large, not PEM, or a key that others can read is an error of this command,
// not a usage error: the fix is on the file system.
func (f *tlsFlags) load() (*tls.Config, error) {
	if !f.enabled() {
		return nil, nil
	}
	certPEM, err := readTLSFile(f.cert, flagTLSCert)
	if err != nil {
		return nil, err
	}
	if err := refuseSharedKey(f.key); err != nil {
		return nil, err
	}
	keyPEM, err := readTLSFile(f.key, flagTLSKey)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load %s and %s: %w", flagTLSCert, flagTLSKey, err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	if f.clientCA == "" {
		return cfg, nil
	}
	pool, err := loadCertPool(f.clientCA, flagTLSClientCA)
	if err != nil {
		return nil, err
	}
	cfg.ClientCAs = pool
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	return cfg, nil
}

// refuseSharedKey refuses a private key that group or others can read. A path
// that is missing or not a regular file is left to readRegularFile, whose
// message names what was found.
func refuseSharedKey(path string) error {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	if perm := fi.Mode().Perm(); perm&keySharedBits != 0 {
		return fmt.Errorf("%s %s is readable by other users (mode %04o); whoever reads the key can stand in for the processor, so chmod 600 it", flagTLSKey, textdiff.Escape(path), perm)
	}
	return nil
}

// readTLSFile reads one of the three files through readRegularFile and names
// the flag and the path in the error unless the refusal already does (a path
// that is not a regular file).
func readTLSFile(path, flagName string) ([]byte, error) {
	data, err := readRegularFile(path, flagName, maxTLSFileBytes)
	switch {
	case err == nil:
		return data, nil
	case errors.Is(err, errNotRegular):
		return nil, err
	}
	return nil, fmt.Errorf("%s %s: %w", flagName, textdiff.Escape(path), err)
}

// loadCertPool reads a PEM file of certificates into a pool and refuses one
// that holds none, so a client authority can never be empty, which crypto/tls
// would read as "verify against the system roots".
func loadCertPool(path, flagName string) (*x509.CertPool, error) {
	data, err := readTLSFile(path, flagName)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s %s holds no PEM certificate", flagName, textdiff.Escape(path))
	}
	return pool, nil
}

// tlsNote says on the listening line how the link is protected, after the
// guarding part so the address stays where the tests and scripts read it.
func tlsNote(cfg *tls.Config) string {
	switch {
	case cfg == nil:
		return ""
	case cfg.ClientAuth == tls.RequireAndVerifyClientCert:
		return ", TLS 1.3 with a client certificate required"
	}
	return ", TLS 1.3 with a server certificate only"
}

// authNote says on the listening line whether hooks are authenticated, and by
// what, so an operator can see at a glance which mode the processor runs in.
func authNote(secret string, cfg *tls.Config) string {
	switch {
	case secret != "":
		return " (hooks must carry the shared secret)"
	case cfg != nil && cfg.ClientAuth == tls.RequireAndVerifyClientCert:
		return " (hooks are authenticated by the client certificate; no --secret-env)"
	}
	return " (hooks are not authenticated: no --secret-env)"
}
