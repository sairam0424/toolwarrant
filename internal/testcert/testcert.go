// Package testcert generates throwaway X.509 material for tests: a certificate
// authority, a server certificate for the processor and client certificates
// for a gateway stand-in, all ECDSA P-256 and valid for one hour from the
// moment they are made. Nothing here is checked into the tree: every key and
// certificate is made when a test asks, so the repository holds no key
// material, and the package is imported by test files only (the processor's
// TLS tests, the serve command's, and end-to-end scenario Q).
// The TLS link it serves is recorded as D19.
package testcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	// ServerName is the DNS name the server certificate carries, and so the
	// name a client verifies the processor under (the gateway's backendTLS
	// hostname emit --processor-tls writes, D19).
	ServerName = "toolwarrant-processor"
	// validFor bounds every certificate's life. Tests finish in minutes; a
	// certificate that outlived the test run would be a secret worth keeping.
	validFor = time.Hour
	// serialBits sizes the random serial numbers; 128 bits is what public
	// authorities use, enough that two certificates of one run never collide.
	serialBits = 128
	// FileMode is how Write stores a key or certificate: owner-only, which is
	// what serve requires of --tls-key.
	FileMode       os.FileMode = 0o600
	pemCertificate             = "CERTIFICATE"
	pemPrivateKey              = "PRIVATE KEY"
	certSuffix                 = ".crt"
	keySuffix                  = ".key"
)

// Authority is a certificate authority made for one test. Its private key
// never leaves the process.
type Authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	// CertPEM is the CA certificate alone, PEM-encoded: what --tls-client-ca
	// names on the processor side and what root names on the gateway side.
	CertPEM []byte
	// Pool holds the CA certificate alone, for a tls.Config's RootCAs or
	// ClientCAs.
	Pool *x509.CertPool
}

// Pair is one leaf certificate with its private key, in the two forms a test
// needs: PEM for the files a command reads and tls.Certificate for a client
// or server configuration built in the test.
type Pair struct {
	CertPEM []byte
	KeyPEM  []byte
	TLS     tls.Certificate
}

// NewAuthority makes a CA named name. Every certificate it issues chains to it
// and to nothing else, so a peer that trusts another authority refuses them.
func NewAuthority(t testing.TB, name string) *Authority {
	t.Helper()
	key := newKey(t)
	template := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("testcert: create authority %s: %v", name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("testcert: parse authority %s: %v", name, err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &Authority{cert: cert, key: key, CertPEM: encode(pemCertificate, der), Pool: pool}
}

// Server issues the processor's certificate: the DNS name ServerName and the
// loopback IP literals as subject alternative names, for server authentication.
func (a *Authority) Server(t testing.TB) Pair {
	t.Helper()
	return a.issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: ServerName},
		DNSNames:    []string{ServerName},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
}

// Client issues a certificate for a gateway stand-in named name, for client
// authentication only.
func (a *Authority) Client(t testing.TB, name string) Pair {
	t.Helper()
	return a.issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: name},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
}

// Write stores the CA certificate as base+".crt" in dir, owner-only, and
// returns its path.
func (a *Authority) Write(t testing.TB, dir, base string) string {
	t.Helper()
	path := filepath.Join(dir, base+certSuffix)
	writeFile(t, path, a.CertPEM)
	return path
}

// Write stores the certificate as base+".crt" and the key as base+".key" in
// dir, both owner-only, and returns the two paths.
func (p Pair) Write(t testing.TB, dir, base string) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, base+certSuffix)
	keyPath = filepath.Join(dir, base+keySuffix)
	writeFile(t, certPath, p.CertPEM)
	writeFile(t, keyPath, p.KeyPEM)
	return certPath, keyPath
}

// issue signs template with the authority's key, filling in the serial number
// and the validity window.
func (a *Authority) issue(t testing.TB, template *x509.Certificate) Pair {
	t.Helper()
	key := newKey(t)
	template.SerialNumber = serial(t)
	template.NotBefore = time.Now().Add(-time.Minute)
	template.NotAfter = time.Now().Add(validFor)
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatalf("testcert: issue %s: %v", template.Subject.CommonName, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("testcert: encode key of %s: %v", template.Subject.CommonName, err)
	}
	pair := Pair{CertPEM: encode(pemCertificate, der), KeyPEM: encode(pemPrivateKey, keyDER)}
	pair.TLS, err = tls.X509KeyPair(pair.CertPEM, pair.KeyPEM)
	if err != nil {
		t.Fatalf("testcert: pair %s does not load: %v", template.Subject.CommonName, err)
	}
	return pair
}

// newKey makes a P-256 key, the curve every TLS 1.3 peer supports.
func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("testcert: generate key: %v", err)
	}
	return key
}

// serial draws a random positive serial number.
func serial(t testing.TB) *big.Int {
	t.Helper()
	limit := new(big.Int).Lsh(big.NewInt(1), serialBits)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		t.Fatalf("testcert: serial number: %v", err)
	}
	return n.Add(n, big.NewInt(1))
}

// encode wraps DER bytes in one PEM block.
func encode(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

// writeFile stores data owner-only; a test that needs a looser mode changes
// it afterwards on purpose.
func writeFile(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, FileMode); err != nil {
		t.Fatalf("testcert: write %s: %v", path, err)
	}
}
