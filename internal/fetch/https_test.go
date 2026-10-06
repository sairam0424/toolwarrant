package fetch

import (
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// trustServerCert makes client accept the self-signed certificate of srv. It
// reaches into the transport, which only package-internal tests can do; real
// callers always get the system trust store.
func trustServerCert(t *testing.T, client *http.Client, srv *httptest.Server) {
	t.Helper()
	_, base := mustGuard(t, client)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	base.TLSClientConfig.RootCAs = pool
}

func TestHTTPSThroughPinnedDial(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("secure"))
	}))
	t.Cleanup(srv.Close)
	port := portOf(t, srv)

	// example.com is one of the names in httptest's certificate. The name is
	// resolved by our fake resolver and dialled by IP, yet TLS still verifies
	// the certificate against the name, not the IP.
	resolver := newFakeResolver(t, map[string][]string{"example.com": {"127.0.0.1"}})
	client := newTestClient(t, Policy{AllowPrivate: true, Resolver: resolver})
	trustServerCert(t, client, srv)

	body, err := getBody(client, "https://example.com:"+port+"/")
	if err != nil || string(body) != "secure" {
		t.Fatalf("body %q, err %v", body, err)
	}
	if _, err := getBody(client, "https://127.0.0.1:"+port+"/"); err != nil {
		t.Fatalf("https to the literal address: %v", err)
	}
}

func TestHTTPSCertificateNotTrustedByDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	client := newTestClient(t, Policy{AllowPrivate: true})
	if _, err := get(client, srv.URL); err == nil {
		t.Fatal("a self-signed certificate must not be accepted without explicit trust")
	}
}

func TestHTTPSBlockedAddressNeverHandshakes(t *testing.T) {
	client := newTestClient(t, Policy{})
	if _, err := get(client, "https://169.254.169.254/"); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("got %v, want ErrBlockedAddress", err)
	}
}
