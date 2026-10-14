package processor

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
	"github.com/sairam0424/toolwarrant/internal/testcert"
)

// tlsLab is the certificate material of one TLS test: an authority that signed
// the processor's certificate and the gateway stand-in's client certificate,
// and a second authority that nothing in the lab trusts.
type tlsLab struct {
	ca     *testcert.Authority
	server testcert.Pair
	client testcert.Pair
	other  *testcert.Authority
}

func newTLSLab(t *testing.T) *tlsLab {
	t.Helper()
	ca := testcert.NewAuthority(t, "toolwarrant test ca")
	return &tlsLab{ca: ca, server: ca.Server(t), client: ca.Client(t, "gateway"), other: testcert.NewAuthority(t, "another ca")}
}

// serverConfig is the processor's TLS configuration as the serve command
// builds it: its certificate, and with requireClient the lab's CA as the only
// accepted client authority. MinVersion is left unset on purpose: Serve must
// raise it.
func (l *tlsLab) serverConfig(requireClient bool) *tls.Config {
	cfg := &tls.Config{Certificates: []tls.Certificate{l.server.TLS}}
	if requireClient {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = l.ca.Pool
	}
	return cfg
}

// newServer returns a Server with the lab's TLS and the echo tool approved,
// plus its log.
func (l *tlsLab) newServer(t *testing.T, requireClient bool, mutate ...func(*Config)) (*Server, *syncBuffer) {
	t.Helper()
	d1 := mustDigest(t, echoV1)
	withTLS := func(c *Config) { c.TLS = l.serverConfig(requireClient) }
	return newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}), append([]func(*Config){withTLS}, mutate...)...)
}

// clientCreds dials the processor over TLS, verifying it under ServerName
// against the lab's CA and presenting certs (none for a client without a
// certificate).
func (l *tlsLab) clientCreds(certs ...tls.Certificate) credentials.TransportCredentials {
	return credentials.NewTLS(l.clientConfig(certs...))
}

func (l *tlsLab) clientConfig(certs ...tls.Certificate) *tls.Config {
	return &tls.Config{RootCAs: l.ca.Pool, ServerName: testcert.ServerName, Certificates: certs, MinVersion: tls.VersionTLS13}
}

// hookFails asserts a hook never reaches the service: the RPC fails with
// Unavailable, which is what a refused handshake looks like to the client.
func hookFails(t *testing.T, client api.ExtMcpClient, what string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), serveStopTimeout)
	defer cancel()
	_, err := client.CheckRequest(ctx, callReq("echo"))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("%s: err = %v, want Unavailable (a refused handshake)", what, err)
	}
	t.Logf("%s: %v", what, err)
}

// hookPasses asserts the echo call is allowed over the connection.
func hookPasses(t *testing.T, client api.ExtMcpClient, what string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), serveStopTimeout)
	defer cancel()
	res, err := client.CheckRequest(ctx, callReq("echo"))
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	requireAllowed(t, res)
}

// serveOnce runs Serve and returns what it returned, failing the test when it
// keeps serving: a configuration that must be refused is refused before the
// listener is used, so a Serve that is still running is the wrong answer, not
// a slow one.
func serveOnce(t *testing.T, s *Server, lis net.Listener) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, lis) }()
	select {
	case err := <-done:
		return err
	case <-time.After(serveStopTimeout):
		t.Fatalf("Serve kept serving for %v instead of refusing the configuration", serveStopTimeout)
		return nil
	}
}

// D19 (planned): a TLS listener refuses what is not a TLS 1.3 client holding a
// certificate the configured authority signed, and a refused handshake leaves
// no trace in the hook counters because no hook was ever read.
func TestServe_TLSListenerRefusesPlaintextAndUnknownClients(t *testing.T) {
	lab := newTLSLab(t)
	oldClient := lab.clientConfig(lab.client.TLS)
	oldClient.MinVersion = tls.VersionTLS12
	oldClient.MaxVersion = tls.VersionTLS12
	cases := []struct {
		name  string
		creds credentials.TransportCredentials
	}{
		{"plaintext client", insecure.NewCredentials()},
		{"tls 1.2 client with the right certificate", credentials.NewTLS(oldClient)},
		{"client certificate from another authority", lab.clientCreds(lab.other.Client(t, "impostor").TLS)},
		{"client that trusts another authority", credentials.NewTLS(&tls.Config{RootCAs: lab.other.Pool, ServerName: testcert.ServerName, Certificates: []tls.Certificate{lab.client.TLS}, MinVersion: tls.VersionTLS13})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := lab.newServer(t, true)
			buf := bufconn.Listen(1 << 20)
			client, stop := serveAndDialWith(t, s, buf, buf, tc.creds)
			hookFails(t, client, tc.name)
			if err := stop(); err != nil {
				t.Fatal(err)
			}
			if st := s.Stats(); st.CallsAllowed != 0 || st.CallsDenied != 0 || st.Unauthenticated != 0 {
				t.Errorf("stats = %+v, want no hook counted for a refused handshake", st)
			}
		})
	}
}

// D19 (planned): with a client CA the gateway must present a certificate that
// CA signed; with one, both hooks work exactly as in plaintext.
func TestServe_TLSWithClientCARequiresAClientCertificate(t *testing.T) {
	lab := newTLSLab(t)
	s, _ := lab.newServer(t, true)
	buf := bufconn.Listen(1 << 20)
	anonymous, stop := serveAndDialWith(t, s, buf, buf, lab.clientCreds())
	hookFails(t, anonymous, "client without a certificate")
	if err := stop(); err != nil {
		t.Fatal(err)
	}

	s, _ = lab.newServer(t, true)
	buf = bufconn.Listen(1 << 20)
	client, _ := serveAndDialWith(t, s, buf, buf, lab.clientCreds(lab.client.TLS))
	hookPasses(t, client, "client with the lab's certificate")
	ctx, cancel := context.WithTimeout(context.Background(), serveStopTimeout)
	defer cancel()
	res, err := client.CheckResponse(ctx, listMsg(listBody("", echoV1, tool("wipe_database", "Danger."))))
	if err != nil {
		t.Fatal(err)
	}
	if got := servedNames(t, res); len(got) != 1 || got[0] != "echo" {
		t.Fatalf("served %v over TLS, want [echo]", got)
	}
	if st := s.Stats(); st.CallsAllowed != 1 || st.ListsServed != 1 || st.Unauthenticated != 0 {
		t.Errorf("stats = %+v, want one allowed call and one served list", st)
	}
}

// D19 (planned): without a client CA the listener protects the bytes, not the
// port: any TLS 1.3 client is served, with or without a certificate, while a
// plaintext client is still refused.
func TestServe_TLSWithoutClientCAAcceptsAnyClient(t *testing.T) {
	lab := newTLSLab(t)
	cases := []struct {
		name  string
		creds credentials.TransportCredentials
		pass  bool
	}{
		{"client without a certificate", lab.clientCreds(), true},
		{"client with a certificate from another authority", lab.clientCreds(lab.other.Client(t, "stranger").TLS), true},
		{"plaintext client", insecure.NewCredentials(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := lab.newServer(t, false)
			buf := bufconn.Listen(1 << 20)
			client, _ := serveAndDialWith(t, s, buf, buf, tc.creds)
			if tc.pass {
				hookPasses(t, client, tc.name)
				return
			}
			hookFails(t, client, tc.name)
		})
	}
}

// O-2, D19 (planned): a verified client certificate authenticates the hooks as
// the shared secret does, so a non-loopback listener with a client CA and no
// secret is not warned about; server-only TLS still is.
func TestServe_ClientCertificateSilencesTheNoSecretWarning(t *testing.T) {
	lab := newTLSLab(t)
	remote := &net.TCPAddr{IP: net.ParseIP("10.0.0.7"), Port: 9001}
	allowRemote := func(c *Config) { c.AllowRemoteListener = true }

	t.Run("client ca, no secret: silent", func(t *testing.T) {
		s, logs := lab.newServer(t, true, allowRemote)
		buf := bufconn.Listen(1 << 20)
		client, stop := serveAndDialWith(t, s, addrListener{Listener: buf, addr: remote}, buf, lab.clientCreds(lab.client.TLS))
		hookPasses(t, client, "remote listener with a client certificate")
		if err := stop(); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(logs.String(), "without a shared secret") {
			t.Errorf("warned although every client must present a verified certificate:\n%s", logs.String())
		}
	})

	t.Run("server-only tls, no secret: warned", func(t *testing.T) {
		s, logs := lab.newServer(t, false, allowRemote)
		buf := bufconn.Listen(1 << 20)
		_, stop := serveAndDialWith(t, s, addrListener{Listener: buf, addr: remote}, buf, lab.clientCreds())
		if err := stop(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(logs.String(), "without a shared secret") {
			t.Errorf("no warning for a remote listener that verifies no client:\n%s", logs.String())
		}
	})
}

// Fail closed on a TLS configuration the listener could not serve safely, and
// never write to the caller's configuration.
func TestServe_RefusesAnUnusableTLSConfig(t *testing.T) {
	lab := newTLSLab(t)
	cases := []struct {
		name string
		cfg  *tls.Config
		want error
	}{
		{"no certificate", &tls.Config{}, errTLSNoCertificate},
		{"client verification against no authority", &tls.Config{Certificates: []tls.Certificate{lab.server.TLS}, ClientAuth: tls.RequireAndVerifyClientCert}, errTLSNoClientCAs},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestServer(newFakeSource(nil), func(c *Config) { c.TLS = tc.cfg })
			buf := bufconn.Listen(1 << 10)
			defer func() { _ = buf.Close() }()
			if err := serveOnce(t, s, buf); !errors.Is(err, tc.want) {
				t.Fatalf("Serve = %v, want %v", err, tc.want)
			}
		})
	}

	given := lab.serverConfig(false)
	s, _ := newTestServer(newFakeSource(nil), func(c *Config) { c.TLS = given })
	if given.MinVersion != 0 {
		t.Errorf("New wrote MinVersion %d into the caller's configuration", given.MinVersion)
	}
	if s.tlsConf.MinVersion != tls.VersionTLS13 {
		t.Errorf("hardened MinVersion = %d, want TLS 1.3", s.tlsConf.MinVersion)
	}
	if hardenTLS(nil) != nil {
		t.Error("hardenTLS(nil) must stay nil, which means plaintext")
	}
}
