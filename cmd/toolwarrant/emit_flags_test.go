package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/emit"
)

// The gateway's own listeners are emitter inputs: each is written where the
// operator put it, the admin API has an off switch, a port shared with the
// serving port or another listener is refused before anything is written, and
// an address other hosts can reach needs the same permission as a wildcard
// bind and is warned about line by line.
func TestEmitWritesListenerAddressesAndRefusesCollisions(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	out := filepath.Join(t.TempDir(), "gateway.yaml")

	r := c.run("emit", "--out", out)
	if r.code != exitOK {
		t.Fatalf("emit: exit %d: %s", r.code, r.stderr)
	}
	defaults := readFile(t, out)
	wantContains(t, "yaml", defaults, `adminAddr: "`+emit.DefaultAdminAddr+`"`, `statsAddr: "`+emit.DefaultStatsAddr+`"`, `readinessAddr: "`+emit.DefaultReadinessAddr+`"`)
	wantNotContains(t, "stderr", r.stderr, "warning")

	r = c.run("emit", "--out", out, "--admin-addr", "127.0.0.1:16000", "--stats-addr", "[::1]:16020", "--readiness-addr", "127.0.0.2:16021")
	if r.code != exitOK {
		t.Fatalf("emit with listener addresses: exit %d: %s", r.code, r.stderr)
	}
	custom := readFile(t, out)
	wantContains(t, "yaml", custom, `adminAddr: "127.0.0.1:16000"`, `statsAddr: "[::1]:16020"`, `readinessAddr: "127.0.0.2:16021"`)
	if _, ok := emit.Verify([]byte(custom)); !ok {
		t.Error("the written file does not verify")
	}
	wantNotContains(t, "stderr", r.stderr, "warning")

	r = c.run("emit", "--out", out, "--disable-admin")
	if r.code != exitOK {
		t.Fatalf("emit --disable-admin: exit %d: %s", r.code, r.stderr)
	}
	off := readFile(t, out)
	wantContains(t, "yaml", off, `adminAddr: "off"`, `statsAddr: "`+emit.DefaultStatsAddr+`"`)

	for name, args := range map[string][]string{
		"admin address and off switch": {"--admin-addr", "127.0.0.1:16000", "--disable-admin"},
		"serving port equals admin":    {"--listen-port", "15000"},
		"two listeners on one port":    {"--stats-addr", "127.0.0.1:15021"},
		"listener with a host name":    {"--admin-addr", "localhost:15000"},
		"exposed listener unasked":     {"--admin-addr", "0.0.0.0:15000"},
	} {
		r = c.fail(exitFailure, append([]string{"emit", "--out", out}, args...)...)
		wantContains(t, name, r.stderr, "emit again")
		if readFile(t, out) != off {
			t.Errorf("%s: a refused input must not touch the file", name)
		}
	}
	r = c.fail(exitFailure, "emit", "--out", out, "--listen-port", "15000")
	wantContains(t, "port collision", r.stderr, "distinct ports", "admin API", "serving port")
	r = c.fail(exitFailure, "emit", "--out", out, "--admin-addr", "0.0.0.0:15000")
	wantContains(t, "exposed admin", r.stderr, "reachable from other hosts", "AllowAllInterfaces")

	r = c.run("emit", "--out", out, "--admin-addr", "0.0.0.0:15000", "--stats-addr", "203.0.113.7:15020", "--allow-all-interfaces")
	if r.code != exitOK {
		t.Fatalf("emit with exposed listeners: exit %d: %s", r.code, r.stderr)
	}
	wantContains(t, "yaml", readFile(t, out), `adminAddr: "0.0.0.0:15000"`, `statsAddr: "203.0.113.7:15020"`)
	lines := nonEmptyLines(r.stderr)
	if len(lines) != 2 {
		t.Errorf("want one warning line per exposed listener, got %d:\n%s", len(lines), r.stderr)
	}
	wantContains(t, "stderr", r.stderr, "warning: admin API listens on 0.0.0.0:15000, every interface of this host", "POST /api/config replaces the running configuration",
		"warning: stats endpoint listens on 203.0.113.7:15020, an address other hosts can reach")
}

// A server URL with a query string is where a credential lives, so the file
// that carries it is owner-only and the warning names the server, never the
// URL; the planted value appears nowhere in the output.
func TestEmitWritesAPrivateFileWhenAServerURLCarriesAQuery(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	c.ok("server", "add", "queried", "http://127.0.0.1:3002/mcp?q="+plant("query"))
	out := filepath.Join(t.TempDir(), "gateway.yaml")
	r := c.run("emit", "--out", out)
	if r.code != exitOK {
		t.Fatalf("emit: exit %d: %s", r.code, r.stderr)
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != secretConfigFileMode {
		t.Errorf("config mode %o, want %o when a server URL carries a query string", fi.Mode().Perm(), secretConfigFileMode)
	}
	wantContains(t, "stderr", r.stderr, "warning: the URL of server queried carries a query string", "where credentials live", "0600")
	wantNotContains(t, "output", r.stdout+r.stderr, canary, "q=")
	wantContains(t, "yaml", readFile(t, out), plant("query"))

	// The same catalog without the queried URL is world-readable again.
	c2, _ := fixture(t)
	c2.approve("alice", "s1", "echo", c2.tool("s1", "echo").Pending)
	plain := filepath.Join(t.TempDir(), "gateway.yaml")
	c2.ok("emit", "--out", plain)
	if fi, err = os.Stat(plain); err != nil || fi.Mode().Perm() != configFileMode {
		t.Errorf("plain config mode %v (%v), want %o", fi.Mode(), err, configFileMode)
	}
}

// A --processor override that names a host other hosts can reach is accepted
// with a warning, and the printed serve command carries the flag serve needs
// to accept it (serve still refuses it without a secret, by design).
func TestEmitWarnsAboutANonLoopbackProcessorOverride(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	out := filepath.Join(t.TempDir(), "gateway.yaml")
	r := c.run("emit", "--out", out, "--processor", "s1=10.0.0.7:9001")
	if r.code != exitOK {
		t.Fatalf("emit: exit %d: %s", r.code, r.stderr)
	}
	wantContains(t, "stderr", r.stderr, "warning: processor for server s1 at 10.0.0.7:9001 is not on loopback", "cross the network", "shared secret")
	wantContains(t, "stdout", r.stdout, "serve --server s1 --target s1 --listen 10.0.0.7:9001 "+allowNonLoopbackFlag)
	wantContains(t, "yaml", readFile(t, out), `host: "10.0.0.7:9001"`)
	r = c.run("emit", "--out", out, "--processor", "s1=localhost:9001")
	if r.code != exitOK {
		t.Fatalf("emit with localhost: exit %d: %s", r.code, r.stderr)
	}
	wantNotContains(t, "stderr", r.stderr, "warning")
	wantNotContains(t, "stdout", r.stdout, allowNonLoopbackFlag)
}

// init refuses a database path that is a symbolic link before anything is
// created: a link planted in a shared working directory would otherwise make
// init create an owner-only file wherever the link points.
func TestInitRefusesASymbolicLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.db")
	link := filepath.Join(dir, "tw.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	c := &cli{t: t, db: link, env: map[string]string{}}
	r := c.fail(exitFailure, "init")
	wantContains(t, "stderr", r.stderr, "symbolic link", "name the file itself")
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("init created the link's target: %v", err)
	}
	// A link whose target exists is refused the same way: the catalog is
	// never created or opened through a link.
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r = c.fail(exitFailure, "init")
	wantContains(t, "stderr", r.stderr, "symbolic link")
	if strings.Contains(r.stdout, dir) {
		t.Errorf("init printed a path although it refused: %s", r.stdout)
	}
}
