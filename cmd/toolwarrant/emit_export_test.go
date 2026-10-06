package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEmitWritesTheGatewayConfigAtomically(t *testing.T) {
	c, u := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	c.ok("server", "add", "s0", "http://127.0.0.1:3001/mcp")
	dir := t.TempDir()
	out := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(out, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout := c.ok("emit", "--out", out)
	yaml := readFile(t, out)
	wantContains(t, "yaml", yaml, "port: 3000", `exact: "/s1/mcp"`, `exact: "/s0/mcp"`, `mcp.tool.name == \"echo\"`,
		`host: "127.0.0.1:9001"`, `host: "127.0.0.1:9002"`, `host: "http://127.0.0.1:3001/mcp"`, "failClosed", `allow: "false"`)
	wantNotContains(t, "yaml", yaml, "stale", "wipe_database")
	if idx0, idx1 := strings.Index(yaml, `name: "s0"`), strings.Index(yaml, `name: "s1"`); idx0 < 0 || idx1 < idx0 {
		t.Errorf("servers must be emitted in name order")
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != configFileMode {
		t.Errorf("config mode %o, want %o", fi.Mode().Perm(), configFileMode)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
	abs, _ := filepath.Abs(c.db)
	wantContains(t, "stdout", stdout, "wrote "+out, "s0", "/s0/mcp", "127.0.0.1:9001", "s1", "/s1/mcp", "127.0.0.1:9002",
		"run one processor per server", programName+" --db "+abs+" serve --server s1 --listen 127.0.0.1:9002")
	wantNotContains(t, "stdout", stdout, u.url()+"?")

	c.ok("emit", "--out", out, "--processor", "s1=127.0.0.1:9100", "--listen-port", "8080", "--processor-base-port", "7000")
	yaml = readFile(t, out)
	wantContains(t, "yaml", yaml, "port: 8080", `host: "127.0.0.1:9100"`, `host: "127.0.0.1:7000"`)
	wantNotContains(t, "yaml", yaml, "9002")

	r := c.fail(exitUsage, "emit", "--out", out, "--processor", "nope=127.0.0.1:1")
	wantContains(t, "stderr", r.stderr, "unknown server nope")
	r = c.fail(exitUsage, "emit", "--out", out, "--processor", "s1=127.0.0.1:1", "--processor", "s1=127.0.0.1:2")
	wantContains(t, "stderr", r.stderr, "twice")
	r = c.fail(exitFailure, "emit", "--out", filepath.Join(dir, "missing", "gateway.yaml"))
	wantContains(t, "stderr", r.stderr, "temp file")
	r = c.fail(exitFailure, "emit", "--out", out, "--listen-port", "70000")
	wantContains(t, "stderr", r.stderr, "emit again")
}

func TestEmitWithNoServersFailsAndSkippedToolsAreWarnedAbout(t *testing.T) {
	c := newCLI(t)
	r := c.fail(exitFailure, "emit", "--out", filepath.Join(t.TempDir(), "g.yaml"))
	wantContains(t, "stderr", r.stderr, "no servers")

	u := newUpstream(t, map[string]string{"héllo": "Non-ASCII name.", "echo": echoV1})
	c.ok("server", "add", "s1", u.url(), "--allow-private")
	c.ok("crawl", "s1")
	c.approve("alice", "s1", "héllo", c.tool("s1", "héllo").Pending)
	out := filepath.Join(t.TempDir(), "g.yaml")
	r = c.run("emit", "--out", out)
	if r.code != exitOK {
		t.Fatalf("emit: exit %d: %s", r.code, r.stderr)
	}
	wantContains(t, "stderr", r.stderr, "warning: s1/héllo is approved but left out", "stays hidden")
	wantNotContains(t, "yaml", readFile(t, out), "héllo")
	wantContains(t, "stdout", r.stdout, "s1")
}

func TestExportWritesFilesAndCommits(t *testing.T) {
	c, _ := fixture(t)
	v1 := c.tool("s1", "echo").Pending
	c.approve("alice", "s1", "echo", v1)
	dir := filepath.Join(t.TempDir(), "approved")

	out := c.ok("export", "--dir", dir)
	wantContains(t, "stdout", out, "exported 1 approved tools to "+dir, "1 written, 0 removed, 0 unchanged")
	snapshot := readFile(t, filepath.Join(dir, "s1", "echo.json"))
	wantContains(t, "echo.json", snapshot, echoV1, `"name":"echo"`)
	wantContains(t, "manifest", readFile(t, filepath.Join(dir, "MANIFEST.json")), "s1/echo.json", v1)
	out = c.ok("export", "--dir", dir)
	wantContains(t, "second export", out, "0 written, 0 removed, 1 unchanged")

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	out = c.ok("--as", "alice", "export", "--dir", dir, "--commit")
	wantContains(t, "commit", out, "committed as alice <alice@"+emailDomain+">")
	if fi, err := os.Stat(filepath.Join(dir, ".git")); err != nil || !fi.IsDir() {
		t.Fatalf("no repository was created: %v", err)
	}
	out = c.ok("--as", "alice", "export", "--dir", dir, "--commit")
	wantContains(t, "second commit", out, "nothing to commit")

	c.approve("bob", "s1", "add", c.tool("s1", "add").Pending)
	out = c.ok("export", "--dir", dir, "--commit", "--git-name", "Release Bot", "--git-email", "bot@example.com")
	wantContains(t, "third commit", out, "1 written", "committed as Release Bot <bot@example.com>")
	r := c.fail(exitFailure, "export", "--dir", dir, "--commit", "--git-email", "bad email")
	wantContains(t, "stderr", r.stderr, "whitespace")
}
