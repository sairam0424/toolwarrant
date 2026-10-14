package main

import (
	"bytes"
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelpAndVersion(t *testing.T) {
	c := newCLI(t)
	out := c.ok("help")
	wantContains(t, "help", out, "approve SERVER TOOL --hash HASH", "server add NAME URL", "server pause NAME", "server resume NAME",
		"crawl SERVER [--every DURATION] [--bearer-env VAR] [--strict] [--json]",
		"serve --server NAME --listen ADDR [--target NAME] [--secret-env VAR] [--allow-non-loopback [--insecure-no-secret]] [--max-evidence-age DURATION]",
		"emit --out FILE [--listen-port N] [--bind-address ADDR [--allow-all-interfaces]] [--admin-addr ADDR | --disable-admin] [--stats-addr ADDR] [--readiness-addr ADDR] [--processor-base-port N] [--processor NAME=HOST:PORT ...] [--secret-env VAR] [--gateway-binary PATH]",
		"verify-gateway --server NAME --url URL [--bearer-env VAR] [--config FILE [--admin ADDR] [--expect-body-hash HEX]] [--no-probe] [--every DURATION] [--keep-going]",
		"budget reset SERVER TOOL [--by NAME]", "audit verify [--expect-head HASH]", "exit codes", "-allow-self-approval")
	out = c.ok("version")
	wantContains(t, "version", out, programName+" dev", gatewayVersion)
	r := c.run("-h")
	if r.code != exitOK {
		t.Fatalf("-h exit %d: %s", r.code, r.stderr)
	}
	wantContains(t, "-h", r.stdout, "global flags")
	out = c.ok("approve", "-h")
	wantContains(t, "approve -h", out, "usage: toolwarrant [global flags] approve", "-hash", "-accept-suspicious")
	wantContains(t, "help serve", c.ok("help", "serve"), "-target", "-secret-env", "-max-evidence-age", "-allow-non-loopback", "-insecure-no-secret", "anyone who reaches the port")
	wantContains(t, "help verify-gateway", c.ok("help", "verify-gateway"), "-config", "-every", "-keep-going", "-admin", "-no-probe", "GET "+adminConfigPath, verdictLiveConfig,
		probeToolPrefix, "HTTP 202", verdictUnhooked, "the probe reaches the upstream exactly when the gateway behaves this way", "L17",
		"-expect-body-hash", "L19", verdictInconclusive, "not accepted as a notification (HTTP 400, by the gateway or by the upstream)", "proves nothing about the hook", "a JSON-RPC answer, single or batched", "as a whole document", "the path of --url must be the emitted route's match", "the ports of --url and --admin must be the emitted gateway's serving port and the emitted adminAddr's port", "backend targets (name and host)", "printed a verdict line",
		"no non-empty top-level section other than config, gateways and routes", "no policy other than mcpAuthorization and mcpGuardrails", "no match that is not a single exact path", "requestHeaders allowed and disallowed lists", "the backendTLS cert, key, root and hostname under the processor's policies", "no processor policy other than backendTLS, no backendTLS field other than those four", "metadata compared by a hash of its canonical form and never shown",
		"is not a regular file", "a listing failure alone is printed, counted and does not stop the run")
	wantContains(t, "help crawl", c.ok("help", "crawl"), "-strict", "-every")
	wantContains(t, "help emit", c.ok("help", "emit"), "-secret-env", "-bind-address", `(default "127.0.0.1")`, "-allow-all-interfaces", "a permission, not a request",
		"-admin-addr", "-disable-admin", "-stats-addr", "-readiness-addr", "-gateway-binary", envGatewayBinary, validateOnlyFlag,
		"always written with mode 0600", "recorded in the catalog", "server.processor_set", "the file at --out is never read for addresses", "replaces the address the catalog records")
	wantContains(t, "help server", c.ok("help", "server"), "PROCESSOR is the processor address emit recorded")
	wantContains(t, "help budget", c.ok("help", "budget"), "subcommands", "budget reset SERVER TOOL [--by NAME]")
	wantContains(t, "help budget reset", c.ok("help", "budget", "reset"), "-by", systemActorName)
	wantContains(t, "help audit verify", c.ok("help", "audit", "verify"), "-expect-head")
	out = c.ok("help", "server")
	wantContains(t, "help server", out, "server add", "server list", "server pause", "server resume")
	out = c.ok("help", "server", "add")
	wantContains(t, "help server add", out, "-allow-private", "-owner")
	out = c.ok("server", "-h")
	wantContains(t, "server -h", out, "subcommands")
	r = c.fail(exitUsage, "help", "nope")
	wantContains(t, "stderr", r.stderr, "unknown command")
}

func TestUsageErrors(t *testing.T) {
	c := newCLI(t)
	c.env["SHORT_SECRET"] = "short"
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no command", nil, "a command is required"},
		{"unknown command", []string{"frobnicate"}, "unknown command"},
		{"unknown global flag", []string{"--bogus", "list"}, "bogus"},
		{"approve without hash", []string{"approve", "s1", "echo"}, "--hash is required"},
		{"approve missing tool", []string{"approve", "s1", "--hash", "deadbeefdead"}, "expected 2 argument(s)"},
		{"server alone", []string{"server"}, "needs a subcommand"},
		{"server unknown", []string{"server", "frob"}, "unknown server subcommand"},
		{"server pause without name", []string{"server", "pause"}, "expected 1 argument(s)"},
		{"server resume as the system actor", []string{"--as", "crawler", "server", "resume", "s1"}, "system actor"},
		{"init extra", []string{"init", "extra"}, "expected 0 argument(s)"},
		{"list two", []string{"list", "a", "b"}, "at most one argument"},
		{"crawl negative every", []string{"crawl", "s1", "--every", "-1s"}, "--every must be at least"},
		{"crawl every below the minimum", []string{"crawl", "s1", "--every", "10ms"}, "--every must be at least 1s"},
		{"verify every below the minimum", []string{"verify-gateway", "--server", "s1", "--url", "http://127.0.0.1:1/mcp", "--every", "1ms"}, "--every must be at least 1s"},
		{"verify admin without config", []string{"verify-gateway", "--server", "s1", "--url", "http://127.0.0.1:1/mcp", "--admin", "127.0.0.1:15000"}, "--admin needs --config"},
		{"verify admin with user info", []string{"verify-gateway", "--server", "s1", "--url", "http://127.0.0.1:1/mcp", "--config", "g.yaml", "--admin", "http://u:p@127.0.0.1:15000"}, "without user info"},
		{"verify admin with a query", []string{"verify-gateway", "--server", "s1", "--url", "http://127.0.0.1:1/mcp", "--config", "g.yaml", "--admin", "127.0.0.1:15000/?x=1"}, "without user info, query or fragment"},
		{"verify expect-body-hash without config", []string{"verify-gateway", "--server", "s1", "--url", "http://127.0.0.1:1/mcp", "--expect-body-hash", strings.Repeat("a", 64)}, "--expect-body-hash needs --config"},
		{"verify expect-body-hash not hex", []string{"verify-gateway", "--server", "s1", "--url", "http://127.0.0.1:1/mcp", "--config", "g.yaml", "--expect-body-hash", "nothex"}, "64 hex digits of the body sha256"},
		{"audit negative limit", []string{"audit", "list", "--limit", "-1"}, "must not be negative"},
		{"rollback without to", []string{"rollback", "s1", "echo"}, "--to is required"},
		{"reject without hash", []string{"reject", "s1", "echo"}, "--hash is required"},
		{"budget alone", []string{"budget"}, "needs a subcommand"},
		{"budget reset without tool", []string{"budget", "reset", "s1"}, "expected 2 argument(s)"},
		{"budget reset by the system actor", []string{"budget", "reset", "s1", "echo", "--by", "crawler"}, "system actor cannot reset"},
		{"budget reset as the system actor", []string{"--as", "crawler", "budget", "reset", "s1", "echo"}, "system actor"},
		{"budget reset by an invalid name", []string{"budget", "reset", "s1", "echo", "--by", "ali ce"}, "must match"},
		{"serve without flags", []string{"serve"}, "--server is required"},
		{"serve without listen", []string{"serve", "--server", "s1"}, "--listen is required"},
		{"serve negative evidence age", []string{"serve", "--server", "s1", "--listen", "127.0.0.1:0", "--max-evidence-age", "-1s"}, "must not be negative"},
		{"serve secret unset", []string{"serve", "--server", "s1", "--listen", "127.0.0.1:0", "--secret-env", "UNSET_SECRET"}, "UNSET_SECRET is unset"},
		{"serve non-loopback without a secret", []string{"serve", "--server", "s1", "--listen", "0.0.0.0:0", "--allow-non-loopback"}, "without a shared secret"},
		{"emit without out", []string{"emit"}, "--out is required"},
		{"emit secret too short", []string{"emit", "--out", "x", "--secret-env", "SHORT_SECRET"}, "16 to 256 printable ASCII"},
		{"emit wildcard bind without permission", []string{"emit", "--out", "x", "--bind-address", "0.0.0.0"}, "--allow-all-interfaces"},
		{"export without dir", []string{"export"}, "--dir is required"},
		{"verify without url", []string{"verify-gateway", "--server", "s1"}, "--url is required"},
		{"unknown subcommand flag", []string{"list", "--nope"}, "nope"},
		{"bad processor override", []string{"emit", "--out", "x", "--processor", "nonsense"}, "NAME=HOST:PORT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := c.sub(t).fail(exitUsage, tc.args...)
			wantContains(t, "stderr", r.stderr, tc.want, programName+":")
		})
	}
}

func TestInitIsIdempotentAndPrivate(t *testing.T) {
	c := newCLI(t)
	first := c.ok("init")
	second := c.ok("init")
	abs, err := filepath.Abs(c.db)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(first) != abs || first != second {
		t.Errorf("init printed %q then %q, want %q twice", first, second, abs)
	}
	fi, err := os.Stat(c.db)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != dbFileMode {
		t.Errorf("database mode %o, want %o", fi.Mode().Perm(), dbFileMode)
	}
}

// The create behind init never follows a symbolic link, so a link planted
// between the path check (TestInitRefusesASymbolicLink) and the open creates
// nothing where the link points.
func TestEnsurePrivateFileNeverFollowsALink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.db")
	link := filepath.Join(dir, "link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a symbolic link here: %v", err)
	}
	if err := ensurePrivateFile(link); err == nil {
		t.Error("ensurePrivateFile followed a symbolic link")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("ensurePrivateFile created the link's target: %v", err)
	}
	if err := refuseSymlink(filepath.Join(dir, "absent.db")); err != nil {
		t.Errorf("an absent path is not a link: %v", err)
	}
	plain := filepath.Join(dir, "plain.db")
	if err := ensurePrivateFile(plain); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(plain); err != nil || fi.Mode().Perm() != dbFileMode {
		t.Errorf("plain file: %v %v, want mode %o", fi, err, dbFileMode)
	}
}

func TestCommandsNeedAnExistingDatabase(t *testing.T) {
	c := &cli{t: t, db: filepath.Join(t.TempDir(), "missing.db"), env: map[string]string{}}
	for _, args := range [][]string{{"list"}, {"audit", "verify"}, {"serve", "--server", "s1", "--listen", "127.0.0.1:0"}, {"--as", "alice", "budget", "reset", "s1", "echo"}} {
		r := c.fail(exitFailure, args...)
		wantContains(t, "stderr", r.stderr, "does not exist", programName+" init")
	}
	if _, err := os.Stat(c.db); !os.IsNotExist(err) {
		t.Error("a failed command must not create the database")
	}
}

func TestDatabasePathComesFromTheEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env.db")
	var out, errb bytes.Buffer
	getenv := func(k string) string {
		if k == envDB {
			return path
		}
		return ""
	}
	if code := runCtx(context.Background(), []string{"init"}, strings.NewReader(""), &out, &errb, getenv); code != exitOK {
		t.Fatalf("init: exit %d: %s", code, errb.String())
	}
	if strings.TrimSpace(out.String()) != path {
		t.Errorf("init printed %q, want %q", out.String(), path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("database not created: %v", err)
	}
}

func TestRunUsesASignalContext(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"version"}, strings.NewReader(""), &out, &errb, func(string) string { return "" })
	if code != exitOK || !strings.Contains(out.String(), programName+" dev") {
		t.Fatalf("run version: exit %d, out %q, err %q", code, out.String(), errb.String())
	}
}

func TestBrokenStreamsExitOne(t *testing.T) {
	ctx := context.Background()
	none := func(string) string { return "" }
	var errb bytes.Buffer
	code := runCtx(ctx, []string{"version"}, strings.NewReader(""), &brokenPipe{}, &errb, none)
	if code != exitFailure {
		t.Fatalf("version with a broken stdout: exit %d, want %d", code, exitFailure)
	}
	wantContains(t, "stderr", errb.String(), "writing to stdout failed", "broken pipe")

	// A broken stderr can only be reported through the exit code; the work
	// itself was done.
	c := newCLI(t)
	u := newUpstream(t, nil)
	var out bytes.Buffer
	code = runCtx(ctx, []string{"--db", c.db, "server", "add", "s1", u.url(), "--allow-private"}, strings.NewReader(""), &out, &brokenPipe{}, c.getenv)
	if code != exitFailure {
		t.Fatalf("server add with a broken stderr: exit %d, want %d", code, exitFailure)
	}
	wantContains(t, "stdout", out.String(), "added server s1")

	// A command that already failed keeps its more specific code.
	if code = runCtx(ctx, []string{"nope"}, strings.NewReader(""), &out, &brokenPipe{}, none); code != exitUsage {
		t.Errorf("unknown command with a broken stderr: exit %d, want %d", code, exitUsage)
	}
}

func TestActorNamesAreValidatedAndLowerCased(t *testing.T) {
	c := newCLI(t)
	u := newUpstream(t, nil)
	r := c.fail(exitUsage, "--as", "ali ce", "server", "add", "s1", u.url())
	wantContains(t, "stderr", r.stderr, "must match")
	r = c.fail(exitUsage, "--as", "ali"+zeroWidth+"ce", "server", "add", "s1", u.url())
	wantContains(t, "stderr", r.stderr, `\u{200B}`)
	wantNotContains(t, "stderr", r.stderr, zeroWidth)
	c.ok("--as", "Alice", "server", "add", "s1", u.url())
	c.env[envActor] = "BOB"
	c.ok("server", "add", "s2", u.url())
	entries := c.auditEntries()
	if len(entries) != 2 || entries[0].Actor != "alice" || entries[1].Actor != "bob" {
		t.Fatalf("audit actors = %+v, want alice then bob", entries)
	}
	if entries[0].ActorType != "human" || entries[0].Event != "server.added" {
		t.Errorf("entry = %+v", entries[0])
	}
}

func TestDefaultActorIsTheOSUser(t *testing.T) {
	who, err := user.Current()
	if err != nil || !actorNamePattern.MatchString(who.Username) {
		t.Skipf("os user %q is not usable as an actor name: %v", who, err)
	}
	c := newCLI(t)
	u := newUpstream(t, nil)
	c.ok("server", "add", "s1", u.url())
	entries := c.auditEntries()
	if len(entries) != 1 || entries[0].Actor != strings.ToLower(who.Username) {
		t.Fatalf("audit actors = %+v, want %q", entries, strings.ToLower(who.Username))
	}
}
