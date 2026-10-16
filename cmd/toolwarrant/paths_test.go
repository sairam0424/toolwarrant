package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/export"
)

// settleTime is how long a command is given to refuse a file it must not open:
// a one-shot canary against a missing file reports CONFIG-EDITED, and emit
// against a directory at --out fails, in well under a second.
const settleTime = 2 * time.Second

// plantFIFO creates a named pipe where the command expects a regular file.
func plantFIFO(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	return path
}

// unblockFIFO opens the pipe for writing without blocking and closes it, so a
// reader blocked in open() wakes up; without a reader the open fails with
// ENXIO and nothing hangs.
func unblockFIFO(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Logf("unblock %s: %v", path, err)
		return
	}
	_ = f.Close()
}

// awaitExit waits settleTime for a launched command to end by itself and
// returns its exit code; a command still running is unblocked and failed.
func awaitExit(t *testing.T, run *running, fifo, what string) int {
	t.Helper()
	select {
	case code := <-run.done:
		return code
	case <-time.After(settleTime):
	}
	t.Errorf("%s after start %s has printed nothing and has not exited: it is blocked opening the FIFO instead of refusing it\nstdout: %q\nstderr: %q", settleTime, what, run.stdout.String(), run.stderr.String())
	unblockFIFO(t, fifo)
	return run.wait()
}

// Fourth review (cli-docs-2): readConfig used os.ReadFile, which on a named
// pipe blocks in open() until a writer appears, so a FIFO planted at --config
// silenced the canary (no verdict, no exit, SIGINT and SIGTERM ignored) while
// the gateway could run anything. The path is refused by Lstat before any
// open, as CONFIG-EDITED with the reason, and the listing still runs.
func TestVerifyGatewayReportsAFIFOAtConfigAsEdited(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	g := newUpstream(t, map[string]string{"echo": echoV1})
	fifo := plantFIFO(t)
	run := c.launch("verify-gateway", "--server", "s1", "--url", g.url()+routePath, "--config", fifo, "--no-probe")
	if code := awaitExit(t, run, fifo, "the canary"); code != exitFailure {
		t.Errorf("exit %d, want %d", code, exitFailure)
	}
	wantContains(t, "stdout", run.stdout.String(), verdictConfigEdited+" "+fifo+": the file could not be read (", "is a named pipe", "must assume it was replaced")
	wantContains(t, "stderr", run.stderr.String(), "could not be read, so it is treated as edited")
	if g.sessions.Load() != 1 {
		t.Errorf("the gateway saw %d session(s), want 1: the listing runs whatever the file is", g.sessions.Load())
	}
	// A symbolic link at --config is refused the same way, even one that
	// points at a regular file: the path must name the file itself.
	real := filepath.Join(t.TempDir(), "real.yaml")
	c.ok("emit", "--out", real)
	link := filepath.Join(t.TempDir(), "link.yaml")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot plant a symbolic link here: %v", err)
	}
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", g.url()+routePath, "--config", link, "--no-probe")
	wantContains(t, "stdout", r.stdout, verdictConfigEdited+" "+link, "is a symbolic link")
}

// emit must not open --out either (D14 i): a named pipe blocked it before
// anything was validated or written, and a symbolic link made the rename
// replace the link while the old code read the forged target through it. A
// directory, a socket, a pipe and a link are refused by Lstat with the kind
// named; an absent path and a regular file are fine.
func TestEmitRefusesAnIrregularOut(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	fifo := plantFIFO(t)
	run := c.launch("emit", "--out", fifo)
	if code := awaitExit(t, run, fifo, "emit"); code != exitFailure {
		t.Errorf("exit %d, want %d", code, exitFailure)
	}
	wantContains(t, "stderr", run.stderr.String(), "--out "+fifo+" is a named pipe, not a regular file; name a regular file")

	dir := t.TempDir()
	r := c.fail(exitFailure, "emit", "--out", dir)
	wantContains(t, "directory", r.stderr, "--out "+dir+" is a directory, not a regular file")

	target := filepath.Join(t.TempDir(), "elsewhere.yaml")
	if err := os.WriteFile(target, []byte("untouched\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot plant a symbolic link here: %v", err)
	}
	r = c.fail(exitFailure, "emit", "--out", link)
	wantContains(t, "symlink", r.stderr, "--out "+link+" is a symbolic link, not a regular file")
	if got := readFile(t, target); got != "untouched\n" {
		t.Errorf("emit wrote through the link: %q", got)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("emit replaced the link: %v %v", fi, err)
	}

	sock := filepath.Join(t.TempDir(), "gateway.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("cannot listen on a unix socket here: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	r = c.fail(exitFailure, "emit", "--out", sock)
	wantContains(t, "socket", r.stderr, "is a socket, not a regular file")

	// A regular file in place is overwritten as before.
	out := filepath.Join(t.TempDir(), "gateway.yaml")
	c.ok("emit", "--out", out)
	c.ok("emit", "--out", out)
}

// readRegularFile reads a regular file within the cap, and refuses what it
// must before opening it as well as a file that grew past the cap.
func TestReadRegularFile(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.yaml")
	if err := os.WriteFile(plain, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := readRegularFile(plain, "--config", emittedFileNoun, 3); err != nil || string(data) != "abc" {
		t.Errorf("plain: %q %v", data, err)
	}
	if _, err := readRegularFile(plain, "--config", emittedFileNoun, 2); err == nil || !strings.Contains(err.Error(), "larger than 2 bytes, which no emitted file is") {
		t.Errorf("over the cap: %v", err)
	}
	if _, err := readRegularFile(plain, "--pub-key", pemPublicKeyNoun, 2); err == nil || !strings.Contains(err.Error(), "which no PEM public key file is") {
		t.Errorf("over the cap, named as a key file: %v", err)
	}
	if _, err := readRegularFile(filepath.Join(dir, "absent"), "--config", emittedFileNoun, 10); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("absent: %v", err)
	}
	if _, err := readRegularFile(dir, "--config", emittedFileNoun, 10); !errors.Is(err, errNotRegular) || !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("directory: %v", err)
	}
	if err := refuseIrregularFile(filepath.Join(dir, "absent"), "--out"); err != nil {
		t.Errorf("absent path refused: %v", err)
	}
	if got := describeFileType(os.ModeDevice); got != "a device" {
		t.Errorf("describeFileType(device) = %q", got)
	}
	if got := describeFileType(os.ModeCharDevice); got != "a device" {
		t.Errorf("describeFileType(char device) = %q", got)
	}
	if got := describeFileType(0); got != "a regular file" {
		t.Errorf("describeFileType(0) = %q", got)
	}
	if got := describeFileType(os.ModeIrregular); got != "not a regular file" {
		t.Errorf("describeFileType(irregular) = %q", got)
	}
}

// Fourth review (cli-docs-8): refuseSymlink and ensurePrivateFile look at the
// final path component only, so a link planted one level up (state ->
// elsewhere) was followed and init created the owner-only database in the
// directory the link points to while printing the link's path. Every
// directory component is now checked; a link root owns (the ones an operating
// system installs, such as /var and /tmp on macOS) is tolerated, because
// nobody but root could have planted it.
func TestInitRefusesADirectorySymlink(t *testing.T) {
	work := t.TempDir()
	elsewhere := t.TempDir()
	link := filepath.Join(work, "state")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Skipf("cannot plant a symbolic link here: %v", err)
	}
	c := &cli{t: t, db: filepath.Join(link, "sub", "..", "tw.db"), env: map[string]string{}}
	r := c.fail(exitFailure, "init")
	wantContains(t, "stderr", r.stderr, "goes through the symbolic link "+link, "which resolves to", "name the resolved directory")
	if _, err := os.Stat(filepath.Join(elsewhere, "tw.db")); err == nil {
		t.Errorf("init created the database through the directory link at %s", filepath.Join(elsewhere, "tw.db"))
	}
	if strings.Contains(r.stdout, "tw.db") {
		t.Errorf("init printed a path although it refused: %s", r.stdout)
	}
	// The resolved directory is accepted, and so is a directory that does not
	// exist yet (the create then says so).
	c = &cli{t: t, db: filepath.Join(elsewhere, "tw.db"), env: map[string]string{}}
	c.ok("init")
	if err := refuseLinkedDirectory(filepath.Join(work, "missing", "tw.db")); err != nil {
		t.Errorf("a missing directory was refused: %v", err)
	}
	// A root-owned link in the path is the operating system's, not a planted
	// one; macOS has one at /var, other systems may have none.
	fi, err := os.Lstat("/var")
	if err != nil || fi.Mode()&os.ModeSymlink == 0 || !ownedByRoot(fi) {
		t.Skip("no root-owned directory link at /var on this system")
	}
	if err := refuseLinkedDirectory("/var/tmp/toolwarrant-test/tw.db"); err != nil {
		t.Errorf("a root-owned link was refused: %v", err)
	}
}

// hostileFiles plants, under dir, the operator-given paths of the escape probe,
// each with an ESC byte in its name built at run time: a directory, a
// world-readable file that is not PEM, a file larger than any PEM key file,
// and a symbolic link to target.
func hostileFiles(t *testing.T, dir, target string) (hdir, file, big, link string) {
	t.Helper()
	hdir, file, big, link = filepath.Join(dir, esc+"[2Jdir"), filepath.Join(dir, esc+"[2Jfile.pem"), filepath.Join(dir, esc+"[2Jbig.pem"), filepath.Join(dir, esc+"[2Jlink.db")
	if err := os.Mkdir(hdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("not pem at all\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(big, []byte(strings.Repeat("x", export.MaxKeyFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	return hdir, file, big, link
}

// escapedOnce asserts that the one hostile value a refusal embedded came out as
// one \u{001B}: never the raw byte, and never the doubled backslash the older
// sites printed while they escaped the value and describe escaped the whole
// sentence again.
func escapedOnce(t *testing.T, where, s string) {
	t.Helper()
	n, doubled, raw := strings.Count(s, `\u{001B}`), strings.Contains(s, `\\u{001B}`), strings.Contains(s, esc)
	if n != 1 || doubled || raw {
		t.Errorf("%s: want one \\u{001B} and neither a doubled backslash nor the raw byte; got %d, doubled %t, raw %t in %q", where, n, doubled, raw, s)
	}
}

// TestRefusalsEscapeHostileValuesOnce drives a path or a flag value holding an
// ESC byte through one refusal of every kind that embeds the value in an error
// describe prints: the key file of --pub-key, the directory and the signing
// key of export, the TLS files of serve, the output file of emit, the database
// path, --expect-head of audit verify, and a line of the emitted file verify
// reads. Each sentence is escaped once, where it is printed, so the operator
// reads the value as given. The usage errors, which exitCode prints as
// written, are not in this table and keep escaping their values themselves.
func TestRefusalsEscapeHostileValuesOnce(t *testing.T) {
	t.Parallel()
	c, _ := fixture(t)
	f := newTLSFiles(t)
	keys := newExportKeys(t)
	dir := t.TempDir()
	hdir, file, big, link := hostileFiles(t, dir, c.db)
	cases := []struct {
		name, db, want string
		args           []string
	}{
		{"pub-key directory", "", "is a directory, not a regular file", []string{"export", "verify", "--dir", dir, "--pub-key", hdir}},
		{"pub-key too large", "", "is larger than", []string{"export", "verify", "--dir", dir, "--pub-key", big}},
		{"pub-key not PEM", "", "not a PEM PUBLIC KEY block", []string{"export", "verify", "--dir", dir, "--pub-key", file}},
		{"export directory", "", "does not verify", []string{"export", "verify", "--dir", hdir, "--pub-key", keys.pub}},
		{"signing key", "", "readable by other users", []string{"export", "--dir", filepath.Join(dir, "approved"), "--sign-key", file}},
		{"tls client authority", "", "holds no PEM certificate", f.serveArgs("--tls-client-ca", file)},
		{"tls key", "", "readable by other users", []string{"serve", "--server", "s1", "--listen", "127.0.0.1:0", "--tls-cert", f.certPath, "--tls-key", file}},
		{"emit output", "", "is a directory, not a regular file", []string{"emit", "--out", hdir}},
		{"database missing", filepath.Join(dir, esc+"[2Jmissing.db"), "does not exist", []string{"list"}},
		{"database symlink", link, "is a symbolic link", []string{"init"}},
		{"audit flag", "", "audit head mismatch", []string{"audit", "verify", "--expect-head", esc + "[2Jdead"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := c.sub(t)
			if tc.db != "" {
				run = &cli{t: t, db: tc.db, env: c.env}
			}
			r := run.fail(exitFailure, tc.args...)
			wantContains(t, "stderr", r.stderr, tc.want)
			escapedOnce(t, tc.name, r.stderr)
		})
	}
	// The emitted-file parser's sentences reach describe through verify's
	// live comparison; the line they quote is escaped there, once.
	_, err := emittedConfig([]byte("gateways:\n    port: 1" + esc + "\n"))
	if err == nil {
		t.Fatal("a gateway key outside a gateway was accepted")
	}
	escapedOnce(t, "emitted file line", describe(err))
}
