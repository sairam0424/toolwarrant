package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/emit"
)

// fakeGateway writes a shell script that stands in for the agentgateway
// binary: it records its arguments in a file next to it, prints message on
// stderr and exits with code.
func fakeGateway(t *testing.T, dir, name string, code int, message string) (script, argsLog string) {
	t.Helper()
	script = filepath.Join(dir, name)
	argsLog = filepath.Join(dir, name+".args")
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + shellWord(argsLog) + "\nprintf '%s' " + shellWord(message) + " >&2\n" + fmt.Sprintf("exit %d\n", code)
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, argsLog
}

// --gateway-binary stages the file next to the target, runs the gateway's
// own --validate-only on it and renames it into place only on success; a
// refusal exits 1, prints the gateway's message escaped and leaves no file,
// neither the staged one nor a target that was not there before.
func TestEmitValidatesWithTheGatewayBinary(t *testing.T) {
	t.Parallel()
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	dir := t.TempDir()
	out := filepath.Join(dir, "gateway.yaml")
	bin := t.TempDir()
	okScript, okArgs := fakeGateway(t, bin, "gateway-ok", 0, "")
	r := c.run("emit", "--out", out, "--gateway-binary", okScript)
	if r.code != exitOK {
		t.Fatalf("emit with an accepting binary: exit %d: %s", r.code, r.stderr)
	}
	wantContains(t, "stdout", r.stdout, "wrote "+out, "validated with "+okScript+" "+validateOnlyFlag)
	args := nonEmptyLines(readFile(t, okArgs))
	if len(args) != 3 || args[0] != "-f" || args[2] != validateOnlyFlag {
		t.Fatalf("the gateway was run with %q, want -f FILE %s", args, validateOnlyFlag)
	}
	staged := args[1]
	if filepath.Dir(staged) != dir || !strings.HasPrefix(filepath.Base(staged), ".toolwarrant-") || !strings.HasSuffix(staged, ".tmp.yaml") {
		t.Errorf("staged file %q is not a temporary file next to %s", staged, out)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Errorf("the staged file was left behind: %v", err)
	}
	yaml := readFile(t, out)
	if _, ok := emit.Verify([]byte(yaml)); !ok {
		t.Error("the written file does not verify")
	}

	// The binary comes from the environment when the flag is absent.
	c.env[envGatewayBinary] = okScript
	r = c.run("emit", "--out", out)
	if r.code != exitOK {
		t.Fatalf("emit with the binary from the environment: exit %d: %s", r.code, r.stderr)
	}
	wantContains(t, "stdout", r.stdout, "validated with "+okScript)

	// A refusal, with a message that carries a terminal escape.
	badScript, _ := fakeGateway(t, bin, "gateway-bad", 1, "refused: unknown field "+esc+"[31mfoo"+esc+"[0m at line 7")
	r = c.fail(exitFailure, "emit", "--out", out, "--gateway-binary", badScript)
	wantContains(t, "stderr", r.stderr, "the gateway binary "+badScript+" refused the configuration, so nothing was written: refused: unknown field \\u{001B}[31mfoo\\u{001B}[0m at line 7")
	wantNotContains(t, "stderr", r.stderr, esc)
	wantNotContains(t, "stdout", r.stdout, "wrote", "validated")
	if readFile(t, out) != yaml {
		t.Error("a refused file must leave the previous one in place")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("files left behind: %v", entries)
	}
	delete(c.env, envGatewayBinary)

	fresh := filepath.Join(t.TempDir(), "g.yaml")
	c.fail(exitFailure, "emit", "--out", fresh, "--gateway-binary", badScript)
	if entries, err = os.ReadDir(filepath.Dir(fresh)); err != nil || len(entries) != 0 {
		t.Errorf("a refusal left files behind: %v %v", entries, err)
	}
	silent, _ := fakeGateway(t, bin, "gateway-silent", 2, "")
	r = c.fail(exitFailure, "emit", "--out", out, "--gateway-binary", silent)
	wantContains(t, "stderr", r.stderr, "refused the configuration", "(no message)")
	r = c.fail(exitFailure, "emit", "--out", out, "--gateway-binary", filepath.Join(bin, "absent"))
	wantContains(t, "stderr", r.stderr, "run gateway binary", "absent")
	if readFile(t, out) != yaml {
		t.Error("a binary that cannot run must leave the previous file in place")
	}
}

func TestOneLineBoundsTheGatewayMessage(t *testing.T) {
	t.Parallel()
	if got := oneLine([]byte("  a\n\tb  c\n")); got != "a b c" {
		t.Errorf("oneLine = %q", got)
	}
	if got := oneLine(nil); got != "(no message)" {
		t.Errorf("oneLine(nil) = %q", got)
	}
	long := strings.Repeat("x", maxGatewayOutput+10)
	if got := oneLine([]byte(long)); len(got) != maxGatewayOutput+len(truncated) || !strings.HasSuffix(got, truncated) {
		t.Errorf("oneLine(long) has %d bytes", len(got))
	}
}

// realGatewayBinary finds the pinned agentgateway release binary the seam
// scripts and the end-to-end test use, or skips loudly: a skip here means the
// real validation was not exercised in this run.
func realGatewayBinary(t *testing.T) string {
	t.Helper()
	path := os.Getenv("TOOLWARRANT_GATEWAY_BIN")
	if path == "" {
		path = filepath.Join("..", "..", ".cache", "agentgateway-darwin-arm64")
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("SKIPPED: the real agentgateway binary is not at %s (set TOOLWARRANT_GATEWAY_BIN); emit --gateway-binary was exercised with fake binaries only", path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// The real gateway accepts what emit writes, secret and credentialed URL
// included, in --validate-only mode (the only mode the binary may be run in
// outside the seam scripts and the end-to-end test).
func TestEmitValidatesWithTheRealGatewayBinary(t *testing.T) {
	t.Parallel()
	bin := realGatewayBinary(t)
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	c.ok("server", "add", "queried", "http://127.0.0.1:3002/mcp?q="+plant("query"))
	c.env[secretVar] = plant("secret")
	out := filepath.Join(t.TempDir(), "gateway.yaml")
	r := c.run("emit", "--out", out, "--gateway-binary", bin, "--secret-env", secretVar, "--processor", "s1=127.0.0.1:9101")
	if r.code != exitOK {
		t.Fatalf("emit validated by the real gateway: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	wantContains(t, "stdout", r.stdout, "validated with "+bin+" "+validateOnlyFlag, "wrote "+out)
	if _, ok := emit.Verify([]byte(readFile(t, out))); !ok {
		t.Error("the written file does not verify")
	}
	wantNotContains(t, "output", r.stdout+r.stderr, canary)
}
