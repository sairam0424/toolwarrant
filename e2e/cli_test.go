//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	// cliTimeout bounds one toolwarrant invocation. A crawl of a loopback mock
	// takes milliseconds; the bound only turns a hang into a failure.
	cliTimeout = 120 * time.Second
	// reviewer is the human actor who decides. The crawls run without --as,
	// so they propose as the system actor and reviewer may approve them.
	reviewer = "reviewer"
	// operator registers servers; registering is not a decision.
	operator = "operator"
	// Exit codes of the CLI, part of its interface.
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
	// flagTrustRoot and flagSSHKey are the CLI's two global flags of the
	// signed flow (D22 (h)); the harness passes the first on every command
	// once scenario S recorded the root and the second on every approve once
	// it bootstrapped the list.
	flagTrustRoot = "--trust-root"
	flagSSHKey    = "--ssh-key"
	// authSockEnv is the variable ssh-agent is found through; the harness
	// never lets the developer's own agent reach a subprocess.
	authSockEnv = "SSH_AUTH_SOCK"
	// signedLinePrefix starts the line every signed decision prints after its
	// own: "signed as NAME with SHA256:FP over head PREV; audit head now HEAD".
	signedLinePrefix = "signed as "
)

// scrubbedEnv are the variables a subprocess never inherits from the test's
// own environment: the developer's agent, key and recorded root would make a
// signed command depend on the machine it runs on.
var scrubbedEnv = []string{authSockEnv, "TOOLWARRANT_SSH_KEY", "TOOLWARRANT_TRUST_ROOT"}

// cliResult is what one toolwarrant invocation produced.
type cliResult struct {
	code   int
	stdout string
	stderr string
}

// toolRow is one entry of list --json.
type toolRow struct {
	Server        string `json:"server"`
	Tool          string `json:"tool"`
	State         string `json:"state"`
	Approved      string `json:"approved"`
	Live          string `json:"live"`
	Pending       string `json:"pending"`
	Drifted       bool   `json:"drifted"`
	Unusable      bool   `json:"unusable"`
	MissingCrawls int    `json:"missing_crawls"`
	Versions      int    `json:"versions"`
}

// serverRow is one entry of server list --json. The processor address is the
// catalog's record of where the server's processor listens (decision D14 i);
// emit writes the file from it and never from the file at --out.
type serverRow struct {
	Name          string `json:"name"`
	Paused        bool   `json:"paused"`
	ProcessorAddr string `json:"processor_addr"`
}

// tw runs the CLI as a subprocess against the stack's catalog, with extra
// environment variables (secrets are passed by name, never as flag values).
// Once scenario S recorded the trust root every command carries it as the
// global --trust-root unless the caller names one itself, and while the lab
// agent is served every command finds it through SSH_AUTH_SOCK.
func (s *stack) tw(t *testing.T, env []string, args ...string) cliResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), cliTimeout)
	defer cancel()
	globals := []string{"--db", s.db}
	if s.trustRoot != "" && !slices.Contains(args, flagTrustRoot) {
		globals = append(globals, flagTrustRoot, s.trustRoot)
	}
	cmd := exec.CommandContext(ctx, s.h.toolwarrant, append(globals, args...)...)
	cmd.Dir = s.h.workdir
	cmd.Env = s.environ(env)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := exitOK
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("run toolwarrant %v: %v", args, err)
		}
		code = exit.ExitCode()
	}
	return cliResult{code: code, stdout: out.String(), stderr: errb.String()}
}

// environ is the environment of one CLI subprocess: the test's own without
// the scrubbed variables, the lab agent's socket while one is served, then the
// caller's extra variables, which win over both.
func (s *stack) environ(extra []string) []string {
	env := make([]string, 0, len(os.Environ())+len(extra)+1)
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		if !slices.Contains(scrubbedEnv, key) {
			env = append(env, kv)
		}
	}
	if s.authSock != "" {
		env = append(env, authSockEnv+"="+s.authSock)
	}
	return append(env, extra...)
}

// withoutAgent runs one CLI invocation with no SSH_AUTH_SOCK in its
// environment: the key-file path of a decision, and the refusal of a .pub
// when no agent can be asked, both need the agent to be out of reach for
// exactly that call.
func (s *stack) withoutAgent(run func() cliResult) cliResult {
	sock := s.authSock
	s.authSock = ""
	defer func() { s.authSock = sock }()
	return run()
}

// twOK runs a command that must succeed and returns its stdout.
func (s *stack) twOK(t *testing.T, args ...string) string {
	t.Helper()
	r := s.tw(t, nil, args...)
	if r.code != exitOK {
		t.Fatalf("toolwarrant %v: exit %d\nstdout: %s\nstderr: %s", args, r.code, r.stdout, r.stderr)
	}
	return r.stdout
}

// twFail runs a command that must exit with the given code.
func (s *stack) twFail(t *testing.T, want int, args ...string) cliResult {
	t.Helper()
	r := s.tw(t, nil, args...)
	if r.code != want {
		t.Fatalf("toolwarrant %v: exit %d, want %d\nstdout: %s\nstderr: %s", args, r.code, want, r.stdout, r.stderr)
	}
	return r
}

// jsonInto runs a --json command and decodes its output.
func (s *stack) jsonInto(t *testing.T, v any, args ...string) {
	t.Helper()
	out := s.twOK(t, args...)
	if err := json.Unmarshal([]byte(out), v); err != nil {
		t.Fatalf("toolwarrant %v: output is not JSON (%v):\n%s", args, err, out)
	}
}

// tools lists the catalog's view of one server.
func (s *stack) tools(t *testing.T, server string) []toolRow {
	t.Helper()
	var rows []toolRow
	s.jsonInto(t, &rows, "list", server, "--json")
	return rows
}

// tool returns the catalog's view of one tool.
func (s *stack) tool(t *testing.T, server, name string) toolRow {
	t.Helper()
	for _, row := range s.tools(t, server) {
		if row.Tool == name {
			return row
		}
	}
	t.Fatalf("tool %s/%s is not in the catalog", server, name)
	return toolRow{}
}

// server returns the catalog's view of one server.
func (s *stack) server(t *testing.T, name string) serverRow {
	t.Helper()
	var rows []serverRow
	s.jsonInto(t, &rows, "server", "list", "--json")
	for _, row := range rows {
		if row.Name == name {
			return row
		}
	}
	t.Fatalf("server %s is not in the catalog", name)
	return serverRow{}
}

// approve is the human decision that binds a tool to one exact digest. Once
// scenario S has set the stack's key it signs as the reviewer through the lab
// agent and must print the signed line; before that, and after N's re-init,
// it runs unsigned and must not claim a signature. The whole result is
// returned so a caller can read the stderr warning of an unsigned decision.
func (s *stack) approve(t *testing.T, server, tool, hash string) cliResult {
	t.Helper()
	if hash == "" {
		t.Fatalf("approve %s/%s: no digest to approve", server, tool)
	}
	args := []string{"--as", reviewer}
	if s.sshKey != "" {
		args = append(args, flagSSHKey, s.sshKey)
	}
	args = append(args, "approve", server, tool, "--hash", hash)
	r := s.tw(t, nil, args...)
	if r.code != exitOK {
		t.Fatalf("toolwarrant %v: exit %d\nstdout: %s\nstderr: %s", args, r.code, r.stdout, r.stderr)
	}
	mustContain(t, "approve output", r.stdout, "approved "+server+"/"+tool+" at "+hash)
	if s.sshKey != "" {
		mustContain(t, "signed approve output", r.stdout, signedLinePrefix+reviewer+" with SHA256:", "audit head now")
	} else {
		mustNotContain(t, "unsigned approve output", r.stdout, signedLinePrefix)
	}
	return r
}

// canaryArgs builds one verify-gateway command for a server's route. config
// is the file for --config, "" for none. The unhooked-call probe is sent only
// when probe is set: agentgateway v1.6.0 forwards the id-less probe, which is
// UNHOOKED-CALLS with exit 1, so every check that is about something else
// keeps the probe off with --no-probe, and scenario O is the one that turns
// it on.
func (s *stack) canaryArgs(server string, probe bool, config string) []string {
	args := []string{"verify-gateway", "--server", server, "--url", s.routeURL(server)}
	if config != "" {
		args = append(args, "--config", config)
	}
	if !probe {
		args = append(args, "--no-probe")
	}
	return args
}

// verifyGateway runs one check of one server's route with the emitted file,
// so CONFIG-EDITED is checked too, and without the probe; extra flags such as
// --admin are appended.
func (s *stack) verifyGateway(t *testing.T, server string, extra ...string) cliResult {
	t.Helper()
	return s.tw(t, nil, append(s.canaryArgs(server, false, s.cfg), extra...)...)
}

// mustContain reports every expected substring that is missing from s.
func mustContain(t *testing.T, where, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Errorf("%s lacks %q:\n%s", where, sub, s)
		}
	}
}

// mustNotContain reports every forbidden substring that is present in s.
func mustNotContain(t *testing.T, where, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			t.Errorf("%s must not contain %q:\n%s", where, sub, s)
		}
	}
}
