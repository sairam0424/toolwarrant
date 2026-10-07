//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Environment variables the harness honours. They exist so that demo/run.sh
// can choose the work directory (and kill anything left in it afterwards) and
// collect the measurements, and so that a developer can point the test at a
// gateway binary somewhere else or keep the logs of a passing run.
const (
	gatewayBinEnv = "TOOLWARRANT_GATEWAY_BIN"
	workdirEnv    = "TOOLWARRANT_E2E_WORKDIR"
	keepEnv       = "TOOLWARRANT_E2E_KEEP"
	reportEnv     = "TOOLWARRANT_E2E_REPORT_FILE"
	// defaultGatewayBin is where the seam scripts and the quickstart expect the
	// sha256-verified v1.6.0 release binary, relative to the module root.
	defaultGatewayBin = ".cache/agentgateway-darwin-arm64"
	buildTimeout      = 5 * time.Minute
	killGrace         = 5 * time.Second
)

// harness is the per-process state of the run: where the module is, where the
// binaries were built, where logs go, which gateway to use and which
// processes were started, so that the end of the run can stop every one of
// them whatever the tests did.
type harness struct {
	root         string
	workdir      string
	ownsWorkdir  bool
	logDir       string
	toolwarrant  string
	mockupstream string
	gatewayBin   string
	// skip is why TestEndToEnd must skip: the gateway binary is missing.
	skip  string
	procs *registry
}

// h is set once by TestMain and read by the tests. It is the one piece of
// package state, and it exists because TestMain cannot pass values to tests.
var h *harness

func TestMain(m *testing.M) {
	hh, err := newHarness()
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: setup failed: %v\n", err)
		os.Exit(1)
	}
	h = hh
	code := m.Run()
	h.procs.killAll()
	h.finish(code)
	os.Exit(code)
}

// newHarness finds the module root, prepares the work directory, locates the
// gateway binary and builds the two binaries the test drives.
func newHarness() (*harness, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	root := filepath.Dir(cwd)
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return nil, fmt.Errorf("module root not found above %s: %w", cwd, err)
	}
	hh := &harness{root: root, procs: newRegistry()}
	if err := hh.prepareWorkdir(); err != nil {
		return nil, err
	}
	hh.gatewayBin = os.Getenv(gatewayBinEnv)
	if hh.gatewayBin == "" {
		hh.gatewayBin = filepath.Join(root, defaultGatewayBin)
	}
	if fi, err := os.Stat(hh.gatewayBin); err != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
		hh.skip = fmt.Sprintf("SKIPPING THE END-TO-END TEST: the agentgateway v1.6.0 binary is not at %s (%v); download release v1.6.0 from github.com/agentgateway/agentgateway, verify its SHA-256, and put it there or set %s", hh.gatewayBin, err, gatewayBinEnv)
	}
	if err := hh.build(); err != nil {
		return nil, err
	}
	return hh, nil
}

// prepareWorkdir uses the caller's directory when one is named (demo/run.sh
// names one so it can clean up after a killed run) and a fresh temporary
// directory otherwise.
func (hh *harness) prepareWorkdir() error {
	if dir := os.Getenv(workdirEnv); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		hh.workdir = dir
	} else {
		dir, err := os.MkdirTemp("", "toolwarrant-e2e-")
		if err != nil {
			return fmt.Errorf("create work directory: %w", err)
		}
		hh.workdir, hh.ownsWorkdir = dir, true
	}
	hh.logDir = filepath.Join(hh.workdir, "logs")
	return os.MkdirAll(hh.logDir, 0o755)
}

// build compiles toolwarrant and mockupstream from the module into the work
// directory. GOFLAGS=-mod=readonly is set so the build can never touch go.mod.
func (hh *harness) build() error {
	bin := filepath.Join(hh.workdir, "bin")
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", bin+string(os.PathSeparator), "./cmd/toolwarrant", "./cmd/mockupstream")
	cmd.Dir = hh.root
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=readonly")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go build ./cmd/toolwarrant ./cmd/mockupstream: %w\n%s", err, out)
	}
	hh.toolwarrant = filepath.Join(bin, "toolwarrant")
	hh.mockupstream = filepath.Join(bin, "mockupstream")
	return nil
}

// finish keeps the work directory when anything failed or the caller asked for
// it, so the process logs can be read, and removes it otherwise. A directory
// the caller supplied (demo/run.sh) is never removed here: its owner decides.
func (hh *harness) finish(code int) {
	switch {
	case code != 0 || os.Getenv(keepEnv) != "":
		fmt.Fprintf(os.Stderr, "e2e: work directory kept at %s (process logs under %s)\n", hh.workdir, hh.logDir)
	case hh.ownsWorkdir:
		_ = os.RemoveAll(hh.workdir)
	}
}

// registry tracks every process the harness started, so that the end of the
// run can kill anything a failed test left behind. It also numbers restarts
// of a process so their logs do not overwrite each other.
type registry struct {
	mu    sync.Mutex
	procs map[*proc]struct{}
	seq   map[string]int
}

func newRegistry() *registry {
	return &registry{procs: map[*proc]struct{}{}, seq: map[string]int{}}
}

func (r *registry) add(p *proc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.procs[p] = struct{}{}
}

func (r *registry) remove(p *proc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.procs, p)
}

// nextSeq returns the restart number of a process name, starting at 1.
func (r *registry) nextSeq(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq[name]++
	return r.seq[name]
}

// killAll sends SIGKILL to every process still running and waits for each to
// be reaped, so that no gateway, processor or mock survives the test binary.
func (r *registry) killAll() {
	r.mu.Lock()
	left := make([]*proc, 0, len(r.procs))
	for p := range r.procs {
		left = append(left, p)
	}
	r.mu.Unlock()
	for _, p := range left {
		if !p.running() {
			continue
		}
		fmt.Fprintf(os.Stderr, "e2e: killing %s (pid %d), still running at the end\n", p.name, p.cmd.Process.Pid)
		_ = p.cmd.Process.Signal(syscall.SIGKILL)
		select {
		case <-p.done:
		case <-time.After(killGrace):
			fmt.Fprintf(os.Stderr, "e2e: %s (pid %d) did not exit after SIGKILL\n", p.name, p.cmd.Process.Pid)
		}
	}
}
