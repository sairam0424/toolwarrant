//go:build e2e

package e2e

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	// stopGrace is how long a process gets after SIGTERM before SIGKILL. The
	// processor drains in-flight hooks for up to five seconds and the gateway
	// drains connections for up to five, so ten covers both.
	stopGrace = 10 * time.Second
	// pollEvery is the interval of every bounded poll in the harness.
	pollEvery = 20 * time.Millisecond
	// portWait bounds how long a freshly started process may take to listen.
	portWait = 30 * time.Second
	// dialTimeout bounds one probe of a port.
	dialTimeout = 500 * time.Millisecond
)

// proc is one process the harness started, with its output captured to files
// under the log directory so a failure can point at them.
type proc struct {
	name    string
	cmd     *exec.Cmd
	stdout  string
	stderr  string
	done    chan struct{}
	waitErr error
}

// start launches bin with args, its stdout and stderr going to
// logs/<name>.<n>.stdout and .stderr, where n counts the starts of that name.
// Its environment is the test's own without the scrubbed variables
// (scrubbedEnv), then extraEnv, which wins. The caller registers the cleanup:
// processes outlive the subtest that started them, so t.Cleanup on the
// subtest would be wrong here.
func (hh *harness) start(t *testing.T, name string, extraEnv []string, bin string, args ...string) *proc {
	t.Helper()
	base := filepath.Join(hh.logDir, fmt.Sprintf("%s.%d", name, hh.procs.nextSeq(name)))
	outf, err := os.Create(base + ".stdout")
	if err != nil {
		t.Fatalf("create log for %s: %v", name, err)
	}
	errf, err := os.Create(base + ".stderr")
	if err != nil {
		t.Fatalf("create log for %s: %v", name, err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = hh.workdir
	cmd.Env = append(scrubbedEnviron(), extraEnv...)
	cmd.Stdout, cmd.Stderr = outf, errf
	p := &proc{name: name, cmd: cmd, stdout: outf.Name(), stderr: errf.Name(), done: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s (%s %s): %v", name, bin, strings.Join(args, " "), err)
	}
	hh.procs.add(p)
	go func() {
		p.waitErr = cmd.Wait()
		_ = outf.Close()
		_ = errf.Close()
		close(p.done)
		hh.procs.remove(p)
	}()
	return p
}

// running reports whether the process has not been reaped yet.
func (p *proc) running() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// stop ends the process gracefully (SIGTERM, which both the gateway and
// toolwarrant serve handle by draining and printing their counters) and falls
// back to SIGKILL after stopGrace. It returns the exit code, -1 when unknown.
func (p *proc) stop() int {
	if p.running() {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-p.done:
	case <-time.After(stopGrace):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
	return p.exitCode()
}

// exitCode is the process exit code after it was reaped.
func (p *proc) exitCode() int {
	<-p.done
	if p.cmd.ProcessState == nil {
		return -1
	}
	return p.cmd.ProcessState.ExitCode()
}

// output reads one of the captured streams as it is right now.
func (p *proc) output(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("(cannot read %s: %v)", path, err)
	}
	return string(data)
}

// logs names the two capture files for a failure message.
func (p *proc) logs() string {
	return fmt.Sprintf("%s: stdout %s, stderr %s", p.name, p.stdout, p.stderr)
}

// freePort asks the kernel for a free loopback port and releases it. The
// window between release and reuse is the usual race, acceptable for a test
// that runs alone on loopback.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick a free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// portOpen reports whether something accepts TCP connections at addr.
func portOpen(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// waitPort waits until addr accepts connections. If p exits first the wait
// fails at once with the process's captured output, so a crashed gateway or
// processor is reported as such rather than as a timeout.
func waitPort(t *testing.T, p *proc, addr string) {
	t.Helper()
	deadline := time.Now().Add(portWait)
	for !portOpen(addr) {
		if p != nil && !p.running() {
			t.Fatalf("%s exited with code %d before %s opened\nstdout:\n%s\nstderr:\n%s", p.name, p.exitCode(), addr, p.output(p.stdout), p.output(p.stderr))
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not open %s within %s", p.name, addr, portWait)
		}
		time.Sleep(pollEvery)
	}
}

// waitPortClosed waits until nothing listens at addr any more, so a restart
// on the same port cannot race the old process's listener.
func waitPortClosed(t *testing.T, addr string) {
	t.Helper()
	if !pollUntil(portWait, func() bool { return !portOpen(addr) }) {
		t.Fatalf("%s is still accepting connections after %s", addr, portWait)
	}
}

// pollUntil calls cond every pollEvery until it is true or timeout passes.
func pollUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(pollEvery)
	}
}

// waitForOutput waits until the process's stdout holds more than before
// occurrences of substr, so a line printed by a loop (one check per tick) can
// be awaited rather than slept for.
func waitForOutput(t *testing.T, p *proc, substr string, before int) {
	t.Helper()
	if !pollUntil(portWait, func() bool { return countIn(p.stdout, substr) > before }) {
		t.Fatalf("%s did not print %q (beyond %d earlier occurrences) within %s\nstdout:\n%s\nstderr:\n%s", p.name, substr, before, portWait, p.output(p.stdout), p.output(p.stderr))
	}
}

// countIn counts the occurrences of substr in the file at path; a file that
// cannot be read counts as empty.
func countIn(path, substr string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return strings.Count(string(data), substr)
}

// lastLineWith returns the last line of text that contains substr, or "".
func lastLineWith(text, substr string) string {
	last := ""
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, substr) {
			last = line
		}
	}
	return last
}

// since formats the time elapsed since t0 in milliseconds.
func since(t0 time.Time) string {
	return fmt.Sprintf("%.1f ms", float64(time.Since(t0).Microseconds())/1000)
}
