package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/catalog"
)

// A file --config cannot read stops a scheduled run at once, --keep-going or
// not, with CONFIG-EDITED and the reason; the listing of that check still
// runs, so a LEAK seen at the same time is reported too, and a gateway that
// is down does not hide the file verdict either.
func TestVerifyGatewayEveryFailsClosedOnAnUnreadableConfig(t *testing.T) {
	c, u := fixture(t)
	missing := filepath.Join(t.TempDir(), "none.yaml")
	before := u.sessions.Load()
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", u.url(), "--every", loopEvery.String(), "--keep-going", "--config", missing, "--no-probe")
	wantContains(t, "stdout", r.stdout, verdictConfigEdited+" "+missing+": the file could not be read (", verdictLeak+" echo live ", verdictLeak+" add live ")
	wantContains(t, "stderr", r.stderr, "could not be read, so it is treated as edited", "3 tool(s) leak")
	if n := u.sessions.Load() - before; n != 1 {
		t.Errorf("%d checks ran, want exactly one before the unreadable file stopped the run", n)
	}
	closed := newUpstream(t, nil)
	closed.http.Close()
	r = c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", closed.url(), "--every", loopEvery.String(), "--keep-going", "--config", missing)
	wantContains(t, "stdout", r.stdout, verdictConfigEdited+" "+missing, "check failed: listing through the gateway failed")
	wantContains(t, "stderr", r.stderr, "could not be read, so it is treated as edited")
}

// An unknown server or a catalog that cannot be trusted stops the run at
// once, --keep-going or not: a canary that kept going would print "check
// failed" for ever. The catalog error is produced while the canary runs, by
// dropping a guard trigger between two checks.
func TestVerifyGatewayEveryStopsAtOnceOnACatalogError(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	g := newUpstream(t, map[string]string{"echo": echoV1})
	r := c.fail(exitFailure, "verify-gateway", "--server", "nope", "--url", g.url(), "--every", loopEvery.String(), "--keep-going")
	wantContains(t, "stdout", r.stdout, "nope: check failed: ", "not found")
	wantContains(t, "stderr", r.stderr, "stopping the canary", "not found")
	if g.sessions.Load() != 0 {
		t.Error("the gateway was listed for a server the catalog does not know")
	}

	run := c.launch("verify-gateway", "--server", "s1", "--url", g.url(), "--every", loopEvery.String(), "--keep-going")
	waitFor(t, "a healthy check", func() bool { return strings.Contains(run.stdout.String(), "1 approved and current") })
	execSQL(t, c.db, "DROP TRIGGER audit_log_no_update")
	if code := run.wait(); code != exitFailure {
		t.Fatalf("exit %d after the catalog lost a guard, want %d\n%s", code, exitFailure, run.stdout.String())
	}
	wantContains(t, "stdout", run.stdout.String(), "s1: check failed: ", "integrity")
	wantContains(t, "stderr", run.stderr.String(), "stopping the canary", adviceCorrupt)
}

// A listing that fails (the gateway is down for a while) is printed as
// "check failed", counted, and does not stop the schedule; the run then exits
// 1 when it is stopped, and a run in which no check ever completed says so.
func TestVerifyGatewayEveryCountsListingFailures(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	g := newUpstream(t, map[string]string{"echo": echoV1})
	run := c.launch("verify-gateway", "--server", "s1", "--url", g.url(), "--every", loopEvery.String())
	waitFor(t, "a healthy check", func() bool { return strings.Contains(run.stdout.String(), "1 approved and current") })
	g.http.Close()
	waitFor(t, "a failed listing", func() bool {
		return strings.Contains(run.stdout.String(), "s1: check failed: listing through the gateway failed: ")
	})
	if code := run.stop(); code != exitFailure {
		t.Fatalf("exit %d after a listing failure, want %d\n%s", code, exitFailure, run.stdout.String())
	}
	wantContains(t, "stderr", run.stderr.String(), "check(s) in this run failed", "or could not run")
	wantNotContains(t, "stdout", run.stdout.String(), g.url())

	closed := newUpstream(t, nil)
	closed.http.Close()
	run = c.launch("verify-gateway", "--server", "s1", "--url", closed.url(), "--every", loopEvery.String(), "--keep-going")
	waitFor(t, "two failed checks", func() bool { return strings.Count(run.stdout.String(), "check failed") >= 2 })
	if code := run.stop(); code != exitFailure {
		t.Fatalf("exit %d when no check completed, want %d", code, exitFailure)
	}
	wantContains(t, "stderr", run.stderr.String(), "no check of this run completed", "could not run", "nothing was proven about the gateway")
}

// Third review (cli-docs-2): the stop signal arrived while the admin API
// fetch of a check was in flight, after the listing of that same check had
// found a LEAK; the LEAK line was printed, the check was never tallied, and a
// --keep-going run whose earlier checks were healthy exited 0 with a LEAK on
// stdout. Now every check is tallied before the signal is looked at, the LEAK
// line is printed before the admin API is asked, and a run that printed any
// failing verdict line exits 1 (D13 f). The test's admin API answers the
// healthy document once, then holds every request open until the canary is
// stopped, while the stand-in gateway starts serving a poisoned echo.
func TestKeepGoingExits1WhenStoppedDuringACheckThatFoundALeak(t *testing.T) {
	c, u, _, cfg := liveFixture(t)
	g := newUpstream(t, map[string]string{"echo": echoV1})
	gw := g.url() + routePath
	var stall atomic.Bool
	stalled := make(chan struct{}, 1)
	healthy := adminDoc(t, u.url())
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stall.Load() {
			select {
			case stalled <- struct{}{}:
			default:
			}
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", mediaJSON)
		_, _ = io.WriteString(w, healthy)
	}))
	t.Cleanup(admin.Close)

	run := c.launch("verify-gateway", "--server", "s1", "--url", gw, "--config", cfg, "--admin", strings.TrimPrefix(admin.URL, "http://"), "--every", loopEvery.String(), "--keep-going", "--no-probe")
	waitFor(t, "a healthy check", func() bool {
		return strings.Contains(run.stdout.String(), "live configuration matches the emitted file")
	})
	g.set("echo", echoV2)
	stall.Store(true)
	<-stalled
	// The LEAK line is already on stdout while the admin fetch is held open.
	wantContains(t, "stdout while stalled", run.stdout.String(), verdictLeak+" echo live ")
	code := run.stop()
	out := run.stdout.String()
	if code != exitFailure {
		t.Errorf("a --keep-going run printed a LEAK and exited %d, want %d\nstdout: %s\nstderr: %s", code, exitFailure, out, run.stderr.String())
	}
	wantContains(t, "stderr", run.stderr.String(), "check(s) in this run failed", verdictLeak)
}

func TestIsFatalCheckError(t *testing.T) {
	for _, err := range []error{catalog.ErrNotFound, catalog.ErrCorrupt, catalog.ErrSchema} {
		if !isFatalCheckError(fmt.Errorf("open database: %w", err)) {
			t.Errorf("%v is not fatal", err)
		}
	}
	for _, err := range []error{errors.New("listing through the gateway failed: connection refused"), context.Canceled, catalog.ErrReadOnly, catalog.ErrPaused} {
		if isFatalCheckError(err) {
			t.Errorf("%v is fatal", err)
		}
	}
}

// The tally fails a run that never completed a check, that had a check error
// or fail, or that printed a failing verdict line; a check cut short by the
// stop signal before it found anything is not counted either way.
func TestLoopTallyOutcome(t *testing.T) {
	var tally loopTally
	if tally.outcome() == nil {
		t.Error("a run without a completed check must fail")
	}
	tally.record(verdicts{}, nil, false)
	if tally.outcome() != nil {
		t.Error("a run with one clean check must pass")
	}
	tally.record(verdicts{}, context.Canceled, true)
	if tally.outcome() != nil || tally.errored != 0 {
		t.Errorf("an interrupted clean check must not count: %+v", tally)
	}
	tally.record(verdicts{}, errors.New("down"), false)
	if err := tally.outcome(); err == nil || !strings.Contains(err.Error(), "1 of 2 check(s) in this run failed") {
		t.Errorf("one errored check: %v", err)
	}
	tally.record(verdicts{probe: probeUnhooked}, nil, false)
	if err := tally.outcome(); err == nil || !strings.Contains(err.Error(), "2 of 3 check(s) in this run failed") {
		t.Errorf("one failed verdict: %v", err)
	}
	tally.record(verdicts{leaks: []leak{{}}}, context.Canceled, true)
	if err := tally.outcome(); err == nil || !strings.Contains(err.Error(), "3 of 4 check(s) in this run failed") {
		t.Errorf("an interrupted check that found a leak: %v", err)
	}
	wantContains(t, "outcome", tally.outcome().Error(), verdictLeak, verdictConfigEdited, verdictLiveConfig, verdictUnhooked, verdictInconclusive)
	printed := loopTally{completed: 1, verdictLines: 1}
	if err := printed.outcome(); err == nil || !strings.Contains(err.Error(), "0 of 1 check(s) in this run failed") {
		t.Errorf("a run that printed a verdict line: %v", err)
	}
}
