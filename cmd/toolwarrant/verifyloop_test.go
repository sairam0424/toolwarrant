package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
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
	var tally loopTally
	if tally.outcome() == nil {
		t.Error("a run without a completed check must fail")
	}
	tally.record(verdicts{}, nil)
	if tally.outcome() != nil {
		t.Error("a run with one clean check must pass")
	}
	tally.record(verdicts{}, errors.New("down"))
	if err := tally.outcome(); err == nil || !strings.Contains(err.Error(), "1 of 2 check(s) in this run failed") {
		t.Errorf("one errored check: %v", err)
	}
	tally.record(verdicts{probe: probeUnhooked}, nil)
	if err := tally.outcome(); err == nil || !strings.Contains(err.Error(), "2 of 3 check(s) in this run failed") {
		t.Errorf("one failed verdict: %v", err)
	}
}
