package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// downUpstream answers every request with 500.
func downUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The scheduled crawl is checked by waiting for completed iterations, not by
// a fixed time window, so a loaded machine cannot turn it into a flake. An
// upstream that is down for a while does not stop the schedule and, once a
// crawl has completed, does not fail it either (D13 f).
func TestCrawlEveryRepeatsAndSurvivesFailures(t *testing.T) {
	c := newCLI(t)
	broken := downUpstream(t)
	c.ok("server", "add", "down", broken.URL, "--allow-private")
	u := newUpstream(t, map[string]string{"echo": echoV1})
	c.ok("server", "add", "up", u.url(), "--allow-private")

	out, errb, stop := c.start("crawl", "down", "--every", loopEvery.String())
	waitFor(t, "two crawl lines", func() bool { return len(nonEmptyLines(out.String())) >= 2 })
	if code := stop(); code != exitFailure {
		t.Fatalf("crawl --every against a broken upstream: exit %d, want %d (no crawl completed): %s", code, exitFailure, errb.String())
	}
	for _, line := range nonEmptyLines(out.String()) {
		wantContains(t, "line", line, "down:", "http status 500")
		wantNotContains(t, "line", line, broken.URL)
	}

	out, errb, stop = c.start("crawl", "up", "--every", loopEvery.String(), "--json")
	waitFor(t, "two json lines", func() bool { return len(nonEmptyLines(out.String())) >= 2 })
	if code := stop(); code != exitOK {
		t.Fatalf("crawl --every --json: exit %d: %s", code, errb.String())
	}
	for i, line := range nonEmptyLines(out.String()) {
		var rep crawlJSON
		if err := json.Unmarshal([]byte(line), &rep); err != nil || !rep.Complete || rep.Server != "up" {
			t.Fatalf("line %d = %s (%v)", i, line, err)
		}
	}
	// the crawls table has one row per iteration, every one of the broken ones incomplete
	var incomplete, complete int
	queryRow(t, c.db, "SELECT COUNT(*) FROM crawls WHERE complete = 0", &incomplete)
	queryRow(t, c.db, "SELECT COUNT(*) FROM crawls WHERE complete = 1", &complete)
	if incomplete < 2 || complete < 2 {
		t.Errorf("crawls recorded: %d incomplete, %d complete", incomplete, complete)
	}

	// An upstream that goes down after a crawl completed: the failures are
	// printed and the run still exits 0 when it is stopped.
	out, errb, stop = c.start("crawl", "up", "--every", loopEvery.String())
	waitFor(t, "a complete crawl", func() bool { return strings.Contains(out.String(), "complete") })
	u.http.Close()
	waitFor(t, "a failed crawl", func() bool { return strings.Contains(out.String(), "crawl of up failed") })
	if code := stop(); code != exitOK {
		t.Fatalf("crawl --every with a completed crawl and a later failure: exit %d, want 0: %s", code, errb.String())
	}
}

// Third review (cli-docs-3): a schedule in which no crawl ever completed
// exited 0 at SIGTERM, although operations.md lists a crawl failure under
// exit code 1. Now the run fails at the end and says why (D13 f).
func TestCrawlEveryExits1WhenNoCrawlCompleted(t *testing.T) {
	c := newCLI(t)
	down := downUpstream(t)
	c.ok("server", "add", "down", down.URL, "--allow-private")
	out, errb, stop := c.start("crawl", "down", "--every", loopEvery.String())
	waitFor(t, "two failed crawls", func() bool { return strings.Count(out.String(), "http status 500") >= 2 })
	if code := stop(); code != exitFailure {
		t.Errorf("a schedule in which no crawl ever completed exited %d, want %d\n%s", code, exitFailure, out.String())
	}
	wantContains(t, "stderr", errb.String(), "no crawl of this run completed (2 failed, 0 refused by the catalog)", "nothing was recorded")
}

// Third review (cli-docs-3): a scheduled crawl kept recording complete crawls,
// audit entries included, into a catalog whose guard trigger had been dropped,
// a file every other command refuses as corrupt, and exited 0 at SIGTERM. Now
// the schedule re-checks the catalog before every crawl and stops at once
// with exit 1, the way the canary does (D13 f).
func TestCrawlEveryStopsAtOnceOnACorruptCatalog(t *testing.T) {
	c, _ := fixture(t)
	run := c.launch("crawl", "s1", "--every", loopEvery.String())
	waitFor(t, "one complete crawl", func() bool { return strings.Contains(run.stdout.String(), "complete") })
	var before int
	queryRow(t, c.db, "SELECT COUNT(*) FROM crawls WHERE complete = 1", &before)
	execSQL(t, c.db, "DROP TRIGGER audit_log_no_update")
	// Every one-shot command now refuses the file.
	r := c.fail(exitFailure, "list", "s1")
	wantContains(t, "list after the drop", r.stderr, "guard trigger audit_log_no_update is missing", adviceCorrupt)
	lines := len(nonEmptyLines(run.stdout.String()))
	if code := run.wait(); code != exitFailure {
		t.Errorf("crawl --every exited %d against a corrupt catalog, want %d\nstdout: %s\nstderr: %s", code, exitFailure, run.stdout.String(), run.stderr.String())
	}
	for _, line := range nonEmptyLines(run.stdout.String())[lines:] {
		if strings.Contains(line, "complete") {
			t.Errorf("a crawl was recorded as complete into a catalog every other command refuses: %s", line)
		}
	}
	wantContains(t, "stdout", run.stdout.String(), "s1: crawl of s1: ", "guard trigger audit_log_no_update is missing")
	wantContains(t, "stderr", run.stderr.String(), "stopping the crawl schedule", adviceCorrupt)
	var after int
	queryRow(t, c.db, "SELECT COUNT(*) FROM crawls WHERE complete = 1", &after)
	if after != before {
		t.Errorf("%d complete crawl(s) were recorded after the guard was dropped", after-before)
	}
}

// The tally fails a run that completed nothing and a run in which the catalog
// refused a listing (a cap); a listing failure beside a completed crawl does
// not fail it.
func TestCrawlTallyOutcome(t *testing.T) {
	var tally crawlTally
	if err := tally.outcome(); err == nil || !strings.Contains(err.Error(), "no crawl of this run completed (0 failed, 0 refused by the catalog)") {
		t.Errorf("empty run: %v", err)
	}
	tally.record(&crawlFailure{server: "s1", class: "timeout"})
	tally.record(errors.New("crawl of s1: context canceled"))
	if err := tally.outcome(); err == nil || !strings.Contains(err.Error(), "(2 failed, 0 refused") {
		t.Errorf("two failures: %v", err)
	}
	tally.record(nil)
	if err := tally.outcome(); err != nil {
		t.Errorf("a completed crawl beside failures must pass: %v", err)
	}
	tally.record(&crawlFailure{server: "s1", class: "too many tools", refused: true})
	if err := tally.outcome(); err == nil || !strings.Contains(err.Error(), "1 crawl(s) of this run were refused by the catalog") {
		t.Errorf("a refused crawl: %v", err)
	}
	if tally.completed != 1 || tally.failed != 2 || tally.refused != 1 {
		t.Errorf("tally = %+v", tally)
	}
}
