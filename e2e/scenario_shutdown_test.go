//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"testing"
	"time"
)

const (
	// pinningRounds is how many drift-and-approve rounds scenario N runs on
	// mock before the re-init, each appending a crawl, a proposal and an
	// approval to the audit log whose newest verified entry the processor's
	// store pins (decision D14 b).
	pinningRounds = 3
	// unavailableMarker is the processor's log line for a catalog read that
	// failed, the one place a source error is reported.
	unavailableMarker = "catalog unavailable, denying"
	// shortDigest is how many hex digits of an audit head a note shows.
	shortDigest = 12
	// auditOKPrefix starts the line audit verify prints for an intact chain:
	// "audit log ok: N entries, head H".
	auditOKPrefix = "audit log ok:"
)

// scenarioN: the processors keep serving across several legitimate crawls and
// approvals (the chain pin of decision D14 b advances and never denies); a
// processor restarted on that log walks the whole chain when its store opens
// and serves exactly what it served before (decision D15 a); a catalog deleted and initialised again under running processors makes every
// one of them deny with a source error on its next hook instead of serving
// the deleted file's approvals (decision D14 e; before the fifth round a
// processor read the deleted file through its open handle for as long as it
// ran, findings core-1 and processor-emit-1); every processor then stops
// cleanly on SIGTERM, exits 0 and prints its counters (mock's processor
// received mockb's hooks in scenario J, hostile's hid vendor_tool in scenario
// L, and the re-init added source errors to mock's and mockb's); and a
// processor started again on the new catalog serves what was re-approved and
// nothing else, which is why the recovery procedures stop every processor of
// the file before deleting it and start them after init.
func scenarioN(t *testing.T, s *stack) {
	scenarioNPinning(t, s)
	scenarioNRestart(t, s)
	scenarioNReinit(t, s)
	scenarioNShutdown(t, s)
	scenarioNRecover(t, s)
}

// scenarioNPinning drifts mock's echo and approves the new digest several
// times, then returns echo to the shipped definition and approves that again;
// every round must serve on the next listing and mock's processor must log no
// source error, since each round appends entries behind the pinned one.
func scenarioNPinning(t *testing.T, s *stack) {
	proc := s.servers["mock"].processor
	before := countIn(proc.stderr, unavailableMarker)
	head0 := s.auditHead(t)
	for i := 1; i <= pinningRounds; i++ {
		s.describe(t, "mock", "echo", fmt.Sprintf("%s (round %d)", echoV1, i))
		mustContain(t, "crawl", s.twOK(t, "crawl", "mock"), "DRIFT")
		s.approve(t, "mock", "echo", s.pendingDigest(t, "mock", "echo"))
		s.expectAllowed(t, s.eventuallyServes(t, "mock", "add", "echo"), "echo", "hello")
	}
	s.describe(t, "mock", "echo", echoV1)
	out := s.twOK(t, "crawl", "mock")
	s.approve(t, "mock", "echo", s.pendingDigest(t, "mock", "echo"))
	s.expectAllowed(t, s.eventuallyServes(t, "mock", "add", "echo"), "echo", "hello")
	if n := countIn(proc.stderr, unavailableMarker); n != before {
		t.Errorf("mock's processor logged %d source error(s) across legitimate crawls and approvals; the chain pin must advance, not deny", n-before)
	}
	s.note(t, "N: %d drift-and-approve rounds and the return to the shipped definition (the crawl printed %q) moved the audit head from %s to %s while mock's processor kept serving and logged no source error (chain pinning, decision D14)",
		pinningRounds, lastLineWith(out, "crawl"), head0[:shortDigest], s.auditHead(t)[:shortDigest])
}

// pendingDigest is the digest a crawl left pending for a tool, which must
// differ from the approved one.
func (s *stack) pendingDigest(t *testing.T, server, tool string) string {
	t.Helper()
	row := s.tool(t, server, tool)
	if row.Pending == "" || row.Pending == row.Approved {
		t.Fatalf("no pending digest to approve for %s/%s: %+v", server, tool, row)
	}
	return row.Pending
}

// auditHead returns the audit head audit verify prints.
func (s *stack) auditHead(t *testing.T) string {
	t.Helper()
	head, _ := s.auditSummary(t)
	return head
}

// auditSummary returns the head and the entry count audit verify prints for
// an intact chain.
func (s *stack) auditSummary(t *testing.T) (head string, entries int) {
	t.Helper()
	out := s.twOK(t, "audit", "verify")
	line := lastLineWith(out, auditOKPrefix)
	if _, err := fmt.Sscanf(line, auditOKPrefix+" %d entries, head %s", &entries, &head); err != nil || len(head) != hexDigestLen {
		t.Fatalf("audit verify printed no %q line with a count and a head (%v):\n%s", auditOKPrefix, err, out)
	}
	return head, entries
}

// scenarioNRestart stops mock's processor and starts it again on the same
// port after the decisions of scenarioNPinning. A store verifies the whole
// audit chain when it opens (decision D15 a), so the fresh processor walks a
// log of crawls, proposals, approvals and a rollback before it serves; it
// must serve exactly what the stopped one served, log no source error, and
// the restart must append nothing to the log.
func scenarioNRestart(t *testing.T, s *stack) {
	head, entries := s.auditSummary(t)
	before := s.servedDescriptions(t, "mock", "add", "echo")
	stopped := s.stopProcessor(t, "mock")
	// The counters end with this process: scenario J pointed mockb's route
	// at mock's processor, so its wrong-backend count is checked here, before
	// the restart starts them from zero.
	if n := statValue(t, lastLineWith(stopped, "stats:"), "wrong backend"); n == 0 {
		t.Errorf("mock's processor counted no wrong-backend hooks before its restart although scenario J pointed mockb's route at it")
	}
	t0 := time.Now()
	s.startProcessor(t, "mock", nil)
	after := s.servedDescriptions(t, "mock", "add", "echo")
	elapsed := since(t0)
	for name, desc := range before {
		if after[name] != desc {
			t.Errorf("after the restart %s is served as %q, before it was %q", name, after[name], desc)
		}
	}
	cs := s.eventuallyServes(t, "mock", "add", "echo")
	s.expectAllowed(t, cs, "echo", "hello")
	s.expectDenied(t, cs, "wipe_database")
	proc := s.servers["mock"].processor
	if n := countIn(proc.stderr, unavailableMarker); n != 0 {
		t.Errorf("the restarted processor logged %d source error(s) on a legitimate history:\n%s", n, proc.output(proc.stderr))
	}
	if h, e := s.auditSummary(t); h != head || e != entries {
		t.Errorf("the restart changed the audit log: %d entries with head %s, before %d with head %s", e, h[:shortDigest], entries, head[:shortDigest])
	}
	s.note(t, "N: mock's processor restarted on a log of %d entries (head %s) served add and echo with the same definitions %s after its start, logged no source error and appended nothing: the open-time chain walk accepts a legitimate history (decision D15 a)", entries, head[:shortDigest], elapsed)
}

// servedDescriptions waits until the route of server lists exactly the given
// names and returns each name's served description.
func (s *stack) servedDescriptions(t *testing.T, server string, names ...string) map[string]string {
	t.Helper()
	cs := s.eventuallyServes(t, server, names...)
	tools, err := listTools(cs)
	if err != nil {
		t.Fatalf("tools/list on %s: %v", server, err)
	}
	out := map[string]string{}
	for _, tool := range tools {
		out[tool.Name] = tool.Description
	}
	return out
}

// scenarioNReinit deletes the catalog and its SQLite side files and runs init
// again while every processor is running, the way the growth-cap recovery
// read before the fifth round, and requires mock's and mockb's routes to deny
// everything on the next hook with a source error. The processors keep their
// handle on the deleted file; only the identity check of decision D14 (e)
// tells them that the path now names another catalog.
func scenarioNReinit(t *testing.T, s *stack) {
	mock, mockb := s.servers["mock"].processor, s.servers["mockb"].processor
	before := countIn(mock.stderr, unavailableMarker)
	s.expectAllowed(t, s.eventuallyServes(t, "mockb", "echo"), "echo", "hello")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(s.db + suffix); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove %s: %v", s.db+suffix, err)
		}
	}
	t0 := time.Now()
	s.twOK(t, "init")
	for _, name := range []string{"mock", "mockb"} {
		cs := s.connect(t, name)
		names, err := listNames(cs)
		if err == nil && len(names) > 0 {
			t.Fatalf("after the catalog at %s was deleted and initialised again under the running processors, the route of %s listed %v: the processor served the deleted file's approvals\n%s", s.db, name, names, s.logHints())
		}
		o := s.expectDenied(t, cs, "echo")
		s.note(t, "N: %s after the re-init, on %s tools/list -> names %v, err %v; tools/call echo -> %s", since(t0), name, names, err, o)
	}
	if !pollUntil(portWait, func() bool { return countIn(mock.stderr, unavailableMarker) > before }) {
		t.Errorf("mock's processor logged no %q line after the re-init\n%s", unavailableMarker, mock.output(mock.stderr))
	}
	mustContain(t, "mockb's processor log", mockb.output(mockb.stderr), unavailableMarker)
	s.note(t, "N: both processors logged %q: a catalog deleted and initialised again under a running processor denies everything from the next hook on (decision D14 e), so the recovery procedures stop every processor of the file before deleting it", unavailableMarker)
}

// scenarioNShutdown stops every processor on SIGTERM and checks the counters
// each prints.
func scenarioNShutdown(t *testing.T, s *stack) {
	for _, name := range s.names {
		u := s.servers[name]
		if u.processor == nil || !u.processor.running() {
			t.Errorf("processor %s is not running at shutdown", name)
			continue
		}
		out := s.stopProcessor(t, name)
		stats := lastLineWith(out, "stats:")
		if stats == "" {
			t.Errorf("processor %s printed no stats line on SIGTERM:\n%s", name, out)
			continue
		}
		s.note(t, "N: processor %s on SIGTERM: %s", name, stats)
		switch name {
		case "hostile":
			if n := statValue(t, stats, "mismatched"); n == 0 {
				t.Errorf("hostile's processor counted no mismatched tools although scenario L served vendor_tool")
			}
		}
		if name != "hostile" {
			if n := statValue(t, stats, "source errors"); n == 0 {
				t.Errorf("%s's processor counted no source errors although it denied hooks after the re-init", name)
			}
		}
	}
}

// scenarioNRecover finishes the documented recovery on the new catalog: mock
// is registered again, crawled and echo re-approved, and a processor started
// afresh serves exactly that, then stops cleanly. The allow rule in the file
// still names add and echo; the processor narrows it to the re-approved echo.
func scenarioNRecover(t *testing.T, s *stack) {
	u := s.servers["mock"]
	mustContain(t, "server add", s.twOK(t, "--as", operator, "server", "add", "mock", u.url, "--allow-private"), "added server mock")
	mustContain(t, "crawl of the new catalog", s.twOK(t, "crawl", "mock"), "new=3")
	s.approve(t, "mock", "echo", s.tool(t, "mock", "echo").Pending)
	t0 := time.Now()
	s.startProcessor(t, "mock", nil)
	cs := s.eventuallyServes(t, "mock", "echo")
	s.expectAllowed(t, cs, "echo", "hello")
	o := s.expectDenied(t, cs, "add")
	s.note(t, "N: a processor started on the re-initialised catalog served the re-approved echo %s after its start; add, approved only in the deleted catalog, is denied: %s", since(t0), o)
	mustContain(t, "restarted processor stdout", s.stopProcessor(t, "mock"), "stats:")
}
