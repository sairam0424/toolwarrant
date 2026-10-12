package catalog

import (
	"errors"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The paused flag is anchored on every path that acts on it (D17 c, extended
// after the round). Snapshot serves nothing of a paused server and RecordCrawl
// refuses one, so an un-pause by one UPDATE on the servers table re-opened
// serving and crawling of a server the log says is paused, with Integrity the
// only control that saw it; and PauseServer and ResumeServer compared the
// request with the column, so the forged flag turned the operator's resume
// into "already paused=false" while the log still said paused.

func TestServers_PausedFlagIsAnchoredOnEveryPathThatReadsIt(t *testing.T) {
	s, path := anchoredServers(t)
	if err := s.PauseServer(bg, "alpha", bob); err != nil {
		t.Fatal(err)
	}
	recorded, err := s.VerifyAudit(bg)
	if err != nil {
		t.Fatal(err)
	}
	db := rawDB(t, path)
	mustExec(t, db, `UPDATE servers SET paused = 0 WHERE name = 'alpha'`)
	mustExec(t, db, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)

	want := []string{"paused of server", `"alpha"`, "is false", "server.paused entry (seq", "recorded true"}
	_, err = s.Server(bg, "alpha")
	requirePausedCorrupt(t, "Server", err, want)
	_, err = s.Snapshot(bg, "alpha")
	requirePausedCorrupt(t, "Snapshot", err, want)
	_, err = s.RecordCrawl(bg, CrawlInput{Server: "alpha", Complete: true}, crawler)
	requirePausedCorrupt(t, "RecordCrawl", err, want)
	requirePausedCorrupt(t, "ResumeServer", s.ResumeServer(bg, "alpha", bob), want)
	requirePausedCorrupt(t, "PauseServer", s.PauseServer(bg, "alpha", bob), want)
	for label, opts := range map[string]OpenOptions{"read-only": {ReadOnly: true}, "read-write": {Policy: lifecycle.DefaultPolicy()}} {
		fresh, err := OpenWith(path, opts)
		if err != nil {
			t.Fatalf("%s Open = %v", label, err)
		}
		_, err = fresh.Snapshot(bg, "alpha")
		requirePausedCorrupt(t, label+" fresh Snapshot", err, want)
		_ = fresh.Close()
	}
	if after, err := s.VerifyAudit(bg); err != nil || after.Head != recorded.Head {
		t.Errorf("VerifyAudit = %+v, %v; the log was not touched", after, err)
	}
	if rep := mustIntegrity(t, s); rep.ServersMismatched != 1 {
		t.Errorf("Integrity.ServersMismatched = %d, want 1; %q", rep.ServersMismatched, rep.Problems)
	}

	mustExec(t, db, `UPDATE servers SET paused = 1 WHERE name = 'alpha'`)
	if snap := mustSnapshot(t, s, "alpha"); len(snap.Tools) != 0 {
		t.Errorf("Snapshot of the paused server once the column is restored = %+v, want no tools", snap.Tools)
	}
	if err := s.ResumeServer(bg, "alpha", bob); err != nil {
		t.Fatalf("ResumeServer once the column is restored = %v", err)
	}
	if snap := mustSnapshot(t, s, "alpha"); !snap.Serves("echo", digestOf(t, "echo", "v1")) {
		t.Errorf("Snapshot after the resume = %+v", snap.Tools["echo"])
	}
	mustBeClean(t, s, "after the resume")
}

// A server the log never paused cannot be paused by the column alone either:
// the flag must have an entry.
func TestServers_PausedFlagWithoutAnEntryIsCorrupt(t *testing.T) {
	s, path := anchoredServers(t)
	db := rawDB(t, path)
	mustExec(t, db, `UPDATE servers SET paused = 1 WHERE name = 'beta'`)
	want := []string{"paused of server", `"beta"`, "is true", "no server.paused or server.resumed entry"}
	_, err := s.Server(bg, "beta")
	requirePausedCorrupt(t, "Server", err, want)
	_, err = s.Snapshot(bg, "beta")
	requirePausedCorrupt(t, "Snapshot", err, want)
	if _, err := s.Servers(bg); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Servers = %v, want ErrCorrupt", err)
	}
}

// requirePausedCorrupt fails unless err is ErrCorrupt mentioning every fragment.
func requirePausedCorrupt(t *testing.T, what string, err error, fragments []string) {
	t.Helper()
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("%s = %v, want ErrCorrupt", what, err)
	}
	for _, f := range fragments {
		if !strings.Contains(err.Error(), f) {
			t.Errorf("%s error %q does not mention %q", what, err, f)
		}
	}
}
