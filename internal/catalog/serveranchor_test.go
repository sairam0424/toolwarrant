package catalog

import (
	"errors"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The seventh hostile review's probe against the server views (D17 c). Server
// and Servers ran no file check and anchored nothing, so one UPDATE on the
// servers table was returned as fact by a long-lived Store and by a fresh one,
// emit wrote the forged processor address into the gateway configuration with
// no change line, and the crawl loop followed the rewritten URL with private
// addresses allowed, while every serving-path read, VerifyAudit and every
// fresh open were clean. Both views now run checkFile and anchor the three
// columns to the verified server.added and server.processor_set entries.

// anchoredServers builds alpha (with an approved tool and a processor address)
// and beta (without one) and returns the Store and its path.
func anchoredServers(t *testing.T) (*Store, string) {
	t.Helper()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	mustAddServer(t, s, "beta")
	if err := s.SetProcessorAddr(bg, "alpha", "127.0.0.1:9001", alice); err != nil {
		t.Fatal(err)
	}
	mustBeClean(t, s, "after the setup")
	return s, path
}

// Each column a forger can rewrite is compared with the verified entry that
// recorded it, on the long-lived Store and on a fresh one; the serving path,
// which does not read these columns, keeps working, and VerifyAudit keeps the
// recorded head, so Integrity is no longer the only control that sees it. The
// URL is never printed.
func TestServers_ColumnsAreAnchoredToTheVerifiedChain(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		update string
		server string
		want   []string
	}{
		"processor_addr rewritten": {`UPDATE servers SET processor_addr = '127.0.0.1:9999' WHERE name = 'alpha'`, "alpha",
			[]string{"processor_addr of server", `"127.0.0.1:9999"`, "server.processor_set entry (seq", `recorded "127.0.0.1:9001"`}},
		"processor_addr emptied": {`UPDATE servers SET processor_addr = '' WHERE name = 'alpha'`, "alpha",
			[]string{"processor_addr of server", `recorded "127.0.0.1:9001"`}},
		"processor_addr set where the log has none": {`UPDATE servers SET processor_addr = '127.0.0.1:9999' WHERE name = 'beta'`, "beta",
			[]string{`"beta"`, "no server.processor_set entry"}},
		"url rewritten": {`UPDATE servers SET url = 'https://attacker.example.net/mcp?token=SECRET' WHERE name = 'alpha'`, "alpha",
			[]string{"the URL of server", "server.added entry (seq", "its hash differs"}},
		"allow_private flipped": {`UPDATE servers SET allow_private = 1 WHERE name = 'alpha'`, "alpha",
			[]string{"allow_private of server", "is true", "recorded false"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s, path := anchoredServers(t)
			recorded, err := s.VerifyAudit(bg)
			if err != nil {
				t.Fatal(err)
			}
			db := rawDB(t, path)
			mustExec(t, db, tc.update)
			mustExec(t, db, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)

			_, err = s.Server(bg, tc.server)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Server after the edit = %v, want ErrCorrupt", err)
			}
			for _, fragment := range tc.want {
				if !strings.Contains(err.Error(), fragment) {
					t.Errorf("Server error %q does not mention %q", err, fragment)
				}
			}
			if strings.Contains(err.Error(), "attacker") || strings.Contains(err.Error(), "SECRET") {
				t.Errorf("the error prints the rewritten URL: %q", err)
			}
			if _, err := s.Servers(bg); !errors.Is(err, ErrCorrupt) {
				t.Errorf("Servers after the edit = %v, want ErrCorrupt", err)
			}
			for label, opts := range map[string]OpenOptions{"read-only": {ReadOnly: true}, "read-write": {Policy: lifecycle.DefaultPolicy()}} {
				fresh, err := OpenWith(path, opts)
				if err != nil {
					t.Fatalf("%s Open = %v", label, err)
				}
				if _, err := fresh.Server(bg, tc.server); !errors.Is(err, ErrCorrupt) {
					t.Errorf("%s fresh Server = %v, want ErrCorrupt", label, err)
				}
				_ = fresh.Close()
			}
			if snap := mustSnapshot(t, s, "alpha"); !snap.Serves("echo", digestOf(t, "echo", "v1")) {
				t.Errorf("Snapshot, which reads none of these columns, = %+v", snap.Tools["echo"])
			}
			if after, err := s.VerifyAudit(bg); err != nil || after.Head != recorded.Head {
				t.Errorf("VerifyAudit = %+v, %v; the log was not touched", after, err)
			}
			if rep := mustIntegrity(t, s); rep.ServersMismatched != 1 {
				t.Errorf("Integrity.ServersMismatched = %d, want 1; %q", rep.ServersMismatched, rep.Problems)
			}
		})
	}
}

// SetProcessorAddr compares the address it is asked to record with the row as
// the chain backs it, not with the column: a column rewritten to the address
// emit is about to assign is ErrCorrupt, not a quiet no-op without an entry.
func TestSetProcessorAddr_ForgedColumnEqualToTheNewAddressIsCorrupt(t *testing.T) {
	t.Parallel()
	s, path := anchoredServers(t)
	db := rawDB(t, path)
	mustExec(t, db, `UPDATE servers SET processor_addr = '127.0.0.1:9999' WHERE name = 'alpha'`)
	err := s.SetProcessorAddr(bg, "alpha", "127.0.0.1:9999", alice)
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "processor_addr of server") {
		t.Fatalf("SetProcessorAddr to the forged address = %v, want ErrCorrupt naming the column", err)
	}
	if n := countEvents(t, s, evServerProcessorSet); n != 1 {
		t.Errorf("%d server.processor_set entries, want the one the setup wrote", n)
	}
	mustExec(t, db, `UPDATE servers SET processor_addr = '127.0.0.1:9001' WHERE name = 'alpha'`)
	if err := s.SetProcessorAddr(bg, "alpha", "127.0.0.1:9002", alice); err != nil {
		t.Fatalf("SetProcessorAddr once the column is restored = %v", err)
	}
	if srv, err := s.Server(bg, "alpha"); err != nil || srv.ProcessorAddr != "127.0.0.1:9002" {
		t.Errorf("Server = %+v, %v", srv, err)
	}
	mustBeClean(t, s, "after the restore")
}

// Server and Servers run the file check every other view runs: another
// catalog identity in meta is ErrReplaced and a dropped guard is ErrCorrupt,
// where both views used to answer.
func TestServers_RunTheFileCheckLikeEveryOtherView(t *testing.T) {
	t.Parallel()
	s, path := anchoredServers(t)
	db := rawDB(t, path)
	mustExec(t, db, `UPDATE meta SET value = 'ffffffffffffffffffffffffffffffff' WHERE key = 'identity'`)
	if _, err := s.Server(bg, "alpha"); !errors.Is(err, ErrReplaced) {
		t.Errorf("Server with another identity = %v, want ErrReplaced", err)
	}
	if _, err := s.Servers(bg); !errors.Is(err, ErrReplaced) {
		t.Errorf("Servers with another identity = %v, want ErrReplaced", err)
	}
	mustExec(t, db, `UPDATE meta SET value = ? WHERE key = 'identity'`, s.identity)
	mustExec(t, db, `DROP TRIGGER tools_no_delete`)
	if _, err := s.Server(bg, "alpha"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Server with a guard dropped = %v, want ErrCorrupt", err)
	}
	if _, err := s.Servers(bg); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Servers with a guard dropped = %v, want ErrCorrupt", err)
	}
	restoreGuard(t, db, "tools_no_delete")
	servers, err := s.Servers(bg)
	if err != nil || len(servers) != 2 || servers[0].ProcessorAddr != "127.0.0.1:9001" || servers[1].ProcessorAddr != "" {
		t.Errorf("Servers once the file is whole again = %+v, %v", servers, err)
	}
}

// The URL and policy of a server are anchored to the FIRST server.added entry
// about it, so appending a sealed second one (the access D14 admits) and
// rewriting the row to match does not pass: the row still disagrees with the
// first entry, and Integrity names the second (eighth review).
func TestServers_ASecondServerAddedEntryIsNotTheAnchor(t *testing.T) {
	t.Parallel()
	s, path := anchoredServers(t)
	recorded, err := s.VerifyAudit(bg)
	if err != nil {
		t.Fatal(err)
	}
	db := rawDB(t, path)
	forged := ServerSpec{Name: "alpha", URL: "https://attacker.example.net/mcp", AllowPrivate: true}
	appendSealed(t, db, audit.Entry{TS: forgedTS, Actor: "mallory", ActorType: string(ActorHuman), Event: evServerAdded,
		Subject: "alpha", Detail: serverAddedDetail(forged)})
	mustExec(t, db, `UPDATE servers SET url = ?, allow_private = 1 WHERE name = 'alpha'`, forged.URL)
	mustExec(t, db, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)

	_, err = s.Server(bg, "alpha")
	requireCorruptMentioning(t, "Server", err, []string{"allow_private of server", `"alpha"`, "server.added entry (seq 1)"})
	if strings.Contains(err.Error(), "attacker") {
		t.Errorf("the error prints the rewritten URL: %q", err)
	}
	if _, err := s.Servers(bg); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Servers = %v, want ErrCorrupt", err)
	}
	if after, err := s.VerifyAudit(bg); err != nil || after.Entries != recorded.Entries+1 {
		t.Errorf("VerifyAudit = %+v, %v; the sealed append extends the chain by one", after, err)
	}
	rep := mustIntegrity(t, s)
	problemMentioning(t, rep, "second server.added about server")
}
