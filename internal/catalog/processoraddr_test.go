package catalog

import (
	"errors"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The processor address lives in the catalog (D14 i): emit records what it
// assigned, one audit entry per change, and a re-emit reads it back from here
// and never from the file at --out.
func TestSetProcessorAddr_RecordsTheAddressAndTheEntry(t *testing.T) {
	t.Parallel()
	s, _ := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	mustAddServer(t, s, "beta")
	if srv, err := s.Server(bg, "alpha"); err != nil || srv.ProcessorAddr != "" {
		t.Fatalf("Server before any emit = %+v, %v; want an empty address", srv, err)
	}
	if err := s.SetProcessorAddr(bg, "alpha", "127.0.0.1:4444", alice); err != nil {
		t.Fatal(err)
	}
	if err := s.SetProcessorAddr(bg, "beta", "[::1]:4445", crawler); err != nil {
		t.Fatalf("a system actor must be able to record an address (an unattended re-emit): %v", err)
	}
	srv, err := s.Server(bg, "alpha")
	if err != nil || srv.ProcessorAddr != "127.0.0.1:4444" {
		t.Errorf("Server after the set = %+v, %v", srv, err)
	}
	servers, err := s.Servers(bg)
	if err != nil || len(servers) != 2 || servers[0].ProcessorAddr != "127.0.0.1:4444" || servers[1].ProcessorAddr != "[::1]:4445" {
		t.Errorf("Servers = %+v, %v", servers, err)
	}
	e := entryOf(t, s, evServerProcessorSet)
	if e.Subject != "beta" || e.Actor != "crawler" || e.ActorType != string(ActorSystem) || e.Detail != "processor_addr=[::1]:4445" {
		t.Errorf("server.processor_set entry = %+v", e)
	}
	if n := countEvents(t, s, evServerProcessorSet); n != 2 {
		t.Errorf("server.processor_set entries = %d, want 2", n)
	}
	mustBeClean(t, s, "after two sets")

	// The same address again is a quiet no-op: no entry, no generation bump.
	before := takeTrace(t, s)
	if err := s.SetProcessorAddr(bg, "alpha", "127.0.0.1:4444", bob); err != nil {
		t.Fatal(err)
	}
	before.mustEqual(t, s, "setting the recorded address again")
	if err := s.SetProcessorAddr(bg, "alpha", "127.0.0.1:4446", bob); err != nil {
		t.Fatal(err)
	}
	if n := countEvents(t, s, evServerProcessorSet); n != 3 {
		t.Errorf("server.processor_set entries after a change = %d, want 3", n)
	}
	if srv, _ := s.Server(bg, "alpha"); srv.ProcessorAddr != "127.0.0.1:4446" {
		t.Errorf("address after the change = %q", srv.ProcessorAddr)
	}
	mustBeClean(t, s, "after the change")

	if err := s.SetProcessorAddr(bg, "gamma", "127.0.0.1:4447", alice); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown server = %v, want ErrNotFound", err)
	}
	if err := s.SetProcessorAddr(bg, "alpha", "127.0.0.1:4447", Actor{Name: "", Type: ActorHuman}); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty actor = %v, want ErrInvalid", err)
	}
	for _, bad := range []string{"", "127.0.0.1", "127.0.0.1:", ":4444", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:44 44",
		"host:4444\n", "[::1]", "http://127.0.0.1:4444", "127.0.0.1:4444/x", "127.0.0.1:4444;", "\u0661\u0662\u0663:4444"} {
		if err := s.SetProcessorAddr(bg, "alpha", bad, alice); !errors.Is(err, ErrInvalid) {
			t.Errorf("SetProcessorAddr(%q) = %v, want ErrInvalid", bad, err)
		}
	}
	for _, ok := range []string{"proc.internal:65535", "[fe80::1]:1", "10.0.0.7:4444"} {
		if err := validateProcessorAddr(ok); err != nil {
			t.Errorf("validateProcessorAddr(%q) = %v, want nil", ok, err)
		}
	}
	before = takeTrace(t, s)
	before.mustEqual(t, s, "the refused calls")
}

// Integrity compares the column with the newest server.processor_set entry: a
// rewritten address, and an address on a server the log never gave one, are
// both reported, and a pause or resume does not disturb the comparison.
func TestIntegrity_ProcessorAddrRewrittenIsReported(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	mustAddServer(t, s, "beta")
	if err := s.SetProcessorAddr(bg, "alpha", "127.0.0.1:4444", alice); err != nil {
		t.Fatal(err)
	}
	if err := s.PauseServer(bg, "alpha", alice); err != nil {
		t.Fatal(err)
	}
	mustBeClean(t, s, "after the set and the pause")
	db := rawDB(t, path)
	mustExec(t, db, `UPDATE servers SET processor_addr = '127.0.0.1:9' WHERE name = 'alpha'`)
	rep := mustIntegrity(t, s)
	if rep.ServersMismatched != 1 {
		t.Errorf("Integrity after the rewrite = %+v, want alpha mismatched", rep)
	}
	problemMentioning(t, rep, `"alpha"`, `processor_addr is "127.0.0.1:9"`, "server.processor_set entry (seq", `recorded "127.0.0.1:4444"`)
	mustExec(t, db, `UPDATE servers SET processor_addr = '127.0.0.1:4444' WHERE name = 'alpha'`)
	mustExec(t, db, `UPDATE servers SET processor_addr = '127.0.0.1:5' WHERE name = 'beta'`)
	rep = mustIntegrity(t, s)
	if rep.ServersMismatched != 1 {
		t.Errorf("Integrity with an address the log never gave = %+v, want beta mismatched", rep)
	}
	problemMentioning(t, rep, `"beta"`, `processor_addr is "127.0.0.1:5"`, "no server.processor_set entry")
	mustExec(t, db, `UPDATE servers SET processor_addr = '' WHERE name = 'beta'`)
	mustBeClean(t, s, "after restoring the columns")
}
