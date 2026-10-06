package catalog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

func TestRecordCrawl_StoresVersionsImmutablyWithCatalogComputedDigests(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	raws := [][]byte{
		[]byte(`{ "description": "first", "name": "echo" ,"x":1.50 }`),
		def("echo", "second"),
		def("echo", "third"),
	}
	for _, raw := range raws {
		mustCrawl(t, s, "alpha", CrawledTool{Name: "echo", Raw: raw})
	}
	vs, err := s.Versions(bg, "alpha", "echo")
	if err != nil || len(vs) != 3 {
		t.Fatalf("Versions = %+v, %v", vs, err)
	}
	db := rawDB(t, path)
	for i, v := range vs {
		wantCanon, err := gate.CanonicalTool(raws[i])
		if err != nil {
			t.Fatal(err)
		}
		if v.No != i+1 || v.Digest != gate.DigestOfCanonical(wantCanon) || !bytes.Equal(v.Canonical, wantCanon) ||
			v.ProposedBy != "crawler" || v.EverApproved || v.FirstSeen.IsZero() {
			t.Errorf("version %d = %+v", i+1, v)
		}
		wantStatus := lifecycle.VersionSuperseded
		if i == 2 {
			wantStatus = lifecycle.VersionPending
		}
		if v.Status != wantStatus {
			t.Errorf("version %d status = %s, want %s", i+1, v.Status, wantStatus)
		}
		var stored []byte
		if err := db.QueryRowContext(bg, `SELECT raw FROM tool_versions WHERE digest = ?`, v.Digest).Scan(&stored); err != nil || !bytes.Equal(stored, raws[i]) {
			t.Errorf("raw of version %d not stored byte for byte: %q %v", i+1, stored, err)
		}
	}
	// The canonical bytes returned to a caller are a copy: scribbling on them changes nothing.
	vs[0].Canonical[0] = 'X'
	again, _ := s.Versions(bg, "alpha", "echo")
	if again[0].Canonical[0] == 'X' {
		t.Error("Versions returned shared memory")
	}
}

func TestRecordCrawl_PreviouslySeenAndRejectedDigests(t *testing.T) {
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	dA, dB := digestOf(t, "echo", "A"), digestOf(t, "echo", "B")

	mustCrawl(t, s, "alpha", tool("echo", "A"))
	mustCrawl(t, s, "alpha", tool("echo", "B"))
	rep := mustCrawl(t, s, "alpha", tool("echo", "A")) // back to a superseded digest: proposed again, not duplicated
	if k := kindsOf(rep)["echo"]; k != ChangeChanged {
		t.Fatalf("kind = %s", k)
	}
	if v := mustTool(t, s, "alpha", "echo"); v.Versions != 2 || v.Pending != dA {
		t.Fatalf("tool = %+v", v)
	}

	if err := s.Reject(bg, "alpha", "echo", dA, bob); err != nil {
		t.Fatal(err)
	}
	if k := kindsOf(mustCrawl(t, s, "alpha", tool("echo", "A")))["echo"]; k != ChangeUnchanged {
		t.Errorf("a rejected digest seen again: kind %s, want unchanged", k)
	}
	if k := kindsOf(mustCrawl(t, s, "alpha", tool("echo", "B")))["echo"]; k != ChangeChanged {
		t.Errorf("a different digest after a rejection: kind %s, want changed", k)
	}
	if v := mustTool(t, s, "alpha", "echo"); v.Pending != dB {
		t.Errorf("pending = %s, want %s", v.Pending, dB)
	}
}

func TestRecordCrawl_UnknownServer(t *testing.T) {
	s := newStore(t)
	gen := mustGeneration(t, s)
	for _, name := range []string{"ghost", "", "Alpha'; --"} {
		if _, err := s.RecordCrawl(bg, CrawlInput{Server: name, Complete: true}, crawler); !errors.Is(err, ErrNotFound) {
			t.Errorf("RecordCrawl(%q) = %v, want ErrNotFound", name, err)
		}
	}
	if mustGeneration(t, s) != gen {
		t.Error("a crawl of an unknown server wrote something")
	}
}

func TestRecordCrawl_ManyToolsInOneTransaction(t *testing.T) {
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	const n = 400
	first := make([]CrawledTool, n)
	for i := range first {
		name := fmt.Sprintf("tool-%04d", i)
		first[i] = CrawledTool{Name: name, Raw: def(name, "v1")}
	}
	gen := mustGeneration(t, s)
	rep := mustCrawl(t, s, "alpha", first...)
	if len(rep.Changes) != n || mustGeneration(t, s) != gen+1 {
		t.Fatalf("changes = %d, generation moved by %d", len(rep.Changes), mustGeneration(t, s)-gen)
	}
	for i := 1; i < len(rep.Changes); i++ {
		if rep.Changes[i-1].Tool >= rep.Changes[i].Tool {
			t.Fatalf("changes not sorted at %d: %q >= %q", i, rep.Changes[i-1].Tool, rep.Changes[i].Tool)
		}
	}
	if _, err := s.VerifyAudit(bg); err != nil {
		t.Fatal(err)
	}
}

func TestRecordCrawl_StampsUTCNanosecondTimes(t *testing.T) {
	s := newStore(t)
	fixed := time.Date(2030, 1, 2, 3, 4, 5, 678901234, time.FixedZone("x", 3600))
	s.now = func() time.Time { return fixed }
	srv := mustAddServer(t, s, "alpha")
	if !srv.CreatedAt.Equal(fixed) || srv.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt = %v (%v)", srv.CreatedAt, srv.CreatedAt.Location())
	}
	entries, _ := s.AuditEntries(bg, 0, 0)
	if entries[0].TS != "2030-01-02T02:04:05.678901234Z" {
		t.Errorf("audit ts = %q", entries[0].TS)
	}
}

func TestClassify(t *testing.T) {
	ev := func(kinds ...lifecycle.EventKind) []lifecycle.Event {
		out := make([]lifecycle.Event, len(kinds))
		for i, k := range kinds {
			out[i] = lifecycle.Event{Kind: k}
		}
		return out
	}
	for name, tc := range map[string]struct {
		events []lifecycle.Event
		want   ChangeKind
	}{
		"none":                 {nil, ChangeUnchanged},
		"new":                  {ev(lifecycle.EvDiscovered, lifecycle.EvProposed), ChangeNew},
		"changed":              {ev(lifecycle.EvSuperseded, lifecycle.EvProposed, lifecycle.EvDrifted), ChangeChanged},
		"proposed only":        {ev(lifecycle.EvProposed), ChangeChanged},
		"reverted":             {ev(lifecycle.EvSuperseded, lifecycle.EvReverted), ChangeReverted},
		"missing":              {ev(lifecycle.EvMissing), ChangeMissing},
		"deprecated":           {ev(lifecycle.EvDeprecated), ChangeDeprecated},
		"reappeared beats new": {ev(lifecycle.EvReappeared, lifecycle.EvSuperseded, lifecycle.EvProposed), ChangeReappeared},
	} {
		if got := classify(tc.events); got != tc.want {
			t.Errorf("%s: classify = %s, want %s", name, got, tc.want)
		}
	}
	if err := crawlMustNotDecide(ev(lifecycle.EvProposed, lifecycle.EvApproved)); err == nil {
		t.Error("a crawl that produces an approval must be refused")
	}
	for _, k := range []lifecycle.EventKind{lifecycle.EvRejected, lifecycle.EvRolledBack} {
		if err := crawlMustNotDecide(ev(k)); err == nil {
			t.Errorf("a crawl that produces %s must be refused", k)
		}
	}
	if err := crawlMustNotDecide(ev(lifecycle.EvProposed, lifecycle.EvMissing)); err != nil {
		t.Errorf("ordinary crawl events refused: %v", err)
	}
}

// The lifecycle is a separate package. If it ever returns something the store
// cannot persist faithfully, the store must fail the transaction, not guess.
func TestSave_RefusesInconsistentLifecycleResults(t *testing.T) {
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	d1 := digestOf(t, "echo", "v1")

	try := func(name string, mutate func(rec *toolRec) (lifecycle.Tool, *preparedTool)) {
		t.Helper()
		err := s.inTx(bg, func(tx *txn) error {
			rec, err := loadTool(bg, tx, "alpha", "echo")
			if err != nil {
				return err
			}
			after, mat := mutate(rec)
			return rec.save(bg, tx, after, mat, 1)
		})
		if err == nil || !strings.Contains(err.Error(), "internal error") {
			t.Errorf("%s: err = %v, want an internal error", name, err)
		}
	}
	try("dropped version", func(rec *toolRec) (lifecycle.Tool, *preparedTool) {
		after := rec.tool
		after.Versions = nil
		return after, nil
	})
	try("reordered digest", func(rec *toolRec) (lifecycle.Tool, *preparedTool) {
		after := rec.tool
		after.Versions = []lifecycle.Version{{Digest: strings.Repeat("a", 64), Status: lifecycle.VersionPending}}
		return after, nil
	})
	try("new version without a definition", func(rec *toolRec) (lifecycle.Tool, *preparedTool) {
		after := rec.tool
		after.Versions = append(append([]lifecycle.Version(nil), rec.tool.Versions...),
			lifecycle.Version{Digest: strings.Repeat("b", 64), Status: lifecycle.VersionPending})
		return after, nil
	})
	try("approved digest that is not a version", func(rec *toolRec) (lifecycle.Tool, *preparedTool) {
		after := rec.tool
		after.State, after.Approved = lifecycle.Enabled, strings.Repeat("c", 64)
		return after, nil
	})
	err := s.inTx(bg, func(tx *txn) error {
		rec, err := loadTool(bg, tx, "alpha", "echo")
		if err != nil {
			return err
		}
		if _, err := rec.versionID(strings.Repeat("d", 64)); err == nil {
			t.Error("versionID of an unknown digest succeeded")
		}
		if id, err := rec.versionID(d1); err != nil || id <= 0 {
			t.Errorf("versionID = %d, %v", id, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRecordCrawl_CancelledContext(t *testing.T) {
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, err := s.RecordCrawl(ctx, crawlOf(tool("a", "v1")), crawler); err == nil {
		t.Fatal("RecordCrawl with a cancelled context succeeded")
	}
	if list, _ := s.Tools(bg, ""); len(list) != 0 {
		t.Errorf("a cancelled crawl left tools behind: %+v", list)
	}
}

func TestRecordCrawl_DoesNotModifyItsInput(t *testing.T) {
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	in := CrawlInput{Server: "alpha", Complete: true, Error: "x", Tools: []CrawledTool{
		{Name: "b", Raw: def("b", "v1")}, {Name: "a", Raw: def("a", "v1")},
	}}
	wantRaw := [][]byte{bytes.Clone(in.Tools[0].Raw), bytes.Clone(in.Tools[1].Raw)}
	if _, err := s.RecordCrawl(bg, in, crawler); err != nil {
		t.Fatal(err)
	}
	if in.Tools[0].Name != "b" || in.Tools[1].Name != "a" {
		t.Errorf("RecordCrawl reordered the caller's tools: %v", in.Tools)
	}
	for i := range wantRaw {
		if !bytes.Equal(in.Tools[i].Raw, wantRaw[i]) {
			t.Errorf("tool %d: the caller's bytes were modified", i)
		}
	}
}
