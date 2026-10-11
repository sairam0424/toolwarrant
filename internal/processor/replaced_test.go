package processor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// replacedLine is the start of the Error line distrust writes once per episode.
const replacedLine = "catalog file replaced or corrupt"

// D14(e), from the fourth review (core-1, processor-emit-1): a Store holds the
// catalog by its open descriptor, so after the operator deleted the file and
// ran init under a running processor, Generation kept returning the deleted
// file's number, nothing reloaded, and every approval of the deleted catalog
// stayed listed and callable with SourceErrors at zero. The Store now reports
// catalog.ErrReplaced (an ErrCorrupt) from Generation; the processor logs the
// condition once per episode, denies every hook as a source error, and does
// not reuse the cached snapshot even when a later Generation call returns the
// number it was cached under, because a fresh file numbers its generations
// from the start. A transient error that is not ErrCorrupt still reuses the
// cache (TestCache_NeverFallsBackToAStaleSnapshot).
func TestCache_CorruptGenerationDiscardsTheCacheUntilASnapshotReloads(t *testing.T) {
	echo1, wipe1 := tool("echo", "e1"), tool("wipe", "wipes the database")
	src := newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(mustDigest(t, echo1))})
	s, logs := newTestServer(src)
	servedNames(t, list(t, s, listBody("", echo1)))
	requireAllowed(t, call(t, s, callReq("echo")))
	_, loadsBefore := src.calls()

	replaced := fmt.Errorf("%w: toolwarrant.db is another file than the one this store opened", catalog.ErrReplaced)
	src.failGeneration(replaced)
	for i := 0; i < 3; i++ {
		requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeUnavailable)
		e := requireListDenied(t, list(t, s, listBody("", echo1)), api.AuthorizationError_PERMISSION_DENIED)
		if e.GetReason() != reasonListUnavailable {
			t.Errorf("reason = %q", e.GetReason())
		}
	}
	if n := strings.Count(logs.String(), replacedLine); n != 1 {
		t.Errorf("the replaced-file line appeared %d times over six hooks, want once:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), `level=ERROR msg="`+replacedLine) {
		t.Errorf("the replaced-file line should be at Error:\n%s", logs.String())
	}
	if st := s.Stats(); st.SourceErrors != 6 || st.CallsDenied != 3 || st.ListsDenied != 3 {
		t.Errorf("stats = %+v, want six source errors", st)
	}

	// The file at the path is now a fresh catalog at the same generation
	// number that approves wipe and knows nothing of echo. The cached snapshot
	// must not be reused: before this round it was, and echo stayed callable.
	src.replace(map[string]catalog.ToolPolicy{"wipe": servedPolicy(mustDigest(t, wipe1))})
	src.failGeneration(nil)
	requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeNotApproved)
	if _, loads := src.calls(); loads != loadsBefore+1 {
		t.Errorf("snapshot loads = %d, want %d: the distrusted cache must be reloaded once", loads, loadsBefore+1)
	}
	if got := servedNames(t, list(t, s, listBody("", echo1, wipe1))); !reflect.DeepEqual(got, []string{"wipe"}) {
		t.Errorf("served %v after the reload, want [wipe]", got)
	}
	requireAllowed(t, call(t, s, callReq("wipe")))

	// A second episode is reported again.
	src.failGeneration(replaced)
	requireCallDenied(t, call(t, s, callReq("wipe")), "wipe", causeUnavailable)
	if n := strings.Count(logs.String(), replacedLine); n != 2 {
		t.Errorf("the replaced-file line appeared %d times after a second episode, want twice", n)
	}
}

// The same through the real catalog, as the fourth review reproduced it: a
// processor reading a Store opened read-only, as serve does, keeps answering
// from the deleted file unless the Store notices. With D14(e) the Store reports
// ErrReplaced on the first Generation call after the file was deleted and
// re-initialised, and the processor denies both hooks with the Error line and
// the counter an operator can see.
func TestCheckResponse_ReplacedCatalogFileDeniesEveryHook(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "toolwarrant.db")
	pol := lifecycle.DefaultPolicy()
	human := catalog.Actor{Name: "bob", Type: catalog.ActorHuman}
	system := catalog.Actor{Name: "crawler", Type: catalog.ActorSystem}
	echo := tool("echo", "Echoes.")

	writer, err := catalog.Open(path, pol)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.AddServer(ctx, catalog.ServerSpec{Name: testServer, URL: "https://mock.example.com/mcp", OwnerGroup: "platform"}, human); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.RecordCrawl(ctx, catalog.CrawlInput{Server: testServer, Complete: true, Tools: []catalog.CrawledTool{{Name: "echo", Raw: echo}}}, system); err != nil {
		t.Fatal(err)
	}
	if err := writer.Approve(ctx, testServer, "echo", mustDigest(t, echo), human); err != nil {
		t.Fatal(err)
	}
	reader, err := catalog.OpenWith(path, catalog.OpenOptions{Policy: pol, ReadOnly: true, MustExist: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	s, logs := newTestServer(reader)
	if got := servedNames(t, list(t, s, listBody("", echo))); !reflect.DeepEqual(got, []string{"echo"}) {
		t.Fatalf("served %v before the re-init, want [echo]", got)
	}
	requireAllowed(t, call(t, s, callReq("echo")))

	// The documented recovery: delete the file and run init. The new catalog
	// knows no server and approves nothing.
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	fresh, err := catalog.Open(path, pol)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fresh.Close() }()
	if _, err := fresh.Snapshot(ctx, testServer); err == nil {
		t.Fatal("test setup: the fresh catalog still knows the server")
	}

	e := requireListDenied(t, list(t, s, listBody("", echo)), api.AuthorizationError_PERMISSION_DENIED)
	if e.GetReason() != reasonListUnavailable {
		t.Errorf("reason = %q", e.GetReason())
	}
	requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeUnavailable)
	if st := s.Stats(); st.SourceErrors != 2 || st.CallsAllowed != 1 || st.ListsServed != 1 {
		t.Errorf("stats = %+v, want two source errors after the re-init", st)
	}
	out := logs.String()
	if strings.Count(out, replacedLine) != 1 || !strings.Contains(out, "another file") {
		t.Errorf("the replaced-file line should appear once and carry the store's reason:\n%s", out)
	}
}
