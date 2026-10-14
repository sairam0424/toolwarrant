package processor

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
)

const (
	// smallPageJunk and bigPageJunk size the junk tool of the two pages the
	// acceptance test sends: one to time the machine, one over gRPC's default.
	smallPageJunk = 256 << 10
	bigPageJunk   = 6 << 20
	// sizeTestSlack multiplies the linear extrapolation from the small page to
	// the big one, so load that grows tenfold between the two still fits.
	sizeTestSlack = 10
)

// D6: the transport and the hook agree on "too big". A page the hook would
// refuse is refused by gRPC before it is read, and gRPC's 4 MiB default, which
// would turn a large catalog page into a transport error, is raised to the cap.
func TestServe_RecvLimitIsThePayloadCap(t *testing.T) {
	if maxRecvMsgSize != maxPayloadBytes {
		t.Fatalf("gRPC accepts %d bytes but the hook accepts %d; the two layers must agree", maxRecvMsgSize, maxPayloadBytes)
	}
	if maxRecvMsgSize != 8<<20 {
		t.Fatalf("recv limit = %d, want 8 MiB", maxRecvMsgSize)
	}
}

// A page over the cap is refused from its length header, before the body is
// read, so this holds whatever the machine does: the gateway sees a failed hook
// (fail closed), never a passed one, and CheckResponse never runs. The status
// names the exact limit, which pins that the server was built with
// maxRecvMsgSize. Since D15 the refusal is still the processor's business: it
// is counted as a denied tools/list, logged with the transport's error, and
// every catalog tool of the snapshot is marked, so the page the processor could
// not read leaves the same trace as one CheckResponse refused itself.
func TestServe_RefusesAPageOverTheRecvLimit(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	s, logs := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}))
	client, _ := startServer(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), serveStopTimeout)
	defer cancel()

	over := make([]byte, 9<<20) // never parsed, so the content does not matter
	_, err := client.CheckResponse(ctx, listMsg(over))
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("9 MiB page: err = %v, want ResourceExhausted", err)
	}
	if msg := status.Convert(err).Message(); !strings.Contains(msg, strconv.Itoa(maxRecvMsgSize)) {
		t.Errorf("the refusal should name the %d byte limit: %q", maxRecvMsgSize, msg)
	}
	// The server stream writes the status to the client before it returns the
	// error to the decoder (serve.go, serviceDesc), so the marking lands a
	// moment after the client has its error; wait for it rather than read the
	// statistics inside that moment.
	awaitMarking(t, func() bool { return s.Stats().ListsDenied == 1 })
	if st := s.Stats(); st.ListsServed != 0 || st.ListsDenied != 1 || st.SourceErrors != 0 {
		t.Errorf("stats = %+v, want the refused page counted as one denied list", st)
	}
	if seen, _, ok := s.observedDigest("echo"); !ok || seen != observedConflict {
		t.Errorf("evidence for echo after the refused page = %q, %v; want the conflict marker", seen, ok)
	}
	if !strings.Contains(logs.String(), "tools/list denied") || !strings.Contains(logs.String(), "ResourceExhausted") {
		t.Errorf("the refusal should be logged as a denied list with the transport's error:\n%s", logs.String())
	}
}

// D15 (f), from the fifth review (core-2, processor-emit-1): D14 (g) marked
// every servable tool before an oversized page was denied, but only when
// CheckResponse was called in process. Over the wire the transport refused the
// message first and nothing was marked, so the digest of the last clean
// listing kept tools/call passing for a tool the upstream had since changed,
// which is the fourth review's decoy case one layer down. The refusal is now
// observed on the CheckResponse decoder: a payload of exactly the cap (the
// smallest the transport refuses, since the message carries the method and
// the service name on top of it) and a page one byte over it both mark every
// catalog tool before the status is written, the call is denied as changed,
// and a clean listing restores it. A tools/call request over the cap is
// refused by the transport as well and marks nothing: the watch is on
// CheckResponse only.
func TestServe_OversizedPageOverTheWireMarksEveryCatalogTool(t *testing.T) {
	echo1 := tool("echo", "e1")
	d1 := mustDigest(t, echo1)
	s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}))
	client, _ := startServer(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), serveStopTimeout)
	defer cancel()

	cleanListing := func() {
		t.Helper()
		res, err := client.CheckResponse(ctx, listMsg(listBody("", echo1)))
		if err != nil {
			t.Fatal(err)
		}
		if got := servedNames(t, res); !reflect.DeepEqual(got, []string{"echo"}) {
			t.Fatalf("served %v, want [echo]", got)
		}
		res2, err := client.CheckRequest(ctx, callReq("echo"))
		if err != nil {
			t.Fatal(err)
		}
		requireAllowed(t, res2)
	}
	// denied is the ListsDenied count the refusal brings the server to; the
	// transport writes the status to the client before pageRefused marks the
	// tools and counts the denial (serve.go, serviceDesc), so the test waits
	// for the count, which is written after the marking, before it reads the
	// evidence (the eighth review's ci run read it inside that moment).
	refused := func(page []byte, denied uint64) {
		t.Helper()
		if _, err := client.CheckResponse(ctx, listMsg(page)); status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("a payload of %d bytes: err = %v, want ResourceExhausted from the transport", len(page), err)
		}
		awaitMarking(t, func() bool { return s.Stats().ListsDenied == denied })
		if seen, _, ok := s.observedDigest("echo"); !ok || seen != observedConflict {
			t.Fatalf("evidence for echo after the refused page = %q, %v; want the conflict marker", seen, ok)
		}
		res, err := client.CheckRequest(ctx, callReq("echo"))
		if err != nil {
			t.Fatal(err)
		}
		requireCallDenied(t, res, "echo", causeChanged)
	}

	cleanListing()
	refused(make([]byte, maxPayloadBytes), 1)
	cleanListing()
	refused(oversizedPage(), 2)
	cleanListing()
	if st := s.Stats(); st.ListsDenied != 2 || st.ListsServed != 3 || st.SourceErrors != 0 {
		t.Errorf("stats = %+v, want two refused pages counted as denied lists", st)
	}

	// The same size on the request hook is the transport's business alone.
	_, err := client.CheckRequest(ctx, rawCallReq(string(make([]byte, 9<<20))))
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("9 MiB tools/call: err = %v, want ResourceExhausted", err)
	}
	if seen, _, ok := s.observedDigest("echo"); !ok || seen != d1 {
		t.Errorf("a refused tools/call marked echo: %q, %v", seen, ok)
	}
	if st := s.Stats(); st.ListsDenied != 2 {
		t.Errorf("stats = %+v, want no list denial for a refused request", st)
	}
}

// A refusal while the catalog is unreadable is a source error like any other
// hook, as for an oversized page CheckResponse reads itself (D14): counted,
// and nothing marked because there is no snapshot to mark against.
func TestServe_RefusedPageWithAnUnreadableCatalogIsASourceError(t *testing.T) {
	src := newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(mustDigest(t, echoV1))})
	src.failGeneration(context.DeadlineExceeded)
	s, _ := newTestServer(src)
	client, _ := startServer(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), serveStopTimeout)
	defer cancel()

	if _, err := client.CheckResponse(ctx, listMsg(oversizedPage())); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("err = %v, want ResourceExhausted", err)
	}
	if st := s.Stats(); st.SourceErrors != 1 || st.ListsDenied != 1 || s.trackedCount() != 0 {
		t.Errorf("stats = %+v, tracked %d; want one source error, one denied list, nothing tracked", st, s.trackedCount())
	}
}

// A 6 MiB page is over gRPC's 4 MiB default and under the cap, so it is
// accepted and filtered. Moving it through gRPC and parsing it twice under the
// race detector takes seconds that scale with the machine, so the deadline is
// not a constant: a page of the same shape at a fraction of the size is timed
// first and the big page gets the linear extrapolation times sizeTestSlack,
// never less than serveStopTimeout.
func TestServe_AcceptsAPageOverGRPCsDefaultLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("moves a 6 MiB page through gRPC; skipped in short mode")
	}
	d1 := mustDigest(t, echoV1)
	s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}))
	client, _ := startServer(t, s)

	elapsed := timePage(t, client, serveStopTimeout, smallPageJunk)
	budget := max(serveStopTimeout, time.Duration(bigPageJunk/smallPageJunk)*elapsed*sizeTestSlack)
	t.Logf("a %d KiB page took %v; the 6 MiB page gets %v", smallPageJunk>>10, elapsed, budget)
	timePage(t, client, budget, bigPageJunk)
	if st := s.Stats(); st.ListsServed != 2 || st.ToolsHidden != 2 {
		t.Errorf("stats = %+v, want 2 pages served and the junk tool hidden on each", st)
	}
}

// timePage sends a page of one junk tool of n bytes plus the approved echo and
// returns how long the round trip took. The junk tool is not in the catalog, so
// it is hidden unhashed and the page shrinks to echo: what is timed is the
// transport and the parsing, the same work at both sizes.
func timePage(t *testing.T, client api.ExtMcpClient, deadline time.Duration, n int) time.Duration {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	junk := tool("junk", strings.Repeat("x", n))
	start := time.Now()
	res, err := client.CheckResponse(ctx, listMsg(listBody("", junk, echoV1)))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("a %d byte page must be accepted (deadline %v): %v", n, deadline, err)
	}
	if got := servedNames(t, res); len(got) != 1 || got[0] != "echo" {
		t.Fatalf("served %v, want [echo]", got)
	}
	return elapsed
}

// awaitMarking polls until ready returns true or two seconds pass; the test
// then asserts the state it waited for, so a marking that never lands fails
// with the usual messages.
func awaitMarking(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !ready() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
}
