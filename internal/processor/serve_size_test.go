package processor

import (
	"context"
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
// (fail closed), never a passed one, and the hook never runs. The status names
// the exact limit, which pins that the server was built with maxRecvMsgSize.
func TestServe_RefusesAPageOverTheRecvLimit(t *testing.T) {
	s, _ := newTestServer(newFakeSource(nil))
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
	if st := s.Stats(); st.ListsServed != 0 || st.ListsDenied != 0 {
		t.Errorf("the hook ran on a page the transport should have refused: %+v", st)
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
