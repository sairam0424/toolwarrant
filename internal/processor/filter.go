package processor

import (
	"context"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/mcpwire"
	"github.com/sairam0424/toolwarrant/internal/strictjson"
)

// hiddenReport says why the catalog tools of one page were hidden. Tools the
// catalog has never heard of are hidden too but not reported here: there is
// nothing to say about them, and a hostile upstream can send any number.
type hiddenReport struct {
	mismatched []string // approved and enabled, but the live definition differs
	unapproved int
	oversized  int
	unverified int // the live definition is the approved one, but the latest crawl could not verify it
}

// filtered is the outcome of filtering one page.
type filtered struct {
	out    []byte   // the re-encoded page
	hidden []string // every hidden name, in page order
	report hiddenReport
}

// listFilter is the state of one two-pass filtering of one tools/list page.
//
// Pass one (collect) reads only names: it counts the entries, finds names that
// repeat, notes which catalog tools the page lists and polls the hook context,
// hashing nothing. Pass two (decide) runs only when the page is clean and does
// the per-tool work in order. Deciding a tool before the whole page has been
// read is what once let a repeated name leave approved evidence behind: the
// first copy was observed and the second copy denied the page, so tools/call
// kept passing on the first copy's digest. With two passes every duplicate is
// known before any evidence is recorded, and a page that is denied for any
// reason leaves the conflict marker behind (markConflicts): on every catalog
// tool it listed when the page could be read to the end, and on every
// servable tool of the snapshot when it could not, so a decoy in any position
// cannot keep older evidence alive for a changed tool.
type listFilter struct {
	ctx        context.Context
	srv        *Server
	cur        *cachedSnapshot
	count      int            // tools seen so far in the current pass
	seen       map[string]int // name -> occurrences, pass one
	dupes      []string       // names that occur more than once, in first-seen order
	present    []string       // catalog tools the page lists, in first-seen order
	tooMany    bool           // the page lists more tools than maxToolsPerPage
	unreadable bool           // pass one stopped before the end of the tools array
	failure    error
	evicted    int // records that forgot an agreeing entry to fit
	dropped    int // records the full table lost
	report     hiddenReport
}

func newListFilter(ctx context.Context, srv *Server, cur *cachedSnapshot) *listFilter {
	return &listFilter{ctx: ctx, srv: srv, cur: cur, seen: make(map[string]int)}
}

// run performs both passes. The result is only meaningful when err is nil. A
// denied page marks catalog tools as conflicting, whatever denied it: the
// page is a fact about the upstream that the processor could not verify, and
// older evidence about those tools must not outlive it.
func (f *listFilter) run(raw []byte) (filtered, error) {
	page, err := f.filter(raw)
	if err != nil {
		f.markConflicts()
	}
	return page, err
}

// filter is the two passes; run says what happens when they fail. A mcpwire
// error from pass one means the scan stopped at an entry it could not read
// (or the document had no tools array at all), so f.present is incomplete:
// f.unreadable records that for markConflicts, whichever error is reported.
func (f *listFilter) filter(raw []byte) (filtered, error) {
	_, _, err := mcpwire.FilterToolsListRaw(raw, f.collect)
	f.unreadable = err != nil
	switch {
	case f.failure != nil:
		return filtered{}, f.failure
	case f.tooMany:
		return filtered{}, errTooManyTools
	case err != nil:
		return filtered{}, fmt.Errorf("filter tools/list: %w", err)
	case len(f.dupes) > 0:
		return filtered{}, fmt.Errorf("tool %s: %w", quoteName(f.dupes[0]), errDuplicateTool)
	}
	f.count = 0
	out, hidden, err := mcpwire.FilterToolsListRaw(raw, f.decide)
	if f.failure != nil {
		return filtered{}, f.failure
	}
	if err != nil {
		return filtered{}, fmt.Errorf("filter tools/list: %w", err)
	}
	return filtered{out: out, hidden: hidden, report: f.report}, nil
}

// tick counts one tool and, every ctxCheckInterval tools (starting with the
// first), checks that the hook is still wanted.
func (f *listFilter) tick() error {
	f.count++
	if (f.count-1)%ctxCheckInterval == 0 {
		if err := f.ctx.Err(); err != nil {
			return fmt.Errorf("verify page: %w", err)
		}
	}
	return nil
}

// collect is the pass-one callback. It keeps nothing (mcpwire's output for
// this pass is discarded) and does no per-tool work beyond one catalog lookup
// and counting names. Past the per-page cap the page is denied already, so
// only catalog names are still noted, for markConflicts, and nothing else is
// remembered: the table of names stays bounded by the cap plus the catalog,
// however many entries a hostile page carries.
func (f *listFilter) collect(name string, _ []byte) bool {
	if f.failure != nil {
		return false
	}
	if err := f.tick(); err != nil {
		f.failure = err
		return false
	}
	_, inCatalog := f.cur.snap.Tools[name]
	if f.count > maxToolsPerPage {
		f.tooMany = true
		if !inCatalog {
			return false
		}
	}
	f.seen[name]++
	switch {
	case f.seen[name] == 1 && inCatalog:
		f.present = append(f.present, name)
	case f.seen[name] == 2:
		f.dupes = append(f.dupes, name)
	}
	return false
}

// decide is the pass-two callback: whether one tool is shown. mcpwire's
// callback cannot return an error, so a failure is parked in f.failure (and
// every later tool is hidden without work) and the caller turns it into a
// denial of the whole page.
func (f *listFilter) decide(name string, tool []byte) bool {
	if f.failure != nil {
		return false
	}
	if err := f.tick(); err != nil {
		f.failure = err
		return false
	}
	// A tool the catalog has never heard of is hidden without being hashed:
	// its content cannot change the answer, and a hostile upstream must not be
	// able to spend our CPU, or deny the whole page, with tools we never serve.
	policy, inCatalog := f.cur.snap.Tools[name]
	if !inCatalog {
		return false
	}
	// Nothing this large was ever approved, so it is hidden unhashed; and it
	// is evidence that the upstream is not serving the approved definition.
	if len(tool) > maxToolBytes {
		f.report.oversized++
		f.record(name, policy, observedConflict)
		return false
	}
	// The failure text goes to the log only, and the name is quoted there, so an
	// operator can see which tool broke the page without the client learning why.
	// The conflict marker for this tool, and for every other catalog tool the
	// page lists, is left by markConflicts once the page is denied.
	digest, err := f.srv.digests.digest(tool)
	if err != nil {
		f.failure = fmt.Errorf("tool %s: %w", quoteName(name), err)
		return false
	}
	f.record(name, policy, digest)
	return f.judgeListed(name, policy, digest)
}

// judgeListed decides a hashed catalog tool and files the reason when it is
// hidden. The live bytes must hash to the approved digest, and the latest
// crawl must not have left a marker in LastSeen: a tool the crawler could not
// verify (an invalid or duplicated definition, an exhausted proposal budget)
// is hidden even while the gateway shows the approved bytes, because judgeCall
// denies every call to it (D9) and what is listed must be what is callable.
func (f *listFilter) judgeListed(name string, policy catalog.ToolPolicy, digest string) bool {
	switch {
	case !f.cur.snap.Serves(name, digest):
		if f.cur.snap.Serves(name, policy.Approved) {
			// It would be served if the upstream served what was approved.
			f.report.mismatched = append(f.report.mismatched, name)
		} else {
			f.report.unapproved++
		}
		return false
	case !lifecycle.LastSeenVerifiable(policy.LastSeen):
		f.report.unverified++
		return false
	}
	return true
}

// record stores evidence about a catalog tool the snapshot could serve, and
// counts what the table had to evict or lose to take it. Evidence about a
// tool that can never be served is not kept: judgeCall denies such a tool
// before it looks at the evidence, so storing it would only let never-served
// names crowd out the entries the call rule depends on. Names outside the
// catalog never reach this function.
func (f *listFilter) record(name string, policy catalog.ToolPolicy, digest string) {
	if !f.cur.snap.Serves(name, policy.Approved) {
		return
	}
	switch f.srv.observe(name, digest, f.cur.generation) {
	case observeEvicted:
		f.evicted++
	case observeDropped:
		f.dropped++
	case observeStored:
	}
}

// markConflicts records a conflict for the catalog tools a denied page is
// evidence against, so tools/call stays denied for each of them until a clean
// page shows what the upstream serves. A page the processor read to the end
// (denied for a repeated name, too many tools, or a tool it could not hash)
// is evidence about exactly the tools it listed. A page it could not read to
// the end (no tools array, or an entry without a string name, wherever it
// sits) is evidence about nothing: the processor cannot know which tools were
// behind the unreadable entry, so every servable tool of the snapshot is
// marked. Either way, evidence recorded earlier must not survive a page that
// contradicts it: with a decoy first on the page, the changed tool behind it
// would otherwise keep its approved digest from an earlier listing.
func (f *listFilter) markConflicts() {
	if f.unreadable {
		for name, policy := range f.cur.snap.Tools {
			f.record(name, policy, observedConflict)
		}
		return
	}
	for _, name := range f.present {
		f.record(name, f.cur.snap.Tools[name], observedConflict)
	}
}

// filterList filters one page with the catalog policy and reports a full
// observed table once per page rather than once per tool. An eviction keeps
// the newest evidence at the cost of an entry that agreed with its approval;
// a drop is a loss, and the line says what judgeCall does about it.
func (s *Server) filterList(ctx context.Context, cur *cachedSnapshot, raw []byte) (filtered, error) {
	f := newListFilter(ctx, s, cur)
	page, err := f.run(raw)
	switch {
	case f.dropped > 0:
		s.log.WarnContext(ctx, "observed-digest table is full, evidence was dropped: tools without listing evidence are denied until a listing records them",
			"server", s.server, "max_tracked", s.maxTracked, "dropped", f.dropped, "evicted", f.evicted)
	case f.evicted > 0:
		s.log.WarnContext(ctx, "observed-digest table is full, agreeing evidence was evicted to keep newer evidence",
			"server", s.server, "max_tracked", s.maxTracked, "evicted", f.evicted)
	}
	return page, err
}

// toolDigest is the digest of one tool definition exactly as the crawler and
// the approval step compute it (gate.Digest over the raw bytes), after
// rejecting definitions that different parsers would read differently. It is
// the slow path behind Server.digests, which remembers its answer per byte
// string so an unchanged definition is canonicalised once, not once per page.
func toolDigest(tool []byte) (string, error) {
	if err := strictjson.Object(tool); err != nil {
		return "", fmt.Errorf("read tool definition: %w", err)
	}
	digest, err := gate.Digest(tool)
	if err != nil {
		return "", fmt.Errorf("digest tool definition: %w", err)
	}
	return digest, nil
}
