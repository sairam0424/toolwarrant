package processor

import (
	"context"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/gate"
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
// repeat and polls the hook context, hashing nothing. Pass two (decide) runs
// only when the page is clean and does the per-tool work in order. Deciding a
// tool before the whole page has been read is what once let a repeated name
// leave approved evidence behind: the first copy was observed and the second
// copy denied the page, so tools/call kept passing on the first copy's digest.
// With two passes every duplicate is known before any evidence is recorded.
type listFilter struct {
	ctx      context.Context
	srv      *Server
	cur      *cachedSnapshot
	count    int            // tools seen so far in the current pass
	seen     map[string]int // name -> occurrences, pass one
	dupes    []string       // names that occur more than once, in first-seen order
	failure  error
	overflow int
	report   hiddenReport
}

func newListFilter(ctx context.Context, srv *Server, cur *cachedSnapshot) *listFilter {
	return &listFilter{ctx: ctx, srv: srv, cur: cur, seen: make(map[string]int)}
}

// run performs both passes. The result is only meaningful when err is nil.
// Conflicts found in pass one are recorded whatever else went wrong with the
// page: they are facts about the upstream, not about the page's shape.
func (f *listFilter) run(raw []byte) (filtered, error) {
	_, _, err := mcpwire.FilterToolsListRaw(raw, f.collect)
	f.markConflicts()
	switch {
	case f.failure != nil:
		return filtered{}, f.failure
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
// this pass is discarded) and does no per-tool work beyond counting names.
func (f *listFilter) collect(name string, _ []byte) bool {
	if f.failure != nil {
		return false
	}
	if err := f.tick(); err != nil {
		f.failure = err
		return false
	}
	if f.count > maxToolsPerPage {
		f.failure = errTooManyTools
		return false
	}
	f.seen[name]++
	if f.seen[name] == 2 {
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
		f.record(name, observedConflict)
		return false
	}
	// The failure text goes to the log only, and the name is quoted there, so an
	// operator can see which tool broke the page without the client learning why.
	digest, err := toolDigest(tool)
	if err != nil {
		f.record(name, observedConflict)
		f.failure = fmt.Errorf("tool %s: %w", quoteName(name), err)
		return false
	}
	f.record(name, digest)
	if f.cur.snap.Serves(name, digest) {
		return true
	}
	if f.cur.snap.Serves(name, policy.Approved) {
		// It would be served if the upstream served what was approved.
		f.report.mismatched = append(f.report.mismatched, name)
	} else {
		f.report.unapproved++
	}
	return false
}

// record stores evidence about a catalog tool, counting the writes a full
// table refused.
func (f *listFilter) record(name, digest string) {
	if !f.srv.observe(name, digest, f.cur.generation) {
		f.overflow++
	}
}

// markConflicts records a conflict for every repeated name the catalog knows,
// so tools/call stays denied for them until a clean page shows what the
// upstream serves. Names outside the catalog are never recorded.
func (f *listFilter) markConflicts() {
	for _, name := range f.dupes {
		if _, ok := f.cur.snap.Tools[name]; ok {
			f.record(name, observedConflict)
		}
	}
}

// filterList filters one page with the catalog policy and reports a full
// observed table once per page rather than once per tool.
func (s *Server) filterList(ctx context.Context, cur *cachedSnapshot, raw []byte) (filtered, error) {
	f := newListFilter(ctx, s, cur)
	page, err := f.run(raw)
	if f.overflow > 0 {
		s.log.WarnContext(ctx, "observed-digest table is full, some tools are not tracked",
			"server", s.server, "max_tracked", s.maxTracked, "untracked", f.overflow)
	}
	return page, err
}

// toolDigest is the digest of one tool definition exactly as the crawler and
// the approval step compute it (gate.Digest over the raw bytes), after
// rejecting definitions that different parsers would read differently.
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
