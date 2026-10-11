package processor

import (
	"errors"
	"time"
)

// The caps below are the processor's whole defence against an upstream, or
// a client, that tries to make the gate expensive. Every one of them turns
// excess into a denial, never into a pass: the gateway fails closed on a
// denial, so the worst a hostile page can do is hide its own tools.
const (
	// maxPayloadBytes is the largest MCP payload the processor will parse. It
	// equals the gRPC receive limit, so the two layers agree on "too big". A
	// page over this cannot be verified in bounded time and memory.
	maxPayloadBytes = 8 << 20

	// maxToolsPerPage caps the tool entries in one tools/list page. It is
	// enforced before any per-tool work, so one page cannot buy millions of
	// catalog lookups.
	maxToolsPerPage = 10000

	// maxToolBytes is the largest tool definition that is hashed at all. The
	// catalog never stores a definition above 256 KiB, so a live definition of
	// twice that size cannot equal any approved one: it is hidden unhashed.
	maxToolBytes = 512 << 10

	// maxConcurrentHooks bounds hooks in flight across all connections and,
	// with the caps above, the memory of the process. One tools/list hook holds
	// the page (at most maxPayloadBytes, owned by gRPC), the decoder's buffer
	// for the largest single value on it (at most the page), the rewritten
	// result (at most about the page), the names of at most maxToolsPerPage
	// entries, and the canonical form of the one tool being hashed (a few times
	// maxToolBytes); nothing else on the page is materialised. A hook therefore
	// costs about three times maxPayloadBytes at the limit and the process
	// about 32 times that, under 1 GiB. A refused page costs far less: the scan
	// stops at the per-page cap before any name is read, so a mebibyte of tiny
	// entries costs a few kibibytes rather than the eighteen mebibytes it cost
	// when the array was materialised first (BenchmarkCheckResponseOverCapTinyNames,
	// TestCheckResponse_OverCapPageIsRefusedBeforeNamesAreRead).
	maxConcurrentHooks = 32

	// ctxCheckInterval is how many tools are processed between checks of the
	// hook context: a cancelled hook stops burning CPU promptly without paying
	// for a check on every tool.
	ctxCheckInterval = 256

	// sourceTimeout bounds one hook's catalog reads, so a wedged database
	// cannot hold the reload lock (and so every hook) forever.
	sourceTimeout = 10 * time.Second
)

var (
	// errPayloadSize means a hook payload was too large to inspect safely. The
	// hook is then denied rather than passed through uninspected.
	errPayloadSize = errors.New("processor: payload exceeds the size limit")

	// errTooManyTools means one tools/list page listed more tools than
	// maxToolsPerPage.
	errTooManyTools = errors.New("processor: page lists more tools than the limit")

	// errDuplicateTool means one tools/list page carried the same tool name
	// twice. The gateway and a client may bind the name to different copies,
	// so no copy can be trusted.
	errDuplicateTool = errors.New("processor: tool name appears twice in one page")

	// errThrottled means every concurrency slot was taken when the hook arrived.
	errThrottled = errors.New("processor: too many hooks in flight")
)
