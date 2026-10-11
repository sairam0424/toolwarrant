package catalog

import "context"

// Limits on what one server may accumulate in the file over its whole history
// (D13). The per-crawl caps (MaxToolsPerCrawl, MaxCrawlBytes) and the per-tool
// proposal budget bound one crawl and one tool; neither bounds an upstream
// that lists fresh names on every crawl, because a deprecated tool keeps its
// row and its versions for ever and nothing prunes. These two do. A crawl that
// would push the server over either cap is recorded as a failed crawl under
// its own class (failureServerTools, failureServerBytes) and adds no row, as a
// listing over a per-crawl cap is.
//
// Recovery: pause the server (`server pause`), then re-initialise the catalog
// (delete the file, `init`, register and approve again). There is no prune in
// v0.1: versions are immutable and the audit log is append-only, so removing
// rows would mean editing history, which is the one thing the file refuses.
const (
	// MaxToolsPerServer bounds the tool rows one server owns, live and
	// deprecated together: five full crawls of entirely fresh names.
	MaxToolsPerServer = 5 * MaxToolsPerCrawl
	// MaxServerBytes bounds the canonical bytes stored across every version of
	// every tool of one server: thirty-two crawls of entirely new definitions
	// at the per-crawl cap, 1 GiB. The raw definition is stored next to the
	// canonical form, so the file can hold about twice this per server.
	MaxServerBytes = 32 * MaxCrawlBytes
)

// Whole-crawl failure classes for the per-server caps.
const (
	failureServerTools = "server-tools-cap"
	failureServerBytes = "server-bytes-cap"
)

// serverCaps holds the per-server limits a Store enforces. The constants are
// the only values outside tests, which lower them to reach the cap quickly.
type serverCaps struct {
	tools int
	bytes int64
}

func defaultServerCaps() serverCaps {
	return serverCaps{tools: MaxToolsPerServer, bytes: MaxServerBytes}
}

// check returns the failure class of a crawl that would push the server over a
// cap, or "" when it fits. Only a crawl that adds rows or bytes
// pays for the counts, so a steady-state crawl costs nothing here.
func (c serverCaps) check(ctx context.Context, q queryer, serverID int64, known map[string]*toolRec, ls *listing) (string, error) {
	newRows, newBytes := ls.growth(known)
	if newRows > 0 {
		have, err := countServerTools(ctx, q, serverID)
		if err != nil {
			return "", err
		}
		if have+newRows > c.tools {
			return failureServerTools, nil
		}
	}
	if newBytes > 0 {
		have, err := sumServerBytes(ctx, q, serverID)
		if err != nil {
			return "", err
		}
		if have+newBytes > c.bytes {
			return failureServerBytes, nil
		}
	}
	return "", nil
}

// growth counts the tool rows and the canonical bytes the listing would add
// to the server: a row per usable name no tool describes, and the bytes of
// every usable definition whose digest its tool does not know and may still
// store (decide applies the proposal budget the same way).
func (ls *listing) growth(known map[string]*toolRec) (rows int, bytes int64) {
	for i := range ls.usable {
		p := &ls.usable[i]
		rec := known[p.name]
		switch {
		case rec == nil:
			rows++
			bytes += int64(len(p.canonical))
		case !rec.knowsDigest(p.digest) && rec.budget < MaxProposalsPerDecision:
			bytes += int64(len(p.canonical))
		}
	}
	return rows, bytes
}
