package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
)

// crawlTally counts the crawls of a scheduled run so that the run fails at
// the end when no crawl completed, or when the catalog refused one (D13 f): a
// schedule that printed failures until it was stopped recorded nothing about
// the upstream's tools, and a refused listing means a cap was hit that nobody
// saw. A listing that failed while others completed does not fail the run: an
// upstream that is down for a while must not turn a schedule into an incident.
type crawlTally struct {
	completed, failed, refused int
}

// record counts one crawl.
func (t *crawlTally) record(err error) {
	var failure *crawlFailure
	switch {
	case err == nil:
		t.completed++
	case errors.As(err, &failure) && failure.refused:
		t.refused++
	default:
		t.failed++
	}
}

// outcome is the exit of a run that was stopped by a signal.
func (t crawlTally) outcome() error {
	switch {
	case t.completed == 0:
		return fmt.Errorf("no crawl of this run completed (%d failed, %d refused by the catalog); nothing was recorded about the upstream's tools", t.failed, t.refused)
	case t.refused > 0:
		return fmt.Errorf("%d crawl(s) of this run were refused by the catalog (a cap was exceeded) and added no rows; the lines above say which", t.refused)
	}
	return nil
}

// loop crawls until the context ends. An upstream that is down for a while
// must not stop the schedule, so a listing failure is printed, recorded and
// counted; a catalog that can no longer be trusted (a dropped guard object,
// another schema) or a server that is gone stops the schedule at once, with
// exit 1, because a long-lived writer must never record a crawl into a file
// that every other command refuses (third review); --strict stops it at the
// first crawl that lists something unservable, because that is what the flag
// asks for. The run fails at the end if no crawl completed or any was refused.
func (cr *crawler) loop(ctx context.Context, every time.Duration) error {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	var tally crawlTally
	for {
		report, err := cr.scheduledCrawl(ctx)
		if ctx.Err() != nil {
			return tally.outcome()
		}
		if werr := cr.printLine(report, err); werr != nil {
			return werr
		}
		if isFatalCheckError(err) {
			return fmt.Errorf("stopping the crawl schedule: %w", err)
		}
		tally.record(err)
		if err == nil {
			if serr := cr.checkStrict(report); serr != nil {
				return serr
			}
		}
		select {
		case <-ctx.Done():
			return tally.outcome()
		case <-ticker.C:
		}
	}
}

// scheduledCrawl re-checks the catalog before every crawl of a schedule, the
// way the canary does before every check: the snapshot load verifies the
// guard objects, so a trigger dropped under a running schedule is seen at the
// next iteration instead of being written past until the process ends.
func (cr *crawler) scheduledCrawl(ctx context.Context) (catalog.CrawlReport, error) {
	if _, err := cr.store.Snapshot(ctx, cr.server.Name); err != nil {
		return catalog.CrawlReport{}, fmt.Errorf("crawl of %s: %w", cr.server.Name, err)
	}
	return cr.crawl(ctx)
}
