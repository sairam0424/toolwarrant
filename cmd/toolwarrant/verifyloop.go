package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
)

// loopTally counts the checks of a scheduled run so that the run fails at the
// end when any check failed, when any failing verdict line was printed, and
// when no check ever completed: a canary that printed "check failed" until it
// was stopped has proven nothing, and one that printed a LEAK and was stopped
// a moment later has proven a leak (D13 f).
type loopTally struct {
	completed, failedVerdicts, errored int
	// verdictLines is how many failing verdict lines the run printed; the
	// third review found a LEAK on stdout and exit 0 when the stop signal
	// arrived while the admin API fetch of the same check was in flight.
	verdictLines int
}

// record counts one check. A check that found a failing verdict is a failed
// check whatever else happened to it; a check that found none and was cut
// short by the stop signal proved nothing either way and is not counted.
func (t *loopTally) record(res verdicts, err error, interrupted bool) {
	switch {
	case res.failed():
		t.completed++
		t.failedVerdicts++
	case err != nil && interrupted:
	case err != nil:
		t.errored++
	default:
		t.completed++
	}
}

// outcome is the exit of a run that was stopped by a signal. The sentence
// names every verdict that counts as a failure, so a supervisor's log line
// says why the canary exited 1 without the lines above it.
func (t loopTally) outcome() error {
	switch {
	case t.completed == 0:
		return fmt.Errorf("no check of this run completed (%d could not run); nothing was proven about the gateway", t.errored)
	case t.failedVerdicts+t.errored > 0 || t.verdictLines > 0:
		return fmt.Errorf("%d of %d check(s) in this run failed: at least one check of this run found a %s or %s, a %s, %s or %s, or could not run; the lines above say which",
			t.failedVerdicts+t.errored, t.completed+t.errored, verdictLeak, verdictConfigEdited, verdictLiveConfig, verdictUnhooked, verdictInconclusive)
	}
	return nil
}

// isFatalCheckError recognises the errors that no later check can recover
// from: the server is not in the catalog, or the catalog itself cannot be
// trusted. A canary or a crawl schedule that kept going would print a failure
// for ever, or keep writing into a file every other command refuses.
func isFatalCheckError(err error) bool {
	return errors.Is(err, catalog.ErrNotFound) || errors.Is(err, catalog.ErrCorrupt) || errors.Is(err, catalog.ErrSchema)
}

// loop repeats the check until the context ends. Every check is tallied before
// the stop signal is looked at, so a check that printed a verdict and was then
// interrupted still fails the run. A listing failure (the gateway is down for
// a while) is printed, counted and does not stop the schedule; a catalog error
// or an unknown server stops it at once; a failed check stops it unless
// keepGoing, whatever error a later step of that check returned (the fourth
// review found a LEAK whose probe then errored repeated on every tick of an
// un-flagged run, cli-docs-5), and a file --config cannot read stops it even
// with keepGoing, whether or not the listing of that check succeeded. The run
// as a whole fails at the end if any check failed, any failing verdict line
// was printed, or none completed.
func (v *verifier) loop(ctx context.Context, every time.Duration, keepGoing bool) error {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	var tally loopTally
	for {
		res, err := v.check(ctx)
		tally.record(res, err, ctx.Err() != nil)
		tally.verdictLines = v.failingLines
		if ctx.Err() != nil {
			break
		}
		stamp := time.Now().UTC().Format(time.RFC3339)
		if err != nil {
			v.a.stdout.printf("%s %s: check failed: %s\n", stamp, cell(v.server), describe(err))
			if isFatalCheckError(err) {
				return fmt.Errorf("stopping the canary: %w", err)
			}
		}
		switch {
		case res.failed() && (!keepGoing || res.configReason != ""):
			return v.conclude(res)
		case err == nil:
			v.a.stdout.printf("%s %s: %s\n", stamp, cell(v.server), res.summary())
		}
		if werr := v.a.stdout.broken(); werr != nil {
			return werr
		}
		select {
		case <-ctx.Done():
			return tally.outcome()
		case <-ticker.C:
		}
	}
	return tally.outcome()
}
