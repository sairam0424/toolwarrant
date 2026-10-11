package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
)

// loopTally counts the checks of a scheduled run so that the run fails at the
// end when any check failed, and when no check ever completed: a canary that
// printed "check failed" until it was stopped has proven nothing.
type loopTally struct {
	completed, failedVerdicts, errored int
}

// record counts one check.
func (t *loopTally) record(res verdicts, err error) {
	switch {
	case err != nil:
		t.errored++
	case res.failed():
		t.completed++
		t.failedVerdicts++
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
	case t.failedVerdicts+t.errored > 0:
		return fmt.Errorf("%d of %d check(s) in this run failed: at least one check of this run found a %s or %s, a %s or %s, or could not run; the lines above say which",
			t.failedVerdicts+t.errored, t.completed+t.errored, verdictLeak, verdictConfigEdited, verdictLiveConfig, verdictUnhooked)
	}
	return nil
}

// isFatalCheckError recognises the errors that no later check can recover
// from: the server is not in the catalog, or the catalog itself cannot be
// trusted. A canary that kept going would print "check failed" for ever.
func isFatalCheckError(err error) bool {
	return errors.Is(err, catalog.ErrNotFound) || errors.Is(err, catalog.ErrCorrupt) || errors.Is(err, catalog.ErrSchema)
}

// loop repeats the check until the context ends. A listing failure (the
// gateway is down for a while) is printed, counted and does not stop the
// schedule; a catalog error or an unknown server stops it at once; a failed
// check stops it unless keepGoing, and a file --config cannot read stops it
// even then, whether or not the listing of that check succeeded. The run as a
// whole fails at the end if any check failed or none completed.
func (v *verifier) loop(ctx context.Context, every time.Duration, keepGoing bool) error {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	var tally loopTally
	for {
		res, err := v.check(ctx)
		if ctx.Err() != nil {
			break
		}
		tally.record(res, err)
		stamp := time.Now().UTC().Format(time.RFC3339)
		switch {
		case err != nil:
			v.a.stdout.printf("%s %s: check failed: %s\n", stamp, cell(v.server), describe(err))
			if isFatalCheckError(err) {
				return fmt.Errorf("stopping the canary: %w", err)
			}
			if res.configReason != "" {
				return v.conclude(res)
			}
		case res.failed() && (!keepGoing || res.configReason != ""):
			return v.conclude(res)
		default:
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
