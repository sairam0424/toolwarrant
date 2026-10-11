package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// Verdict words. LEAK is the one that matters: the gateway serves something
// the catalog would not serve, which is what a route without its processor
// looks like (the guard is config-presence-based and fails open; decision
// D12). CONFIG-EDITED, LIVE-CONFIG-MISMATCH, UNHOOKED-CALLS and
// PROBE-INCONCLUSIVE are the other ways a deployment fails the check. MISSING
// is a report and never fails.
const (
	verdictLeak = "LEAK"
	// verdictMismatch is a sub-label on a LEAK line, never a verdict of its
	// own: the tool is approved and enabled, the latest crawl saw the approved
	// digest, and the gateway hands out other bytes. See leak.mismatch.
	verdictMismatch = "MISMATCH"
	// verdictUnverified is the other sub-label on a LEAK line: the latest
	// crawl left a marker instead of a digest on the tool, so the processor
	// hides it whatever bytes the gateway shows (D9, D13). See leak.unverified.
	verdictUnverified   = "UNVERIFIED"
	verdictMissing      = "MISSING"
	verdictConfigEdited = "CONFIG-EDITED"
	verdictLiveConfig   = "LIVE-CONFIG-MISMATCH"
	verdictUnhooked     = "UNHOOKED-CALLS"
	// verdictInconclusive is the probe's answer when a 2xx with a body came
	// back: the canary cannot tell whether the gateway or the upstream wrote
	// it, so it fails the check rather than call the gateway healthy (D13 h).
	verdictInconclusive = "PROBE-INCONCLUSIVE"
	verdictOK           = "OK"
	// noHash is shown for a config whose header is missing or malformed.
	noHash = "(no header)"
)

// liveTool is one tool as the gateway served it: its digest, or "" with the
// reason when the definition could not be used (and so could never have been
// approved).
type liveTool struct {
	name     string
	digest   string
	unusable string
}

// leak is one served tool that the catalog's serving rule would hide, with
// what the catalog knows about it, so the line can say why the gateway should
// not have served it.
type leak struct {
	liveTool
	// approved is the catalog's approved digest for the name, "" when none.
	approved string
	// mismatch marks the one leak whose only explanation is the gateway: the
	// tool is enabled, the latest crawl saw the approved digest, and the bytes
	// the gateway hands out hash differently. The processor hides exactly
	// those bytes, so a client can see them only when the route has no
	// processor, or when the gateway re-serialised the definition (limit L2),
	// which with the processor in place shows as MISSING instead. It is a
	// diagnostic sub-label; the verdict is LEAK either way.
	mismatch bool
	// unverified is the marker the latest crawl left on the tool instead of a
	// digest (lifecycle.UnusableDigest, limit L6), "" for every other leak. The
	// processor hides such a tool even when the gateway shows the approved
	// bytes, so a route that serves it has no processor; the canary applies
	// the same rule (lifecycle.LastSeenVerifiable) so the two cannot disagree.
	unverified string
}

// probeOutcome is what the unhooked-call probe found.
type probeOutcome int

const (
	// probeSkipped means no probe was sent (--no-probe).
	probeSkipped probeOutcome = iota
	// probeHealthy means the gateway refused the id-less tools/call (HTTP 400).
	probeHealthy
	// probeUnhooked means the gateway accepted it (HTTP 202) and so forwarded
	// it to the upstream without the processor or the allow rule.
	probeUnhooked
	// probeInconclusive means the answer was another 2xx with a body, or a
	// 400 whose body is JSON (a JSON-RPC answer, single or batched), which the
	// gateway or the upstream may have written; the canary cannot tell (D13 h,
	// D14 i, D15 k).
	probeInconclusive
)

// liveCheck is the outcome of comparing the gateway's live configuration with
// the emitted file. It is skipped without --admin, and when the emitted file
// could not be read there is nothing to compare against.
type liveCheck struct {
	compared bool
	skipped  string // why the comparison did not run, when it did not
	// diffs names every item that differs, already escaped; empty when the
	// live configuration is the emitted one.
	diffs []string
}

// verdicts is the outcome of one check of one gateway route.
type verdicts struct {
	// leaks are served tools that the serving rule would hide, an unusable
	// live definition and an unverified tool included.
	leaks []leak
	// missing are approved tools the latest crawl saw at the approved digest
	// but the gateway does not list; missingDigests holds their approved
	// digests for the MISSING lines.
	missing        []string
	missingDigests map[string]string
	// served counts live tools that are approved and current.
	served       int
	configEdited bool
	configHash   string
	// configReason is why the emitted file could not be read, "" when it was.
	// An unreadable file counts as edited: a canary that cannot read the file
	// it is meant to compare must not report OK.
	configReason string
	// configExpected is the body hash the operator recorded and passed with
	// --expect-body-hash when the file's body hashes to something else, ""
	// otherwise. Such a file verifies (its header was recomputed, limit L19)
	// and is still not the file emit wrote.
	configExpected string
	live           liveCheck
	probe          probeOutcome
}

// failed reports whether the check must fail the command. Exit 0 is OK or
// MISSING only.
func (v verdicts) failed() bool {
	return len(v.leaks) > 0 || v.configEdited || len(v.live.diffs) > 0 || v.probe == probeUnhooked || v.probe == probeInconclusive
}

// subLabelCounts counts the leaks that carry each sub-label.
func (v verdicts) subLabelCounts() (mismatched, unverified int) {
	for _, l := range v.leaks {
		switch {
		case l.mismatch:
			mismatched++
		case l.unverified != "":
			unverified++
		}
	}
	return mismatched, unverified
}

// summary is the one-line account of a check. docs/operations.md quotes its
// first clause and the MISSING count, so the two must change together.
func (v verdicts) summary() string {
	s := fmt.Sprintf("the gateway serves %d tool(s), %d approved and current", v.served+len(v.leaks), v.served)
	if n := len(v.leaks); n > 0 {
		s += fmt.Sprintf(", %d leaked", n)
		var labels []string
		if m, u := v.subLabelCounts(); m+u > 0 {
			if m > 0 {
				labels = append(labels, fmt.Sprintf("%d of them %s", m, verdictMismatch))
			}
			if u > 0 {
				labels = append(labels, fmt.Sprintf("%d of them %s", u, verdictUnverified))
			}
			s += " (" + strings.Join(labels, ", ") + ")"
		}
	}
	if n := len(v.missing); n > 0 {
		s += fmt.Sprintf(", %d approved but not listed (%s)", n, verdictMissing)
	}
	if v.configEdited {
		s += ", configuration edited"
	}
	return s + v.live.summary() + v.probe.summary()
}

// summary is the live-configuration part of the check's one-line account.
func (l liveCheck) summary() string {
	switch {
	case l.compared && len(l.diffs) > 0:
		return fmt.Sprintf("; live configuration differs from the emitted file (%s)", verdictLiveConfig)
	case l.compared:
		return "; live configuration matches the emitted file"
	case l.skipped != "":
		return "; live configuration not compared (" + l.skipped + ")"
	}
	return "; live configuration not compared (no --admin)"
}

// summary is the probe's part of the check's one-line account.
func (p probeOutcome) summary() string {
	switch p {
	case probeHealthy:
		return "; id-less tools/call rejected by the gateway"
	case probeUnhooked:
		return fmt.Sprintf("; id-less tools/call forwarded unhooked (%s)", verdictUnhooked)
	case probeInconclusive:
		return fmt.Sprintf("; id-less tools/call answered by someone (%s)", verdictInconclusive)
	}
	return "; unhooked-call probe skipped (--no-probe)"
}

// compare sorts the live tools into verdicts. Every served tool that the
// serving rule rejects is a leak: a tool the catalog never approved, a
// disabled or paused one, a drifted or rejected definition, a definition that
// cannot be digested, and a tool whose latest crawl left a marker instead of
// a digest (the processor hides it whatever the gateway shows, D9; the canary
// applies lifecycle.LastSeenVerifiable so the two agree, D13). The approved,
// enabled tool whose live digest differs from the approved one while the
// latest crawl saw the approved digest is a leak too, labelled MISMATCH so the
// owner knows the catalog has no record of drift (decision D12). An approved
// tool that the latest crawl saw at the approved digest but the gateway does
// not list is missing, which does not fail; a tool carrying a marker is never
// missing, because the processor is right to hide it.
func compare(snap catalog.Snapshot, live []liveTool, res *verdicts) {
	seen := map[string]bool{}
	for _, t := range live {
		seen[t.name] = true
		pol, known := snap.Tools[t.name]
		switch {
		case known && !lifecycle.LastSeenVerifiable(pol.LastSeen):
			res.leaks = append(res.leaks, leak{liveTool: t, approved: pol.Approved, unverified: pol.LastSeen})
		case snap.Serves(t.name, t.digest):
			res.served++
		default:
			res.leaks = append(res.leaks, leak{liveTool: t, approved: pol.Approved, mismatch: isMismatch(pol, t.digest)})
		}
	}
	for name, pol := range snap.Tools {
		if !seen[name] && lifecycle.LastSeenVerifiable(pol.LastSeen) && snap.Serves(name, pol.LastSeen) {
			if res.missingDigests == nil {
				res.missingDigests = map[string]string{}
			}
			res.missing = append(res.missing, name)
			res.missingDigests[name] = pol.Approved
		}
	}
	sort.Strings(res.missing)
}

// isMismatch recognises the leak that only the gateway can explain: the tool
// is enabled, the crawl saw the approved digest, and the bytes the gateway
// hands out hash to another digest. A tool whose crawl recorded drift, a
// rejected digest the upstream keeps serving, or a disabled tool is a plain
// leak: the catalog knows why it must not be served.
func isMismatch(pol catalog.ToolPolicy, live string) bool {
	return pol.State == lifecycle.Enabled && pol.Approved != "" && pol.LastSeen == pol.Approved && live != "" && live != pol.Approved
}

// printListing writes the verdict lines the listing and the file check
// produced, before any later network call runs (D13 f): a CONFIG-EDITED or a
// LEAK must never wait behind an admin API or a probe that may hang until the
// run is stopped. Digests are shown short, both sides for a MISMATCH so the
// owner can approve the served definition if it is legitimate. Every name
// comes from the gateway or the catalog and is escaped. The failing lines are
// counted so that a scheduled run fails at the end if it ever printed one.
func (v *verifier) printListing(res verdicts) {
	out := v.a.stdout
	if res.configEdited {
		v.printConfigEdited(res)
		v.failingLines++
	}
	for _, l := range res.leaks {
		out.printf("%s\n", leakLine(l))
		v.failingLines++
	}
	for _, name := range res.missing {
		out.printf("%s %s %s\n", verdictMissing, cell(name), shortDigest(res.approvedOf(name)))
	}
}

// printChecks writes the verdict lines of the live comparison and the probe,
// which run after the listing.
func (v *verifier) printChecks(res verdicts) {
	out := v.a.stdout
	for _, d := range res.live.diffs {
		out.printf("%s %s: %s\n", verdictLiveConfig, cell(v.server), d)
		v.failingLines++
	}
	switch res.probe {
	case probeUnhooked:
		out.printf("%s %s: the gateway accepted a tools/call without an id (HTTP 202) and forwarded it to the upstream without the processor or the allow rule; every tools/call in that shape bypasses the approval (known limit L17)\n", verdictUnhooked, cell(v.server))
		v.failingLines++
	case probeInconclusive:
		out.printf("%s %s: the gateway answered a tools/call without an id with a 2xx status and a body, or with HTTP 400 and a JSON body, instead of a bare HTTP 400; the gateway or the upstream may have written that answer, so whether such calls reach the upstream unhooked is unknown and the check fails\n", verdictInconclusive, cell(v.server))
		v.failingLines++
	}
}

// printConfigEdited writes the CONFIG-EDITED line: a file that is not what
// emit wrote, a file whose body hash is not the one the operator recorded, or
// a file the canary could not read at all.
func (v *verifier) printConfigEdited(res verdicts) {
	switch {
	case res.configReason != "":
		v.a.stdout.printf("%s %s: the file could not be read (%s); a canary that cannot read the emitted file must assume it was replaced\n", verdictConfigEdited, textdiff.Escape(v.config), res.configReason)
	case res.configExpected != "":
		v.a.stdout.printf("%s %s: the body sha256 is %s, not the recorded %s; the file verifies, so whoever replaced it recomputed the header hash (known limit L19)\n", verdictConfigEdited, textdiff.Escape(v.config), res.configHash, res.configExpected)
	default:
		hash := res.configHash
		if hash == "" {
			hash = noHash
		}
		v.a.stdout.printf("%s %s: the file is not what emit wrote (body sha256 %s); a route that lost its processor entry fails open\n", verdictConfigEdited, textdiff.Escape(v.config), hash)
	}
}

// leakLine renders one LEAK verdict with as much as the catalog knows.
func leakLine(l leak) string {
	if l.unusable != "" {
		return fmt.Sprintf("%s %s (unusable definition: %s)", verdictLeak, cell(l.name), cell(l.unusable))
	}
	line := fmt.Sprintf("%s %s live %s", verdictLeak, cell(l.name), shortDigest(l.digest))
	if l.approved != "" {
		line += " approved " + shortDigest(l.approved)
	}
	switch {
	case l.mismatch:
		line += fmt.Sprintf(" (%s: the latest crawl saw the approved digest, so the route has no processor or the gateway re-serialised the definition; the processor would have hidden these bytes)", verdictMismatch)
	case l.unverified != "":
		line += fmt.Sprintf(" (%s: the latest crawl left the marker %s instead of a digest, so the processor hides this tool whatever the gateway shows; the route has no processor)", verdictUnverified, cell(l.unverified))
	}
	return line
}

// approvedOf is the approved digest of a missing tool, kept on the verdicts
// so the printer does not need the snapshot.
func (v verdicts) approvedOf(name string) string {
	if d, ok := v.missingDigests[name]; ok {
		return d
	}
	return ""
}
