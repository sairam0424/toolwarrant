package main

import (
	"fmt"
	"sort"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// Verdict words. LEAK is the one that matters: the gateway serves something
// the catalog would not serve, which is what a route without its processor
// looks like (the guard is config-presence-based and fails open; decision
// D12). CONFIG-EDITED, LIVE-CONFIG-MISMATCH and UNHOOKED-CALLS are the other
// ways a deployment fails the check. MISSING is a report and never fails.
const (
	verdictLeak = "LEAK"
	// verdictMismatch is a sub-label on a LEAK line, never a verdict of its
	// own: the tool is approved and enabled, the latest crawl saw the approved
	// digest, and the gateway hands out other bytes. See leak.mismatch.
	verdictMismatch     = "MISMATCH"
	verdictMissing      = "MISSING"
	verdictConfigEdited = "CONFIG-EDITED"
	verdictLiveConfig   = "LIVE-CONFIG-MISMATCH"
	verdictUnhooked     = "UNHOOKED-CALLS"
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

// leak is one served tool that Serves would hide, with what the catalog knows
// about it, so the line can say why the gateway should not have served it.
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
}

// probeOutcome is what the unhooked-call probe found.
type probeOutcome int

const (
	// probeSkipped means no probe was sent (--no-probe).
	probeSkipped probeOutcome = iota
	// probeHealthy means the gateway refused the id-less tools/call.
	probeHealthy
	// probeUnhooked means the gateway accepted it (HTTP 202) and so forwarded
	// it to the upstream without the processor or the allow rule.
	probeUnhooked
)

// liveCheck is the outcome of comparing the gateway's live configuration with
// the emitted file. It is skipped without --admin, and when the emitted file
// could not be read there is nothing to compare against.
type liveCheck struct {
	compared bool
	skipped  string // why the comparison did not run, when it did not
	// diffs names every field that differs, already escaped; empty when the
	// live configuration is the emitted one.
	diffs []string
}

// verdicts is the outcome of one check of one gateway route.
type verdicts struct {
	// leaks are served tools that Serves would hide, an unusable live
	// definition included.
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
	live         liveCheck
	probe        probeOutcome
}

// failed reports whether the check must fail the command. Exit 0 is OK or
// MISSING only.
func (v verdicts) failed() bool {
	return len(v.leaks) > 0 || v.configEdited || len(v.live.diffs) > 0 || v.probe == probeUnhooked
}

// mismatchCount is how many leaks carry the MISMATCH sub-label.
func (v verdicts) mismatchCount() int {
	n := 0
	for _, l := range v.leaks {
		if l.mismatch {
			n++
		}
	}
	return n
}

// summary is the one-line account of a check. docs/operations.md quotes its
// first clause and the MISSING count, so the two must change together.
func (v verdicts) summary() string {
	s := fmt.Sprintf("the gateway serves %d tool(s), %d approved and current", v.served+len(v.leaks), v.served)
	if n := len(v.leaks); n > 0 {
		s += fmt.Sprintf(", %d leaked", n)
		if m := v.mismatchCount(); m > 0 {
			s += fmt.Sprintf(" (%d of them %s)", m, verdictMismatch)
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
	}
	return "; unhooked-call probe skipped (--no-probe)"
}

// compare sorts the live tools into verdicts. Every served tool that Serves
// rejects is a leak: a tool the catalog never approved, a disabled or paused
// one, a drifted or rejected definition, a definition that cannot be
// digested. The approved, enabled tool whose live digest differs from the
// approved one while the latest crawl saw the approved digest is a leak too,
// labelled MISMATCH so the owner knows the catalog has no record of drift
// (decision D12; the second review found a poisoned and then rejected
// definition reported as a non-failing MISMATCH). An approved tool that the
// latest crawl saw at the approved digest but the gateway does not list is
// missing, which does not fail.
func compare(snap catalog.Snapshot, live []liveTool, res *verdicts) {
	seen := map[string]bool{}
	for _, t := range live {
		seen[t.name] = true
		if snap.Serves(t.name, t.digest) {
			res.served++
			continue
		}
		pol := snap.Tools[t.name]
		res.leaks = append(res.leaks, leak{liveTool: t, approved: pol.Approved, mismatch: isMismatch(pol, t.digest)})
	}
	for name, pol := range snap.Tools {
		if !seen[name] && snap.Serves(name, pol.LastSeen) {
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

// print writes one line per verdict. Digests are shown short, both sides for
// a MISMATCH so the owner can approve the served definition if it is
// legitimate. Every name comes from the gateway or the catalog and is escaped.
func (v *verifier) print(res verdicts) {
	out := v.a.stdout
	if res.configEdited {
		v.printConfigEdited(res)
	}
	for _, l := range res.leaks {
		out.printf("%s\n", leakLine(l))
	}
	for _, d := range res.live.diffs {
		out.printf("%s %s: %s\n", verdictLiveConfig, cell(v.server), d)
	}
	if res.probe == probeUnhooked {
		out.printf("%s %s: the gateway accepted a tools/call without an id (HTTP 202) and forwarded it to the upstream without the processor or the allow rule; every tools/call in that shape bypasses the approval (known limit L17)\n", verdictUnhooked, cell(v.server))
	}
	for _, name := range res.missing {
		out.printf("%s %s %s\n", verdictMissing, cell(name), shortDigest(res.approvedOf(name)))
	}
}

// printConfigEdited writes the CONFIG-EDITED line: a file that is not what
// emit wrote, or a file the canary could not read at all.
func (v *verifier) printConfigEdited(res verdicts) {
	if res.configReason != "" {
		v.a.stdout.printf("%s %s: the file could not be read (%s); a canary that cannot read the emitted file must assume it was replaced\n", verdictConfigEdited, textdiff.Escape(v.config), res.configReason)
		return
	}
	hash := res.configHash
	if hash == "" {
		hash = noHash
	}
	v.a.stdout.printf("%s %s: the file is not what emit wrote (body sha256 %s); a route that lost its processor entry fails open\n", verdictConfigEdited, textdiff.Escape(v.config), hash)
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
	if l.mismatch {
		line += fmt.Sprintf(" (%s: the latest crawl saw the approved digest, so the route has no processor or the gateway re-serialised the definition; the processor would have hidden these bytes)", verdictMismatch)
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
