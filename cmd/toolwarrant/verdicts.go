package main

import (
	"fmt"
	"sort"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// Verdict words. LEAK is the one that matters: the gateway serves something
// the catalog would hide, which is what happens when a config loses its
// processor (the guard is config-presence-based and fails open). CONFIG-EDITED
// is its early warning.
const (
	verdictLeak         = "LEAK"
	verdictMismatch     = "MISMATCH"
	verdictMissing      = "MISSING"
	verdictConfigEdited = "CONFIG-EDITED"
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

// verdicts is the outcome of one comparison of a live listing with the
// catalog's serving policy.
type verdicts struct {
	// leaks are served tools that Serves would hide, an unusable live
	// definition included.
	leaks []liveTool
	// mismatches are approved, enabled tools whose live digest differs from
	// the approved one while the catalog has no record of drift.
	mismatches []liveTool
	// missing are approved tools the latest crawl saw at the approved digest
	// but the gateway does not list.
	missing []string
	// served counts live tools that are approved and current.
	served       int
	configEdited bool
	configHash   string
}

// failed reports whether the check must fail the command.
func (v verdicts) failed() bool { return len(v.leaks) > 0 || v.configEdited }

// summary is the one-line account of a check.
func (v verdicts) summary() string {
	s := fmt.Sprintf("the gateway serves %d tool(s), %d approved and current", v.served+len(v.leaks)+len(v.mismatches), v.served)
	if n := len(v.leaks); n > 0 {
		s += fmt.Sprintf(", %d leaked", n)
	}
	if n := len(v.mismatches); n > 0 {
		s += fmt.Sprintf(", %d with a digest other than the approved one (MISMATCH)", n)
	}
	if n := len(v.missing); n > 0 {
		s += fmt.Sprintf(", %d approved but not listed (MISSING)", n)
	}
	if v.configEdited {
		s += ", configuration edited"
	}
	return s
}

// compare sorts the live tools into verdicts. A tool whose live definition
// cannot be digested, or that Serves would hide, leaks. An approved, enabled
// tool whose live digest merely differs from the approved one is a mismatch:
// the catalog has no record of drift, so the difference may be the gateway's
// own re-serialisation of fields it does not know (see the processor package
// comment), or drift since the last crawl; either way the processor would hide
// it, so it is reported rather than failed. An approved tool that the latest
// crawl saw at the approved digest but the gateway does not list is missing.
func compare(snap catalog.Snapshot, live []liveTool, res *verdicts) {
	seen := map[string]bool{}
	for _, t := range live {
		seen[t.name] = true
		switch {
		case snap.Serves(t.name, t.digest):
			res.served++
		case t.digest != "" && isMismatch(snap.Tools[t.name], t.digest):
			res.mismatches = append(res.mismatches, t)
		default:
			res.leaks = append(res.leaks, t)
		}
	}
	for name, pol := range snap.Tools {
		if !seen[name] && snap.Serves(name, pol.LastSeen) {
			res.missing = append(res.missing, name)
		}
	}
	sort.Strings(res.missing)
}

// isMismatch recognises the one case that is not a plain leak: the tool is
// approved and enabled, the crawl saw the approved digest, and only the bytes
// the gateway hands out hash differently.
func isMismatch(pol catalog.ToolPolicy, live string) bool {
	return pol.State == lifecycle.Enabled && pol.Approved != "" && pol.Approved != live
}

// print writes one line per verdict. Digests are shown short, both sides for a
// mismatch so the owner can approve the served definition if it is legitimate.
func (v *verifier) print(res verdicts, snap catalog.Snapshot) {
	out := v.a.stdout
	if res.configEdited {
		hash := res.configHash
		if hash == "" {
			hash = noHash
		}
		out.printf("%s %s: the file is not what emit wrote (body sha256 %s); a route that lost its processor entry fails open\n", verdictConfigEdited, textdiff.Escape(v.config), hash)
	}
	for _, l := range res.leaks {
		if l.unusable != "" {
			out.printf("%s %s (unusable definition: %s)\n", verdictLeak, cell(l.name), cell(l.unusable))
			continue
		}
		out.printf("%s %s %s\n", verdictLeak, cell(l.name), shortDigest(l.digest))
	}
	for _, m := range res.mismatches {
		out.printf("%s %s live %s approved %s: the gateway serves a definition whose digest differs from the approved one; this may be the gateway re-serialising unknown fields, or drift since the last crawl, and the processor hides the tool either way\n",
			verdictMismatch, cell(m.name), shortDigest(m.digest), shortDigest(snap.Tools[m.name].Approved))
	}
	for _, name := range res.missing {
		out.printf("%s %s %s\n", verdictMissing, cell(name), shortDigest(snap.Tools[name].Approved))
	}
}
