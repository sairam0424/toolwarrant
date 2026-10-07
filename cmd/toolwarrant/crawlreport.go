package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// crawlJSON is the machine-readable crawl report.
type crawlJSON struct {
	Server   string         `json:"server"`
	CrawlID  int64          `json:"crawl_id"`
	Complete bool           `json:"complete"`
	Error    string         `json:"error,omitempty"`
	Changes  []changeJSON   `json:"changes"`
	Rejected []rejectedJSON `json:"rejected"`
}

// changeJSON is one tool's line of the report. Unusable means the upstream
// listed the tool with a definition that cannot be served; Reason says why.
type changeJSON struct {
	Tool     string `json:"tool"`
	Kind     string `json:"kind"`
	State    string `json:"state"`
	Digest   string `json:"digest"`
	Drifted  bool   `json:"drifted"`
	Unusable bool   `json:"unusable"`
	Reason   string `json:"reason,omitempty"`
}

// rejectedJSON is a listed entry that no tool row records. Name is empty when
// the name itself broke the rule.
type rejectedJSON struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

// printLine writes the one-line summary of a scheduled crawl.
func (cr *crawler) printLine(report catalog.CrawlReport, err error) error {
	if cr.asJSON {
		return writeCompactJSON(cr.out, cr.toJSON(report, err))
	}
	stamp := time.Now().UTC().Format(time.RFC3339)
	if err != nil {
		cr.out.printf("%s %s: %s\n", stamp, cell(cr.server.Name), describe(err))
		return cr.out.broken()
	}
	cr.out.printf("%s %s: crawl %d complete, %d tools, %s%s\n",
		stamp, cell(cr.server.Name), report.CrawlID, len(report.Changes), summarize(report.Changes), rejectedSuffix(report.Rejected))
	return cr.out.broken()
}

// printReport writes the full report of a single crawl: one line per tool with
// the change kind in upper case when a person should look at it, then every
// rejected entry.
func (cr *crawler) printReport(report catalog.CrawlReport) error {
	if cr.asJSON {
		return writeJSON(cr.out, cr.toJSON(report, nil))
	}
	cr.out.printf("crawl %d of %s complete: %d tools, %s%s\n",
		report.CrawlID, cell(cr.server.Name), len(report.Changes), summarize(report.Changes), rejectedSuffix(report.Rejected))
	if len(report.Changes) > 0 {
		t := newTable(cr.out)
		t.row("CHANGE", "TOOL", "STATE", "LIVE", "FLAGS", "REASON")
		for _, ch := range report.Changes {
			t.row(changeLabel(ch), cell(ch.Tool), string(ch.State), liveCell(ch), changeFlags(ch), cell(ch.Reason))
		}
		if err := t.flush(); err != nil {
			return err
		}
	}
	cr.printRejected(report.Rejected)
	return cr.out.broken()
}

// printRejected lists the entries no tool row records. A name is shown only
// when the catalog kept it; a refused name is withheld entirely so that a
// look-alike is never displayed. The reason and detail are fixed words (a
// code point, a size against its cap) and are escaped anyway.
func (cr *crawler) printRejected(rejected []catalog.RejectedTool) {
	for _, r := range rejected {
		name := nameWithheld
		if r.Name != "" {
			name = cell(r.Name)
		}
		cr.out.printf("REJECTED %s: %s (%s)\n", name, cell(r.Reason), cell(r.Detail))
	}
}

// rejectedSuffix extends the summary line when entries were rejected.
func rejectedSuffix(rejected []catalog.RejectedTool) string {
	if len(rejected) == 0 {
		return ""
	}
	return fmt.Sprintf(", %d rejected", len(rejected))
}

// isUnusable reports whether a change is an unusable observation: the catalog
// sets Reason exactly then, whatever kind the classifier picked.
func isUnusable(ch catalog.ToolChange) bool {
	return ch.Reason != "" || ch.Kind == catalog.ChangeUnusable
}

// countUnusable counts the unusable observations of one crawl.
func countUnusable(changes []catalog.ToolChange) int {
	n := 0
	for _, ch := range changes {
		if isUnusable(ch) {
			n++
		}
	}
	return n
}

// liveCell shows what the upstream serves for the tool: a digest, the unusable
// marker, or nothing when the tool was absent.
func liveCell(ch catalog.ToolChange) string {
	if isUnusable(ch) {
		return lifecycle.UnusableDigest
	}
	return shortDigest(ch.Digest)
}

// changeLabel highlights what needs attention: a new, changed, returned-from-
// deprecation or unusable definition.
func changeLabel(ch catalog.ToolChange) string {
	switch ch.Kind {
	case catalog.ChangeNew, catalog.ChangeChanged, catalog.ChangeReappeared, catalog.ChangeUnusable:
		return strings.ToUpper(string(ch.Kind))
	}
	return string(ch.Kind)
}

// changeFlags marks the conditions that need a person after this crawl.
func changeFlags(ch catalog.ToolChange) string {
	var flags []string
	if ch.State == lifecycle.ChangedPendingReapproval {
		flags = append(flags, flagDrift)
	}
	if isUnusable(ch) {
		flags = append(flags, flagUnusable)
	}
	return strings.Join(flags, ",")
}

// summarize counts the changes by kind in a fixed order, so the line is
// readable and stable.
func summarize(changes []catalog.ToolChange) string {
	counts := map[catalog.ChangeKind]int{}
	for _, ch := range changes {
		counts[ch.Kind]++
	}
	order := []catalog.ChangeKind{catalog.ChangeNew, catalog.ChangeChanged, catalog.ChangeReappeared, catalog.ChangeReturned,
		catalog.ChangeReverted, catalog.ChangeUnusable, catalog.ChangeMissing, catalog.ChangeDeprecated, catalog.ChangeUnchanged}
	parts := make([]string, 0, len(order))
	for _, k := range order {
		if counts[k] > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
		}
	}
	if len(parts) == 0 {
		return "no changes"
	}
	return strings.Join(parts, " ")
}

func (cr *crawler) toJSON(report catalog.CrawlReport, err error) crawlJSON {
	out := crawlJSON{Server: cr.server.Name, CrawlID: report.CrawlID, Complete: report.Complete, Error: report.Error,
		Changes: []changeJSON{}, Rejected: []rejectedJSON{}}
	if err != nil {
		out.Error = err.Error()
	}
	for _, ch := range report.Changes {
		out.Changes = append(out.Changes, changeJSON{Tool: ch.Tool, Kind: string(ch.Kind), State: string(ch.State), Digest: ch.Digest,
			Drifted: ch.State == lifecycle.ChangedPendingReapproval, Unusable: isUnusable(ch), Reason: ch.Reason})
	}
	for _, r := range report.Rejected {
		out.Rejected = append(out.Rejected, rejectedJSON{Name: r.Name, Reason: r.Reason, Detail: r.Detail})
	}
	return out
}
