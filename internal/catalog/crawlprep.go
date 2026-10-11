package catalog

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/toolname"
)

// Whole-crawl failure classes: the listing as a whole breaks a cap, so no tool
// is observed and the crawl is recorded as failed under this class.
const (
	failureTooManyTools = "too-many-tools"
	failureTooLarge     = "too-large"
	// failureRejectedCap is the class of a listing with more entries to reject
	// than MaxRejectedPerCrawl allows.
	failureRejectedCap = "rejected-cap"
	// failureError is the class of caller text that is not itself a class.
	failureError = "error"
)

// rejection is one listed entry the catalog cannot observe as a definition.
type rejection struct {
	name   string // "" when the name itself was refused and must not be shown
	reason string
	detail string
}

// listing is the content of one complete crawl after validation, computed
// outside the write lock. Every entry the upstream listed lands in exactly one
// place: usable (a definition to observe), unusable (a valid name whose
// definition cannot be used), or nameless (a name the shared rule refuses).
type listing struct {
	usable   []preparedTool // sorted by name, unique
	unusable map[string]rejection
	nameless []rejection
	count    int    // entries the upstream listed
	failure  string // whole-crawl failure class, "" when the listing is fine
}

// prepareListing validates a complete crawl per tool (D3). It never refuses
// the crawl because of one tool: a hostile name or definition is quarantined
// so that every other tool is still observed and LastSeen never freezes.
func prepareListing(in CrawlInput) listing {
	ls := listing{unusable: map[string]rejection{}, count: len(in.Tools) + len(in.Unusable)}
	if ls.count > MaxToolsPerCrawl {
		ls.failure = failureTooManyTools
		return ls
	}
	total := 0
	for _, ct := range in.Tools {
		if total += len(ct.Raw); total > MaxCrawlBytes {
			ls.failure = failureTooLarge
			return ls
		}
	}
	seen := countNames(in)
	for _, ct := range in.Tools {
		ls.addListed(ct, seen[ct.Name])
	}
	for _, ut := range in.Unusable {
		ls.addUnusable(ut, seen[ut.Name])
	}
	sort.Slice(ls.usable, func(i, j int) bool { return ls.usable[i].name < ls.usable[j].name })
	return ls
}

// countNames counts how often each name is listed, across usable and unusable
// entries alike, so that every copy of a repeated name can be quarantined.
func countNames(in CrawlInput) map[string]int {
	seen := make(map[string]int, len(in.Tools)+len(in.Unusable))
	for _, ct := range in.Tools {
		seen[ct.Name]++
	}
	for _, ut := range in.Unusable {
		if ut.Name != "" {
			seen[ut.Name]++
		}
	}
	return seen
}

// addListed places one crawled definition.
func (ls *listing) addListed(ct CrawledTool, copies int) {
	if err := toolname.Validate(ct.Name); err != nil {
		ls.nameless = append(ls.nameless, rejection{reason: reasonInvalidName, detail: nameDetail(err)})
		return
	}
	if copies > 1 {
		ls.markUnusable(ct.Name, reasonDuplicateName, fmt.Sprintf("the name is listed %d times", copies))
		return
	}
	p, terr := prepareTool(ct)
	if terr != nil {
		ls.markUnusable(ct.Name, terr.reason, terr.detail)
		return
	}
	ls.usable = append(ls.usable, p)
}

// addUnusable places one entry the crawler already found unusable. Its reason
// and detail are the crawler's words, reduced to a token and a bounded,
// sanitised string: the catalog does not trust even its own crawler to keep
// upstream bytes out.
func (ls *listing) addUnusable(ut UnusableTool, copies int) {
	reason := classOf(ut.Reason, reasonUnusable)
	detail := sanitizeText(ut.Detail, maxDetailBytes)
	if ut.Name == "" || toolname.Validate(ut.Name) != nil {
		ls.nameless = append(ls.nameless, rejection{reason: reason, detail: detail})
		return
	}
	if copies > 1 {
		ls.markUnusable(ut.Name, reasonDuplicateName, fmt.Sprintf("the name is listed %d times", copies))
		return
	}
	ls.markUnusable(ut.Name, reason, detail)
}

// markUnusable records the first verdict on a valid name; later copies of a
// repeated name add nothing.
func (ls *listing) markUnusable(name, reason, detail string) {
	if _, done := ls.unusable[name]; done {
		return
	}
	ls.unusable[name] = rejection{name: name, reason: reason, detail: detail}
}

// nameDetail turns a toolname error into a detail string. The package never
// echoes the name, so the message is safe; only its sentinel prefix is dropped.
func nameDetail(err error) string {
	return strings.TrimPrefix(err.Error(), toolname.ErrInvalid.Error()+": ")
}

// names returns every valid name the listing carries, usable and unusable:
// the tools a crawl has to load, deprecated or not.
func (ls *listing) names() []string {
	names := make([]string, 0, len(ls.usable)+len(ls.unusable))
	for i := range ls.usable {
		names = append(names, ls.usable[i].name)
	}
	for name := range ls.unusable {
		names = append(names, name)
	}
	return names
}

// rejectedCount counts the entries the crawl would record as rejected: every
// nameless entry and every unusable name that no tool row of the server
// describes (known holds the server's loaded tools). A known tool listed with
// an unusable definition is observed, not rejected, and is not counted.
func (ls *listing) rejectedCount(known map[string]*toolRec) int {
	n := len(ls.nameless)
	for name := range ls.unusable {
		if known[name] == nil {
			n++
		}
	}
	return n
}

// usableByName returns the prepared definition listed under name, if any.
func (ls *listing) usableByName(name string) *preparedTool {
	i := sort.Search(len(ls.usable), func(i int) bool { return ls.usable[i].name >= name })
	if i < len(ls.usable) && ls.usable[i].name == name {
		return &ls.usable[i]
	}
	return nil
}

// rejected converts a rejection into the report line the caller sees.
func (r rejection) rejected() RejectedTool {
	return RejectedTool{Name: r.name, Reason: r.reason, Detail: r.detail}
}

// auditName renders a rejected name for an audit detail: quoted when it passed
// the shared rule, a fixed marker otherwise, so the log never carries a name
// that could render as another one.
func (r rejection) auditName() string {
	if r.name == "" {
		return "<unprintable>"
	}
	return strconv.Quote(r.name)
}

// errorClass reduces the caller's crawl error to a class token for the audit
// log: the text itself when it already is one (the CLI passes classes such as
// "timeout"), failureError otherwise. Raw text never reaches the log.
func errorClass(text string) string {
	return classOf(text, failureError)
}

// crawlErrorRecord is what the crawls table keeps about a failed crawl: the
// class, followed by a quoted, sanitised and length-capped fragment of the
// caller's text when that text was not itself a class. The fragment can echo a
// request URL, which is why it lives in the crawls table only and never in the
// audit log, and why it is quoted: nothing in it can reach a terminal raw.
func crawlErrorRecord(text, failure string) string {
	if failure != "" {
		return failure
	}
	trimmed := strings.TrimSpace(text)
	switch {
	case trimmed == "":
		return ""
	case isClassToken(trimmed):
		return trimmed
	}
	return failureError + " " + strconv.Quote(sanitizeText(trimmed, maxCrawlErrorBytes))
}
