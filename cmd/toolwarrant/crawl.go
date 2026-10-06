package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/crawl"
	"github.com/sairam0424/toolwarrant/internal/fetch"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

const (
	headerAuthorization = "Authorization"
	bearerScheme        = "Bearer "
	// Error classes stored for a failed crawl. Only the class and an HTTP
	// status are kept: the raw error can echo the URL (with its query), the
	// response body or a header, and the crawls table is read by operators.
	classUnknown    = "unknown error"
	classTimeout    = "timeout"
	classCancelled  = "cancelled"
	classDNS        = "dns lookup failed"
	classRefused    = "connection refused"
	classConnection = "connection failed"
)

// crawler holds what one crawl of one server needs.
type crawler struct {
	store   *catalog.Store
	server  catalog.Server
	client  *http.Client
	headers http.Header
	actor   catalog.Actor
	asJSON  bool
	out     io.Writer
}

// crawlJSON is the machine-readable crawl report.
type crawlJSON struct {
	Server   string       `json:"server"`
	CrawlID  int64        `json:"crawl_id"`
	Complete bool         `json:"complete"`
	Error    string       `json:"error,omitempty"`
	Changes  []changeJSON `json:"changes"`
}

type changeJSON struct {
	Tool    string `json:"tool"`
	Kind    string `json:"kind"`
	State   string `json:"state"`
	Digest  string `json:"digest"`
	Drifted bool   `json:"drifted"`
}

// crawlFailure is a listing that failed and was recorded as incomplete.
type crawlFailure struct{ server, class string }

func (e *crawlFailure) Error() string {
	return fmt.Sprintf("crawl of %s failed: %s; the failure was recorded and no tool changed", e.server, e.class)
}

// runCrawl fetches every tool of one upstream and records the result. Without
// --as it runs as the system crawler; with --as the named person proposes the
// versions and therefore cannot approve them.
func runCrawl(a *app, c *command, args []string) error {
	fs := newFlagSet(c.name)
	every := fs.Duration("every", 0, "repeat at this interval until SIGINT or SIGTERM, one line per crawl")
	bearerEnv := fs.String("bearer-env", "", "environment variable holding a bearer token for Authorization (never printed or stored)")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos, "SERVER"); err != nil {
		return err
	}
	if *every < 0 {
		return &usageError{msg: "--every must be a positive duration", cmd: c}
	}
	headers, err := bearerHeader(c, a.getenv, *bearerEnv)
	if err != nil {
		return err
	}
	actor, err := a.actor(true)
	if err != nil {
		return err
	}
	store, err := a.openStore(false)
	if err != nil {
		return err
	}
	defer store.Close()
	cr, err := newCrawler(a, store, pos[0], headers, actor, *asJSON)
	if err != nil {
		return err
	}
	if *every == 0 {
		report, err := cr.crawl(a.ctx)
		if err != nil {
			return err
		}
		return cr.printReport(report)
	}
	return cr.loop(a.ctx, *every)
}

func newCrawler(a *app, store *catalog.Store, server string, headers http.Header, actor catalog.Actor, asJSON bool) (*crawler, error) {
	srv, err := store.Server(a.ctx, server)
	if err != nil {
		return nil, err
	}
	client, err := fetch.NewClient(fetch.Policy{AllowPrivate: srv.AllowPrivate})
	if err != nil {
		return nil, fmt.Errorf("build egress client: %w", err)
	}
	return &crawler{store: store, server: srv, client: client, headers: headers, actor: actor, asJSON: asJSON, out: a.stdout}, nil
}

// bearerHeader builds the Authorization header from the named variable. The
// value is checked for line breaks so it cannot smuggle a second header.
func bearerHeader(c *command, getenv func(string) string, name string) (http.Header, error) {
	if name == "" {
		return nil, nil
	}
	token := getenv(name)
	if token == "" {
		return nil, &usageError{msg: fmt.Sprintf("environment variable %s is unset or empty", textdiff.Escape(name)), cmd: c}
	}
	if strings.ContainsAny(token, "\r\n") {
		return nil, &usageError{msg: fmt.Sprintf("the token in %s contains a line break", textdiff.Escape(name)), cmd: c}
	}
	h := http.Header{}
	h.Set(headerAuthorization, bearerScheme+token)
	return h, nil
}

// crawl lists the upstream and records the outcome. A listing failure is
// recorded as an incomplete crawl carrying only the error class, then
// returned; an interrupted crawl is not recorded at all.
func (cr *crawler) crawl(ctx context.Context) (catalog.CrawlReport, error) {
	opts := crawl.Options{Client: cr.client, Headers: cr.headers, ClientName: programName, ClientVersion: version}
	res, err := crawl.ListTools(ctx, cr.server.URL, opts)
	if err != nil {
		if ctx.Err() != nil {
			return catalog.CrawlReport{}, fmt.Errorf("crawl of %s: %w", cr.server.Name, ctx.Err())
		}
		class := scrubCrawlError(err)
		failure := catalog.CrawlInput{Server: cr.server.Name, Complete: false, Error: class}
		if _, rerr := cr.store.RecordCrawl(ctx, failure, cr.actor); rerr != nil {
			return catalog.CrawlReport{}, fmt.Errorf("crawl of %s failed (%s) and recording the failure failed too: %w", cr.server.Name, class, rerr)
		}
		return catalog.CrawlReport{}, &crawlFailure{server: cr.server.Name, class: class}
	}
	in := catalog.CrawlInput{Server: cr.server.Name, Complete: true, Tools: crawledTools(res.Tools)}
	report, err := cr.store.RecordCrawl(ctx, in, cr.actor)
	if err != nil {
		return catalog.CrawlReport{}, fmt.Errorf("record crawl of %s: %w", cr.server.Name, err)
	}
	return report, nil
}

func crawledTools(tools []crawl.Tool) []catalog.CrawledTool {
	out := make([]catalog.CrawledTool, 0, len(tools))
	for _, t := range tools {
		out = append(out, catalog.CrawledTool{Name: t.Name, Raw: []byte(t.Raw)})
	}
	return out
}

// scrubCrawlError reduces a listing error to a class that is safe to store and
// print. It never returns the error text.
func scrubCrawlError(err error) string {
	var status *crawl.HTTPStatusError
	var rpc *crawl.RPCError
	var dns *net.DNSError
	var netErr net.Error
	var opErr *net.OpError
	switch {
	case errors.As(err, &status):
		return fmt.Sprintf("http status %d", status.Status)
	case errors.As(err, &rpc):
		return fmt.Sprintf("json-rpc error %d", rpc.Code)
	case errors.Is(err, context.DeadlineExceeded):
		return classTimeout
	case errors.Is(err, context.Canceled):
		return classCancelled
	case errors.As(err, &dns):
		return classDNS
	case errors.Is(err, syscall.ECONNREFUSED):
		return classRefused
	}
	if class, ok := sentinelClass(err); ok {
		return class
	}
	switch {
	case errors.As(err, &netErr) && netErr.Timeout():
		return classTimeout
	case errors.As(err, &opErr):
		return classConnection
	}
	return classUnknown
}

// sentinelClass names the fetch and crawl policy refusals.
func sentinelClass(err error) (string, bool) {
	classes := []struct {
		sentinel error
		class    string
	}{
		{fetch.ErrBlockedAddress, "egress policy: address not allowed"},
		{fetch.ErrBlockedHost, "egress policy: host not allowed"},
		{fetch.ErrBlockedScheme, "egress policy: scheme not allowed"},
		{fetch.ErrRedirect, "egress policy: redirect refused"},
		{fetch.ErrTooLarge, "response too large"},
		{crawl.ErrTooManyPages, "too many pages"},
		{crawl.ErrTooManyTools, "too many tools"},
		{crawl.ErrCursorLoop, "pagination cursor loop"},
		{crawl.ErrDuplicateTool, "duplicate tool name"},
		{crawl.ErrMalformed, "malformed server response"},
		{crawl.ErrInvalidOptions, "invalid crawl options"},
	}
	for _, c := range classes {
		if errors.Is(err, c.sentinel) {
			return c.class, true
		}
	}
	return "", false
}

// loop crawls until the context ends, surviving failures: an upstream that is
// down for a while must not stop the schedule.
func (cr *crawler) loop(ctx context.Context, every time.Duration) error {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		report, err := cr.crawl(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err := cr.printLine(report, err); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// printLine writes the one-line summary of a scheduled crawl.
func (cr *crawler) printLine(report catalog.CrawlReport, err error) error {
	if cr.asJSON {
		return writeCompactJSON(cr.out, cr.toJSON(report, err))
	}
	stamp := time.Now().UTC().Format(time.RFC3339)
	if err != nil {
		_, werr := fmt.Fprintf(cr.out, "%s %s: %s\n", stamp, cell(cr.server.Name), describe(err))
		return werr
	}
	_, werr := fmt.Fprintf(cr.out, "%s %s: crawl %d complete, %d tools, %s\n",
		stamp, cell(cr.server.Name), report.CrawlID, len(report.Changes), summarize(report.Changes))
	return werr
}

// printReport writes the full report of a single crawl: one line per tool with
// the change kind in upper case when a person should look at it.
func (cr *crawler) printReport(report catalog.CrawlReport) error {
	if cr.asJSON {
		return writeJSON(cr.out, cr.toJSON(report, nil))
	}
	fmt.Fprintf(cr.out, "crawl %d of %s complete: %d tools, %s\n", report.CrawlID, cell(cr.server.Name), len(report.Changes), summarize(report.Changes))
	if len(report.Changes) == 0 {
		return nil
	}
	t := newTable(cr.out)
	t.row("CHANGE", "TOOL", "STATE", "LIVE", "FLAGS")
	for _, ch := range report.Changes {
		t.row(changeLabel(ch), cell(ch.Tool), string(ch.State), shortDigest(ch.Digest), driftFlag(ch))
	}
	return t.flush()
}

// changeLabel highlights what needs attention: a new or changed definition.
func changeLabel(ch catalog.ToolChange) string {
	switch ch.Kind {
	case catalog.ChangeNew, catalog.ChangeChanged, catalog.ChangeReappeared:
		return strings.ToUpper(string(ch.Kind))
	}
	return string(ch.Kind)
}

func driftFlag(ch catalog.ToolChange) string {
	if ch.State == lifecycle.ChangedPendingReapproval {
		return flagDrift
	}
	return ""
}

// summarize counts the changes by kind in a fixed order, so the line is
// readable and stable.
func summarize(changes []catalog.ToolChange) string {
	counts := map[catalog.ChangeKind]int{}
	for _, ch := range changes {
		counts[ch.Kind]++
	}
	order := []catalog.ChangeKind{catalog.ChangeNew, catalog.ChangeChanged, catalog.ChangeReappeared, catalog.ChangeReverted,
		catalog.ChangeMissing, catalog.ChangeDeprecated, catalog.ChangeUnchanged}
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
	out := crawlJSON{Server: cr.server.Name, CrawlID: report.CrawlID, Complete: report.Complete, Changes: []changeJSON{}}
	if err != nil {
		out.Error = err.Error()
	}
	for _, ch := range report.Changes {
		out.Changes = append(out.Changes, changeJSON{Tool: ch.Tool, Kind: string(ch.Kind), State: string(ch.State),
			Digest: ch.Digest, Drifted: ch.State == lifecycle.ChangedPendingReapproval})
	}
	return out
}
