package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/crawl"
	"github.com/sairam0424/toolwarrant/internal/fetch"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

const (
	headerAuthorization = "Authorization"
	bearerScheme        = "Bearer "
	// minEvery bounds the repeat interval of crawl and verify-gateway: a tiny
	// interval hammers an upstream and writes one crawls row per iteration.
	minEvery = time.Second
	// Error classes stored for a failed crawl. Only the class and an HTTP
	// status are kept: the raw error can echo the URL (with its query), the
	// response body or a header, and the crawls table is read by operators.
	// The catalog stores a class verbatim only when it is lower-case words
	// (letters, digits, "._-") separated by single spaces and at most 64
	// bytes; anything else it quotes as free text, so every class here keeps
	// to that shape (no colons).
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
	strict  bool
	out     *stream
}

// crawlFailure is a listing that failed and was recorded as incomplete.
// refused marks the one the catalog turned down as a whole (a cap), as
// opposed to an upstream that could not be listed: a schedule counts the two
// apart, because a refusal means rows that were never recorded.
type crawlFailure struct {
	server, class string
	refused       bool
}

func (e *crawlFailure) Error() string {
	return fmt.Sprintf("crawl of %s failed: %s; the failure was recorded and no tool changed", e.server, e.class)
}

// strictFailure is a complete, recorded crawl that --strict refuses because
// the upstream listed something that cannot be served.
type strictFailure struct {
	server             string
	rejected, unusable int
}

func (e *strictFailure) Error() string {
	return fmt.Sprintf("crawl of %s was recorded, but --strict refuses it: %d rejected and %d unusable tool(s), listed above", e.server, e.rejected, e.unusable)
}

// runCrawl fetches every tool of one upstream and records the result. Without
// --as it runs as the system crawler; with --as the named person proposes the
// versions and therefore cannot approve them.
func runCrawl(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	every := fs.Duration("every", 0, "repeat at this interval (at least 1s) until SIGINT or SIGTERM, one line per crawl")
	bearerEnv := fs.String("bearer-env", "", "environment variable holding a bearer token for Authorization (never printed or stored)")
	strict := fs.Bool("strict", false, "exit 1 when the crawl reports a rejected or unusable tool (with --every: stop at the first such crawl)")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos, "SERVER"); err != nil {
		return err
	}
	if err := checkEvery(c, *every); err != nil {
		return err
	}
	headers, err := bearerHeader(c, a.getenv, *bearerEnv)
	if err != nil {
		return err
	}
	actor, err := a.actor(true)
	if err != nil {
		return err
	}
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	cr, err := newCrawler(a, store, pos[0], headers, actor, *asJSON, *strict)
	if err != nil {
		return err
	}
	if *every == 0 {
		report, err := cr.crawl(a.ctx)
		if err != nil {
			return err
		}
		if err := cr.printReport(report); err != nil {
			return err
		}
		return cr.checkStrict(report)
	}
	return cr.loop(a.ctx, *every)
}

// checkEvery enforces the repeat interval's lower bound; zero means once.
func checkEvery(c *command, every time.Duration) error {
	if every == 0 || every >= minEvery {
		return nil
	}
	return &usageError{msg: fmt.Sprintf("--every must be at least %s", minEvery), cmd: c}
}

func newCrawler(a *app, store *catalog.Store, server string, headers http.Header, actor catalog.Actor, asJSON, strict bool) (*crawler, error) {
	srv, err := store.Server(a.ctx, server)
	if err != nil {
		return nil, err
	}
	client, err := fetch.NewClient(fetch.Policy{AllowPrivate: srv.AllowPrivate})
	if err != nil {
		return nil, fmt.Errorf("build egress client: %w", err)
	}
	return &crawler{store: store, server: srv, client: client, headers: headers, actor: actor, asJSON: asJSON, strict: strict, out: a.stdout}, nil
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

// crawl lists the upstream and records the outcome. Every listing of an
// unpaused server is recorded: a complete one with its usable and unusable
// tools, a failed one as an incomplete crawl carrying only the error class,
// which is then returned. An interrupted crawl is not recorded at all, and a
// paused server is not contacted.
//
// The crawler's neutral default clientInfo is deliberately kept: announcing
// the program name would let an upstream tell the crawler from the gateway
// and show each a different definition. The processor's check of the live
// listing is the real defence against that, but a crawler that does not
// introduce itself costs nothing and removes the easiest tell.
func (cr *crawler) crawl(ctx context.Context) (catalog.CrawlReport, error) {
	srv, err := cr.store.Server(ctx, cr.server.Name)
	if err != nil {
		return catalog.CrawlReport{}, err
	}
	if srv.Paused {
		return catalog.CrawlReport{}, fmt.Errorf("crawl of %s: %w", cr.server.Name, catalog.ErrPaused)
	}
	res, err := crawl.ListTools(ctx, srv.URL, crawl.Options{Client: cr.client, Headers: cr.headers})
	if err != nil {
		if ctx.Err() != nil {
			return catalog.CrawlReport{}, fmt.Errorf("crawl of %s: %w", cr.server.Name, ctx.Err())
		}
		return cr.recordFailure(ctx, scrubCrawlError(err))
	}
	in := catalog.CrawlInput{Server: cr.server.Name, Complete: true, Tools: crawledTools(res.Tools), Unusable: unusableTools(res.Unusable)}
	report, err := cr.store.RecordCrawl(ctx, in, cr.actor)
	if err != nil {
		return catalog.CrawlReport{}, fmt.Errorf("record crawl of %s: %w", cr.server.Name, err)
	}
	if !report.Complete {
		// the catalog refused the listing as a whole (a cap) and recorded that
		return report, &crawlFailure{server: cr.server.Name, class: report.Error, refused: true}
	}
	return report, nil
}

// recordFailure stores an incomplete crawl under its class and returns the
// failure, so a crawl that could not list is still visible in the history.
func (cr *crawler) recordFailure(ctx context.Context, class string) (catalog.CrawlReport, error) {
	failure := catalog.CrawlInput{Server: cr.server.Name, Complete: false, Error: class}
	report, err := cr.store.RecordCrawl(ctx, failure, cr.actor)
	if err != nil {
		return catalog.CrawlReport{}, fmt.Errorf("crawl of %s failed (%s) and recording the failure failed too: %w", cr.server.Name, class, err)
	}
	return report, &crawlFailure{server: cr.server.Name, class: class}
}

func crawledTools(tools []crawl.Tool) []catalog.CrawledTool {
	out := make([]catalog.CrawledTool, 0, len(tools))
	for _, t := range tools {
		out = append(out, catalog.CrawledTool{Name: t.Name, Raw: []byte(t.Raw)})
	}
	return out
}

// unusableTools hands the crawler's quarantine to the catalog, which marks a
// known tool of that name unusable and records an unknown one as rejected.
func unusableTools(list []crawl.UnusableTool) []catalog.UnusableTool {
	out := make([]catalog.UnusableTool, 0, len(list))
	for _, u := range list {
		out = append(out, catalog.UnusableTool{Name: u.Name, Reason: string(u.Reason), Detail: u.Detail})
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
		{fetch.ErrBlockedAddress, "egress policy address not allowed"},
		{fetch.ErrBlockedHost, "egress policy host not allowed"},
		{fetch.ErrBlockedScheme, "egress policy scheme not allowed"},
		{fetch.ErrRedirect, "egress policy redirect refused"},
		{fetch.ErrTooLarge, "response too large"},
		{crawl.ErrTooManyPages, "too many pages"},
		{crawl.ErrTooManyTools, "too many tools"},
		{crawl.ErrTooLarge, "tool definitions too large"},
		{crawl.ErrCursorLoop, "pagination cursor loop"},
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

// checkStrict is the --strict rule: a crawl that reports a rejected entry or
// an unusable observation fails, after the report was printed and recorded.
func (cr *crawler) checkStrict(report catalog.CrawlReport) error {
	if !cr.strict {
		return nil
	}
	unusable := countUnusable(report.Changes)
	if len(report.Rejected) == 0 && unusable == 0 {
		return nil
	}
	return &strictFailure{server: cr.server.Name, rejected: len(report.Rejected), unusable: unusable}
}
