package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/crawl"
	"github.com/sairam0424/toolwarrant/internal/emit"
	"github.com/sairam0424/toolwarrant/internal/fetch"
	"github.com/sairam0424/toolwarrant/internal/gate"
)

// verifier holds what one deploy-time check of one gateway route needs.
type verifier struct {
	a       *app
	store   *catalog.Store
	server  string
	url     string
	headers http.Header
	config  string // emitted configuration file to verify, "" for none
}

// verifyFailure is a check that found the gateway serving what the catalog
// would hide, or running a configuration that is not the emitted one.
type verifyFailure struct {
	leaks        int
	configEdited bool
	server, url  string
}

func (e *verifyFailure) Error() string {
	var parts []string
	if e.leaks > 0 {
		parts = append(parts, fmt.Sprintf("%d tool(s) leak: the gateway at %s serves definitions the catalog would not; check that the route for %s has the toolwarrant processor", e.leaks, safeURL(e.url), e.server))
	}
	if e.configEdited {
		parts = append(parts, "the gateway configuration was edited after emit wrote it; run emit again and reload the gateway")
	}
	return joinSentences(parts)
}

// joinSentences joins sentences with "; ".
func joinSentences(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "; "
		}
		out += p
	}
	return out
}

// runVerifyGateway is the deploy-time self-test: it lists tools through the
// gateway like a client would and compares each one with the catalog's
// serving policy. With --every it repeats, opening a fresh MCP session each
// time so that a gateway which reloaded between checks is seen as it is now.
func runVerifyGateway(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	server := fs.String("server", "", "catalog server the gateway route is for (required)")
	gatewayURL := fs.String("url", "", "MCP endpoint of the gateway route to test (required)")
	bearerEnv := fs.String("bearer-env", "", "environment variable holding a bearer token for Authorization (never printed)")
	configPath := fs.String("config", "", "gateway configuration file written by emit; CONFIG-EDITED when it is no longer the file emit wrote")
	every := fs.Duration("every", 0, "repeat at this interval (at least 1s) with a fresh MCP session each time, until SIGINT or SIGTERM")
	keepGoing := fs.Bool("keep-going", false, "with --every, keep checking after a LEAK or CONFIG-EDITED instead of exiting at the first one")
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos); err != nil {
		return err
	}
	if err := requireFlag(c, *server, "server", "name the catalog server"); err != nil {
		return err
	}
	if err := requireFlag(c, *gatewayURL, "url", "give the gateway endpoint to list through"); err != nil {
		return err
	}
	if err := checkEvery(c, *every); err != nil {
		return err
	}
	headers, err := bearerHeader(c, a.getenv, *bearerEnv)
	if err != nil {
		return err
	}
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	v := &verifier{a: a, store: store, server: *server, url: *gatewayURL, headers: headers, config: *configPath}
	if *every == 0 {
		res, err := v.check(a.ctx)
		if err != nil {
			return err
		}
		return v.conclude(res)
	}
	return v.loop(a.ctx, *every, *keepGoing)
}

// check runs one comparison and prints its verdict lines. The catalog is read
// first, so an unknown server is reported before anything is fetched.
func (v *verifier) check(ctx context.Context) (verdicts, error) {
	snap, err := v.store.Snapshot(ctx, v.server)
	if err != nil {
		return verdicts{}, err
	}
	var res verdicts
	if v.config != "" {
		if res.configHash, res.configEdited, err = configEdited(v.config); err != nil {
			return verdicts{}, err
		}
	}
	live, err := listThroughGateway(ctx, v.url, v.headers)
	if err != nil {
		return verdicts{}, err
	}
	compare(snap, live, &res)
	v.print(res, snap)
	return res, v.a.stdout.broken()
}

// configEdited reads the emitted file and checks its integrity header. Any
// edit, a missing header or a reformatted copy counts as edited: a route whose
// processor entry was removed fails open for every new session, so the file
// must be exactly what emit wrote.
func configEdited(path string) (bodyHash string, edited bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false, fmt.Errorf("read gateway config: %w", err)
	}
	hash, ok := emit.Verify(data)
	return hash, !ok, nil
}

// conclude turns one check into the command's outcome: LEAK and CONFIG-EDITED
// fail; MISMATCH and MISSING are reported but do not, because neither means
// the gateway serves something the catalog would hide.
func (v *verifier) conclude(res verdicts) error {
	if res.failed() {
		return &verifyFailure{leaks: len(res.leaks), configEdited: res.configEdited, server: v.server, url: v.url}
	}
	v.a.stdout.printf("%s: %s\n", verdictOK, res.summary())
	return v.a.stdout.broken()
}

// loop repeats the check until the context ends. A listing failure (the
// gateway is down for a while) is printed and does not stop the schedule; a
// LEAK or CONFIG-EDITED stops it unless keepGoing, in which case the run as a
// whole still fails at the end if anything leaked.
func (v *verifier) loop(ctx context.Context, every time.Duration, keepGoing bool) error {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	leaked := false
	for {
		res, err := v.check(ctx)
		if ctx.Err() != nil {
			break
		}
		stamp := time.Now().UTC().Format(time.RFC3339)
		switch {
		case err != nil:
			v.a.stdout.printf("%s %s: check failed: %s\n", stamp, cell(v.server), describe(err))
		case res.failed() && !keepGoing:
			return v.conclude(res)
		default:
			leaked = leaked || res.failed()
			v.a.stdout.printf("%s %s: %s\n", stamp, cell(v.server), res.summary())
		}
		if werr := v.a.stdout.broken(); werr != nil {
			return werr
		}
		select {
		case <-ctx.Done():
			return v.loopOutcome(leaked)
		case <-ticker.C:
		}
	}
	return v.loopOutcome(leaked)
}

// loopOutcome is the exit of a --keep-going run.
func (v *verifier) loopOutcome(leaked bool) error {
	if leaked {
		return errors.New("at least one check of this run found a LEAK or CONFIG-EDITED, listed above")
	}
	return nil
}

// listThroughGateway lists the route with the hardened client in a fresh MCP
// session. The gateway is the operator's own and usually local, so private
// addresses are allowed. A listing error is reduced to its class, never
// wrapped: the raw text could carry the URL. The neutral default clientInfo
// is kept for the same reason as in crawl.
func listThroughGateway(ctx context.Context, url string, headers http.Header) ([]liveTool, error) {
	client, err := fetch.NewClient(fetch.Policy{AllowPrivate: true})
	if err != nil {
		return nil, fmt.Errorf("build client: %w", err)
	}
	res, err := crawl.ListTools(ctx, url, crawl.Options{Client: client, Headers: headers})
	if err != nil {
		return nil, fmt.Errorf("listing through the gateway failed: %s", scrubCrawlError(err))
	}
	out := make([]liveTool, 0, len(res.Tools)+len(res.Unusable))
	for _, t := range res.Tools {
		digest, err := gate.Digest(t.Raw)
		if err != nil {
			digest = ""
		}
		out = append(out, liveTool{name: t.Name, digest: digest})
	}
	for _, u := range res.Unusable {
		out = append(out, liveTool{name: u.Name, digest: "", unusable: string(u.Reason)})
	}
	return out, nil
}
