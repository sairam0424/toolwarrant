package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/crawl"
	"github.com/sairam0424/toolwarrant/internal/emit"
	"github.com/sairam0424/toolwarrant/internal/fetch"
	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// liveSkippedEdited is why the live comparison does not run against a file
// that failed the header check: the file is not what emit wrote, so agreeing
// with it would prove nothing, and the check already fails as CONFIG-EDITED.
const liveSkippedEdited = "the file named by --config is not what emit wrote, so there is nothing to compare the live configuration with"

// liveSkippedUnreadable is why the live comparison does not run when the file
// could not be read at all.
const liveSkippedUnreadable = "the emitted file could not be read"

// verifier holds what one check of one gateway route needs. One hardened
// client serves the listing, the probe and the admin API: the gateway is the
// operator's own and usually local, so private addresses are allowed.
type verifier struct {
	a       *app
	store   *catalog.Store
	client  *http.Client
	server  string
	url     string
	urlPath string // the path of url, compared with the emitted route's match
	headers http.Header
	config  string // emitted configuration file to verify, "" for none
	admin   string // base URL of the gateway's admin API, "" skips the live comparison
	// expectBodyHash is the body sha256 the operator recorded when emit wrote
	// the file, lower-case, "" when none was given.
	expectBodyHash string
	probe          bool // send the unhooked-call probe
	// failingLines counts the failing verdict lines this verifier printed, so
	// a scheduled run fails at the end if it ever printed one (D13 f), even
	// when the check that printed it was cut short by the stop signal.
	failingLines int
}

// verifyOptions are the flags of verify-gateway.
type verifyOptions struct {
	server, url, bearerEnv, config, admin, expectBodyHash string
	noProbe, keepGoing                                    bool
	every                                                 time.Duration
}

// verifyFailure is a check that found the gateway serving what the catalog
// would not, running a configuration that is not the emitted one, or
// answering the probe in a way that does not prove the hook.
type verifyFailure struct {
	leaks          int
	configEdited   bool
	configReason   string
	configExpected string
	liveDiffs      int
	probe          probeOutcome
	server, url    string
}

func (e *verifyFailure) Error() string {
	var parts []string
	if e.leaks > 0 {
		parts = append(parts, fmt.Sprintf("%d tool(s) leak: the gateway at %s serves definitions the catalog would not; check that the route for %s has the toolwarrant processor", e.leaks, safeURL(e.url), e.server))
	}
	switch {
	case e.configReason != "":
		parts = append(parts, "the gateway configuration file could not be read, so it is treated as edited; restore the file emit wrote")
	case e.configExpected != "":
		parts = append(parts, "the gateway configuration file's body hash is not the one recorded with --expect-body-hash, so the file was replaced and its header recomputed; run emit again, reload the gateway and find out who changed it")
	case e.configEdited:
		parts = append(parts, "the gateway configuration was edited after emit wrote it; run emit again and reload the gateway")
	}
	if e.liveDiffs > 0 {
		parts = append(parts, fmt.Sprintf("the configuration the gateway is running differs from the emitted file in %d place(s), listed above; run emit again, reload the gateway and find out who changed it", e.liveDiffs))
	}
	switch e.probe {
	case probeUnhooked:
		parts = append(parts, "the gateway forwards a tools/call without an id to the upstream unhooked ("+verdictUnhooked+", known limit L17); every such call bypasses the approval")
	case probeInconclusive:
		parts = append(parts, "the gateway answered a tools/call without an id with a 2xx status and a body, or with HTTP 400 and a JSON body ("+verdictInconclusive+"); the upstream may have written that answer, so treat the gateway as unhooked until it answers HTTP 400 with an empty or non-JSON body")
	}
	return strings.Join(parts, "; ")
}

// bindVerifyFlags registers the flags of verify-gateway. The probe's help text
// says where the probe goes, because that is why it can be switched off.
func bindVerifyFlags(fs *flag.FlagSet) *verifyOptions {
	o := &verifyOptions{}
	fs.StringVar(&o.server, "server", "", "catalog server the gateway route is for (required)")
	fs.StringVar(&o.url, "url", "", "MCP endpoint of the gateway route to test (required); with --admin its path must be the emitted route's match")
	fs.StringVar(&o.bearerEnv, "bearer-env", "", "environment variable holding a bearer token for Authorization (never printed)")
	fs.StringVar(&o.config, "config", "", "gateway configuration file written by emit; "+verdictConfigEdited+" when it is no longer the file emit wrote, cannot be read, or is not a regular file (a symbolic link, directory, device, socket or named pipe is refused before it is opened, so a planted pipe cannot block the check)")
	fs.StringVar(&o.expectBodyHash, "expect-body-hash", "", "the body sha256 emit printed for --config, recorded outside the gateway host; "+verdictConfigEdited+" when the file's body hashes to anything else, which catches a replacement that recomputed the header hash (known limit L19); needs --config")
	fs.StringVar(&o.admin, "admin", "", "HOST:PORT or http(s) URL of the gateway's admin API (emit --admin-addr, default "+emit.DefaultAdminAddr+"); the configuration the gateway is running (GET "+adminConfigPath+") is compared with --config as a whole document: no non-empty top-level section other than config, gateways and routes may be present, the config block must declare the same adminAddr, statsAddr and readinessAddr and no other field, every emitted gateway must be present exactly once with the same bind address and port and no other field, every emitted route exactly once with the same gateway, match path, allow rules, backend targets and processors (host, kind, failureMode, methods, the requestHeaders allowed and disallowed lists, and the metadata compared by a hash of its canonical form and never shown), nothing the file does not carry may exist (no other route, gateway or section; inside a route no field other than name, gateways, matches, policies and backends, no policy other than mcpAuthorization and mcpGuardrails, no match that is not a single exact path, no backend other than the one mcp backend with the emitted target, and no field of a processor, rule or target that emit does not write), no path may be matched by two routes, and the path of --url must be the emitted route's match; any difference is "+verdictLiveConfig+"; needs --config")
	fs.BoolVar(&o.noProbe, "no-probe", false, "skip the unhooked-call probe; by default every check sends one tools/call WITHOUT a JSON-RPC id for the tool name \""+probeToolPrefix+"<random>\": a gateway that accepts it (HTTP 202) forwards it to the upstream without the processor or the allow rule and is reported as "+verdictUnhooked+" (exit 1), HTTP 400 with an empty or non-JSON body is healthy, and any other 2xx answer with a body or a 400 whose body is JSON (a JSON-RPC answer, single or batched) is "+verdictInconclusive+" (exit 1) because the gateway or the upstream may have written it; the probe reaches the upstream exactly when the gateway behaves this way, which is why it can be switched off (agentgateway v1.6.0 answers 202, known limit L17)")
	fs.DurationVar(&o.every, "every", 0, "repeat at this interval (at least 1s) with a fresh MCP session each time, until SIGINT or SIGTERM")
	fs.BoolVar(&o.keepGoing, "keep-going", false, "with --every, keep checking after a failed check instead of exiting at the first one; without it a check that printed a failing verdict exits 1 at once, even when a later step of that check (the live comparison, the probe) could not run, while a listing failure alone is printed, counted and does not stop the run; the run still exits 1 at the end if any check failed or printed a verdict line, or none completed, and a file --config cannot read, an unknown --server or a catalog error stops it at once")
	return o
}

// check validates the flag combination as a usage error naming the fix and
// returns the admin API base URL, "" when --admin was not given. The recorded
// body hash is normalised to lower case here so the comparison is exact.
func (o *verifyOptions) check(c *command) (string, error) {
	if err := requireFlag(c, o.server, "server", "name the catalog server"); err != nil {
		return "", err
	}
	if err := requireFlag(c, o.url, "url", "give the gateway endpoint to list through"); err != nil {
		return "", err
	}
	if err := checkEvery(c, o.every); err != nil {
		return "", err
	}
	if o.admin != "" && o.config == "" {
		return "", &usageError{msg: "--admin needs --config: the configuration the gateway is running is compared with the file emit wrote", cmd: c}
	}
	if o.expectBodyHash != "" {
		if o.config == "" {
			return "", &usageError{msg: "--expect-body-hash needs --config: the recorded body hash is compared with the file emit wrote", cmd: c}
		}
		o.expectBodyHash = strings.ToLower(o.expectBodyHash)
		if !lifecycle.IsDigest(o.expectBodyHash) {
			return "", &usageError{msg: "--expect-body-hash must be the 64 hex digits of the body sha256 that emit printed", cmd: c}
		}
	}
	return normalizeAdminURL(c, o.admin)
}

// normalizeAdminURL accepts the admin API as HOST:PORT (the form emit takes)
// or as an http(s) URL, and refuses user info, a query and a fragment: the
// address is printed, so it must not be able to carry a credential.
func normalizeAdminURL(c *command, raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	addr := raw
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", &usageError{msg: fmt.Sprintf("--admin %s must be HOST:PORT or an http(s) URL of the gateway's admin API, without user info, query or fragment", textdiff.Escape(raw)), cmd: c}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}

// routePathOf is the path of the --url the canary lists through, which the
// live comparison holds against the emitted route's match. A URL that does not
// parse keeps its raw text: the listing fails on it anyway, and the difference
// line then shows what was typed, escaped.
func routePathOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Path
}

// runVerifyGateway is the deploy-time self-test and the canary: it lists
// tools through the gateway like a client would and compares each one with
// the catalog's serving policy, checks the emitted file on disk and, with
// --admin, the configuration the gateway is running, and probes the gateway
// for unhooked calls. With --every it repeats, opening a fresh MCP session
// each time so that a gateway which reloaded between checks is seen as it is
// now (limit L3).
func runVerifyGateway(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	o := bindVerifyFlags(fs)
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos); err != nil {
		return err
	}
	adminURL, err := o.check(c)
	if err != nil {
		return err
	}
	headers, err := bearerHeader(c, a.getenv, o.bearerEnv)
	if err != nil {
		return err
	}
	client, err := fetch.NewClient(fetch.Policy{AllowPrivate: true})
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	v := &verifier{a: a, store: store, client: client, server: o.server, url: o.url, urlPath: routePathOf(o.url), headers: headers,
		config: o.config, admin: adminURL, expectBodyHash: o.expectBodyHash, probe: !o.noProbe}
	if o.every == 0 {
		res, err := v.check(a.ctx)
		if err != nil {
			return err
		}
		return v.conclude(res)
	}
	return v.loop(a.ctx, o.every, o.keepGoing)
}

// check runs one comparison and prints its verdict lines. The catalog is read
// first, so an unknown server is reported before anything is fetched; the
// file is read next and the listing runs whatever the file said, so a LEAK is
// reported even when the file is gone. The verdicts of the file check and the
// listing are printed before the live comparison and the probe run (D13 f):
// a CONFIG-EDITED or a LEAK must never wait behind an admin API or an
// upstream that hangs until the run is stopped, and what the listing showed is
// printed even when a later step could not run.
func (v *verifier) check(ctx context.Context) (verdicts, error) {
	snap, err := v.store.Snapshot(ctx, v.server)
	if err != nil {
		return verdicts{}, err
	}
	var res verdicts
	emitted := v.readConfig(&res)
	live, listErr := listThroughGateway(ctx, v.client, v.url, v.headers)
	if listErr == nil {
		compare(snap, live, &res)
	}
	v.printListing(res)
	// The live comparison runs even when the listing failed: a policy or a
	// backend posted through the admin API can break the route for the
	// canary's own listing, and the operator must still see what differs
	// (sixth round; finding cli-docs-1 of the fifth review as observed on
	// the real gateway, where a requestMirror policy did exactly that).
	liveErr := v.compareLive(ctx, emitted, &res)
	if listErr != nil {
		v.printChecks(res)
		return res, v.listingFailure(res, listErr, liveErr)
	}
	err = liveErr
	if err == nil && v.probe {
		res.probe, err = probeUnhookedCalls(ctx, v.client, v.url, v.headers)
	}
	v.printChecks(res)
	if err != nil {
		return res, err
	}
	return res, v.a.stdout.broken()
}

// listingFailure is the error of a check whose listing failed. The live
// comparison may still have found differences; they are named after the
// listing failure so a route broken by a posted policy is explained, not only
// reported as unreachable. The probe does not run on such a check.
func (v *verifier) listingFailure(res verdicts, listErr, liveErr error) error {
	switch {
	case liveErr != nil:
		return fmt.Errorf("%w; %w", listErr, liveErr)
	case len(res.live.diffs) > 0:
		return fmt.Errorf("%w; %w", listErr, &verifyFailure{liveDiffs: len(res.live.diffs), server: v.server, url: v.url})
	}
	return listErr
}

// readConfig reads the emitted file and checks its integrity header. Any
// edit, a missing header or a reformatted copy counts as edited: a route whose
// processor entry was removed fails open for every new session, so the file
// must be exactly what emit wrote. A file that verifies but whose body hash is
// not the one the operator recorded with --expect-body-hash counts as edited
// too: its header was recomputed (limit L19). A file that cannot be read
// counts as edited as well, with the reason, because a canary that cannot see
// the file it is meant to compare must not say OK (second review); so does a
// path that is not a regular file, refused before it is opened, because a
// named pipe planted there would otherwise block the check for ever with no
// verdict and no exit (fourth review cli-docs-2). nil is returned so the live
// comparison knows there is nothing to compare against.
func (v *verifier) readConfig(res *verdicts) []byte {
	if v.config == "" {
		return nil
	}
	data, err := readRegularFile(v.config, "--config", maxEmittedFileBytes)
	if err != nil {
		res.configEdited, res.configReason = true, textdiff.Escape(err.Error())
		return nil
	}
	hash, ok := emit.Verify(data)
	res.configHash, res.configEdited = hash, !ok
	if ok && v.expectBodyHash != "" && hash != v.expectBodyHash {
		res.configEdited, res.configExpected = true, v.expectBodyHash
	}
	return data
}

// compareLive fetches the configuration the gateway is running and compares
// the whole of it with the emitted file (D13 e). It runs only against a file
// that passed the header check: a file that could not be read or that is not
// what emit wrote gives nothing trustworthy to compare with, and the check
// already fails as CONFIG-EDITED. A file without a route for the server is an
// error too, as is an admin API that cannot be reached or read: a canary that
// cannot see both sides must not report that they match.
func (v *verifier) compareLive(ctx context.Context, emitted []byte, res *verdicts) error {
	if v.admin == "" {
		return nil
	}
	switch {
	case emitted == nil:
		res.live = liveCheck{skipped: liveSkippedUnreadable}
		return nil
	case res.configEdited:
		res.live = liveCheck{skipped: liveSkippedEdited}
		return nil
	}
	doc, err := emittedConfig(emitted)
	if err != nil {
		return fmt.Errorf("read the emitted file: %w", err)
	}
	if _, err := emittedRouteOf(doc, v.server); err != nil {
		return err
	}
	liveDoc, err := fetchLiveConfig(ctx, v.client, v.admin)
	if err != nil {
		return err
	}
	res.live = liveCheck{compared: true, diffs: compareDocuments(doc, liveDoc.config(), v.server, v.urlPath)}
	return nil
}

// conclude turns one check into the command's outcome. Exit 0 is OK or
// MISSING only (decision D12).
func (v *verifier) conclude(res verdicts) error {
	if res.failed() {
		return &verifyFailure{leaks: len(res.leaks), configEdited: res.configEdited, configReason: res.configReason, configExpected: res.configExpected,
			liveDiffs: len(res.live.diffs), probe: res.probe, server: v.server, url: v.url}
	}
	v.a.stdout.printf("%s: %s\n", verdictOK, res.summary())
	return v.a.stdout.broken()
}

// listThroughGateway lists the route in a fresh MCP session. A listing error
// is reduced to its class, never wrapped: the raw text could carry the URL.
// The neutral default clientInfo is kept for the same reason as in crawl.
func listThroughGateway(ctx context.Context, client *http.Client, url string, headers http.Header) ([]liveTool, error) {
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
