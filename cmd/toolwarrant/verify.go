package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/crawl"
	"github.com/sairam0424/toolwarrant/internal/emit"
	"github.com/sairam0424/toolwarrant/internal/fetch"
	"github.com/sairam0424/toolwarrant/internal/gate"
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
	headers http.Header
	config  string // emitted configuration file to verify, "" for none
	admin   string // base URL of the gateway's admin API, "" skips the live comparison
	probe   bool   // send the unhooked-call probe
}

// verifyOptions are the flags of verify-gateway.
type verifyOptions struct {
	server, url, bearerEnv, config, admin string
	noProbe, keepGoing                    bool
	every                                 time.Duration
}

// verifyFailure is a check that found the gateway serving what the catalog
// would not, running a configuration that is not the emitted one, or
// forwarding calls without the hook.
type verifyFailure struct {
	leaks        int
	configEdited bool
	configReason string
	liveDiffs    int
	unhooked     bool
	server, url  string
}

func (e *verifyFailure) Error() string {
	var parts []string
	if e.leaks > 0 {
		parts = append(parts, fmt.Sprintf("%d tool(s) leak: the gateway at %s serves definitions the catalog would not; check that the route for %s has the toolwarrant processor", e.leaks, safeURL(e.url), e.server))
	}
	switch {
	case e.configReason != "":
		parts = append(parts, "the gateway configuration file could not be read, so it is treated as edited; restore the file emit wrote")
	case e.configEdited:
		parts = append(parts, "the gateway configuration was edited after emit wrote it; run emit again and reload the gateway")
	}
	if e.liveDiffs > 0 {
		parts = append(parts, fmt.Sprintf("the configuration the gateway is running differs from the emitted file in %d place(s), listed above; run emit again, reload the gateway and find out who changed it", e.liveDiffs))
	}
	if e.unhooked {
		parts = append(parts, "the gateway forwards a tools/call without an id to the upstream unhooked ("+verdictUnhooked+", known limit L17); every such call bypasses the approval")
	}
	return strings.Join(parts, "; ")
}

// bindVerifyFlags registers the flags of verify-gateway. The probe's help text
// says where the probe goes, because that is why it can be switched off.
func bindVerifyFlags(fs *flag.FlagSet) *verifyOptions {
	o := &verifyOptions{}
	fs.StringVar(&o.server, "server", "", "catalog server the gateway route is for (required)")
	fs.StringVar(&o.url, "url", "", "MCP endpoint of the gateway route to test (required)")
	fs.StringVar(&o.bearerEnv, "bearer-env", "", "environment variable holding a bearer token for Authorization (never printed)")
	fs.StringVar(&o.config, "config", "", "gateway configuration file written by emit; CONFIG-EDITED when it is no longer the file emit wrote or cannot be read")
	fs.StringVar(&o.admin, "admin", "", "HOST:PORT or http(s) URL of the gateway's admin API (emit --admin-addr, default "+emit.DefaultAdminAddr+"); the configuration the gateway is running (GET "+adminConfigPath+") is compared with --config and any difference is "+verdictLiveConfig+"; needs --config")
	fs.BoolVar(&o.noProbe, "no-probe", false, "skip the unhooked-call probe; by default every check sends one tools/call WITHOUT a JSON-RPC id for the tool name \""+probeToolPrefix+"<random>\": a gateway that accepts it (HTTP 202) forwards it to the upstream without the processor or the allow rule and is reported as "+verdictUnhooked+" (exit 1), a 400 or a JSON-RPC error is healthy; the probe reaches the upstream exactly when the gateway behaves this way, which is why it can be switched off (agentgateway v1.6.0 answers 202, known limit L17)")
	fs.DurationVar(&o.every, "every", 0, "repeat at this interval (at least 1s) with a fresh MCP session each time, until SIGINT or SIGTERM")
	fs.BoolVar(&o.keepGoing, "keep-going", false, "with --every, keep checking after a failed check instead of exiting at the first one; the run still exits 1 at the end if any check failed or none completed, and a file --config cannot read, an unknown --server or a catalog error stops it at once")
	return o
}

// check validates the flag combination as a usage error naming the fix and
// returns the admin API base URL, "" when --admin was not given.
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
	v := &verifier{a: a, store: store, client: client, server: o.server, url: o.url, headers: headers, config: o.config, admin: adminURL, probe: !o.noProbe}
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
// reported even when the file is gone. What the file check found is printed
// even when the listing fails, and what the listing showed is printed even
// when a later step could not run: a CONFIG-EDITED or a LEAK must never be
// hidden behind a gateway or an admin API that is down.
func (v *verifier) check(ctx context.Context) (verdicts, error) {
	snap, err := v.store.Snapshot(ctx, v.server)
	if err != nil {
		return verdicts{}, err
	}
	var res verdicts
	emitted := v.readConfig(&res)
	live, err := listThroughGateway(ctx, v.client, v.url, v.headers)
	if err != nil {
		v.print(res)
		return res, err
	}
	compare(snap, live, &res)
	err = v.compareLive(ctx, emitted, &res)
	if err == nil && v.probe {
		res.probe, err = probeUnhookedCalls(ctx, v.client, v.url, v.headers)
	}
	v.print(res)
	if err != nil {
		return res, err
	}
	return res, v.a.stdout.broken()
}

// readConfig reads the emitted file and checks its integrity header. Any
// edit, a missing header or a reformatted copy counts as edited: a route whose
// processor entry was removed fails open for every new session, so the file
// must be exactly what emit wrote. A file that cannot be read counts as edited
// too, with the reason, because a canary that cannot see the file it is meant
// to compare must not say OK (second review); nil is returned so the live
// comparison knows there is nothing to compare against.
func (v *verifier) readConfig(res *verdicts) []byte {
	if v.config == "" {
		return nil
	}
	data, err := os.ReadFile(v.config)
	if err != nil {
		res.configEdited, res.configReason = true, textdiff.Escape(err.Error())
		return nil
	}
	hash, ok := emit.Verify(data)
	res.configHash, res.configEdited = hash, !ok
	return data
}

// compareLive fetches the configuration the gateway is running and compares
// the route for the server with the emitted file. It runs only against a
// file that passed the header check: a file that could not be read or that
// is not what emit wrote gives nothing trustworthy to compare with, and the
// check already fails as CONFIG-EDITED. A file without a route for the server
// is an error too, as is an admin API that cannot be reached or read: a
// canary that cannot see both sides must not report that they match.
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
	want, err := emittedRoute(emitted, v.server)
	if err != nil {
		return fmt.Errorf("read the emitted route of %s: %w", cell(v.server), err)
	}
	if !want.found {
		return fmt.Errorf("the file named by --config has no route for server %s; run emit again before comparing the live configuration with it", cell(v.server))
	}
	doc, err := fetchLiveConfig(ctx, v.client, v.admin)
	if err != nil {
		return err
	}
	res.live = liveCheck{compared: true, diffs: compareRoutes(want, liveRoute(doc, v.server))}
	return nil
}

// conclude turns one check into the command's outcome. Exit 0 is OK or
// MISSING only (decision D12).
func (v *verifier) conclude(res verdicts) error {
	if res.failed() {
		return &verifyFailure{leaks: len(res.leaks), configEdited: res.configEdited, configReason: res.configReason,
			liveDiffs: len(res.live.diffs), unhooked: res.probe == probeUnhooked, server: v.server, url: v.url}
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
