package main

import (
	"context"
	"fmt"
	"net/http"
	"sort"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/crawl"
	"github.com/sairam0424/toolwarrant/internal/fetch"
	"github.com/sairam0424/toolwarrant/internal/gate"
)

// Verdict words. LEAK is the one that matters: the gateway serves something
// the catalog would hide, which is what happens when a config loses its
// processor (the guard is config-presence-based and fails open).
const (
	verdictLeak    = "LEAK"
	verdictMissing = "MISSING"
	verdictOK      = "OK"
)

// liveTool is one tool as the gateway served it, with its digest or "" when
// the definition could not be digested (and so could never have been approved).
type liveTool struct {
	name   string
	digest string
}

// runVerifyGateway is the deploy-time self-test: it lists tools through the
// gateway like a client would and compares each one with the catalog's
// serving policy.
func runVerifyGateway(a *app, c *command, args []string) error {
	fs := newFlagSet(c.name)
	server := fs.String("server", "", "catalog server the gateway route is for (required)")
	gatewayURL := fs.String("url", "", "MCP endpoint of the gateway route to test (required)")
	bearerEnv := fs.String("bearer-env", "", "environment variable holding a bearer token for Authorization (never printed)")
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
	headers, err := bearerHeader(c, a.getenv, *bearerEnv)
	if err != nil {
		return err
	}
	store, err := a.openStore(false)
	if err != nil {
		return err
	}
	defer store.Close()
	snap, err := store.Snapshot(a.ctx, *server)
	if err != nil {
		return err
	}
	live, err := listThroughGateway(a.ctx, *gatewayURL, headers)
	if err != nil {
		return err
	}
	leaks, missing := compareServed(snap, live)
	for _, l := range leaks {
		fmt.Fprintf(a.stdout, "%s %s %s\n", verdictLeak, cell(l.name), shortDigest(l.digest))
	}
	for _, m := range missing {
		fmt.Fprintf(a.stdout, "%s %s %s\n", verdictMissing, cell(m), shortDigest(snap.Tools[m].Approved))
	}
	if len(leaks) > 0 {
		return fmt.Errorf("%d tool(s) leak: the gateway at %s serves definitions the catalog would not; check that the route for %s has the toolwarrant processor", len(leaks), safeURL(*gatewayURL), *server)
	}
	fmt.Fprintf(a.stdout, "%s: the gateway serves %d tool(s), every one approved and current\n", verdictOK, len(live))
	return nil
}

// listThroughGateway lists the route with the hardened client. The gateway
// is the operator's own and usually local, so private addresses are allowed.
// A listing error is reduced to its class, never wrapped: the raw text could
// carry the URL.
func listThroughGateway(ctx context.Context, url string, headers http.Header) ([]liveTool, error) {
	client, err := fetch.NewClient(fetch.Policy{AllowPrivate: true})
	if err != nil {
		return nil, fmt.Errorf("build client: %w", err)
	}
	opts := crawl.Options{Client: client, Headers: headers, ClientName: programName, ClientVersion: version}
	res, err := crawl.ListTools(ctx, url, opts)
	if err != nil {
		return nil, fmt.Errorf("listing through the gateway failed: %s", scrubCrawlError(err))
	}
	out := make([]liveTool, 0, len(res.Tools))
	for _, t := range res.Tools {
		digest, err := gate.Digest(t.Raw)
		if err != nil {
			digest = ""
		}
		out = append(out, liveTool{name: t.Name, digest: digest})
	}
	return out, nil
}

// compareServed finds leaks (served but not allowed) and missing tools
// (allowed with a current live digest but not served).
func compareServed(snap catalog.Snapshot, live []liveTool) (leaks []liveTool, missing []string) {
	seen := map[string]bool{}
	for _, t := range live {
		seen[t.name] = true
		if t.digest == "" || !snap.Serves(t.name, t.digest) {
			leaks = append(leaks, t)
		}
	}
	for name, pol := range snap.Tools {
		if !seen[name] && pol.LastSeen != "" && snap.Serves(name, pol.LastSeen) {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return leaks, missing
}
