package main

import (
	"fmt"
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
)

// serverCommands is the table behind "server".
func serverCommands() []*command {
	return []*command{
		{name: "add", synopsis: "server add NAME URL [--owner GROUP] [--allow-private]", summary: "register an upstream MCP server (URLs with user info are refused)", run: runServerAdd},
		{name: "list", synopsis: "server list [--json]", summary: "list the registered upstreams", run: runServerList},
	}
}

// serverJSON is one server in machine-readable output. The URL is reduced to
// scheme://host[:port]/path like everywhere else.
type serverJSON struct {
	Name         string    `json:"name"`
	URL          string    `json:"url"`
	OwnerGroup   string    `json:"owner_group"`
	AllowPrivate bool      `json:"allow_private"`
	CreatedAt    time.Time `json:"created_at"`
}

// runServerAdd registers an upstream. --allow-private is recorded on the server
// row and warned about, because it is the one switch that lets the crawler
// reach loopback and private networks.
func runServerAdd(a *app, c *command, args []string) error {
	fs := newFlagSet(c.name)
	owner := fs.String("owner", "", "owning group, a label only")
	allowPrivate := fs.Bool("allow-private", false, "let the crawler reach loopback and private addresses (lab use only)")
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos, "NAME", "URL"); err != nil {
		return err
	}
	actor, err := a.actor(false)
	if err != nil {
		return err
	}
	store, err := a.openStore(false)
	if err != nil {
		return err
	}
	defer store.Close()
	spec := catalog.ServerSpec{Name: pos[0], URL: pos[1], OwnerGroup: *owner, AllowPrivate: *allowPrivate}
	srv, err := store.AddServer(a.ctx, spec, actor)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "added server %s at %s\n", cell(srv.Name), displayURL(srv.URL))
	if srv.AllowPrivate {
		fmt.Fprintf(a.stderr, "warning: %s may be crawled at loopback and private addresses; use this only in a lab\n", cell(srv.Name))
	}
	return nil
}

// runServerList lists the upstreams, newest last.
func runServerList(a *app, c *command, args []string) error {
	fs := newFlagSet(c.name)
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos); err != nil {
		return err
	}
	store, err := a.openStore(false)
	if err != nil {
		return err
	}
	defer store.Close()
	servers, err := store.Servers(a.ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.stdout, serversJSON(servers))
	}
	t := newTable(a.stdout)
	t.row("NAME", "URL", "OWNER", "PRIVATE", "CREATED")
	for _, s := range servers {
		t.row(cell(s.Name), displayURL(s.URL), cell(s.OwnerGroup), fmt.Sprint(s.AllowPrivate), s.CreatedAt.UTC().Format(time.RFC3339))
	}
	return t.flush()
}

func serversJSON(servers []catalog.Server) []serverJSON {
	out := make([]serverJSON, 0, len(servers))
	for _, s := range servers {
		out = append(out, serverJSON{Name: s.Name, URL: safeURL(s.URL), OwnerGroup: s.OwnerGroup, AllowPrivate: s.AllowPrivate, CreatedAt: s.CreatedAt.UTC()})
	}
	return out
}
