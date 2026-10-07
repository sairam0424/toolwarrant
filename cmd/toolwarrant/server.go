package main

import (
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
)

// serverCommands is the table behind "server".
func serverCommands() []*command {
	return []*command{
		{name: "add", synopsis: "server add NAME URL [--owner GROUP] [--allow-private]", summary: "register an upstream MCP server (URLs with user info are refused)", run: runServerAdd},
		{name: "list", synopsis: "server list [--json]", summary: "list the registered upstreams; PAUSED marks a server that is neither crawled nor served", run: runServerList},
		{name: "pause", synopsis: "server pause NAME", summary: "stop crawling a server and serve nothing of it until resume (the remedy against a misbehaving upstream)", run: runServerPause},
		{name: "resume", synopsis: "server resume NAME", summary: "let crawls and serving of a paused server continue", run: runServerResume},
	}
}

// serverJSON is one server in machine-readable output. The URL is reduced to
// scheme://host[:port]/path like everywhere else.
type serverJSON struct {
	Name         string    `json:"name"`
	URL          string    `json:"url"`
	OwnerGroup   string    `json:"owner_group"`
	AllowPrivate bool      `json:"allow_private"`
	Paused       bool      `json:"paused"`
	CreatedAt    time.Time `json:"created_at"`
}

// runServerAdd registers an upstream. --allow-private is recorded on the server
// row and warned about, because it is the one switch that lets the crawler
// reach loopback and private networks.
func runServerAdd(a *app, c *command, args []string) (err error) {
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
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	spec := catalog.ServerSpec{Name: pos[0], URL: pos[1], OwnerGroup: *owner, AllowPrivate: *allowPrivate}
	srv, err := store.AddServer(a.ctx, spec, actor)
	if err != nil {
		return err
	}
	a.stdout.printf("added server %s at %s\n", cell(srv.Name), displayURL(srv.URL))
	if srv.AllowPrivate {
		a.stderr.printf("warning: %s may be crawled at loopback and private addresses; use this only in a lab\n", cell(srv.Name))
	}
	return nil
}

// runServerList lists the upstreams in name order.
func runServerList(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos); err != nil {
		return err
	}
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	servers, err := store.Servers(a.ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.stdout, serversJSON(servers))
	}
	t := newTable(a.stdout)
	t.row("NAME", "URL", "OWNER", "PRIVATE", "PAUSED", "CREATED")
	for _, s := range servers {
		t.row(cell(s.Name), displayURL(s.URL), cell(s.OwnerGroup), boolCell(s.AllowPrivate), boolCell(s.Paused), s.CreatedAt.UTC().Format(time.RFC3339))
	}
	return t.flush()
}

// boolCell renders a flag column.
func boolCell(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func serversJSON(servers []catalog.Server) []serverJSON {
	out := make([]serverJSON, 0, len(servers))
	for _, s := range servers {
		out = append(out, serverJSON{Name: s.Name, URL: safeURL(s.URL), OwnerGroup: s.OwnerGroup, AllowPrivate: s.AllowPrivate, Paused: s.Paused, CreatedAt: s.CreatedAt.UTC()})
	}
	return out
}

// runServerPause stops crawling and serving a server. It is a decision, so
// only a named person may take it.
func runServerPause(a *app, c *command, args []string) error {
	return runServerSwitch(a, c, args, true)
}

// runServerResume lets a paused server be crawled and served again.
func runServerResume(a *app, c *command, args []string) error {
	return runServerSwitch(a, c, args, false)
}

// runServerSwitch is the shared body of pause and resume.
func runServerSwitch(a *app, c *command, args []string, pause bool) (err error) {
	fs := newFlagSet(c.name)
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos, "NAME"); err != nil {
		return err
	}
	actor, err := a.decidingActor(c)
	if err != nil {
		return err
	}
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	if pause {
		if err := store.PauseServer(a.ctx, pos[0], actor); err != nil {
			return err
		}
		a.stdout.printf("paused server %s: crawls are refused and nothing of it is served until \"%s server resume %s\"\n", cell(pos[0]), programName, cell(pos[0]))
		return nil
	}
	if err := store.ResumeServer(a.ctx, pos[0], actor); err != nil {
		return err
	}
	a.stdout.printf("resumed server %s: crawls and serving continue\n", cell(pos[0]))
	return nil
}
