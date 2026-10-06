package main

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/processor"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

const (
	unixPrefix = "unix:"
	localhost  = "localhost"
	// socketMode lets only the owner connect. The ExtMCP protocol has no
	// authentication and every reply decides what the gateway serves, so the
	// socket must not be reachable by other users of the machine.
	socketMode os.FileMode = 0o600
)

// runServe runs the ExtMCP processor for one server until SIGINT or SIGTERM.
// Only loopback and unix-socket listeners are accepted by default, for the
// same reason the socket is owner-only.
func runServe(a *app, c *command, args []string) error {
	fs := newFlagSet(c.name)
	server := fs.String("server", "", "catalog server this processor guards (required)")
	listen := fs.String("listen", "", "host:port or unix:/path to listen on (required; loopback unless --allow-non-loopback)")
	allowNonLoopback := fs.Bool("allow-non-loopback", false, "listen on a non-loopback address even though ExtMCP has no authentication")
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos); err != nil {
		return err
	}
	if err := requireFlag(c, *server, "server", "name the catalog server to guard"); err != nil {
		return err
	}
	if err := requireFlag(c, *listen, "listen", "give host:port or unix:/path"); err != nil {
		return err
	}
	if err := checkListenAddr(c, *listen, *allowNonLoopback); err != nil {
		return err
	}
	store, err := a.openStore(false)
	if err != nil {
		return err
	}
	defer store.Close()
	if _, err := store.Server(a.ctx, *server); err != nil {
		return err
	}
	lis, err := listenOn(*listen)
	if err != nil {
		return err
	}
	defer lis.Close()
	logger := slog.New(slog.NewJSONHandler(a.stderr, nil))
	proc := processor.New(store, processor.Config{Server: *server, Logger: logger})
	fmt.Fprintf(a.stdout, "listening on %s, guarding server %s\n", textdiff.Escape(lis.Addr().String()), cell(*server))
	serveErr := proc.Serve(a.ctx, lis)
	writeStats(a.stdout, proc.Stats())
	if serveErr != nil {
		return fmt.Errorf("processor stopped: %w", serveErr)
	}
	return nil
}

// checkListenAddr refuses a TCP address that is not loopback unless the
// operator said so explicitly.
func checkListenAddr(c *command, addr string, allowNonLoopback bool) error {
	if path, ok := strings.CutPrefix(addr, unixPrefix); ok {
		if path == "" {
			return &usageError{msg: "--listen unix: needs a socket path", cmd: c}
		}
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--listen %s is neither host:port nor unix:/path", textdiff.Escape(addr)), cmd: c}
	}
	if allowNonLoopback || isLoopbackHost(host) {
		return nil
	}
	return &usageError{msg: fmt.Sprintf("refusing to listen on %s: it is not a loopback address and the ExtMCP protocol has no authentication; pass --allow-non-loopback only on a network that nobody but the gateway can reach", textdiff.Escape(addr)), cmd: c}
}

// isLoopbackHost accepts "localhost" and loopback IP literals. A host name
// other than localhost is not resolved: a listen address is configuration,
// and a name is not a safe way to say "loopback".
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, localhost) {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// listenOn opens the listener. A unix socket is made owner-only right after it
// is created; Go removes the socket file when the listener closes.
func listenOn(addr string) (net.Listener, error) {
	if path, ok := strings.CutPrefix(addr, unixPrefix); ok {
		lis, err := net.Listen("unix", path)
		if err != nil {
			return nil, fmt.Errorf("listen on unix socket: %w", err)
		}
		if err := os.Chmod(path, socketMode); err != nil {
			_ = lis.Close()
			return nil, fmt.Errorf("restrict socket permissions: %w", err)
		}
		return lis, nil
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	return lis, nil
}

// writeStats prints the processor counters when it stops, so an operator can
// see at a glance whether the gateway ever asked and what was hidden.
func writeStats(w io.Writer, st processor.Stats) {
	fmt.Fprintf(w, "stats: lists served=%d denied=%d, tools hidden=%d, calls allowed=%d denied=%d, source errors=%d\n",
		st.ListsServed, st.ListsDenied, st.ToolsHidden, st.CallsAllowed, st.CallsDenied, st.SourceErrors)
}
