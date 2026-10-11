package main

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// maxProcessorPort is the highest TCP port a new server's processor can take.
const maxProcessorPort = 65535

// Processor addresses live in the catalog (D14 i). Until the fourth review a
// re-emit kept each server's address by reading the file at --out when it
// passed emit.Verify, an unkeyed hash that whoever can write the directory of
// --out recomputes (limit L19): the L19 attacker edited the processor host,
// resealed the header, and the documented CONFIG-EDITED remedy (run emit
// again) adopted the forged address, printed no change line and wrote a fresh
// valid header, after which every control said OK while the gateway dialled a
// processor nobody but the attacker chose (cli-docs-3). The file at --out is
// now never read: each server's address is the one the catalog records
// (servers.processor_addr, written by emit itself and by --processor, one
// server.processor_set audit entry per change), a new server takes the next
// free port above every recorded one, and every new or changed address is
// printed.

// planEmit assigns every server its route, processor address and approved tool
// names. An override wins; otherwise a server keeps the address the catalog
// records for it; a server with neither takes the next free port on
// processorHost at or above the base port and above every recorded port, in
// name order, so that a first emit gives the i-th server base+i and a later
// addition moves nobody.
func planEmit(c *command, servers []catalog.Server, approved []catalog.ApprovedTool, basePort int, overrides processorOverrides) ([]emitPlan, error) {
	sorted := append([]catalog.Server(nil), servers...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	byServer := map[string][]string{}
	for _, t := range approved {
		byServer[t.Server] = append(byServer[t.Server], t.Name)
	}
	ports := newPortAllocator(basePort, recordedAddresses(sorted), overrides)
	known := map[string]bool{}
	plans := make([]emitPlan, 0, len(sorted))
	for _, s := range sorted {
		known[s.Name] = true
		plan := emitPlan{name: s.Name, url: s.URL, previous: s.ProcessorAddr, tools: byServer[s.Name]}
		switch addr, overridden := overrides[s.Name]; {
		case overridden:
			plan.processor = addr
		case plan.previous != "":
			plan.processor = plan.previous
		default:
			port, err := ports.next()
			if err != nil {
				return nil, err
			}
			plan.processor = fmt.Sprintf("%s:%d", processorHost, port)
		}
		plans = append(plans, plan)
	}
	for name := range overrides {
		if !known[name] {
			return nil, &usageError{msg: fmt.Sprintf("--processor names unknown server %s", textdiff.Escape(name)), cmd: c}
		}
	}
	return plans, nil
}

// recordedAddresses is the processor address the catalog holds for each
// server that has one.
func recordedAddresses(servers []catalog.Server) map[string]string {
	out := map[string]string{}
	for _, s := range servers {
		if s.ProcessorAddr != "" {
			out[s.Name] = s.ProcessorAddr
		}
	}
	return out
}

// recordProcessorAddrs writes every new or changed address into the catalog
// after the file at out was validated and renamed into place (D15 j), so the
// catalog records addresses of files that exist: the fifth review found a
// gateway refusal leaving the address and its audit entry behind, after which
// the next emit printed no "is new" line for an address no file had ever
// carried. An unchanged address writes nothing and adds no audit entry. The
// plans were computed from the catalog before the write, so an emit that
// fails here is repeated with the same addresses and prints them again.
func recordProcessorAddrs(a *app, store *catalog.Store, plans []emitPlan, out string) error {
	var actor catalog.Actor
	resolved := false
	for _, p := range plans {
		if p.processor == p.previous {
			continue
		}
		if !resolved {
			var err error
			if actor, err = a.actor(false); err != nil {
				return err
			}
			resolved = true
		}
		if err := store.SetProcessorAddr(a.ctx, p.name, p.processor, actor); err != nil {
			return fmt.Errorf("%s was written, but recording the processor address of server %s failed: %w", textdiff.Escape(out), cell(p.name), err)
		}
	}
	return nil
}

// portAllocator hands out processor ports that neither the catalog nor an
// override uses. The recorded ports raise the starting point, so a new server
// lands above every port in use; an override only reserves its port, so a
// first emit with an override still numbers the others from the base port.
type portAllocator struct {
	cursor int
	used   map[int]bool
}

func newPortAllocator(basePort int, recorded map[string]string, overrides processorOverrides) *portAllocator {
	p := &portAllocator{cursor: basePort, used: map[int]bool{}}
	for _, addr := range recorded {
		if port, ok := portOf(addr); ok {
			p.used[port] = true
			if port >= p.cursor {
				p.cursor = port + 1
			}
		}
	}
	for _, addr := range overrides {
		if port, ok := portOf(addr); ok {
			p.used[port] = true
		}
	}
	return p
}

// next returns the lowest free port from the starting point on and reserves
// it. Running out is an error rather than a wrap-around: a wrapped port could
// land on one that is in use.
func (p *portAllocator) next() (int, error) {
	for p.cursor <= maxProcessorPort {
		port := p.cursor
		p.cursor++
		if !p.used[port] {
			p.used[port] = true
			return port, nil
		}
	}
	return 0, errors.New("no free processor port is left above the ones in use; pass --processor NAME=HOST:PORT for the new server")
}

// portOf reads the port of a host:port address; an address of another shape
// reserves nothing, and the emitter refuses it later.
func portOf(addr string) (int, bool) {
	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 {
		return 0, false
	}
	return port, true
}
