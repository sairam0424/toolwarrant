package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"sort"
	"strconv"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/emit"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// maxProcessorPort is the highest TCP port a new server's processor can take.
const maxProcessorPort = 65535

// previousFile is what the file at --out said before this emit: the processor
// address of every route when the file was emit's own output (header and body
// hash intact), nothing otherwise. Re-emits keep each server's processor where
// it is (D13 g): numbering servers afresh moved every later server's port when
// one was added, and the processors already running then guarded the wrong
// routes or none until each was restarted (third review).
type previousFile struct {
	read       bool              // the file existed and was what emit wrote
	processors map[string]string // route name to processor address
	warning    string            // why an existing file was not read, "" when it was or there was none
}

// readPreviousFile reads the processor addresses from the file at path. A
// missing file is the first emit; a file that is not what emit wrote (edited,
// or another file at that path) is not trusted for addresses, because whoever
// wrote it would otherwise choose where the operator's processors listen, and
// a warning says so; a file that cannot be read is an error, since it could
// not be replaced either.
func readPreviousFile(path string) (previousFile, error) {
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return previousFile{}, nil
	case err != nil:
		return previousFile{}, fmt.Errorf("read the existing file %s: %w", textdiff.Escape(path), err)
	}
	if _, ok := emit.Verify(data); !ok {
		return previousFile{warning: fmt.Sprintf("%s exists but is not what emit wrote, so no processor address was kept from it and every server is numbered afresh", textdiff.Escape(path))}, nil
	}
	doc, err := emittedConfig(data)
	if err != nil {
		return previousFile{}, fmt.Errorf("read the processor addresses of %s: %w", textdiff.Escape(path), err)
	}
	prev := previousFile{read: true, processors: map[string]string{}}
	for _, r := range doc.routes {
		if len(r.processors) > 0 {
			prev.processors[r.name] = r.processors[0].host
		}
	}
	return prev, nil
}

// planEmit assigns every server its route, processor address and approved tool
// names. An override wins; otherwise a server keeps the address the previous
// file gave it; a server with neither takes the next free port on
// processorHost at or above the base port and above every port the previous
// file uses, in name order, so that a first emit gives the i-th server
// base+i as before and a later addition moves nobody.
func planEmit(c *command, servers []catalog.Server, approved []catalog.ApprovedTool, basePort int, overrides processorOverrides, previous map[string]string) ([]emitPlan, error) {
	sorted := append([]catalog.Server(nil), servers...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	byServer := map[string][]string{}
	for _, t := range approved {
		byServer[t.Server] = append(byServer[t.Server], t.Name)
	}
	ports := newPortAllocator(basePort, previous, overrides)
	known := map[string]bool{}
	plans := make([]emitPlan, 0, len(sorted))
	for _, s := range sorted {
		known[s.Name] = true
		plan := emitPlan{name: s.Name, url: s.URL, previous: previous[s.Name], tools: byServer[s.Name]}
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

// portAllocator hands out processor ports that neither the previous file nor
// an override uses. The previous file's ports raise the starting point, so a
// new server lands above every port in use; an override only reserves its
// port, so a first emit with an override still numbers the others from the
// base port as before.
type portAllocator struct {
	cursor int
	used   map[int]bool
}

func newPortAllocator(basePort int, previous map[string]string, overrides processorOverrides) *portAllocator {
	p := &portAllocator{cursor: basePort, used: map[int]bool{}}
	for _, addr := range previous {
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
