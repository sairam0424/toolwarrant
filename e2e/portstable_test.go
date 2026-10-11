//go:build e2e

package e2e

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// sideConfigName is a second emitted file that no gateway loads. The stack
// pins every processor address of the watched file with --processor, so the
// rule emit applies on its own (an existing file written by emit is read
// first, each server keeps its address, a new server takes the next free
// port; decision D13) is exercised on this file, re-emitted by scenario J as
// servers are added in an order that would renumber them under name order.
const (
	sideConfigName = "gateway.side.yaml"
	// processorHostKey is how the emitted file names a route's processor.
	processorHostKey = "host: "
)

// assertProcessorsPinned checks that the file emit just wrote names each
// server's processor at the address the stack runs it on. The stack re-emits
// many times as servers and approvals are added; an address that moved would
// darken a route until its processor was restarted (decision D13).
func (s *stack) assertProcessorsPinned(t *testing.T) {
	t.Helper()
	cfg := string(s.config(t))
	for _, name := range s.names {
		if want := processorHostKey + `"` + s.processorAddr(name) + `"`; !strings.Contains(cfg, want) {
			t.Errorf("after emit the file does not pin the processor of %s at %s; its address must not move across re-emits", name, s.processorAddr(name))
		}
	}
}

// emitSide re-emits the side file without --processor overrides and returns
// the processor address emit chose for each registered server, read from the
// table it prints (SERVER ROUTE PROCESSOR APPROVED).
func (s *stack) emitSide(t *testing.T) map[string]string {
	t.Helper()
	out := s.twOK(t, "emit", "--out", filepath.Join(s.h.workdir, sideConfigName))
	addrs := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 4 && strings.HasPrefix(fields[1], "/") {
			addrs[fields[0]] = fields[2]
		}
	}
	for _, name := range s.names {
		if addrs[name] == "" {
			t.Fatalf("emit's table names no processor address for %s:\n%s", name, out)
		}
	}
	return addrs
}

// reemitSide emits the side file again after servers were added and requires
// every server of before to keep its address and every new server to get one
// no earlier server had. It returns the new table for the next step.
func (s *stack) reemitSide(t *testing.T, before map[string]string) map[string]string {
	t.Helper()
	after := s.emitSide(t)
	taken := map[string]string{}
	for name, addr := range before {
		if after[name] != addr {
			t.Errorf("re-emitting %s moved the processor of %s from %s to %s; an address must survive the addition of a server, or its route goes dark until the processor is restarted (decision D13)", sideConfigName, name, addr, after[name])
		}
		taken[addr] = name
	}
	for name, addr := range after {
		if _, old := before[name]; old {
			continue
		}
		if other, dup := taken[addr]; dup {
			t.Errorf("new server %s was given %s, the processor address of %s", name, addr, other)
		}
	}
	s.note(t, "J: %s re-emitted without --processor for %s: %s", sideConfigName, strings.Join(sortedKeys(after), ", "), describeAddrs(after))
	return after
}

// sortedKeys is the sorted key list of a map, for a deterministic note.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// describeAddrs renders server=address pairs in name order.
func describeAddrs(m map[string]string) string {
	parts := make([]string, 0, len(m))
	for _, k := range sortedKeys(m) {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, " ")
}
