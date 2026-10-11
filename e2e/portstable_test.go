//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Processor addresses live in the catalog (decision D14 i): emit records the
// address it gives a new server, --processor records an override, each with a
// server.processor_set audit entry, server list shows them, and emit never
// reads an address from the file at --out, so whoever can write that file
// cannot choose where the processors listen (finding cli-docs-3 of the fourth
// review: a re-emit adopted the addresses of any file whose header hash
// verified, and the documented CONFIG-EDITED remedy, run emit again, laundered
// a forged address). The stack pins every address with --processor on every
// emit of the watched file; the side file, emitted without --processor as
// servers are added, shows that a file with no history gets the catalog's
// addresses and that no address moves (decision D13 g).
const (
	// sideConfigName is a second emitted file that no gateway loads.
	sideConfigName = "gateway.side.yaml"
	// processorHostKey is how the emitted file names a route's processor.
	processorHostKey = "host: "
	// hashLinePrefix starts the header line that carries the body hash; the
	// body is everything after that line (limit L19: the hash is unkeyed, so
	// an editor can recompute it and emit.Verify passes).
	hashLinePrefix = "# toolwarrant-sha256: "
	// processorSetEvent is the audit event every address change records.
	processorSetEvent = "server.processor_set"
	// addressChangedLine is part of what emit prints when a server's address
	// moved; a re-emit from the catalog must never print it.
	addressChangedLine = "changed from"
)

// assertProcessorsPinned checks, after an emit of the watched file, that the
// file names each server's processor at the address the stack runs it on and
// that the catalog records the same address. An address that moved would
// darken a route until its processor was restarted (decision D13 g); an
// address the catalog does not hold could only have come from the file
// (decision D14 i).
func (s *stack) assertProcessorsPinned(t *testing.T) {
	t.Helper()
	cfg := string(s.config(t))
	for _, name := range s.names {
		if want := processorHostKey + `"` + s.processorAddr(name) + `"`; !strings.Contains(cfg, want) {
			t.Errorf("after emit the file does not pin the processor of %s at %s; its address must not move across re-emits", name, s.processorAddr(name))
		}
	}
	s.assertCatalogAddresses(t)
}

// assertCatalogAddresses requires server list to show every server's
// processor at the stack's address, in JSON and in the table.
func (s *stack) assertCatalogAddresses(t *testing.T) {
	t.Helper()
	var rows []serverRow
	s.jsonInto(t, &rows, "server", "list", "--json")
	table := s.twOK(t, "server", "list")
	for _, name := range s.names {
		want := s.processorAddr(name)
		got := "(no row)"
		for _, row := range rows {
			if row.Name == name {
				got = row.ProcessorAddr
			}
		}
		if got != want {
			t.Errorf("server list --json shows the processor of %s at %q, want %s: processor addresses live in the catalog (decision D14 i)", name, got, want)
		}
		if !strings.Contains(table, want) {
			t.Errorf("server list does not show %s, the processor address of %s:\n%s", want, name, table)
		}
	}
}

// emitSide emits the side file without --processor and returns the processor
// address emit chose for each registered server, read from the table it
// prints (SERVER ROUTE PROCESSOR APPROVED). Every address must be the one the
// catalog holds, which is the stack's: the file at --out supplies none.
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
		switch addrs[name] {
		case "":
			t.Fatalf("emit's table names no processor address for %s:\n%s", name, out)
		case s.processorAddr(name):
		default:
			t.Errorf("emit without --processor gave %s the processor %s; the catalog holds %s, and the file at --out must not supply one (decision D14 i)", name, addrs[name], s.processorAddr(name))
		}
	}
	return addrs
}

// reemitSide emits the side file again after servers were added and requires
// every server of before to keep its address. It returns the new table for
// the next step.
func (s *stack) reemitSide(t *testing.T, before map[string]string) map[string]string {
	t.Helper()
	after := s.emitSide(t)
	for name, addr := range before {
		if after[name] != addr {
			t.Errorf("re-emitting %s moved the processor of %s from %s to %s; an address must survive the addition of a server, or its route goes dark until the processor is restarted (decision D13 g)", sideConfigName, name, addr, after[name])
		}
	}
	s.note(t, "J: %s re-emitted without --processor for %s, every address from the catalog: %s", sideConfigName, strings.Join(sortedKeys(after), ", "), describeAddrs(after))
	return after
}

// scenarioJAddresses: the addresses the stack pinned with --processor are in
// the catalog and in the audit log; a re-emit of the watched file without
// --processor keeps every one and prints no change line; and the file at
// --out, edited to name another processor for mock with its header hash
// recomputed so that emit.Verify passes (limit L19), is CONFIG-EDITED against
// the recorded body hash, and the next emit changes no address (finding
// cli-docs-3 of the fourth review).
func scenarioJAddresses(t *testing.T, s *stack) {
	s.assertCatalogAddresses(t)
	mustContain(t, "audit list", s.twOK(t, "audit", "list"), processorSetEvent)
	r := s.emitFromCatalog(t)
	mustNotContain(t, "emit without --processor", r.stdout, addressChangedLine)
	s.note(t, "J: %s re-emitted without --processor; every processor address came from the catalog: %s", filepath.Base(s.cfg), describeAddrs(s.stackAddrs()))

	forged, other := s.forgeProcessorAddress(t, "mock")
	s.writeConfig(t, forged)
	r = s.verifyGateway(t, "mock", "--expect-body-hash", s.bodyHash)
	if r.code != exitFailure {
		t.Errorf("verify-gateway --expect-body-hash on the forged file: exit %d, want 1\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	mustContain(t, "verify-gateway on the forged file", r.stdout, "CONFIG-EDITED")
	r = s.emitFromCatalog(t)
	mustNotContain(t, "emit after the forged file", r.stdout, addressChangedLine, other)
	if strings.Contains(string(s.config(t)), other) {
		t.Errorf("after the re-emit the file still names %s, the address the forged file gave mock's processor; emit must not read addresses from the file at --out (decision D14 i)", other)
	}
	s.note(t, "J: the watched file edited to name %s as mock's processor with its header hash recomputed was CONFIG-EDITED against the recorded body hash, and the next emit kept %s from the catalog", other, s.processorAddr("mock"))
	s.eventuallyServes(t, "mock", "add", "echo")
}

// forgeProcessorAddress returns the watched file with the processor of server
// pointed at another loopback port and the header hash recomputed, the edit
// limit L19 describes, and the forged address.
func (s *stack) forgeProcessorAddress(t *testing.T, server string) ([]byte, string) {
	t.Helper()
	other := loopback(s.freeProcPort(t))
	cfg := string(s.config(t))
	old := processorHostKey + `"` + s.processorAddr(server) + `"`
	if strings.Count(cfg, old) != 1 {
		t.Fatalf("the emitted file carries %d copies of %s, want 1", strings.Count(cfg, old), old)
	}
	return reseal(t, strings.Replace(cfg, old, processorHostKey+`"`+other+`"`, 1)), other
}

// reseal recomputes the hash line of an emitted file over its body, so that
// emit.Verify accepts the edit (limit L19).
func reseal(t *testing.T, file string) []byte {
	t.Helper()
	i := strings.Index(file, hashLinePrefix)
	if i < 0 {
		t.Fatalf("the emitted file has no %q line", hashLinePrefix)
	}
	nl := strings.IndexByte(file[i:], '\n')
	if nl < 0 {
		t.Fatalf("the hash line of the emitted file has no newline")
	}
	body := file[i+nl+1:]
	sum := sha256.Sum256([]byte(body))
	return []byte(file[:i] + hashLinePrefix + hex.EncodeToString(sum[:]) + "\n" + body)
}

// stackAddrs is every registered server's processor address as the stack runs
// it, for a note.
func (s *stack) stackAddrs() map[string]string {
	out := map[string]string{}
	for _, name := range s.names {
		out[name] = s.processorAddr(name)
	}
	return out
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
