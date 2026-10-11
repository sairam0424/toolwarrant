package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/emit"
)

// processorSetEvent is the audit event the catalog writes for a recorded
// processor address (D14 i).
const processorSetEvent = "server.processor_set"

// bodyHashOf is the body sha256 an emit printed.
func bodyHashOf(t *testing.T, emitOutput string) string {
	t.Helper()
	m := bodyHashLine.FindStringSubmatch(emitOutput)
	if m == nil {
		t.Fatalf("emit printed no body sha256 line:\n%s", emitOutput)
	}
	return m[1]
}

// reseal recomputes the hash line of an emitted file after an edit, the way
// limit L19 says an attacker can: the header is an unkeyed SHA-256 of the
// body, so whoever rewrites the body rewrites line four as well.
func reseal(t *testing.T, file string) string {
	t.Helper()
	const prefix = "# toolwarrant-sha256: "
	i := strings.Index(file, prefix)
	if i < 0 {
		t.Fatal("no hash line in the emitted file")
	}
	nl := strings.IndexByte(file[i:], '\n')
	if nl < 0 {
		t.Fatal("hash line without a newline")
	}
	body := file[i+nl+1:]
	sum := sha256.Sum256([]byte(body))
	return file[:i] + prefix + hex.EncodeToString(sum[:]) + "\n" + body
}

// processorSetEntries returns the server.processor_set audit entries.
func (c *cli) processorSetEntries() []auditRow {
	c.t.Helper()
	var out []auditRow
	for _, e := range c.auditEntries() {
		if e.Event == processorSetEvent {
			out = append(out, e)
		}
	}
	return out
}

// Third review (processor-emit-8) and fourth review (cli-docs-3, D14 i): a
// re-emit keeps every server's processor address, a new server takes the next
// free port above the ones in use, and every new or changed address is
// printed. The addresses live in the catalog, recorded by emit with one
// server.processor_set audit entry per change and shown by server list; the
// file at --out is never read for them, so another --out gets the same
// addresses and a re-emit that changes nothing adds no entry.
func TestEmitKeepsProcessorAddressesAcrossReEmits(t *testing.T) {
	c := newCLI(t)
	u := newUpstream(t, map[string]string{"echo": echoV1})
	c.ok("server", "add", "b", u.url(), "--allow-private")
	c.ok("server", "add", "c", u.url(), "--allow-private")
	out := filepath.Join(t.TempDir(), "gateway.yaml")
	wantContains(t, "server list before the first emit", c.ok("server", "list"), "PROCESSOR")
	first := c.ok("emit", "--out", out)
	wantContains(t, "first emit", first, "127.0.0.1:9001", "127.0.0.1:9002",
		"processor address of server b is new: 127.0.0.1:9001", "processor address of server c is new: 127.0.0.1:9002")
	wantContains(t, "server list", c.ok("server", "list"), "PROCESSOR", "127.0.0.1:9001", "127.0.0.1:9002")
	var rows []serverJSON
	c.jsonInto(&rows, "server", "list", "--json")
	if len(rows) != 2 || rows[0].ProcessorAddr != "127.0.0.1:9001" || rows[1].ProcessorAddr != "127.0.0.1:9002" {
		t.Errorf("server list --json = %+v", rows)
	}
	if entries := c.processorSetEntries(); len(entries) != 2 || entries[0].Subject != "b" || entries[0].Detail != "processor_addr=127.0.0.1:9001" || entries[1].Subject != "c" {
		t.Errorf("%s entries after the first emit = %+v", processorSetEvent, entries)
	}

	c.ok("server", "add", "a", u.url(), "--allow-private")
	second := c.ok("emit", "--out", out)
	yaml := readFile(t, out)
	for _, want := range []string{`- name: "a"`, `host: "127.0.0.1:9003"`, `- name: "b"`, `host: "127.0.0.1:9001"`, `- name: "c"`, `host: "127.0.0.1:9002"`} {
		wantContains(t, "yaml after adding a", yaml, want)
	}
	if strings.Index(yaml, `- name: "a"`) > strings.Index(yaml, `- name: "b"`) {
		t.Error("routes must stay in name order")
	}
	wantContains(t, "second emit", second, "processor address of server a is new: 127.0.0.1:9003", "serve --server b --target b --listen 127.0.0.1:9001", "serve --server c --target c --listen 127.0.0.1:9002")
	wantNotContains(t, "second emit", second, "server b changed", "server c changed", "server b is new", "server c is new")

	// A re-emit that changes nothing prints no address line and adds no entry.
	n := len(c.auditEntries())
	wantNotContains(t, "unchanged re-emit", c.ok("emit", "--out", out), "processor address of server")
	if got := len(c.auditEntries()); got != n {
		t.Errorf("an unchanged re-emit added %d audit entry(ies)", got-n)
	}

	// An override wins over the recorded address, the move is printed and
	// recorded, and a later emit without the override keeps the new address.
	third := c.ok("emit", "--out", out, "--processor", "c=127.0.0.1:9200")
	wantContains(t, "third emit", third, "processor address of server c changed from 127.0.0.1:9002 to 127.0.0.1:9200; restart its processor on the new address")
	wantContains(t, "yaml after the override", readFile(t, out), `host: "127.0.0.1:9200"`, `host: "127.0.0.1:9001"`, `host: "127.0.0.1:9003"`)
	if entries := c.processorSetEntries(); len(entries) != 4 || entries[3].Subject != "c" || entries[3].Detail != "processor_addr=127.0.0.1:9200" {
		t.Errorf("%s entries after the override = %+v", processorSetEvent, entries)
	}
	c.ok("server", "add", "d", u.url(), "--allow-private")
	wantContains(t, "fourth emit", c.ok("emit", "--out", out), "processor address of server d is new: 127.0.0.1:9201")

	// Another output file gets the same addresses: they come from the catalog,
	// not from a file.
	other := filepath.Join(t.TempDir(), "other.yaml")
	wantNotContains(t, "emit to another file", c.ok("emit", "--out", other), "processor address of server")
	wantContains(t, "other yaml", readFile(t, other), `host: "127.0.0.1:9001"`, `host: "127.0.0.1:9003"`, `host: "127.0.0.1:9200"`, `host: "127.0.0.1:9201"`)
}

// Fourth review (cli-docs-3, raised to high): the L19 attacker edited the
// processor address in the emitted file and recomputed the hash line;
// --expect-body-hash reported CONFIG-EDITED, and the documented remedy (run
// emit again) adopted the forged address from the file, printed no change line
// and resealed it, after which the canary with the new hash and a mirroring
// live configuration said OK while the gateway dialled the attacker's
// processor. Now the re-emit takes the address from the catalog, the forged
// file is simply overwritten, and a live configuration that still dials the
// forged address is LIVE-CONFIG-MISMATCH.
func TestReEmitIgnoresAForgedAddressInTheFileAtOut(t *testing.T) {
	c, u := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	out := filepath.Join(t.TempDir(), "gateway.yaml")
	first := c.ok("emit", "--out", out)
	wantContains(t, "first emit", first, "serve --server s1 --target s1 --listen 127.0.0.1:9001")
	recorded := bodyHashOf(t, first)
	yaml := readFile(t, out)
	const good, evil = `- host: "127.0.0.1:9001"`, `- host: "127.0.0.1:4444"`
	if strings.Count(yaml, good) != 1 {
		t.Fatalf("the emitted file does not carry exactly one processor line %s:\n%s", good, yaml)
	}
	forged := reseal(t, strings.Replace(yaml, good, evil, 1))
	if _, ok := emit.Verify([]byte(forged)); !ok {
		t.Fatal("the forged file does not verify, so the premise of limit L19 does not hold here")
	}
	if err := os.WriteFile(out, []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	g := newUpstream(t, map[string]string{"echo": echoV1})
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", g.url()+routePath, "--config", out, "--expect-body-hash", recorded, "--no-probe")
	wantContains(t, "canary against the forged file", r.stdout, verdictConfigEdited, "recomputed the header hash")

	second := c.ok("emit", "--out", out)
	after := readFile(t, out)
	wantNotContains(t, "re-emitted file", after, evil)
	wantContains(t, "re-emitted file", after, good)
	wantNotContains(t, "re-emit output", second, "processor address of server", "127.0.0.1:4444")
	wantContains(t, "re-emit output", second, "serve --server s1 --target s1 --listen 127.0.0.1:9001")
	wantContains(t, "server list", c.ok("server", "list"), "127.0.0.1:9001")

	admin := serveAdmin(t, http.StatusOK, adminDoc(t, u.url(), `"127.0.0.1:9001"`, `"127.0.0.1:4444"`))
	r = c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", g.url()+routePath, "--config", out, "--expect-body-hash", bodyHashOf(t, second), "--admin", admin.hostPort(), "--no-probe")
	wantContains(t, "canary after the re-emit", r.stdout, verdictLiveConfig+" s1: processor host: emitted 127.0.0.1:9001, live 127.0.0.1:4444")
	wantNotContains(t, "canary after the re-emit", r.stdout, verdictOK, verdictConfigEdited)
}

// Unit view of the same rule: b and c keep their recorded addresses when a is
// added, a first emit numbers from the base port, an override reserves its
// port without raising the start, and an unknown override is refused.
func TestPlanEmitKeepsPreviousAddresses(t *testing.T) {
	c := &command{name: "emit"}
	before := []catalog.Server{{ServerSpec: catalog.ServerSpec{Name: "b", URL: "http://127.0.0.1:3001/mcp"}}, {ServerSpec: catalog.ServerSpec{Name: "c", URL: "http://127.0.0.1:3002/mcp"}}}
	plans, err := planEmit(c, before, nil, defaultProcessorBasePort, processorOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	recorded := map[string]string{}
	for _, p := range plans {
		if p.previous != "" {
			t.Errorf("first emit: server %s has a previous address %s", p.name, p.previous)
		}
		recorded[p.name] = p.processor
	}
	if recorded["b"] != "127.0.0.1:9001" || recorded["c"] != "127.0.0.1:9002" {
		t.Fatalf("first emit: %v", recorded)
	}
	after := []catalog.Server{{ServerSpec: catalog.ServerSpec{Name: "a", URL: "http://127.0.0.1:3000/mcp"}}}
	for _, s := range before {
		s.ProcessorAddr = recorded[s.Name]
		after = append(after, s)
	}
	plans, err = planEmit(c, after, nil, defaultProcessorBasePort, processorOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range plans {
		if old, ok := recorded[p.name]; ok && (old != p.processor || p.previous != old) {
			t.Errorf("server %s: processor moved from %s to %s because server a was added", p.name, old, p.processor)
		}
		if p.name == "a" && (p.processor != "127.0.0.1:9003" || p.previous != "") {
			t.Errorf("server a: %+v", p)
		}
	}
	plans, err = planEmit(c, before, nil, 7000, processorOverrides{"c": "127.0.0.1:7000"})
	if err != nil || plans[0].processor != "127.0.0.1:7001" || plans[1].processor != "127.0.0.1:7000" {
		t.Errorf("override on the base port: %v %+v", err, plans)
	}
	if _, err := planEmit(c, before, nil, 7000, processorOverrides{"nope": "127.0.0.1:1"}); err == nil {
		t.Error("an override for an unknown server was accepted")
	}
}

// The allocator never hands out a port in use and refuses to wrap around.
func TestPortAllocator(t *testing.T) {
	p := newPortAllocator(9001, map[string]string{"x": "10.0.0.7:9005", "y": "nonsense"}, processorOverrides{"z": "127.0.0.1:9006"})
	for _, want := range []int{9007, 9008} {
		if got, err := p.next(); err != nil || got != want {
			t.Errorf("next = %d, %v, want %d", got, err, want)
		}
	}
	tail := newPortAllocator(maxProcessorPort, nil, processorOverrides{"a": "127.0.0.1:65535"})
	if _, err := tail.next(); err == nil || !strings.Contains(err.Error(), "no free processor port") {
		t.Errorf("exhausted allocator: %v", err)
	}
	if port, ok := portOf("127.0.0.1:-1"); ok {
		t.Errorf("portOf(-1) = %d, %v", port, ok)
	}
}
