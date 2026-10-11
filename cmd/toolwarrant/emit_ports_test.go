package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/catalog"
)

// Third review (processor-emit-8): emit gave the i-th server in name order
// the processor 127.0.0.1:(base+i), so adding a server whose name sorts first
// renumbered every later server; the processors already running kept their
// old ports and the reloaded gateway sent each route's hooks to the wrong
// processor or to nobody. Now a re-emit keeps every server's address as the
// existing file has it, a new server takes the next free port above the ones
// in use, and the change is printed (D13 g).
func TestEmitKeepsProcessorAddressesAcrossReEmits(t *testing.T) {
	c := newCLI(t)
	u := newUpstream(t, map[string]string{"echo": echoV1})
	c.ok("server", "add", "b", u.url(), "--allow-private")
	c.ok("server", "add", "c", u.url(), "--allow-private")
	out := filepath.Join(t.TempDir(), "gateway.yaml")
	first := c.ok("emit", "--out", out)
	wantContains(t, "first emit", first, "127.0.0.1:9001", "127.0.0.1:9002")
	wantNotContains(t, "first emit", first, "processor address of server")
	before := readFile(t, out)

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
	wantNotContains(t, "second emit", second, "server b changed", "server c changed")

	// An override wins over the kept address, and the move is printed.
	third := c.ok("emit", "--out", out, "--processor", "c=127.0.0.1:9200")
	wantContains(t, "third emit", third, "processor address of server c changed from 127.0.0.1:9002 to 127.0.0.1:9200; restart its processor on the new address")
	wantContains(t, "yaml after the override", readFile(t, out), `host: "127.0.0.1:9200"`, `host: "127.0.0.1:9001"`, `host: "127.0.0.1:9003"`)
	// Without the override the kept address is the overridden one now, and
	// a new server lands above it.
	c.ok("server", "add", "d", u.url(), "--allow-private")
	wantContains(t, "fourth emit", c.ok("emit", "--out", out), "processor address of server d is new: 127.0.0.1:9201")

	// A file that is not what emit wrote lends no addresses: a warning says
	// so and the servers are numbered afresh from the base port.
	if err := os.WriteFile(out, []byte(strings.Replace(before, "failClosed", "failOpen", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	r := c.run("emit", "--out", out)
	if r.code != exitOK {
		t.Fatalf("emit over an edited file: exit %d: %s", r.code, r.stderr)
	}
	wantContains(t, "stderr", r.stderr, "warning: "+out+" exists but is not what emit wrote, so no processor address was kept from it")
	wantNotContains(t, "stdout", r.stdout, "processor address of server")
	wantContains(t, "yaml afresh", readFile(t, r.stdout[len("wrote "):strings.Index(r.stdout, "\n")]), `host: "127.0.0.1:9001"`, `host: "127.0.0.1:9004"`)
}

// Unit view of the same rule: b and c keep 9001 and 9002 when a is added.
func TestPlanEmitKeepsPreviousAddresses(t *testing.T) {
	c := &command{name: "emit"}
	before := []catalog.Server{{ServerSpec: catalog.ServerSpec{Name: "b", URL: "http://127.0.0.1:3001/mcp"}}, {ServerSpec: catalog.ServerSpec{Name: "c", URL: "http://127.0.0.1:3002/mcp"}}}
	plans, err := planEmit(c, before, nil, defaultProcessorBasePort, processorOverrides{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	previous := map[string]string{}
	for _, p := range plans {
		previous[p.name] = p.processor
	}
	if previous["b"] != "127.0.0.1:9001" || previous["c"] != "127.0.0.1:9002" {
		t.Fatalf("first emit: %v", previous)
	}
	after := append([]catalog.Server{{ServerSpec: catalog.ServerSpec{Name: "a", URL: "http://127.0.0.1:3000/mcp"}}}, before...)
	plans, err = planEmit(c, after, nil, defaultProcessorBasePort, processorOverrides{}, previous)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range plans {
		if old, ok := previous[p.name]; ok && (old != p.processor || p.previous != old) {
			t.Errorf("server %s: processor moved from %s to %s because server a was added", p.name, old, p.processor)
		}
		if p.name == "a" && (p.processor != "127.0.0.1:9003" || p.previous != "") {
			t.Errorf("server a: %+v", p)
		}
	}
	// An override reserves its port without raising the start, so a first
	// emit with one still numbers the others from the base port.
	plans, err = planEmit(c, before, nil, 7000, processorOverrides{"c": "127.0.0.1:7000"}, nil)
	if err != nil || plans[0].processor != "127.0.0.1:7001" || plans[1].processor != "127.0.0.1:7000" {
		t.Errorf("override on the base port: %v %+v", err, plans)
	}
	if _, err := planEmit(c, before, nil, 7000, processorOverrides{"nope": "127.0.0.1:1"}, nil); err == nil {
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

// readPreviousFile: a missing file is the first emit, an edited file lends
// nothing and says so, and a path that cannot be read is an error.
func TestReadPreviousFile(t *testing.T) {
	dir := t.TempDir()
	prev, err := readPreviousFile(filepath.Join(dir, "absent.yaml"))
	if err != nil || prev.read || prev.warning != "" || len(prev.processors) != 0 {
		t.Errorf("absent file: %+v %v", prev, err)
	}
	edited := filepath.Join(dir, "edited.yaml")
	if err := os.WriteFile(edited, []byte("routes: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev, err = readPreviousFile(edited)
	if err != nil || prev.read || !strings.Contains(prev.warning, "not what emit wrote") {
		t.Errorf("edited file: %+v %v", prev, err)
	}
	if _, err := readPreviousFile(dir); err == nil || !strings.Contains(err.Error(), "read the existing file") {
		t.Errorf("directory: %v", err)
	}
}
