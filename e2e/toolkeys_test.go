//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The L2 golden. agentgateway v1.6.0 deserialises every tools/list page into
// its own typed model and serialises it again before the ExtMCP hook runs, so
// a key path the model does not carry never reaches the processor (limit L2).
// Scenario L lists vendorTool through a route whose processor was removed,
// derives from the bytes a raw client received which key paths the gateway
// dropped, kept and added, and compares the three sorted lists with the
// fixture recorded on the pinned release. A difference fails the scenario
// naming the list and the entries: either the pin moved (L7) and the golden
// must be re-recorded from the file the run writes next to its process logs,
// or the gateway changed under the pin.
const (
	// toolKeysGoldenPath is the fixture, relative to this package directory;
	// go test runs a package's tests with that directory as working directory.
	toolKeysGoldenPath = "testdata/gateway_tool_keys.json"
	// toolKeysObservedFile is written into the run's log directory with the
	// lists the run derived, in the golden's exact layout, so a re-record is
	// one copy.
	toolKeysObservedFile = "gateway_tool_keys.observed.json"
	// pinnedGateway is the release the golden must name; a fixture recorded
	// on another release is refused rather than compared.
	pinnedGateway = "v1.6.0"
	// toolKeysIndent is the indentation of the golden and the observed file.
	toolKeysIndent = "  "
	// toolKeysFileMode is the mode of the observed file; it holds no secret.
	toolKeysFileMode = 0o644
)

// errToolKeysGolden is wrapped by every refusal of a golden file.
var errToolKeysGolden = errors.New("gateway tool keys golden")

// toolKeys are the three sorted key-path lists of one tool listed through the
// gateway: dropped are the upstream's paths the gateway did not serve, kept
// the paths both carry, added the served paths the upstream never sent.
type toolKeys struct {
	Gateway string   `json:"gateway"`
	Dropped []string `json:"dropped"`
	Kept    []string `json:"kept"`
	Added   []string `json:"added"`
}

// observeToolKeys derives the three lists from the upstream's definition and
// the one the gateway served, both as raw JSON, and names the pinned release.
func observeToolKeys(upstream, served json.RawMessage) (toolKeys, error) {
	var up, sv any
	if err := json.Unmarshal(upstream, &up); err != nil {
		return toolKeys{}, fmt.Errorf("upstream definition: %w", err)
	}
	if err := json.Unmarshal(served, &sv); err != nil {
		return toolKeys{}, fmt.Errorf("served definition: %w", err)
	}
	upKeys, svKeys := keyPaths(up, ""), keyPaths(sv, "")
	return toolKeys{
		Gateway: pinnedGateway,
		Dropped: missing(upKeys, svKeys),
		Kept:    missing(upKeys, missing(upKeys, svKeys)),
		Added:   missing(svKeys, upKeys),
	}, nil
}

// keyPaths lists every object key path in a JSON document, so two renderings
// of one tool can be compared key by key.
func keyPaths(v any, prefix string) []string {
	var out []string
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			out = append(out, path)
			out = append(out, keyPaths(child, path)...)
		}
	case []any:
		for i, child := range x {
			out = append(out, keyPaths(child, fmt.Sprintf("%s[%d]", prefix, i))...)
		}
	}
	return out
}

// missing returns the sorted members of a that are not in b, never nil, so
// that an empty list is written as [] and not as null.
func missing(a, b []string) []string {
	have := map[string]bool{}
	for _, k := range b {
		have[k] = true
	}
	out := []string{}
	for _, k := range a {
		if !have[k] {
			out = append(out, k)
		}
	}
	sortStrings(out)
	return out
}

// readToolKeysGolden reads a fixture and refuses one that names another
// release, carries a field this test does not know, or holds an unsorted or
// repeated list, so that a hand-edited golden cannot pass by accident.
func readToolKeysGolden(path string) (toolKeys, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return toolKeys{}, fmt.Errorf("%w: %w", errToolKeysGolden, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var g toolKeys
	if err := dec.Decode(&g); err != nil {
		return toolKeys{}, fmt.Errorf("%w %s: %w", errToolKeysGolden, path, err)
	}
	if g.Gateway != pinnedGateway {
		return toolKeys{}, fmt.Errorf("%w %s: recorded on gateway %q, this test runs against %s; re-record it", errToolKeysGolden, path, g.Gateway, pinnedGateway)
	}
	for _, l := range namedLists(g) {
		if l.list == nil {
			return toolKeys{}, fmt.Errorf("%w %s: list %q is missing", errToolKeysGolden, path, l.name)
		}
		if !slices.IsSorted(l.list) || len(slices.Compact(slices.Clone(l.list))) != len(l.list) {
			return toolKeys{}, fmt.Errorf("%w %s: list %q is not sorted and unique", errToolKeysGolden, path, l.name)
		}
	}
	return g, nil
}

// encodeToolKeys renders the lists in the golden's layout: two-space indent,
// the fields in declaration order, a final newline.
func encodeToolKeys(k toolKeys) ([]byte, error) {
	data, err := json.MarshalIndent(k, "", toolKeysIndent)
	if err != nil {
		return nil, fmt.Errorf("encode the gateway tool keys: %w", err)
	}
	return append(data, '\n'), nil
}

// writeObservedToolKeys writes what this run derived into the log directory
// and returns the path, so a failing comparison can point at the file to copy.
func writeObservedToolKeys(t *testing.T, s *stack, got toolKeys) string {
	t.Helper()
	path := filepath.Join(s.h.logDir, toolKeysObservedFile)
	data, err := encodeToolKeys(got)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := os.WriteFile(path, data, toolKeysFileMode); err != nil {
		t.Fatalf("write the observed gateway tool keys: %v", err)
	}
	return path
}

// listDiff says how got differs from want, both sorted, or "" when they are
// equal: the golden's entries the run did not see and the run's entries the
// golden does not name, each by path.
func listDiff(want, got []string) string {
	if slices.Equal(want, got) {
		return ""
	}
	var parts []string
	if m := missing(want, got); len(m) > 0 {
		parts = append(parts, fmt.Sprintf("the golden names %q, this run did not see them", m))
	}
	if m := missing(got, want); len(m) > 0 {
		parts = append(parts, fmt.Sprintf("this run saw %q, the golden does not name them", m))
	}
	if len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("the same members in another order or count: golden %q, run %q", want, got))
	}
	return strings.Join(parts, "; ")
}

// namedList is one of the three lists with its name in the golden.
type namedList struct {
	name string
	list []string
}

// namedLists returns the three lists in the golden's order, so that checks
// and messages name them in the order a reader sees them in the file.
func namedLists(k toolKeys) []namedList {
	return []namedList{{"dropped", k.Dropped}, {"kept", k.Kept}, {"added", k.Added}}
}

// compareToolKeys fails the test for every list that differs from the golden,
// naming the list, the entries and the file to copy if the pin moved.
func compareToolKeys(t *testing.T, want, got toolKeys, observed string) {
	t.Helper()
	wants, gots := namedLists(want), namedLists(got)
	for i, w := range wants {
		if d := listDiff(w.list, gots[i].list); d != "" {
			t.Errorf("L2 golden %s, list %q: %s; if the gateway pin moved (L7), re-record the golden from %s", toolKeysGoldenPath, w.name, d, observed)
		}
	}
}

// scenarioLKeys is the recording half of scenario L: with the processor
// removed from the hostile route, the gateway serves the re-serialised bytes
// of vendor_tool to a raw client, and the key paths it dropped, kept and
// added are noted, written next to the process logs and compared with the
// golden. The named assertion that the unknown top-level key x-vendor is
// dropped stays, because it is what keeps the tool mismatching with the
// processor in place. The MCP protocol version the gateway negotiated with
// the raw client is noted too: scripts/requalify-gateway.sh compares it with
// the revision the probe and the crawler send when the pin moves (L7).
func scenarioLKeys(t *testing.T, s *stack, vendor json.RawMessage) {
	t.Helper()
	raw := openRaw(t, s.routeURL("hostile"))
	s.note(t, "L: the gateway negotiated MCP protocol version %s with a raw client that asked for %s", raw.protocol, defaultProtocol)
	served := servedTool(t, raw.listRaw(t), "vendor_tool")
	got, err := observeToolKeys(vendor, served)
	if err != nil {
		t.Fatalf("compare definitions: %v", err)
	}
	s.note(t, "L: keys the gateway dropped before the hook: %v; kept: %v; added: %v", got.Dropped, got.Kept, got.Added)
	s.note(t, "L: upstream served %s", vendor)
	s.note(t, "L: gateway served  %s", served)
	if !slices.Contains(got.Dropped, "x-vendor") {
		t.Errorf("the gateway kept the unknown top-level key x-vendor, so the processor's mismatch has another cause; dropped %v", got.Dropped)
	}
	observed := writeObservedToolKeys(t, s, got)
	want, err := readToolKeysGolden(toolKeysGoldenPath)
	if err != nil {
		t.Errorf("%v; the lists this run derived are in %s", err, observed)
		return
	}
	compareToolKeys(t, want, got, observed)
}

// TestToolKeysGoldenRefusesWhatItCannotCompare pins the refusals of the L2
// golden reader and the words of a list difference without a gateway: a
// fixture from another release, an unknown field and an unsorted list are
// errors, and listDiff names the entries on each side.
func TestToolKeysGoldenRefusesWhatItCannotCompare(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), toolKeysFileMode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cases := map[string]string{
		`{"gateway":"v9.9.9","dropped":[],"kept":[],"added":[]}`:                        `recorded on gateway "v9.9.9"`,
		`{"gateway":"v1.6.0","dropped":[],"kept":[],"added":[],"extra":1}`:              `unknown field "extra"`,
		`{"gateway":"v1.6.0","dropped":["b","a"],"kept":[],"added":[]}`:                 `list "dropped" is not sorted and unique`,
		`{"gateway":"v1.6.0","dropped":[],"kept":["a","a"],"added":[]}`:                 `list "kept" is not sorted and unique`,
		`{"gateway":"v1.6.0","dropped":[],"kept":[]}`:                                   `list "added" is missing`,
		`{"gateway":"v1.6.0","dropped":["x-vendor"],"kept":["name"],"added":[]}` + "\n": "",
	}
	for body, want := range cases {
		_, err := readToolKeysGolden(write("golden.json", body))
		switch {
		case want == "" && err != nil:
			t.Errorf("%s: unexpected error %v", body, err)
		case want != "" && (err == nil || !errors.Is(err, errToolKeysGolden) || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: got %v, want an error wrapping errToolKeysGolden and containing %q", body, err, want)
		}
	}
	if _, err := readToolKeysGolden(filepath.Join(dir, "absent.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("absent golden: got %v, want a not-exist error", err)
	}
	if d := listDiff([]string{"a", "b"}, []string{"b", "c"}); d != `the golden names ["a"], this run did not see them; this run saw ["c"], the golden does not name them` {
		t.Errorf("listDiff: %s", d)
	}
	if d := listDiff([]string{"a"}, []string{"a"}); d != "" {
		t.Errorf("listDiff of equal lists: %q", d)
	}
	got, err := observeToolKeys(json.RawMessage(`{"name":"t","x":{"y":1},"_meta":{"k":"v"}}`), json.RawMessage(`{"name":"t","_meta":{"k":"v"},"z":true}`))
	if err != nil {
		t.Fatal(err)
	}
	want := toolKeys{Gateway: pinnedGateway, Dropped: []string{"x", "x.y"}, Kept: []string{"_meta", "_meta.k", "name"}, Added: []string{"z"}}
	if !slices.Equal(got.Dropped, want.Dropped) || !slices.Equal(got.Kept, want.Kept) || !slices.Equal(got.Added, want.Added) || got.Gateway != want.Gateway {
		t.Errorf("observeToolKeys: got %+v, want %+v", got, want)
	}
}
