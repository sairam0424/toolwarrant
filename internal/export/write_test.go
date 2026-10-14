package export

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestWrite_LayoutManifestAndModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "approved")
	echo := mkTool(t, "weather", "echo", "Echoes.")
	add := mkTool(t, "math", "add", "Adds.")
	rep := mustWrite(t, dir, echo, add)

	wantReport(t, rep, 2, 0, 0)
	if got := readFile(t, filepath.Join(dir, "weather", "echo.json")); got != string(echo.Canonical)+"\n" {
		t.Fatalf("echo.json = %q", got)
	}
	for _, p := range []string{"weather/echo.json", "math/add.json", "MANIFEST.json"} {
		if m := snapshot(t, dir)[p].Mode; m != 0o644 {
			t.Errorf("%s mode = %v, want 0644", p, m)
		}
	}
	for _, p := range []string{".", "weather", "math"} {
		if m := snapshot(t, dir)[p].Mode.Perm(); m != 0o755 {
			t.Errorf("%s mode = %v, want 0755", p, m)
		}
	}
	for p := range snapshot(t, dir) {
		if strings.Contains(p, ".tmp-") {
			t.Errorf("temporary file left behind: %s", p)
		}
	}
}

func TestWrite_ManifestIsSortedPrettyAndUTC(t *testing.T) {
	dir := t.TempDir()
	zed := mkTool(t, "b", "zed", "z")
	alpha := mkTool(t, "b", "alpha", "a")
	first := mkTool(t, "a", "only", "o")
	first.VersionNo = 7
	mustWrite(t, dir, zed, alpha, first)

	raw := readFile(t, filepath.Join(dir, "MANIFEST.json"))
	if !strings.HasSuffix(raw, "}\n") || !strings.Contains(raw, "\n    {\n      \"server\": \"a\"") {
		t.Fatalf("manifest is not pretty printed with a trailing newline:\n%s", raw)
	}
	var doc manifestDoc
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != manifestVersion || doc.Status != statusComplete {
		t.Fatalf("version/status = %d/%q", doc.Version, doc.Status)
	}
	var order []string
	for _, e := range doc.Tools {
		order = append(order, e.Server+"/"+e.Tool)
	}
	if want := []string{"a/only", "b/alpha", "b/zed"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("manifest order = %v, want %v", order, want)
	}
	got := doc.Tools[0]
	want := manifestEntry{
		Server: "a", Tool: "only", File: "a/only.json", Digest: first.Digest,
		ApprovedBy: "alice@example.com", ApprovedAt: "2026-10-07T12:30:05Z", VersionNo: 7,
	}
	if got != want {
		t.Fatalf("entry = %+v, want %+v", got, want)
	}
}

// The manifest used to carry the raw upstream names, so a tool called
// "a<b>&c" put those bytes into a file people read with git diff. It now
// holds the percent-encoded names, which are also the file names.
func TestWrite_ManifestHoldsEncodedNamesOnly(t *testing.T) {
	dir := t.TempDir()
	tool := mkTool(t, "s", "a<b>&c", "x")
	mustWrite(t, dir, tool)
	raw := readFile(t, filepath.Join(dir, "MANIFEST.json"))
	if !strings.Contains(raw, `"tool": "a%3Cb%3E%26c"`) || !strings.Contains(raw, `"file": "s/a%3Cb%3E%26c.json"`) {
		t.Fatalf("manifest does not hold the encoded name:\n%s", raw)
	}
	if strings.ContainsAny(raw, "<>&") {
		t.Fatalf("manifest carries a raw name byte:\n%s", raw)
	}
}

func TestWrite_TwiceIsByteIdenticalAndUntouched(t *testing.T) {
	dir := t.TempDir()
	a := mkTool(t, "s1", "one", "1")
	b := mkTool(t, "s2", "two", "2")
	c := mkTool(t, "s2", "three", "3")
	mustWrite(t, dir, a, b, c)
	before := snapshot(t, dir)

	time.Sleep(20 * time.Millisecond)
	rep := mustWrite(t, dir, c, b, a) // different input order
	after := snapshot(t, dir)

	wantReport(t, rep, 0, 0, 3)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("directory changed between identical writes (times included):\nbefore %v\nafter  %v", names(before), names(after))
	}
}

func TestWrite_ChangedToolIsRewrittenOthersAreNot(t *testing.T) {
	dir := t.TempDir()
	a := mkTool(t, "s", "one", "v1")
	b := mkTool(t, "s", "two", "v1")
	mustWrite(t, dir, a, b)
	a2 := mkTool(t, "s", "one", "v2 with different length")
	a2.VersionNo = 2

	rep := mustWrite(t, dir, a2, b)
	wantReport(t, rep, 1, 0, 1)
	if !strings.Contains(readFile(t, filepath.Join(dir, "s", "one.json")), "v2 with") {
		t.Fatal("changed tool was not rewritten")
	}
	// Same length, different bytes must also be detected.
	a3 := mkTool(t, "s", "one", "v3 with different length")
	if rep := mustWrite(t, dir, a3, b); rep.Written != 1 {
		t.Fatalf("same-size change not detected: %+v", rep)
	}
}

func TestWrite_EmptyListClearsOnlyCreatedFiles(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, mkTool(t, "s", "one", "1"))
	rep := mustWrite(t, dir)
	wantReport(t, rep, 0, 1, 0)
	snap := snapshot(t, dir)
	if _, ok := snap["s"]; ok {
		t.Fatal("empty server directory must be removed")
	}
	var doc manifestDoc
	if err := json.Unmarshal([]byte(snap["MANIFEST.json"].Content), &doc); err != nil || doc.Tools == nil || len(doc.Tools) != 0 {
		t.Fatalf("manifest must list an empty tools array, got %q (%v)", snap["MANIFEST.json"].Content, err)
	}
	if doc.Status != statusComplete {
		t.Fatalf("status = %q", doc.Status)
	}
}

func TestWrite_CreatesMissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b", "export")
	mustWrite(t, dir, mkTool(t, "s", "one", "1"))
	if _, err := os.Stat(filepath.Join(dir, "s", "one.json")); err != nil {
		t.Fatal(err)
	}
}

// A corpus of hostile names must never create a path outside dir nor collide.
func TestWrite_HostileNameCorpusStaysInsideDir(t *testing.T) {
	corpus := []string{
		"../x", "..", ".", "a/b", "/abs", `..\x`, `a\b`, "a\x00b", "\x00", "~", "$(id)", "`id`",
		"CON", "nul.txt", ".git", ".git/config", "MANIFEST.json", "x.json", "é", "a b", "-rf", "--", "%2E%2E",
		"../../../../etc/passwd", "a/../../b", "..%2F", "line\nbreak", "tab\t", "*", "?", "<>", "a:b", ".tmp-x",
	}
	parent := t.TempDir()
	sentinel := filepath.Join(parent, "sentinel.txt")
	writeFile(t, sentinel, "keep")
	dir := filepath.Join(parent, "out")
	var tools []Tool
	for _, n := range corpus {
		tools = append(tools, mkTool(t, n, n, "body"))
		tools = append(tools, mkTool(t, "srv", n, "body"))
	}
	rep := mustWrite(t, dir, tools...)
	wantReport(t, rep, 2*len(corpus), 0, 0)

	for p := range snapshot(t, parent) {
		if p == "." || p == "sentinel.txt" || p == "out" || strings.HasPrefix(p, "out"+string(filepath.Separator)) {
			continue
		}
		t.Errorf("file outside the export directory: %s", p)
	}
	if readFile(t, sentinel) != "keep" {
		t.Fatal("sentinel was modified")
	}
	// Every tool landed in exactly one file: two per corpus entry plus the manifest.
	files := 0
	for p, e := range snapshot(t, dir) {
		if e.Mode.IsRegular() {
			files++
			if strings.Contains(p, "..") && !strings.Contains(p, "%2E") {
				t.Errorf("suspicious path %q", p)
			}
		}
	}
	if want := 2*len(corpus) + 1; files != want {
		t.Fatalf("regular files = %d, want %d", files, want)
	}
}

func TestWrite_CollisionsAreRefusedBeforeAnythingIsWritten(t *testing.T) {
	cases := map[string][]Tool{
		"exact duplicate":   {mkTool(t, "s", "a", "1"), mkTool(t, "s", "a", "2")},
		"case server":       {mkTool(t, "Srv", "a", "1"), mkTool(t, "srv", "b", "2")},
		"case plus escapes": {mkTool(t, "s", "é", "1"), mkTool(t, "s", "\u00c9", "2")}, // %C3%A9 vs %C3%89 differ: must NOT collide
	}
	for label, tools := range cases {
		dir := filepath.Join(t.TempDir(), "out")
		_, err := Write(dir, tools, testOpts)
		if label == "case plus escapes" {
			if err != nil {
				t.Errorf("%s: distinct names must not collide: %v", label, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: want a collision error", label)
		}
		if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
			t.Errorf("%s: directory must not be created on refusal", label)
		}
	}
}

// Two approved tools of one server whose names differ only in case used to
// make Write refuse the whole batch, so the mirror stopped recording every
// other approval. The colliding group is now left out and reported.
func TestWrite_CaseCollidingToolsAreSkippedNotFatal(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	upper := mkTool(t, "s", "Fetch", "1")
	lower := mkTool(t, "s", "fetch", "2")
	other := mkTool(t, "s", "other", "3")
	elsewhere := mkTool(t, "t", "fetch", "4")
	rep, err := Write(dir, []Tool{lower, other, upper, elsewhere}, testOpts)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	wantSkipped := []Skipped{
		{Server: "s", Name: "Fetch", Reason: ReasonCaseCollision},
		{Server: "s", Name: "fetch", Reason: ReasonCaseCollision},
	}
	if rep.Written != 2 || rep.Removed != 0 || rep.Unchanged != 0 || !reflect.DeepEqual(rep.Skipped, wantSkipped) {
		t.Fatalf("report = %+v", rep)
	}
	snap := snapshot(t, dir)
	for _, p := range []string{"s/other.json", "t/fetch.json"} {
		if _, ok := snap[p]; !ok {
			t.Errorf("%s must be written", p)
		}
	}
	for p := range snap {
		if strings.EqualFold(p, filepath.Join("s", "fetch.json")) {
			t.Errorf("a colliding tool was written: %s", p)
		}
	}
	if files := readManifest(t, dir).files(); !reflect.DeepEqual(files, []string{"s/other.json", "t/fetch.json"}) {
		t.Fatalf("manifest files = %v", files)
	}
	again, err := Write(dir, []Tool{lower, other, upper, elsewhere}, testOpts)
	if err != nil || again.Unchanged != 2 || !reflect.DeepEqual(again.Skipped, wantSkipped) {
		t.Fatalf("second Write = %+v, %v", again, err)
	}
	three, err := Write(filepath.Join(t.TempDir(), "three"), []Tool{upper, lower, mkTool(t, "s", "FETCH", "5")}, testOpts)
	if err != nil || three.Written != 0 || len(three.Skipped) != 3 {
		t.Fatalf("three-way collision: %+v, %v", three, err)
	}
}

func TestWrite_NamesThatLookAlikeAfterDecodingDoNotCollide(t *testing.T) {
	dir := t.TempDir()
	rep := mustWrite(t, dir, mkTool(t, "s", "a.b", "1"), mkTool(t, "s", "a%2Eb", "2"), mkTool(t, "s", "a%252Eb", "3"))
	wantReport(t, rep, 3, 0, 0)
}

func TestWrite_InputValidationRefusesAndTouchesNothing(t *testing.T) {
	good := mkTool(t, "s", "ok", "1")
	mut := func(f func(*Tool)) Tool {
		c := mkTool(t, "s", "bad", "1")
		f(&c)
		return c
	}
	cases := map[string]Tool{
		"digest mismatch":         mut(func(x *Tool) { x.Digest = strings.Repeat("0", 64) }),
		"upper-case digest":       mut(func(x *Tool) { x.Digest = strings.ToUpper(x.Digest) }),
		"empty digest":            mut(func(x *Tool) { x.Digest = "" }),
		"tampered canonical":      mut(func(x *Tool) { x.Canonical = append([]byte(nil), x.Canonical...); x.Canonical[2] ^= 1 }),
		"invalid json":            withDigest(t, []byte(`{"name":`)),
		"invalid utf-8 canonical": withDigest(t, []byte("{\"name\":\"t\",\"d\":\"\xff\xfe\"}")),
		"empty canonical":         mut(func(x *Tool) { x.Canonical = nil }),
		"negative version":        mut(func(x *Tool) { x.VersionNo = -1 }),
		"empty server":            mut(func(x *Tool) { x.Server = "" }),
		"empty name":              mut(func(x *Tool) { x.Name = "" }),
		"oversized":               withDigest(t, []byte(`"`+strings.Repeat("a", maxToolBytes)+`"`)),
		"approver too long":       mut(func(x *Tool) { x.ApprovedBy = strings.Repeat("a", maxApproverBytes+1) }),
		"approver invalid utf-8":  mut(func(x *Tool) { x.ApprovedBy = "al\xffice" }),
	}
	for label, bad := range cases {
		dir := filepath.Join(t.TempDir(), "out")
		if _, err := Write(dir, []Tool{good, bad}, testOpts); err == nil {
			t.Errorf("%s: want an error", label)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("%s: a rejected batch must not create or change the directory", label)
		}
	}
}

func TestWrite_DigestErrorNamesTheExpectedDigestOnly(t *testing.T) {
	bad := mkTool(t, "s", "x", "super secret description")
	bad.Digest = strings.Repeat("a", 64)
	_, err := Write(filepath.Join(t.TempDir(), "o"), []Tool{bad}, testOpts)
	if err == nil || strings.Contains(err.Error(), "super secret") {
		t.Fatalf("error must not leak the definition: %v", err)
	}
}

func TestWrite_EmptyDirArgumentIsRefused(t *testing.T) {
	if _, err := Write("", nil, testOpts); err == nil {
		t.Fatal("empty dir must be refused")
	}
}

func TestWrite_SortedPlannedHelper(t *testing.T) {
	in := []plannedTool{{rel: "b/a.json"}, {rel: "a/z.json"}}
	out := sortPlanned(in)
	if in[0].rel != "b/a.json" {
		t.Fatal("sortPlanned must not mutate its argument")
	}
	got := []string{out[0].rel, out[1].rel}
	if !sort.StringsAreSorted(got) {
		t.Fatalf("not sorted: %v", got)
	}
}
