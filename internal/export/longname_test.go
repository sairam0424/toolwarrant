package export

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/sairam0424/toolwarrant/internal/toolname"
)

// cjk is a three-byte letter (U+5DE5), so a name made of it triples in size
// once percent-encoded; it is the cheapest way to exceed the file-name cap
// with a short, legitimate name.
const cjk = "\u5de5"

// validName fails the test unless name is legitimate per the shared rule, so
// the cases below exercise names the catalog really approves.
func validName(t testing.TB, name string) string {
	t.Helper()
	if err := toolname.Validate(name); err != nil {
		t.Fatalf("test setup: a %d-byte name must pass the shared name rule: %v", len(name), err)
	}
	return name
}

// Ported from the review's TestReview_OneLongApprovedNameFailsTheWholeExport.
// The shared name rule accepts 256 bytes and the catalog approves such names,
// but a file name is capped at 200 encoded bytes. One such tool used to fail
// the whole Write, so the mirror stopped recording every other approval until
// the operator disabled the tool. It is now skipped and reported, like a case
// collision, and every other tool is written.
func TestWrite_LongToolNameIsSkippedNotFatal(t *testing.T) {
	cases := map[string]string{
		"201 ascii bytes":           strings.Repeat("x", maxEncodedNameBytes+1),
		"69 raw bytes, 207 encoded": strings.Repeat(cjk, 23),
	}
	for label, name := range cases {
		validName(t, name)
		dir := filepath.Join(t.TempDir(), "out")
		long := mkTool(t, "alpha", name, "v1")
		ok := mkTool(t, "alpha", "ok", "v1")
		fine := mkTool(t, "beta", "fine", "v1")
		rep, err := Write(dir, []Tool{long, ok, fine}, testOpts)
		if err != nil {
			t.Fatalf("%s: Write: %v", label, err)
		}
		wantSkipped := []Skipped{{Server: "alpha", Name: name, Reason: ReasonNameTooLong}}
		if rep.Written != 2 || rep.Removed != 0 || rep.Unchanged != 0 || !reflect.DeepEqual(rep.Skipped, wantSkipped) {
			t.Fatalf("%s: report = %+v", label, rep)
		}
		if files := readManifest(t, dir).files(); !reflect.DeepEqual(files, []string{"alpha/ok.json", "beta/fine.json"}) {
			t.Fatalf("%s: manifest files = %v", label, files)
		}
		regular := 0
		for p, e := range snapshot(t, dir) {
			if e.Mode.IsRegular() {
				regular++
			}
			if n := len(filepath.Base(p)); n > maxEncodedNameBytes+len(jsonSuffix) {
				t.Errorf("%s: a %d-byte file name was written, over the cap", label, n)
			}
		}
		if regular != 3 {
			t.Fatalf("%s: regular files = %d, want the two tools and the manifest", label, regular)
		}
		again, err := Write(dir, []Tool{fine, ok, long}, testOpts)
		if err != nil || again.Written != 0 || again.Unchanged != 2 || !reflect.DeepEqual(again.Skipped, wantSkipped) {
			t.Fatalf("%s: second Write = %+v, %v", label, again, err)
		}
	}
}

// The longest name the shared rule accepts, whatever its bytes, is approved by
// the catalog and must never make Write fail: it is written when it fits the
// file-name cap and skipped when it does not. The cap itself is the boundary:
// 200 encoded bytes are written, 201 are skipped.
func TestWrite_MaxLengthAndBoundaryNamesNeverFail(t *testing.T) {
	cases := map[string]struct {
		name    string
		skipped bool
	}{
		"exactly the cap":               {strings.Repeat("x", maxEncodedNameBytes), false},
		"one over the cap":              {strings.Repeat("x", maxEncodedNameBytes+1), true},
		"max bytes, ascii":              {strings.Repeat("a", toolname.MaxBytes), true},
		"max bytes, every byte escaped": {strings.Repeat("/", toolname.MaxBytes), true},
		"max bytes, three-byte letters": {strings.Repeat(cjk, toolname.MaxBytes/3) + "x", true},
		"fits raw, not once encoded":    {strings.Repeat(cjk, 66) + "xx", true},
	}
	for label, c := range cases {
		validName(t, c.name)
		if strings.HasPrefix(label, "max bytes") && len(c.name) != toolname.MaxBytes {
			t.Fatalf("%s: test setup: %d bytes, want %d", label, len(c.name), toolname.MaxBytes)
		}
		dir := filepath.Join(t.TempDir(), "out")
		rep, err := Write(dir, []Tool{mkTool(t, "s", c.name, "v"), mkTool(t, "s", "short", "v")}, testOpts)
		if err != nil {
			t.Fatalf("%s (%d bytes): Write failed on a name the catalog approves: %v", label, len(c.name), err)
		}
		switch {
		case c.skipped && (rep.Written != 1 || len(rep.Skipped) != 1 || rep.Skipped[0].Name != c.name || rep.Skipped[0].Reason != ReasonNameTooLong):
			t.Errorf("%s: want the long name skipped and the short one written, got %+v", label, rep)
		case !c.skipped && (rep.Written != 2 || len(rep.Skipped) != 0):
			t.Errorf("%s: a name within the cap must be written, got %+v", label, rep)
		}
	}
}

// Any single name the shared rule accepts is planned or skipped, never
// refused: the catalog approves such names and a refusal would block the
// mirror. The outcome must also agree with encodeName, so a name that fits is
// never skipped by mistake. Names are built to a byte budget drawn from the
// whole range the rule allows, over an alphabet that stays in NFC, so about
// half of them exceed the file-name cap once encoded and the skip path is
// exercised rather than merely permitted.
func TestPlanAll_NeverRefusesAValidToolName(t *testing.T) {
	pieces := rapid.SampledFrom([]string{"x", "Z", "7", "_", "-", "/", ".", "%", cjk, "\u00e9", "\u03a9", "\U0001F600"})
	rapid.Check(t, func(rt *rapid.T) {
		budget := rapid.IntRange(1, toolname.MaxBytes).Draw(rt, "bytes")
		var b strings.Builder
		for piece := pieces.Draw(rt, "piece"); b.Len()+len(piece) <= budget; piece = pieces.Draw(rt, "piece") {
			b.WriteString(piece)
		}
		name := b.String()
		if name == "" {
			name = "x" // the first piece alone was over a one- or two-byte budget
		}
		if err := toolname.Validate(name); err != nil {
			rt.Fatalf("test alphabet produced a name the shared rule refuses: %v", err)
		}
		planned, skipped, err := planAll([]Tool{mkTool(t, "s", name, "v")})
		if err != nil {
			rt.Fatalf("planAll refused a %d-byte name the shared rule accepts: %v", len(name), err)
		}
		enc, encErr := encodeName("tool", name)
		switch {
		case encErr == nil && (len(planned) != 1 || len(skipped) != 0 || planned[0].encTool != enc):
			rt.Fatalf("a name that fits must be planned: planned=%d skipped=%d", len(planned), len(skipped))
		case encErr != nil && (len(planned) != 0 || len(skipped) != 1 || skipped[0].Reason != ReasonNameTooLong):
			rt.Fatalf("a name that does not fit must be skipped: planned=%d skipped=%d", len(planned), len(skipped))
		}
	})
}

// A skip is for the upstream's choice of name only. A long-named tool whose
// content the caller got wrong, one passed twice, one with no name, or one
// under a server name that is itself too long still refuses the whole batch,
// so a catalog bug can never hide behind a skip.
func TestWrite_LongNamedToolStillFailsOnCallerErrors(t *testing.T) {
	long := strings.Repeat("x", maxEncodedNameBytes+1)
	badDigest := mkTool(t, "s", long, "v")
	badDigest.Digest = strings.Repeat("0", 64)
	cases := map[string][]Tool{
		"digest mismatch":      {mkTool(t, "s", "ok", "v"), badDigest},
		"exact duplicate":      {mkTool(t, "s", long, "v"), mkTool(t, "s", long, "v")},
		"empty name":           {mkTool(t, "s", "ok", "v"), mkTool(t, "s", "", "v")},
		"server name too long": {mkTool(t, long, "ok", "v")},
		"both names too long":  {mkTool(t, long, long, "v")},
	}
	for label, tools := range cases {
		dir := filepath.Join(t.TempDir(), "out")
		_, err := Write(dir, tools, testOpts)
		if err == nil {
			t.Errorf("%s: want an error", label)
		}
		if errors.Is(err, errToolNameTooLong) {
			t.Errorf("%s: the refusal must not be the skip sentinel: %v", label, err)
		}
		if strings.HasPrefix(label, "server") && !errors.Is(err, errNameTooLong) {
			t.Errorf("%s: want a server-name length error, got %v", label, err)
		}
		if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
			t.Errorf("%s: a refused batch must not create the directory", label)
		}
	}
}

// Skipped is sorted by server then name across both reasons, so the report is
// stable whatever order the caller used.
func TestWrite_SkippedIsSortedAcrossReasons(t *testing.T) {
	long := strings.Repeat("z", maxEncodedNameBytes+1)
	dir := filepath.Join(t.TempDir(), "out")
	rep, err := Write(dir, []Tool{mkTool(t, "t", long, "1"), mkTool(t, "s", "Fetch", "1"), mkTool(t, "s", long, "1"), mkTool(t, "s", "fetch", "2")}, testOpts)
	if err != nil {
		t.Fatal(err)
	}
	want := []Skipped{
		{Server: "s", Name: "Fetch", Reason: ReasonCaseCollision},
		{Server: "s", Name: "fetch", Reason: ReasonCaseCollision},
		{Server: "s", Name: long, Reason: ReasonNameTooLong},
		{Server: "t", Name: long, Reason: ReasonNameTooLong},
	}
	if rep.Written != 0 || !reflect.DeepEqual(rep.Skipped, want) {
		t.Fatalf("report = %+v", rep)
	}
	if doc := readManifest(t, dir); len(doc.Tools) != 0 || doc.Status != statusComplete {
		t.Fatalf("manifest = %+v, want a complete manifest with no tools", doc)
	}
}

// The reason names the cap so the operator reading the warning learns the
// limit; the number must follow the constant.
func TestReasonNameTooLong_NamesTheCap(t *testing.T) {
	if !strings.Contains(ReasonNameTooLong, strconv.Itoa(maxEncodedNameBytes)) {
		t.Fatalf("ReasonNameTooLong = %q does not name the cap %d", ReasonNameTooLong, maxEncodedNameBytes)
	}
}
