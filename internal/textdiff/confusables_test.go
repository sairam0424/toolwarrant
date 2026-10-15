package textdiff

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

const (
	confusablesDataPath = "../../third_party/unicode/confusables.txt"
	confusablesGoPath   = "confusables_table.go"
	ciWorkflowPath      = "../../.github/workflows/ci.yml"
	dataVersionPrefix   = "# Version: "
	versionParts        = 3
	lintJob             = "lint"
	makeLintStep        = "- run: make lint\n"
	confusablesStep     = "- run: scripts/gen-confusables.sh --check\n"
)

// jobHeading matches the line that opens a job of the workflow.
var jobHeading = regexp.MustCompile(`(?m)^  [a-z][a-z0-9-]*:$`)

// readConfusables parses the vendored file the way the generator does, with
// an independent reading of the format: source ; target ; MA # comment.
func readConfusables(t *testing.T) (version string, table map[rune]string) {
	t.Helper()
	f, err := os.Open(confusablesDataPath)
	if err != nil {
		t.Fatalf("open the vendored data: %v", err)
	}
	defer func() { _ = f.Close() }()
	table = map[rune]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, dataVersionPrefix) {
			version = strings.TrimSpace(strings.TrimPrefix(line, dataVersionPrefix))
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		body, _, _ := strings.Cut(line, "#")
		fields := strings.Split(body, ";")
		if len(fields) < 3 || strings.TrimSpace(fields[2]) != "MA" {
			t.Fatalf("unexpected data line %q", line)
		}
		src := hexRunes(t, fields[0])
		if len(src) != 1 {
			t.Fatalf("source is not one code point: %q", line)
		}
		if _, dup := table[src[0]]; dup {
			t.Fatalf("duplicate source %U", src[0])
		}
		table[src[0]] = string(hexRunes(t, fields[1]))
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return version, table
}

func hexRunes(t *testing.T, field string) []rune {
	t.Helper()
	var out []rune
	for _, w := range strings.Fields(field) {
		v, err := strconv.ParseUint(w, 16, 32)
		if err != nil || !utf8.ValidRune(rune(v)) {
			t.Fatalf("bad code point %q", w)
		}
		out = append(out, rune(v))
	}
	return out
}

// The committed table is exactly the vendored file: the same sources, the same
// targets, sorted by source without a duplicate, and the generated header
// names the version and the count. A hand edit of the table or a data file
// swapped under it fails here and in scripts/gen-confusables.sh --check.
func TestConfusables_tableIsGeneratedFromTheVendoredFile(t *testing.T) {
	t.Parallel()
	version, want := readConfusables(t)
	if len(want) != len(confusables) {
		t.Fatalf("the table has %d entries, the vendored file %d", len(confusables), len(want))
	}
	for i, c := range confusables {
		if dst, ok := want[c.src]; !ok || dst != c.dst {
			t.Errorf("entry %d: %U maps to %q in the table, %q in the file", i, c.src, c.dst, dst)
		}
		if i > 0 && confusables[i-1].src >= c.src {
			t.Errorf("entry %d: %U does not sort after %U", i, c.src, confusables[i-1].src)
		}
		if dst, ok := confusableOf(c.src); !ok || dst != c.dst {
			t.Errorf("confusableOf(%U) = %q, %v", c.src, dst, ok)
		}
	}
	src, err := os.ReadFile(confusablesGoPath)
	if err != nil {
		t.Fatal(err)
	}
	header := strings.SplitN(string(src), "\n", 2)[0]
	for _, part := range []string{"Code generated", "DO NOT EDIT", "Version: " + version, strconv.Itoa(len(want)) + " mappings"} {
		if !strings.Contains(header, part) {
			t.Errorf("generated header %q lacks %q", header, part)
		}
	}
	for i := 0; i < len(src); i++ {
		if src[i] >= utf8.RuneSelf {
			t.Fatalf("the generated file holds a raw non-ASCII byte at %d; targets must be escapes", i)
		}
	}
	if _, ok := confusableOf(0x0061); ok {
		t.Error("the Latin a is a prototype, not a source")
	}
}

// The data version is the one the generator pins, and it is not older than
// the toolchain's unicode tables: go1.27 ships 17.0.0 and the vendored file is
// 18.0.0, since unicode.org publishes no 17.0.0 security directory. A newer
// table is safe (see Skeleton); an older one would miss code points the
// toolchain knows, so that is the direction refused.
func TestConfusables_versionIsTheVendoredHeaderAndNotOlderThanTheToolchains(t *testing.T) {
	t.Parallel()
	version, _ := readConfusables(t)
	if version != confusablesVersion {
		t.Fatalf("the vendored file says version %q, the table was generated from %q", version, confusablesVersion)
	}
	table, toolchain := parseVersion(t, confusablesVersion), parseVersion(t, unicode.Version)
	for i := range table {
		if table[i] > toolchain[i] {
			return
		}
		if table[i] < toolchain[i] {
			t.Fatalf("the confusables table is version %s, older than the toolchain's unicode %s", confusablesVersion, unicode.Version)
		}
	}
}

func parseVersion(t *testing.T, v string) [versionParts]int {
	t.Helper()
	parts := strings.Split(v, ".")
	if len(parts) != versionParts {
		t.Fatalf("version %q is not major.minor.patch", v)
	}
	var out [versionParts]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("version %q: %v", v, err)
		}
		out[i] = n
	}
	return out
}

// The lint job of ci.yml runs scripts/gen-confusables.sh --check after make
// lint, so a committed table that differs from the vendored data file fails
// every pull request. CHANGELOG.md and CLAUDE.md state that step; this is what
// keeps the statement true.
func TestConfusablesCI_lintJobRunsTheCheck(t *testing.T) {
	t.Parallel()
	workflow, err := os.ReadFile(ciWorkflowPath)
	if err != nil {
		t.Fatal(err)
	}
	job := jobBody(t, string(workflow), lintJob)
	lint, check := strings.Index(job, makeLintStep), strings.Index(job, confusablesStep)
	if lint < 0 {
		t.Fatalf("the %s job lacks the step %q", lintJob, strings.TrimSpace(makeLintStep))
	}
	if check < 0 {
		t.Fatalf("the %s job lacks the step %q", lintJob, strings.TrimSpace(confusablesStep))
	}
	if check < lint {
		t.Fatalf("the %s job runs %q before %q", lintJob, strings.TrimSpace(confusablesStep), strings.TrimSpace(makeLintStep))
	}
}

// jobBody returns the text of the named job of a workflow, from its heading to
// the next job heading or the end of the file; it fails when the job is absent.
func jobBody(t *testing.T, workflow, name string) string {
	t.Helper()
	heading := "\n  " + name + ":\n"
	start := strings.Index(workflow, heading)
	if start < 0 {
		t.Fatalf("%s has no job %q", ciWorkflowPath, name)
	}
	body := workflow[start+len(heading):]
	if next := jobHeading.FindStringIndex(body); next != nil {
		body = body[:next[0]]
	}
	return body
}
