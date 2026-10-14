package requalifypolicy

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	// scriptFile and libFile are the checklist runner and the helpers it sources.
	scriptFile = "scripts/requalify-gateway.sh"
	libFile    = "scripts/requalify-lib.sh"
	// scenarioFile holds the TestEndToEnd scenario table.
	scenarioFile = "e2e/e2e_test.go"
	// ciFile holds the dispatch job that runs the script.
	ciFile = ".github/workflows/ci.yml"
	// itemCount is the number of checklist items the document and the script
	// agree on; items_total in the script must say the same.
	itemCount = 17
	// maxParentDirs bounds the walk from the package directory to go.mod.
	maxParentDirs = 6
)

var (
	// testName is a cited top-level test name; the e2e subtest form
	// TestEndToEnd/X_Name is cut at the slash by the regexp.
	testName = regexp.MustCompile(`\bTest[A-Z][A-Za-z0-9_]*`)
	// scenarioRef is an e2e subtest the script reads, as go test -v names it.
	scenarioRef = regexp.MustCompile(`TestEndToEnd/([A-Z]_[A-Za-z0-9]+)`)
	// scenarioEntry is one row of the scenario table in e2e/e2e_test.go.
	scenarioEntry = regexp.MustCompile(`\{"([A-Z]_[A-Za-z0-9]+)", scenario`)
	// itemNumber is the number of an item as the script reports it: a status
	// and a number, or the number item_tests is given. PENDING is not a
	// status any more: item 15 became a real item when scenario Q landed.
	itemNumber = regexp.MustCompile(`(?m)(?:report (?:PASS|CHANGED|SKIPPED)|^item_tests) ([0-9]+) `)
	// testFunc is a test function declaration in a _test.go file.
	testFunc = regexp.MustCompile(`(?m)^func (Test[A-Z][A-Za-z0-9_]*)\(`)
)

// TestRequalifyScript_citesExistingTestsAndScenarios fails when the script
// names a test no _test.go file of the module declares, or an e2e scenario
// TestEndToEnd does not run.
func TestRequalifyScript_citesExistingTestsAndScenarios(t *testing.T) {
	root := moduleRoot(t)
	script := readFile(t, filepath.Join(root, scriptFile)) + readFile(t, filepath.Join(root, libFile))
	declared := declaredTests(t, root)
	cited := uniqueMatches(testName, script, 0)
	if len(cited) < itemCount {
		t.Fatalf("the script cites %d test names, fewer than its %d items; the regexp or the script is wrong", len(cited), itemCount)
	}
	for _, name := range cited {
		if !declared[name] {
			t.Errorf("%s cites %s, which no _test.go file declares", scriptFile, name)
		}
	}
	scenarios := uniqueMatches(scenarioEntry, readFile(t, filepath.Join(root, scenarioFile)), 1)
	refs := uniqueMatches(scenarioRef, script, 1)
	if len(refs) == 0 {
		t.Fatal("the script reads no TestEndToEnd scenario; the regexp or the script is wrong")
	}
	for _, ref := range refs {
		if !slices.Contains(scenarios, ref) {
			t.Errorf("%s reads TestEndToEnd/%s, which %s does not run (it runs %s)", scriptFile, ref, scenarioFile, strings.Join(scenarios, ", "))
		}
	}
}

// TestRequalifyScript_reportsEveryItemOnce fails when the script's item
// numbers are not exactly 1 to 17, each reported by one function, when
// items_total says anything else, or when an item is still reported as
// PENDING, which item 15 was until end-to-end scenario Q landed.
func TestRequalifyScript_reportsEveryItemOnce(t *testing.T) {
	root := moduleRoot(t)
	script := readFile(t, filepath.Join(root, scriptFile))
	if want := fmt.Sprintf("\nitems_total=%d\n", itemCount); !strings.Contains(script, want) {
		t.Errorf("%s does not set items_total=%d", scriptFile, itemCount)
	}
	if strings.Contains(script, "report PENDING") {
		t.Errorf("%s still reports an item as PENDING; every item is PASS, CHANGED or SKIPPED since scenario Q landed", scriptFile)
	}
	seen := map[int][]string{}
	for _, m := range itemNumber.FindAllStringSubmatch(script, -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatal(err)
		}
		seen[n] = append(seen[n], m[0])
	}
	for n := 1; n <= itemCount; n++ {
		if len(seen[n]) == 0 {
			t.Errorf("item %d is never reported", n)
		}
	}
	for n, lines := range seen {
		if n < 1 || n > itemCount {
			t.Errorf("item %d is outside 1..%d: %q", n, itemCount, lines)
		}
	}
}

// TestRequalifyCI_dispatchJobRunsTheScript fails when ci.yml lacks the
// requalify job, its two dispatch inputs or the command that runs the
// checklist with --e2e, which docs/operations.md describes.
func TestRequalifyCI_dispatchJobRunsTheScript(t *testing.T) {
	ci := readFile(t, filepath.Join(moduleRoot(t), ciFile))
	for _, want := range []string{
		"\n  requalify:\n",
		"\n      gateway_version:\n",
		"\n      gateway_sha256:\n",
		`scripts/requalify-gateway.sh "$GATEWAY_VERSION" "$GATEWAY_SHA256" --e2e`,
		"if: github.event_name == 'workflow_dispatch' && inputs.gateway_version != ''",
	} {
		if !strings.Contains(ci, want) {
			t.Errorf("%s lacks %q", ciFile, want)
		}
	}
}

// declaredTests collects every top-level test function the module declares,
// build tags included, by reading every _test.go file under root.
func declaredTests(t *testing.T, root string) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "third_party") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		for _, name := range uniqueMatches(testFunc, readFile(t, path), 1) {
			found[name] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		t.Fatalf("no test function found under %s; the walk is wrong", root)
	}
	return found
}

// uniqueMatches returns the sorted distinct values of one group of every
// match of re in s.
func uniqueMatches(re *regexp.Regexp, s string, group int) []string {
	set := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		set[m[group]] = true
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// moduleRoot walks up from the package directory to the directory with go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for range maxParentDirs {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("go.mod not found within %d directories above the package", maxParentDirs)
	return ""
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
