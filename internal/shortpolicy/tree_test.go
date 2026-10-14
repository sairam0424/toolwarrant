package shortpolicy

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	// goSuffix is what the walk parses: every Go file, not only test files.
	goSuffix = ".go"
	// testSuffix marks the files the go tool runs tests from.
	testSuffix = "_test.go"
	// notTestFileReason is the error for a testing.Short() in a file without
	// the test suffix, where even a function named Test... is no test.
	notTestFileReason = "consults testing.Short() in a file without the " + testSuffix + " suffix, which the go tool runs no test from, so the policy cannot name it"
)

func TestShortCallersInTree_readsFilesWithoutTheTestSuffix(t *testing.T) {
	root := t.TempDir()
	// A named skip in a test file; a helper in an ordinary file that a test
	// calls (the test itself never spells testing.Short()); a function named
	// like a test in an ordinary file; and a testdata file the walk must skip.
	files := map[string]string{
		"internal/a/a_test.go":     "package a\nimport \"testing\"\nfunc TestSlow(t *testing.T) { if testing.Short() { t.Skip() } }\n",
		"internal/b/helper.go":     "package b\nimport \"testing\"\nfunc SkipIfShort(t *testing.T) { if testing.Short() { t.Skip() } }\n",
		"internal/b/b_test.go":     "package b\nimport \"testing\"\nfunc TestEvades(t *testing.T) { SkipIfShort(t) }\n",
		"internal/c/c.go":          "package c\nimport \"testing\"\nfunc TestLooksLikeOne(t *testing.T) { if testing.Short() { t.Skip() } }\n",
		"internal/d/testdata/x.go": "package x\nimport \"testing\"\nvar short = testing.Short()\n",
	}
	for name, src := range files {
		writeFile(t, filepath.Join(root, filepath.FromSlash(name)), src)
	}
	report, err := shortCallersInTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(report.callers); got != "[internal/a.TestSlow]" {
		t.Errorf("callers = %s, want [internal/a.TestSlow]", got)
	}
	want := []string{
		filepath.Join(root, "internal", "b", "helper.go") + ": SkipIfShort consults testing.Short() but " + notNameableReason,
		filepath.Join(root, "internal", "c", "c.go") + ": TestLooksLikeOne " + notTestFileReason,
	}
	if !slices.Equal(report.problems, want) {
		t.Errorf("problems = %q, want %q", report.problems, want)
	}
}

// writeFile creates path's directories and writes src, for a tree under TempDir.
func writeFile(t *testing.T, path, src string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
}

// treeReport is what the walk of one tree found: the test functions that
// consult testing.Short(), and the uses of it the policy cannot name, one
// message per file, each starting with the file's path.
type treeReport struct {
	callers  []shortCaller
	problems []string
}

// shortCallersInTree parses every Go file under root, not only the _test.go
// files (a helper in an ordinary file would otherwise hide a skip), and
// collects the test functions that consult testing.Short(). A call the policy
// cannot name (a helper, a method, TestMain, a package-level expression, any
// function in a file the go tool runs no test from) is a problem on the file.
func shortCallersInTree(root string) (treeReport, error) {
	var report treeReport
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), goSuffix) {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		names, err := fileShortCallers(d.Name(), f)
		if err != nil {
			report.problems = append(report.problems, path+": "+err.Error())
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		for _, n := range names {
			report.callers = append(report.callers, shortCaller{pkg: filepath.ToSlash(rel), name: n})
		}
		return nil
	})
	return report, err
}

// fileShortCallers is shortCallers for one file of the tree, judged by its
// name: a file without the _test.go suffix is compiled into the package the
// tests exercise and the go tool runs no test from it, so a testing.Short()
// there is a use the policy cannot name even inside a function called Test...
// (a helper there is already refused by shortCallers).
func fileShortCallers(name string, f *ast.File) ([]string, error) {
	names, err := shortCallers(f)
	if err != nil {
		return nil, err
	}
	if len(names) > 0 && !strings.HasSuffix(name, testSuffix) {
		return nil, fmt.Errorf("%s %s", strings.Join(names, ", "), notTestFileReason)
	}
	return names, nil
}

// skipDir names the directories the walk never enters: what the go tool
// ignores (testdata, dot and underscore directories) and the vendored,
// downloaded and built trees, which are not this module's tests.
func skipDir(name string) bool {
	switch name {
	case "testdata", "bin", "dist", "third_party", "seam":
		return true
	}
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}
