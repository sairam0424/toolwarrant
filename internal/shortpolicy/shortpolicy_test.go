package shortpolicy

import (
	"errors"
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
	// claudeFile names every test that consults testing.Short().
	claudeFile = "CLAUDE.md"
	// ciFile holds the test-full job whose command runs those tests in full.
	ciFile = ".github/workflows/ci.yml"
	// testFullJob is the job key as ci.yml spells it (two spaces, then the name).
	testFullJob = "  test-full:"
	// testingPath is the import path whose Short function the policy is about.
	testingPath = "testing"
	// shortFunc is the function a test consults.
	shortFunc = "Short"
	// maxParentDirs bounds the walk from the package directory to go.mod.
	maxParentDirs = 6
	// notNameableReason is the error for a testing.Short() in a function the
	// policy cannot name: a helper, a method, TestMain or an Example.
	notNameableReason = "is not a top-level Test or Fuzz function (a helper, a method, TestMain or an Example), so the policy cannot name it"
	// benchmarkReason is the error for a Benchmark, which runs only under
	// -bench; -short governs no benchmark, so the call is simply wrong.
	benchmarkReason = "is a Benchmark, which runs only under -bench and never in the suite -short shortens; drop the testing.Short() call"
)

// shortCaller is one test function that consults testing.Short(), with the
// package directory relative to the module root in forward-slash form.
type shortCaller struct {
	pkg  string
	name string
}

func (c shortCaller) String() string { return c.pkg + "." + c.name }

func TestShortPolicy_everyShortSkipIsNamedInCLAUDEAndRunsInFull(t *testing.T) {
	root := moduleRoot(t)
	claude := readFile(t, filepath.Join(root, claudeFile))
	full, err := testFullPackages(readFile(t, filepath.Join(root, ciFile)))
	if err != nil {
		t.Fatal(err)
	}
	callers := shortCallersInTree(t, root)
	if len(callers) == 0 {
		t.Fatal("no test consults testing.Short(); CLAUDE.md names six, so the walk is wrong")
	}
	for _, c := range callers {
		if !strings.Contains(claude, "`"+c.name+"`") {
			t.Errorf("%s consults testing.Short() but %s does not name it", c, claudeFile)
		}
		if !full["..."] && !full[c.pkg] {
			t.Errorf("%s consults testing.Short() but the test-full job of %s does not run %s in full (it runs %s)", c, ciFile, c.pkg, keys(full))
		}
	}
}

func TestShortCallers_namesTheTestAndRefusesAHelper(t *testing.T) {
	names, err := shortCallers(parseSource(t, `package p
import "testing"
func TestSlow(t *testing.T) { if testing.Short() { t.Skip("slow") } }
func TestFast(t *testing.T) { t.Run("sub", func(t *testing.T) {}) }
func TestSubtestSkips(t *testing.T) { t.Run("sub", func(t *testing.T) { if testing.Short() { t.Skip() } }) }
func FuzzSeeds(f *testing.F) { if testing.Short() { f.Skip("slow seeds") }; f.Fuzz(func(t *testing.T, s string) {}) }
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names, ","); got != "TestSlow,TestSubtestSkips,FuzzSeeds" {
		t.Fatalf("names = %q, want TestSlow,TestSubtestSkips,FuzzSeeds", got)
	}
	// Each refused shape, with the reason the error must give so that the
	// author is sent the right way: a benchmark drops the call, the others move
	// it into a test the policy can name.
	refused := map[string]struct{ src, reason string }{
		"helper":      {"package p\nimport \"testing\"\nfunc skipShort(t *testing.T) { if testing.Short() { t.Skip() } }\n", notNameableReason},
		"alias":       {"package p\nimport tst \"testing\"\nfunc skipShort(t *tst.T) { if tst.Short() { t.Skip() } }\n", notNameableReason},
		"dot import":  {"package p\nimport . \"testing\"\nfunc skipShort(t *T) { if Short() { t.Skip() } }\n", notNameableReason},
		"method":      {"package p\nimport \"testing\"\ntype s struct{}\nfunc (s) TestX(t *testing.T) { if testing.Short() { t.Skip() } }\n", notNameableReason},
		"TestMain":    {"package p\nimport ( \"os\"; \"testing\" )\nfunc TestMain(m *testing.M) { if testing.Short() { os.Exit(0) }; os.Exit(m.Run()) }\n", notNameableReason},
		"Example":     {"package p\nimport \"testing\"\nfunc ExampleX() { if testing.Short() { return } }\n", notNameableReason},
		"Benchmark":   {"package p\nimport \"testing\"\nfunc BenchmarkX(b *testing.B) { if testing.Short() { b.Skip() } }\n", benchmarkReason},
		"package var": {"package p\nimport \"testing\"\nvar short = testing.Short()\n", "consulted outside a function"},
	}
	for what, c := range refused {
		_, err := shortCallers(parseSource(t, c.src))
		if err == nil {
			t.Errorf("%s: a testing.Short() outside a test function was accepted", what)
		} else if !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%s: error %q does not say %q", what, err, c.reason)
		}
	}
}

func TestFullPackages_readsTheTestFullJobOnly(t *testing.T) {
	ci := "jobs:\n  test:\n    steps:\n      - run: go test -short ./...\n" +
		"  test-full:\n    steps:\n      - run: go install x@v1\n" +
		"      - run: gotestsum --jsonfile \"$RUNNER_TEMP/g.json\" -- -race ./internal/a/ ./internal/b/c/\n" +
		"  docs:\n    steps:\n      - run: go test ./internal/d/\n"
	got, err := testFullPackages(ci)
	if err != nil {
		t.Fatal(err)
	}
	if s := keys(got); s != "internal/a internal/b/c" {
		t.Fatalf("packages = %q, want internal/a internal/b/c", s)
	}
	if _, err := testFullPackages("jobs:\n  test-full:\n    steps:\n      - run: echo nothing\n"); err == nil {
		t.Fatal("a test-full job that tests no package was accepted")
	}
	if _, err := testFullPackages("jobs:\n  test:\n    steps:\n      - run: go test ./...\n"); err == nil {
		t.Fatal("a workflow without a test-full job was accepted")
	}
}

// moduleRoot walks up from the package directory to the directory holding
// go.mod, so that the test reads the tree it is part of and nothing else.
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
	t.Fatalf("no go.mod within %d directories above the package", maxParentDirs)
	return ""
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func parseSource(t *testing.T, src string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "src_test.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// keys renders a set in sorted order for a message.
func keys(set map[string]bool) string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return strings.Join(out, " ")
}

// skipDir names the directories the walk never enters: not Go the module
// tests (the go tool ignores testdata and dot and underscore directories), or
// vendored and downloaded trees.
func skipDir(name string) bool {
	switch name {
	case "testdata", "bin", "dist", "third_party", "seam":
		return true
	}
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}

// shortCallersInTree parses every _test.go file under root and collects the
// test functions that consult testing.Short(); a call the policy cannot name
// (a helper, a method, TestMain, a package-level expression) is a failure
// reported on the file.
func shortCallersInTree(t *testing.T, root string) []shortCaller {
	t.Helper()
	var callers []shortCaller
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
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		names, err := shortCallers(f)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		for _, n := range names {
			callers = append(callers, shortCaller{pkg: filepath.ToSlash(rel), name: n})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return callers
}

// shortCallers returns the top-level test functions of one file whose body
// consults testing.Short(), in source order; a fuzz target counts, since its
// seed corpus runs in every go test run. Any other use of testing.Short() is
// an error: the policy names tests, so a helper or a method that skips on its
// behalf would hide the skip from CLAUDE.md, and a benchmark never runs in the
// suite -short shortens.
func shortCallers(f *ast.File) ([]string, error) {
	short := shortMatcher(f)
	var names []string
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			if consultsShort(d, short) {
				return nil, errors.New("testing.Short() consulted outside a function")
			}
			continue
		}
		if !consultsShort(fn.Body, short) {
			continue
		}
		if isTopLevel(fn, "Benchmark") {
			return nil, fmt.Errorf("%s %s", fn.Name.Name, benchmarkReason)
		}
		if !isTestFunc(fn) {
			return nil, fmt.Errorf("%s consults testing.Short() but %s", fn.Name.Name, notNameableReason)
		}
		names = append(names, fn.Name.Name)
	}
	return names, nil
}

// isTestFunc reports whether fn is a function the go tool runs in a plain go
// test run, so one the policy can name: top-level, named Test or Fuzz followed
// by something, not TestMain.
func isTestFunc(fn *ast.FuncDecl) bool {
	return fn.Name.Name != "TestMain" && (isTopLevel(fn, "Test") || isTopLevel(fn, "Fuzz"))
}

// isTopLevel reports whether fn has no receiver and a name that is prefix
// followed by at least one more character, as the go tool reads test names.
func isTopLevel(fn *ast.FuncDecl, prefix string) bool {
	n := fn.Name.Name
	return fn.Recv == nil && len(n) > len(prefix) && strings.HasPrefix(n, prefix)
}

// shortMatcher returns the predicate for a call expression that is
// testing.Short() under the file's own import of the testing package: the
// package name, an alias, or a dot import (then a bare Short()).
func shortMatcher(f *ast.File) func(*ast.CallExpr) bool {
	name := testingPath
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, "\"") == testingPath && imp.Name != nil {
			name = imp.Name.Name
		}
	}
	return func(call *ast.CallExpr) bool {
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			x, ok := fun.X.(*ast.Ident)
			return ok && x.Name == name && fun.Sel.Name == shortFunc
		case *ast.Ident:
			return name == "." && fun.Name == shortFunc
		}
		return false
	}
}

// consultsShort reports whether any call under node matches short.
func consultsShort(node ast.Node, short func(*ast.CallExpr) bool) bool {
	if node == nil {
		return false
	}
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && short(call) {
			found = true
		}
		return !found
	})
	return found
}

// testFullPackages reads the ci workflow as text and returns the set of
// package directories (relative, no ./ or trailing slash; "..." for a
// wildcard) that any run: line of the test-full job names. The job key is
// matched literally and the job ends at the next key at the same indent, so
// a renamed job or an empty command fails here rather than passing silently.
func testFullPackages(ci string) (map[string]bool, error) {
	pkgs := map[string]bool{}
	in := false
	for _, line := range strings.Split(ci, "\n") {
		if line == testFullJob {
			in = true
			continue
		}
		if in && isJobKey(line) {
			break
		}
		if !in || !strings.Contains(line, "run:") {
			continue
		}
		for _, tok := range strings.Fields(line) {
			if strings.HasPrefix(tok, "./") {
				pkgs[strings.TrimSuffix(strings.TrimPrefix(tok, "./"), "/")] = true
			}
		}
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("%s: no run: line of the %q job names a ./ package; the job or this parser changed", ciFile, strings.TrimSpace(testFullJob))
	}
	return pkgs, nil
}

// isJobKey reports whether line opens a job under jobs: (two spaces of
// indent, a name, a colon, nothing else).
func isJobKey(line string) bool {
	return len(line) > 3 && strings.HasPrefix(line, "  ") && line[2] != ' ' && line[2] != '-' && line[2] != '#' && strings.HasSuffix(line, ":")
}
