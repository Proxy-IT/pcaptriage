package analysis_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Proxy-IT/pcaptriage/internal/synth"
)

// TestNoTestAssertsOnlyInsideAnUncheckedLoop is the class guard for the defect
// this repo has now produced four times.
//
// Each instance looked different and each passed while measuring nothing:
//
//   - the escaping check, which compared strings that were both empty;
//   - the emphasis round-trip, which reconstructed its expected value from the
//     parser it was testing, so empty runs rebuilt the right source;
//   - the export basis check, which matched ".basis-inferred" against the
//     stylesheet the report inlines rather than against any card;
//   - TestR04MidstreamRTTIsInferred, which iterated R04 findings in a fixture
//     whose R04 findings are all confirmed, so its body never ran.
//
// The shared shape is the last one: a test whose only assertions live inside a
// range loop, with nothing establishing that the loop has anything to range
// over. Such a test passes on an empty collection, which is indistinguishable
// from passing on a correct one — and an empty collection is exactly what a
// regression produces.
//
// So this is a lint, written as a test, over this repo's own test files. It
// parses each one and flags any test function whose t.Error/t.Fatal calls are
// all inside range loops while the function never checks a length, never
// counts iterations, and never calls a helper that would.
//
// It cannot catch every empty assertion — the stylesheet and round-trip cases
// above are different shapes, and are guarded where they live. It closes the
// one that has recurred and is mechanically detectable.
func TestNoTestAssertsOnlyInsideAnUncheckedLoop(t *testing.T) {
	root := filepath.Dir(filepath.Dir(synth.FixtureDir()))

	var files []string
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("found no test files to lint, so this test asserted nothing — " +
			"which is the defect it exists to catch")
	}

	var scanned int
	for _, path := range files {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			scanned++
			if guarded(fn) {
				continue
			}
			total, inLoop := countAssertions(fn)
			if total > 0 && total == inLoop {
				t.Errorf("%s: %s asserts only inside a range loop and never checks that the loop "+
					"runs — it passes unchanged on an empty collection. Add a length assertion, "+
					"count the iterations, or fail when the count is zero.",
					filepath.Base(path), fn.Name.Name)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("parsed test files but found no Test functions, so nothing was linted")
	}
	t.Logf("linted %d test functions across %d files", scanned, len(files))
}

// guarded reports whether fn establishes that its collections are non-empty:
// either a len(...) somewhere in the body, or a counter it increments and can
// then check.
//
// An earlier version of this also treated "calls a same-package helper" as
// guarded, on the theory that helpers do their own checks. That exempted
// precisely the shape being hunted — the original defect is
// `for _, f := range findingsFor(res, "R04")`, which is nothing but a helper
// call — and the lint passed on the reintroduced bug. Narrow is right here: a
// test that never writes len() and never counts has not considered emptiness,
// whatever it delegates to.
func guarded(fn *ast.FuncDecl) bool {
	var ok bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			if id, isIdent := v.Fun.(*ast.Ident); isIdent {
				if id.Name == "len" || guardingHelpers[id.Name] {
					ok = true
				}
			}
		case *ast.IncDecStmt:
			ok = true
		}
		return !ok
	})
	return ok
}

// guardingHelpers are the helpers that do the emptiness check themselves, so a
// caller ranging over one has the guarantee even though no len() appears in
// the caller.
//
// An explicit allowlist, not "any function call" — that broader rule is what
// let the original defect through, since `range findingsFor(res, "R04")` is a
// function call too. Every name here must fatal on empty at its definition; if
// one stops doing so, this list is the record of what relied on it.
var guardingHelpers = map[string]bool{
	// allFixtures (r01_test.go) fatals when no fixtures are registered.
	"allFixtures": true,
}

// literalTables collects the names in fn assigned a composite literal with
// elements in it — the `cases := []struct{...}{ ... }` shape that table-driven
// tests use. Ranging over one of those provably executes, so assertions inside
// are unconditional.
func literalTables(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	record := func(lhs []ast.Expr, rhs []ast.Expr) {
		for i, l := range lhs {
			if i >= len(rhs) {
				return
			}
			id, ok := l.(*ast.Ident)
			if !ok {
				continue
			}
			if lit, ok := rhs[i].(*ast.CompositeLit); ok && len(lit.Elts) > 0 {
				out[id.Name] = true
			}
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			record(v.Lhs, v.Rhs)
		case *ast.ValueSpec:
			for _, name := range v.Names {
				for _, val := range v.Values {
					if lit, ok := val.(*ast.CompositeLit); ok && len(lit.Elts) > 0 {
						out[name.Name] = true
					}
				}
			}
		}
		return true
	})
	return out
}

// provablyNonEmpty reports whether a range expression's trip count is visible
// in the source: a literal written in place, or a name bound to one.
func provablyNonEmpty(x ast.Expr, tables map[string]bool) bool {
	switch v := x.(type) {
	case *ast.CompositeLit:
		return len(v.Elts) > 0
	case *ast.Ident:
		return tables[v.Name]
	}
	return false
}

// countAssertions returns how many t.Error/t.Fatal-family calls fn makes, and
// how many of those are inside a range loop whose trip count is not evident.
func countAssertions(fn *ast.FuncDecl) (total, inLoop int) {
	tables := literalTables(fn)
	var depth int
	var walk func(ast.Node) bool
	walk = func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.RangeStmt:
			// A loop over a literal with elements in it provably runs, so
			// assertions inside it are not conditional on anything. Excluding
			// these is what separates "asserts over whatever the engine
			// produced" from "asserts over a fixed list written right here" —
			// the table-driven tests throughout this repo are the latter, and
			// flagging them would be noise that trains people to ignore this.
			if provablyNonEmpty(v.X, tables) {
				ast.Inspect(v.Body, walk)
				return false
			}
			depth++
			ast.Inspect(v.Body, walk)
			depth--
			return false
		case *ast.CallExpr:
			sel, ok := v.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok || recv.Name != "t" {
				return true
			}
			switch sel.Sel.Name {
			case "Error", "Errorf", "Fatal", "Fatalf":
				total++
				if depth > 0 {
					inLoop++
				}
			}
		}
		return true
	}
	ast.Inspect(fn.Body, walk)
	return total, inLoop
}
