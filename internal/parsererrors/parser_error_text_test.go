package parsererrors

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var quotingParsers = map[string][]string{
	"net/url":   {"Parse", "ParseRequestURI", "ParseQuery", "PathUnescape", "QueryUnescape"},
	"strconv":   {"Atoi", "ParseBool", "ParseInt", "ParseUint", "ParseFloat", "ParseComplex", "Unquote", "UnquoteChar", "QuotedPrefix"},
	"net":       {"ParseCIDR", "ParseMAC"},
	"net/netip": {"ParseAddr", "ParseAddrPort", "ParsePrefix"},
	"net/mail":  {"ParseAddress", "ParseAddressList"},
	"time":      {"Parse", "ParseDuration", "ParseInLocation"},
}

type finding struct {
	position token.Position
	parser   string
}

func importedNames(file *ast.File) map[string]string {
	names := map[string]string{}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		name := path[strings.LastIndex(path, "/")+1:]
		if spec.Name != nil {
			name = spec.Name.Name
		}
		names[name] = path
	}
	return names
}

func parserCalled(expr ast.Expr, imports map[string]string) (string, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return "", false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	path, ok := imports[pkg.Name]
	if !ok || !slices.Contains(quotingParsers[path], selector.Sel.Name) {
		return "", false
	}
	return path + "." + selector.Sel.Name, true
}

type emptyImporter struct{}

func (emptyImporter) Import(path string) (*types.Package, error) {
	pkg := types.NewPackage(path, path[strings.LastIndex(path, "/")+1:])
	pkg.MarkComplete()
	return pkg, nil
}

func objectsOf(fset *token.FileSet, file *ast.File) *types.Info {
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	config := types.Config{Importer: emptyImporter{}, Error: func(error) {}}
	_, _ = config.Check(file.Name.Name, fset, []*ast.File{file}, info)
	return info
}

func objectOf(info *types.Info, ident *ast.Ident) types.Object {
	if object := info.Defs[ident]; object != nil {
		return object
	}
	return info.Uses[ident]
}

func isLogCall(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return ok && strings.HasPrefix(selector.Sel.Name, "Log")
}

func allowedUse(stack []ast.Node, ident *ast.Ident) bool {
	for i := len(stack) - 1; i >= 0; i-- {
		switch node := stack[i].(type) {
		case *ast.BinaryExpr:
			other := node.X
			if other == ident {
				other = node.Y
			}
			if nilIdent, ok := other.(*ast.Ident); ok && nilIdent.Name == "nil" && (node.X == ident || node.Y == ident) {
				return true
			}
			return false
		case *ast.CallExpr:
			if isLogCall(node) {
				return true
			}
		case ast.Stmt:
			return false
		}
	}
	return false
}

func check(fset *token.FileSet, file *ast.File) []finding {
	imports := importedNames(file)
	info := objectsOf(fset, file)
	var findings []finding
	for _, decl := range file.Decls {
		function, ok := decl.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		assignments := map[types.Object][]token.Pos{}
		type source struct {
			object types.Object
			pos    token.Pos
			parser string
		}
		var sources []source
		ast.Inspect(function.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, lhs := range assign.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok {
					if object := objectOf(info, ident); object != nil {
						assignments[object] = append(assignments[object], assign.Pos())
					}
				}
			}
			if len(assign.Rhs) != 1 {
				return true
			}
			name, ok := parserCalled(assign.Rhs[0], imports)
			if !ok {
				return true
			}
			last, ok := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident)
			if !ok || last.Name == "_" {
				return true
			}
			if object := objectOf(info, last); object != nil {
				sources = append(sources, source{object: object, pos: assign.End(), parser: name})
			}
			return true
		})
		for _, src := range sources {
			until := function.Body.End()
			for _, pos := range assignments[src.object] {
				if pos > src.pos && pos < until {
					until = pos
				}
			}
			var stack []ast.Node
			ast.Inspect(function.Body, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				stack = append(stack, n)
				ident, ok := n.(*ast.Ident)
				if !ok || objectOf(info, ident) != src.object || ident.Pos() <= src.pos || ident.Pos() >= until {
					return true
				}
				if !allowedUse(stack[:len(stack)-1], ident) {
					findings = append(findings, finding{position: fset.Position(ident.Pos()), parser: src.parser})
				}
				return true
			})
		}
	}
	return findings
}

func checkSource(t *testing.T, source string) []finding {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("failed to parse the fixture: %v", err)
	}
	return check(fset, file)
}

func TestCheck_FlagsAParserErrorThatLeavesTheFunctionInAnyShape(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		imports  string
		findings int
	}{
		{name: "returned as it is", imports: `"net/url"`, body: `u, err := url.Parse(s); if err != nil { return err }; _ = u`, findings: 1},
		{name: "wrapped with %w", imports: `"fmt"; "net/url"`, body: `_, err := url.Parse(s); if err != nil { return fmt.Errorf("bad: %w", err) }`, findings: 1},
		{name: "its text formatted in", imports: `"fmt"; "strconv"`, body: `_, err := strconv.Atoi(s); if err != nil { return fmt.Errorf("bad: %s", err.Error()) }`, findings: 1},
		{name: "joined", imports: `"errors"; "strconv"`, body: `_, err := strconv.ParseBool(s); if err != nil { return errors.Join(errors.New("bad"), err) }`, findings: 1},
		{name: "handed to a helper", imports: `"strconv"`, body: `_, err := strconv.ParseInt(s, 10, 64); if err != nil { return wrap(err) }`, findings: 1},
		{name: "assigned onward", imports: `"time"`, body: `_, err := time.ParseDuration(s); kept := err; return kept`, findings: 1},
		{name: "under an import alias", imports: `neturl "net/url"`, body: `_, err := neturl.ParseRequestURI(s); return err`, findings: 1},
		{name: "assigned with = rather than :=", imports: `"net/netip"`, body: `var err error; _, err = netip.ParseAddr(s); return err`, findings: 1},
		{name: "in an if statement's init", imports: `"net/url"`, body: `if _, err := url.Parse(s); err != nil { return err }; return nil`, findings: 1},
		{name: "compared against nil only", imports: `"net/url"`, body: `if _, err := url.Parse(s); err != nil { return errFixed }; return nil`},
		{name: "compared inside a longer condition", imports: `"net/url"`, body: `p, err := url.Parse(s); if err != nil || !p.IsAbs() { return errFixed }; return nil`},
		{name: "logged, text included", imports: `"net/url"`, body: `if _, err := url.Parse(s); err != nil { cfg.LogInfo(ctx, "bad", "error", truncate(err.Error())); return errFixed }; return nil`},
		{name: "reassigned from something else before it is returned", imports: `"strconv"`, body: `_, err := strconv.Atoi(s); if err != nil { return errFixed }; _, err = other(); return err`},
		{name: "discarded", imports: `"strconv"`, body: `n, _ := strconv.Atoi(s); _ = n; return nil`},
		{name: "a parser this rule does not list", imports: `"encoding/json"`, body: `var v any; err := json.Unmarshal([]byte(s), &v); return err`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			imports := strings.ReplaceAll(tc.imports, "; ", "\n")
			source := "package fixture\n\nimport (\n" + imports + "\n)\n\nfunc f(s string) error {\n" + strings.ReplaceAll(tc.body, "; ", "\n") + "\n}\n"
			if got := checkSource(t, source); len(got) != tc.findings {
				t.Errorf("expected %d findings, got %d: %v\n%s", tc.findings, len(got), got, source)
			}
		})
	}
}

func TestNoParserErrorTextLeavesItsFunction(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("failed to find the module root: %v", err)
	}
	fset := token.NewFileSet()
	var findings []finding
	scanned := 0
	for _, dir := range []string{"model", "internal", "server", "client"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			scanned++
			findings = append(findings, check(fset, file)...)
			return nil
		})
		if err != nil {
			t.Fatalf("failed to scan %s: %v", dir, err)
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no files, so the rule checked nothing")
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].position.String() < findings[j].position.String() })
	for _, f := range findings {
		relative, _ := filepath.Rel(root, f.position.Filename)
		t.Errorf("%s:%d: the error from %s quotes its input, so it must not be returned, wrapped or formatted into another error, because it can reach a response (#210). Return fixed text that names the rule, and log the detail", relative, f.position.Line, f.parser)
	}
}
