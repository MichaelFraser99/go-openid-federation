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
	"net/http":  {"NewRequest", "NewRequestWithContext"},
	"strconv":   {"Atoi", "ParseBool", "ParseInt", "ParseUint", "ParseFloat", "ParseComplex", "Unquote", "UnquoteChar", "QuotedPrefix"},
	"net":       {"ParseCIDR", "ParseMAC"},
	"net/netip": {"ParseAddr", "ParseAddrPort", "ParsePrefix"},
	"net/mail":  {"ParseAddress", "ParseAddressList"},
	"time":      {"Parse", "ParseDuration", "ParseInLocation"},
}

var urlConstructors = []string{"Parse", "ParseRequestURI"}

var logHelpers = []string{"LogInfo", "LogError"}

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

type checker struct {
	fset    *token.FileSet
	file    *ast.File
	info    *types.Info
	imports map[string]string
	urls    map[types.Object]bool
}

func (c *checker) packageParser(call *ast.CallExpr) (string, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	path, ok := c.imports[pkg.Name]
	if !ok || !slices.Contains(quotingParsers[path], selector.Sel.Name) {
		return "", false
	}
	return path + "." + selector.Sel.Name, true
}

func (c *checker) parser(expr ast.Expr) (string, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return "", false
	}
	if name, ok := c.packageParser(call); ok {
		return name, true
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Parse" {
		return "", false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if ok && c.urls[objectOf(c.info, receiver)] {
		return "net/url.(*URL).Parse", true
	}
	return "", false
}

func isLogCall(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return ok && slices.Contains(logHelpers, selector.Sel.Name)
}

func allowedUse(stack []ast.Node, ident *ast.Ident) bool {
	for i := len(stack) - 1; i >= 0; i-- {
		switch node := stack[i].(type) {
		case *ast.BinaryExpr:
			other := node.X
			if other == ident {
				other = node.Y
			}
			nilIdent, ok := other.(*ast.Ident)
			return ok && nilIdent.Name == "nil" && (node.X == ident || node.Y == ident)
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

type source struct {
	object   types.Object
	stmt     ast.Node
	function *ast.BlockStmt
	results  *ast.FieldList
	parser   string
	siblings []ast.Stmt
	loop     *ast.BlockStmt
}

type span struct{ from, to token.Pos }

func (c *checker) sources(file *ast.File) ([]source, []finding) {
	var found []source
	var unbound []finding
	type frame struct {
		body    *ast.BlockStmt
		results *ast.FieldList
	}
	var functions []frame
	var stack []ast.Node
	bound := map[*ast.CallExpr]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			switch top.(type) {
			case *ast.FuncDecl, *ast.FuncLit:
				functions = functions[:len(functions)-1]
			}
			return true
		}
		stack = append(stack, n)
		switch node := n.(type) {
		case *ast.FuncDecl:
			functions = append(functions, frame{body: node.Body, results: node.Type.Results})
		case *ast.FuncLit:
			functions = append(functions, frame{body: node.Body, results: node.Type.Results})
		case *ast.AssignStmt:
			if len(node.Rhs) == 1 {
				if call, ok := node.Rhs[0].(*ast.CallExpr); ok {
					bound[call] = true
				}
				c.recordURL(node.Lhs, node.Rhs[0])
				if name, ok := c.parser(node.Rhs[0]); ok && len(functions) > 0 {
					if _, ok := node.Lhs[len(node.Lhs)-1].(*ast.Ident); !ok {
						unbound = append(unbound, finding{position: c.fset.Position(node.Lhs[len(node.Lhs)-1].Pos()), parser: name})
					}
					if last, ok := node.Lhs[len(node.Lhs)-1].(*ast.Ident); ok && last.Name != "_" {
						if object := objectOf(c.info, last); object != nil {
							found = append(found, c.newSource(object, node, functions[len(functions)-1].body, functions[len(functions)-1].results, name, stack))
						}
					}
				}
			}
		case *ast.ValueSpec:
			if len(node.Values) == 1 {
				if call, ok := node.Values[0].(*ast.CallExpr); ok {
					bound[call] = true
				}
				lhs := make([]ast.Expr, len(node.Names))
				for i, name := range node.Names {
					lhs[i] = name
				}
				c.recordURL(lhs, node.Values[0])
				if name, ok := c.parser(node.Values[0]); ok && len(node.Names) > 0 {
					last := node.Names[len(node.Names)-1]
					if object := objectOf(c.info, last); object != nil && last.Name != "_" {
						var body *ast.BlockStmt
						var results *ast.FieldList
						if len(functions) > 0 {
							body, results = functions[len(functions)-1].body, functions[len(functions)-1].results
						}
						found = append(found, c.newSource(object, node, body, results, name, stack))
					}
				}
			}
		case *ast.ExprStmt:
			if call, ok := node.X.(*ast.CallExpr); ok {
				bound[call] = true
			}
		case *ast.CallExpr:
			if name, ok := c.parser(node); ok && !bound[node] {
				unbound = append(unbound, finding{position: c.fset.Position(node.Pos()), parser: name})
			}
		}
		return true
	})
	return found, unbound
}

func (c *checker) recordURL(lhs []ast.Expr, rhs ast.Expr) {
	call, ok := rhs.(*ast.CallExpr)
	if !ok || len(lhs) == 0 {
		return
	}
	name, ok := c.packageParser(call)
	if !ok || !strings.HasPrefix(name, "net/url.") || !slices.Contains(urlConstructors, strings.TrimPrefix(name, "net/url.")) {
		return
	}
	if first, ok := lhs[0].(*ast.Ident); ok {
		if object := objectOf(c.info, first); object != nil {
			c.urls[object] = true
		}
	}
}

func (c *checker) newSource(object types.Object, node ast.Node, body *ast.BlockStmt, results *ast.FieldList, parser string, stack []ast.Node) source {
	src := source{object: object, stmt: node, function: body, results: results, parser: parser}
	for i := len(stack) - 1; i > 0; i-- {
		statement, ok := stack[i].(ast.Stmt)
		if !ok {
			continue
		}
		src.stmt = statement
		switch parent := stack[i-1].(type) {
		case *ast.BlockStmt:
			src.siblings = parent.List
		case *ast.CaseClause:
			src.siblings = parent.Body
		case *ast.CommClause:
			src.siblings = parent.Body
		}
		break
	}
	for i := len(stack) - 1; i >= 0; i-- {
		var loopBody *ast.BlockStmt
		switch loop := stack[i].(type) {
		case *ast.ForStmt:
			loopBody = loop.Body
		case *ast.RangeStmt:
			loopBody = loop.Body
		}
		if _, ok := stack[i].(*ast.FuncLit); ok {
			break
		}
		if _, ok := stack[i].(*ast.FuncDecl); ok {
			break
		}
		if loopBody != nil && object.Pos() < loopBody.Pos() {
			src.loop = loopBody
			break
		}
	}
	return src
}

func (c *checker) declaredInFunction(src source) bool {
	return src.function != nil && src.object.Pos() >= src.function.Pos()
}

func (c *checker) spans(src source) []span {
	end := src.stmt.End()
	until := c.file.End()
	if c.declaredInFunction(src) {
		until = src.function.End()
	}
	for _, sibling := range src.siblings {
		if sibling.Pos() <= src.stmt.Pos() {
			continue
		}
		assign, ok := sibling.(*ast.AssignStmt)
		if !ok {
			continue
		}
		for _, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && objectOf(c.info, ident) == src.object && assign.End() < until {
				until = assign.End()
			}
		}
	}
	spans := []span{{from: end, to: until}}
	if src.function == nil {
		spans = append(spans, span{from: c.file.Pos(), to: src.stmt.Pos()})
	}
	if src.loop != nil {
		spans = append(spans, span{from: src.loop.Pos(), to: src.stmt.Pos()})
	}
	return spans
}

func within(pos token.Pos, spans []span) bool {
	for _, s := range spans {
		if pos > s.from && pos < s.to {
			return true
		}
	}
	return false
}

func (c *checker) isNamedResult(src source) bool {
	if src.results == nil {
		return false
	}
	for _, field := range src.results.List {
		for _, name := range field.Names {
			if objectOf(c.info, name) == src.object {
				return true
			}
		}
	}
	return false
}

func (c *checker) uses(src source, scope ast.Node) []finding {
	var findings []finding
	spans := c.spans(src)
	namedResult := c.isNamedResult(src)
	writes := map[*ast.Ident]bool{}
	var stack []ast.Node
	ast.Inspect(scope, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok {
					writes[ident] = true
				}
			}
		case *ast.ReturnStmt:
			if namedResult && len(node.Results) == 0 && within(node.Pos(), spans) {
				findings = append(findings, finding{position: c.fset.Position(node.Pos()), parser: src.parser})
			}
		case *ast.Ident:
			if writes[node] || objectOf(c.info, node) != src.object || !within(node.Pos(), spans) {
				return true
			}
			if !allowedUse(stack[:len(stack)-1], node) {
				findings = append(findings, finding{position: c.fset.Position(node.Pos()), parser: src.parser})
			}
		}
		return true
	})
	return findings
}

func check(fset *token.FileSet, file *ast.File) []finding {
	c := &checker{fset: fset, file: file, info: objectsOf(fset, file), imports: importedNames(file), urls: map[types.Object]bool{}}
	sources, findings := c.sources(file)
	for _, src := range sources {
		var scope ast.Node = file
		if c.declaredInFunction(src) {
			scope = src.function
		}
		findings = append(findings, c.uses(src, scope)...)
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
		source   string
		findings int
	}{
		{name: "returned directly from the call", imports: `"net/url"`, body: `return url.Parse(s)`, findings: 1},
		{name: "passed straight into another call", imports: `"strconv"`, body: `return wrap(strconv.Atoi(s))`, findings: 1},
		{name: "declared with var", imports: `"net/url"`, body: `var u, err = url.Parse(s); _ = u; return err`, findings: 1},
		{name: "a naked return of a named result", source: "package fixture\n\nimport \"net/url\"\n\nfunc f(s string) (err error) {\n_, err = url.Parse(s)\nreturn\n}\n", findings: 1},
		{name: "reassigned in one branch only", imports: `"net/url"`, body: `_, err := url.Parse(s); if s == "" { err = nil }; return err`, findings: 1},
		{name: "reassigned to fixed text in one branch only", imports: `"net/url"`, body: `_, err := url.Parse(s); if s == "x" { err = errFixed }; return err`, findings: 1},
		{name: "used earlier in a loop body", imports: `"net/url"`, body: `var err error; for _, v := range []string{s} { if err != nil { return err }; _, err = url.Parse(v) }; return nil`, findings: 1},
		{name: "in a package-level closure", source: "package fixture\n\nimport \"net/url\"\n\nvar g = func(s string) error {\n_, err := url.Parse(s)\nreturn err\n}\n", findings: 1},
		{name: "the method form on a parsed url", imports: `"net/url"`, body: `base, err := url.Parse("https://example.com"); if err != nil { return errFixed }; _, err = base.Parse(s); return err`, findings: 1},
		{name: "a request built from a url", imports: `"net/http"`, body: `_, err := http.NewRequest("GET", s, nil); return err`, findings: 1},
		{name: "a call whose name only starts with Log", imports: `"net/url"`, body: `_, err := url.Parse(s); return c.LogAndWrap(err)`, findings: 1},
		{name: "a call named like Log but unrelated", imports: `"net/url"`, body: `_, err := url.Parse(s); return c.Login(err)`, findings: 1},
		{name: "logged at error level", imports: `"net/url"`, body: `if _, err := url.Parse(s); err != nil { cfg.LogError(ctx, "bad", "error", err.Error()); return errFixed }; return nil`},
		{name: "a call whose result is discarded", imports: `"net/url"`, body: `url.Parse(s); return nil`},
		{name: "wrapped by reassignment", imports: `"net/url"`, body: `_, err := url.Parse(s); err = wrap(err); return err`, findings: 1},
		{name: "written from a closure into an outer variable", imports: `"net/url"`, body: `var err error; func() { _, err = url.Parse(s) }(); return err`, findings: 1},
		{name: "written through sync.Once", imports: `"net/url"; "sync"`, body: `var o sync.Once; var err error; o.Do(func() { _, err = url.Parse(s) }); return err`, findings: 1},
		{name: "a package-level variable used below it", source: "package fixture\n\nimport \"net/url\"\n\nvar base, baseErr = url.Parse(\"https://example.com\")\n\nfunc f() error {\n_ = base\nreturn baseErr\n}\n", findings: 1},
		{name: "a package-level variable used above it", source: "package fixture\n\nimport \"net/url\"\n\nfunc f() error {\nreturn baseErr\n}\n\nvar base, baseErr = url.Parse(\"https://example.com\")\n\nvar _ = base\n", findings: 1},
		{name: "stored straight into a field", imports: `"net/url"`, body: `var r struct{ err error }; _, r.err = url.Parse(s); return nil`, findings: 1},
		{name: "stored straight into an index", imports: `"net/url"`, body: `e := make([]error, 1); _, e[0] = url.Parse(s); return nil`, findings: 1},
		{name: "stored through a pointer", imports: `"net/url"`, body: `p := new(error); _, *p = url.Parse(s); return nil`, findings: 1},
		{name: "reassigned from something else, then returned", imports: `"net/url"`, body: `_, err := url.Parse(s); if err != nil { return errFixed }; err = other(); return err`},
		{name: "a closure's own local error", imports: `"net/url"`, body: `g := func() error { _, err := url.Parse(s); if err != nil { return errFixed }; return nil }; err := g(); return err`},
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
			source := tc.source
			if source == "" {
				imports := strings.ReplaceAll(tc.imports, "; ", "\n")
				source = "package fixture\n\nimport (\n" + imports + "\n)\n\nfunc f(s string) error {\n" + strings.ReplaceAll(tc.body, "; ", "\n") + "\n}\n"
			}
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
