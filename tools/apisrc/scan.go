// scan.go 任务书 §28 W14-SRC：Go 源码路由注册静态扫描（P2-07 源码 API 发现 v1）。
//
// 识别形态（字面量路由注册，按调用形态与方法名启发式识别，不做类型检查）：
//   - net/http ServeMux：mux.Handle("GET /path")（Go 1.22 方法模式）、
//     mux.Handle("/path")（无方法模式 → 展开为 8 个标准方法）、
//     http.Handle / http.HandleFunc 包级注册（同上）；
//   - 框架方法路由：chi（r.Get/r.Post 首字母大写）、gin/echo（r.GET/e.GET 全大写）
//     等按方法名识别，第一参数须为路径字符串字面量；
//   - gin/httprouter 的 r.Handle("METHOD", "/path") 两参形态。
//
// 路径参数归一：chi {id} 原样保留、{id:[0-9]+} 正则约束收敛为 {id}、
// gin/echo :id 映射为 {id}、gin *path 具名通配映射为 {path}、echo * 无名通配
// 映射为 {wildcard}、Go 1.22 {path...} 后缀通配收敛为 {path}、{$} 精确匹配
// 标记段移除。
//
// 已知限制（v1 不展开）：Group/Route/Mount 前缀不合并（子路径按字面量原样记录）、
// 变量/常量拼接路径无法静态提取（跳过）、函数参数间接传入的注册不追踪。
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// httpMethods OpenAPI 3 Path Item 支持的 HTTP 方法（与 server 侧 openAPI3Methods 一致；
// 无方法模式（ServeMux "/path"）展开时按此全集登记）。
var httpMethods = []string{"GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"}

// httpMethodSet 大写方法名集合（ServeMux 方法模式与 gin Handle(method, path) 校验用）。
var httpMethodSet = func() map[string]bool {
	m := make(map[string]bool, len(httpMethods))
	for _, mth := range httpMethods {
		m[mth] = true
	}
	return m
}()

// routeMethodBySelector 框架方法路由选择子名 → HTTP 方法：
// 全大写（gin/echo）与首字母大写（chi）两种拼写。
var routeMethodBySelector = func() map[string]string {
	m := map[string]string{}
	for _, mth := range httpMethods {
		m[mth] = mth // GET / POST / ...
		lower := strings.ToLower(mth)
		m[strings.ToUpper(lower[:1])+lower[1:]] = mth // Get / Post / ...
	}
	return m
}()

// rawFinding 单条原始发现（未聚合）。
type rawFinding struct {
	Method string
	Path   string
	File   string
	Line   int
}

// Finding 聚合去重后的端点发现（同一 method+path 的来源合并，升序去重）。
type Finding struct {
	Method  string   `json:"method"`
	Path    string   `json:"path"`
	Sources []string `json:"sources"` // "文件:行号" 列表
}

// FileError 解析失败的文件与错误（容错：单文件失败不中断整体扫描）。
type FileError struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

// Result 一次目录扫描的完整结果。
type Result struct {
	Dir          string      `json:"dir"`
	FilesScanned int         `json:"files_scanned"` // 成功解析的 .go 文件数
	FilesFailed  int         `json:"files_failed"`  // 解析失败的文件数
	ParseErrors  []FileError `json:"parse_errors,omitempty"`
	Findings     []Finding   `json:"findings"` // 按 (Path, Method) 排序
}

// ScanDir 递归扫描 dir 下 Go 源码（跳过隐藏目录、vendor 与 _test.go 测试文件），
// 聚合去重路由注册发现。目录不可读等整体性错误返回 error；单文件解析失败
// 记入 ParseErrors 并继续（容错，不静默：结果与清单文本中均可见）。
func ScanDir(dir string) (*Result, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("扫描目录不可访问: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("扫描目标不是目录: %s", dir)
	}
	res := &Result{Dir: dir}
	fset := token.NewFileSet()
	var raw []rawFinding
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err // 遍历本身失败（权限等）整体报错，不静默
		}
		if d.IsDir() {
			name := d.Name()
			if path != dir && (strings.HasPrefix(name, ".") || name == "vendor") {
				return filepath.SkipDir // 隐藏目录（.git 等）与 vendor 跳过
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil // 非 Go 源码 / 测试文件（测试桩注册非真实路由）跳过
		}
		found, perr := scanFile(fset, path)
		if perr != nil {
			res.FilesFailed++
			res.ParseErrors = append(res.ParseErrors, FileError{File: path, Error: perr.Error()})
			return nil // 单文件容错，继续扫描
		}
		res.FilesScanned++
		raw = append(raw, found...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("遍历源码目录失败: %w", err)
	}
	res.Findings = aggregateFindings(raw)
	return res, nil
}

// scanFile 解析单个 Go 文件并提取路由注册发现。
func scanFile(fset *token.FileSet, path string) ([]rawFinding, error) {
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []rawFinding
	add := func(method, routePath string, pos token.Pos) {
		p := fset.Position(pos)
		out = append(out, rawFinding{Method: method, Path: routePath, File: path, Line: p.Line})
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := sel.Sel.Name
		// 框架方法路由：r.Get("/path") / r.GET("/path")（chi/gin/echo 按方法名识别）
		if method, ok := routeMethodBySelector[name]; ok {
			if s, ok := stringLitArg(call, 0); ok && strings.HasPrefix(s, "/") {
				add(method, NormalizePath(s), call.Pos())
			}
			return true
		}
		// net/http ServeMux 与 gin/httprouter Handle 形态
		if name == "Handle" || name == "HandleFunc" {
			scanHandleCall(call, add)
		}
		return true
	})
	return out, nil
}

// scanHandleCall 处理 Handle/HandleFunc 调用：
//   - 第一参数含空格 → Go 1.22 ServeMux 方法模式 "METHOD /path"；
//   - 第一参数为方法名且第二参数为路径字面量 → gin/httprouter Handle(method, path)；
//   - 第一参数为 "/path" → ServeMux 无方法模式，展开为全部标准方法。
func scanHandleCall(call *ast.CallExpr, add func(method, path string, pos token.Pos)) {
	s, ok := stringLitArg(call, 0)
	if !ok {
		return // 变量/拼接路径无法静态提取，跳过
	}
	if strings.Contains(s, " ") {
		parts := strings.Fields(s)
		if len(parts) == 2 && httpMethodSet[strings.ToUpper(parts[0])] && strings.HasPrefix(parts[1], "/") {
			add(strings.ToUpper(parts[0]), NormalizePath(parts[1]), call.Pos())
		}
		return
	}
	if httpMethodSet[strings.ToUpper(s)] {
		if p, ok := stringLitArg(call, 1); ok && strings.HasPrefix(p, "/") {
			add(strings.ToUpper(s), NormalizePath(p), call.Pos())
		}
		return
	}
	if strings.HasPrefix(s, "/") {
		for _, m := range httpMethods {
			add(m, NormalizePath(s), call.Pos())
		}
	}
}

// stringLitArg 取调用第 i 个参数的字符串字面量值（非字面量返回 ok=false）。
func stringLitArg(call *ast.CallExpr, i int) (string, bool) {
	if i >= len(call.Args) {
		return "", false
	}
	lit, ok := call.Args[i].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// NormalizePath 统一框架路径参数形态为 OpenAPI {param}：
// 逐段处理 —— ":id"（gin/echo）→ "{id}"；"*path"（gin 具名通配）→ "{path}"；
// "*"（echo 无名通配）→ "{wildcard}"；"{id:regex}"（chi 正则约束）→ "{id}"；
// "{path...}"（Go 1.22 后缀通配）→ "{path}"；"{$}"（Go 1.22 精确匹配标记）→ 移除该段。
func NormalizePath(p string) string {
	segs := strings.Split(p, "/")
	out := make([]string, 0, len(segs))
	for _, seg := range segs {
		switch {
		case strings.HasPrefix(seg, ":") && len(seg) > 1:
			out = append(out, "{"+seg[1:]+"}")
		case seg == "*":
			out = append(out, "{wildcard}")
		case strings.HasPrefix(seg, "*") && len(seg) > 1:
			out = append(out, "{"+seg[1:]+"}")
		case seg == "{$}":
			continue // 精确匹配标记：移除该段（/exact/{$} → /exact）
		case strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}"):
			name := seg[1 : len(seg)-1]
			name = strings.TrimSuffix(name, "...")
			if i := strings.Index(name, ":"); i >= 0 {
				name = name[:i]
			}
			out = append(out, "{"+name+"}")
		default:
			out = append(out, seg)
		}
	}
	return strings.Join(out, "/")
}

// aggregateFindings 按 method+path 聚合去重：来源合并升序去重，结果按 (Path, Method) 排序。
func aggregateFindings(raw []rawFinding) []Finding {
	type key struct{ Method, Path string }
	byKey := map[key]*Finding{}
	for _, r := range raw {
		k := key{r.Method, r.Path}
		f, ok := byKey[k]
		if !ok {
			f = &Finding{Method: r.Method, Path: r.Path}
			byKey[k] = f
		}
		f.Sources = append(f.Sources, fmt.Sprintf("%s:%d", r.File, r.Line))
	}
	out := make([]Finding, 0, len(byKey))
	for _, f := range byKey {
		sort.Strings(f.Sources)
		// 同一文件行重复注册去重（sources 已排序）
		dedup := f.Sources[:0]
		for i, s := range f.Sources {
			if i == 0 || s != f.Sources[i-1] {
				dedup = append(dedup, s)
			}
		}
		f.Sources = dedup
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}
