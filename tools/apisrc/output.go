// output.go apisrc 输出生成：OpenAPI 3 最小骨架（可直接走规范中心导入流水线）
// 与人类可读的清单文本。
package main

import (
	"fmt"
	"sort"
	"strings"
)

// SourceCodeMarker OpenAPI 骨架顶层来源标记（规范中心据此识别 SOURCE_CODE 学习来源，
// 见 server/internal/apisecurity/spec_source.go）。
const SourceCodeMarker = "SOURCE_CODE"

// OpenAPIDoc 生成 OpenAPI 3.0.3 最小骨架文档：
//
//	{"source":"SOURCE_CODE","openapi":"3.0.3","info":{...},"paths":{...},"x-apisrc":{...}}
//
// paths 下每个方法操作为空对象并带 x-apisrc-source 扩展（发现来源 file:line 列表）；
// source/x-apisrc 等顶层扩展键不影响规范解析器（仅识别 openapi + paths）。
func (r *Result) OpenAPIDoc() map[string]any {
	paths := map[string]any{}
	for _, f := range r.Findings {
		item, _ := paths[f.Path].(map[string]any)
		if item == nil {
			item = map[string]any{}
			paths[f.Path] = item
		}
		sources := make([]any, 0, len(f.Sources))
		for _, s := range f.Sources {
			sources = append(sources, s)
		}
		item[strings.ToLower(f.Method)] = map[string]any{"x-apisrc-source": sources}
	}
	return map[string]any{
		"source":  SourceCodeMarker,
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":   fmt.Sprintf("apisrc source inventory (%s)", r.Dir),
			"version": "0.0.0",
		},
		"paths": paths,
		"x-apisrc": map[string]any{
			"dir":           r.Dir,
			"files_scanned": r.FilesScanned,
			"files_failed":  r.FilesFailed,
			"parse_errors":  r.ParseErrors,
		},
	}
}

// Inventory 人类可读清单文本：端点列表（方法 路径 来源）+ 扫描统计 + 解析失败明细。
func (r *Result) Inventory() string {
	var b strings.Builder
	fmt.Fprintf(&b, "apisrc 源码 API 清单\n")
	fmt.Fprintf(&b, "扫描目录: %s\n", r.Dir)
	fmt.Fprintf(&b, "解析文件: %d 成功 / %d 失败\n", r.FilesScanned, r.FilesFailed)
	fmt.Fprintf(&b, "发现端点: %d（按 method+path 去重）\n\n", len(r.Findings))
	// 端点按 (Path, Method) 已排序；对齐输出
	width := 0
	keys := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		k := f.Method + " " + f.Path
		keys = append(keys, k)
		if len(k) > width {
			width = len(k)
		}
	}
	for i, f := range r.Findings {
		fmt.Fprintf(&b, "%-*s  %s\n", width, keys[i], strings.Join(f.Sources, ", "))
	}
	if len(r.ParseErrors) > 0 {
		b.WriteString("\n解析失败文件（已跳过，不影响其他文件）:\n")
		sort.Slice(r.ParseErrors, func(i, j int) bool { return r.ParseErrors[i].File < r.ParseErrors[j].File })
		for _, pe := range r.ParseErrors {
			fmt.Fprintf(&b, "  %s: %s\n", pe.File, pe.Error)
		}
	}
	return b.String()
}
