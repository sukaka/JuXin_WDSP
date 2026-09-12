// apisrc 任务书 §28 W14-SRC：源码 API 发现工具 v1（P2-07，学习来源 SOURCE_CODE）。
//
// 静态扫描 Go 源码中的路由注册（net/http ServeMux 方法模式与 http.HandleFunc、
// chi/echo/gin 字面量方法路由），输出 OpenAPI 3.0.3 最小骨架 JSON
// （{"source":"SOURCE_CODE","openapi":"3.0.3","paths":{...}}），可直接经
// 规范中心导入接口（POST /api/v1/api-security/specs/import）导入。
//
// 用法：
//
//	cd tools/apisrc && go run . -dir <源码目录> [-out inventory.json]
//
// -out 缺省时 JSON 写 stdout；指定 -out 时 JSON 落盘、stdout 打印清单文本。
// 仅使用 Go 标准库（go/parser + go/ast），不做类型检查，单文件语法错误容错跳过。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	dir := flag.String("dir", "", "待扫描的 Go 源码目录（必填）")
	out := flag.String("out", "", "OpenAPI3 骨架 JSON 输出路径（缺省写 stdout）")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "用法: apisrc -dir <源码目录> [-out inventory.json]（必须指定 -dir）")
		os.Exit(2)
	}
	res, err := ScanDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "扫描失败:", err)
		os.Exit(1)
	}
	data, err := json.MarshalIndent(res.OpenAPIDoc(), "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "生成 JSON 失败:", err)
		os.Exit(1)
	}
	data = append(data, '\n')
	if *out == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			fmt.Fprintln(os.Stderr, "写 stdout 失败:", err)
			os.Exit(1)
		}
		return
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "写输出文件失败:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, res.Inventory())
	fmt.Fprintf(os.Stdout, "JSON 已写入: %s\n", *out)
}
