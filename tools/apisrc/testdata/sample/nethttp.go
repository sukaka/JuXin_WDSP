// 样例：net/http ServeMux 与包级注册形态（仅语法解析样例，不参与编译）。
package sample

import "net/http"

func registerNetHTTP() {
	mux := http.NewServeMux()
	mux.Handle("GET /users/{id}", nil)      // Go 1.22 方法模式
	mux.HandleFunc("POST /orders", nil)     // 方法模式 HandleFunc
	mux.Handle("/legacy", nil)              // 无方法模式 → 展开 8 方法
	mux.Handle("GET /files/{path...}", nil) // 后缀通配 → {path}
	mux.Handle("GET /exact/{$}", nil)       // {$} 精确标记 → /exact
	http.Handle("HEAD /healthz", nil)       // 包级 Handle
	http.HandleFunc("GET /ping", nil)       // 包级 HandleFunc
	pattern := "/dynamic"
	mux.Handle(pattern, nil) // 变量路径 → 跳过
	mux.Handle(123, nil)     // 非字符串 → 跳过
}
