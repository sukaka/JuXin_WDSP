// 302 Location 端口改写（HTTP 代理配置之一，阶段8）。
//
// 背景：源站 302 跳转常携带内部地址/端口（如 http://upstream:8080/login），
// 客户端经 WAF 接入端口访问时会拿到不可达的 Location；开启后把所有放行响应中
// 绝对 Location 的显式端口统一改写为接入端口（redirect_port_rewrite 下发的值）。
// 默认关闭：redirect_port_rewrite=0 时 serveNext 不包装 writer，零行为变化。
package jiuzhang_guard

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// redirectLocationWriter 包装下游 ResponseWriter：在头部提交前（WriteHeader/首次 Write/Flush）
// 一次性改写 Location 端口。实现 http.Flusher / http.Hijacker / Unwrap 透传（反代 SSE/WebSocket 需要）。
type redirectLocationWriter struct {
	http.ResponseWriter
	port        int
	wroteHeader bool
}

func newRedirectLocationWriter(w http.ResponseWriter, port int) *redirectLocationWriter {
	return &redirectLocationWriter{ResponseWriter: w, port: port}
}

// commit 头部提交前执行一次性改写（改写失败原样放行，不影响响应）。
func (w *redirectLocationWriter) commit() {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	loc := w.Header().Get("Location")
	if loc == "" {
		return
	}
	if rewritten, ok := rewriteLocationPort(loc, w.port); ok {
		w.Header().Set("Location", rewritten)
	}
}

func (w *redirectLocationWriter) WriteHeader(code int) {
	// 1xx 信息响应不提交最终头部（后续还有正式 WriteHeader）
	if code < 100 || code >= 200 {
		w.commit()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *redirectLocationWriter) Write(p []byte) (int, error) {
	w.commit()
	return w.ResponseWriter.Write(p)
}

// Flush 透传底层 Flusher；Flush 会提交头部，先执行改写。
func (w *redirectLocationWriter) Flush() {
	w.commit()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap 返回底层 writer（http.ResponseController 依赖，用于透传 Hijack 等可选能力）。
func (w *redirectLocationWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack 透传连接劫持（WebSocket 升级需要；底层不支持时如实报错）。
func (w *redirectLocationWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying writer does not support hijacking")
	}
	return h.Hijack()
}

// rewriteLocationPort 把绝对 Location 的显式端口改写为 port（port==80 时剥离端口），
// 保留原 scheme、host 与 query。
// 相对路径、无显式端口、端口已相同、URL 解析失败均不改写（ok=false，调用方保持原值）。
func rewriteLocationPort(loc string, port int) (string, bool) {
	if port <= 0 {
		return "", false
	}
	u, err := url.Parse(loc)
	if err != nil {
		return "", false // 错误 URL：原样放行
	}
	if !u.IsAbs() || u.Host == "" {
		return "", false // 相对路径/协议相对：不动
	}
	cur := u.Port()
	if cur == "" {
		return "", false // 无显式端口：不动
	}
	if curPort, err := strconv.Atoi(cur); err != nil || curPort == port {
		return "", false // 非法端口或端口已相同：不动
	}
	host := u.Hostname()
	if port != 80 {
		u.Host = net.JoinHostPort(host, strconv.Itoa(port))
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]" // IPv6 字面量剥离端口后仍需保留方括号
	} else {
		u.Host = host
	}
	return u.String(), true
}
