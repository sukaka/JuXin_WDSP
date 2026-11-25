// tls_bridge.go 将 jiuzhang_tls_mux 的加密连接元数据（国密 TLCP / 国际 TLS / ClientHello / JA3）
// 桥接到 jiuzhang_guard 请求上下文，并提供站点级 HTTP 协议版本降级门控。
package jiuzhang_guard

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/tlsmux"
)

type tlsConnMetaKey struct{}

// tlsConnMetaFrom 从请求上下文提取 jiuzhang_tls_mux 登记的加密会话元数据（未经过 mux 时返回 nil）。
func tlsConnMetaFrom(ctx context.Context) *tlsmux.ConnMeta {
	if ctx == nil {
		return nil
	}
	if m, ok := ctx.Value(tlsConnMetaKey{}).(*tlsmux.ConnMeta); ok {
		return m
	}
	return nil
}

// attachTLSConnMeta 在 ServeHTTP 入口（RemoteAddr 改写之前）检索连接级 TLS/TLCP 元数据并绑定至请求上下文：
// 若当前为国密 TLCP 1.1 连接且 r.TLS 为空，则补齐真实语义的 *tls.ConnectionState，
// 使下游 reverse_proxy（X-Forwarded-Proto: https）、Bot 挑战（HTTPS 判定）与访问日志全链路一致。
func attachTLSConnMeta(ctx context.Context, r *http.Request) context.Context {
	var localAddr net.Addr
	if v := ctx.Value(http.LocalAddrContextKey); v != nil {
		localAddr, _ = v.(net.Addr)
	}
	meta := tlsmux.LookupConnMeta(r.RemoteAddr, localAddr)
	if meta == nil {
		return ctx
	}
	if r.TLS == nil && meta.IsGM {
		r.TLS = meta.SyntheticTLSState()
	}
	return context.WithValue(ctx, tlsConnMetaKey{}, meta)
}

// compileAllowedHTTPVersions 编译站点允许的 HTTP 协议版本集合（空列表 = nil，表示不限制，零行为变化）。
func compileAllowedHTTPVersions(versions []string) map[string]bool {
	if len(versions) == 0 {
		return nil
	}
	out := make(map[string]bool, len(versions))
	for _, raw := range versions {
		switch strings.ToUpper(strings.TrimSpace(raw)) {
		case "HTTP/1.0", "1.0":
			out["HTTP/1.0"] = true
		case "HTTP/1.1", "1.1":
			out["HTTP/1.1"] = true
		case "HTTP/2", "HTTP/2.0", "2", "H2":
			out["HTTP/2.0"] = true
		case "HTTP/3", "HTTP/3.0", "3", "H3":
			out["HTTP/3.0"] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// isHTTPVersionAllowed 检查请求 HTTP 版本是否在站点允许列表内（未配置限制时恒放行）。
func (g *Guard) isHTTPVersionAllowed(r *http.Request) bool {
	if len(g.allowedHTTPVersionSet) == 0 {
		return true
	}
	proto := strings.ToUpper(strings.TrimSpace(r.Proto))
	if proto == "HTTP/2" {
		proto = "HTTP/2.0"
	} else if proto == "HTTP/3" {
		proto = "HTTP/3.0"
	}
	return g.allowedHTTPVersionSet[proto]
}
