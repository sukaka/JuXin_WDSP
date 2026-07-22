// Package middleware 提供管理 API 的 HTTP 中间件。
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/response"
)

// RequestIDHeader 是管理系统 Request ID 响应头。
const RequestIDHeader = "X-Jiuzhang-Request-ID"

// newRequestID 生成与网关格式一致的 Request ID（UUID v4）。
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]), hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]), hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]))
}

// RequestID 为每个请求生成 Request ID。
// 不完全信任客户端传入值：仅当客户端值符合严格格式时才采纳用于关联，
// 否则生成新值。
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := sanitizeClientRequestID(r.Header.Get(RequestIDHeader))
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set(RequestIDHeader, id)
		ctx := context.WithValue(r.Context(), response.RequestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// sanitizeClientRequestID 校验客户端 Request ID 格式（防止日志注入）。
func sanitizeClientRequestID(v string) string {
	if len(v) == 0 || len(v) > 64 {
		return ""
	}
	for _, c := range v {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return ""
		}
	}
	return v
}

// SecurityHeaders 设置安全响应头。
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// MaintenanceChecker 检查系统是否处于维护模式（恢复流程使用）。
type MaintenanceChecker interface {
	// InMaintenance 返回 true 表示维护中。
	InMaintenance(ctx context.Context) (bool, error)
}

// MaintenanceGate 在维护模式下拒绝写操作与发布类路径（允许恢复确认/取消、健康检查、只读 GET）。
func MaintenanceGate(checker MaintenanceChecker) func(http.Handler) http.Handler {
	if checker == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	allowPrefix := []string{
		"/api/v1/health",
		"/api/v1/auth/",
		"/api/v1/restores",
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 只读放行
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			path := r.URL.Path
			for _, p := range allowPrefix {
				if strings.HasPrefix(path, p) {
					next.ServeHTTP(w, r)
					return
				}
			}
			ok, err := checker.InMaintenance(r.Context())
			if err != nil {
				slog.Warn("maintenance check failed", "error", err)
				next.ServeHTTP(w, r)
				return
			}
			if ok {
				response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable,
					"系统处于维护模式（数据恢复中），请稍后再试")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CORS 处理跨域（仅允许配置的来源）。
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := map[string]bool{}
	for _, o := range allowedOrigins {
		allowed[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && allowed[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, "+RequestIDHeader)
				w.Header().Set("Access-Control-Max-Age", "600")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RecoverPanic 捕获 panic，返回统一内部错误（不泄露堆栈）。
func RecoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered",
					"request_id", response.RequestIDFrom(r),
					"path", r.URL.Path,
					"panic", rec,
				)
				response.Error(w, r, http.StatusInternalServerError,
					response.CodeInternalError, "服务器内部错误，请稍后重试")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// AccessLog 记录管理 API 访问日志。
func AccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		slog.Info("api access",
			"request_id", response.RequestIDFrom(r),
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_ip", remoteIP(r),
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Flush 透传 http.Flusher（SSE 流式响应需要，否则流式接口无法向下刷新）。
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap 暴露底层 ResponseWriter（http.NewResponseController 设置写期限等需要）。
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// remoteIP 返回直接连接的来源 IP（管理面无前置代理时不信任 XFF）。
// 正确处理 IPv4 与 IPv6（含方括号）地址。
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RemoteIP 导出 remoteIP 供业务模块记录来源 IP。
func RemoteIP(r *http.Request) string {
	return remoteIP(r)
}
