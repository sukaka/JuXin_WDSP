package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnvironmentHeader(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	// 配置环境标识时：所有响应携带该头（含非 2xx）
	rw := httptest.NewRecorder()
	EnvironmentHeader("test")(next).ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if got := rw.Header().Get("X-Jiuzhang-Environment"); got != "test" {
		t.Fatalf("X-Jiuzhang-Environment = %q, want test", got)
	}

	// 空值（未配置）时不写头——门禁按「标识缺失」处理
	rw2 := httptest.NewRecorder()
	EnvironmentHeader("")(next).ServeHTTP(rw2, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if got := rw2.Header().Get("X-Jiuzhang-Environment"); got != "" {
		t.Fatalf("empty env must not emit header, got %q", got)
	}
}
