package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCLIHealthcheckFlag(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "enabled": true, "listening": true, "listen": "0.0.0.0:15000",
		})
	}))
	defer okSrv.Close()

	addr := strings.TrimPrefix(okSrv.URL, "http://")
	if err := run([]string{"--healthcheck", "--health-addr", addr}); err != nil {
		t.Fatalf("--healthcheck 对健康端点应返回 nil: %v", err)
	}

	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer badSrv.Close()

	badAddr := strings.TrimPrefix(badSrv.URL, "http://")
	if err := run([]string{"--healthcheck", "--health-addr", badAddr}); err == nil {
		t.Fatal("--healthcheck 对 503 端点应返回错误")
	}
}
