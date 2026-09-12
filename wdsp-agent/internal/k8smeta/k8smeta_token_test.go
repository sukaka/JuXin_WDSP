// 代码审查回归测试（批次5-A）：
// LOW-A5 ServiceAccount token 投射卷轮换后重读：每轮 sync 重读文件，
// 且单次请求 401 时重读并重试一次，不再永久 401 停滞。
package k8smeta

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// newTokenServer 仅接受 expected token；记录每次请求携带的 token。
func newTokenServer(t *testing.T, expected func() string) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		got = append(got, tok)
		mu.Unlock()
		if tok != expected() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/pods", "/api/v1/endpoints":
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{}, "items": []any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

// 每轮 sync 开头重读 token 文件：投射卷轮换（文件内容更新）后下一轮即恢复。
func TestSyncReloadsTokenFileEachRound(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	current := "v1"
	srv, _ := newTokenServer(t, func() string { return current })

	c := &Client{baseURL: srv.URL, token: "v1", tokenPath: tokenPath, nodeName: "n", cluster: "c", http: srv.Client()}
	if _, err := c.sync(context.Background()); err != nil {
		t.Fatalf("首轮应成功: %v", err)
	}
	// 投射卷轮换：apiserver 只认 v2，文件更新为 v2
	current = "v2"
	if err := os.WriteFile(tokenPath, []byte("v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.sync(context.Background()); err != nil {
		t.Fatalf("token 轮换后 sync 应重读文件并恢复: %v", err)
	}
	if c.token != "v2" {
		t.Fatalf("token 应已重读: %q", c.token)
	}
}

// 单次请求 401（内存 token 落后于文件）→ 重读文件并重试一次即成功。
func TestGetRetriesOnceWithReloadedTokenOn401(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	// 文件已是新 token，但 Client 内存中还是旧 token（模拟两次 sync 之间发生轮换）
	if err := os.WriteFile(tokenPath, []byte("fresh"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, got := newTokenServer(t, func() string { return "fresh" })

	c := &Client{baseURL: srv.URL, token: "stale", tokenPath: tokenPath, nodeName: "n", cluster: "c", http: srv.Client()}
	var page podList
	if err := c.get(context.Background(), "/api/v1/pods?limit=500", &page); err != nil {
		t.Fatalf("401 后应重读 token 并重试成功: %v", err)
	}
	if len(*got) != 2 || (*got)[0] != "stale" || (*got)[1] != "fresh" {
		t.Fatalf("应先 401 后携带新 token 重试: %v", *got)
	}
}

// 文件未更新且 401 持续 → 重试一次后如实报错（不无限重试）。
func TestGetPersistent401ReturnsError(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, got := newTokenServer(t, func() string { return "never" })

	c := &Client{baseURL: srv.URL, token: "stale", tokenPath: tokenPath, nodeName: "n", cluster: "c", http: srv.Client()}
	var page podList
	if err := c.get(context.Background(), "/api/v1/pods?limit=500", &page); err == nil {
		t.Fatal("持续 401 应返回错误")
	}
	if len(*got) != 2 {
		t.Fatalf("401 只应重试一次: %d 次请求", len(*got))
	}
}
