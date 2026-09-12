// caddyclient_nodesync_test.go W18-SYNC 节点管理通道地址校验与 http(s) 客户端单测：
// 地址校验词表（unix 路径/内网 http(s) 放行；公网/保留地址、非 http 方案、
// userinfo/路径/查询、不可解析主机名拦截）+ httptest 假 Caddy Admin 全链路
// （/load 原文推送 + /config/ 读取 + 规范化哈希一致）。
package gatewayconfig

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestValidateNodeAdminAddr 登记地址校验词表（仅内网管理面地址纪律）。
func TestValidateNodeAdminAddr(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		// 放行：unix socket 两种形态 + 内网 http(s)
		{"unix 绝对路径", "/run/caddy-admin.sock", false},
		{"unix:// 形式", "unix:///run/caddy-admin.sock", false},
		{"http 私网地址带端口", "http://10.0.0.5:2019", false},
		{"https 私网地址", "https://192.168.1.2:2019", false},
		{"http 回环地址", "http://127.0.0.1:2019", false},
		{"http 回环 v6", "http://[::1]:2019", false},
		{"http 链路本地", "http://169.254.1.1:2019", false},
		{"http 根路径斜杠", "http://172.16.0.3:2019/", false},
		{"localhost 主机名", "http://localhost:2019", false},
		// 拦截：格式与范围
		{"空地址", "", true},
		{"纯主机名无方案", "10.0.0.5:2019", true},
		{"非 http 方案", "ftp://10.0.0.5:2019", true},
		{"公网 IP", "http://8.8.8.8:2019", true},
		{"公网 IP https", "https://203.0.113.10:2019", true},
		{"未指定地址", "http://0.0.0.0:2019", true},
		{"组播地址", "http://224.0.0.1:2019", true},
		{"携带用户信息", "http://user:pass@10.0.0.5:2019", true},
		{"携带路径", "http://10.0.0.5:2019/admin", true},
		{"携带查询", "http://10.0.0.5:2019?x=1", true},
		{"缺少主机名", "http://", true},
		{"unix:// 相对路径", "unix://run/caddy.sock", true},
		{"不可解析主机名", "http://node-nonexistent.invalid:2019", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateNodeAdminAddr(c.addr)
			if c.wantErr && err == nil {
				t.Fatalf("ValidateNodeAdminAddr(%q) = nil, want error", c.addr)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("ValidateNodeAdminAddr(%q) = %v, want nil", c.addr, err)
			}
			if c.wantErr && !errors.Is(err, ErrAdminAddrDenied) {
				t.Fatalf("ValidateNodeAdminAddr(%q) error = %v, want ErrAdminAddrDenied", c.addr, err)
			}
		})
	}
}

// fakeCaddyAdmin 假 Caddy Admin API（/load 存原文，/config/ 返回已加载原文）。
type fakeCaddyAdmin struct {
	mu       sync.Mutex
	loaded   string
	loadCode int // 非 0 时 /load 返回该状态码（推送失败注入）
	config   string
	loadBody []string
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type truncatedResponseBody struct {
	done bool
}

func (b *truncatedResponseBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, io.ErrUnexpectedEOF
	}
	b.done = true
	return copy(p, `{"ok":`), nil
}

func (f *fakeCaddyAdmin) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /load", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.loadBody = append(f.loadBody, string(body))
		code := f.loadCode
		if code == 0 {
			f.loaded = string(body)
		}
		f.mu.Unlock()
		if code != 0 {
			http.Error(w, `{"error":"load rejected"}`, code)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /config/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		out := f.loaded
		if f.config != "" {
			out = f.config
		}
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(out))
	})
	return mux
}

func (f *fakeCaddyAdmin) loadedConfig() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loaded
}

func (f *fakeCaddyAdmin) loadCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.loadBody...)
}

// TestCaddyClientForAdminAddrHTTP http(s) 目标全链路：/load 推送原文 +
// /config/ 读取 + 规范化哈希与发布内容一致（与主发布 verifyPublish 同口径）。
func TestCaddyClientForAdminAddrHTTP(t *testing.T) {
	fake := &fakeCaddyAdmin{}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	client, err := NewCaddyClientForAdminAddr(srv.URL)
	if err != nil {
		t.Fatalf("NewCaddyClientForAdminAddr: %v", err)
	}
	ctx := context.Background()
	cfg := `{"apps":{"http":{"servers":{"s0":{}}}},"admin":{"listen":"unix//run/caddy.sock"}}`
	if err := client.LoadConfig(ctx, cfg); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := fake.loadCalls(); len(got) != 1 || got[0] != cfg {
		t.Fatalf("load bodies = %v, want exact config json", got)
	}
	current, err := client.GetCurrentConfig(ctx)
	if err != nil {
		t.Fatalf("GetCurrentConfig: %v", err)
	}
	if current != cfg {
		t.Fatalf("current config = %q, want pushed json", current)
	}
	wantHash, err := CanonicalConfigHash(cfg)
	if err != nil {
		t.Fatalf("CanonicalConfigHash: %v", err)
	}
	gotHash, err := client.GetConfigHash(ctx)
	if err != nil {
		t.Fatalf("GetConfigHash: %v", err)
	}
	if gotHash != wantHash {
		t.Fatalf("hash = %s, want %s", gotHash, wantHash)
	}
	if err := client.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

// TestCaddyClientForAdminAddrRejected 非法地址构建客户端直接失败（推送前拦截）。
func TestCaddyClientForAdminAddrRejected(t *testing.T) {
	if _, err := NewCaddyClientForAdminAddr("http://8.8.8.8:2019"); !errors.Is(err, ErrAdminAddrDenied) {
		t.Fatalf("public ip: err = %v, want ErrAdminAddrDenied", err)
	}
	if _, err := NewCaddyClientForAdminAddr("gopher://10.0.0.1"); !errors.Is(err, ErrAdminAddrDenied) {
		t.Fatalf("bad scheme: err = %v, want ErrAdminAddrDenied", err)
	}
}

// TestCaddyClientForAdminAddrUnix unix 目标与 NewCaddyClient 等价（socketPath 保留）。
func TestCaddyClientForAdminAddrUnix(t *testing.T) {
	client, err := NewCaddyClientForAdminAddr("/run/caddy-admin.sock")
	if err != nil {
		t.Fatalf("NewCaddyClientForAdminAddr: %v", err)
	}
	if client.SocketPath() != "/run/caddy-admin.sock" {
		t.Fatalf("socket path = %q", client.SocketPath())
	}
}

// TestCaddyClientLoadErrorPropagated /load 非 200 如实返回 LoadError（含状态码）。
func TestCaddyClientLoadErrorPropagated(t *testing.T) {
	fake := &fakeCaddyAdmin{loadCode: http.StatusBadRequest}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	client, err := NewCaddyClientForAdminAddr(srv.URL)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	err = client.LoadConfig(context.Background(), `{"apps":{}}`)
	var loadErr *LoadError
	if !errors.As(err, &loadErr) || loadErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("LoadConfig error = %v, want LoadError 400", err)
	}
	if !strings.Contains(loadErr.Message, "load rejected") {
		t.Fatalf("LoadError message = %q", loadErr.Message)
	}
}

// TestCaddyClientLoadConfigRejectsInterruptedResponseBody 防止 /load 已返回 200
// 但响应体传输中断时被误判为成功；该错误必须回到节点同步结果，供后续恢复重试。
func TestCaddyClientLoadConfigRejectsInterruptedResponseBody(t *testing.T) {
	client := &CaddyClient{
		baseURL: "http://admin",
		httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(&truncatedResponseBody{}),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		})},
	}

	err := client.LoadConfig(context.Background(), `{"apps":{}}`)
	if err == nil || !strings.Contains(err.Error(), "load config response body") {
		t.Fatalf("LoadConfig error = %v, want interrupted response-body error", err)
	}
}

// TestCaddyClientGetCurrentConfigRejectsInterruptedResponseBody 防止读取当前配置
// 时的传输中断被上层误判为无上下文的普通错误。
func TestCaddyClientGetCurrentConfigRejectsInterruptedResponseBody(t *testing.T) {
	client := &CaddyClient{
		baseURL: "http://admin",
		httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(&truncatedResponseBody{}),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		})},
	}

	_, err := client.GetCurrentConfig(context.Background())
	if err == nil || !strings.Contains(err.Error(), "get config response body") {
		t.Fatalf("GetCurrentConfig error = %v, want interrupted response-body context", err)
	}
}

// TestCaddyClientPingRejectsInterruptedResponseBody 防止 /config/ 响应体中途
// 断开时 Ping 仍把节点判定为健康，导致发布/恢复链路跳过真实故障。
func TestCaddyClientPingRejectsInterruptedResponseBody(t *testing.T) {
	client := &CaddyClient{
		baseURL: "http://admin",
		httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(&truncatedResponseBody{}),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		})},
	}

	err := client.Ping(context.Background())
	if err == nil || !strings.Contains(err.Error(), "admin api response body") {
		t.Fatalf("Ping error = %v, want interrupted response-body context", err)
	}
}
