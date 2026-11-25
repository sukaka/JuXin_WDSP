package jiuzhang_guard

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/tlsmux"
)

func TestGuardBridgesGMTLCPMetaAndAccessLogFields(t *testing.T) {
	dir := t.TempDir()
	accessLogPath := filepath.Join(dir, "access-full.jsonl")
	g := &Guard{
		AppID:       "app-gm-test",
		GatewayNode: "gw-gm-01",
		EventsLog:   filepath.Join(dir, "events.log"),
		AccessLog: &accessLogJSON{
			Enabled: true,
			LogPath: accessLogPath,
		},
		AllowedHTTPVersions: []string{"HTTP/1.1", "HTTP/2"},
	}
	if err := g.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Guard.Provision: %v", err)
	}
	defer func() { _ = g.Cleanup() }()

	remoteAddr := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321}
	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}
	unregister := tlsmux.RegisterConnMeta(remoteAddr, localAddr, &tlsmux.ConnMeta{
		ApplicationID:      "app-gm-test",
		SNI:                "gm.example.com",
		DetectedProtocol:   tlsmux.ProtoTLCP11,
		NegotiatedProtocol: tlsmux.ProtoTLCP11,
		ProtocolVersion:    tlsmux.VersionTLCP11,
		CipherSuiteID:      0xe053,
		CipherSuite:        "TLCP_ECC_SM4_GCM_SM3",
		IsGM:               true,
		JA3Hash:            "0123456789abcdef0123456789abcdef",
		ALPN:               "http/1.1",
	})
	defer unregister()

	var downstreamSawTLS bool
	var downstreamTLSVersion uint16
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.TLS != nil {
			downstreamSawTLS = true
			downstreamTLSVersion = r.TLS.Version
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return nil
	})

	// 1. 合法 HTTP/1.1 国密请求：放行 + 下游看到 r.TLS(0x0101) + 访问日志含国密字段
	req := httptest.NewRequest(http.MethodGet, "https://gm.example.com/orders", nil)
	req.RemoteAddr = remoteAddr.String()
	req.TLS = nil // 模拟 *tlcp.Conn 进入 net/http 时 r.TLS 为 nil
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, localAddr))
	rr := httptest.NewRecorder()
	if err := g.ServeHTTP(rr, req, next); err != nil {
		t.Fatalf("ServeHTTP HTTP/1.1 failed: %v", err)
	}
	if !downstreamSawTLS || downstreamTLSVersion != tlsmux.VersionTLCP11 {
		t.Fatalf("expected downstream r.TLS with version 0x0101, sawTLS=%v ver=0x%x", downstreamSawTLS, downstreamTLSVersion)
	}

	// 2. HTTP/1.0 请求被站点降级策略拒绝（返回 505）
	req10 := httptest.NewRequest(http.MethodGet, "https://gm.example.com/old", nil)
	req10.Proto = "HTTP/1.0"
	req10.ProtoMajor = 1
	req10.ProtoMinor = 0
	req10.RemoteAddr = remoteAddr.String()
	req10 = req10.WithContext(context.WithValue(req10.Context(), http.LocalAddrContextKey, localAddr))
	rr10 := httptest.NewRecorder()
	err := g.ServeHTTP(rr10, req10, next)
	if err == nil {
		t.Fatal("expected HTTP/1.0 to be rejected when allowed_http_versions=[HTTP/1.1, HTTP/2]")
	}
	var hErr caddyhttp.HandlerError
	if ok := func() bool {
		he, ok := err.(caddyhttp.HandlerError)
		hErr = he
		return ok
	}(); !ok || hErr.StatusCode != http.StatusHTTPVersionNotSupported {
		t.Fatalf("expected 505 HandlerError, got %T %v", err, err)
	}

	// 校验全量访问日志已记录国密 TLS 字段
	raw, err := os.ReadFile(accessLogPath)
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	foundGM := false
	for scanner.Scan() {
		var rec accessLogRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Fatalf("unmarshal access log: %v", err)
		}
		if rec.Path == "/orders" && rec.TLSProtocol == tlsmux.ProtoTLCP11 && rec.TLSIsGM &&
			rec.TLSCipherSuite == "TLCP_ECC_SM4_GCM_SM3" && rec.TLSJA3 == "0123456789abcdef0123456789abcdef" {
			foundGM = true
		}
	}
	if !foundGM {
		t.Fatalf("access log missing GM TLCP fields, content:\n%s", string(raw))
	}
}

func TestCapabilityManifestIncludesTLSMuxAndTLCP(t *testing.T) {
	m := buildCapabilityManifest(capabilityInputs{NodeID: "gw-01", GRPCUnary: true}, time.Now())
	if msg := m.Validate(); msg != "" {
		t.Fatalf("manifest validation failed: %s", msg)
	}
	if m.Protocols["tls_mux"] != "v1" {
		t.Errorf("protocols.tls_mux = %q, want v1", m.Protocols["tls_mux"])
	}
	if m.Protocols["tlcp"] != "1.1" {
		t.Errorf("protocols.tlcp = %q, want 1.1", m.Protocols["tlcp"])
	}
}
