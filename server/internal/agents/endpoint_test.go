package agents

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSelfSignedCertWithIPs(t *testing.T, ips ...string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var ipList []net.IP
	for _, s := range ips {
		ipList = append(ipList, net.ParseIP(s))
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "wdsp-console"},
		IPAddresses:  ipList,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(t.TempDir(), "console.crt")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return certPath
}

func TestNormalizeInstallServerURL(t *testing.T) {
	cases := []struct {
		in      string
		port    int
		want    string
		wantErr bool
	}{
		{"", 8443, "", false},
		{"192.168.10.20", 8443, "https://192.168.10.20:8443", false},
		{"192.168.10.20", 443, "https://192.168.10.20", false},
		{"192.168.10.20:9443", 8443, "https://192.168.10.20:9443", false},
		{"https://10.0.1.5:8443/", 8443, "https://10.0.1.5:8443", false},
		{"fd00::10", 8443, "https://[fd00::10]:8443", false},
		{"http://127.0.0.1:8080", 8443, "http://127.0.0.1:8080", false},
		{"http://192.168.10.20:8080", 8443, "", true},           // 非回环明文 HTTP 拒绝
		{"https://192.168.10.20:8443/sub", 8443, "", true},      // 拒绝子路径
		{"https://user:pass@192.168.10.20", 8443, "", true},     // 拒绝凭据段
		{"https://192.168.10.20:8443?a=1", 8443, "", true},      // 拒绝查询串
		{"https://192.168.10.20:8443;id", 8443, "", true},       // 拒绝 Shell 元字符
		{"https://192.168.10.20:99999", 8443, "", true},         // 非法端口
		{"ftp://192.168.10.20", 8443, "", true},                 // 非法协议
	}
	for _, tc := range cases {
		got, err := NormalizeInstallServerURL(tc.in, tc.port)
		if tc.wantErr {
			if err == nil {
				t.Errorf("NormalizeInstallServerURL(%q) expected error, got %q", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeInstallServerURL(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizeInstallServerURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestInstallEndpointAutoDiscoveryAndPersistence(t *testing.T) {
	kv := &fakeSettingsKV{m: map[string]string{}}
	auditSpy := &spyAuditRecorder{}
	certPath := writeSelfSignedCertWithIPs(t, "127.0.0.1", "10.20.30.40")

	h := NewHandler(nil).
		SetAudits(auditSpy).
		SetInstallEndpointConfig(InstallEndpointConfig{
			ConsoleHTTPSPort: 8443,
			HostIPs:          []string{"192.168.50.10", "127.0.0.1"},
			ConsoleCertFile:  certPath,
			Settings:         kv,
			detectLocalIPs:   func() []string { return []string{"172.18.0.5"} },
		})

	mux := http.NewServeMux()
	RegisterAdminRoutes(mux, injectPerms(PermAgentsView, PermAgentsManage), h)

	// 1. 浏览器经 HTTP :8080 访问某个 IP 时，自动升级到 https://<该IP>:8443，并汇总候选 IP
	req := httptest.NewRequest(http.MethodGet, "http://192.168.50.10:8080/api/v1/traffic/agents/install-endpoint", nil)
	req.Host = "192.168.50.10:8080"
	req.Header.Set("X-Forwarded-Proto", "http")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET install-endpoint HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Data InstallEndpointResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data.RecommendedURL != "https://192.168.50.10:8443" {
		t.Fatalf("HTTP :8080 访问应自动升级为 HTTPS :8443，got %q", env.Data.RecommendedURL)
	}
	if env.Data.Source != "request_host" {
		t.Fatalf("source=%q, want request_host", env.Data.Source)
	}
	if !env.Data.SelfSignedTLS {
		t.Fatal("自签 console.crt 应标记 self_signed_tls=true")
	}
	if len(env.Data.CandidateIPs) < 3 {
		t.Fatalf("应聚合全部非回环候选 IP，got %v", env.Data.CandidateIPs)
	}

	// 2. 浏览器经 localhost 访问时，不推荐 127.0.0.1，改用宿主配置 IP
	reqLocal := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:5173/api/v1/traffic/agents/install-endpoint", nil)
	reqLocal.Host = "127.0.0.1:5173"
	recLocal := httptest.NewRecorder()
	mux.ServeHTTP(recLocal, reqLocal)
	if err := json.Unmarshal(recLocal.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data.RecommendedURL != "https://192.168.50.10:8443" || env.Data.Source != "configured_host_ip" {
		t.Fatalf("localhost 访问应自动回退至宿主机 IP，got url=%q source=%q", env.Data.RecommendedURL, env.Data.Source)
	}

	// 3. PUT 保存自定义裸 IP（自动补 https:// 与端口并记审计）
	recPut := httptest.NewRecorder()
	reqPut := httptest.NewRequest(http.MethodPut, "/api/v1/traffic/agents/install-endpoint",
		bytes.NewBufferString(`{"server_url":"10.99.88.77"}`))
	mux.ServeHTTP(recPut, reqPut)
	if recPut.Code != http.StatusOK {
		t.Fatalf("PUT install-endpoint HTTP %d: %s", recPut.Code, recPut.Body.String())
	}
	if err := json.Unmarshal(recPut.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data.RecommendedURL != "https://10.99.88.77:8443" || env.Data.SavedURL != "https://10.99.88.77:8443" || env.Data.Source != "saved" {
		t.Fatalf("保存后应优先返回 saved URL，got %+v", env.Data)
	}
	if len(auditSpy.records) == 0 || auditSpy.records[len(auditSpy.records)-1].ObjectType != "agent_install_endpoint" {
		t.Fatalf("PUT 应记录审计日志，got %+v", auditSpy.records)
	}

	// 4. PUT 非法非回环 HTTP 必须返回 400
	recBad := httptest.NewRecorder()
	reqBad := httptest.NewRequest(http.MethodPut, "/api/v1/traffic/agents/install-endpoint",
		bytes.NewBufferString(`{"server_url":"http://10.99.88.77:8080"}`))
	mux.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("非回环 http 应返回 400，got %d", recBad.Code)
	}

	// 5. PUT 空串清空覆盖，恢复自动探测
	recClear := httptest.NewRecorder()
	reqClear := httptest.NewRequest(http.MethodPut, "/api/v1/traffic/agents/install-endpoint",
		bytes.NewBufferString(`{"server_url":""}`))
	reqClear.Host = "127.0.0.1:8080"
	mux.ServeHTTP(recClear, reqClear)
	if recClear.Code != http.StatusOK {
		t.Fatalf("清空保存地址应返回 200，got %d", recClear.Code)
	}
	if err := json.Unmarshal(recClear.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data.SavedURL != "" || env.Data.Source != "configured_host_ip" {
		t.Fatalf("清空后应恢复自动探测，got %+v", env.Data)
	}
}
