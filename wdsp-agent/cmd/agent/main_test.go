package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
)

// testCertPEM 测试用自签证书 PEM。
func testCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "agent-1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCmdEnrollSavesCertBundle(t *testing.T) {
	certPEM := testCertPEM(t)
	var gotCSR string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/enroll" {
			t.Errorf("path=%s", r.URL.Path)
		}
		var req struct {
			CSRPEM string `json:"csr_pem"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotCSR = req.CSRPEM
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agent_id": "agent-1", "credential": "wda_deadbeef",
			"heartbeat_interval_seconds": 15, "config_version": 0,
			"agent_cert_pem":  certPEM,
			"ca_cert_pem":     certPEM,
			"cert_expires_at": "2026-12-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.json")
	stateDir := filepath.Join(dir, "state")
	if err := cmdEnroll([]string{
		"--server", srv.URL, "--token", "wdt_abc",
		"--config", cfgPath, "--state-dir", stateDir,
	}); err != nil {
		t.Fatal(err)
	}

	// CSR 已上送且 CN 留空（契约 §7）
	block, _ := pem.Decode([]byte(gotCSR))
	if block == nil {
		t.Fatal("enroll 未上送 csr_pem")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "" {
		t.Fatalf("CSR CN 应留空，got %q", csr.Subject.CommonName)
	}

	// 私钥 0600 落盘
	fi, err := os.Stat(filepath.Join(stateDir, "agent.key"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("agent.key 权限=%o，应 0600", perm)
	}
	// 证书与 CA 三件套
	for _, name := range []string{"agent.crt", "ca.crt"} {
		data, err := os.ReadFile(filepath.Join(stateDir, name))
		if err != nil {
			t.Fatalf("%s 未保存: %v", name, err)
		}
		if string(data) != certPEM {
			t.Fatalf("%s 内容与服务端下发不一致", name)
		}
	}
	// agent.json 记录 cert_expires_at
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentID != "agent-1" || cfg.Credential != "wda_deadbeef" {
		t.Fatalf("cfg=%+v", cfg)
	}
	if cfg.CertExpiresAt != "2026-12-01T00:00:00Z" {
		t.Fatalf("cert_expires_at=%q", cfg.CertExpiresAt)
	}
}

func TestCmdEnrollLegacyServerBearer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"agent_id":"agent-1","credential":"wda_x","heartbeat_interval_seconds":15,"config_version":0,"agent_cert_pem":null,"ca_cert_pem":null,"cert_expires_at":null}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.json")
	stateDir := filepath.Join(dir, "state")
	if err := cmdEnroll([]string{
		"--server", srv.URL, "--token", "wdt_abc",
		"--config", cfgPath, "--state-dir", stateDir,
	}); err != nil {
		t.Fatal(err)
	}

	// 老服务端：无证书文件，agent.json 正常保存（Bearer 模式）
	if _, err := os.Stat(filepath.Join(stateDir, "agent.crt")); !os.IsNotExist(err) {
		t.Fatal("老服务端不应产生 agent.crt")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentID != "agent-1" || cfg.CertExpiresAt != "" {
		t.Fatalf("cfg=%+v", cfg)
	}
}
