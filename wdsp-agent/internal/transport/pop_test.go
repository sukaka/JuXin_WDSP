package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// testIdentity 生成测试用自签证书身份。
func testIdentity(t *testing.T, notAfter time.Time) (*Identity, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "agent-1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &Identity{CertDER: der, Key: key, NotAfter: notAfter}, certPEM
}

// popCapture 捕获并校验 PoP 三头的服务端桩。
type popCapture struct {
	certHeader string
	tsHeader   string
	sigHeader  string
	authHeader string
	body       []byte
	path       string
	method     string
}

func (p *popCapture) handler(t *testing.T, resp func(w http.ResponseWriter)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.certHeader = r.Header.Get(HeaderAgentCert)
		p.tsHeader = r.Header.Get(HeaderAgentTimestamp)
		p.sigHeader = r.Header.Get(HeaderAgentSignature)
		p.authHeader = r.Header.Get("Authorization")
		p.path = r.URL.Path
		p.method = r.Method
		p.body, _ = io.ReadAll(r.Body)
		resp(w)
	}
}

// verifyPoP 按契约 §8 逐字节复现签名串并用证书公钥验签。
func (p *popCapture) verifyPoP(t *testing.T, wantDER []byte, wantTS int64) {
	t.Helper()
	if p.certHeader == "" || p.tsHeader == "" || p.sigHeader == "" {
		t.Fatalf("PoP 三头缺失: cert=%dB ts=%q sig=%dB", len(p.certHeader), p.tsHeader, len(p.sigHeader))
	}
	der, err := base64.StdEncoding.DecodeString(p.certHeader)
	if err != nil {
		t.Fatalf("证书头 base64: %v", err)
	}
	if string(der) != string(wantDER) {
		t.Fatal("证书头 DER 与身份证书不一致")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := strconv.ParseInt(p.tsHeader, 10, 64)
	if err != nil {
		t.Fatalf("时间戳头非 Unix 秒: %q", p.tsHeader)
	}
	if ts != wantTS {
		t.Fatalf("时间戳=%d，应 %d", ts, wantTS)
	}
	// 逐字节复现签名串：POP\n<METHOD>\n<PATH>\n<TS>\n<hex(SHA256(body))>
	sum := sha256.Sum256(p.body)
	input := "POP\n" + p.method + "\n" + p.path + "\n" + p.tsHeader + "\n" + hex.EncodeToString(sum[:])
	digest := sha256.Sum256([]byte(input))
	sig, err := base64.StdEncoding.DecodeString(p.sigHeader)
	if err != nil {
		t.Fatalf("签名头 base64: %v", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("证书公钥非 ECDSA")
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("PoP 签名验签失败（签名串未逐字节复现或密钥不匹配）")
	}
}

func (p *popCapture) assertNoPoP(t *testing.T) {
	t.Helper()
	if p.certHeader != "" || p.tsHeader != "" || p.sigHeader != "" {
		t.Fatalf("不应携带 PoP 头: cert=%dB ts=%q sig=%dB", len(p.certHeader), p.tsHeader, len(p.sigHeader))
	}
}

func TestPoPHeadersSignedPost(t *testing.T) {
	fixed := time.Unix(1788256800, 0)
	id, _ := testIdentity(t, fixed.Add(24*time.Hour))
	pc := &popCapture{}
	srv := httptest.NewServer(pc.handler(t, func(w http.ResponseWriter) {
		_ = json.NewEncoder(w).Encode(HeartbeatResponse{ServerTime: 1788256801, ConfigVersion: 1, DesiredState: "ENABLED"})
	}))
	defer srv.Close()

	c := newClient(t, srv)
	c.SetCredential("wda_x")
	c.SetIdentity(id)
	c.now = func() time.Time { return fixed }

	_, err := c.Heartbeat(context.Background(), "agent-1", HeartbeatRequest{
		Timestamp: 1788256800, Status: "ONLINE", Metrics: Metrics{CPUPercent: 1.5},
	})
	if err != nil {
		t.Fatal(err)
	}
	if pc.method != http.MethodPost || pc.path != "/api/v1/agents/agent-1/heartbeat" {
		t.Fatalf("%s %s", pc.method, pc.path)
	}
	if pc.authHeader != "" {
		t.Fatalf("启用 PoP 身份时不得附带 Bearer 凭据（防降级泄露）, auth=%q", pc.authHeader)
	}
	if len(pc.body) == 0 {
		t.Fatal("POST 应有 JSON body")
	}
	pc.verifyPoP(t, id.CertDER, fixed.Unix())
}

func TestPoPHeadersSignedEmptyBodyGet(t *testing.T) {
	fixed := time.Unix(1788256800, 0)
	id, _ := testIdentity(t, fixed.Add(24*time.Hour))
	pc := &popCapture{}
	srv := httptest.NewServer(pc.handler(t, func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"version":3,"policy":null}`))
	}))
	defer srv.Close()

	c := newClient(t, srv)
	c.SetCredential("x")
	c.SetIdentity(id)
	c.now = func() time.Time { return fixed }

	if _, err := c.GetConfig(context.Background(), "agent-1"); err != nil {
		t.Fatal(err)
	}
	if len(pc.body) != 0 {
		t.Fatalf("GET 应无 body，got %dB", len(pc.body))
	}
	// 空 body 也算哈希（契约 §8）：e3b0c442... 为 SHA256("") 周知值
	sum := sha256.Sum256(nil)
	if hex.EncodeToString(sum[:]) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal("测试前提：空串 SHA256 周知值不符")
	}
	pc.verifyPoP(t, id.CertDER, fixed.Unix())
}

func TestPoPAbsentWithoutIdentity(t *testing.T) {
	pc := &popCapture{}
	srv := httptest.NewServer(pc.handler(t, func(w http.ResponseWriter) {
		_ = json.NewEncoder(w).Encode(HeartbeatResponse{ConfigVersion: 1, DesiredState: "ENABLED"})
	}))
	defer srv.Close()

	c := newClient(t, srv)
	c.SetCredential("wda_x") // 无证书 → 仅 Bearer（现状行为）
	if _, err := c.Heartbeat(context.Background(), "a", HeartbeatRequest{}); err != nil {
		t.Fatal(err)
	}
	pc.assertNoPoP(t)
	if pc.authHeader != "Bearer wda_x" {
		t.Fatalf("auth=%q", pc.authHeader)
	}
}

func TestPoPSkippedWhenCertExpired(t *testing.T) {
	id, _ := testIdentity(t, time.Now().Add(-time.Minute)) // 已过期
	pc := &popCapture{}
	srv := httptest.NewServer(pc.handler(t, func(w http.ResponseWriter) {
		_ = json.NewEncoder(w).Encode(HeartbeatResponse{ConfigVersion: 1, DesiredState: "ENABLED"})
	}))
	defer srv.Close()

	c := newClient(t, srv)
	c.SetCredential("wda_x")
	c.SetIdentity(id)
	if _, err := c.Heartbeat(context.Background(), "a", HeartbeatRequest{}); err != nil {
		t.Fatal(err)
	}
	pc.assertNoPoP(t) // 过期证书不得签发 PoP 头（服务端对无效 PoP 一律 401 不降级）
	if pc.authHeader != "Bearer wda_x" {
		t.Fatalf("过期后应回退 Bearer, auth=%q", pc.authHeader)
	}
}

func TestEnrollWithCSRAndCertFields(t *testing.T) {
	var got EnrollRequest
	idPEM := func() []byte {
		_, pemData := testIdentity(t, time.Now().Add(90*24*time.Hour))
		return pemData
	}()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agent_id": "agent-1", "credential": "wda_x",
			"heartbeat_interval_seconds": 15, "config_version": 0,
			"agent_cert_pem":  string(idPEM),
			"ca_cert_pem":     string(idPEM),
			"cert_expires_at": "2026-12-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	c := newClient(t, srv)
	resp, err := c.Enroll(context.Background(), EnrollRequest{
		EnrollmentToken: "wdt_1", Hostname: "h", CSRPEM: "-----BEGIN CERTIFICATE REQUEST-----\n...",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.CSRPEM == "" {
		t.Fatal("enroll 请求应携带 csr_pem")
	}
	if resp.AgentCertPEM == "" || resp.CACertPEM == "" || resp.CertExpiresAt != "2026-12-01T00:00:00Z" {
		t.Fatalf("resp=%+v", resp)
	}
}

func TestEnrollLegacyServerNullCertFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"agent_id":"a","credential":"wda_x","heartbeat_interval_seconds":15,"config_version":0,"agent_cert_pem":null,"ca_cert_pem":null,"cert_expires_at":null}`))
	}))
	defer srv.Close()

	c := newClient(t, srv)
	resp, err := c.Enroll(context.Background(), EnrollRequest{EnrollmentToken: "wdt_1", Hostname: "h"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.AgentCertPEM != "" || resp.CACertPEM != "" || resp.CertExpiresAt != "" {
		t.Fatalf("老服务端 null 字段应解析为空串: %+v", resp)
	}
}

func TestRotateCertEndpoint(t *testing.T) {
	fixed := time.Unix(1788256800, 0)
	id, _ := testIdentity(t, fixed.Add(24*time.Hour))
	_, newCertPEM := testIdentity(t, fixed.Add(90*24*time.Hour))
	pc := &popCapture{}
	var gotReq RotateCertRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pc.handler(t, func(w http.ResponseWriter) {
			if r.URL.Path != "/api/v1/agents/agent-1/rotate-cert" || r.Method != http.MethodPost {
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			}
			_ = json.Unmarshal(pc.body, &gotReq)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"agent_cert_pem":  string(newCertPEM),
				"ca_cert_pem":     string(newCertPEM),
				"cert_expires_at": "2026-12-25T00:00:00Z",
			})
		})(w, r)
	}))
	defer srv.Close()

	c := newClient(t, srv)
	c.SetCredential("wda_x")
	c.SetIdentity(id)
	c.now = func() time.Time { return fixed }

	resp, err := c.RotateCert(context.Background(), "agent-1", "-----BEGIN CERTIFICATE REQUEST-----\nCSR")
	if err != nil {
		t.Fatal(err)
	}
	if gotReq.CSRPEM == "" {
		t.Fatal("rotate-cert 请求应携带 csr_pem")
	}
	pc.verifyPoP(t, id.CertDER, fixed.Unix()) // 轮换请求用当前证书 PoP（契约 §9）
	if resp.AgentCertPEM == "" || resp.CertExpiresAt != "2026-12-25T00:00:00Z" {
		t.Fatalf("resp=%+v", resp)
	}
}

func TestRotateCertBadResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"agent_cert_pem":"","ca_cert_pem":null,"cert_expires_at":null}`))
	}))
	defer srv.Close()
	c := newClient(t, srv)
	c.SetCredential("x")
	if _, err := c.RotateCert(context.Background(), "a", "csr"); err == nil {
		t.Fatal("缺少 agent_cert_pem 应报错")
	}
}
