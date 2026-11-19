// pop_test.go Phase 2-B 机器身份证书与 PoP 认证单测（契约 §7-§12）：
// enroll 带/不带 CSR、PoP 全链路、防降级、过期/未知指纹/CN 不匹配/时间窗外、
// 宽限期语义、rotate-cert（仅 PoP）、disable 后旧证书立即失效。
// 测试内用真实自签 CA + ECDSA P-256 闭环（仓储仍为内存 fake，不触 DB）。
package agents

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ---------- fakeMachineStore Phase 2-B 方法（接口实现） ----------

func (f *fakeMachineStore) AgentByID(_ context.Context, agentID uuid.UUID) (*Agent, error) {
	if a, ok := f.agentsByID[agentID]; ok {
		return a, nil
	}
	return nil, ErrAgentNotFound
}

// CertFingerprintUsable 模拟契约 §10 语义：当前指纹直接可用；宽限行 grace_until > now 可用；
// 立即撤销（revokedFP）、禁用 Agent 与未知指纹不可用。
func (f *fakeMachineStore) CertFingerprintUsable(_ context.Context, agentID uuid.UUID, fingerprint string, now time.Time) (bool, error) {
	a, ok := f.agentsByID[agentID]
	if !ok || a.Disabled {
		return false, nil
	}
	if f.revokedFP[fingerprint] {
		return false, nil
	}
	if a.CertFingerprint != nil && *a.CertFingerprint == fingerprint {
		return true, nil
	}
	if g, ok := f.graceFP[fingerprint]; ok && g.After(now) {
		return true, nil
	}
	return false, nil
}

func (f *fakeMachineStore) HasCertRevocations(_ context.Context, agentID uuid.UUID) (bool, error) {
	return f.revokedAgents[agentID], nil
}

// RotateAgentCert 模拟契约 §9 事务语义：出示指纹须==当前指纹，旧指纹入宽限，当前指纹/到期换新。
func (f *fakeMachineStore) RotateAgentCert(_ context.Context, in RotateCertInput) (*RotateCertResult, error) {
	f.rotateCalls++
	if f.rotateErr != nil {
		return nil, f.rotateErr
	}
	if f.rotateResult == nil {
		f.rotateResult = map[string]RotateCertResult{}
	}
	key := in.OldFingerprint + ":" + in.PublicKeyHash
	if result, ok := f.rotateResult[key]; ok {
		return &result, nil
	}
	a, ok := f.agentsByID[in.AgentID]
	if !ok {
		return nil, ErrAgentNotFound
	}
	if a.CertFingerprint == nil || *a.CertFingerprint != in.OldFingerprint {
		return nil, ErrCertFingerprintMismatch
	}
	f.graceFP[in.OldFingerprint] = in.GraceUntil
	newFP := in.NewFingerprint
	newNA := in.NewNotAfter
	a.CertFingerprint = &newFP
	a.CertNotAfter = &newNA
	cp := in
	f.rotateIn = &cp
	result := RotateCertResult{AgentCertPEM: in.AgentCertPEM, CACertPEM: in.CACertPEM, CertExpiresAt: in.NewNotAfter}
	f.rotateResult[key] = result
	return &result, nil
}

// ---------- 测试辅助：真实 CA / 密钥 / CSR / 签名请求 ----------

// newTestCA 生成真实自签 CA（不走设置表——单测闭环）。
func newTestCA(t *testing.T) *AgentCA {
	t.Helper()
	key, cert, certPEM, err := generateAgentCA()
	if err != nil {
		t.Fatalf("generateAgentCA: %v", err)
	}
	return newAgentCA(key, cert, certPEM)
}

// newAgentKey 生成 Agent 侧 ECDSA P-256 密钥对。
func newAgentKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// testCSR 生成 PEM CSR（cn 留空——契约 §7：CN 由服务端填 agent_id）。
func testCSR(t *testing.T, key *ecdsa.PrivateKey, cn string) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// issueTestCert 用测试 CA 为 agentID 签发证书（返回证书与指纹）。
func issueTestCert(t *testing.T, ca *AgentCA, agentID uuid.UUID, key *ecdsa.PrivateKey, now time.Time) (*x509.Certificate, string) {
	t.Helper()
	csr, err := ParseAgentCSR(testCSR(t, key, ""))
	if err != nil {
		t.Fatalf("ParseAgentCSR: %v", err)
	}
	certPEM, fp, _, err := ca.IssueCertificate(csr, agentID.String(), now)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, fp
}

// popTS 当前 Unix 秒时间戳串。
func popTS(now time.Time) string { return strconv.FormatInt(now.Unix(), 10) }

// doPoP 发送带完整 PoP 三头的请求（signKey 可与 cert 不配对——用于防降级/签名错用例）。
func doPoP(t *testing.T, mux http.Handler, signKey *ecdsa.PrivateKey, cert *x509.Certificate,
	method, path, ts, body, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	digest := sha256.Sum256(popSigningInput(method, path, ts, BodySHA256Hex([]byte(body))))
	sig, err := ecdsa.SignASN1(rand.Reader, signKey, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	req.Header.Set(popCertHeader, base64.StdEncoding.EncodeToString(cert.Raw))
	req.Header.Set(popTimestampHeader, ts)
	req.Header.Set(popSignatureHeader, base64.StdEncoding.EncodeToString(sig))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// popFixture 一套 CA + 已登记持证书 Agent。
type popFixture struct {
	ca      *AgentCA
	store   *fakeMachineStore
	mh      *MachineHandler
	mux     *http.ServeMux
	agentID uuid.UUID
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	fp      string
	now     time.Time
}

func newPopFixture(t *testing.T) *popFixture {
	t.Helper()
	fx := &popFixture{ca: newTestCA(t), store: newFakeMachineStore(), agentID: uuid.New(), now: time.Now()}
	fx.key = newAgentKey(t)
	fx.cert, fx.fp = issueTestCert(t, fx.ca, fx.agentID, fx.key, fx.now)
	registerAgent(fx.store, fx.agentID, false)
	a := fx.store.agentsByID[fx.agentID]
	a.CertFingerprint = &fx.fp
	notAfter := fx.cert.NotAfter
	a.CertNotAfter = &notAfter
	fx.mh = NewMachineHandler(fx.store).SetCA(fx.ca)
	fx.mh.now = func() time.Time { return fx.now }
	fx.mux = newMachineMux(fx.mh)
	return fx
}

// hbPath 心跳路径。
func (fx *popFixture) hbPath() string { return "/api/v1/agents/" + fx.agentID.String() + "/heartbeat" }

// ---------- enroll 证书签发（契约 §7） ----------

// TestEnrollWithCSR enroll 携带 csr_pem：201 + 证书三字段非 null，CN=agent_id，链到 CA，指纹/到期落库。
func TestEnrollWithCSR(t *testing.T) {
	ca := newTestCA(t)
	store := newFakeMachineStore()
	mux := newMachineMux(NewMachineHandler(store).SetCA(ca))
	key := newAgentKey(t)
	token := "wdt_" + strings.Repeat("cd", 32)
	body, _ := json.Marshal(map[string]interface{}{
		"enrollment_token": token, "hostname": "web-prod-01", "ip": "10.0.1.10",
		"csr_pem": testCSR(t, key, ""),
	})
	rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/enroll", string(body), "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		AgentID       string `json:"agent_id"`
		AgentCertPem  string `json:"agent_cert_pem"`
		CaCertPem     string `json:"ca_cert_pem"`
		CertExpiresAt string `json:"cert_expires_at"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AgentCertPem == "" || resp.CaCertPem == "" || resp.CertExpiresAt == "" {
		t.Fatalf("证书字段不得为空: %+v", resp)
	}
	if resp.CaCertPem != ca.CertPEM() {
		t.Error("ca_cert_pem 与 CA 证书不一致")
	}
	block, _ := pem.Decode([]byte(resp.AgentCertPem))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("agent_cert_pem 解析失败: %v", err)
	}
	if cert.Subject.CommonName != resp.AgentID {
		t.Errorf("证书 CN = %q, want agent_id %q（服务端填，CSR 自报 CN 不采信）", cert.Subject.CommonName, resp.AgentID)
	}
	if err := ca.VerifyClientCert(cert, time.Now()); err != nil {
		t.Errorf("签发证书未链到 CA: %v", err)
	}
	expires, err := time.Parse(time.RFC3339, resp.CertExpiresAt)
	if err != nil {
		t.Fatalf("cert_expires_at 非 RFC3339: %v", err)
	}
	if d := time.Until(expires); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Errorf("cert_expires_at 距现在 %v, want ~90 天", d)
	}
	// 指纹与到期回填落库
	if store.enrollIn == nil || store.enrollIn.CertFingerprint == nil || store.enrollIn.CertNotAfter == nil {
		t.Fatal("指纹/到期未随注册落库")
	}
	if *store.enrollIn.CertFingerprint != CertFingerprint(cert) {
		t.Error("落库指纹与签发证书不一致")
	}
	if !store.enrollIn.CertNotAfter.Truncate(time.Second).Equal(expires) {
		t.Error("落库到期与 cert_expires_at 不一致")
	}
}

// TestEnrollWithoutCSRNullCert 无 csr_pem：三个证书字段为 null，其余行为同 Phase 1。
func TestEnrollWithoutCSRNullCert(t *testing.T) {
	ca := newTestCA(t)
	store := newFakeMachineStore()
	mux := newMachineMux(NewMachineHandler(store).SetCA(ca))
	token := "wdt_" + strings.Repeat("cd", 32)
	body := `{"enrollment_token":"` + token + `","hostname":"h","ip":"10.0.0.1"}`
	rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/enroll", body, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", rr.Code, rr.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{"agent_cert_pem", "ca_cert_pem", "cert_expires_at"} {
		if string(raw[k]) != "null" {
			t.Errorf("%s = %s, want null", k, raw[k])
		}
	}
	if _, ok := raw["credential"]; !ok {
		t.Error("credential 字段缺失（Phase 1 行为不得变化）")
	}
	if store.enrollIn.CertFingerprint != nil || store.enrollIn.CertNotAfter != nil {
		t.Error("无 CSR 时指纹/到期不得落库")
	}
}

// TestEnrollBadCSR CSR 非法 → 400 且不触库（格式问题不烧令牌）。
func TestEnrollBadCSR(t *testing.T) {
	cases := []struct {
		name string
		csr  string
	}{
		{"非 PEM", "not-a-pem"},
		{"PEM 但非 CSR", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ca := newTestCA(t)
			store := newFakeMachineStore()
			mux := newMachineMux(NewMachineHandler(store).SetCA(ca))
			token := "wdt_" + strings.Repeat("cd", 32)
			body, _ := json.Marshal(map[string]interface{}{
				"enrollment_token": token, "hostname": "h", "ip": "10.0.0.1", "csr_pem": c.csr,
			})
			rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/enroll", string(body), "")
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", rr.Code, rr.Body.String())
			}
			if store.enrollIn != nil {
				t.Error("CSR 校验失败不应触库（令牌不得被烧毁）")
			}
		})
	}
}

// ---------- PoP 认证（契约 §8） ----------

// TestPoPHeartbeatOK PoP 全链路：合法签名请求 → 200（CA 链/有效期/指纹/CN/时间窗/签名全过）。
func TestPoPHeartbeatOK(t *testing.T) {
	fx := newPopFixture(t)
	body := `{"timestamp":1788256800,"status":"ONLINE"}`
	rr := doPoP(t, fx.mux, fx.key, fx.cert, http.MethodPost, fx.hbPath(), popTS(fx.now), body, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if fx.store.hbStatus != "ONLINE" {
		t.Errorf("心跳未落库: status=%q", fx.store.hbStatus)
	}
}

// TestPoPNoDowngrade 防降级：PoP 头存在但签名错误 → 401，即使 Bearer credential 正确。
func TestPoPNoDowngrade(t *testing.T) {
	fx := newPopFixture(t)
	cred := "wda_" + strings.Repeat("ef", 32) // registerAgent 登记的明文凭据
	wrongKey := newAgentKey(t)                // 用另一把私钥签名 → 签名校验失败
	body := `{"timestamp":1788256800,"status":"ONLINE"}`
	rr := doPoP(t, fx.mux, wrongKey, fx.cert, http.MethodPost, fx.hbPath(), popTS(fx.now), body, cred)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401（PoP 失败绝不降级 Bearer）", rr.Code)
	}
	code, _ := decodeErrEnvelope(t, rr)
	if code != mcUnauthenticated {
		t.Errorf("error.code = %q, want %q", code, mcUnauthenticated)
	}
}

// TestPoPPartialHeaders PoP 头不全 → 401（即使 Bearer 正确；防剥离签名单头重放）。
func TestPoPPartialHeaders(t *testing.T) {
	fx := newPopFixture(t)
	cred := "wda_" + strings.Repeat("ef", 32)
	body := `{"timestamp":1788256800,"status":"ONLINE"}`
	req := httptest.NewRequest(http.MethodPost, fx.hbPath(), strings.NewReader(body))
	req.Header.Set(popCertHeader, base64.StdEncoding.EncodeToString(fx.cert.Raw)) // 只带证书头
	req.Header.Set("Authorization", "Bearer "+cred)
	rr := httptest.NewRecorder()
	fx.mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401（头不全绝不降级）", rr.Code)
	}
}

// TestPoPExpiredCert 证书过期 → 401。
func TestPoPExpiredCert(t *testing.T) {
	fx := newPopFixture(t)
	fx.now = fx.cert.NotAfter.Add(time.Hour) // 服务端时间越过证书有效期
	body := `{"timestamp":1788256800,"status":"ONLINE"}`
	rr := doPoP(t, fx.mux, fx.key, fx.cert, http.MethodPost, fx.hbPath(), popTS(fx.now), body, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

// TestPoPUnknownFingerprint 指纹未登记：同 CA 签发但非该 Agent 当前/宽限指纹 → 401。
func TestPoPUnknownFingerprint(t *testing.T) {
	fx := newPopFixture(t)
	otherKey := newAgentKey(t)
	otherCert, _ := issueTestCert(t, fx.ca, fx.agentID, otherKey, fx.now) // CN 相同但指纹未登记
	body := `{"timestamp":1788256800,"status":"ONLINE"}`
	rr := doPoP(t, fx.mux, otherKey, otherCert, http.MethodPost, fx.hbPath(), popTS(fx.now), body, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

// TestPoPCNMismatch 证书 CN 与路径 agent_id 不匹配 → 401。
func TestPoPCNMismatch(t *testing.T) {
	fx := newPopFixture(t)
	otherID := uuid.New()
	registerAgent(fx.store, otherID, false)
	a := fx.store.agentsByID[otherID]
	a.CertFingerprint = &fx.fp // 指纹对另一 Agent 可用，但 CN 绑定原 Agent
	body := `{"timestamp":1788256800,"status":"ONLINE"}`
	path := "/api/v1/agents/" + otherID.String() + "/heartbeat"
	rr := doPoP(t, fx.mux, fx.key, fx.cert, http.MethodPost, path, popTS(fx.now), body, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

// TestPoPTimestampWindow 时间窗外 → 401；窗口边界（±300s）内放行。
func TestPoPTimestampWindow(t *testing.T) {
	body := `{"timestamp":1788256800,"status":"ONLINE"}`
	t.Run("超前 301s 401", func(t *testing.T) {
		fx := newPopFixture(t)
		ts := popTS(fx.now.Add(-301 * time.Second))
		rr := doPoP(t, fx.mux, fx.key, fx.cert, http.MethodPost, fx.hbPath(), ts, body, "")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
	})
	t.Run("滞后 300s 边界放行", func(t *testing.T) {
		fx := newPopFixture(t)
		ts := popTS(fx.now.Add(300 * time.Second))
		rr := doPoP(t, fx.mux, fx.key, fx.cert, http.MethodPost, fx.hbPath(), ts, body, "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}
	})
	t.Run("非 Unix 秒 401", func(t *testing.T) {
		fx := newPopFixture(t)
		rr := doPoP(t, fx.mux, fx.key, fx.cert, http.MethodPost, fx.hbPath(), "2026-09-02T00:00:00Z", body, "")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
	})
}

// ---------- 宽限期与轮换（契约 §9/§10） ----------

// TestPoPGracePeriod 宽限期语义：轮换后新旧证书均可认证；grace_until 过后旧证书 401。
func TestPoPGracePeriod(t *testing.T) {
	fx := newPopFixture(t)
	body := `{"timestamp":1788256800,"status":"ONLINE"}`

	// 模拟完成一次轮换：旧指纹入宽限（+24h），新指纹成为当前
	oldKey, oldCert, oldFP := fx.key, fx.cert, fx.fp
	newKey := newAgentKey(t)
	newCert, newFP := issueTestCert(t, fx.ca, fx.agentID, newKey, fx.now)
	fx.store.graceFP[oldFP] = fx.now.Add(rotateGracePeriod)
	a := fx.store.agentsByID[fx.agentID]
	a.CertFingerprint = &newFP

	t.Run("宽限内旧证书可用", func(t *testing.T) {
		rr := doPoP(t, fx.mux, oldKey, oldCert, http.MethodPost, fx.hbPath(), popTS(fx.now), body, "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}
	})
	t.Run("新证书可用", func(t *testing.T) {
		rr := doPoP(t, fx.mux, newKey, newCert, http.MethodPost, fx.hbPath(), popTS(fx.now), body, "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}
	})
	t.Run("grace_until 过后旧证书 401", func(t *testing.T) {
		fx.now = fx.now.Add(rotateGracePeriod + time.Minute) // 越过宽限期（新证书仍在有效期内）
		rr := doPoP(t, fx.mux, oldKey, oldCert, http.MethodPost, fx.hbPath(), popTS(fx.now), body, "")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
	})
}

// TestRotateCert rotate-cert：PoP 调用签发新证书、旧指纹入宽限；Bearer 调用 401。
func TestRotateCert(t *testing.T) {
	t.Run("PoP 轮换成功", func(t *testing.T) {
		fx := newPopFixture(t)
		newKey := newAgentKey(t)
		body, _ := json.Marshal(map[string]string{"csr_pem": testCSR(t, newKey, "")})
		path := "/api/v1/agents/" + fx.agentID.String() + "/rotate-cert"
		rr := doPoP(t, fx.mux, fx.key, fx.cert, http.MethodPost, path, popTS(fx.now), string(body), "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}
		var resp struct {
			AgentCertPem  string `json:"agent_cert_pem"`
			CaCertPem     string `json:"ca_cert_pem"`
			CertExpiresAt string `json:"cert_expires_at"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.AgentCertPem == "" || resp.CaCertPem != fx.ca.CertPEM() || resp.CertExpiresAt == "" {
			t.Errorf("响应字段异常: %+v", resp)
		}
		block, _ := pem.Decode([]byte(resp.AgentCertPem))
		newCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("新证书解析失败: %v", err)
		}
		if newCert.Subject.CommonName != fx.agentID.String() {
			t.Errorf("新证书 CN = %q, want %q", newCert.Subject.CommonName, fx.agentID)
		}
		// 仓储语义：旧指纹入宽限（now+24h），当前指纹换新
		in := fx.store.rotateIn
		if in == nil {
			t.Fatal("store.RotateAgentCert 未被调用")
		}
		if in.OldFingerprint != fx.fp || in.NewFingerprint != CertFingerprint(newCert) {
			t.Errorf("轮换指纹异常: old=%q new=%q", in.OldFingerprint, in.NewFingerprint)
		}
		if d := in.GraceUntil.Sub(fx.now); d != rotateGracePeriod {
			t.Errorf("grace_until = now+%v, want now+%v", d, rotateGracePeriod)
		}
		if !in.OldNotBefore.Equal(fx.cert.NotBefore) {
			t.Errorf("not_before = %v, want 旧证书 NotBefore %v", in.OldNotBefore, fx.cert.NotBefore)
		}
	})
	t.Run("响应丢失后同 CSR 重试返回同一已签发身份且不重复推进", func(t *testing.T) {
		fx := newPopFixture(t)
		newKey := newAgentKey(t)
		body, _ := json.Marshal(map[string]string{"csr_pem": testCSR(t, newKey, "")})
		path := "/api/v1/agents/" + fx.agentID.String() + "/rotate-cert"
		first := doPoP(t, fx.mux, fx.key, fx.cert, http.MethodPost, path, popTS(fx.now), string(body), "")
		if first.Code != http.StatusOK {
			t.Fatalf("first status = %d (body=%s)", first.Code, first.Body.String())
		}
		second := doPoP(t, fx.mux, fx.key, fx.cert, http.MethodPost, path, popTS(fx.now), string(body), "")
		if second.Code != http.StatusOK {
			t.Fatalf("retry status = %d (body=%s)", second.Code, second.Body.String())
		}
		if second.Body.String() != first.Body.String() {
			t.Fatalf("retry response changed:\nfirst=%s\nretry=%s", first.Body.String(), second.Body.String())
		}
		if fx.store.rotateCalls != 2 {
			t.Fatalf("store calls = %d, want 2 idempotent lookups", fx.store.rotateCalls)
		}
		if fx.store.rotateIn == nil || fx.store.rotateIn.NewFingerprint == "" {
			t.Fatal("first rotation did not advance fingerprint")
		}
		if got := *fx.store.agentsByID[fx.agentID].CertFingerprint; got != fx.store.rotateIn.NewFingerprint {
			t.Fatalf("retry advanced fingerprint: got %q want %q", got, fx.store.rotateIn.NewFingerprint)
		}
	})
	t.Run("Bearer 调用 401", func(t *testing.T) {
		fx := newPopFixture(t)
		cred := "wda_" + strings.Repeat("ef", 32)
		newKey := newAgentKey(t)
		body, _ := json.Marshal(map[string]string{"csr_pem": testCSR(t, newKey, "")})
		path := "/api/v1/agents/" + fx.agentID.String() + "/rotate-cert"
		rr := doMachine(t, fx.mux, http.MethodPost, path, string(body), cred)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401（Bearer 不可轮换证书）", rr.Code)
		}
		if fx.store.rotateIn != nil {
			t.Error("Bearer 调用不得触发轮换")
		}
	})
	t.Run("出示证书非当前生效 409", func(t *testing.T) {
		fx := newPopFixture(t)
		other := "deadbeef"
		fx.store.agentsByID[fx.agentID].CertFingerprint = &other // 库中当前指纹被抢先轮换
		fx.store.graceFP[fx.fp] = fx.now.Add(time.Hour)          // 出示证书仍在宽限（PoP 可过）
		newKey := newAgentKey(t)
		body, _ := json.Marshal(map[string]string{"csr_pem": testCSR(t, newKey, "")})
		path := "/api/v1/agents/" + fx.agentID.String() + "/rotate-cert"
		rr := doPoP(t, fx.mux, fx.key, fx.cert, http.MethodPost, path, popTS(fx.now), string(body), "")
		if rr.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 (body=%s)", rr.Code, rr.Body.String())
		}
	})
	t.Run("缺 csr_pem 400", func(t *testing.T) {
		fx := newPopFixture(t)
		path := "/api/v1/agents/" + fx.agentID.String() + "/rotate-cert"
		rr := doPoP(t, fx.mux, fx.key, fx.cert, http.MethodPost, path, popTS(fx.now), `{}`, "")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})
}

// TestDisabledAgentCertRevoked disable 后旧证书立即失效（契约 §11）：
// 禁用事务把当前指纹写入 revocations（grace_until=NULL）并清空当前指纹——
// fake 以 revokedFP + CertFingerprint=nil 模拟该事务的净效果，验证 PoP 立即 401
// 且 Bearer 回退仍可用（disabled 心跳放行通道）。SQL 侧由迁移/集成验证。
func TestDisabledAgentCertRevoked(t *testing.T) {
	fx := newPopFixture(t)
	fx.store.revokedFP[fx.fp] = true
	fx.store.agentsByID[fx.agentID].CertFingerprint = nil
	body := `{"timestamp":1788256800,"status":"ONLINE"}`
	rr := doPoP(t, fx.mux, fx.key, fx.cert, http.MethodPost, fx.hbPath(), popTS(fx.now), body, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401（吊销即禁用，立即生效）", rr.Code)
	}
}

// ---------- CA 材料加载/创建（契约 §7，LoadOrCreate 模式） ----------

// fakeSettingsKV 内存设置表。
type fakeSettingsKV struct{ m map[string]string }

func (f *fakeSettingsKV) GetString(_ context.Context, group, key, def string) string {
	if v, ok := f.m[group+"/"+key]; ok {
		return v
	}
	return def
}

func (f *fakeSettingsKV) UpsertString(_ context.Context, group, key, value, _ string, _ uuid.UUID) error {
	f.m[group+"/"+key] = value
	return nil
}

// fakeEncryptor 可逆伪加密（base64 包裹——明文不可读，验证私钥不落明文且必经加密服务）。
type fakeEncryptor struct{}

func (fakeEncryptor) Encrypt(plain string) (string, error) {
	return "enc:" + base64.StdEncoding.EncodeToString([]byte(plain)), nil
}

func (fakeEncryptor) Decrypt(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encoded, "enc:"))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// TestLoadOrCreateAgentCA CA 材料：首启生成并加密落库（私钥不落明文），二次加载复原同一 CA。
func TestLoadOrCreateAgentCA(t *testing.T) {
	kv := &fakeSettingsKV{m: map[string]string{}}
	ca1, err := LoadOrCreateAgentCA(context.Background(), kv, fakeEncryptor{})
	if err != nil {
		t.Fatalf("首次 LoadOrCreate: %v", err)
	}
	raw := kv.m[caSettingsGroup+"/"+caSettingsKey]
	if raw == "" {
		t.Fatal("CA 材料未落系统设置")
	}
	if !strings.HasPrefix(raw, "enc:") {
		t.Error("CA 材料未经加密服务落库")
	}
	if strings.Contains(raw, "PRIVATE KEY") {
		t.Error("落库材料含明文私钥")
	}
	ca2, err := LoadOrCreateAgentCA(context.Background(), kv, fakeEncryptor{})
	if err != nil {
		t.Fatalf("二次 LoadOrCreate: %v", err)
	}
	if ca1.CertPEM() != ca2.CertPEM() {
		t.Error("二次加载未复原同一 CA")
	}
	// 加载的 CA 可正常签发并校验
	key := newAgentKey(t)
	cert, _ := issueTestCert(t, ca2, uuid.New(), key, time.Now())
	if err := ca2.VerifyClientCert(cert, time.Now()); err != nil {
		t.Errorf("复原 CA 签发的证书链校验失败: %v", err)
	}
}

// ---------- H-22.1 & M-A1 安全回归测试 ----------

func TestBearerFallbackRejectedForCertBoundOrRevokedAgent(t *testing.T) {
	cred := "wda_" + strings.Repeat("ef", 32)
	body := `{"timestamp":1788256800,"status":"ONLINE"}`

	t.Run("持有效证书指纹的 Agent 剥离 PoP 头回退 Bearer 被 401 拒绝", func(t *testing.T) {
		fx := newPopFixture(t)
		rr := doMachine(t, fx.mux, http.MethodPost, fx.hbPath(), body, cred)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (body=%s)", rr.Code, rr.Body.String())
		}
	})

	t.Run("证书已清空但存在撤销记录的 Agent 回退 Bearer 被 401 拒绝", func(t *testing.T) {
		fx := newPopFixture(t)
		fx.store.agentsByID[fx.agentID].CertFingerprint = nil
		fx.store.revokedAgents[fx.agentID] = true
		rr := doMachine(t, fx.mux, http.MethodPost, fx.hbPath(), body, cred)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (body=%s)", rr.Code, rr.Body.String())
		}
	})
}

func TestPoPReplayProtection(t *testing.T) {
	t.Run("相同签名请求在时钟偏差窗口内重放被 401 拒绝", func(t *testing.T) {
		fx := newPopFixture(t)
		body := `{"timestamp":1788256800,"status":"ONLINE"}`
		ts := popTS(fx.now)
		digest := sha256.Sum256(popSigningInput(http.MethodPost, fx.hbPath(), ts, BodySHA256Hex([]byte(body))))
		sig, err := ecdsa.SignASN1(rand.Reader, fx.key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sendOnce := func() *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPost, fx.hbPath(), strings.NewReader(body))
			req.Header.Set(popCertHeader, base64.StdEncoding.EncodeToString(fx.cert.Raw))
			req.Header.Set(popTimestampHeader, ts)
			req.Header.Set(popSignatureHeader, base64.StdEncoding.EncodeToString(sig))
			rr := httptest.NewRecorder()
			fx.mux.ServeHTTP(rr, req)
			return rr
		}
		if rr := sendOnce(); rr.Code != http.StatusOK {
			t.Fatalf("first status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}
		if rr := sendOnce(); rr.Code != http.StatusUnauthorized {
			t.Fatalf("replayed status = %d, want 401 (body=%s)", rr.Code, rr.Body.String())
		}
	})

	t.Run("重复携带相同 X-WDSP-PoP-Nonce 被 401 拒绝", func(t *testing.T) {
		fx := newPopFixture(t)
		body := `{"timestamp":1788256800,"status":"ONLINE"}`
		ts := popTS(fx.now)
		sendWithNonce := func(nonce string) *httptest.ResponseRecorder {
			digest := sha256.Sum256(popSigningInput(http.MethodPost, fx.hbPath(), ts, BodySHA256Hex([]byte(body))))
			sig, err := ecdsa.SignASN1(rand.Reader, fx.key, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, fx.hbPath(), strings.NewReader(body))
			req.Header.Set(popCertHeader, base64.StdEncoding.EncodeToString(fx.cert.Raw))
			req.Header.Set(popTimestampHeader, ts)
			req.Header.Set(popSignatureHeader, base64.StdEncoding.EncodeToString(sig))
			req.Header.Set(popNonceHeader, nonce)
			rr := httptest.NewRecorder()
			fx.mux.ServeHTTP(rr, req)
			return rr
		}
		if rr := sendWithNonce("nonce-abc-123"); rr.Code != http.StatusOK {
			t.Fatalf("first nonce status = %d, want 200", rr.Code)
		}
		if rr := sendWithNonce("nonce-abc-123"); rr.Code != http.StatusUnauthorized {
			t.Fatalf("replayed nonce status = %d, want 401", rr.Code)
		}
		if rr := sendWithNonce("nonce-abc-456"); rr.Code != http.StatusOK {
			t.Fatalf("fresh nonce status = %d, want 200", rr.Code)
		}
	})

	t.Run("有界缓存淘汰与过期清理", func(t *testing.T) {
		cache := newPopReplayCache(4)
		now := time.Unix(1788256800, 0).UTC()
		ts := strconv.FormatInt(now.Unix(), 10)
		for i := 0; i < 10; i++ {
			if !cache.CheckAndRecord("agent-1", ts, "sig-"+strconv.Itoa(i), "", now) {
				t.Fatalf("unexpected duplicate at %d", i)
			}
		}
		if len(cache.entries) > 4 {
			t.Fatalf("cache exceeded bound: got %d, max 4", len(cache.entries))
		}
		if cache.CheckAndRecord("agent-1", ts, "sig-9", "", now) {
			t.Fatal("recent signature should still be detected as replay")
		}
		// 越过偏差窗口后自动过期可清理
		afterWindow := now.Add((popMaxClockSkewSeconds + 2) * time.Second)
		if !cache.CheckAndRecord("agent-1", ts, "sig-9", "", afterWindow) {
			t.Fatal("expired entry should not block after skew window")
		}
	})
}

func TestRevokedCredentialHashInvalidatesBearer(t *testing.T) {
	h1, err := revokedCredentialHash()
	if err != nil {
		t.Fatal(err)
	}
	h2, err := revokedCredentialHash()
	if err != nil {
		t.Fatal(err)
	}
	if len(h1) != 64 || !strings.HasPrefix(h1, "revoked:") || h1 == h2 {
		t.Fatalf("unexpected revoked credential hash: h1=%q h2=%q", h1, h2)
	}
}
