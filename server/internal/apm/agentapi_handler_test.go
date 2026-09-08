// agentapi_handler_test.go Agent 面机器接口单元测试（真实 CA + fake 仓储；
// 覆盖注册令牌生命周期（用即作废/过期/重放拒绝/语言约束）、PoP 认证各失败分支、
// 心跳、策略拉取、证书轮换后旧证失效）。
package apm

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// agentTestRig 装配：fake 仓储 + 真实 CA + Agent 面 mux。
type agentTestRig struct {
	repo *fakeAgentRepo
	ca   *AgentCA
	mux  *http.ServeMux
}

func newAgentTestRig(t *testing.T) *agentTestRig {
	t.Helper()
	repo := newFakeAgentRepo()
	ca, _ := newTestCA(t)
	cfg := NewAgentControlConfig("127.0.0.1:4317", 72, 10)
	h := NewAgentAPIHandler(repo, ca, cfg)
	mux := http.NewServeMux()
	RegisterAgentDataRoutes(mux, h)
	return &agentTestRig{repo: repo, ca: ca, mux: mux}
}

// seedToken 直接向 fake 仓储种一枚未用令牌。
func (r *agentTestRig) seedToken(plain string, appID *uuid.UUID, langs []string, ttl time.Duration) {
	now := time.Now().UTC()
	r.repo.tokens[HashEnrollmentToken(plain)] = &EnrollmentTokenRow{
		ID: uuid.New(), ApplicationID: appID, Environment: "prod",
		AllowedLanguages: langs, ExpiresAt: now.Add(ttl),
	}
}

// enroll 完成一次注册（返回 agent_id、客户端证书与私钥）。
func (r *agentTestRig) enroll(t *testing.T, plain string) (uuid.UUID, *x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	priv, csrPEM := newEd25519CSR(t, "shop-svc")
	body := fmt.Sprintf(`{"token":%q,"csr":%q,"service_name":"shop-svc","instance_id":"host-1","language":"java","agent_version":"1.0.0","node_info":{"hostname":"host-1"}}`,
		plain, csrPEM)
	rr := doJSON(t, r.mux, "POST", "/api/v1/apm/agent/register", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("register status = %d, body: %s", rr.Code, rr.Body.String())
	}
	data := dataOf(t, rr)
	agentID, err := uuid.Parse(data["agent_id"].(string))
	if err != nil {
		t.Fatalf("agent_id parse: %v", err)
	}
	cert := mustParseCert(t, data["client_cert"].(string))
	return agentID, cert, priv
}

// popHeaders 构造 PoP 认证头。
func popHeaders(t *testing.T, cert *x509.Certificate, priv ed25519.PrivateKey, method, path string, body []byte) map[string]string {
	t.Helper()
	ts := time.Now().UTC().Format(time.RFC3339)
	return map[string]string{
		"X-JiuZhang-Agent-Cert":      base64.StdEncoding.EncodeToString(cert.Raw),
		"X-JiuZhang-Agent-Timestamp": ts,
		"X-JiuZhang-Agent-Signature": popSign(t, priv, method, path, ts, body),
	}
}

// doAgentReq 带 PoP 头的机器请求。
func doAgentReq(t *testing.T, mux http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func TestAgentRegister(t *testing.T) {
	rig := newAgentTestRig(t)
	appID := uuid.New()
	rig.seedToken("jzapm_testtoken-1", &appID, []string{"java"}, time.Hour)

	_, cert, _ := rig.enroll(t, "jzapm_testtoken-1")
	if err := cert.CheckSignatureFrom(rig.ca.cert); err != nil {
		t.Errorf("client cert not CA-signed: %v", err)
	}
	// 登记行：归属取自令牌（应用/环境），非请求体自报
	var registered *AgentRow
	for _, a := range rig.repo.agents {
		registered = a
	}
	if registered == nil || registered.StoredStatus != AgentStatusConnectedBaseline {
		t.Fatalf("registered agent = %+v", registered)
	}
	svc := rig.repo.services["shop-svc|prod"]
	if svc == nil || svc.ApplicationID == nil || *svc.ApplicationID != appID || svc.ClaimStatus != "CLAIMED" {
		t.Errorf("service claim = %+v", svc)
	}
	// 令牌用后即作废（重放拒绝）
	priv, csrPEM := newEd25519CSR(t, "svc")
	rr := doJSON(t, rig.mux, "POST", "/api/v1/apm/agent/register",
		fmt.Sprintf(`{"token":"jzapm_testtoken-1","csr":%q,"service_name":"shop-svc","instance_id":"host-2","language":"java"}`, csrPEM))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("replayed token status = %d, want 401", rr.Code)
	}
	_ = priv

	// 过期令牌 → 401（统一口径）
	rig.seedToken("jzapm_expired", nil, nil, -time.Minute)
	rr = doJSON(t, rig.mux, "POST", "/api/v1/apm/agent/register",
		fmt.Sprintf(`{"token":"jzapm_expired","csr":%q,"service_name":"a","instance_id":"b","language":"go"}`, csrPEM))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expired token status = %d, want 401", rr.Code)
	}
	// 语言不在令牌白名单 → 400（且先于令牌消费校验：令牌不被烧毁）
	rig.seedToken("jzapm_langrestrict", nil, []string{"java"}, time.Hour)
	rr = doJSON(t, rig.mux, "POST", "/api/v1/apm/agent/register",
		fmt.Sprintf(`{"token":"jzapm_langrestrict","csr":%q,"service_name":"a","instance_id":"b","language":"go"}`, csrPEM))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("disallowed language status = %d", rr.Code)
	}
	if rig.repo.tokens[HashEnrollmentToken("jzapm_langrestrict")].UsedAt != nil {
		t.Error("token must not be consumed on language rejection")
	}
	// 坏 CSR → 400（且 CSR 先于令牌消费校验：令牌不被烧毁）
	rig.seedToken("jzapm_badcsr", nil, nil, time.Hour)
	rr = doJSON(t, rig.mux, "POST", "/api/v1/apm/agent/register",
		`{"token":"jzapm_badcsr","csr":"garbage","service_name":"a","instance_id":"b","language":"go"}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad csr status = %d", rr.Code)
	}
	if rig.repo.tokens[HashEnrollmentToken("jzapm_badcsr")].UsedAt != nil {
		t.Error("token must not be consumed on CSR validation failure")
	}
	// 非法 service_name（注入字符）→ 400
	rig.seedToken("jzapm_badname", nil, nil, time.Hour)
	rr = doJSON(t, rig.mux, "POST", "/api/v1/apm/agent/register",
		fmt.Sprintf(`{"token":"jzapm_badname","csr":%q,"service_name":"a b\"; DROP","instance_id":"b","language":"go"}`, csrPEM))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad service_name status = %d", rr.Code)
	}
	// node_info 非白名单键 → 400
	rig.seedToken("jzapm_badnode", nil, nil, time.Hour)
	rr = doJSON(t, rig.mux, "POST", "/api/v1/apm/agent/register",
		fmt.Sprintf(`{"token":"jzapm_badnode","csr":%q,"service_name":"a","instance_id":"b","language":"go","node_info":{"cmdline":"x"}}`, csrPEM))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad node_info status = %d", rr.Code)
	}
}

func TestAgentRegister_ClaimConflict(t *testing.T) {
	rig := newAgentTestRig(t)
	appA, appB := uuid.New(), uuid.New()
	rig.seedToken("jzapm_a", &appA, nil, time.Hour)
	rig.enroll(t, "jzapm_a")
	// 同名同环境服务被应用 B 的令牌注册 → 409 认领冲突（且令牌不被烧毁：
	// 冲突属事务内失败，整体回滚——BUG-01）
	rig.seedToken("jzapm_b", &appB, nil, time.Hour)
	_, csrPEM := newEd25519CSR(t, "shop-svc")
	rr := doJSON(t, rig.mux, "POST", "/api/v1/apm/agent/register",
		fmt.Sprintf(`{"token":"jzapm_b","csr":%q,"service_name":"shop-svc","instance_id":"host-9","language":"go"}`, csrPEM))
	if rr.Code != http.StatusConflict {
		t.Errorf("claim conflict status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if rig.repo.tokens[HashEnrollmentToken("jzapm_b")].UsedAt != nil {
		t.Error("token must not be consumed on claim conflict")
	}
	if len(rig.repo.agents) != 1 {
		t.Errorf("agents = %d, want 1 (conflict must not register)", len(rig.repo.agents))
	}
}

func TestAgentRegister_Supersede(t *testing.T) {
	rig := newAgentTestRig(t)
	rig.seedToken("jzapm_s1", nil, nil, time.Hour)
	firstID, firstCert, _ := rig.enroll(t, "jzapm_s1")
	// 同服务同实例重新注册：旧 Agent 顶替为 REVOKED、旧证书指纹入撤销列表
	rig.seedToken("jzapm_s2", nil, nil, time.Hour)
	secondID, _, _ := rig.enroll(t, "jzapm_s2")
	if secondID == firstID {
		t.Error("re-enrollment must create a new agent row")
	}
	if rig.repo.agents[firstID].StoredStatus != AgentStatusRevoked {
		t.Error("superseded agent not revoked")
	}
	if !rig.repo.revokedFPs[CertFingerprint(firstCert)] {
		t.Error("superseded cert fingerprint not revoked")
	}
}

// TestAgentRegister_CAFailure CA 签发失败 → 500 且零状态变更（签发为事务外纯计算，
// 令牌/服务/Agent 均不受影响——BUG-01）。
func TestAgentRegister_CAFailure(t *testing.T) {
	rig := newAgentTestRig(t)
	rig.seedToken("jzapm_cafail", nil, nil, time.Hour)
	// 私钥与 CA 证书不匹配的损坏 CA（同包构造）：CreateCertificate 签发必失败
	_, mismatchedKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	brokenCA := &AgentCA{key: mismatchedKey, cert: rig.ca.cert, certPEM: rig.ca.certPEM}
	cfg := NewAgentControlConfig("127.0.0.1:4317", 72, 10)
	h := NewAgentAPIHandler(rig.repo, brokenCA, cfg)
	mux := http.NewServeMux()
	RegisterAgentDataRoutes(mux, h)
	_, csrPEM := newEd25519CSR(t, "svc")
	rr := doJSON(t, mux, "POST", "/api/v1/apm/agent/register",
		fmt.Sprintf(`{"token":"jzapm_cafail","csr":%q,"service_name":"a","instance_id":"b","language":"go"}`, csrPEM))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("ca failure status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if rig.repo.tokens[HashEnrollmentToken("jzapm_cafail")].UsedAt != nil {
		t.Error("token must not be consumed on CA failure")
	}
	if len(rig.repo.agents) != 0 {
		t.Errorf("agents = %d, want 0", len(rig.repo.agents))
	}
}

// TestAgentRegister_InsertFailure 登记步骤失败 → 500 且整体回滚：令牌未消费、
// 存量健康 Agent 未被顶替（健康实例不被误下线——BUG-01 核心回归）；
// 回滚后同一令牌可重试成功（失败路径不烧毁令牌）。
func TestAgentRegister_InsertFailure(t *testing.T) {
	rig := newAgentTestRig(t)
	rig.seedToken("jzapm_ok", nil, nil, time.Hour)
	oldID, oldCert, _ := rig.enroll(t, "jzapm_ok")
	rig.repo.insertErr = errors.New("insert boom")
	rig.seedToken("jzapm_retry", nil, nil, time.Hour)
	_, csrPEM := newEd25519CSR(t, "shop-svc")
	rr := doJSON(t, rig.mux, "POST", "/api/v1/apm/agent/register",
		fmt.Sprintf(`{"token":"jzapm_retry","csr":%q,"service_name":"shop-svc","instance_id":"host-1","language":"go"}`, csrPEM))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("insert failure status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if rig.repo.tokens[HashEnrollmentToken("jzapm_retry")].UsedAt != nil {
		t.Error("token must not be consumed on insert failure")
	}
	if rig.repo.agents[oldID].StoredStatus != AgentStatusConnectedBaseline {
		t.Error("healthy agent must not be superseded when enrollment rolls back")
	}
	if rig.repo.revokedFPs[CertFingerprint(oldCert)] {
		t.Error("healthy agent cert must not be revoked when enrollment rolls back")
	}
	if len(rig.repo.agents) != 1 {
		t.Errorf("agents = %d, want 1", len(rig.repo.agents))
	}
	// 回滚后同一令牌重试成功：旧 Agent 才被顶替
	rig.repo.insertErr = nil
	rr = doJSON(t, rig.mux, "POST", "/api/v1/apm/agent/register",
		fmt.Sprintf(`{"token":"jzapm_retry","csr":%q,"service_name":"shop-svc","instance_id":"host-1","language":"go"}`, csrPEM))
	if rr.Code != http.StatusOK {
		t.Fatalf("retry after rollback status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if rig.repo.agents[oldID].StoredStatus != AgentStatusRevoked {
		t.Error("old agent should be superseded after successful retry")
	}
	if len(rig.repo.agents) != 2 {
		t.Errorf("agents = %d, want 2", len(rig.repo.agents))
	}
}

// TestAgentRegister_PolicyFailure 策略解析失败 → 500 且令牌不消费、Agent 不登记
// （策略读取/惰性创建在事务内，失败整体回滚——BUG-01）。
func TestAgentRegister_PolicyFailure(t *testing.T) {
	rig := newAgentTestRig(t)
	rig.seedToken("jzapm_polfail", nil, nil, time.Hour)
	rig.repo.policyErr = errors.New("policy boom")
	_, csrPEM := newEd25519CSR(t, "svc")
	rr := doJSON(t, rig.mux, "POST", "/api/v1/apm/agent/register",
		fmt.Sprintf(`{"token":"jzapm_polfail","csr":%q,"service_name":"a","instance_id":"b","language":"go"}`, csrPEM))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("policy failure status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if rig.repo.tokens[HashEnrollmentToken("jzapm_polfail")].UsedAt != nil {
		t.Error("token must not be consumed on policy failure")
	}
	if len(rig.repo.agents) != 0 {
		t.Errorf("agents = %d, want 0", len(rig.repo.agents))
	}
}

// TestAgentRegister_Concurrent 并发注册（BUG-01）：
// 同一令牌并发复用 → 恰好一次成功、其余 401（FOR UPDATE 串行化防双花）；
// 不同令牌并发 → 全部成功，每枚令牌对应一个登记行，无中间态泄漏。
func TestAgentRegister_Concurrent(t *testing.T) {
	rig := newAgentTestRig(t)
	rig.seedToken("jzapm_race", nil, nil, time.Hour)
	_, csrPEM := newEd25519CSR(t, "svc")
	body := fmt.Sprintf(`{"token":"jzapm_race","csr":%q,"service_name":"race-svc","instance_id":"h","language":"go"}`, csrPEM)
	const n = 8
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = doJSON(t, rig.mux, "POST", "/api/v1/apm/agent/register", body).Code
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		} else if c != http.StatusUnauthorized {
			t.Errorf("unexpected status %d", c)
		}
	}
	if ok != 1 {
		t.Errorf("concurrent same-token enrollments succeeded %d times, want exactly 1", ok)
	}
	if len(rig.repo.agents) != 1 {
		t.Errorf("agents = %d, want 1", len(rig.repo.agents))
	}
	if rig.repo.tokens[HashEnrollmentToken("jzapm_race")].UsedAt == nil {
		t.Error("token must be consumed exactly once")
	}

	// 多令牌并发（同服务不同实例）→ 全部成功
	const m = 8
	bodies := make([]string, m)
	for i := 0; i < m; i++ {
		rig.seedToken(fmt.Sprintf("jzapm_par_%d", i), nil, nil, time.Hour)
		_, csr := newEd25519CSR(t, "race-svc")
		bodies[i] = fmt.Sprintf(`{"token":"jzapm_par_%d","csr":%q,"service_name":"race-svc","instance_id":"h-%d","language":"go"}`, i, csr, i)
	}
	codes = make([]int, m)
	for i := 0; i < m; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = doJSON(t, rig.mux, "POST", "/api/v1/apm/agent/register", bodies[i]).Code
		}(i)
	}
	wg.Wait()
	for i, c := range codes {
		if c != http.StatusOK {
			t.Errorf("parallel enrollment %d status = %d", i, c)
		}
	}
	if len(rig.repo.agents) != 1+m {
		t.Errorf("agents = %d, want %d", len(rig.repo.agents), 1+m)
	}
}

func TestAgentHeartbeat(t *testing.T) {
	rig := newAgentTestRig(t)
	rig.seedToken("jzapm_hb", nil, nil, time.Hour)
	agentID, cert, priv := rig.enroll(t, "jzapm_hb")

	// 正常心跳（空体也合法）
	body := `{"agent_version":"1.0.1"}`
	rr := doAgentReq(t, rig.mux, "POST", "/api/v1/apm/agent/heartbeat", body,
		popHeaders(t, cert, priv, "POST", "/api/v1/apm/agent/heartbeat", []byte(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d, body: %s", rr.Code, rr.Body.String())
	}
	data := dataOf(t, rr)
	if data["status"] != "ok" || data["policy_version"] == nil {
		t.Errorf("heartbeat response = %v", data)
	}
	if rig.repo.agents[agentID].LastHeartbeatAt == nil {
		t.Error("last_heartbeat_at not updated")
	}

	// 无认证头 → 401
	if rr := doAgentReq(t, rig.mux, "POST", "/api/v1/apm/agent/heartbeat", body, nil); rr.Code != http.StatusUnauthorized {
		t.Errorf("no-auth status = %d", rr.Code)
	}
	// 篡改正文（签名不覆盖新正文）→ 401
	headers := popHeaders(t, cert, priv, "POST", "/api/v1/apm/agent/heartbeat", []byte(body))
	if rr := doAgentReq(t, rig.mux, "POST", "/api/v1/apm/agent/heartbeat", `{"agent_version":"9.9.9"}`, headers); rr.Code != http.StatusUnauthorized {
		t.Errorf("tampered body status = %d", rr.Code)
	}
	// 时间戳超窗 → 401
	stale := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
	headers = map[string]string{
		"X-JiuZhang-Agent-Cert":      base64.StdEncoding.EncodeToString(cert.Raw),
		"X-JiuZhang-Agent-Timestamp": stale,
		"X-JiuZhang-Agent-Signature": popSign(t, priv, "POST", "/api/v1/apm/agent/heartbeat", stale, []byte(body)),
	}
	if rr := doAgentReq(t, rig.mux, "POST", "/api/v1/apm/agent/heartbeat", body, headers); rr.Code != http.StatusUnauthorized {
		t.Errorf("stale timestamp status = %d", rr.Code)
	}
	// 撤销后 → 403
	rig.repo.agents[agentID].StoredStatus = AgentStatusRevoked
	rr = doAgentReq(t, rig.mux, "POST", "/api/v1/apm/agent/heartbeat", body,
		popHeaders(t, cert, priv, "POST", "/api/v1/apm/agent/heartbeat", []byte(body)))
	if rr.Code != http.StatusForbidden {
		t.Errorf("revoked agent heartbeat status = %d", rr.Code)
	}
}

func TestAgentHeartbeat_ExpiredCert(t *testing.T) {
	rig := newAgentTestRig(t)
	rig.seedToken("jzapm_exp", nil, nil, time.Hour)
	agentID, cert, priv := rig.enroll(t, "jzapm_exp")
	// 登记行证书到期（证书本体未过期，登记口径已过期 → 401）
	rig.repo.agents[agentID].CertNotAfter = time.Now().Add(-time.Hour)
	body := `{}`
	if rr := doAgentReq(t, rig.mux, "POST", "/api/v1/apm/agent/heartbeat", body,
		popHeaders(t, cert, priv, "POST", "/api/v1/apm/agent/heartbeat", []byte(body))); rr.Code != http.StatusUnauthorized {
		t.Errorf("expired cert heartbeat status = %d", rr.Code)
	}
	// 指纹入撤销列表（如轮换后旧证）→ 403
	rig.repo.agents[agentID].CertNotAfter = time.Now().Add(time.Hour)
	rig.repo.revokedFPs[CertFingerprint(cert)] = true
	if rr := doAgentReq(t, rig.mux, "POST", "/api/v1/apm/agent/heartbeat", body,
		popHeaders(t, cert, priv, "POST", "/api/v1/apm/agent/heartbeat", []byte(body))); rr.Code != http.StatusForbidden {
		t.Errorf("revoked fingerprint heartbeat status = %d", rr.Code)
	}
}

func TestAgentPullPolicy(t *testing.T) {
	rig := newAgentTestRig(t)
	appID := uuid.New()
	rig.seedToken("jzapm_pp", &appID, nil, time.Hour)
	_, cert, priv := rig.enroll(t, "jzapm_pp")

	// 注册响应已携带签名基线策略（全局 v1 惰性创建）；拉取同版本
	rr := doAgentReq(t, rig.mux, "GET", "/api/v1/apm/agent/policy", "",
		popHeaders(t, cert, priv, "GET", "/api/v1/apm/agent/policy", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("pull policy status = %d, body: %s", rr.Code, rr.Body.String())
	}
	env := dataOf(t, rr)
	if env["scope"] != PolicyScopeGlobal || env["version"] != float64(1) {
		t.Errorf("policy = %v/%v", env["scope"], env["version"])
	}
	// 应用级策略发布后优先于全局
	rig.repo.CreatePolicyVersion(t.Context(), ApplicationPolicyScope(appID),
		map[string]interface{}{"sampling_rate": 0.5}, "sig", PolicySignKeyID,
		time.Now(), time.Now().Add(time.Hour), nil, nil)
	rr = doAgentReq(t, rig.mux, "GET", "/api/v1/apm/agent/policy", "",
		popHeaders(t, cert, priv, "GET", "/api/v1/apm/agent/policy", nil))
	if dataOf(t, rr)["scope"] != ApplicationPolicyScope(appID) {
		t.Errorf("application scope not preferred: %v", dataOf(t, rr)["scope"])
	}
	// 无 PoP → 401
	if rr := doAgentReq(t, rig.mux, "GET", "/api/v1/apm/agent/policy", "", nil); rr.Code != http.StatusUnauthorized {
		t.Errorf("no-auth policy pull status = %d", rr.Code)
	}
}

func TestAgentRotateCert(t *testing.T) {
	rig := newAgentTestRig(t)
	rig.seedToken("jzapm_rot", nil, nil, time.Hour)
	agentID, oldCert, oldPriv := rig.enroll(t, "jzapm_rot")

	newPriv, newCSR := newEd25519CSR(t, "shop-svc")
	body := fmt.Sprintf(`{"csr":%q}`, newCSR)
	rr := doAgentReq(t, rig.mux, "POST", "/api/v1/apm/agent/rotate-cert", body,
		popHeaders(t, oldCert, oldPriv, "POST", "/api/v1/apm/agent/rotate-cert", []byte(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("rotate status = %d, body: %s", rr.Code, rr.Body.String())
	}
	newCert := mustParseCert(t, dataOf(t, rr)["client_cert"].(string))
	newFP := CertFingerprint(newCert)
	if rig.repo.agents[agentID].CertFingerprint != newFP {
		t.Error("agent fingerprint not rotated")
	}
	if !rig.repo.revokedFPs[CertFingerprint(oldCert)] {
		t.Error("old fingerprint not revoked")
	}
	// 旧证书立即失效（403 指纹撤销）
	hb := `{}`
	if rr := doAgentReq(t, rig.mux, "POST", "/api/v1/apm/agent/heartbeat", hb,
		popHeaders(t, oldCert, oldPriv, "POST", "/api/v1/apm/agent/heartbeat", []byte(hb))); rr.Code != http.StatusUnauthorized {
		// 旧指纹已不在登记映射（fake 语义）→ 401；真实库为当前指纹不匹配 → 同样拒绝
		t.Errorf("old cert heartbeat status = %d", rr.Code)
	}
	// 新证书可用
	if rr := doAgentReq(t, rig.mux, "POST", "/api/v1/apm/agent/heartbeat", hb,
		popHeaders(t, newCert, newPriv, "POST", "/api/v1/apm/agent/heartbeat", []byte(hb))); rr.Code != http.StatusOK {
		t.Errorf("new cert heartbeat status = %d", rr.Code)
	}
}
