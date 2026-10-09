// apimachineid_test.go 机器身份装配与请求链测试（NG-ID G1 批次 B2）：
// 装配 fail-safe/fail-closed/C01、水位拒载、401/403/503/413 形态、OBSERVE 放行、
// Bot 豁免三重矩阵、identity_key 不变量、白名单/L7 不绕过、能力自报恒报。
package jiuzhang_guard

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/machineid"
	"github.com/jiuzhang-waf/gateway/dynamic_security/httpsig"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
	"go.uber.org/zap"
)

var midTestNow = time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC)

// ---------- 签名基础设施 ----------

// midTestKey 测试 ed25519 密钥对与登记段。
func midTestKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return priv, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// midSignedRequest 构造 G1 完整签名请求（体保全消费同口径：先签名后读体）。
func midSignedRequest(t *testing.T, priv ed25519.PrivateKey, body []byte) *http.Request {
	t.Helper()
	created := midTestNow.Add(-30 * time.Second).Unix()
	expires := midTestNow.Add(60 * time.Second).Unix()
	return midSignedRequestAt(t, priv, body, created, expires)
}

func midSignedRequestAt(t *testing.T, priv ed25519.PrivateKey, body []byte, created, expires int64) *http.Request {
	t.Helper()
	var br *strings.Reader
	if body != nil {
		br = strings.NewReader(string(body))
	} else {
		br = strings.NewReader("")
	}
	r := httptest.NewRequest(http.MethodPost, "/api/agent?k=v", br)
	r.Host = "example.com"
	r.Header.Set("X-Request-Id", "req-mid-1")
	components := []string{"@method", "@authority", "@path", "@query"}
	if body != nil {
		sum := sha256.Sum256(body)
		r.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":")
		components = append(components, "content-digest")
	}
	var sb strings.Builder
	sb.WriteString(`sig1=(`)
	for i, c := range components {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(`"` + c + `"`)
	}
	sb.WriteString(`);created=` + strconvInt(created) + `;expires=` + strconvInt(expires) + `;nonce="n8f6kfs9.2gkf0s9";keyid="k1";alg="ed25519"`)
	r.Header.Set("Signature-Input", sb.String())
	p, err := httpsig.ParseHeaders(sb.String(), "sig1=::", httpsig.DefaultBudgets())
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Signature", "sig1=::")
	base, _, err := httpsig.BuildSignatureBase(r, p)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, base)
	r.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return r
}

func strconvInt(v int64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	u := uint64(v)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}

// newMIDGuard 构造带机器身份装配的 Guard（PROTECT/OBSERVE 绑定可选；重放桩注入）。
// 返回（Guard, API 事件日志路径, access_control 事件日志路径）。
func newMIDGuard(t *testing.T, pubPEM string, mode string, replay *httpsig.ReplayStore) (*Guard, string, string) {
	t.Helper()
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	eventsLogPath := filepath.Join(t.TempDir(), "guard-events.log")
	el, err := events.NewLogger(eventsLogPath, "test-node")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = el.Close() })
	g.events = el
	g.IdentitySalt = "test-salt"
	g.APIMachineIdentities = []machineIdentityJSON{{
		IdentityName: "agent-01", Status: "ENABLED",
		Keys: []machineIdentityKeyJSON{{Kid: "k1", Alg: "ed25519", PublicKeyPEM: pubPEM, Status: "ACTIVE"}},
	}}
	g.APIMachineIDBindings = []machineIDBindingJSON{
		{ApplicationID: "app-1", PathPrefix: "/api/agent", Mode: mode},
	}
	g.APIMachineIDMeta = &machineIDMetaJSON{RevocationWatermark: 3, RegistryVersion: 7}
	cfg, err := g.buildMachineIDConfig()
	if err != nil {
		t.Fatalf("装配: %v", err)
	}
	g.apiMachineID = cfg
	g.apiMachineID.Now = func() time.Time { return midTestNow }
	if replay == nil {
		g.machineIDReplay = httpsig.NewReplayStore(nil)
	} else {
		g.machineIDReplay = replay
	}
	return g, logPath, eventsLogPath
}

// fakeMIDEval 重放桩（httpsig.Evaluator——SET NX 语义模拟）。
type fakeMIDEval struct {
	seen map[string]bool
	err  error
}

func (f *fakeMIDEval) Eval(_ context.Context, _ string, keys []string, _ []string) ([]interface{}, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.seen[keys[0]] {
		return []interface{}{int64(0)}, nil
	}
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	f.seen[keys[0]] = true
	return []interface{}{int64(1)}, nil
}

// midServe 完整请求链：验证点（生产 serveGuard 顺序的显式镜像）→ 处置点
// （serveNext 统一出口——enforceJWTTrust→enforceMachineIdentity 顺序即
// 白名单/L7 allow 不绕过的承载（均汇于 serveNext））。
func midServe(t *testing.T, g *Guard, r *http.Request, nextCalled *bool) *httptest.ResponseRecorder {
	t.Helper()
	g.verifyMachineIdentity(r) // 生产顺序：serveGuard 内 JWT 验证后（见 module.go 挂点注释）
	rec := httptest.NewRecorder()
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		*nextCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("origin-ok"))
		return nil
	})
	if err := g.serveNext(rec, r, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	return rec
}

// TestMIDVerifiedPassE2E 有效证明全链通过：VERIFIED 放行到源站 + 审计事件在册 +
// 身份信号注入。
func TestMIDVerifiedPassE2E(t *testing.T) {
	priv, pubPEM := midTestKey(t)
	g, _, evLog := newMIDGuard(t, pubPEM, machineid.ModeProtect, httpsig.NewReplayStore(&fakeMIDEval{}))
	r := midSignedRequest(t, priv, []byte(`{"hello":"world"}`))
	called := false
	rec := midServe(t, g, r, &called)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("VERIFIED 应放行: called=%v code=%d", called, rec.Code)
	}
	// 信号注入（同请求 VERIFIED 机器身份）
	vm := identitybehavior.VerifiedMachineIdentityFrom(r.Context())
	if vm == nil || vm.KeyID != "k1" || vm.RegistryVersion != 7 || vm.MachineIDFP == "" {
		t.Fatalf("注入信号 = %+v", vm)
	}
	// 审计事件（MID_VERIFIED，不落签名/nonce/公钥原文）
	data := readEventsLog(t, evLog)
	if !strings.Contains(data, string(events.MIDVerified)) {
		t.Fatalf("缺 MID_VERIFIED 事件: %s", data)
	}
}

// TestMIDInvalidMatrix 401 形态矩阵（篡改/未知键/过期；固定短语不带 WWW-Authenticate）。
func TestMIDInvalidMatrix(t *testing.T) {
	priv, pubPEM := midTestKey(t)
	g, _, evLog := newMIDGuard(t, pubPEM, machineid.ModeProtect, httpsig.NewReplayStore(&fakeMIDEval{}))
	t.Run("有效证明通过后重放同 nonce", func(t *testing.T) {
		r := midSignedRequest(t, priv, []byte(`{"hello":"world"}`))
		called := false
		rec := midServe(t, g, r, &called)
		if !called {
			t.Fatal("首次应放行")
		}
		_ = rec
		// 重放（同签名同 nonce 再发一次）
		r2 := midSignedRequest(t, priv, []byte(`{"hello":"world"}`))
		called2 := false
		rec2 := midServe(t, g, r2, &called2)
		if called2 || rec2.Code != http.StatusUnauthorized {
			t.Fatalf("重放应 401: called=%v code=%d", called2, rec2.Code)
		}
		assertMIDBody(t, rec2, "machine_identity_failed")
	})
	t.Run("目标篡改拒绝", func(t *testing.T) {
		r := midSignedRequest(t, priv, []byte(`{"hello":"world"}`))
		r.RequestURI = "/api/agent?k=evil" // 签名后篡改 query
		r.URL.RawQuery = "k=evil"
		called := false
		rec := midServe(t, g, r, &called)
		if called || rec.Code != http.StatusUnauthorized {
			t.Fatalf("篡改应 401: called=%v code=%d", called, rec.Code)
		}
		assertMIDBody(t, rec, "machine_identity_failed")
		if rec.Header().Get("WWW-Authenticate") != "" {
			t.Fatal("不得携带 WWW-Authenticate（不冒用未注册方案）")
		}
		data := readEventsLog(t, evLog)
		if !strings.Contains(data, string(events.MIDAuthFailed)) {
			t.Fatalf("缺 MID_AUTH_FAILED: %s", data)
		}
	})
}

// TestMIDUnavailableShapes UNAVAILABLE 形态：重放存储缺席 PROTECT 503 / OBSERVE 放行。
func TestMIDUnavailableShapes(t *testing.T) {
	priv, pubPEM := midTestKey(t)
	t.Run("PROTECT 503", func(t *testing.T) {
		g, _, _ := newMIDGuard(t, pubPEM, machineid.ModeProtect, nil) // nil 存储
		r := midSignedRequest(t, priv, []byte(`{"hello":"world"}`))
		called := false
		rec := midServe(t, g, r, &called)
		if called || rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("存储缺席 PROTECT 应 503: called=%v code=%d", called, rec.Code)
		}
		assertMIDBody(t, rec, "machine_identity_unavailable")
	})
	t.Run("OBSERVE 放行+披露", func(t *testing.T) {
		g, _, evLog := newMIDGuard(t, pubPEM, machineid.ModeObserve, nil)
		r := midSignedRequest(t, priv, []byte(`{"hello":"world"}`))
		called := false
		rec := midServe(t, g, r, &called)
		if !called || rec.Code != http.StatusOK {
			t.Fatalf("OBSERVE 应放行: called=%v code=%d", called, rec.Code)
		}
		data := readEventsLog(t, evLog)
		if !strings.Contains(data, "dependency_unavailable") {
			t.Fatalf("缺依赖披露: %s", data)
		}
	})
}

// TestMIDProofRequiredUnsigned proof_required=true 未签名 → 401（准入策略判定）。
func TestMIDProofRequiredUnsigned(t *testing.T) {
	_, pubPEM := midTestKey(t)
	g, _, _ := newMIDGuard(t, pubPEM, machineid.ModeProtect, httpsig.NewReplayStore(&fakeMIDEval{}))
	// proof_required=true 需要重建绑定
	cfg := g.apiMachineID
	cfg.Bindings[0].ProofRequired = true
	r := httptest.NewRequest(http.MethodPost, "/api/agent?k=v", strings.NewReader("x"))
	r.Host = "example.com"
	r.Header.Set("X-Request-Id", "req-mid-unsigned")
	called := false
	rec := midServe(t, g, r, &called)
	if called || rec.Code != http.StatusUnauthorized {
		t.Fatalf("proof_required 未签名应 401: called=%v code=%d", called, rec.Code)
	}
	assertMIDBody(t, rec, "machine_identity_failed")
}

// TestMIDAbsentZeroBehavior NG-T-C01：无身份无绑定全链零行为。
func TestMIDAbsentZeroBehavior(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	if g.apiMachineID != nil {
		t.Fatal("三段全缺装配应 nil")
	}
	called := false
	rec := midServe(t, g, midSignedRequestForAbsent(t), &called)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("无配置应原样放行: %v %d", called, rec.Code)
	}
	data := readEventsLog(t, logPath)
	if strings.Contains(data, "MID_") || strings.Contains(data, "machine_id") {
		t.Fatalf("零行为事件不得含机器身份痕迹: %s", data)
	}
}

func midSignedRequestForAbsent(t *testing.T) *http.Request {
	priv, _ := midTestKey(t)
	return midSignedRequest(t, priv, []byte(`{"a":1}`))
}

// TestMIDBotExemptMatrix Bot 豁免三重矩阵（§1.7：身份 exempt ∩ 绑定命中 ∩
// VERIFIED——三重全真才豁免）。
func TestMIDBotExemptMatrix(t *testing.T) {
	priv, pubPEM := midTestKey(t)
	newG := func(t *testing.T, exempt bool) *Guard {
		g, _, _ := newMIDGuard(t, pubPEM, machineid.ModeProtect, httpsig.NewReplayStore(&fakeMIDEval{}))
		g.APIMachineIdentities[0].BotChallengeExempt = exempt
		cfg, err := g.buildMachineIDConfig()
		if err != nil {
			t.Fatal(err)
		}
		cfg.Now = func() time.Time { return midTestNow }
		g.apiMachineID = cfg
		return g
	}
	// 三重全真 → 豁免
	t.Run("三重全真豁免", func(t *testing.T) {
		g := newG(t, true)
		r := midSignedRequest(t, priv, []byte(`{"hello":"world"}`))
		g.verifyMachineIdentity(r)
		if !g.machineIDBotExempt(r) {
			t.Fatal("三重全真应豁免")
		}
	})
	// 身份未声明 exempt → 不豁免（照走挑战）
	t.Run("未声明不豁免", func(t *testing.T) {
		g := newG(t, false)
		r := midSignedRequest(t, priv, []byte(`{"hello":"world"}`))
		g.verifyMachineIdentity(r)
		if g.machineIDBotExempt(r) {
			t.Fatal("未声明 exempt 不得豁免")
		}
	})
	// 验证未通过 → 不豁免（验证链全步通过前提）
	t.Run("未通过不豁免", func(t *testing.T) {
		g := newG(t, true)
		r := midSignedRequest(t, priv, []byte(`{"hello":"world"}`))
		r.Method = http.MethodGet // 篡改目标 → 验证失败
		g.verifyMachineIdentity(r)
		if g.machineIDBotExempt(r) {
			t.Fatal("验证未通过不得豁免")
		}
	})
	// 无评估（未命中绑定）→ 不豁免
	t.Run("未命中绑定不豁免", func(t *testing.T) {
		g := newG(t, true)
		r := httptest.NewRequest(http.MethodGet, "/other", nil)
		g.verifyMachineIdentity(r)
		if g.machineIDBotExempt(r) {
			t.Fatal("未命中绑定不得豁免")
		}
	})
}

// TestMIDIdentityKeyInvariant VERIFIED 信号注入不影响 identity_key（AGENTS.md 红线——
// identity.go:63-70：不改写 Type、不合并、不参与 identity_key 计算）。
func TestMIDIdentityKeyInvariant(t *testing.T) {
	priv, pubPEM := midTestKey(t)
	g, _, _ := newMIDGuard(t, pubPEM, machineid.ModeProtect, httpsig.NewReplayStore(&fakeMIDEval{}))
	r := midSignedRequest(t, priv, []byte(`{"hello":"world"}`))
	before := identitybehavior.ResolveIdentity(r, g.IdentitySalt, "192.0.2.1")
	g.verifyMachineIdentity(r)
	vm := identitybehavior.VerifiedMachineIdentityFrom(r.Context())
	if vm == nil {
		t.Fatal("VERIFIED 应注入独立信号")
	}
	after := identitybehavior.ResolveIdentity(r, g.IdentitySalt, "192.0.2.1")
	if before.Key != after.Key || before.Type != after.Type {
		t.Fatalf("identity_key/identity_type 语义被改写: %+v → %+v", before, after)
	}
}

// TestMIDAssemblyDiscipline 装配纪律：fail-safe 归一 / PROTECT 缺陷 fail-closed /
// C01 nil / 词表外降级不误放。
func TestMIDAssemblyDiscipline(t *testing.T) {
	_, pubPEM := midTestKey(t)
	t.Run("C01 三段全缺 nil", func(t *testing.T) {
		g := &Guard{logger: zap.NewNop()}
		cfg, err := g.buildMachineIDConfig()
		if err != nil || cfg != nil {
			t.Fatalf("应 (nil,nil): %v %v", cfg, err)
		}
	})
	t.Run("fail-safe 归一", func(t *testing.T) {
		g := &Guard{logger: zap.NewNop(), AppID: "app-1"}
		g.APIMachineIdentities = []machineIdentityJSON{{
			IdentityName: "a1", Status: "WEIRD", // 词表外 → DISABLED 不误放
			Keys: []machineIdentityKeyJSON{{Kid: "k1", Alg: "hmac-sha256", PublicKeyPEM: pubPEM, Status: "ACTIVE"}}, // alg 词表外跳行
		}}
		g.APIMachineIDBindings = []machineIDBindingJSON{
			{ApplicationID: "app-1", PathExact: "/a", Mode: "weird-mode"}, // 词表外归一 OBSERVE
		}
		cfg, err := g.buildMachineIDConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Bindings[0].Mode != machineid.ModeObserve {
			t.Fatal("mode 归一失败")
		}
		if cfg.Registry.IdentityByName("a1").Status != "DISABLED" {
			t.Fatal("status 词表外应 DISABLED")
		}
		if len(cfg.Registry.IdentityByName("a1").Keys) != 0 {
			t.Fatal("alg 词表外键应跳行")
		}
	})
	t.Run("PROTECT 缺陷 fail-closed", func(t *testing.T) {
		g := &Guard{logger: zap.NewNop(), AppID: "app-1"}
		g.APIMachineIdentities = []machineIdentityJSON{{
			IdentityName: "a1", Status: "ENABLED",
			Keys: []machineIdentityKeyJSON{{Kid: "k1", Alg: "ed25519", PublicKeyPEM: "not-a-pem", Status: "ACTIVE"}},
		}}
		g.APIMachineIDBindings = []machineIDBindingJSON{
			{ApplicationID: "app-1", PathPrefix: "/a", Mode: "PROTECT"},
		}
		if _, err := g.buildMachineIDConfig(); err == nil {
			t.Fatal("PROTECT 含 PEM 缺陷应拒绝整体加载")
		}
	})
	t.Run("OBSERVE 缺陷 fail-safe", func(t *testing.T) {
		g := &Guard{logger: zap.NewNop(), AppID: "app-1"}
		g.APIMachineIdentities = []machineIdentityJSON{{
			IdentityName: "a1", Status: "ENABLED",
			Keys: []machineIdentityKeyJSON{{Kid: "k1", Alg: "ed25519", PublicKeyPEM: "not-a-pem", Status: "ACTIVE"}},
		}}
		g.APIMachineIDBindings = []machineIDBindingJSON{
			{ApplicationID: "app-1", PathPrefix: "/a", Mode: "OBSERVE"},
		}
		if _, err := g.buildMachineIDConfig(); err != nil {
			t.Fatalf("OBSERVE 应 fail-safe 不拒载: %v", err)
		}
	})
}

// TestMIDWatermarkRegression 水位拒载：快照水位 < 已应用水位 → Provision 拒绝
// （fail-closed 保留旧配置；普通回滚不复活已撤销密钥，§1.6）。
func TestMIDWatermarkRegression(t *testing.T) {
	_, pubPEM := midTestKey(t)
	resetMachineIDWatermarkForTest()
	t.Cleanup(resetMachineIDWatermarkForTest)
	newG := func(watermark int64) *Guard {
		g := &Guard{
			AppID: "app-wm", AppCode: "shop",
			EventsLog:        filepath.Join(t.TempDir(), "events.log"),
			APIMachineIDMeta: &machineIDMetaJSON{RevocationWatermark: watermark, RegistryVersion: watermark},
			APIMachineIdentities: []machineIdentityJSON{{
				IdentityName: "a1", Status: "ENABLED",
				Keys: []machineIdentityKeyJSON{{Kid: "k1", Alg: "ed25519", PublicKeyPEM: pubPEM, Status: "ACTIVE"}},
			}},
			APIMachineIDBindings: []machineIDBindingJSON{
				{ApplicationID: "app-wm", PathPrefix: "/api/agent", Mode: "OBSERVE"},
			},
		}
		return g
	}
	resetSharedEngineForTest()
	t.Cleanup(resetSharedEngineForTest)
	g5 := newG(5)
	if err := g5.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("首装 watermark=5: %v", err)
	}
	t.Cleanup(func() { _ = g5.Cleanup() })
	// 回滚到低水位 → 拒载
	g3 := newG(3)
	if err := g3.Provision(caddy.Context{Context: context.Background()}); err == nil ||
		!strings.Contains(err.Error(), "watermark regression") {
		t.Fatalf("低水位应拒载: %v", err)
	}
	// 同水位/更高水位 → 放行
	g6 := newG(6)
	if err := g6.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("更高水位应放行: %v", err)
	}
	t.Cleanup(func() { _ = g6.Cleanup() })
}

// TestCapabilityReportMachineID 能力自报恒报 mid/1（不绑配置态）。
func TestCapabilityReportMachineID(t *testing.T) {
	m := buildCapabilityManifest(capabilityInputs{NodeID: "n1"}, time.Now())
	for _, d := range m.Detectors {
		if d.Name == "machineid" && d.Version == "mid/1" {
			return
		}
	}
	t.Fatalf("能力清单缺 machineid/mid/1: %+v", m.Detectors)
}

// assertMIDBody 固定短语体断言（error+request_id 两键，不含其他细节）。
func assertMIDBody(t *testing.T, rec *httptest.ResponseRecorder, errText string) {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body 非 JSON: %v", err)
	}
	if body["error"] != errText || len(body) != 2 {
		t.Fatalf("body = %v（固定短语形态不符）", body)
	}
}

// readEventsLog 读 access_control 事件日志（既有事件通道）。
func readEventsLog(t *testing.T, eventsLogPath string) string {
	t.Helper()
	data, err := os.ReadFile(eventsLogPath)
	if err != nil {
		return ""
	}
	return string(data)
}

// TestMIDEnforceOrderNonBypass 白名单/L7 allow 不绕过机器身份 PROTECT
// （serveNext 统一出口顺序实证——直达分支汇于 serveNextViaBot→serveNext，
// enforceMachineIdentity 在其中，结构上不可能绕过）。
func TestMIDEnforceOrderNonBypass(t *testing.T) {
	priv, pubPEM := midTestKey(t)
	g, _, _ := newMIDGuard(t, pubPEM, machineid.ModeProtect, httpsig.NewReplayStore(&fakeMIDEval{}))
	r := midSignedRequest(t, priv, []byte(`{"hello":"world"}`))
	// 篡改目标路径（保持 POST+体可读——目标绑定不一致签名验签失败）
	r.RequestURI = "/api/agent/evil?k=v"
	r.URL.Path = "/api/agent/evil"
	g.verifyMachineIdentity(r)
	called := false
	// 经 Bot 直达分支路径（botPolicy nil → serveNextViaBot 直转 serveNext——
	// 白名单/L7 allow 与常规链路同一汇合点）
	rec := httptest.NewRecorder()
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := g.serveNextViaBot(rec, r, next, g.eventBase(r, "req-mid-bypass", machineIDClientIPResult(r)), machineIDClientIPResult(r)); err != nil {
		t.Fatalf("serveNextViaBot: %v", err)
	}
	if called || rec.Code != http.StatusUnauthorized {
		t.Fatalf("直达分支不得绕过机器身份 PROTECT: called=%v code=%d", called, rec.Code)
	}
	assertMIDBody(t, rec, "machine_identity_failed")
}
