// JWT 信任链集成测试（WDSP P0-03 集成步骤；任务书
// docs/tasks/wdsp-p0/P0-03_JWT_TRUST_CHAIN.md §7 处置表与 §10 验收
// JWT-10/11/12/14/17）。测试密钥均为代码内临时生成，不引用任何真实凭据。
package jiuzhang_guard

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/temporaryblock"
	"go.uber.org/zap"
)

// ---------- 测试密钥与 Token 工具（stdlib 签名，避免新增直接依赖） ----------

const jwtTestIssuer = "https://idp.example.com"
const jwtTestSalt = "jwt-trust-test-salt-not-a-real-credential"

func jwtTestRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 测试密钥失败: %v", err)
	}
	return k
}

// jwtTestJWKS 构造公钥 JWKS（JWK：kty/kid/alg/use/n/e，n/e 为 base64url 大端字节）。
func jwtTestJWKS(t *testing.T, pub *rsa.PublicKey, kid string) json.RawMessage {
	t.Helper()
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	jwks := map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
		"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
	}}}
	raw, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("序列化测试 JWKS 失败: %v", err)
	}
	return raw
}

// jwtSignRS256 用测试私钥签发 compact JWS（RS256）。
func jwtSignRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	pb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("序列化测试 claims 失败: %v", err)
	}
	head := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sum := sha256.Sum256([]byte(head))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("测试签名失败: %v", err)
	}
	return head + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func jwtValidClaims() map[string]any {
	return map[string]any{
		"iss": jwtTestIssuer,
		"sub": "user-42",
		"aud": "api://orders",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
}

// jwtStaticSection 静态 JWKS 单 issuer 策略段（selector：/api 前缀，全方法）。
func jwtStaticSection(mode string, tokenRequired bool, jwks json.RawMessage) *jwtTrustJSON {
	return &jwtTrustJSON{
		SchemaVersion: jwtTrustSchemaVersion,
		ApplicationID: "app-1",
		Mode:          mode,
		Version:       3,
		Selectors: []jwtSelectorJSON{{
			Methods:       []string{"GET", "POST"},
			PathPrefix:    "/api",
			TokenRequired: tokenRequired,
		}},
		Issuers: []jwtIssuerJSON{{
			IssuerConfigID: "iss-test-1",
			Issuer:         jwtTestIssuer,
			Audiences:      []string{"api://orders"},
			Algorithms:     []string{"RS256"},
			KeySourceType:  "STATIC_JWKS",
			JWKS:           jwks,
			KeysetVersion:  "ks-test-1",
		}},
	}
}

// jwtRemoteSection REMOTE_JWKS 策略段（冷启动无缓存 → UNAVAILABLE 用例）。
func jwtRemoteSection(mode string) *jwtTrustJSON {
	sec := jwtStaticSection(mode, true, nil)
	sec.Issuers[0].KeySourceType = "REMOTE_JWKS"
	sec.Issuers[0].JWKS = nil
	sec.Issuers[0].RemoteURL = "https://idp.example.com/jwks.json"
	return sec
}

// newJWTGuard 构建带 JWT 验证器的测试 Guard（内存后端；extra 可追加白名单/CC 等配置）。
func newJWTGuard(t *testing.T, sec *jwtTrustJSON, extra func(*Guard)) *Guard {
	t.Helper()
	g := newTestGuard(t, Guard{AppID: "app-1", AppCode: "shop", IdentitySalt: jwtTestSalt})
	if extra != nil {
		extra(g)
	}
	if sec != nil {
		raw, err := json.Marshal(sec)
		if err != nil {
			t.Fatalf("marshal jwt_trust section: %v", err)
		}
		g.JWTTrust = raw
		if err := g.assembleJWTTrust(); err != nil {
			t.Fatalf("assemble jwt_trust: %v", err)
		}
	}
	return g
}

// jwtReq 构造带可选 Bearer 的测试请求。
func jwtReq(method, path, remoteAddr, token string) *http.Request {
	r := httptest.NewRequest(method, "http://waf-test.local"+path, nil)
	r.RemoteAddr = remoteAddr
	r.Header.Set("X-Request-Id", "jwt-test-req-1")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// jwtServe 经完整 ServeHTTP 链路发一个请求。
func jwtServe(t *testing.T, g *Guard, r *http.Request) (*httptest.ResponseRecorder, bool, error) {
	t.Helper()
	called := false
	rec := httptest.NewRecorder()
	err := g.ServeHTTP(rec, r, nextHandler{&called})
	return rec, called, err
}

// ---------- JWT-10：OFF/范围外/optional/required × 观察/保护 逐项处置表 ----------

// OFF：不装配验证器，原行为、无事件。
func TestJWTTrust_OffNoVerifier(t *testing.T) {
	key := jwtTestRSA(t)
	sec := jwtStaticSection("OFF", true, jwtTestJWKS(t, &key.PublicKey, "k1"))
	g := newJWTGuard(t, sec, nil)
	if g.jwtVerifier != nil {
		t.Fatal("OFF 模式不应装配验证器")
	}
	_, called, err := jwtServe(t, g, jwtReq("GET", "/api/orders", "203.0.113.50:1", ""))
	if err != nil || !called {
		t.Fatalf("OFF 应原样放行: err=%v called=%v", err, called)
	}
	for _, e := range g.readEvents(t) {
		if strings.HasPrefix(string(e.EventType), "JWT_") {
			t.Fatalf("OFF 不应产 JWT 事件: %+v", e)
		}
	}
}

// 范围外（未命中 selector）：PROTECT 也保持原行为。
func TestJWTTrust_OutOfScopeUnchanged(t *testing.T) {
	key := jwtTestRSA(t)
	sec := jwtStaticSection("PROTECT", true, jwtTestJWKS(t, &key.PublicKey, "k1"))
	g := newJWTGuard(t, sec, nil)
	_, called, err := jwtServe(t, g, jwtReq("GET", "/web/home", "203.0.113.51:1", ""))
	if err != nil || !called {
		t.Fatalf("范围外应原样放行: err=%v called=%v", err, called)
	}
}

// 范围内可选未携带：PROTECT 允许（NOT_PRESENT）。
func TestJWTTrust_OptionalNotPresentAllowed(t *testing.T) {
	key := jwtTestRSA(t)
	sec := jwtStaticSection("PROTECT", false, jwtTestJWKS(t, &key.PublicKey, "k1"))
	g := newJWTGuard(t, sec, nil)
	rec, called, err := jwtServe(t, g, jwtReq("GET", "/api/orders", "203.0.113.52:1", ""))
	if err != nil || !called {
		t.Fatalf("optional 未携带应放行: err=%v called=%v", err, called)
	}
	if rec.Code != 200 {
		t.Fatalf("optional 未携带不应 401/503: code=%d", rec.Code)
	}
}

// 范围内缺必需 Bearer：OBSERVE 记录放行；PROTECT 401 + 规范 challenge + 认证失败事件。
func TestJWTTrust_RequiredMissing(t *testing.T) {
	key := jwtTestRSA(t)
	jwks := jwtTestJWKS(t, &key.PublicKey, "k1")

	// OBSERVE：放行 + JWT_OBSERVED(MISSING_TOKEN)
	gObs := newJWTGuard(t, jwtStaticSection("OBSERVE", true, jwks), nil)
	if _, called, err := jwtServe(t, gObs, jwtReq("GET", "/api/orders", "203.0.113.53:1", "")); err != nil || !called {
		t.Fatalf("OBSERVE 缺必需 Bearer 应记录放行: err=%v called=%v", err, called)
	}
	evs := gObs.readEvents(t)
	var obsEv *events.Event
	for i := range evs {
		if evs[i].EventType == events.JWTObserved {
			obsEv = &evs[i]
		}
	}
	if obsEv == nil || obsEv.Action != "OBSERVE" || obsEv.JWT == nil ||
		obsEv.JWT.Status != string(jwtverify.StatusInvalid) || obsEv.JWT.ReasonCode != string(jwtverify.ReasonMissingToken) {
		t.Fatalf("OBSERVE 缺必需 Bearer 应记 JWT_OBSERVED/MISSING_TOKEN: %+v", obsEv)
	}

	// PROTECT：401 + Bearer challenge + 统一简短文案（不回显内部 reason）+ JWT_AUTH_FAILED
	gPro := newJWTGuard(t, jwtStaticSection("PROTECT", true, jwks), nil)
	rec, called, err := jwtServe(t, gPro, jwtReq("GET", "/api/orders", "203.0.113.54:1", ""))
	if err != nil || called {
		t.Fatalf("PROTECT 缺必需 Bearer 应 401: err=%v called=%v", err, called)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("PROTECT 缺必需 Bearer 应 401, got %d", rec.Code)
	}
	if wa := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(wa, `Bearer realm=`) {
		t.Fatalf("缺规范 Bearer challenge: %q", wa)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "authentication_failed") || strings.Contains(body, "MISSING_TOKEN") {
		t.Fatalf("401 文案应统一简短且不回显内部原因: %q", body)
	}
	evs = gPro.readEvents(t)
	var failEv *events.Event
	for i := range evs {
		if evs[i].EventType == events.JWTAuthFailed {
			failEv = &evs[i]
		}
	}
	if failEv == nil || failEv.Action != "REJECT" || failEv.ResponseStatus != 401 ||
		failEv.JWT == nil || failEv.JWT.ReasonCode != string(jwtverify.ReasonMissingToken) ||
		failEv.JWT.PolicyVersion != "3" {
		// 缺 Token 时无法解析发行方，issuer_config_id 为空属正确语义（无 Issuer 可溯源）
		t.Fatalf("应产 JWT_AUTH_FAILED 事件: %+v", failEv)
	}
}

// INVALID（伪造签名）：OBSERVE 记录放行不产可信主体；PROTECT 401。
func TestJWTTrust_Invalid(t *testing.T) {
	key := jwtTestRSA(t)
	other := jwtTestRSA(t) // 另一把私钥签名 → SIGNATURE_INVALID
	jwks := jwtTestJWKS(t, &key.PublicKey, "k1")
	bad := jwtSignRS256(t, other, "k1", jwtValidClaims())

	gObs := newJWTGuard(t, jwtStaticSection("OBSERVE", true, jwks), nil)
	r := jwtReq("GET", "/api/orders", "203.0.113.55:1", bad)
	if _, called, err := jwtServe(t, gObs, r); err != nil || !called {
		t.Fatalf("OBSERVE INVALID 应记录放行: err=%v called=%v", err, called)
	}
	if vi := identitybehavior.VerifiedIdentityFrom(r.Context()); vi != nil {
		t.Fatalf("OBSERVE INVALID 不产可信主体: %+v", vi)
	}
	found := false
	for _, e := range gObs.readEvents(t) {
		if e.EventType == events.JWTObserved && e.JWT != nil &&
			e.JWT.ReasonCode == string(jwtverify.ReasonSignatureInvalid) {
			found = true
		}
	}
	if !found {
		t.Fatal("OBSERVE INVALID 应记 JWT_OBSERVED/SIGNATURE_INVALID")
	}

	gPro := newJWTGuard(t, jwtStaticSection("PROTECT", true, jwks), nil)
	rec, called, err := jwtServe(t, gPro, jwtReq("GET", "/api/orders", "203.0.113.56:1", bad))
	if err != nil || called || rec.Code != http.StatusUnauthorized {
		t.Fatalf("PROTECT INVALID 应 401: err=%v called=%v code=%d", err, called, rec.Code)
	}
}

// UNAVAILABLE（REMOTE_JWKS 冷启动无缓存 + 拨号失败）：OBSERVE 记录放行；
// PROTECT 503（不伪装成 Token 错误）+ 验证不可用事件。
func TestJWTTrust_Unavailable(t *testing.T) {
	key := jwtTestRSA(t)
	token := jwtSignRS256(t, key, "k1", jwtValidClaims())
	newFailingGuard := func(mode string) *Guard {
		return newJWTGuard(t, jwtRemoteSection(mode), func(g *Guard) {
			g.jwtFetcher = jwtverify.NewFetcher(jwtverify.FetcherConfig{
				DialTCP: func(ctx context.Context, network, address string) (net.Conn, error) {
					return nil, errors.New("dial blocked in test")
				},
			})
		})
	}

	gObs := newFailingGuard("OBSERVE")
	if _, called, err := jwtServe(t, gObs, jwtReq("GET", "/api/orders", "203.0.113.57:1", token)); err != nil || !called {
		t.Fatalf("OBSERVE UNAVAILABLE 应记录放行: err=%v called=%v", err, called)
	}
	found := false
	for _, e := range gObs.readEvents(t) {
		if e.EventType == events.JWTObserved && e.JWT != nil &&
			e.JWT.Status == string(jwtverify.StatusUnavailable) &&
			e.JWT.ReasonCode == string(jwtverify.ReasonKeysetUnavailable) {
			found = true
		}
	}
	if !found {
		t.Fatal("OBSERVE UNAVAILABLE 应记 JWT_OBSERVED/KEYSET_UNAVAILABLE")
	}

	gPro := newFailingGuard("PROTECT")
	rec, called, err := jwtServe(t, gPro, jwtReq("GET", "/api/orders", "203.0.113.58:1", token))
	if err != nil || called {
		t.Fatalf("PROTECT UNAVAILABLE 应 503: err=%v called=%v", err, called)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("PROTECT UNAVAILABLE 应 503, got %d", rec.Code)
	}
	if wa := rec.Header().Get("WWW-Authenticate"); wa != "" {
		t.Fatalf("503 不得伪装成 Token 错误（不带 Bearer challenge）: %q", wa)
	}
	if !strings.Contains(rec.Body.String(), "authentication_unavailable") {
		t.Fatalf("503 文案: %q", rec.Body.String())
	}
	found = false
	for _, e := range gPro.readEvents(t) {
		if e.EventType == events.JWTUnavailable && e.Action == "REJECT" && e.ResponseStatus == 503 {
			found = true
		}
	}
	if !found {
		t.Fatal("PROTECT UNAVAILABLE 应产 JWT_UNAVAILABLE 事件")
	}
}

// VERIFIED：继续后续检测（不绕过其他防护），可信信号注入身份上下文。
func TestJWTTrust_VerifiedPassWithIdentity(t *testing.T) {
	key := jwtTestRSA(t)
	sec := jwtStaticSection("PROTECT", true, jwtTestJWKS(t, &key.PublicKey, "k1"))
	sec.Issuers[0].TenantClaim = "tenant"
	g := newJWTGuard(t, sec, nil)
	claims := jwtValidClaims()
	claims["tenant"] = "acme"
	r := jwtReq("GET", "/api/orders", "203.0.113.59:1", jwtSignRS256(t, key, "k1", claims))
	if _, called, err := jwtServe(t, g, r); err != nil || !called {
		t.Fatalf("VERIFIED 应放行: err=%v called=%v", err, called)
	}
	res, ok := jwtResultFrom(r.Context())
	if !ok || res.Status != jwtverify.StatusVerified || res.VerifiedPrincipalID == "" {
		t.Fatalf("应产出 VERIFIED 结果与主体指纹: %+v ok=%v", res, ok)
	}
	vi := identitybehavior.VerifiedIdentityFrom(r.Context())
	if vi == nil || vi.PrincipalID != res.VerifiedPrincipalID || vi.TenantID != "acme" {
		t.Fatalf("可信身份信号应注入请求上下文: %+v", vi)
	}
}

// ---------- JWT-11：观测独立性与既有顺序 ----------

// 身份观测关闭（ibh=nil）时 JWT 验证与执行照常（不经过观测的 fail-open 分支）。
func TestJWTTrust_EnforcedWithoutIdentityObservation(t *testing.T) {
	key := jwtTestRSA(t)
	g := newJWTGuard(t, jwtStaticSection("PROTECT", true, jwtTestJWKS(t, &key.PublicKey, "k1")), nil)
	if g.ibh != nil {
		t.Fatal("本用例身份观测应关闭")
	}
	rec, called, err := jwtServe(t, g, jwtReq("GET", "/api/orders", "203.0.113.60:1", ""))
	if err != nil || called || rec.Code != http.StatusUnauthorized {
		t.Fatalf("身份观测关闭不得跳过 JWT 执行: err=%v called=%v code=%d", err, called, rec.Code)
	}
	// 合法 Token 同样执行并放行
	if _, called, err := jwtServe(t, g, jwtReq("GET", "/api/orders", "203.0.113.60:1",
		jwtSignRS256(t, key, "k1", jwtValidClaims()))); err != nil || !called {
		t.Fatalf("身份观测关闭时 VERIFIED 应放行: err=%v called=%v", err, called)
	}
}

// jwtPanicStore 身份观测存储故障注入：Observe 无条件 panic，模拟身份观测引擎在
// 请求收束（End 记账）阶段运行期崩溃——由 identitybehavior.Engine.End 的 defer
// recover 兜底（fail-open）；若 recover 失效，panic 沿请求链传播使本测试崩溃失败。
type jwtPanicStore struct{}

func (jwtPanicStore) Observe(identitybehavior.ObserveInput) (*identitybehavior.Snapshot, error) {
	panic("jwt trust test: identity observation store panic")
}

func (jwtPanicStore) Close() error { return nil }

// 身份观测开启但其引擎在请求中 panic：PROTECT 下无 Token/无效 Token 仍 401（含规范
// Bearer challenge）且 JWT 事件照产，合法 Token 仍放行——JWT 验证与执行不经过观测
// 模块的 fail-open 分支（jwt_trust.go 头部纪律）。
// 注入点说明：身份引擎为具体类型 *identitybehavior.Engine，无法整体替换为 panic
// mock；Store 是引擎运行期唯一可注入的故障点（NewEngine 参数），故以同配置重建引擎
// 并注入每请求 panic 的 Store。Begin 为纯本地解析、无可注入分支，不在故障模拟范围。
func TestJWTTrust_EnforcedDespiteIdentityObservationPanic(t *testing.T) {
	key := jwtTestRSA(t)
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app-1", AppCode: "shop", EventsLog: filepath.Join(t.TempDir(), "events.log"),
		IdentitySalt:     jwtTestSalt,
		IdentityBehavior: &identityBehaviorJSON{Enabled: true},
		JWTTrust:         mustJSON(t, jwtStaticSection("PROTECT", true, jwtTestJWKS(t, &key.PublicKey, "k1"))),
	})
	if g.ibh == nil || g.jwtVerifier == nil {
		t.Fatal("身份观测引擎与 JWT 验证器均应装配")
	}
	eventsPaths.Store(g, g.EventsLog) // Provision 路径不登记，readEvents 需要

	cfg, err := identitybehavior.Compile(&identityBehaviorJSON{Enabled: true}, zap.NewNop())
	if err != nil || cfg == nil {
		t.Fatalf("compile identity config: %v", err)
	}
	ibe, err := identitybehavior.NewEventLogger(filepath.Join(t.TempDir(), "identity-events.log"), "test-node", zap.NewNop())
	if err != nil {
		t.Fatalf("identity events logger: %v", err)
	}
	_ = g.ibh.Close() // 关闭原引擎（事件日志/存储）；注入引擎由 Guard Cleanup 统一关闭
	g.ibh = identitybehavior.NewEngine(cfg, jwtPanicStore{}, ibe, identitybehavior.Options{
		AppID: g.AppID, AppCode: g.AppCode, GatewayNode: g.GatewayNode,
		Salt: g.IdentitySalt, Logger: zap.NewNop(),
	})

	// 缺必需 Bearer：观测引擎崩溃不跳过 JWT 执行——401 + 规范 Bearer challenge
	rMissing := jwtReq("GET", "/api/orders", "203.0.113.67:1", "")
	rMissing.Header.Set("X-Request-Id", "jwt-ibpanic-missing")
	rec, called, err := jwtServe(t, g, rMissing)
	if err != nil || called || rec.Code != http.StatusUnauthorized {
		t.Fatalf("观测引擎 panic 不得跳过 JWT 401: err=%v called=%v code=%d", err, called, rec.Code)
	}
	if wa := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(wa, `Bearer realm=`) {
		t.Fatalf("缺规范 Bearer challenge: %q", wa)
	}

	// 无效 Token（伪造签名）：同样 401 + 规范 challenge
	bad := jwtSignRS256(t, jwtTestRSA(t), "k1", jwtValidClaims())
	rInvalid := jwtReq("GET", "/api/orders", "203.0.113.67:2", bad)
	rInvalid.Header.Set("X-Request-Id", "jwt-ibpanic-invalid")
	rec, called, err = jwtServe(t, g, rInvalid)
	if err != nil || called || rec.Code != http.StatusUnauthorized {
		t.Fatalf("观测引擎 panic 下伪造签名应 401: err=%v called=%v code=%d", err, called, rec.Code)
	}
	if wa := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(wa, `Bearer realm=`) {
		t.Fatalf("缺规范 Bearer challenge: %q", wa)
	}

	// 合法 Token：VERIFIED 放行不受观测引擎崩溃影响（End panic 被 recover）
	rValid := jwtReq("GET", "/api/orders", "203.0.113.67:3", jwtSignRS256(t, key, "k1", jwtValidClaims()))
	rValid.Header.Set("X-Request-Id", "jwt-ibpanic-valid")
	rec, called, err = jwtServe(t, g, rValid)
	if err != nil || !called || rec.Code != http.StatusOK {
		t.Fatalf("观测引擎 panic 不得影响 VERIFIED 放行: err=%v called=%v code=%d", err, called, rec.Code)
	}

	// JWT 事件仍产生：两次 401 各产 JWT_AUTH_FAILED（MISSING_TOKEN / SIGNATURE_INVALID）
	var missingEv, invalidEv *events.Event
	evs := g.readEvents(t)
	for i := range evs {
		if evs[i].EventType != events.JWTAuthFailed {
			continue
		}
		switch evs[i].RequestID {
		case "jwt-ibpanic-missing":
			missingEv = &evs[i]
		case "jwt-ibpanic-invalid":
			invalidEv = &evs[i]
		}
	}
	if missingEv == nil || missingEv.Action != "REJECT" || missingEv.ResponseStatus != 401 ||
		missingEv.JWT == nil || missingEv.JWT.ReasonCode != string(jwtverify.ReasonMissingToken) {
		t.Fatalf("应产 JWT_AUTH_FAILED/MISSING_TOKEN 事件: %+v", missingEv)
	}
	if invalidEv == nil || invalidEv.Action != "REJECT" || invalidEv.ResponseStatus != 401 ||
		invalidEv.JWT == nil || invalidEv.JWT.ReasonCode != string(jwtverify.ReasonSignatureInvalid) {
		t.Fatalf("应产 JWT_AUTH_FAILED/SIGNATURE_INVALID 事件: %+v", invalidEv)
	}
}

// 人工临时封禁优先于白名单与 JWT 处置（封禁查询在验证处置点之前）。
func TestJWTTrust_ManualBlockPrecedesJWT(t *testing.T) {
	key := jwtTestRSA(t)
	g := newJWTGuard(t, jwtStaticSection("PROTECT", true, jwtTestJWKS(t, &key.PublicKey, "k1")), nil)
	if err := g.engine.blockCache.PutLocal(reqCtx(), temporaryblock.Block{
		ID: "mb-1", ClientIP: "203.0.113.61", AppID: "app-1",
		ExpiresAt: time.Now().Add(time.Hour), Auto: false, Reason: "manual",
	}); err != nil {
		t.Fatalf("put manual block: %v", err)
	}
	// 缺必需 Bearer 的人工封禁 IP：403 人工封禁（非 JWT 401）
	_, called, err := jwtServe(t, g, jwtReq("GET", "/api/orders", "203.0.113.61:1", ""))
	if err == nil || called {
		t.Fatalf("人工封禁应 403 拦截: err=%v called=%v", err, called)
	}
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != http.StatusForbidden {
		t.Fatalf("人工封禁应优先于 JWT 401（403 HandlerError）: %v", err)
	}
	for _, e := range g.readEvents(t) {
		if e.EventType == events.JWTAuthFailed {
			t.Fatalf("人工封禁优先，不应产 JWT_AUTH_FAILED: %+v", e)
		}
	}
}

// 白名单不绕过 JWT PROTECT（安全底线）：白名单 IP 缺必需 Bearer 仍 401。
func TestJWTTrust_WhitelistDoesNotBypassProtect(t *testing.T) {
	key := jwtTestRSA(t)
	g := newJWTGuard(t, jwtStaticSection("PROTECT", true, jwtTestJWKS(t, &key.PublicKey, "k1")),
		func(g *Guard) {
			g.allowG, _ = buildRuleSet([]ruleJSON{{ID: "a1", Address: "203.0.113.62", Priority: 1}})
		})
	rec, called, err := jwtServe(t, g, jwtReq("GET", "/api/orders", "203.0.113.62:1", ""))
	if err != nil || called || rec.Code != http.StatusUnauthorized {
		t.Fatalf("白名单不得绕过 JWT PROTECT: err=%v called=%v code=%d", err, called, rec.Code)
	}
	// 白名单命中事件仍在（ALLOW），JWT 401 事件也在——两个事实都可追溯
	var allowEv, jwtEv bool
	for _, e := range g.readEvents(t) {
		if e.EventType == events.IPAllowMatch {
			allowEv = true
		}
		if e.EventType == events.JWTAuthFailed {
			jwtEv = true
		}
	}
	if !allowEv || !jwtEv {
		t.Fatalf("白名单命中与 JWT 401 事件均应存在: allow=%v jwt=%v", allowEv, jwtEv)
	}
}

// ---------- JWT-12：VERIFIED 不产生全局放行 ----------

// VERIFIED JWT + CC 超限：最终处置仍为 CC 模块 429（JWT 不放行其他防护）。
func TestJWTTrust_VerifiedDoesNotBypassCC(t *testing.T) {
	key := jwtTestRSA(t)
	g := newJWTGuard(t, jwtStaticSection("PROTECT", true, jwtTestJWKS(t, &key.PublicKey, "k1")),
		func(g *Guard) {
			g.policies, _ = compilePolicies([]policyJSON{{
				ID: "cc1", Dimension: "CLIENT_IP", Algorithm: "TOKEN_BUCKET",
				URIMatchType: "ALL", RequestsLimit: 1, WindowSeconds: 60, BurstCapacity: 1,
				Action: "REJECT", Priority: 1,
			}})
		})
	token := jwtSignRS256(t, key, "k1", jwtValidClaims())
	if _, called, err := jwtServe(t, g, jwtReq("GET", "/api/orders", "203.0.113.63:1", token)); err != nil || !called {
		t.Fatalf("首个 VERIFIED 请求应放行: err=%v called=%v", err, called)
	}
	rec, called, err := jwtServe(t, g, jwtReq("GET", "/api/orders", "203.0.113.63:1", token))
	if err != nil || called || rec.Code != http.StatusTooManyRequests {
		t.Fatalf("VERIFIED 不得绕过 CC：第二请求应 429: err=%v called=%v code=%d", err, called, rec.Code)
	}
}

// VERIFIED JWT + 黑名单命中：最终处置仍为访问控制 403。
func TestJWTTrust_VerifiedDoesNotBypassDeny(t *testing.T) {
	key := jwtTestRSA(t)
	g := newJWTGuard(t, jwtStaticSection("PROTECT", true, jwtTestJWKS(t, &key.PublicKey, "k1")),
		func(g *Guard) {
			g.denyG, _ = buildRuleSet([]ruleJSON{{ID: "d1", Address: "203.0.113.64", Priority: 1}})
		})
	_, called, err := jwtServe(t, g, jwtReq("GET", "/api/orders", "203.0.113.64:1",
		jwtSignRS256(t, key, "k1", jwtValidClaims())))
	var he caddyhttp.HandlerError
	if err == nil || called || !errors.As(err, &he) || he.StatusCode != http.StatusForbidden {
		t.Fatalf("VERIFIED 不得绕过黑名单：应 403: err=%v called=%v", err, called)
	}
}

// VERIFIED JWT + API 攻击（FORMAL 模型类型偏离，API 管线 PROTECT）：
// 最终处置为 API 检测模块 403，被拦事件仍携带 jwt_verification（VERIFIED）溯源。
func TestJWTTrust_VerifiedAPIAttackStillBlocked(t *testing.T) {
	key := jwtTestRSA(t)
	logPath := filepath.Join(t.TempDir(), "api-runtime-events.log")
	al, err := apievents.NewLogger(logPath, "test-node")
	if err != nil {
		t.Fatalf("api events logger: %v", err)
	}
	t.Cleanup(func() { _ = al.Close() })
	g := newJWTGuard(t, jwtStaticSection("PROTECT", true, jwtTestJWKS(t, &key.PublicKey, "k1")),
		func(g *Guard) {
			g.APIDynamicProtection = true
			g.APIProtectionMode = "PROTECT"
			g.APIFormalSchemas = map[string]map[string]string{"POST /api/orders": {"id": "number"}}
			g.apiEvents = al
		})
	r := httptest.NewRequest(http.MethodPost, "http://waf-test.local/api/orders", strings.NewReader(`{"id":"abc"`+`}`))
	r.RemoteAddr = "203.0.113.65:1"
	r.Header.Set("X-Request-Id", "jwt-attack-1")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+jwtSignRS256(t, key, "k1", jwtValidClaims()))
	called := false
	err = g.ServeHTTP(httptest.NewRecorder(), r, nextHandler{&called})
	var he caddyhttp.HandlerError
	if err == nil || called || !errors.As(err, &he) || he.StatusCode != http.StatusForbidden {
		t.Fatalf("VERIFIED JWT + 攻击载荷应被 API 模块 403: err=%v called=%v", err, called)
	}
	_ = al.Close()
	found := false
	for _, rec := range readAPIRecords(t, logPath) {
		if rec.RequestID == "jwt-attack-1" && rec.FinalAction == "BLOCK" {
			found = true
			if rec.JWTVerification == nil || rec.JWTVerification.Status != string(jwtverify.StatusVerified) ||
				rec.JWTVerification.VerifiedPrincipalID == "" {
				t.Fatalf("被拦 API 事件应携带 VERIFIED 验证摘要: %+v", rec.JWTVerification)
			}
		}
	}
	if !found {
		t.Fatal("应产出 final_action=BLOCK 的 API 主事件")
	}
}

// VERIFIED JWT + 下游 WAF 阻断（单元层：next handler 扮演 WAF/Coraza 层，真实 Coraza
// 组合由集成测试覆盖，见 P0-08）：下游 403 阻断原样生效——VERIFIED 不跳过、不覆盖
// 下游防护处置；事件仍携带 VERIFIED 验证摘要（最终处置可关联）。
func TestJWTTrust_VerifiedDoesNotBypassDownstreamWAF(t *testing.T) {
	key := jwtTestRSA(t)
	logPath := filepath.Join(t.TempDir(), "api-runtime-events.log")
	al, err := apievents.NewLogger(logPath, "test-node")
	if err != nil {
		t.Fatalf("api events logger: %v", err)
	}
	t.Cleanup(func() { _ = al.Close() })
	g := newJWTGuard(t, jwtStaticSection("PROTECT", true, jwtTestJWKS(t, &key.PublicKey, "k1")),
		func(g *Guard) {
			g.APIDynamicProtection = true
			g.APIProtectionMode = "OBSERVE" // 统一管线只观测不定案：唯一阻断来自下游
			g.apiEvents = al
		})
	token := jwtSignRS256(t, key, "k1", jwtValidClaims())
	newReq := func(reqID string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "http://waf-test.local/api/orders", strings.NewReader(`{"id":1}`))
		r.RemoteAddr = "203.0.113.68:1"
		r.Header.Set("X-Request-Id", reqID)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}

	// 变体1：coraza-caddy 请求相位中断——不写响应，返回 403 哨兵错误（apicoraza.go 口径）
	called1 := false
	next1 := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called1 = true
		return caddyhttp.HandlerError{
			StatusCode: http.StatusForbidden, ID: "tx-jwt-waf-1", Err: errors.New("interruption triggered"),
		}
	})
	err = g.ServeHTTP(httptest.NewRecorder(), newReq("jwt-waf-block-1"), next1)
	var he caddyhttp.HandlerError
	if !called1 {
		t.Fatal("VERIFIED 应到达下游（JWT 不短路），由下游防护处置")
	}
	if err == nil || !errors.As(err, &he) || he.StatusCode != http.StatusForbidden {
		t.Fatalf("下游 WAF 403 应原样传播（JWT 不覆盖）: err=%v", err)
	}

	// 变体2：下游自写 403 阻断页并返回 nil——guard 不得改写状态码与内容
	called2 := false
	next2 := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called2 = true
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("blocked by downstream waf"))
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, newReq("jwt-waf-block-2"), next2); err != nil {
		t.Fatalf("下游自写 403 不应产生 guard 错误: %v", err)
	}
	if !called2 {
		t.Fatal("VERIFIED 应到达下游（JWT 不短路）")
	}
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "blocked by downstream waf") {
		t.Fatalf("VERIFIED 不得覆盖下游 403 响应: code=%d body=%q", rec.Code, rec.Body.String())
	}

	// 最终处置可关联：两个变体的 API 事件均携带 VERIFIED 验证摘要
	_ = al.Close()
	byID := map[string]apievents.Record{}
	for _, rec := range readAPIRecords(t, logPath) {
		byID[rec.RequestID] = rec
	}
	ev1, ok := byID["jwt-waf-block-1"]
	if !ok {
		t.Fatal("变体1 应产 API 主事件")
	}
	if ev1.FinalAction != "BLOCK" || ev1.ResponseStatus != http.StatusForbidden {
		t.Fatalf("变体1 最终处置应按实记下游 BLOCK/403: final_action=%q status=%d", ev1.FinalAction, ev1.ResponseStatus)
	}
	attributed := false
	for _, d := range ev1.Details {
		if d.Detector == "waf" && d.RuleID == "waf.downstream_intercept" {
			attributed = true
		}
	}
	if !attributed {
		t.Fatalf("变体1 阻断应归因下游 WAF（非 JWT 处置）: %+v", ev1.Details)
	}
	if ev1.JWTVerification == nil || ev1.JWTVerification.Status != string(jwtverify.StatusVerified) ||
		ev1.JWTVerification.VerifiedPrincipalID == "" || ev1.JWTVerification.PolicyVersion != "3" {
		t.Fatalf("变体1 事件应携带 VERIFIED 验证摘要: %+v", ev1.JWTVerification)
	}
	ev2, ok := byID["jwt-waf-block-2"]
	if !ok {
		t.Fatal("变体2 应产 API 主事件")
	}
	if ev2.ResponseStatus != http.StatusForbidden {
		t.Fatalf("变体2 事件应如实记录下游 403: status=%d", ev2.ResponseStatus)
	}
	if ev2.JWTVerification == nil || ev2.JWTVerification.Status != string(jwtverify.StatusVerified) ||
		ev2.JWTVerification.VerifiedPrincipalID == "" {
		t.Fatalf("变体2 事件应携带 VERIFIED 验证摘要: %+v", ev2.JWTVerification)
	}
}

// API 主事件（放行流量）携带 jwt_verification；tenant 不落明文（加盐指纹）。
func TestJWTTrust_APIMainEventCarriesVerification(t *testing.T) {
	key := jwtTestRSA(t)
	logPath := filepath.Join(t.TempDir(), "api-runtime-events.log")
	al, err := apievents.NewLogger(logPath, "test-node")
	if err != nil {
		t.Fatalf("api events logger: %v", err)
	}
	t.Cleanup(func() { _ = al.Close() })
	sec := jwtStaticSection("PROTECT", true, jwtTestJWKS(t, &key.PublicKey, "k1"))
	sec.Issuers[0].TenantClaim = "tenant"
	g := newJWTGuard(t, sec, func(g *Guard) {
		g.APIDynamicProtection = true
		g.APIProtectionMode = "OBSERVE"
		g.apiEvents = al
	})
	claims := jwtValidClaims()
	claims["tenant"] = "acme"
	r := httptest.NewRequest(http.MethodPost, "http://waf-test.local/api/orders", strings.NewReader(`{"id":1}`))
	r.RemoteAddr = "203.0.113.66:1"
	r.Header.Set("X-Request-Id", "jwt-pass-1")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Authorization", "Bearer "+jwtSignRS256(t, key, "k1", claims))
	called := false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil || !called {
		t.Fatalf("VERIFIED API 请求应放行: err=%v called=%v", err, called)
	}
	_ = al.Close()
	found := false
	for _, ev := range readAPIRecords(t, logPath) {
		if ev.RequestID == "jwt-pass-1" {
			found = true
			jv := ev.JWTVerification
			if jv == nil || jv.Status != string(jwtverify.StatusVerified) || jv.ReasonCode != string(jwtverify.ReasonValid) ||
				jv.PolicyVersion != "3" || jv.IssuerConfigID != "iss-test-1" || jv.VerifiedPrincipalID == "" ||
				jv.EvaluatedAt == "" {
				t.Fatalf("API 主事件应携带完整验证摘要: %+v", jv)
			}
			if jv.VerifiedTenantID == "" || jv.VerifiedTenantID == "acme" {
				t.Fatalf("tenant 应加盐指纹上报而非明文/缺失: %q", jv.VerifiedTenantID)
			}
		}
	}
	if !found {
		t.Fatal("应产出该请求的 API 主事件")
	}
}

// ---------- JWT-14：未知 schema_version / 未知字段 / 未知强制语义 fail-closed ----------

func TestJWTTrust_FailClosedOnUnknownSemantics(t *testing.T) {
	key := jwtTestRSA(t)
	good := jwtStaticSection("PROTECT", true, jwtTestJWKS(t, &key.PublicKey, "k1"))

	// 未知 schema_version → 拒绝加载
	bad := *good
	bad.SchemaVersion = 99
	if _, err := parseJWTTrustSection(mustJSON(t, &bad)); err == nil {
		t.Fatal("未知 schema_version 必须拒绝加载（fail-closed）")
	}
	// 未知 mode 强制语义 → 拒绝加载
	badMode := *good
	badMode.Mode = "ENFORCE"
	if _, err := parseJWTTrustSection(mustJSON(t, &badMode)); err == nil {
		t.Fatal("未知 mode 必须拒绝加载（fail-closed）")
	}
	// 未知字段（可能携带本网关不理解的强制语义）→ 严格解码拒绝
	raw := map[string]any{}
	if err := json.Unmarshal(mustJSON(t, good), &raw); err != nil {
		t.Fatal(err)
	}
	raw["future_enforcement_toggle"] = true
	if _, err := parseJWTTrustSection(mustJSON(t, raw)); err == nil {
		t.Fatal("未知字段必须拒绝加载（jwt_trust 为容忍未知字段惯例的显式例外）")
	}
	// PROTECT 缺身份指纹密钥 → 装配拒绝（与 NewVerifier 门禁对应）
	g := newTestGuard(t, Guard{AppID: "app-1", AppCode: "shop"}) // IdentitySalt 为空
	g.JWTTrust = mustJSON(t, good)
	if err := g.assembleJWTTrust(); !errors.Is(err, jwtverify.ErrIdentitySecretRequired) {
		t.Fatalf("PROTECT 缺身份密钥应 fail-closed: %v", err)
	}
	// OBSERVE 缺身份指纹密钥 → 可运行（验签照常，不产可信主体）
	g2 := newTestGuard(t, Guard{AppID: "app-1", AppCode: "shop"})
	sec := jwtStaticSection("OBSERVE", true, jwtTestJWKS(t, &key.PublicKey, "k1"))
	g2.JWTTrust = mustJSON(t, sec)
	if err := g2.assembleJWTTrust(); err != nil {
		t.Fatalf("OBSERVE 空密钥应可装配: %v", err)
	}
	r := jwtReq("GET", "/api/orders", "203.0.113.70:1", jwtSignRS256(t, key, "k1", jwtValidClaims()))
	if _, called, err := jwtServe(t, g2, r); err != nil || !called {
		t.Fatalf("OBSERVE 空密钥应放行: err=%v called=%v", err, called)
	}
	res, ok := jwtResultFrom(r.Context())
	if !ok || res.Status != jwtverify.StatusVerified || res.VerifiedPrincipalID != "" {
		t.Fatalf("OBSERVE 空密钥：VERIFIED 但不产可信主体: %+v ok=%v", res, ok)
	}
	// Validate 同步 fail-closed（Caddy 配置校验期）
	v := &Guard{EventsLog: "x", JWTTrust: mustJSON(t, &bad)}
	if err := v.Validate(); err == nil {
		t.Fatal("Validate 对未知 schema_version 必须报错")
	}
}

// 真实 Provision 路径：未知 schema_version 的 jwt_trust 段拒绝整体配置加载。
func TestJWTTrust_ProvisionRejectsUnknownSchema(t *testing.T) {
	key := jwtTestRSA(t)
	bad := jwtStaticSection("PROTECT", true, jwtTestJWKS(t, &key.PublicKey, "k1"))
	bad.SchemaVersion = 2
	resetSharedEngineForTest()
	t.Cleanup(resetSharedEngineForTest)
	g := &Guard{
		AppID: "app-1", AppCode: "shop", IdentitySalt: jwtTestSalt,
		EventsLog: filepath.Join(t.TempDir(), "events.log"),
		JWTTrust:  mustJSON(t, bad),
	}
	if err := g.Provision(caddy.Context{Context: context.Background()}); err == nil {
		t.Fatal("Provision 对未知 schema_version 必须拒绝（不静默删除 PROTECT 策略）")
	}
}

// ---------- JWT-17：identity_key 语义不变 ----------

// VERIFIED 注入可信信号后 identity_key/identity_type 完全不变（独立字段，
// APPLICATION/SERVICE 不改写 HUMAN，不与未验证 sub 相同者合并）。
func TestJWTTrust_IdentityKeyUnchanged(t *testing.T) {
	r1 := httptest.NewRequest(http.MethodGet, "http://waf-test.local/api/orders", nil)
	r1.Header.Set("Authorization", "Bearer some-unverified-token")
	r2 := httptest.NewRequest(http.MethodGet, "http://waf-test.local/api/orders", nil)
	r2.Header.Set("Authorization", "Bearer some-unverified-token")
	r2 = r2.WithContext(identitybehavior.WithVerifiedIdentity(r2.Context(), &identitybehavior.VerifiedIdentity{
		PrincipalID: "fp-verified-1", TenantID: "acme", IssuerConfigID: "iss-1", PolicyVersion: "3",
	}))
	id1 := identitybehavior.ResolveIdentity(r1, jwtTestSalt, "203.0.113.80")
	id2 := identitybehavior.ResolveIdentity(r2, jwtTestSalt, "203.0.113.80")
	if id1.Key != id2.Key || id1.Type != id2.Type {
		t.Fatalf("可信信号不得改变 identity_key/identity_type: %q/%s vs %q/%s", id1.Key, id1.Type, id2.Key, id2.Type)
	}
	if id2.VerifiedPrincipalID != "fp-verified-1" || id2.VerifiedTenantID != "acme" {
		t.Fatalf("可信信号应填充独立字段: %+v", id2)
	}
	if id1.VerifiedPrincipalID != "" || id1.VerifiedTenantID != "" {
		t.Fatalf("未注入时可信字段应为空: %+v", id1)
	}
}

// 身份观测启用时：VERIFIED 可信信号经完整链路进入身份解析结果。
func TestJWTTrust_VerifiedSignalReachesIdentityEngine(t *testing.T) {
	key := jwtTestRSA(t)
	sec := jwtStaticSection("PROTECT", true, jwtTestJWKS(t, &key.PublicKey, "k1"))
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app-1", AppCode: "shop", EventsLog: filepath.Join(t.TempDir(), "events.log"),
		IdentitySalt:     jwtTestSalt,
		IdentityBehavior: &identityBehaviorJSON{Enabled: true},
		JWTTrust:         mustJSON(t, sec),
	})
	if g.ibh == nil || g.jwtVerifier == nil {
		t.Fatal("身份引擎与 JWT 验证器均应装配")
	}
	r := jwtReq("GET", "/api/orders", "203.0.113.81:1", jwtSignRS256(t, key, "k1", jwtValidClaims()))
	called := false
	if err := g.ServeHTTP(httptest.NewRecorder(), r, nextHandler{&called}); err != nil || !called {
		t.Fatalf("VERIFIED 应放行: err=%v called=%v", err, called)
	}
	id := identitybehavior.IdentityFrom(r.Context())
	if id == nil || id.VerifiedPrincipalID == "" {
		t.Fatalf("身份解析结果应携带可信主体指纹: %+v", id)
	}
	res, _ := jwtResultFrom(r.Context())
	if id.VerifiedPrincipalID != res.VerifiedPrincipalID {
		t.Fatalf("可信主体指纹应与验证结果一致: %q vs %q", id.VerifiedPrincipalID, res.VerifiedPrincipalID)
	}
	// identity_key 仍由凭据派生（不因可信信号改变语义）
	if id.Key == "" {
		t.Fatal("identity_key 应非空")
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}
