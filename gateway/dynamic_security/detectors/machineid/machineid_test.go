// machineid_test.go 十步验证链矩阵（固定序短路逐步独立 reason）+ 覆盖五态 +
// 键状态机/时效/nonce/重放/principal_binding/范围核对。
package machineid

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
	"github.com/jiuzhang-waf/gateway/dynamic_security/httpsig"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
)

// 冻结测试时钟（created/expires 窗口围绕它构造）。
var testNow = time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC)

// fakeReplayEval 重放桩（实现 httpsig.Evaluator——NewReplayStore 包装后
// 供给 Evaluate；SET NX 语义在桩上模拟）。
type fakeReplayEval struct {
	err  error
	seen map[string]bool
}

func newFakeReplay() *fakeReplayEval { return &fakeReplayEval{seen: map[string]bool{}} }

func (f *fakeReplayEval) Eval(_ context.Context, _ string, keys []string, _ []string) ([]interface{}, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.seen[keys[0]] {
		return []interface{}{int64(0)}, nil
	}
	f.seen[keys[0]] = true
	return []interface{}{int64(1)}, nil
}

// wrapReplay 桩包装为 *httpsig.ReplayStore（冻结签名消费形态）。
func wrapReplay(f *fakeReplayEval) *httpsig.ReplayStore {
	if f == nil {
		return nil
	}
	return httpsig.NewReplayStore(f)
}

// ---------- 测试签名基础设施（httpsig 库外消费形态） ----------

// testRegistry 构造登记册（一键一身份；pub 为外部生成的公钥——变异场景
// 与签名私钥同对（同一密钥对贯穿矩阵，防误配））。
func testRegistry(t *testing.T, alg string, pub any, mutate func(*Identity)) *Registry {
	t.Helper()
	id := Identity{
		Name: "agent-01", Status: "ENABLED",
		Keys: map[string]KeyRecord{
			"k1": {Kid: "k1", Alg: alg, PublicKeyPEM: pubPEM(t, pub), Status: "ACTIVE"},
		},
	}
	if mutate != nil {
		mutate(&id)
	}
	return NewRegistry([]Identity{id}, 7, 3)
}

// genEDPriv 生成测试 ed25519 密钥对（矩阵共用私钥——公钥经 priv.Public() 派生）。
func genEDPriv(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func pubPEM(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// signRequest 构造签名请求（G1 完整成分：@method/@authority/@path(+@query)
// (+content-digest)；created/expires 围绕 testNow）。
func signRequest(t *testing.T, method, target string, body []byte, priv ed25519.PrivateKey, created, expires int64, nonce string) *http.Request {
	t.Helper()
	var br *strings.Reader
	if body != nil {
		br = strings.NewReader(string(body))
	} else {
		br = strings.NewReader("")
	}
	r := httptest.NewRequest(method, target, br)
	r.Host = "example.com"
	r.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	components := []string{"@method", "@authority", "@path"}
	if strings.Contains(target, "?") {
		components = append(components, "@query")
	}
	if body != nil {
		sum := sha256Of(body)
		r.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(sum)+":")
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
	sb.WriteString(`);created=` + itoa(created) + `;expires=` + itoa(expires) + `;nonce="` + nonce + `";keyid="k1";alg="ed25519"`)
	r.Header.Set("Signature-Input", sb.String())
	p, err := httpsig.ParseHeaders(sb.String(), "sig1=::", httpsig.DefaultBudgets())
	if err != nil {
		t.Fatalf("ParseHeaders: %v", err)
	}
	r.Header.Set("Signature", "sig1=::")
	base, _, err := httpsig.BuildSignatureBase(r, p)
	if err != nil {
		t.Fatalf("基线: %v", err)
	}
	sig := ed25519.Sign(priv, base)
	r.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return r
}

func sha256Of(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// ---------- 链矩阵 ----------

// testEvaluate 评估辅助（固定时钟+新鲜重放桩）。
func testEvaluate(t *testing.T, reg *Registry, r *http.Request, body []byte, replay *fakeReplayEval, jwtRes *jwtverify.VerificationResult, mode string) (*dsctx.RequestContext, *Result, *coverage.Observation) {
	t.Helper()
	cfg := &Config{
		AppID:    "app-1",
		Bindings: []Binding{{ID: "app-1|/foo", PathPrefix: "/foo", Mode: mode}},
		Registry: reg, IdentitySalt: "test-salt",
		Now: func() time.Time { return testNow },
	}
	ctx := dsctx.New("req-mid-1", dsctx.DefaultParseLimits())
	cov := Evaluate(ctx, r, body, cfg, wrapReplay(replay), jwtRes, true)
	return ctx, ResultFromContext(ctx), cov
}

func TestChainTenStepMatrix(t *testing.T) {
	priv := genEDPriv(t)
	edPub := priv.Public().(ed25519.PublicKey)
	reg := testRegistry(t, httpsig.AlgEd25519, edPub, nil)
	created := testNow.Add(-30 * time.Second).Unix() // 30s 前（偏移窗内）
	expires := testNow.Add(60 * time.Second).Unix()  // 寿命 90s（≤120 合法）
	nonce := "n8f6kfs9.2gkf0s9"
	body := []byte(`{"hello": "world"}`)
	valid := func() *http.Request {
		return signRequest(t, "POST", "/foo?param=Value&Pet=dog", body, priv, created, expires, nonce)
	}

	// 全通过 → VERIFIED
	t.Run("全步通过 VERIFIED", func(t *testing.T) {
		ctx, res, cov := testEvaluate(t, reg, valid(), body, newFakeReplay(), nil, ModeProtect)
		if res == nil || res.Status != StatusVerified {
			t.Fatalf("res = %+v", res)
		}
		if res.MachineIDFP == "" || res.KeyID != "k1" || res.RegistryVersion != 7 || res.Watermark != 3 {
			t.Fatalf("结果读数 = %+v", res)
		}
		if cov.Status != coverage.StatusFull {
			t.Fatalf("覆盖 = %s", cov.Status)
		}
		if m := findMIDMatch(ctx, CoverageRuleID); m == nil || m.Evidence["kid"] != "k1" || m.Evidence["identity_fp"] == "" {
			t.Fatalf("id.coverage_v1 = %+v", m)
		}
	})

	// 步 1：头形态畸形
	t.Run("步1 畸形", func(t *testing.T) {
		r := valid()
		r.Header.Set("Signature-Input", `sig1=("@method"`)
		_, res, _ := testEvaluate(t, reg, r, body, newFakeReplay(), nil, ModeProtect)
		assertReason(t, res, StatusInvalid, ReasonSignatureMalformed)
	})
	t.Run("步1 未签名+proof_required", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/foo?param=Value&Pet=dog", strings.NewReader(string(body)))
		r.Host = "example.com"
		reg2 := testRegistry(t, httpsig.AlgEd25519, edPub, nil)
		cfg := &Config{AppID: "app-1", Bindings: []Binding{{ID: "app-1|/foo", PathPrefix: "/foo", Mode: ModeProtect, ProofRequired: true}}, Registry: reg2, IdentitySalt: "s", Now: func() time.Time { return testNow }}
		ctx := dsctx.New("r1", dsctx.DefaultParseLimits())
		Evaluate(ctx, r, body, cfg, wrapReplay(newFakeReplay()), nil, true)
		assertReason(t, ResultFromContext(ctx), StatusInvalid, ReasonSignatureMalformed)
	})
	t.Run("未签名+proof_required=false NOT_APPLICABLE", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/foo", nil)
		r.Host = "example.com"
		_, res, cov := testEvaluate(t, reg, r, nil, newFakeReplay(), nil, ModeProtect)
		if res == nil || res.Status != StatusNotPresent {
			t.Fatalf("res = %+v", res)
		}
		if cov.Status != coverage.StatusNotApplicable || cov.NARuleID != NARuleUnsigned {
			t.Fatalf("cov = %+v", cov)
		}
	})
	// 步 2：keyid 未登记 / 身份 DISABLED
	t.Run("步2 keyid 未登记", func(t *testing.T) {
		r := valid()
		input := r.Header.Get("Signature-Input")
		r.Header.Set("Signature-Input", strings.Replace(input, `keyid="k1"`, `keyid="ghost"`, 1))
		_, res, _ := testEvaluate(t, reg, r, body, newFakeReplay(), nil, ModeProtect)
		assertReason(t, res, StatusInvalid, ReasonKeyUnknown)
	})
	t.Run("步2 身份 DISABLED 不可验", func(t *testing.T) {
		regD := testRegistry(t, httpsig.AlgEd25519, edPub, func(id *Identity) { id.Status = "DISABLED" })
		_, res, _ := testEvaluate(t, regD, valid(), body, newFakeReplay(), nil, ModeProtect)
		assertReason(t, res, StatusInvalid, ReasonKeyUnknown)
	})
	// 步 3：算法词表外/不一致
	t.Run("步3 alg 词表外", func(t *testing.T) {
		r := valid()
		r.Header.Set("Signature-Input", strings.Replace(r.Header.Get("Signature-Input"), `alg="ed25519"`, `alg="hmac-sha256"`, 1))
		_, res, _ := testEvaluate(t, reg, r, body, newFakeReplay(), nil, ModeProtect)
		assertReason(t, res, StatusInvalid, ReasonAlgRejected)
	})
	// 步 4：键状态机三形态
	t.Run("步4 REVOKED", func(t *testing.T) {
		regR := testRegistry(t, httpsig.AlgEd25519, edPub, func(id *Identity) {
			k := id.Keys["k1"]
			k.Status = "REVOKED"
			k.RevokedSeq = 5
			id.Keys["k1"] = k
		})
		_, res, _ := testEvaluate(t, regR, valid(), body, newFakeReplay(), nil, ModeProtect)
		assertReason(t, res, StatusInvalid, ReasonKeyRevoked)
	})
	t.Run("步4 RETIRED 窗口内放行/窗口外拒", func(t *testing.T) {
		regT := testRegistry(t, httpsig.AlgEd25519, edPub, func(id *Identity) {
			k := id.Keys["k1"]
			k.Status = "RETIRED"
			until := testNow.Add(time.Hour)
			k.RetireOverlapUntil = &until
			id.Keys["k1"] = k
		})
		_, res, _ := testEvaluate(t, regT, valid(), body, newFakeReplay(), nil, ModeProtect)
		if res == nil || res.Status != StatusVerified {
			t.Fatalf("窗口内应放行: %+v", res)
		}
		regT2 := testRegistry(t, httpsig.AlgEd25519, edPub, func(id *Identity) {
			k := id.Keys["k1"]
			k.Status = "RETIRED"
			until := testNow.Add(-time.Hour)
			k.RetireOverlapUntil = &until
			id.Keys["k1"] = k
		})
		_, res2, _ := testEvaluate(t, regT2, valid(), body, newFakeReplay(), nil, ModeProtect)
		assertReason(t, res2, StatusInvalid, ReasonKeyRetiredExpired)
	})
	t.Run("步4 生效域外", func(t *testing.T) {
		regE := testRegistry(t, httpsig.AlgEd25519, edPub, func(id *Identity) {
			k := id.Keys["k1"]
			nb := testNow.Add(time.Hour)
			k.NotBefore = &nb
			id.Keys["k1"] = k
		})
		_, res, _ := testEvaluate(t, regE, valid(), body, newFakeReplay(), nil, ModeProtect)
		assertReason(t, res, StatusInvalid, ReasonKeyExpired)
	})
	// 步 5：时效三形态
	t.Run("步5 未来日戳", func(t *testing.T) {
		future := testNow.Add(200 * time.Second).Unix()
		_, res, _ := testEvaluate(t, reg, signRequest(t, "POST", "/foo?param=Value&Pet=dog", body, priv, future, future+90, nonce), body, newFakeReplay(), nil, ModeProtect)
		assertReason(t, res, StatusInvalid, ReasonClockSkew)
	})
	t.Run("步5 过期", func(t *testing.T) {
		past := testNow.Add(-200 * time.Second).Unix()
		_, res, _ := testEvaluate(t, reg, signRequest(t, "POST", "/foo?param=Value&Pet=dog", body, priv, past, past+90, nonce), body, newFakeReplay(), nil, ModeProtect)
		assertReason(t, res, StatusInvalid, ReasonProofExpired)
	})
	t.Run("步5 寿命超 120s", func(t *testing.T) {
		c2 := testNow.Add(-60 * time.Second).Unix()
		_, res, _ := testEvaluate(t, reg, signRequest(t, "POST", "/foo?param=Value&Pet=dog", body, priv, c2, c2+300, nonce), body, newFakeReplay(), nil, ModeProtect)
		assertReason(t, res, StatusInvalid, ReasonProofExpired)
	})
	t.Run("步5 nonce 形态", func(t *testing.T) {
		_, res, _ := testEvaluate(t, reg, signRequest(t, "POST", "/foo?param=Value&Pet=dog", body, priv, created, expires, "short"), body, newFakeReplay(), nil, ModeProtect)
		assertReason(t, res, StatusInvalid, ReasonNonceInvalid)
	})
	// 步 6：覆盖不足（缺 @query）
	t.Run("步6 覆盖不足", func(t *testing.T) {
		// 手工构造缺 @query 的签名头（签名本身仍合法——覆盖门先于验签拒绝）
		r := valid()
		input := r.Header.Get("Signature-Input")
		r.Header.Set("Signature-Input", strings.Replace(input, ` "@query"`, "", 1))
		_, res, _ := testEvaluate(t, reg, r, body, newFakeReplay(), nil, ModeProtect)
		assertReason(t, res, StatusInvalid, ReasonCoverageInsufficient)
	})
	// 步 8：体摘要篡改
	t.Run("步8 digest 篡改", func(t *testing.T) {
		r := valid()
		_, res, _ := testEvaluate(t, reg, r, []byte(`{"hello": "evil"}`), newFakeReplay(), nil, ModeProtect)
		assertReason(t, res, StatusInvalid, ReasonDigestMismatch)
	})
	// 步 9：目标篡改 → 验签失败（目标绑定与验签不可分割部分并入 SIGNATURE-INVALID
	// ——登记偏差；成分不可得的局部可证子集见下）
	t.Run("步9 目标篡改验签拒绝", func(t *testing.T) {
		r := valid()
		r.Method = "GET"
		_, res, _ := testEvaluate(t, reg, r, body, newFakeReplay(), nil, ModeProtect)
		assertReason(t, res, StatusInvalid, ReasonSignatureInvalid)
	})
	t.Run("步7 成分不可得→TARGET-MISMATCH", func(t *testing.T) {
		// 覆盖含请求不存在的头成分（签名目标含本请求不存在的成分——可证不一致）
		r := valid()
		input := r.Header.Get("Signature-Input")
		r.Header.Set("Signature-Input", strings.Replace(input, `"@method"`, `"@method" "x-custom-ghost"`, 1))
		_, res, _ := testEvaluate(t, reg, r, body, newFakeReplay(), nil, ModeProtect)
		assertReason(t, res, StatusInvalid, ReasonTargetMismatch)
	})
	// 步 10：重放检出/存储故障
	t.Run("步10 重放检出", func(t *testing.T) {
		replay := newFakeReplay()
		testEvaluate(t, reg, valid(), body, replay, nil, ModeProtect) // 首次登记
		_, res, _ := testEvaluate(t, reg, valid(), body, replay, nil, ModeProtect)
		assertReason(t, res, StatusInvalid, ReasonReplayDetected)
	})
	t.Run("步10 存储故障 UNAVAILABLE", func(t *testing.T) {
		replay := newFakeReplay()
		replay.err = errFakeStore
		_, res, cov := testEvaluate(t, reg, valid(), body, replay, nil, ModeProtect)
		if res == nil || res.Status != StatusUnavailable {
			t.Fatalf("res = %+v", res)
		}
		if res.ReasonCode != "" {
			t.Fatalf("UNAVAILABLE 非证明判定 reason 应空: %q", res.ReasonCode)
		}
		if cov.ReasonCode != coverage.ReasonDependencyUnavailable {
			t.Fatalf("cov = %+v", cov)
		}
	})
	// 登记册缺席
	t.Run("登记册缺席 COV_NO_REGISTRY", func(t *testing.T) {
		cfg := &Config{AppID: "app-1", Bindings: []Binding{{ID: "app-1|/foo", PathPrefix: "/foo", Mode: ModeProtect}}, IdentitySalt: "s", Now: func() time.Time { return testNow }}
		ctx := dsctx.New("r2", dsctx.DefaultParseLimits())
		cov := Evaluate(ctx, valid(), body, cfg, wrapReplay(newFakeReplay()), nil, true)
		res := ResultFromContext(ctx)
		if res == nil || res.Status != StatusUnavailable || cov.ReasonCode != coverage.ReasonNoRegistry {
			t.Fatalf("res/cov = %+v %+v", res, cov)
		}
	})
	// principal_binding 一致性
	t.Run("principal_binding 一致/不一致", func(t *testing.T) {
		regP := testRegistry(t, httpsig.AlgEd25519, edPub, func(id *Identity) {
			id.PrincipalBinding = principalFingerprint("test-salt", "user-1")
		})
		jwtV := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-1"}
		_, res, _ := testEvaluate(t, regP, valid(), body, newFakeReplay(), jwtV, ModeProtect)
		if res == nil || res.Status != StatusVerified {
			t.Fatalf("一致应通过: %+v", res)
		}
		jwtBad := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-2"}
		_, res2, _ := testEvaluate(t, regP, valid(), body, newFakeReplay(), jwtBad, ModeProtect)
		assertReason(t, res2, StatusInvalid, ReasonPrincipalMismatch)
		// JWT 缺席：机器身份独立成立（I02——不冒充人类主体）
		_, res3, _ := testEvaluate(t, regP, valid(), body, newFakeReplay(), nil, ModeProtect)
		if res3 == nil || res3.Status != StatusVerified {
			t.Fatalf("JWT 缺席应独立成立: %+v", res3)
		}
	})
	// 重放存储 nil → UNAVAILABLE（严禁本机去重）
	t.Run("存储 nil 严禁本机去重", func(t *testing.T) {
		_, res, _ := testEvaluate(t, reg, valid(), body, nil, nil, ModeProtect)
		if res == nil || res.Status != StatusUnavailable {
			t.Fatalf("res = %+v", res)
		}
	})
	// 短路断言：keyid 未知不产后续步骤
	t.Run("固定序短路", func(t *testing.T) {
		r := valid()
		input := r.Header.Get("Signature-Input")
		r.Header.Set("Signature-Input", strings.Replace(input, `keyid="k1"`, `keyid="ghost"`, 1))
		ctx, _, _ := testEvaluate(t, reg, r, body, newFakeReplay(), nil, ModeProtect)
		if n := len(ctx.CopyMatches()); n != 2 { // coverage + 一条违规
			t.Fatalf("短路后明细数 = %d", n)
		}
	})
}

// assertReason 断言结果状态与 reason。
func assertReason(t *testing.T, res *Result, status, reason string) {
	t.Helper()
	if res == nil {
		t.Fatalf("结果 nil（应 %s/%s）", status, reason)
	}
	if res.Status != status || res.ReasonCode != reason {
		t.Fatalf("res = %s/%s，应 %s/%s", res.Status, res.ReasonCode, status, reason)
	}
}

func findMIDMatch(ctx *dsctx.RequestContext, ruleID string) *dsctx.DetectorMatch {
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == ruleID {
			mm := m
			return &mm
		}
	}
	return nil
}

var errFakeStore = errors.New("fake store down")

func TestC07MatchBindingPathCanonicalAndBoundary(t *testing.T) {
	cfg := &Config{
		Bindings: []Binding{
			{ID: "b-api", PathPrefix: "/api", Mode: ModeProtect},
			{ID: "b-exact", PathExact: "/exact/endpoint", Mode: ModeProtect},
		},
	}
	for _, wantMatch := range []string{"/api", "/api/", "/api/v1", "//api//v1", "/x/../api/v1", "/./exact//endpoint", "/a/../exact/endpoint"} {
		if !cfg.MatchBindingPath(wantMatch) {
			t.Fatalf("MatchBindingPath(%q) = false, want true", wantMatch)
		}
	}
	for _, wantNoMatch := range []string{"/apiv2", "/apiv2/orders", "/api_admin", "/exact/endpoint/extra"} {
		if cfg.MatchBindingPath(wantNoMatch) {
			t.Fatalf("MatchBindingPath(%q) = true, want false (must enforce '/' boundary)", wantNoMatch)
		}
	}
}

func TestH10ChunkedOversizedAndReplayTTLWindow(t *testing.T) {
	priv := genEDPriv(t)
	edPub := priv.Public().(ed25519.PublicKey)
	reg := testRegistry(t, httpsig.AlgEd25519, edPub, nil)
	created := testNow.Add(-10 * time.Second).Unix()
	expires := testNow.Add(60 * time.Second).Unix()

	t.Run("chunked 无 content-digest + BodyUnavailableExtension 必须 fail-closed UNAVAILABLE", func(t *testing.T) {
		// 构造未覆盖 content-digest 的签名头，模拟攻击者发送 >4MiB chunked 请求试图当作空体通过
		r := signRequest(t, "POST", "/foo", nil, priv, created, expires, "nonce-chunked-1")
		r.ContentLength = -1
		r.Body = http.NoBody
		cfg := &Config{
			AppID:    "app-1",
			Bindings: []Binding{{ID: "app-1|/foo", PathPrefix: "/foo", Mode: ModeProtect}},
			Registry: reg, IdentitySalt: "test-salt",
			Now: func() time.Time { return testNow },
		}
		ctx := dsctx.New("req-h10-chunked", dsctx.DefaultParseLimits())
		ctx.SetExtension(BodyUnavailableExtension, "body_exceeds_preserve_limit")
		Evaluate(ctx, r, nil, cfg, wrapReplay(newFakeReplay()), nil, true)
		res := ResultFromContext(ctx)
		if res == nil || res.Status != StatusUnavailable {
			t.Fatalf("chunked 超限请求不得被当作空体 VERIFIED，应 UNAVAILABLE: %+v", res)
		}
		if findMIDMatch(ctx, "machineid.body_unavailable") == nil {
			t.Fatalf("缺少 machineid.body_unavailable 明细: %+v", ctx.CopyMatches())
		}
	})

	t.Run("proofTTL 覆盖完整 expires+skew 接受窗口", func(t *testing.T) {
		skew := int64(30)
		p := &httpsig.Params{Created: testNow.Unix(), Expires: testNow.Add(120 * time.Second).Unix()}
		ttl := proofTTL(p, testNow, skew)
		if ttl != 150*time.Second {
			t.Fatalf("proofTTL=%v want 150s (expires+skew)", ttl)
		}
		// 已过 expires 但仍在 expires+skew 容差窗内：TTL 仍须覆盖剩余 skew 窗
		afterExp := testNow.Add(130 * time.Second)
		ttlInSkew := proofTTL(p, afterExp, skew)
		if ttlInSkew != 20*time.Second {
			t.Fatalf("skew 窗内 proofTTL=%v want 20s", ttlInSkew)
		}
		// 最大正偏移边界（created = now+skew, expires = now+skew+120）：上限 120+2*skew = 180s
		pMax := &httpsig.Params{Created: testNow.Add(30 * time.Second).Unix(), Expires: testNow.Add(150 * time.Second).Unix()}
		if ttlMax := proofTTL(pMax, testNow, skew); ttlMax != 180*time.Second {
			t.Fatalf("最大偏移边界 proofTTL=%v want 180s", ttlMax)
		}
	})
}
