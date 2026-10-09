// authzdecide_az3_test.go NG-AZ-03 VERIFIED_VIOLATION 决策与实断资格测试
// （经 EvaluateAuthorization 端到端）：
//   - §1.2 八因子资格真值表：任一因子不真 → 既有 reason code 落 UNKNOWN（或
//     TENANT-001 OBSERVE_VIOLATION），绝不折算、绝不实断（UNKNOWN 不误断红线）；
//   - §1.1 双闸：端点 enforcement=PROTECT 且决策引擎 PROTECT 语义才落
//     VERIFIED_VIOLATION + category=BLOCK finding；OBSERVE 形态降级
//     OBSERVE_VIOLATION 同语义记录（拟动作保留 ProposedDecision）；
//   - §1.4 authz_enforcement 证据逐键完整性（BOLA 冻结十五键 + 八因子布尔）；
//   - BFLA 行级/继承两态；v1/v2 快照无 enforcement 字段零变化。
package detectors

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// v3Fixture NG-AZ-03 夹具（v2 schema + enforcement=PROTECT 模型 + 决策引擎
// PROTECT 语义；默认 OTHER_OWNER 场景——关系属主 user-1，请求主体 user-2）。
type v3Fixture struct {
	cfg  AuthorizationConfig
	path string
	jwt  *jwtverify.VerificationResult
}

func newV3Fixture(t *testing.T, mutate func(*AuthorizationConfig, *ObjectModel)) v3Fixture {
	t.Helper()
	model := ObjectModel{
		EndpointKey: "GET /orders/{orderId}", ObjectType: "ORDER",
		PathTemplate: "/orders/{orderId}", Identifiers: []ObjectIdentifier{{Location: "path", Name: "orderId", Primary: true}},
		RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true,
		Enforcement: "PROTECT", EnforcementOwner: "zhang.lei@example.com", EvidenceSource: "AUTHORITY_SYNC", OnUnknown: "ALLOW_UNKNOWN",
		ModelVersion: "model-v9",
	}
	ref := ObjectRefHMAC([]byte("obj-secret"), "7")
	produced := v2Now.Add(-time.Minute)
	cfg := AuthorizationConfig{
		EndpointKey: "GET /orders/7", Models: []ObjectModel{model}, ObjectRefHMACKey: []byte("obj-secret"),
		Relations:           []ObjectRelation{{PrincipalID: "user-1", ObjectType: "ORDER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED"}},
		Now:                 func() time.Time { return v2Now },
		PolicyVersion:       "authz-v3",
		Schema:              AuthzSnapshotSchemaV2,
		RevocationWatermark: &RevocationWatermark{ManualSeq: 7, Sources: map[string]int64{"src-a": 3}},
		LeaseSeconds:        60,
		AppliedAt:           v2Now.Add(-12 * time.Second),
		ProducedAt:          &produced,
		EngineProtect:       true,
	}
	if mutate != nil {
		mutate(&cfg, &cfg.Models[0])
	}
	return v3Fixture{cfg: cfg, path: "/orders/7",
		jwt: &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-2"}}
}

func (f v3Fixture) eval(t *testing.T) (*AuthorizationDecisionGroup, *dsctx.RequestContext) {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "https://example.test"+f.path, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := dsctx.New("req-v3", dsctx.DefaultParseLimits())
	parsed, err := parser.ParseRequest(r, ctx)
	if err != nil {
		t.Fatal(err)
	}
	return EvaluateAuthorization(ctx, parsed, f.cfg, f.jwt), ctx
}

// v3AssertNeverBlocked UNKNOWN/OBSERVE 不误断红线断言：无 VERIFIED_VIOLATION
// 检查、无 BLOCK 类明细、无实断证据。
func v3AssertNeverBlocked(t *testing.T, group *AuthorizationDecisionGroup, ctx *dsctx.RequestContext) {
	t.Helper()
	if group != nil {
		if group.Decision == AuthorizationVerifiedViolation {
			t.Fatalf("组决策不得为 VERIFIED_VIOLATION: %+v", group)
		}
		for _, c := range group.Checks {
			if c.Decision == AuthorizationVerifiedViolation {
				t.Fatalf("检查不得为 VERIFIED_VIOLATION: %+v", c)
			}
		}
	}
	for _, m := range ctx.CopyMatches() {
		if strings.EqualFold(m.Category, "BLOCK") {
			t.Fatalf("UNKNOWN/OBSERVE 绝不映射 BLOCK（红线）: %+v", m)
		}
	}
	if ev := AuthzEnforcementEvidenceFromContext(ctx); ev != nil {
		t.Fatalf("非实断路径不得生成 authz_enforcement 证据: %+v", ev)
	}
}

func v3PrimaryCheck(t *testing.T, group *AuthorizationDecisionGroup) AuthorizationCheck {
	t.Helper()
	if group == nil || len(group.Checks) == 0 {
		t.Fatalf("group=%+v", group)
	}
	return group.Checks[0]
}

// 八因子全真 + 双 PROTECT → VERIFIED_VIOLATION + BLOCK finding + §1.4 证据逐键。
func TestV3BOLAVerifiedViolationProtectEnforced(t *testing.T) {
	f := newV3Fixture(t, nil)
	group, ctx := f.eval(t)
	if group == nil || group.Decision != AuthorizationVerifiedViolation {
		t.Fatalf("组决策应 VERIFIED_VIOLATION: %+v", group)
	}
	check := v3PrimaryCheck(t, group)
	if check.Decision != AuthorizationVerifiedViolation || check.ReasonCode != "AUTHZ-BOLA-001" || check.RelationState != "OTHER_OWNER" {
		t.Fatalf("BOLA 检查应 VERIFIED_VIOLATION+AUTHZ-BOLA-001+OTHER_OWNER: %+v", check)
	}
	if check.ProposedDecision != "" {
		t.Fatalf("实断路径不留拟动作: %+v", check)
	}
	if check.ModelVersion != "model-v9" || check.PolicyVersion != "authz-v3" {
		t.Fatalf("版本戳不符: %+v", check)
	}
	// BLOCK finding：category=BLOCK + rule_id=AUTHZ-BOLA-001 + evidence.enforced=true（D4）
	var blockMatch *dsctx.DetectorMatch
	for i, m := range ctx.CopyMatches() {
		if m.Detector == "api_authz" && strings.EqualFold(m.Category, "BLOCK") {
			blockMatch = &ctx.CopyMatches()[i]
		}
	}
	if blockMatch == nil {
		t.Fatalf("VERIFIED_VIOLATION 应以 category=BLOCK 写 ctx: %+v", ctx.CopyMatches())
	}
	if blockMatch.RuleID != "AUTHZ-BOLA-001" || blockMatch.Evidence["enforced"] != "true" ||
		blockMatch.Evidence["decision"] != "VERIFIED_VIOLATION" || blockMatch.Evidence["reason_code"] != "AUTHZ-BOLA-001" {
		t.Fatalf("BLOCK finding 形状不符: %+v", blockMatch)
	}
	// §1.4 证据：十五冻结键逐键核对
	ev := AuthzEnforcementEvidenceFromContext(ctx)
	if ev == nil {
		t.Fatal("实断必须生成 authz_enforcement 证据")
	}
	if ev.Decision != "VERIFIED_VIOLATION" || ev.ReasonCode != "AUTHZ-BOLA-001" || !ev.Enforced {
		t.Fatalf("证据决策头不符: %+v", ev)
	}
	if ev.EndpointKey != "GET /orders/{orderId}" || ev.ModelVersion != "model-v9" || ev.PolicyVersion != "authz-v3" {
		t.Fatalf("证据端点/版本不符: %+v", ev)
	}
	if ev.RevocationWatermark.ManualSeq != 7 || ev.RevocationWatermark.Sources["src-a"] != 3 {
		t.Fatalf("证据水位不符: %+v", ev.RevocationWatermark)
	}
	if ev.PrincipalSource != "JWT_VERIFIED" || ev.ObjectRef != ObjectRefHMAC([]byte("obj-secret"), "7") {
		t.Fatalf("证据主体/对象不符: %+v", ev)
	}
	if ev.LeaseSeconds != 60 || ev.AppliedAtAgeSeconds != 12 {
		t.Fatalf("证据租约读数不符: %+v", ev)
	}
	if ev.EnforcementOwner != "zhang.lei@example.com" || ev.EvidenceSource != "AUTHORITY_SYNC" {
		t.Fatalf("证据四要素不符: %+v", ev)
	}
	if _, err := time.Parse(time.RFC3339Nano, ev.RecordedAt); err != nil {
		t.Fatalf("recorded_at 非 RFC3339: %q", ev.RecordedAt)
	}
	// 八因子逐键全真（§1.4 eligibility 冻结八键）
	wantFactors := []string{"trusted_identity", "model_applicable", "relation_valid", "no_conflict",
		"tenant_consistent", "evidence_fresh", "other_owner", "owner_exclusive"}
	if len(ev.Eligibility) != len(wantFactors) {
		t.Fatalf("eligibility 键数不符: %+v", ev.Eligibility)
	}
	for _, k := range wantFactors {
		if ok, present := ev.Eligibility[k]; !present || !ok {
			t.Fatalf("eligibility.%s 应为 true: %+v", k, ev.Eligibility)
		}
	}
	// 序列化键完整性（冻结键集合精确相等，多/少键即违约）
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]any
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{"decision", "reason_code", "enforced", "endpoint_key", "model_version", "policy_version",
		"revocation_watermark", "principal_source", "object_ref", "eligibility", "lease_seconds",
		"applied_at_age_seconds", "enforcement_owner", "evidence_source", "recorded_at"}
	if len(keys) != len(wantKeys) {
		t.Fatalf("证据键数 %d ≠ 冻结 %d: %s", len(keys), len(wantKeys), raw)
	}
	for _, k := range wantKeys {
		if _, present := keys[k]; !present {
			t.Fatalf("证据缺冻结键 %s: %s", k, raw)
		}
	}
}

// §1.2 真值表负向矩阵：任一因子不真 → 既有 reason code 落 UNKNOWN
// （或 TENANT-001 OBSERVE_VIOLATION / degraded 标记），绝不实断。
func TestV3BOLAEligibilityNegativeMatrix(t *testing.T) {
	cases := []struct {
		name         string
		mutate       func(*AuthorizationConfig, *ObjectModel)
		mutateJWT    func(*jwtverify.VerificationResult)
		wantDecision AuthorizationDecision
		wantReason   string
	}{
		{name: "主体不可信(未验证)", mutateJWT: func(j *jwtverify.VerificationResult) {
			j.Status = jwtverify.StatusUnverified
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-IDENTITY-001"},
		{name: "主体不可信(主体为空)", mutateJWT: func(j *jwtverify.VerificationResult) {
			j.VerifiedPrincipalID = ""
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-IDENTITY-001"},
		{name: "模型不可发布", mutate: func(_ *AuthorizationConfig, m *ObjectModel) {
			m.Publishable = false
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-POLICY-001"},
		{name: "非排他所有权", mutate: func(_ *AuthorizationConfig, m *ObjectModel) {
			m.OwnerExclusive = false
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-POLICY-001"},
		{name: "非OWNER必需关系", mutate: func(_ *AuthorizationConfig, m *ObjectModel) {
			m.RequiredRelation = "EDITOR"
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-POLICY-001"},
		{name: "多模型匹配", mutate: func(cfg *AuthorizationConfig, m *ObjectModel) {
			dup := *m
			cfg.Models = append(cfg.Models, dup)
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-POLICY-001"},
		{name: "模型stale", mutate: func(_ *AuthorizationConfig, m *ObjectModel) {
			m.Stale = true
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-POLICY-002"},
		{name: "关系已撤销", mutate: func(cfg *AuthorizationConfig, _ *ObjectModel) {
			cfg.Relations[0].Status = "REVOKED"
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-RELATION-001"},
		{name: "关系未生效", mutate: func(cfg *AuthorizationConfig, _ *ObjectModel) {
			from := v2Now.Add(time.Minute)
			cfg.Relations[0].ValidFrom = &from
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-RELATION-001"},
		{name: "关系已过期", mutate: func(cfg *AuthorizationConfig, _ *ObjectModel) {
			until := v2Now.Add(-time.Minute)
			cfg.Relations[0].ValidUntil = &until
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-RELATION-001"},
		{name: "无有效关系NONE", mutate: func(cfg *AuthorizationConfig, _ *ObjectModel) {
			cfg.Relations = nil
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-RELATION-001"},
		{name: "关系主体不足INSUFFICIENT", mutate: func(cfg *AuthorizationConfig, _ *ObjectModel) {
			cfg.Relations[0].PrincipalID = ""
			cfg.Relations[0].SubjectPrincipalID = ""
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-BOLA-002"},
		{name: "OPEN冲突对象", mutate: func(cfg *AuthorizationConfig, _ *ObjectModel) {
			cfg.ConflictedObjects = []ConflictedObject{{ObjectType: "ORDER", ObjectRef: ObjectRefHMAC([]byte("obj-secret"), "7")}}
			cfg.ConflictedIndex = BuildConflictedObjectIndex(cfg.ConflictedObjects)
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-CONFLICT-001"},
		{name: "租约过期strict", mutate: func(cfg *AuthorizationConfig, _ *ObjectModel) {
			cfg.AppliedAt = v2Now.Add(-2 * time.Minute)
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-LEASE-001"},
		{name: "时钟漂移strict", mutate: func(cfg *AuthorizationConfig, _ *ObjectModel) {
			produced := v2Now.Add(5 * time.Minute)
			cfg.ProducedAt = &produced
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-CLOCK-001"},
		{name: "租户冲突", mutate: func(cfg *AuthorizationConfig, _ *ObjectModel) {
			cfg.Relations = append(cfg.Relations, ObjectRelation{PrincipalID: "user-3", ObjectType: "ORDER",
				ObjectRef: cfg.Relations[0].ObjectRef, Relation: "OWNER", Status: "CONFIRMED", TenantID: "tenant-b"})
			cfg.Relations[0].TenantID = "tenant-a"
		}, mutateJWT: func(j *jwtverify.VerificationResult) {
			j.VerifiedTenantID = "tenant-a"
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-TENANT-002"},
		{name: "租户不完整", mutate: func(_ *AuthorizationConfig, _ *ObjectModel) {
		}, mutateJWT: func(j *jwtverify.VerificationResult) {
			j.VerifiedTenantID = "tenant-a"
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-TENANT-002"},
		{name: "租户不一致维持OBSERVE不实断", mutate: func(cfg *AuthorizationConfig, _ *ObjectModel) {
			cfg.Relations[0].TenantID = "tenant-b"
		}, mutateJWT: func(j *jwtverify.VerificationResult) {
			j.VerifiedTenantID = "tenant-a"
		}, wantDecision: AuthorizationObserveViolation, wantReason: "AUTHZ-TENANT-001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newV3Fixture(t, tc.mutate)
			if tc.mutateJWT != nil {
				tc.mutateJWT(f.jwt)
			}
			group, ctx := f.eval(t)
			check := v3PrimaryCheck(t, group)
			if check.Decision != tc.wantDecision || check.ReasonCode != tc.wantReason {
				t.Fatalf("决策=%s reason=%s，期望 %s/%s: %+v", check.Decision, check.ReasonCode, tc.wantDecision, tc.wantReason, check)
			}
			v3AssertNeverBlocked(t, group, ctx)
		})
	}
}

// 时效异常 degraded：评估继续但 evidence_fresh=false → OBSERVE_VIOLATION +
// UNKNOWN 标记，绝不升级实断（D7 交互矩阵「lease 过期 degraded：评估+标记但放行」）。
func TestV3BOLADegradedLeaseExpiredNeverVerified(t *testing.T) {
	f := newV3Fixture(t, func(cfg *AuthorizationConfig, m *ObjectModel) {
		cfg.AppliedAt = v2Now.Add(-2 * time.Minute)
		m.OnLeaseExpired = "degraded"
	})
	group, ctx := f.eval(t)
	checks := checksOf(group)
	var sawViolation, sawMarker bool
	for _, c := range checks {
		if c.Decision == AuthorizationObserveViolation && c.ReasonCode == "AUTHZ-BOLA-001" && c.RelationState == "OTHER_OWNER" {
			sawViolation = true
			if c.ProposedDecision != "" {
				t.Fatalf("资格不全（evidence_fresh=false）不得留拟动作: %+v", c)
			}
		}
		if c.Decision == AuthorizationUnknown && c.ReasonCode == "AUTHZ-LEASE-002" {
			sawMarker = true
		}
	}
	if !sawViolation || !sawMarker {
		t.Fatalf("degraded 租约过期应 OBSERVE_VIOLATION+LEASE-002 标记: %+v", checks)
	}
	v3AssertNeverBlocked(t, group, ctx)
}

// §1.1 降级链：资格全真但 OBSERVE 形态（端点 OBSERVE / 决策引擎 OBSERVE）→
// OBSERVE_VIOLATION 同语义记录 + 拟动作保留，不实断。
func TestV3BOLAObserveFormsDowngrade(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*AuthorizationConfig, *ObjectModel)
	}{
		{name: "端点OBSERVE+引擎PROTECT", mutate: func(_ *AuthorizationConfig, m *ObjectModel) {
			m.Enforcement = "OBSERVE"
		}},
		{name: "端点PROTECT+引擎OBSERVE", mutate: func(cfg *AuthorizationConfig, _ *ObjectModel) {
			cfg.EngineProtect = false
		}},
		{name: "端点OBSERVE+引擎OBSERVE", mutate: func(cfg *AuthorizationConfig, m *ObjectModel) {
			cfg.EngineProtect = false
			m.Enforcement = "OBSERVE"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newV3Fixture(t, tc.mutate)
			group, ctx := f.eval(t)
			check := v3PrimaryCheck(t, group)
			if check.Decision != AuthorizationObserveViolation || check.ReasonCode != "AUTHZ-BOLA-001" {
				t.Fatalf("OBSERVE 形态应降级 OBSERVE_VIOLATION: %+v", check)
			}
			if check.ProposedDecision != AuthorizationVerifiedViolation {
				t.Fatalf("拟动作保留缺失（资格全真应留 VERIFIED_VIOLATION 拟判定）: %+v", check)
			}
			if group.Decision != AuthorizationObserveViolation {
				t.Fatalf("组决策应 OBSERVE_VIOLATION: %+v", group)
			}
			v3AssertNeverBlocked(t, group, ctx)
			// 明细证据携带拟动作（details evidence 是 §1.1 允许出现新值的位置之一）
			var found bool
			for _, m := range ctx.CopyMatches() {
				if m.Detector == "api_authz" && m.Evidence["proposed_decision"] == "VERIFIED_VIOLATION" &&
					strings.EqualFold(m.Category, "OBSERVE") {
					found = true
				}
			}
			if !found {
				t.Fatalf("OBSERVE 明细应携带 proposed_decision=VERIFIED_VIOLATION: %+v", ctx.CopyMatches())
			}
		})
	}
}

// 零变化纪律：enforcement 未配置（v1/v2 旧快照无字段）→ 逐字节既有行为——
// OBSERVE_VIOLATION 无拟动作留痕、无实断证据、无明细新增键。
func TestV3UnconfiguredEnforcementZeroChange(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*AuthorizationConfig, *ObjectModel)
	}{
		{name: "v2快照无enforcement字段", mutate: func(_ *AuthorizationConfig, m *ObjectModel) {
			m.Enforcement, m.EnforcementOwner, m.EvidenceSource, m.OnUnknown = "", "", "", ""
		}},
		{name: "v1快照无enforcement字段", mutate: func(cfg *AuthorizationConfig, m *ObjectModel) {
			m.Enforcement, m.EnforcementOwner, m.EvidenceSource, m.OnUnknown = "", "", "", ""
			cfg.Schema = ""
			cfg.RevocationWatermark = nil
			cfg.LeaseSeconds = 0
			cfg.AppliedAt = time.Time{}
			cfg.ProducedAt = nil
			cfg.EngineProtect = false
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newV3Fixture(t, tc.mutate)
			group, ctx := f.eval(t)
			check := v3PrimaryCheck(t, group)
			if check.Decision != AuthorizationObserveViolation || check.ReasonCode != "AUTHZ-BOLA-001" {
				t.Fatalf("未配置应维持既有 OBSERVE_VIOLATION: %+v", check)
			}
			if check.ProposedDecision != "" {
				t.Fatalf("未配置 enforcement 不得留拟动作痕（零变化）: %+v", check)
			}
			v3AssertNeverBlocked(t, group, ctx)
			raw, err := json.Marshal(check)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "proposed_decision") || strings.Contains(string(raw), "VERIFIED_VIOLATION") {
				t.Fatalf("未配置快照检查 JSON 必须零变化: %s", raw)
			}
			for _, m := range ctx.CopyMatches() {
				if _, present := m.Evidence["proposed_decision"]; present {
					t.Fatalf("未配置快照明细证据必须零变化: %+v", m)
				}
				if _, present := m.Evidence["enforced"]; present {
					t.Fatalf("未配置快照明细证据必须零变化: %+v", m)
				}
			}
		})
	}
}

// v3BFLAFixture BFLA 夹具（角色基线 + 可选端点模型）。
func v3BFLAConfig(t *testing.T, mutate func(*AuthorizationConfig)) AuthorizationConfig {
	t.Helper()
	produced := v2Now.Add(-time.Minute)
	cfg := AuthorizationConfig{
		EndpointKey:         "GET /admin/users",
		Now:                 func() time.Time { return v2Now },
		PolicyVersion:       "authz-v3",
		Schema:              AuthzSnapshotSchemaV2,
		RevocationWatermark: &RevocationWatermark{ManualSeq: 7, Sources: map[string]int64{"src-a": 3}},
		LeaseSeconds:        60,
		AppliedAt:           v2Now.Add(-12 * time.Second),
		ProducedAt:          &produced,
		EngineProtect:       true,
		RoleBaselines: []VerifiedRoleBaseline{
			{EndpointKey: "GET /admin/users", Method: "GET", Role: "reader", Allowed: true, Confirmed: true},
			{EndpointKey: "GET /admin/users", Method: "GET", Role: "ops", Allowed: false, Confirmed: true, Enforcement: "PROTECT"},
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return cfg
}

func v3EvalBFLA(t *testing.T, cfg AuthorizationConfig, jwt *jwtverify.VerificationResult) (*AuthorizationDecisionGroup, *dsctx.RequestContext) {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "https://example.test/admin/users", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := dsctx.New("req-v3-bfla", dsctx.DefaultParseLimits())
	parsed, err := parser.ParseRequest(r, ctx)
	if err != nil {
		t.Fatal(err)
	}
	return EvaluateAuthorization(ctx, parsed, cfg, jwt), ctx
}

// BFLA 行级 PROTECT：显式 deny 行违规 → VERIFIED_VIOLATION + BLOCK finding +
// 证据（行级无伴随列——enforcement_owner/evidence_source/model_version 置空、
// object_ref 置空；eligibility 为 BFLA 资格键集）。
func TestV3BFLAVerifiedViolationRowLevelProtect(t *testing.T) {
	cfg := v3BFLAConfig(t, nil)
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-2", VerifiedRoles: []string{"ops"}}
	group, ctx := v3EvalBFLA(t, cfg, jwt)
	check := v3PrimaryCheck(t, group)
	if check.Decision != AuthorizationVerifiedViolation || check.ReasonCode != "AUTHZ-BFLA-001" || check.Type != "BFLA" {
		t.Fatalf("BFLA 检查应 VERIFIED_VIOLATION+AUTHZ-BFLA-001: %+v", check)
	}
	if group.Decision != AuthorizationVerifiedViolation {
		t.Fatalf("组决策应 VERIFIED_VIOLATION: %+v", group)
	}
	var blockMatch *dsctx.DetectorMatch
	for i, m := range ctx.CopyMatches() {
		if m.Detector == "api_authz" && strings.EqualFold(m.Category, "BLOCK") {
			blockMatch = &ctx.CopyMatches()[i]
		}
	}
	if blockMatch == nil || blockMatch.RuleID != "AUTHZ-BFLA-001" || blockMatch.Evidence["enforced"] != "true" {
		t.Fatalf("BFLA BLOCK finding 形状不符: %+v", ctx.CopyMatches())
	}
	ev := AuthzEnforcementEvidenceFromContext(ctx)
	if ev == nil {
		t.Fatal("BFLA 实断必须生成 authz_enforcement 证据")
	}
	if ev.Decision != "VERIFIED_VIOLATION" || ev.ReasonCode != "AUTHZ-BFLA-001" || !ev.Enforced {
		t.Fatalf("证据决策头不符: %+v", ev)
	}
	if ev.EndpointKey != "GET /admin/users" || ev.ObjectRef != "" || ev.ModelVersion != "" ||
		ev.EnforcementOwner != "" || ev.EvidenceSource != "" {
		t.Fatalf("行级 PROTECT 证据伴随字段应置空: %+v", ev)
	}
	if ev.PolicyVersion != "authz-v3" || ev.PrincipalSource != "JWT_VERIFIED" ||
		ev.RevocationWatermark.ManualSeq != 7 || ev.LeaseSeconds != 60 || ev.AppliedAtAgeSeconds != 12 {
		t.Fatalf("证据版本/水位/租约读数不符: %+v", ev)
	}
	wantFactors := []string{"trusted_identity", "baselines_applicable", "evidence_fresh", "role_violation"}
	if len(ev.Eligibility) != len(wantFactors) {
		t.Fatalf("BFLA eligibility 键数不符: %+v", ev.Eligibility)
	}
	for _, k := range wantFactors {
		if ok, present := ev.Eligibility[k]; !present || !ok {
			t.Fatalf("eligibility.%s 应为 true: %+v", k, ev.Eligibility)
		}
	}
}

// BFLA 无覆盖角色行（主体角色不在基线允许集）+ 行级 PROTECT → VERIFIED_VIOLATION
// （违规事实为端点基线集整体）。
func TestV3BFLANoCoveredRoleVerifies(t *testing.T) {
	cfg := v3BFLAConfig(t, nil)
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-2", VerifiedRoles: []string{"guest"}}
	group, ctx := v3EvalBFLA(t, cfg, jwt)
	check := v3PrimaryCheck(t, group)
	if check.Decision != AuthorizationVerifiedViolation || check.ReasonCode != "AUTHZ-BFLA-001" {
		t.Fatalf("无覆盖角色行+PROTECT 应 VERIFIED_VIOLATION: %+v", check)
	}
	v3AssertEvidenceReason(t, ctx, "AUTHZ-BFLA-001")
	_ = group
}

func v3AssertEvidenceReason(t *testing.T, ctx *dsctx.RequestContext, reason string) {
	t.Helper()
	ev := AuthzEnforcementEvidenceFromContext(ctx)
	if ev == nil || ev.ReasonCode != reason || !ev.Enforced {
		t.Fatalf("实断证据缺失或 reason 不符（want %s）: %+v", reason, ev)
	}
}

// BFLA 继承端点模型：基线行无 enforcement 时继承恰一匹配 object model 的
// PROTECT 声明，证据伴随字段（enforcement_owner/evidence_source/model_version）
// 取继承来源模型值。
func TestV3BFLAVerifiedViolationInheritedFromEndpointModel(t *testing.T) {
	key := []byte("obj-secret")
	ref := ObjectRefHMAC(key, "1")
	cfg := v3BFLAConfig(t, func(c *AuthorizationConfig) {
		c.EndpointKey = "GET /admin/users/1"
		c.ObjectRefHMACKey = key
		c.Models = []ObjectModel{{
			EndpointKey: "GET /admin/users/{id}", ObjectType: "ADMIN_USER",
			PathTemplate: "/admin/users/{id}", Identifiers: []ObjectIdentifier{{Location: "path", Name: "id", Primary: true}},
			RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true,
			Enforcement: "PROTECT", EnforcementOwner: "sec-ops@example.com", EvidenceSource: "MANUAL_CONFIRMED",
			ModelVersion: "model-bfla-1",
		}}
		c.Relations = []ObjectRelation{{PrincipalID: "user-1", ObjectType: "ADMIN_USER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED"}}
		c.RoleBaselines = []VerifiedRoleBaseline{
			{EndpointKey: "GET /admin/users/1", Method: "GET", Role: "ops", Allowed: false, Confirmed: true},
		}
	})
	// 主体为对象属主（BOLA ALLOW）但角色被基线拒绝（BFLA 违规）——两检查独立成立
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-1", VerifiedRoles: []string{"ops"}}
	r, err := http.NewRequest(http.MethodGet, "https://example.test/admin/users/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := dsctx.New("req-v3-bfla-inherit", dsctx.DefaultParseLimits())
	parsed, err := parser.ParseRequest(r, ctx)
	if err != nil {
		t.Fatal(err)
	}
	group := EvaluateAuthorization(ctx, parsed, cfg, jwt)
	if group == nil || group.Decision != AuthorizationVerifiedViolation {
		t.Fatalf("组决策应 VERIFIED_VIOLATION: %+v", group)
	}
	var bflaCheck *AuthorizationCheck
	for i, c := range group.Checks {
		if c.Type == "BFLA" {
			bflaCheck = &group.Checks[i]
		}
	}
	if bflaCheck == nil || bflaCheck.Decision != AuthorizationVerifiedViolation || bflaCheck.ReasonCode != "AUTHZ-BFLA-001" {
		t.Fatalf("BFLA 继承 PROTECT 应 VERIFIED_VIOLATION: %+v", group.Checks)
	}
	ev := AuthzEnforcementEvidenceFromContext(ctx)
	if ev == nil || ev.ReasonCode != "AUTHZ-BFLA-001" {
		t.Fatalf("实断证据缺失: %+v", ev)
	}
	if ev.EnforcementOwner != "sec-ops@example.com" || ev.EvidenceSource != "MANUAL_CONFIRMED" || ev.ModelVersion != "model-bfla-1" {
		t.Fatalf("继承证据伴随字段应取端点模型值: %+v", ev)
	}
}

// BFLA 降级与零变化：行级 PROTECT+引擎 OBSERVE 降级留拟动作；行级 OBSERVE 显式
// 降级留拟动作；全未配置零变化；身份/时效资格门槛不真恒 UNKNOWN 不实断。
func TestV3BFLADowngradeZeroChangeAndEligibility(t *testing.T) {
	deniedJWT := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-2", VerifiedRoles: []string{"ops"}}

	t.Run("行级PROTECT+引擎OBSERVE降级", func(t *testing.T) {
		cfg := v3BFLAConfig(t, func(c *AuthorizationConfig) { c.EngineProtect = false })
		group, ctx := v3EvalBFLA(t, cfg, deniedJWT)
		check := v3PrimaryCheck(t, group)
		if check.Decision != AuthorizationObserveViolation || check.ReasonCode != "AUTHZ-BFLA-001" ||
			check.ProposedDecision != AuthorizationVerifiedViolation {
			t.Fatalf("应降级 OBSERVE_VIOLATION+拟动作保留: %+v", check)
		}
		v3AssertNeverBlocked(t, group, ctx)
	})

	t.Run("行级OBSERVE显式降级", func(t *testing.T) {
		cfg := v3BFLAConfig(t, func(c *AuthorizationConfig) {
			c.RoleBaselines[1].Enforcement = "OBSERVE"
		})
		group, ctx := v3EvalBFLA(t, cfg, deniedJWT)
		check := v3PrimaryCheck(t, group)
		if check.Decision != AuthorizationObserveViolation || check.ProposedDecision != AuthorizationVerifiedViolation {
			t.Fatalf("显式 OBSERVE 应降级+拟动作保留: %+v", check)
		}
		v3AssertNeverBlocked(t, group, ctx)
	})

	t.Run("全未配置零变化", func(t *testing.T) {
		cfg := v3BFLAConfig(t, func(c *AuthorizationConfig) {
			c.RoleBaselines[1].Enforcement = ""
		})
		group, ctx := v3EvalBFLA(t, cfg, deniedJWT)
		check := v3PrimaryCheck(t, group)
		if check.Decision != AuthorizationObserveViolation || check.ReasonCode != "AUTHZ-BFLA-001" || check.ProposedDecision != "" {
			t.Fatalf("未配置应零变化 OBSERVE_VIOLATION: %+v", check)
		}
		v3AssertNeverBlocked(t, group, ctx)
		raw, _ := json.Marshal(check)
		if strings.Contains(string(raw), "proposed_decision") {
			t.Fatalf("未配置检查 JSON 必须零变化: %s", raw)
		}
	})

	t.Run("身份不可信恒UNKNOWN不实断", func(t *testing.T) {
		cfg := v3BFLAConfig(t, nil)
		untrusted := &jwtverify.VerificationResult{Status: jwtverify.StatusUnverified, VerifiedPrincipalID: "user-2", VerifiedRoles: []string{"ops"}}
		group, ctx := v3EvalBFLA(t, cfg, untrusted)
		check := v3PrimaryCheck(t, group)
		if check.Decision != AuthorizationUnknown || check.ReasonCode != "AUTHZ-IDENTITY-001" {
			t.Fatalf("未验证主体应 AUTHZ-IDENTITY-001 UNKNOWN: %+v", check)
		}
		v3AssertNeverBlocked(t, group, ctx)
	})

	t.Run("租约过期恒UNKNOWN不实断", func(t *testing.T) {
		cfg := v3BFLAConfig(t, func(c *AuthorizationConfig) {
			c.AppliedAt = v2Now.Add(-2 * time.Minute)
		})
		group, ctx := v3EvalBFLA(t, cfg, deniedJWT)
		check := v3PrimaryCheck(t, group)
		if check.Decision != AuthorizationUnknown || check.ReasonCode != "AUTHZ-LEASE-001" {
			t.Fatalf("租约过期应 AUTHZ-LEASE-001 UNKNOWN: %+v", check)
		}
		v3AssertNeverBlocked(t, group, ctx)
	})

	t.Run("基线冲突恒UNKNOWN不实断", func(t *testing.T) {
		cfg := v3BFLAConfig(t, func(c *AuthorizationConfig) {
			c.RoleBaselines[0].Role = "ops" // 与 deny 行同角色反向 → 冲突
		})
		group, ctx := v3EvalBFLA(t, cfg, deniedJWT)
		check := v3PrimaryCheck(t, group)
		if check.Decision != AuthorizationUnknown || check.ReasonCode != "AUTHZ-POLICY-001" {
			t.Fatalf("基线冲突应 AUTHZ-POLICY-001 UNKNOWN: %+v", check)
		}
		v3AssertNeverBlocked(t, group, ctx)
	})
}
