// authzdecide_v2_test.go NG-AZ-02 决策消费测试（经 EvaluateAuthorization 端到端）：
// D4-2 PreviousValid 水位二次校验、D5 lease strict/degraded、D7 冲突对象、
// D8 漂移 strict/degraded、v1 快照全惰性。
package detectors

import (
	"net/http"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

var v2Now = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

// v2Fixture 授权快照夹具（v2 schema + 可控水位/租约/冲突/编译时刻）。
type v2Fixture struct {
	cfg  AuthorizationConfig
	ref  string
	path string
	jwt  *jwtverify.VerificationResult
}

func newV2Fixture(t *testing.T, mutate func(*AuthorizationConfig, *ObjectModel)) v2Fixture {
	t.Helper()
	model := ObjectModel{
		EndpointKey: "GET /orders/{orderId}", ObjectType: "ORDER",
		PathTemplate: "/orders/{orderId}", Identifiers: []ObjectIdentifier{{Location: "path", Name: "orderId", Primary: true}},
		RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true,
	}
	ref := ObjectRefHMAC([]byte("obj-secret"), "7")
	produced := v2Now.Add(-time.Minute)
	cfg := AuthorizationConfig{
		EndpointKey: "GET /orders/7", Models: []ObjectModel{model}, ObjectRefHMACKey: []byte("obj-secret"),
		Relations:           []ObjectRelation{{PrincipalID: "user-1", ObjectType: "ORDER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED"}},
		Now:                 func() time.Time { return v2Now },
		PolicyVersion:       "authz-v3",
		Schema:              AuthzSnapshotSchemaV2,
		RevocationWatermark: &RevocationWatermark{ManualSeq: 5, Sources: map[string]int64{"src-a": 3}},
		AppliedAt:           v2Now.Add(-time.Minute),
		ProducedAt:          &produced,
	}
	if mutate != nil {
		mutate(&cfg, &cfg.Models[0])
	}
	return v2Fixture{cfg: cfg, ref: ref, path: "/orders/7",
		jwt: &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-1"}}
}

func (f v2Fixture) eval(t *testing.T) *AuthorizationDecisionGroup {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "https://example.test"+f.path, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := dsctx.New("req-v2", dsctx.DefaultParseLimits())
	parsed, err := parser.ParseRequest(r, ctx)
	if err != nil {
		t.Fatal(err)
	}
	return EvaluateAuthorization(ctx, parsed, f.cfg, f.jwt)
}

func checksOf(group *AuthorizationDecisionGroup) []AuthorizationCheck {
	if group == nil {
		return nil
	}
	return group.Checks
}

// D4-2：PreviousValid 水位低于当前快照 → 拒绝回退（AUTHZ-POLICY-002 UNKNOWN）。
func TestV2PreviousValidWatermarkRegressionRejected(t *testing.T) {
	f := newV2Fixture(t, func(cfg *AuthorizationConfig, _ *ObjectModel) {
		expired := v2Now.Add(-time.Hour)
		cfg.SnapshotExpiresAt = &expired // 当前快照过期 → 触发回退路径
		prev := AuthorizationConfig{
			Models: cfg.Models, Relations: cfg.Relations, ObjectRefHMACKey: cfg.ObjectRefHMACKey,
			PolicyVersion: "authz-v2", Schema: AuthzSnapshotSchemaV2,
			RevocationWatermark: &RevocationWatermark{ManualSeq: 3}, // 低于当前 5
		}
		cfg.PreviousValid = &prev
	})
	group := f.eval(t)
	checks := checksOf(group)
	if len(checks) != 1 || checks[0].ReasonCode != "AUTHZ-POLICY-002" || checks[0].Decision != AuthorizationUnknown {
		t.Fatalf("水位不足应拒绝回退落 AUTHZ-POLICY-002: %+v", checks)
	}
}

// D4-2 对照：PreviousValid 水位 ≥ 当前 → 允许回退（按旧快照给出 BOLA 判定）。
func TestV2PreviousValidWatermarkSatisfiedAllows(t *testing.T) {
	f := newV2Fixture(t, func(cfg *AuthorizationConfig, _ *ObjectModel) {
		expired := v2Now.Add(-time.Hour)
		cfg.SnapshotExpiresAt = &expired
		prev := AuthorizationConfig{
			Models: cfg.Models, Relations: cfg.Relations, ObjectRefHMACKey: cfg.ObjectRefHMACKey,
			PolicyVersion: "authz-v2", Schema: AuthzSnapshotSchemaV2,
			RevocationWatermark: &RevocationWatermark{ManualSeq: 5, Sources: map[string]int64{"src-a": 3}},
		}
		cfg.PreviousValid = &prev
	})
	group := f.eval(t)
	var sawAllow bool
	for _, c := range checksOf(group) {
		if c.Decision == AuthorizationAllow {
			sawAllow = true
		}
	}
	if !sawAllow {
		t.Fatalf("水位满足应允许回退给出 ALLOW: %+v", checksOf(group))
	}
}

// D5 strict（缺省）：租约过期 → UNKNOWN + AUTHZ-LEASE-001 + DependencyUnavailable。
func TestV2LeaseExpiredStrictUnknown(t *testing.T) {
	f := newV2Fixture(t, func(cfg *AuthorizationConfig, _ *ObjectModel) {
		cfg.LeaseSeconds = 60
		cfg.AppliedAt = v2Now.Add(-2 * time.Minute)
	})
	checks := checksOf(f.eval(t))
	// 无端点基线：仅 BOLA 拦截（BFLA 空基线不产空载检查）；strict 租约过期 UNKNOWN+LEASE-001
	if len(checks) != 1 || checks[0].Decision != AuthorizationUnknown || checks[0].ReasonCode != "AUTHZ-LEASE-001" {
		t.Fatalf("strict 租约过期应 UNKNOWN+AUTHZ-LEASE-001: %+v", checks)
	}
	if !checks[0].DependencyUnavailable {
		t.Fatalf("strict 租约过期应披露 dependency_unavailable: %+v", checks[0])
	}
	// 有角色基线：BFLA 同被 strict 拦截（BFLA/BOLA 双双）
	fB := newV2Fixture(t, func(cfg *AuthorizationConfig, _ *ObjectModel) {
		cfg.LeaseSeconds = 60
		cfg.AppliedAt = v2Now.Add(-2 * time.Minute)
		cfg.RoleBaselines = []VerifiedRoleBaseline{{EndpointKey: "GET /orders/7", Role: "admin", Allowed: true, Confirmed: true}}
	})
	fB.jwt.VerifiedRoles = []string{"admin"}
	checks2 := checksOf(fB.eval(t))
	if len(checks2) != 2 {
		t.Fatalf("BFLA/BOLA 应双双拦截: %+v", checks2)
	}
	for _, c := range checks2 {
		if c.Decision != AuthorizationUnknown || c.ReasonCode != "AUTHZ-LEASE-001" {
			t.Fatalf("strict 租约过期应 UNKNOWN+AUTHZ-LEASE-001: %+v", checks2)
		}
	}
	// 未过期对照
	f2 := newV2Fixture(t, func(cfg *AuthorizationConfig, _ *ObjectModel) {
		cfg.LeaseSeconds = 60
		cfg.AppliedAt = v2Now.Add(-10 * time.Second)
	})
	for _, c := range checksOf(f2.eval(t)) {
		if c.ReasonCode == "AUTHZ-LEASE-001" || c.ReasonCode == "AUTHZ-LEASE-002" {
			t.Fatalf("未过期不得产租约检查: %+v", c)
		}
	}
}

// D5 degraded：租约过期 → 评估继续（EFFECTIVE_OWNER ALLOW 保留）+ AUTHZ-LEASE-002 标记。
func TestV2LeaseExpiredDegradedMarkedButEvaluated(t *testing.T) {
	f := newV2Fixture(t, func(cfg *AuthorizationConfig, model *ObjectModel) {
		cfg.LeaseSeconds = 60
		cfg.AppliedAt = v2Now.Add(-2 * time.Minute)
		model.OnLeaseExpired = "degraded"
	})
	checks := checksOf(f.eval(t))
	var sawAllow, sawMarker bool
	for _, c := range checks {
		if c.Decision == AuthorizationAllow && c.RelationState == "EFFECTIVE_OWNER" {
			sawAllow = true
		}
		if c.Decision == AuthorizationUnknown && c.ReasonCode == "AUTHZ-LEASE-002" {
			sawMarker = true
			if !c.DependencyUnavailable {
				t.Fatalf("degraded 租约标记应披露 dependency_unavailable: %+v", c)
			}
		}
	}
	if !sawAllow || !sawMarker {
		t.Fatalf("degraded 应评估继续(ALLOW)+LEASE-002 标记: %+v", checks)
	}
}

// D7：冲突对象 → UNKNOWN + AUTHZ-CONFLICT-001（不出 ALLOW/VIOLATION）。
func TestV2ConflictedObjectUnknown(t *testing.T) {
	f := newV2Fixture(t, func(cfg *AuthorizationConfig, _ *ObjectModel) {
		cfg.ConflictedObjects = []ConflictedObject{{ApplicationID: "", ObjectType: "ORDER", ObjectRef: ObjectRefHMAC([]byte("obj-secret"), "7")}}
		cfg.ConflictedIndex = BuildConflictedObjectIndex(cfg.ConflictedObjects)
	})
	checks := checksOf(f.eval(t))
	if len(checks) != 1 || checks[0].Decision != AuthorizationUnknown || checks[0].ReasonCode != "AUTHZ-CONFLICT-001" {
		t.Fatalf("冲突对象应 UNKNOWN+AUTHZ-CONFLICT-001: %+v", checks)
	}
	// 无冲突对照：同一夹具不加冲突集 → EFFECTIVE_OWNER ALLOW
	f2 := newV2Fixture(t, nil)
	var sawAllow bool
	for _, c := range checksOf(f2.eval(t)) {
		if c.Decision == AuthorizationAllow {
			sawAllow = true
		}
	}
	if !sawAllow {
		t.Fatal("无冲突应照常 ALLOW")
	}
}

// D8 strict：produced_at 超前（节点时钟落后管理面）超上限 → UNKNOWN + AUTHZ-CLOCK-001（BFLA/BOLA 双双拦截）。
func TestV2ClockSkewStrictUnknown(t *testing.T) {
	f := newV2Fixture(t, func(cfg *AuthorizationConfig, _ *ObjectModel) {
		produced := v2Now.Add(5 * time.Minute)
		cfg.ProducedAt = &produced
		cfg.RoleBaselines = []VerifiedRoleBaseline{{EndpointKey: "GET /orders/7", Role: "admin", Allowed: true, Confirmed: true}}
	})
	f.jwt.VerifiedRoles = []string{"admin"}
	checks := checksOf(f.eval(t))
	if len(checks) == 0 {
		t.Fatal("漂移应产检查")
	}
	for _, c := range checks {
		if c.Decision != AuthorizationUnknown || c.ReasonCode != "AUTHZ-CLOCK-001" {
			t.Fatalf("漂移 strict 应全部 UNKNOWN+AUTHZ-CLOCK-001: %+v", checks)
		}
	}
	// 自然老化对照（produced_at 早于 now 不判漂移）
	f2 := newV2Fixture(t, nil)
	for _, c := range checksOf(f2.eval(t)) {
		if c.ReasonCode == "AUTHZ-CLOCK-001" {
			t.Fatalf("自然老化不得产漂移检查: %+v", c)
		}
	}
}

// D8 degraded：produced_at 超前 → 评估继续 + AUTHZ-CLOCK-001 标记。
func TestV2ClockSkewDegradedMarked(t *testing.T) {
	f := newV2Fixture(t, func(cfg *AuthorizationConfig, model *ObjectModel) {
		produced := v2Now.Add(5 * time.Minute)
		cfg.ProducedAt = &produced
		model.OnLeaseExpired = "degraded"
	})
	checks := checksOf(f.eval(t))
	var sawAllow, sawMarker bool
	for _, c := range checks {
		if c.Decision == AuthorizationAllow {
			sawAllow = true
		}
		if c.Decision == AuthorizationUnknown && c.ReasonCode == "AUTHZ-CLOCK-001" {
			sawMarker = true
		}
	}
	if !sawAllow || !sawMarker {
		t.Fatalf("degraded 漂移应评估继续+CLOCK-001 标记: %+v", checks)
	}
}

// v1 快照（无 schema）：同输入下 lease/skew/conflict 配置全部惰性（行为与旧版一致）。
func TestV1SnapshotInert(t *testing.T) {
	f := newV2Fixture(t, func(cfg *AuthorizationConfig, model *ObjectModel) {
		cfg.Schema = "" // v1
		cfg.LeaseSeconds = 1
		cfg.AppliedAt = v2Now.Add(-time.Hour)
		produced := v2Now.Add(-time.Hour)
		cfg.ProducedAt = &produced
		cfg.ConflictedObjects = []ConflictedObject{{ObjectType: "ORDER", ObjectRef: ObjectRefHMAC([]byte("obj-secret"), "7")}}
		cfg.ConflictedIndex = BuildConflictedObjectIndex(cfg.ConflictedObjects)
		model.OnLeaseExpired = "strict"
	})
	checks := checksOf(f.eval(t))
	for _, c := range checks {
		switch c.ReasonCode {
		case "AUTHZ-LEASE-001", "AUTHZ-LEASE-002", "AUTHZ-CLOCK-001", "AUTHZ-CONFLICT-001":
			t.Fatalf("v1 快照 v2 逻辑应全惰性: %+v", c)
		}
	}
	var sawAllow bool
	for _, c := range checks {
		if c.Decision == AuthorizationAllow {
			sawAllow = true
		}
	}
	if !sawAllow {
		t.Fatalf("v1 应照常 ALLOW: %+v", checks)
	}
}
