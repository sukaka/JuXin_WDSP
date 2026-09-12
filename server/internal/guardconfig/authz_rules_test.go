// authz_rules_test.go 授权基线下发单测（W4-GW，纯 fake，不依赖数据库）：
// 表缺失容忍（Warn 跳过）、未注入零行为、正常读取透传、api_policy_version 纳入两段。
package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// fakeRoleBaselineLister 内存版角色基线读取（可注入错误路径）。
type fakeRoleBaselineLister struct {
	rules []gatewayconfig.GuardRoleBaseline
	err   error
}

func (f *fakeRoleBaselineLister) ListConfirmedRoleBaselines(ctx context.Context) ([]gatewayconfig.GuardRoleBaseline, error) {
	_ = ctx
	return f.rules, f.err
}

// fakeFieldPermissionLister 内存版字段权限读取（可注入错误路径）。
type fakeFieldPermissionLister struct {
	perms []gatewayconfig.GuardFieldPermission
	err   error
}

func (f *fakeFieldPermissionLister) ListFieldPermissions(ctx context.Context) ([]gatewayconfig.GuardFieldPermission, error) {
	_ = ctx
	return f.perms, f.err
}

// TestLoadAPIRoleBaselinesTolerance 角色基线：未注入 nil；查询失败（如 000043 表未建立）Warn 跳过返回 nil；
// 空结果不下发；正常读取透传。
func TestLoadAPIRoleBaselinesTolerance(t *testing.T) {
	// 未注入
	p := &Provider{}
	if got := p.loadAPIRoleBaselines(context.Background()); got != nil {
		t.Fatalf("nil lister must yield nil: %v", got)
	}
	// 查询失败（表不存在）→ 容忍跳过
	p = &Provider{roleBaselines: &fakeRoleBaselineLister{err: errors.New(`relation "api_role_baselines" does not exist`)}}
	if got := p.loadAPIRoleBaselines(context.Background()); got != nil {
		t.Fatalf("missing table must be tolerated: %v", got)
	}
	// 空结果 → 不下发
	p = &Provider{roleBaselines: &fakeRoleBaselineLister{rules: []gatewayconfig.GuardRoleBaseline{}}}
	if got := p.loadAPIRoleBaselines(context.Background()); got != nil {
		t.Fatalf("empty baselines must yield nil: %v", got)
	}
	// 正常读取
	want := []gatewayconfig.GuardRoleBaseline{{
		EndpointKey: "GET /v1/orders", Role: "ops", Method: "GET", Action: "READ", Allowed: true,
	}}
	p = &Provider{roleBaselines: &fakeRoleBaselineLister{rules: want}}
	got := p.loadAPIRoleBaselines(context.Background())
	if len(got) != 1 || got[0].EndpointKey != want[0].EndpointKey || got[0].Role != "ops" || !got[0].Allowed {
		t.Fatalf("baselines = %+v", got)
	}
}

// TestLoadAPIFieldPermissionsTolerance 字段权限：未注入 nil；查询失败（如 000044 表未建立）Warn 跳过返回 nil；
// 空结果不下发；正常读取透传（role/tenant 默认行空串口径）。
func TestLoadAPIFieldPermissionsTolerance(t *testing.T) {
	// 未注入
	p := &Provider{}
	if got := p.loadAPIFieldPermissions(context.Background()); got != nil {
		t.Fatalf("nil lister must yield nil: %v", got)
	}
	// 查询失败（表不存在）→ 容忍跳过
	p = &Provider{fieldPermissions: &fakeFieldPermissionLister{err: errors.New(`relation "api_field_permissions" does not exist`)}}
	if got := p.loadAPIFieldPermissions(context.Background()); got != nil {
		t.Fatalf("missing table must be tolerated: %v", got)
	}
	// 空结果 → 不下发
	p = &Provider{fieldPermissions: &fakeFieldPermissionLister{perms: []gatewayconfig.GuardFieldPermission{}}}
	if got := p.loadAPIFieldPermissions(context.Background()); got != nil {
		t.Fatalf("empty permissions must yield nil: %v", got)
	}
	// 正常读取
	want := []gatewayconfig.GuardFieldPermission{{
		EndpointKey: "POST /v1/orders", FieldPath: "json.role", Direction: "REQUEST", Attribute: "FORBIDDEN",
	}}
	p = &Provider{fieldPermissions: &fakeFieldPermissionLister{perms: want}}
	got := p.loadAPIFieldPermissions(context.Background())
	if len(got) != 1 || got[0].FieldPath != "json.role" || got[0].Attribute != "FORBIDDEN" ||
		got[0].Role != "" || got[0].Tenant != "" {
		t.Fatalf("permissions = %+v", got)
	}
}

// TestComputeAPIPolicyVersionAuthz 版本戳纳入授权两段：内容变更即变；不变（含空 vs nil）恒同。
func TestComputeAPIPolicyVersionAuthz(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"amount": "number"}}
	baselines := []gatewayconfig.GuardRoleBaseline{{
		EndpointKey: "POST /v1/orders", Role: "ops", Method: "POST", Action: "WRITE", Allowed: true,
	}}
	perms := []gatewayconfig.GuardFieldPermission{{
		EndpointKey: "POST /v1/orders", FieldPath: "json.role", Direction: "REQUEST", Attribute: "FORBIDDEN",
	}}

	base := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIFormalSchemas: schemas})
	// 纳入基线 → 版本变化
	withBaselines := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIFormalSchemas: schemas, APIRoleBaselines: baselines})
	if withBaselines == base {
		t.Fatal("role baselines must be part of policy version")
	}
	// 纳入字段权限 → 版本变化
	withPerms := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIFormalSchemas: schemas, APIRoleBaselines: baselines, APIFieldPermissions: perms})
	if withPerms == withBaselines {
		t.Fatal("field permissions must be part of policy version")
	}
	// 同内容恒同（确定性）
	if v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIFormalSchemas: schemas, APIRoleBaselines: baselines, APIFieldPermissions: perms}); v != withPerms {
		t.Fatalf("same content must yield same version: %s != %s", v, withPerms)
	}
	// 基线内容变更（allowed 翻转）→ 版本变化
	denied := []gatewayconfig.GuardRoleBaseline{{
		EndpointKey: "POST /v1/orders", Role: "ops", Method: "POST", Action: "WRITE", Allowed: false,
	}}
	if v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIFormalSchemas: schemas, APIRoleBaselines: denied, APIFieldPermissions: perms}); v == withPerms {
		t.Fatal("baseline content change must change version")
	}
}
