// api_admission_test.go api_admission 段组装单元测试（WDSP P1）：
// 策略注入（OFF 应用不出现 / OBSERVE 无确认集也出现 / PROTECT 正常）、
// 读取失败 fail-hard、确认集 nil 归一为 []、版本戳纳入准入内容。
package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type fakeAPIAdmissionLister struct {
	policies map[string]*gatewayconfig.GuardAPIAdmissionPolicy
	err      error
}

func (f fakeAPIAdmissionLister) ListForGuard(context.Context) (map[string]*gatewayconfig.GuardAPIAdmissionPolicy, error) {
	return f.policies, f.err
}

const (
	testAdmAppOBSERVE = "11111111-1111-1111-1111-111111111111"
	testAdmAppPROTECT = "22222222-2222-2222-2222-222222222222"
)

// TestLoadAPIAdmissionInject 策略注入 GuardConfig（key=application_id）：
// OBSERVE 应用无确认端点同样出现（空数组语义=无确认端点）；PROTECT 应用确认集透传。
func TestLoadAPIAdmissionInject(t *testing.T) {
	p := &Provider{apiAdmission: fakeAPIAdmissionLister{policies: map[string]*gatewayconfig.GuardAPIAdmissionPolicy{
		testAdmAppOBSERVE: {Mode: "OBSERVE", ConfirmedEndpoints: []string{}},
		testAdmAppPROTECT: {Mode: "PROTECT", ConfirmedEndpoints: []string{"GET /v1/orders/{id}", "POST /v1/login"}},
	}}}
	cfg := &gatewayconfig.GuardConfig{}
	if err := p.loadAPIAdmission(context.Background(), cfg); err != nil {
		t.Fatalf("loadAPIAdmission: %v", err)
	}
	obs := cfg.APIAdmission[testAdmAppOBSERVE]
	if obs == nil || obs.Mode != "OBSERVE" {
		t.Fatalf("OBSERVE 策略未注入: %+v", cfg.APIAdmission)
	}
	if obs.ConfirmedEndpoints == nil || len(obs.ConfirmedEndpoints) != 0 {
		t.Fatalf("OBSERVE 空确认集应为非 nil 空切片: %#v", obs.ConfirmedEndpoints)
	}
	pro := cfg.APIAdmission[testAdmAppPROTECT]
	if pro == nil || pro.Mode != "PROTECT" || len(pro.ConfirmedEndpoints) != 2 {
		t.Fatalf("PROTECT 策略未注入: %+v", cfg.APIAdmission)
	}
}

// TestLoadAPIAdmissionNilLister 未注入 lister：不下发该段（纯 WAF 装配形态零行为变化）。
func TestLoadAPIAdmissionNilLister(t *testing.T) {
	p := &Provider{}
	cfg := &gatewayconfig.GuardConfig{}
	if err := p.loadAPIAdmission(context.Background(), cfg); err != nil {
		t.Fatalf("nil lister should be no-op: %v", err)
	}
	if cfg.APIAdmission != nil {
		t.Fatal("nil lister must not inject api_admission")
	}
}

// TestLoadAPIAdmissionEmptyPolicies 无启用应用（全 OFF）：不下发该段。
func TestLoadAPIAdmissionEmptyPolicies(t *testing.T) {
	p := &Provider{apiAdmission: fakeAPIAdmissionLister{policies: map[string]*gatewayconfig.GuardAPIAdmissionPolicy{}}}
	cfg := &gatewayconfig.GuardConfig{}
	if err := p.loadAPIAdmission(context.Background(), cfg); err != nil {
		t.Fatalf("empty policies: %v", err)
	}
	if cfg.APIAdmission != nil {
		t.Fatal("empty policies must not inject api_admission")
	}
}

// TestLoadAPIAdmissionReadErrorFailsHard 读取失败中止发布
// （防已 PROTECT 应用在新配置中静默丢失准入拦截）。
func TestLoadAPIAdmissionReadErrorFailsHard(t *testing.T) {
	p := &Provider{apiAdmission: fakeAPIAdmissionLister{err: errors.New("db down")}}
	if err := p.loadAPIAdmission(context.Background(), &gatewayconfig.GuardConfig{}); err == nil {
		t.Fatal("read error must abort publish")
	}
}

// TestLoadAPIAdmissionNilEndpointsNormalized 确认集 nil 防御性归一为非 nil 空切片
// （下发 JSON 为 [] 而非 null，冻结契约数组形态）。
func TestLoadAPIAdmissionNilEndpointsNormalized(t *testing.T) {
	p := &Provider{apiAdmission: fakeAPIAdmissionLister{policies: map[string]*gatewayconfig.GuardAPIAdmissionPolicy{
		testAdmAppOBSERVE: {Mode: "OBSERVE", ConfirmedEndpoints: nil},
	}}}
	cfg := &gatewayconfig.GuardConfig{}
	if err := p.loadAPIAdmission(context.Background(), cfg); err != nil {
		t.Fatalf("loadAPIAdmission: %v", err)
	}
	if cfg.APIAdmission[testAdmAppOBSERVE].ConfirmedEndpoints == nil {
		t.Fatal("nil confirmed_endpoints must be normalized to empty slice")
	}
}

// TestAPIAdmissionInPolicyVersion 准入内容纳入 api_policy_version 版本戳
// （确认/模式变更经发布产生新版本戳，供生效校验与网关回报比对）。
func TestAPIAdmissionInPolicyVersion(t *testing.T) {
	base := &gatewayconfig.GuardConfig{APIDynamicProtection: true, APIProtectionMode: "OBSERVE"}
	withAdmission := &gatewayconfig.GuardConfig{
		APIDynamicProtection: true, APIProtectionMode: "OBSERVE",
		APIAdmission: map[string]*gatewayconfig.GuardAPIAdmissionPolicy{
			testAdmAppPROTECT: {Mode: "PROTECT", ConfirmedEndpoints: []string{"GET /v1/a"}},
		},
	}
	if computeAPIPolicyVersion(base) == computeAPIPolicyVersion(withAdmission) {
		t.Fatal("api_admission 内容必须纳入 api_policy_version")
	}
	// 确认集变化同样改变版本戳
	changed := &gatewayconfig.GuardConfig{
		APIDynamicProtection: true, APIProtectionMode: "OBSERVE",
		APIAdmission: map[string]*gatewayconfig.GuardAPIAdmissionPolicy{
			testAdmAppPROTECT: {Mode: "PROTECT", ConfirmedEndpoints: []string{"GET /v1/a", "GET /v1/b"}},
		},
	}
	if computeAPIPolicyVersion(withAdmission) == computeAPIPolicyVersion(changed) {
		t.Fatal("确认集变化必须改变 api_policy_version")
	}
}
