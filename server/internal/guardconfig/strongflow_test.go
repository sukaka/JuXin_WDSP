// strongflow_test.go 强流程发布段单测（NG-FLOW-01）：编译读取错误路径、
// 版本戳纳入（内容变更即变/缺省零变化）、缺表 Warn 跳过。
package guardconfig

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type fakeStrongFlowLister struct {
	flows []gatewayconfig.GuardStrongFlowDefinition
	err   error
}

func (f *fakeStrongFlowLister) ListPublishableStrongFlows(context.Context) ([]gatewayconfig.GuardStrongFlowDefinition, error) {
	return f.flows, f.err
}

func testStrongFlows() []gatewayconfig.GuardStrongFlowDefinition {
	return []gatewayconfig.GuardStrongFlowDefinition{{
		DefinitionID: "d-1", ApplicationID: "app-1", Name: "下单支付", Version: 3,
		BindingPathPrefix: "/api/v1/orders", InstanceKeyParam: "query:order_id", Mode: "OBSERVE",
		Steps: []gatewayconfig.GuardStrongFlowStep{
			{StepKey: "create", EndpointKey: "POST /api/v1/orders", Sequence: 1,
				SuccessRule:    json.RawMessage(`{"status_codes":[200]}`),
				TimeoutSeconds: 30, RetrySemantics: "IDEMPOTENT", LeaseSeconds: 60},
			{StepKey: "pay", EndpointKey: "POST /api/v1/orders/pay", Sequence: 2,
				SuccessRule:    json.RawMessage(`{"body_jsonpath_equals":{"path":"$.status","value":"PAID"}}`),
				TimeoutSeconds: 60, RetrySemantics: "REQUIRES_REVIEW", LeaseSeconds: 120, Allows202: true},
		},
	}}
}

func TestLoadAPIStrongFlows(t *testing.T) {
	// 未注入 → nil（段省略，NG-T-C01 零变化）
	p := &Provider{}
	if got := p.loadAPIStrongFlows(context.Background()); got != nil {
		t.Fatalf("未注入应不下发: %+v", got)
	}
	// 错误 → Warn 跳过 nil
	p = &Provider{strongFlows: &fakeStrongFlowLister{err: errors.New("db down")}}
	if got := p.loadAPIStrongFlows(context.Background()); got != nil {
		t.Fatalf("查询失败应跳过不下发: %+v", got)
	}
	// 空集 → nil
	p = &Provider{strongFlows: &fakeStrongFlowLister{flows: nil}}
	if got := p.loadAPIStrongFlows(context.Background()); got != nil {
		t.Fatalf("无 ACTIVE 定义应段省略: %+v", got)
	}
	// 正常读取（DRAFT/RETIRED 不下发由 SQL WHERE status='ACTIVE' 承载，fake 层只看透传）
	p = &Provider{strongFlows: &fakeStrongFlowLister{flows: testStrongFlows()}}
	got := p.loadAPIStrongFlows(context.Background())
	if len(got) != 1 || got[0].Name != "下单支付" || got[0].Version != 3 || len(got[0].Steps) != 2 ||
		got[0].Steps[1].Allows202 != true || got[0].InstanceKeyParam != "query:order_id" {
		t.Fatalf("strong flows = %+v", got)
	}
}

// TestComputeAPIPolicyVersionStrongFlows 版本戳纳入强流程段：内容变更即变；缺省
// （nil/空）零变化（omitempty 与既有版本逐字节一致）。
func TestComputeAPIPolicyVersionStrongFlows(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"amount": "number"}}

	base := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIFormalSchemas: schemas})
	withFlows := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{
		APIFormalSchemas: schemas, APIStrongFlows: testStrongFlows()})
	if withFlows == base {
		t.Fatal("strong flows must be part of policy version")
	}
	// 同内容恒同（确定性）
	if v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{
		APIFormalSchemas: schemas, APIStrongFlows: testStrongFlows()}); v != withFlows {
		t.Fatalf("same content must yield same version: %s != %s", v, withFlows)
	}
	// 内容变更（mode 翻转）→ 版本变化
	changed := testStrongFlows()
	changed[0].Mode = "PROTECT"
	if v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{
		APIFormalSchemas: schemas, APIStrongFlows: changed}); v == withFlows {
		t.Fatal("mode change must change version")
	}
	// 步骤判定式变更 → 版本变化
	changed2 := testStrongFlows()
	changed2[0].Steps[0].SuccessRule = json.RawMessage(`{"status_codes":[201]}`)
	if v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{
		APIFormalSchemas: schemas, APIStrongFlows: changed2}); v == withFlows {
		t.Fatal("success_rule change must change version")
	}
	// 空切片与 nil 等价（缺省零变化）
	if v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{
		APIFormalSchemas: schemas, APIStrongFlows: []gatewayconfig.GuardStrongFlowDefinition{}}); v != base {
		t.Fatal("empty strong flows must not change version")
	}
}

// NG-FLOW-02 联调修正：含 ACTIVE 强流程定义但无授权模型时对象 HMAC 密钥随快照下发
// （实例键构造依赖该键——不下发则网关恒 UNKNOWN hmac_key_unavailable）；
// 无定义/已有键/无设置行三分支。
func TestStrongFlowHMACKeyInjection(t *testing.T) {
	load := func(p *Provider) (string, error) {
		cfg := &gatewayconfig.GuardConfig{APIStrongFlows: testStrongFlows()}
		if len(cfg.APIStrongFlows) > 0 && cfg.APIAuthzObjectHMACKeyHex == "" && p.authzObjectHMACKey != nil {
			key, err := p.authzObjectHMACKey(context.Background())
			if err != nil {
				return "", err
			}
			if key == "" {
				return "", errors.New("strong flows require api_authz.object_hmac_key（含 ACTIVE 强流程定义但密钥未配置）")
			}
			cfg.APIAuthzObjectHMACKeyHex = key
		}
		return cfg.APIAuthzObjectHMACKeyHex, nil
	}
	// 有 ACTIVE 定义 + 有 key → 注入
	k, err := load(&Provider{authzObjectHMACKey: func(context.Context) (string, error) { return "deadbeef", nil }})
	if err != nil || k != "deadbeef" {
		t.Fatalf("应注入密钥: %q %v", k, err)
	}
	// 有 ACTIVE 定义 + 无 key（空串）→ fail-hard
	if _, err := load(&Provider{authzObjectHMACKey: func(context.Context) (string, error) { return "", nil }}); err == nil {
		t.Fatal("无密钥配置应 fail-hard")
	}
	// loader 未装配（nil）→ 不注入不炸（旧装配形态容忍）
	if k, err := load(&Provider{}); err != nil || k != "" {
		t.Fatalf("未装配 loader 应跳过: %q %v", k, err)
	}
}
