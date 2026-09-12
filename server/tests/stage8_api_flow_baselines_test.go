// stage8_api_flow_baselines_test.go 流程基线管理面 + 发布侧端到端贯通测试（阶段8 §44 发布下发面）。
//
// 链路：管理面 HTTP API CRUD（/api/v1/api-security/flow-baselines，
// 权限 api_flow.read/manage，种子见迁移 000155）
//
//	→ 发布通道组装（guardconfig.Provider.BuildGuardConfig，与 app.go 同一接线：
//	  SetFlowBaselineLister(NewFlowBaselineStore(db))）
//	→ 生成器产出 Caddy JSON：jiuzhang_guard 处理器内 api_flow_baselines 段
//	  （键名与网关 detectors.FlowBaseline 契约对应：flow_id/steps[step_id/endpoint_key/…]）
//	→ 访问控制版本快照落库/回读保留流程基线（回滚路径不丢配置）
//	→ 禁用/删除驱动发布内容回落与 api_policy_version 确定性回归基线（P0-21 锚点）。
//
// 覆盖边界（如实声明）：本测试覆盖「配置 → 下发内容」的 server 侧全链与 CRUD/权限；
// 网关侧解析/校验/接线由模块级测试覆盖
// （gateway/modules/jiuzhang_guard/apiflow_test.go），两侧经同一下发契约键名衔接。
//
// 运行方式（与 make stage8-test-api 一致）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestStage8APIFlowBaselinesE2E -count=1
package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/accesscontrolversions"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/guardconfig"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
	"github.com/jiuzhang-waf/server/internal/ratelimitpolicies"
	"github.com/jiuzhang-waf/server/internal/trustedproxies"
)

// s8FlowProvider 按 app.go 同一接线构造发布组装器（WDSP 形态 + 流程基线读取）。
func s8FlowProvider(env *testEnv) *guardconfig.Provider {
	p := guardconfig.NewProvider(
		trustedproxies.NewStore(env.db), protectedaddresses.NewStore(env.db),
		accessrules.NewStore(env.db), ratelimitpolicies.NewStore(env.db),
		accesscontrolversions.NewStore(env.db),
		guardconfig.Config{
			APIDynamicProtection: true, APIProtectionMode: "PROTECT",
			APIEventsLog: "/var/log/caddy/api-runtime-events.log",
			GatewayNode:  "gw-test",
		})
	p.SetAPIModels(apimodels.NewStore(env.db))
	p.SetAPIAssets(apiassets.NewStore(env.db))
	p.SetFlowBaselineLister(guardconfig.NewFlowBaselineStore(env.db))
	return p
}

func TestStage8APIFlowBaselinesE2E(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	cookies, csrf := env.s5Login(t, "s8flow", "SECURITY_ADMIN")
	kw := "s8f" + s5Rand()

	// 两个端点（等价网关采集链路喂入的发现数据）
	ep1 := s8SeedEndpoint(t, env, "GET", "/"+kw+"/items", 0.9)
	ep2 := s8SeedEndpoint(t, env, "POST", "/"+kw+"/orders/{id}/pay", 0.9)
	ek1, ek2 := ep1.EndpointKey, ep2.EndpointKey

	// ---------- 1. 基线：无流程基线 → 不下发 api_flow_baselines 段 ----------
	cfg0, err := s8FlowProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config (baseline): %v", err)
	}
	if len(cfg0.APIFlowBaselines) != 0 {
		t.Fatalf("baseline flow baselines = %+v, want empty", cfg0.APIFlowBaselines)
	}
	if j := s8GenerateGuardJSON(t, cfg0); strings.Contains(j, "api_flow_baselines") {
		t.Fatal("baseline caddy json must not contain api_flow_baselines")
	}

	// ---------- 2. 管理面创建流程基线（201 + 步骤明细，含批量执行/取消语义字段） ----------
	flowID := "flow-" + kw
	createBody := fmt.Sprintf(`{"flow_id":%q,"name":"下单流程","max_per_window":20,"rate_window_seconds":120,"steps":[
		{"step_id":"browse","endpoint_id":%q,"sequence":1},
		{"step_id":"pay","endpoint_id":%q,"sequence":2,"predecessors":["browse"],
		 "terminal":true,"state_from":"CREATED","state_to":"PAID",
		 "max_per_window":3,"rate_window_seconds":30,"cancels_flow":true}]}`,
		flowID, ep1.ID.String(), ep2.ID.String())
	resp := env.post(t, "/api/v1/api-security/flow-baselines", createBody, cookies, csrf)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want 201, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	var created apiResp
	readJSON(t, resp, &created)
	id, _ := created.Data["id"].(string)
	if id == "" {
		t.Fatalf("created id missing: %+v", created.Data)
	}
	if s5Num(t, created.Data, "max_per_window") != 20 || s5Num(t, created.Data, "rate_window_seconds") != 120 {
		t.Fatalf("flow-level rate fields = %+v", created.Data)
	}
	steps, _ := created.Data["steps"].([]interface{})
	if len(steps) != 2 {
		t.Fatalf("steps = %+v", created.Data["steps"])
	}
	step1, _ := steps[1].(map[string]interface{})
	if step1["endpoint_key"] != ek2 || step1["state_to"] != "PAID" {
		t.Fatalf("step detail = %+v (want endpoint_key %q)", step1, ek2)
	}
	if s5Num(t, step1, "max_per_window") != 3 || s5Num(t, step1, "rate_window_seconds") != 30 ||
		step1["cancels_flow"] != true {
		t.Fatalf("step rate/cancel fields = %+v", step1)
	}

	// ---------- 2b. 批量执行字段校验：负上限 / 窗口超会话 TTL → 400 ----------
	for name, bad := range map[string]string{
		"negative max_per_window": fmt.Sprintf(`{"flow_id":"neg-%s","steps":[
			{"step_id":"a","endpoint_id":%q,"sequence":1,"max_per_window":-1}]}`, kw, ep1.ID.String()),
		"window over session TTL": fmt.Sprintf(`{"flow_id":"win-%s","steps":[
			{"step_id":"a","endpoint_id":%q,"sequence":1,"max_per_window":5,"rate_window_seconds":601}]}`, kw, ep1.ID.String()),
		"negative flow-level window": fmt.Sprintf(`{"flow_id":"fneg-%s","rate_window_seconds":-1,"steps":[
			{"step_id":"a","endpoint_id":%q,"sequence":1}]}`, kw, ep1.ID.String()),
	} {
		s5Expect(t, env.post(t, "/api/v1/api-security/flow-baselines", bad, cookies, csrf),
			http.StatusBadRequest, name)
	}

	// ---------- 3. 列表 / 详情 / 权限 ----------
	listed := s5OK(t, env.get(t, "/api/v1/api-security/flow-baselines", cookies), "list flow baselines")
	items, _ := listed.Data["items"].([]interface{})
	if len(items) != 1 {
		t.Fatalf("list items = %+v", listed.Data)
	}
	detail := s5OK(t, env.get(t, "/api/v1/api-security/flow-baselines/"+id, cookies), "get flow baseline")
	if detail.Data["flow_id"] != flowID {
		t.Fatalf("detail = %+v", detail.Data)
	}
	// AUDIT_ADMIN（纯审计角色）读/写均 403
	auditCookies, auditCSRF := env.s5Login(t, "s8faudit", "AUDIT_ADMIN")
	s5Expect(t, env.get(t, "/api/v1/api-security/flow-baselines", auditCookies), http.StatusForbidden, "auditor list flow baselines")
	s5Expect(t, env.post(t, "/api/v1/api-security/flow-baselines", createBody, auditCookies, auditCSRF),
		http.StatusForbidden, "auditor create flow baseline")

	// ---------- 4. 发布通道组装：流程基线进入 GuardConfig（契约键名） ----------
	cfg1, err := s8FlowProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config: %v", err)
	}
	if len(cfg1.APIFlowBaselines) != 1 {
		t.Fatalf("flow baselines = %+v, want 1", cfg1.APIFlowBaselines)
	}
	fb := cfg1.APIFlowBaselines[0]
	if fb.FlowID != flowID || len(fb.Steps) != 2 {
		t.Fatalf("flow baseline payload = %+v", fb)
	}
	if fb.Steps[0].EndpointKey != ek1 || fb.Steps[1].EndpointKey != ek2 ||
		len(fb.Steps[1].Predecessors) != 1 || fb.Steps[1].Predecessors[0] != "browse" {
		t.Fatalf("flow steps = %+v (want %q / %q)", fb.Steps, ek1, ek2)
	}
	// 批量执行/取消语义五字段随发布载荷下发（rapid_batch/post_cancel 阈值契约）
	if fb.MaxPerWindow != 20 || fb.RateWindowSeconds != 120 ||
		fb.Steps[1].MaxPerWindow != 3 || fb.Steps[1].RateWindowSeconds != 30 || !fb.Steps[1].CancelsFlow ||
		fb.Steps[0].MaxPerWindow != 0 || fb.Steps[0].CancelsFlow {
		t.Fatalf("rate/cancel fields not propagated: %+v", fb)
	}
	// 策略版本戳随流程基线内容确定性变化（P0-21 生效校验锚点）
	if cfg1.APIPolicyVersion == cfg0.APIPolicyVersion {
		t.Fatal("api_policy_version must change when flow baselines change")
	}

	// ---------- 5. 生成器：Caddy JSON 的 jiuzhang_guard 处理器含 api_flow_baselines ----------
	j := s8GenerateGuardJSON(t, cfg1)
	for _, want := range []string{
		`"handler":"jiuzhang_guard"`,
		`"api_flow_baselines":[{"flow_id":"` + flowID + `"`,
		`"step_id":"pay"`, `"endpoint_key":"` + ek2 + `"`,
		`"predecessors":["browse"]`, `"state_from":"CREATED"`, `"state_to":"PAID"`,
		`"max_per_window":20`, `"rate_window_seconds":120`,
		`"max_per_window":3`, `"rate_window_seconds":30`, `"cancels_flow":true`,
	} {
		if !strings.Contains(j, want) {
			t.Errorf("caddy json missing %q", want)
		}
	}

	// ---------- 6. 版本快照落库/回读：流程基线随快照保留（回滚路径不丢配置） ----------
	versionID, err := s8FlowProvider(env).SaveVersionSnapshot(ctx, cfg1, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("save version snapshot: %v", err)
	}
	back, err := s8FlowProvider(env).GetVersionConfig(ctx, versionID)
	if err != nil {
		t.Fatalf("get version config: %v", err)
	}
	if len(back.APIFlowBaselines) != 1 || back.APIFlowBaselines[0].FlowID != flowID {
		t.Fatalf("snapshot round-trip lost flow baselines: %+v", back.APIFlowBaselines)
	}
	if back.APIFlowBaselines[0].MaxPerWindow != 20 || !back.APIFlowBaselines[0].Steps[1].CancelsFlow {
		t.Fatalf("snapshot round-trip lost rate/cancel fields: %+v", back.APIFlowBaselines[0])
	}

	// ---------- 7. 乐观锁：过期版本 409；禁用后退出发布载荷 ----------
	stalePut := fmt.Sprintf(`{"flow_id":%q,"expected_version":99,"steps":[
		{"step_id":"browse","endpoint_id":%q,"sequence":1}]}`, flowID, ep1.ID.String())
	s5Expect(t, env.do(t, "PUT", "/api/v1/api-security/flow-baselines/"+id, stalePut, cookies, csrf),
		http.StatusConflict, "stale version update")
	disablePut := fmt.Sprintf(`{"flow_id":%q,"enabled":false,"expected_version":1,"steps":[
		{"step_id":"browse","endpoint_id":%q,"sequence":1}]}`, flowID, ep1.ID.String())
	updated := s5OK(t, env.do(t, "PUT", "/api/v1/api-security/flow-baselines/"+id, disablePut, cookies, csrf), "disable flow baseline")
	if s5Num(t, updated.Data, "version") != 2 {
		t.Fatalf("version after update = %v, want 2", updated.Data["version"])
	}
	cfg2, err := s8FlowProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config (disabled): %v", err)
	}
	if len(cfg2.APIFlowBaselines) != 0 {
		t.Fatalf("disabled flow must leave publish payload: %+v", cfg2.APIFlowBaselines)
	}
	if cfg2.APIPolicyVersion != cfg0.APIPolicyVersion {
		t.Fatal("api_policy_version must return to baseline when flow disabled（同内容恒同版）")
	}

	// ---------- 8. 删除 → 发布内容回落；非法前置 400 ----------
	// 重新启用后再删（验证删除路径独立于禁用回落）
	enablePut := fmt.Sprintf(`{"flow_id":%q,"enabled":true,"expected_version":2,"steps":[
		{"step_id":"browse","endpoint_id":%q,"sequence":1}]}`, flowID, ep1.ID.String())
	s5OK(t, env.do(t, "PUT", "/api/v1/api-security/flow-baselines/"+id, enablePut, cookies, csrf), "re-enable flow baseline")
	s5Expect(t, env.post(t, "/api/v1/api-security/flow-baselines",
		fmt.Sprintf(`{"flow_id":"bad-%s","steps":[{"step_id":"a","endpoint_id":%q,"sequence":1,"predecessors":["ghost"]}]}`,
			kw, ep1.ID.String()), cookies, csrf),
		http.StatusBadRequest, "undeclared predecessor rejected")
	delResp := env.do(t, "DELETE", "/api/v1/api-security/flow-baselines/"+id, "", cookies, csrf)
	s5OK(t, delResp, "delete flow baseline")
	cfg3, err := s8FlowProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config (deleted): %v", err)
	}
	if len(cfg3.APIFlowBaselines) != 0 {
		t.Fatalf("deleted flow must leave publish payload: %+v", cfg3.APIFlowBaselines)
	}
	if j := s8GenerateGuardJSON(t, cfg3); strings.Contains(j, "api_flow_baselines") {
		t.Fatal("deleted flow must not appear in caddy json")
	}
}
