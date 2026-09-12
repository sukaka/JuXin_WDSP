// stage8_mask_publish_e2e_test.go MASK_RESPONSE 发布侧端到端贯通测试（任务书 W5-C 分片）。
//
// 链路：管理面 HTTP API 配置脱敏规则（POST/PATCH /api/v1/api-security/masking-rules）
//
//	→ 发布通道组装（guardconfig.Provider.BuildGuardConfig，与 app.go 同一接线：
//	  SetMaskRuleLister(NewMaskRuleStore(db))）
//	→ 生成器产出 Caddy JSON：jiuzhang_guard 处理器内 api_mask_rules 段
//	  （键名与网关 maskRuleJSON 契约逐一对应：endpoint_key/field_path/data_type/algorithm/params）
//	→ 访问控制版本快照落库/回读保留规则（回滚路径不丢脱敏配置）
//	→ 规则启停驱动 api_policy_version 确定性变化（生效校验锚点，P0-21）。
//
// 覆盖边界（如实声明）：本测试覆盖「配置 → 下发内容」的 server 侧全链；
// 网关侧真实脱敏改写与 Content-Length 修正由模块级测试覆盖
// （gateway/modules/jiuzhang_guard/apiresponse_test.go: TestServeNext_MaskResponseProtect），
// 两侧经同一下发契约键名衔接；真网关形态可由 test/waf/scripts 的 stage8 系列 harness 扩展复用。
//
// 运行方式（与 make stage8-test-api 一致）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestStage8MaskResponsePublishE2E -count=1
package tests

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/accesscontrolversions"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/guardconfig"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
	"github.com/jiuzhang-waf/server/internal/ratelimitpolicies"
	"github.com/jiuzhang-waf/server/internal/trustedproxies"
)

// s8MaskProvider 按 app.go 同一接线构造发布组装器（WDSP 形态 + 脱敏规则读取）。
func s8MaskProvider(env *testEnv) *guardconfig.Provider {
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
	p.SetMaskRuleLister(guardconfig.NewMaskRuleStore(env.db))
	return p
}

// s8GenerateGuardJSON 生成单应用 Caddy 配置（guard 处理器所在路由），返回配置 JSON。
func s8GenerateGuardJSON(t *testing.T, cfg *gatewayconfig.GuardConfig) string {
	t.Helper()
	port := 8080
	gen, err := gatewayconfig.Generate(gatewayconfig.GenerateInput{
		Apps: []gatewayconfig.AppData{{
			AppID: uuid.NewString(), Code: "maskshop", ProtectionMode: applications.ModeProtect,
			Domains: []applications.Domain{{
				NormalizedHostname: "mask.example.com", HTTPEnabled: true, HTTPPort: &port, Status: "ACTIVE",
			}},
			Upstreams: []applications.Upstream{{NormalizedHost: "127.0.0.1", Port: 9001, Status: "ACTIVE", Weight: 1}},
		}},
		AdminSocket: "/var/run/caddy/admin.sock",
		Guard:       cfg,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return gen.JSON
}

func TestStage8MaskResponsePublishE2E(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	cookies, csrf := env.s5Login(t, "s8mx", "SECURITY_ADMIN")

	// ---------- 1. 基线：无启用规则 → 不下发 api_mask_rules 段 ----------
	cfg0, err := s8MaskProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config (baseline): %v", err)
	}
	if len(cfg0.APIMaskRules) != 0 {
		t.Fatalf("baseline mask rules = %+v, want empty", cfg0.APIMaskRules)
	}
	if cfg0.APIPolicyVersion == "" {
		t.Fatal("api_policy_version must always be computed (P0-21 生效校验锚点)")
	}
	if j := s8GenerateGuardJSON(t, cfg0); strings.Contains(j, "api_mask_rules") {
		t.Fatal("baseline caddy json must not contain api_mask_rules")
	}

	// ---------- 2. 管理面 HTTP API 创建 ENDPOINT 级脱敏规则 ----------
	createBody := `{"name":"用户手机号脱敏","scope":"ENDPOINT","endpoint_key":"POST /v1/users",` +
		`"field_path":"users[].phone","data_type":"phone","algorithm":"MASK",` +
		`"params_json":{"keep_head":3,"keep_tail":4}}`
	created := s5OK(t, env.post(t, "/api/v1/api-security/masking-rules", createBody, cookies, csrf), "create masking rule")
	ruleID, _ := created.Data["id"].(string)
	if ruleID == "" {
		t.Fatalf("created rule id missing: %+v", created.Data)
	}

	// ---------- 3. 发布通道组装：规则进入 GuardConfig ----------
	cfg1, err := s8MaskProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config: %v", err)
	}
	if len(cfg1.APIMaskRules) != 1 {
		t.Fatalf("mask rules = %+v, want 1", cfg1.APIMaskRules)
	}
	r := cfg1.APIMaskRules[0]
	if r.EndpointKey != "POST /v1/users" || r.FieldPath != "users[].phone" ||
		r.DataType != "phone" || r.Algorithm != "MASK" {
		t.Fatalf("mask rule payload mismatch: %+v", r)
	}
	if r.Params["keep_head"] != float64(3) || r.Params["keep_tail"] != float64(4) {
		t.Fatalf("mask rule params lost: %+v", r.Params)
	}
	// 策略版本戳随规则内容确定性变化（同内容恒同版；内容变则版变）
	if cfg1.APIPolicyVersion == cfg0.APIPolicyVersion {
		t.Fatal("api_policy_version must change when mask rules change")
	}

	// ---------- 4. 生成器：Caddy JSON 的 jiuzhang_guard 处理器含 api_mask_rules（网关契约键名） ----------
	j := s8GenerateGuardJSON(t, cfg1)
	for _, want := range []string{
		`"handler":"jiuzhang_guard"`,
		`"api_dynamic_protection":true`,
		`"api_protection_mode":"PROTECT"`,
		`"api_mask_rules":[{"endpoint_key":"POST /v1/users","field_path":"users[].phone",` +
			`"data_type":"phone","algorithm":"MASK","params":{"keep_head":3,"keep_tail":4}}]`,
		`"api_policy_version":"` + cfg1.APIPolicyVersion + `"`,
	} {
		if !strings.Contains(j, want) {
			t.Errorf("caddy json missing %q", want)
		}
	}

	// ---------- 5. 版本快照落库/回读：脱敏规则随快照保留（回滚路径不丢配置） ----------
	versionID, err := s8MaskProvider(env).SaveVersionSnapshot(ctx, cfg1, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("save version snapshot: %v", err)
	}
	back, err := s8MaskProvider(env).GetVersionConfig(ctx, versionID)
	if err != nil {
		t.Fatalf("get version config: %v", err)
	}
	if len(back.APIMaskRules) != 1 || back.APIMaskRules[0].FieldPath != "users[].phone" {
		t.Fatalf("snapshot round-trip lost mask rules: %+v", back.APIMaskRules)
	}

	// ---------- 6. 停用规则 → 发布内容回落（版本戳确定性回到基线） ----------
	s5OK(t, env.do(t, "PATCH", "/api/v1/api-security/masking-rules/"+ruleID,
		`{"enabled":false}`, cookies, csrf), "disable masking rule")
	cfg2, err := s8MaskProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config (disabled): %v", err)
	}
	if len(cfg2.APIMaskRules) != 0 {
		t.Fatalf("disabled rule must leave publish payload: %+v", cfg2.APIMaskRules)
	}
	if cfg2.APIPolicyVersion != cfg0.APIPolicyVersion {
		t.Fatal("api_policy_version must return to baseline when rule disabled（同内容恒同版）")
	}
	if j := s8GenerateGuardJSON(t, cfg2); strings.Contains(j, "api_mask_rules") {
		t.Fatal("disabled rule must not appear in caddy json")
	}

	// 权限底线：未登录访问 401（POST 无会话会先被 CSRF 拦截，用 GET 断言认证底线，
	// 与既有集成测试同一口径）
	resp := env.do(t, "GET", "/api/v1/api-security/masking-rules", "", nil, "")
	s5Expect(t, resp, 401, "unauthenticated masking rules list")
}
