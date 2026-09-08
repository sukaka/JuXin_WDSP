// llm_models_test.go LLM 授权模型名单下发单测（W10-LLM / P2-04，纯函数不依赖数据库）：
// gateway_runtime.api_llm_allowed_models 逗号分隔解析、缺省不下发、非法取值报错。
package guardconfig

import (
	"strconv"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// TestApplyGatewayRuntimeLLMAllowedModels 名单解析：逗号分隔/trim/去空项/去重保序；
// 缺省与空串不下发（nil），与「缺省不判定」纪律一致。
func TestApplyGatewayRuntimeLLMAllowedModels(t *testing.T) {
	cfg := &gatewayconfig.GuardConfig{}
	err := applyGatewayRuntimeSettings(cfg, map[string]string{
		"api_llm_allowed_models": " gpt-4o , ,gpt-4o-mini,gpt-4o ,qwen-max ",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"gpt-4o", "gpt-4o-mini", "qwen-max"}
	if len(cfg.APILLMAllowedModels) != len(want) {
		t.Fatalf("models = %+v", cfg.APILLMAllowedModels)
	}
	for i := range want {
		if cfg.APILLMAllowedModels[i] != want[i] {
			t.Fatalf("models[%d] = %q want %q", i, cfg.APILLMAllowedModels[i], want[i])
		}
	}

	// 缺省（map 无键）/空串值：保持 nil → 发布不下发，网关不判定
	for _, kv := range []map[string]string{
		{},
		{"api_llm_allowed_models": "  "},
		{"api_llm_allowed_models": " , , "},
	} {
		empty := &gatewayconfig.GuardConfig{}
		if err := applyGatewayRuntimeSettings(empty, kv); err != nil {
			t.Fatal(err)
		}
		if empty.APILLMAllowedModels != nil {
			t.Fatalf("default must stay nil: %+v (kv=%v)", empty.APILLMAllowedModels, kv)
		}
	}
}

// TestParseLLMAllowedModelsGuardrails 防误配护栏：单项超长/条数超限如实报错（不静默截断）。
func TestParseLLMAllowedModelsGuardrails(t *testing.T) {
	if _, err := parseLLMAllowedModels(strings.Repeat("m", maxLLMAllowedModelLen+1)); err == nil {
		t.Fatal("overlong item must fail")
	}
	over := make([]string, maxLLMAllowedModels+1)
	for i := range over {
		over[i] = "model-" + strings.Repeat("a", 1) + strconv.Itoa(i)
	}
	if _, err := parseLLMAllowedModels(strings.Join(over, ",")); err == nil {
		t.Fatal("too many models must fail")
	}
	// 边界内合法
	ok := []string{"gpt-4o", "qwen-max"}
	got, err := parseLLMAllowedModels(strings.Join(ok, ","))
	if err != nil || len(got) != 2 {
		t.Fatalf("valid: %+v err=%v", got, err)
	}
}
