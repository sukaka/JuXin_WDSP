// stage8_api_llm_mcp_test.go MCP 内容级检测配套（W12-GW / P2-04 续，任务书 §154）集成测试。
// 覆盖：迁移 000070 mcp_method 列落位（类型/默认值）；apillm 采集链路 mcp_method
// 透传与列宽兜底截断；SQL Store 列表回读。网关侧方法识别/词表核对/敏感参数检测
// 见 gateway dynamic_security 单测（detectors/mcp_test.go、pipeline/pipeline_mcp_test.go）。
//
// 说明：网关事件 llm_observation.mcp_method → Record.LLMObservation → ObservationInput
// 的采集接线为集成方装配（apillm.LLMObservation 同一 JSON 契约，字段透传无需改采集器），
// 本测试以 ObservationInput 手工映射驱动同一写入接口。
package tests

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/server/internal/apillm"
)

// TestStage8LLMMCPMigrationColumn 迁移 000070 落位：mcp_method 列存在、
// VARCHAR(128)、NOT NULL DEFAULT ”（存量行回填空串 = 非 MCP 口径）。
func TestStage8LLMMCPMigrationColumn(t *testing.T) {
	env := setupStage8Env(t)

	var dataType, nullable, def string
	var maxLen int
	if err := env.db.QueryRow(context.Background(), `SELECT data_type, character_maximum_length, is_nullable, column_default
		FROM information_schema.columns
		WHERE table_name='api_llm_observations' AND column_name='mcp_method'`).
		Scan(&dataType, &maxLen, &nullable, &def); err != nil {
		t.Fatalf("mcp_method column missing: %v", err)
	}
	if dataType != "character varying" || maxLen != 128 || nullable != "NO" || def != "''::character varying" {
		t.Fatalf("mcp_method shape: type=%s len=%d nullable=%s default=%s", dataType, maxLen, nullable, def)
	}
}

// TestStage8LLMMCPObservationRoundtrip 采集回环：mcp_method 透传落库并随列表回读；
// 超长方法名按列宽兜底截断；llm.mcp_* 明细入 findings（证据不含参数值，网关纪律透传）。
func TestStage8LLMMCPObservationRoundtrip(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	endpointKey := "POST /mcp-" + rid
	now := time.Now().UTC()
	rec := apillm.NewObsStore(env.db)

	details := []dsctx.DetectorMatch{
		{Detector: "llm", RuleID: "llm.mcp_sensitive_arg", Category: "OBSERVE", Severity: "MEDIUM",
			Evidence: map[string]string{"tool": "query_customer", "data_type": "phone"}},
		{Detector: "llm", RuleID: "llm.mcp_unknown_method", Category: "OBSERVE", Severity: "LOW",
			Evidence: map[string]string{"method": "custom/doEverything"}},
		{Detector: "waf", RuleID: "942100", Severity: "HIGH"}, // 非 llm.* 明细：不入 findings
	}
	in := apillm.ObservationInput{
		RequestID: "mcp-req-" + rid, OccurredAt: now, EndpointKey: endpointKey,
		IdentityFingerprint: "auth:u1",
		Observation: apillm.LLMObservation{
			PromptPresent: true, PromptLenBucket: "XS", MCPMethod: "tools/call",
		},
		Details: details,
	}
	if err := rec.RecordLLMObservation(ctx, in); err != nil {
		t.Fatalf("record: %v", err)
	}
	// 落库断言：mcp_method 透传；findings 只含 2 条 llm.mcp_*（waf 明细剔除）
	var mcpMethod string
	var findingsRaw []byte
	if err := env.db.QueryRow(ctx, `SELECT mcp_method, findings
		FROM api_llm_observations WHERE endpoint_key=$1`, endpointKey).Scan(&mcpMethod, &findingsRaw); err != nil {
		t.Fatalf("query: %v", err)
	}
	if mcpMethod != "tools/call" {
		t.Fatalf("mcp_method = %q", mcpMethod)
	}
	var findings []dsctx.DetectorMatch
	if err := json.Unmarshal(findingsRaw, &findings); err != nil || len(findings) != 2 {
		t.Fatalf("findings = %s (err=%v)", findingsRaw, err)
	}
	for _, f := range findings {
		if !strings.HasPrefix(f.RuleID, "llm.mcp_") {
			t.Fatalf("non-mcp finding leaked: %+v", f)
		}
		for k, v := range f.Evidence {
			if strings.Contains(v, "13800138000") {
				t.Fatalf("evidence must not contain arg value: %s=%s", k, v)
			}
		}
	}

	// 列宽兜底：超长方法名（异常网关直送）截断 128，不报错不越宽
	longMethod := strings.Repeat("m", 200)
	if err := rec.RecordLLMObservation(ctx, apillm.ObservationInput{
		RequestID: "mcp-req-long-" + rid, OccurredAt: now, EndpointKey: endpointKey,
		Observation: apillm.LLMObservation{MCPMethod: longMethod},
	}); err != nil {
		t.Fatalf("record long method: %v", err)
	}
	if err := env.db.QueryRow(ctx, `SELECT mcp_method FROM api_llm_observations
		WHERE endpoint_key=$1 AND mcp_method LIKE 'mmm%'`, endpointKey).Scan(&mcpMethod); err != nil {
		t.Fatalf("query long: %v", err)
	}
	if len([]rune(mcpMethod)) != 128 {
		t.Fatalf("mcp_method truncation = %d runes, want 128", len([]rune(mcpMethod)))
	}

	// 列表回读：mcp_method 随明细返回
	store := apillm.NewStore(env.db)
	items, total, err := store.ListObservations(ctx, apillm.ObservationFilter{
		Days: 7, EndpointKey: endpointKey, Page: 1, PageSize: 20,
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("list = total %d items %d", total, len(items))
	}
	var sawToolsCall bool
	for _, it := range items {
		if it.MCPMethod == "tools/call" {
			sawToolsCall = true
		}
	}
	if !sawToolsCall {
		t.Fatalf("list items must carry mcp_method: %+v", items)
	}
}
