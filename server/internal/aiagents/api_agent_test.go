// api_agent_test.go API 安全分析 Agent 单测（fake Registry/Tool 驱动真实 Agent）：
// 默认事实、关键词工具追加、权限失败降级、缺 ID 不编造。
package aiagents

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aiorchestrator"
	"github.com/jiuzhang-waf/server/internal/aitools"
)

// fakeAPITool 测试 Tool：记录调用次数与入参，返回固定结果或错误。
type fakeAPITool struct {
	code      string
	perm      string
	res       interface{}
	err       error
	calls     int
	lastInput map[string]interface{}
}

func (f *fakeAPITool) Code() string                        { return f.code }
func (f *fakeAPITool) Name() string                        { return f.code }
func (f *fakeAPITool) Description() string                 { return f.code }
func (f *fakeAPITool) Version() string                     { return "1.0" }
func (f *fakeAPITool) RiskLevel() string                   { return aitools.RiskReadOnly }
func (f *fakeAPITool) RequiredPermission() string          { return f.perm }
func (f *fakeAPITool) TimeoutSeconds() int                 { return 5 }
func (f *fakeAPITool) MaxResults() int                     { return 50 }
func (f *fakeAPITool) InputSchema() map[string]interface{} { return nil }

func (f *fakeAPITool) Run(_ context.Context, input json.RawMessage) (interface{}, error) {
	f.calls++
	f.lastInput = map[string]interface{}{}
	_ = json.Unmarshal(input, &f.lastInput)
	if f.err != nil {
		return nil, f.err
	}
	return f.res, nil
}

func newAPIAgentRegistry(tools ...*fakeAPITool) *aitools.Registry {
	reg := aitools.NewRegistry()
	for _, t := range tools {
		reg.Register(t)
	}
	return reg
}

func newAPIAnalyzeInput(reg *aitools.Registry, msg string, perms map[string]bool, ids ...string) *aiorchestrator.AnalyzeInput {
	return &aiorchestrator.AnalyzeInput{
		Principal: &aitools.Principal{UserID: uuid.New(), Username: "tester", Permissions: perms},
		TaskID:    uuid.New(),
		TaskType:  aiorchestrator.TaskAPISecurityAnalysis,
		Message:   msg,
		EventIDs:  ids,
		ToolCtx:   &aiorchestrator.ToolContext{Registry: reg},
		Evidence:  aiorchestrator.NewEvidenceSet(),
	}
}

func fakePosture() map[string]interface{} {
	return map[string]interface{}{
		"endpoints": map[string]interface{}{
			"total":              12,
			"by_asset_status":    map[string]interface{}{"DISCOVERED": 3, "CONFIRMED": 9},
			"by_learning_status": map[string]interface{}{"LEARNED": 6},
		},
		"findings": map[string]interface{}{
			"open_total":       4,
			"open_by_severity": map[string]interface{}{"HIGH": 1, "MEDIUM": 3},
		},
		"learning_coverage": 0.5,
		"model_freeze_rate": 0.25,
	}
}

func fakeRuntimeStats() map[string]interface{} {
	return map[string]interface{}{
		"total":           100,
		"by_final_action": map[string]interface{}{"ALLOW": 90, "BLOCK": 10},
		"by_risk_level":   map[string]interface{}{"LOW": 80, "HIGH": 20},
		"top_endpoints": []interface{}{
			map[string]interface{}{"endpoint_key": "GET /api/v1/users", "count": 42},
		},
	}
}

// TestAPISecurityAgentDefaultFacts 默认拉取态势 + 运行时统计，登记证据与结构化事实。
func TestAPISecurityAgentDefaultFacts(t *testing.T) {
	posture := &fakeAPITool{code: "api_posture.get", res: fakePosture()}
	stats := &fakeAPITool{code: "api_runtime.statistics", res: fakeRuntimeStats()}
	reg := newAPIAgentRegistry(posture, stats)
	in := newAPIAnalyzeInput(reg, "API 安全态势怎么样", nil)

	res, err := NewAPISecurityAgent(nil).Analyze(context.Background(), in)
	if err != nil {
		t.Fatalf("Analyze err = %v", err)
	}
	if posture.calls != 1 || stats.calls != 1 {
		t.Errorf("默认工具调用次数 posture=%d stats=%d, want 1/1", posture.calls, stats.calls)
	}
	if in.Evidence.Count() != 2 {
		t.Errorf("证据数 = %d, want 2", in.Evidence.Count())
	}
	for _, kw := range []string{"API 安全态势", "端点总数", "API 运行时统计", "运行时事件总量", "Top 接口"} {
		if !strings.Contains(res.FactsText, kw) {
			t.Errorf("FactsText 缺少 %q\n%s", kw, res.FactsText)
		}
	}
	facts, ok := res.Facts.(map[string]interface{})
	if !ok || facts["api_posture.get"] == nil || facts["api_runtime.statistics"] == nil {
		t.Errorf("Facts 结构化载荷缺失: %#v", res.Facts)
	}
}

// TestAPISecurityAgentKeywordTools 关键词追加资产搜索与风险发现，影子问题自动限定 DISCOVERED。
func TestAPISecurityAgentKeywordTools(t *testing.T) {
	posture := &fakeAPITool{code: "api_posture.get", res: fakePosture()}
	stats := &fakeAPITool{code: "api_runtime.statistics", res: fakeRuntimeStats()}
	asset := &fakeAPITool{code: "api_asset.search", res: map[string]interface{}{
		"total": 2,
		"items": []interface{}{
			map[string]interface{}{"http_method": "GET", "normalized_path": "/api/v1/cards/{id}", "asset_status": "DISCOVERED", "learning_status": "NOT_STARTED", "hit_count": 7},
		},
	}}
	risk := &fakeAPITool{code: "api_risk.search", res: map[string]interface{}{
		"total": 1,
		"items": []interface{}{
			map[string]interface{}{"finding_type": "SHADOW", "severity": "HIGH", "title": "影子接口 /api/v1/cards/{id}", "status": "OPEN"},
		},
	}}
	reg := newAPIAgentRegistry(posture, stats, asset, risk)
	in := newAPIAnalyzeInput(reg, "有哪些影子 API 和越权风险", nil)

	res, err := NewAPISecurityAgent(nil).Analyze(context.Background(), in)
	if err != nil {
		t.Fatalf("Analyze err = %v", err)
	}
	if asset.calls != 1 || risk.calls != 1 {
		t.Fatalf("关键词工具调用次数 asset=%d risk=%d, want 1/1", asset.calls, risk.calls)
	}
	if got := asset.lastInput["asset_status"]; got != "DISCOVERED" {
		t.Errorf("影子问题资产搜索应限定 DISCOVERED, got %v", got)
	}
	if got := risk.lastInput["finding_type"]; got != "SHADOW" {
		t.Errorf("影子关键词应映射 finding_type=SHADOW, got %v", got)
	}
	for _, kw := range []string{"API 资产搜索", "API 风险发现", "影子接口"} {
		if !strings.Contains(res.FactsText, kw) {
			t.Errorf("FactsText 缺少 %q\n%s", kw, res.FactsText)
		}
	}
	if in.Evidence.Count() != 4 {
		t.Errorf("证据数 = %d, want 4", in.Evidence.Count())
	}
}

// TestAPISecurityAgentPermissionDeniedDegrades 权限失败如实写入事实并降级，其余事实保留，不 panic。
func TestAPISecurityAgentPermissionDeniedDegrades(t *testing.T) {
	posture := &fakeAPITool{code: "api_posture.get", perm: "api_runtime.read", res: fakePosture()}
	stats := &fakeAPITool{code: "api_runtime.statistics", res: fakeRuntimeStats()}
	reg := newAPIAgentRegistry(posture, stats)
	// 无任何权限：posture 被 Registry 权限校验拒绝，stats（无权限要求）成功
	in := newAPIAnalyzeInput(reg, "API 安全态势怎么样", map[string]bool{})

	res, err := NewAPISecurityAgent(nil).Analyze(context.Background(), in)
	if err != nil {
		t.Fatalf("Analyze err = %v", err)
	}
	if posture.calls != 0 {
		t.Errorf("权限不足的 Tool 不应进入 Run, calls=%d", posture.calls)
	}
	if stats.calls != 1 {
		t.Errorf("运行时统计应正常执行, calls=%d", stats.calls)
	}
	if !strings.Contains(res.FactsText, "暂无法确认") || !strings.Contains(res.FactsText, "API 运行时统计") {
		t.Errorf("失败应如实降级且保留其余事实\n%s", res.FactsText)
	}
	if in.Evidence.Count() != 1 {
		t.Errorf("证据数 = %d, want 1（失败调用不登记证据）", in.Evidence.Count())
	}
}

// TestAPISecurityAgentToolErrorDegrades Tool 执行错误同样降级不中断。
func TestAPISecurityAgentToolErrorDegrades(t *testing.T) {
	posture := &fakeAPITool{code: "api_posture.get", err: errors.New("db down")}
	stats := &fakeAPITool{code: "api_runtime.statistics", res: fakeRuntimeStats()}
	reg := newAPIAgentRegistry(posture, stats)
	in := newAPIAnalyzeInput(reg, "API 安全态势怎么样", nil)

	res, err := NewAPISecurityAgent(nil).Analyze(context.Background(), in)
	if err != nil {
		t.Fatalf("Analyze err = %v", err)
	}
	if !strings.Contains(res.FactsText, "暂无法确认") {
		t.Errorf("Tool 错误应写入事实文本\n%s", res.FactsText)
	}
}

// TestAPISecurityAgentMissingIDDoesNotFabricate 缺接口 ID 时不调用学习状态 Tool，明确提示补充。
func TestAPISecurityAgentMissingIDDoesNotFabricate(t *testing.T) {
	posture := &fakeAPITool{code: "api_posture.get", res: fakePosture()}
	stats := &fakeAPITool{code: "api_runtime.statistics", res: fakeRuntimeStats()}
	asset := &fakeAPITool{code: "api_asset.search", res: map[string]interface{}{"total": 0, "items": []interface{}{}}}
	learning := &fakeAPITool{code: "api_learning.status", res: map[string]interface{}{}}
	reg := newAPIAgentRegistry(posture, stats, asset, learning)
	in := newAPIAnalyzeInput(reg, "这个接口的学习状态怎么样", nil)

	res, err := NewAPISecurityAgent(nil).Analyze(context.Background(), in)
	if err != nil {
		t.Fatalf("Analyze err = %v", err)
	}
	if learning.calls != 0 {
		t.Errorf("缺接口 ID 不得调用 api_learning.status（不编造 ID）, calls=%d", learning.calls)
	}
	if !strings.Contains(res.FactsText, "请补充接口 ID") {
		t.Errorf("缺少 ID 时应明确提示补充\n%s", res.FactsText)
	}
}

// TestAPISecurityAgentLearningWithID 携带接口 ID 时正常查询学习状态。
func TestAPISecurityAgentLearningWithID(t *testing.T) {
	posture := &fakeAPITool{code: "api_posture.get", res: fakePosture()}
	stats := &fakeAPITool{code: "api_runtime.statistics", res: fakeRuntimeStats()}
	asset := &fakeAPITool{code: "api_asset.search", res: map[string]interface{}{"total": 0, "items": []interface{}{}}}
	endpointID := uuid.NewString()
	learning := &fakeAPITool{code: "api_learning.status", res: map[string]interface{}{
		"endpoint_id":     endpointID,
		"learning_status": "LEARNING",
		"samples":         map[string]interface{}{"total": 30, "accepted": 25, "excluded": 5},
	}}
	reg := newAPIAgentRegistry(posture, stats, asset, learning)
	in := newAPIAnalyzeInput(reg, "接口 "+endpointID+" 的学习状态", nil, endpointID)

	res, err := NewAPISecurityAgent(nil).Analyze(context.Background(), in)
	if err != nil {
		t.Fatalf("Analyze err = %v", err)
	}
	if learning.calls != 1 {
		t.Fatalf("api_learning.status calls = %d, want 1", learning.calls)
	}
	if got := learning.lastInput["endpoint_id"]; got != endpointID {
		t.Errorf("endpoint_id = %v, want %s", got, endpointID)
	}
	if !strings.Contains(res.FactsText, "LEARNING") {
		t.Errorf("FactsText 应含学习状态\n%s", res.FactsText)
	}
}

// TestAPISecurityAgentModelDiffNeedsTwoIDs 模型差异缺 ID 提示补充，带两个 ID 正常调用。
func TestAPISecurityAgentModelDiffNeedsTwoIDs(t *testing.T) {
	posture := &fakeAPITool{code: "api_posture.get", res: fakePosture()}
	stats := &fakeAPITool{code: "api_runtime.statistics", res: fakeRuntimeStats()}
	diff := &fakeAPITool{code: "api_model.diff", res: map[string]interface{}{
		"from": map[string]interface{}{"version_number": 1, "status": "FORMAL"},
		"to":   map[string]interface{}{"version_number": 2, "status": "DRAFT"},
	}}
	reg := newAPIAgentRegistry(posture, stats, diff)

	// 无 ID：提示补充，不调用
	in := newAPIAnalyzeInput(reg, "这两个模型版本有什么差异", nil)
	res, err := NewAPISecurityAgent(nil).Analyze(context.Background(), in)
	if err != nil {
		t.Fatalf("Analyze err = %v", err)
	}
	if diff.calls != 0 {
		t.Errorf("缺模型版本 ID 不得调用 api_model.diff, calls=%d", diff.calls)
	}
	if !strings.Contains(res.FactsText, "两个模型版本 ID") {
		t.Errorf("应提示补充两个模型版本 ID\n%s", res.FactsText)
	}

	// 两个 ID：正常调用并映射 id/other_id
	idA, idB := uuid.NewString(), uuid.NewString()
	in2 := newAPIAnalyzeInput(reg, "对比模型版本差异 "+idA+" "+idB, nil, idA, idB)
	if _, err := NewAPISecurityAgent(nil).Analyze(context.Background(), in2); err != nil {
		t.Fatalf("Analyze err = %v", err)
	}
	if diff.calls != 1 || diff.lastInput["id"] != idA || diff.lastInput["other_id"] != idB {
		t.Errorf("api_model.diff 调用参数错误: calls=%d input=%v", diff.calls, diff.lastInput)
	}
}
