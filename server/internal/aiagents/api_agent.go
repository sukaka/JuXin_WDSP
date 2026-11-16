// api_agent.go API 安全分析 Agent（阶段8 / WDSP 形态专属，code=api_security）。
// 仅在 cfg.Product.APIDynamicProtectionEnabled() 时由 app.go 注册并同步进 ai_agents 目录；
// 纯 WAF 形态不装配（编排器对未注册 Agent 跳过调度，不产生伪造事实）。
//
// 纪律：
//   - 事实全部来自 aitools 注册中心的 READ_ONLY Tool（api_posture/api_runtime/api_asset/
//     api_model/api_parameter/api_risk/api_weakness/api_sensitive/api_learning），
//     一律经 ToolCtx.CallTool 调用并登记 Evidence，Agent 不直查数据库；
//   - 权限不足 / Tool 停用 / 查询失败如实写入事实文本并降级继续，不 panic、不编造；
//   - 需要业务 ID（接口 ID / 模型版本 ID）而消息中未携带时，明确提示补充，不用猜测值顶替。
package aiagents

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aiorchestrator"
)

// APISecurityAgent API 安全分析（资产/态势/模型/参数/风险/弱点/敏感数据/学习状态）。
type APISecurityAgent struct{ base }

// NewAPISecurityAgent 创建。
func NewAPISecurityAgent(db *pgxpool.Pool) *APISecurityAgent {
	return &APISecurityAgent{base{code: "api_security", db: db}}
}

// apiRiskFindingType 关键词 → api_risk.search finding_type 映射（按优先级取首个命中）。
var apiRiskFindingType = []struct {
	keywords []string
	finding  string
}{
	{[]string{"bola"}, "BOLA"},
	{[]string{"bfla"}, "BFLA"},
	{[]string{"影子", "shadow"}, "SHADOW"},
	{[]string{"僵尸", "zombie"}, "ZOMBIE"},
	{[]string{"偏离"}, "SCHEMA_DEVIATION"},
	{[]string{"泄露", "敏感", "涉敏"}, "SENSITIVE_LEAK"},
}

// Analyze 确定性 Tool 选择：默认态势+运行时统计，按关键词追加域内只读 Tool。
func (a *APISecurityAgent) Analyze(ctx context.Context, in *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error) {
	var b strings.Builder
	b.WriteString("**API 安全分析**（数据来自 API 动态防护域只读 Tool，AI 不执行任何变更）\n")
	facts := map[string]interface{}{}
	msg := strings.ToLower(in.Message)

	// 1. 默认事实：API 安全态势 + 运行时统计
	a.addPosture(ctx, in, &b, facts)
	a.addRuntimeStats(ctx, in, &b, facts)

	// 2. 关键词追加：资产搜索（影子/僵尸/未确认/清单；路径关键字取消息中的 URI）
	if hasAny(msg, "影子", "shadow", "僵尸", "zombie", "资产", "清单", "未确认", "待确认", "新发现", "接口", "端点", "搜索", "查找") ||
		extractProfileURI(in.Message) != "" {
		a.addAssetSearch(ctx, in, &b, facts, msg)
	}
	// 风险发现（影子/僵尸/越权/BOLA/BFLA/偏离/泄露/敏感/风险/发现）
	if hasAny(msg, "影子", "shadow", "僵尸", "zombie", "bola", "bfla", "越权", "偏离", "泄露", "敏感", "涉敏", "风险", "发现", "finding") {
		a.addRiskSearch(ctx, in, &b, facts, msg)
	}
	// 弱点整改
	if hasAny(msg, "弱点", "整改", "超期", "催办", "weakness") {
		a.addWeaknessSearch(ctx, in, &b, facts, msg)
	}
	// 敏感数据类型
	if hasAny(msg, "敏感", "涉敏", "泄露", "脱敏") {
		a.addSensitiveSearch(ctx, in, &b, facts)
	}
	// 学习状态（需接口 ID）
	if hasAny(msg, "学习", "learn", "样本") {
		a.addLearningStatus(ctx, in, &b, facts)
	}
	// 模型版本差异（需两个模型版本 ID）
	if hasAny(msg, "差异", "diff", "对比", "比较", "变更") {
		a.addModelDiff(ctx, in, &b, facts)
	}
	// 参数模型（需模型版本 ID）
	if hasAny(msg, "参数", "偏离") {
		a.addParameters(ctx, in, &b, facts)
	}

	b.WriteString("\n> 以上仅为只读分析；资产确认、模型冻结、策略发布、弱点流转等变更均需走既有人工审核与发布流程。")
	return &aiorchestrator.AnalyzeResult{FactsText: b.String(), Facts: facts}, nil
}

// callAPITool 统一 Tool 调用：失败如实写入事实并返回 ok=false（降级而非中断）。
func (a *APISecurityAgent) callAPITool(ctx context.Context, in *aiorchestrator.AnalyzeInput, facts map[string]interface{},
	b *strings.Builder, code, label string, input map[string]interface{}) (map[string]interface{}, string, bool) {
	res, ref, err := callTool(ctx, in, in.Principal, code, input, "%s", label)
	if err != nil {
		fmt.Fprintf(b, "- %s：查询未完成（%v），该项数据暂无法确认，不做推测。\n", label, err)
		return nil, "", false
	}
	facts[code] = res
	return asStringMap(res), ref, true
}

// addPosture 默认事实 1：API 安全态势（api_posture.get）。
func (a *APISecurityAgent) addPosture(ctx context.Context, in *aiorchestrator.AnalyzeInput, b *strings.Builder, facts map[string]interface{}) {
	m, ref, ok := a.callAPITool(ctx, in, facts, b, "api_posture.get", "API 安全态势", map[string]interface{}{})
	if !ok {
		return
	}
	b.WriteString("\n**API 安全态势**\n")
	if ep, ok := m["endpoints"].(map[string]interface{}); ok {
		b.WriteString(fmtKV("端点总数", ep["total"]))
		b.WriteString(fmtKV("资产状态分布", renderStringIntMap(ep["by_asset_status"])))
		b.WriteString(fmtKV("学习状态分布", renderStringIntMap(ep["by_learning_status"])))
	}
	if fd, ok := m["findings"].(map[string]interface{}); ok {
		b.WriteString(fmtKV("未闭环风险发现", fd["open_total"]))
		b.WriteString(fmtKV("按严重级别", renderStringIntMap(fd["open_by_severity"])))
	}
	b.WriteString(fmtKV("学习覆盖率", renderPercent(m["learning_coverage"])))
	b.WriteString(fmtKV("模型冻结率", renderPercent(m["model_freeze_rate"])))
	b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
}

// addRuntimeStats 默认事实 2：API 运行时统计（api_runtime.statistics）。
func (a *APISecurityAgent) addRuntimeStats(ctx context.Context, in *aiorchestrator.AnalyzeInput, b *strings.Builder, facts map[string]interface{}) {
	m, ref, ok := a.callAPITool(ctx, in, facts, b, "api_runtime.statistics", "API 运行时统计", map[string]interface{}{})
	if !ok {
		return
	}
	b.WriteString("\n**API 运行时统计**\n")
	b.WriteString(fmtKV("运行时事件总量", m["total"]))
	b.WriteString(fmtKV("最终动作分布", renderStringIntMap(m["by_final_action"])))
	b.WriteString(fmtKV("风险级别分布", renderStringIntMap(m["by_risk_level"])))
	if tops, ok := m["top_endpoints"].([]interface{}); ok && len(tops) > 0 {
		b.WriteString("Top 接口：\n")
		for i, it := range tops {
			if i >= 5 {
				break
			}
			if e, ok := it.(map[string]interface{}); ok {
				fmt.Fprintf(b, "- %v：%v 次\n", e["endpoint_key"], e["count"])
			}
		}
	}
	b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
}

// addAssetSearch 资产搜索（api_asset.search；影子/未确认类问题自动限定 DISCOVERED）。
func (a *APISecurityAgent) addAssetSearch(ctx context.Context, in *aiorchestrator.AnalyzeInput, b *strings.Builder, facts map[string]interface{}, msg string) {
	input := map[string]interface{}{"limit": 10}
	if kw := extractProfileURI(in.Message); kw != "" {
		input["keyword"] = kw
	}
	if hasAny(msg, "影子", "shadow", "未确认", "待确认", "新发现") {
		input["asset_status"] = "DISCOVERED"
	}
	m, ref, ok := a.callAPITool(ctx, in, facts, b, "api_asset.search", "API 资产搜索", input)
	if !ok {
		return
	}
	b.WriteString("\n**API 资产搜索**\n")
	b.WriteString(fmtKV("匹配端点数", m["total"]))
	for _, it := range mapItems(m, 5) {
		if e, ok := it.(map[string]interface{}); ok {
			fmt.Fprintf(b, "- %v %v（资产 %v / 学习 %v，命中 %v 次）\n",
				e["http_method"], e["normalized_path"], e["asset_status"], e["learning_status"], e["hit_count"])
		}
	}
	b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
}

// addRiskSearch 风险发现搜索（api_risk.search；按关键词映射 finding_type）。
func (a *APISecurityAgent) addRiskSearch(ctx context.Context, in *aiorchestrator.AnalyzeInput, b *strings.Builder, facts map[string]interface{}, msg string) {
	input := map[string]interface{}{"limit": 10}
	findingType := ""
	for _, rule := range apiRiskFindingType {
		if hasAny(msg, rule.keywords...) {
			findingType = rule.finding
			break
		}
	}
	if findingType != "" {
		input["finding_type"] = findingType
	}
	if hasAny(msg, "未闭环", "未处理", "待处理", "新增") {
		input["status"] = "OPEN"
	}
	label := "API 风险发现"
	if findingType != "" {
		label += "（" + findingType + "）"
	}
	m, ref, ok := a.callAPITool(ctx, in, facts, b, "api_risk.search", label, input)
	if !ok {
		return
	}
	b.WriteString("\n**API 风险发现**\n")
	b.WriteString(fmtKV("匹配发现数", m["total"]))
	for _, it := range mapItems(m, 5) {
		if f, ok := it.(map[string]interface{}); ok {
			fmt.Fprintf(b, "- [%v/%v] %v（状态 %v）\n", f["finding_type"], f["severity"], f["title"], f["status"])
		}
	}
	b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
}

// addWeaknessSearch 弱点搜索（api_weakness.search）。
func (a *APISecurityAgent) addWeaknessSearch(ctx context.Context, in *aiorchestrator.AnalyzeInput, b *strings.Builder, facts map[string]interface{}, msg string) {
	input := map[string]interface{}{"limit": 10}
	if hasAny(msg, "待整改", "整改") {
		input["status"] = "TO_FIX"
	}
	m, ref, ok := a.callAPITool(ctx, in, facts, b, "api_weakness.search", "API 弱点搜索", input)
	if !ok {
		return
	}
	b.WriteString("\n**API 弱点**\n")
	b.WriteString(fmtKV("匹配弱点数", m["total"]))
	for _, it := range mapItems(m, 5) {
		if w, ok := it.(map[string]interface{}); ok {
			fmt.Fprintf(b, "- %v（%v/%v，状态 %v，触发 %v 次）\n",
				w["weakness_name"], w["category"], w["severity"], w["status"], w["trigger_count"])
		}
	}
	b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
}

// addSensitiveSearch 敏感数据类型搜索（api_sensitive.search；类型定义即识别规则，不含样本值）。
func (a *APISecurityAgent) addSensitiveSearch(ctx context.Context, in *aiorchestrator.AnalyzeInput, b *strings.Builder, facts map[string]interface{}) {
	m, ref, ok := a.callAPITool(ctx, in, facts, b, "api_sensitive.search", "敏感数据类型", map[string]interface{}{"limit": 10})
	if !ok {
		return
	}
	b.WriteString("\n**敏感数据类型（识别规则定义，不含样本值）**\n")
	b.WriteString(fmtKV("类型总数", m["total"]))
	for _, it := range mapItems(m, 5) {
		if s, ok := it.(map[string]interface{}); ok {
			fmt.Fprintf(b, "- %v（等级 %v，状态 %v）\n", s["name"], s["level"], s["status"])
		}
	}
	b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
}

// addLearningStatus 学习状态（api_learning.status；需接口 ID，缺失时明确提示补充）。
func (a *APISecurityAgent) addLearningStatus(ctx context.Context, in *aiorchestrator.AnalyzeInput, b *strings.Builder, facts map[string]interface{}) {
	if len(in.EventIDs) == 0 {
		b.WriteString("\n**学习状态**：当前问题未携带接口 ID，无法定位具体接口；请补充接口 ID（UUID，可在 API 资产列表复制）后再查询学习状态。\n")
		return
	}
	endpointID := in.EventIDs[0]
	m, ref, ok := a.callAPITool(ctx, in, facts, b, "api_learning.status", fmt.Sprintf("接口 %s 学习状态", endpointID),
		map[string]interface{}{"endpoint_id": endpointID})
	if !ok {
		return
	}
	b.WriteString(fmt.Sprintf("\n**接口学习状态**（%s）\n", endpointID))
	b.WriteString(fmtKV("学习状态", m["learning_status"]))
	if samples, ok := m["samples"].(map[string]interface{}); ok {
		b.WriteString(fmtKV("样本统计", fmt.Sprintf("总 %v / 采纳 %v / 排除 %v", samples["total"], samples["accepted"], samples["excluded"])))
	}
	b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
}

// addModelDiff 模型版本差异（api_model.diff；需两个模型版本 ID，缺失时明确提示补充）。
func (a *APISecurityAgent) addModelDiff(ctx context.Context, in *aiorchestrator.AnalyzeInput, b *strings.Builder, facts map[string]interface{}) {
	if len(in.EventIDs) < 2 {
		b.WriteString("\n**模型版本差异**：比较模型差异需要两个模型版本 ID；请补充目标版本与对比基准版本 ID（UUID）后再查询。\n")
		return
	}
	id, otherID := in.EventIDs[0], in.EventIDs[1]
	m, ref, ok := a.callAPITool(ctx, in, facts, b, "api_model.diff", fmt.Sprintf("模型版本差异 %s vs %s", id, otherID),
		map[string]interface{}{"id": id, "other_id": otherID})
	if !ok {
		return
	}
	b.WriteString("\n**模型版本差异**\n")
	if to, ok := m["to"].(map[string]interface{}); ok {
		b.WriteString(fmtKV("目标版本", fmt.Sprintf("v%v（%v）", to["version_number"], to["status"])))
	}
	if from, ok := m["from"].(map[string]interface{}); ok {
		b.WriteString(fmtKV("基准版本", fmt.Sprintf("v%v（%v）", from["version_number"], from["status"])))
	}
	b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
}

// addParameters 参数模型列表（api_parameter.get；需模型版本 ID，缺失时明确提示补充）。
func (a *APISecurityAgent) addParameters(ctx context.Context, in *aiorchestrator.AnalyzeInput, b *strings.Builder, facts map[string]interface{}) {
	if len(in.EventIDs) == 0 {
		b.WriteString("\n**参数模型**：查询参数模型需要模型版本 ID；请补充模型版本 ID（UUID，可在 API 模型页面复制）后再查询。\n")
		return
	}
	versionID := in.EventIDs[0]
	m, ref, ok := a.callAPITool(ctx, in, facts, b, "api_parameter.get", fmt.Sprintf("模型版本 %s 参数", versionID),
		map[string]interface{}{"model_version_id": versionID})
	if !ok {
		return
	}
	b.WriteString(fmt.Sprintf("\n**参数模型**（模型版本 %s）\n", versionID))
	b.WriteString(fmtKV("参数数量", m["count"]))
	for _, it := range mapItems(m, 10) {
		if p, ok := it.(map[string]interface{}); ok {
			fmt.Fprintf(b, "- %v（%v/%v，类型 %v，敏感级别 %v）\n",
				p["name"], p["direction"], p["location"], p["data_type"], p["sensitivity_level"])
		}
	}
	if truncated, _ := m["truncated"].(bool); truncated {
		b.WriteString("- 列表已截断（上限 200 条），完整清单请走管理面接口。\n")
	}
	b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
}

// hasAny 消息（已小写化）是否含任一关键词。
func hasAny(msg string, keywords ...string) bool {
	for _, kw := range keywords {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}

// asStringMap Tool 结果归一化为 map（struct 结果经 JSON 往返；失败返回 nil）。
func asStringMap(res interface{}) map[string]interface{} {
	if m, ok := res.(map[string]interface{}); ok {
		return m
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}

// mapItems 取列表型结果中的 items 并截断到 limit 条。
func mapItems(m map[string]interface{}, limit int) []interface{} {
	items, _ := m["items"].([]interface{})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

// renderStringIntMap 渲染 map[string]int 风格的分布（按键排序保证输出确定）。
func renderStringIntMap(v interface{}) string {
	m, _ := v.(map[string]interface{})
	if len(m) == 0 {
		return "无数据"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %v", k, m[k]))
	}
	return strings.Join(parts, "、")
}

// renderPercent 0-1 比例渲染为百分比文本（非数值原样输出）。
func renderPercent(v interface{}) string {
	switch n := v.(type) {
	case float64:
		return fmt.Sprintf("%.1f%%", n*100)
	default:
		return fmt.Sprint(v)
	}
}
