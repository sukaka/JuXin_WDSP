// verdict.go LLM 误报评分：经 aimodel.Gateway（standard 档）调用，
// system prompt 约束只输出 JSON；解析失败/LLM 不可用一律降级 UNKNOWN，不致命。
// 注入证据全部来自数据库事实（代表事件、规则命中、时间分布），禁止编造。
package ainoise

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jiuzhang-waf/server/internal/aimodel"
)

// LLMGateway 模型网关最小契约（*aimodel.Gateway 满足，便于单测替换）。
type LLMGateway interface {
	Chat(ctx context.Context, complexity aimodel.TaskComplexity, req aimodel.ChatRequest) (*aimodel.ChatResult, error)
}

// VerdictResult LLM 评分结果。
type VerdictResult struct {
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// VerdictEvaluator 簇误报评分器。
type VerdictEvaluator struct {
	gw LLMGateway
}

// NewVerdictEvaluator 创建评分器（gw 为 nil 时全部 UNKNOWN）。
func NewVerdictEvaluator(gw LLMGateway) *VerdictEvaluator {
	return &VerdictEvaluator{gw: gw}
}

// verdictSystemPrompt 约束模型只输出 JSON，且只能基于给定证据判断。
const verdictSystemPrompt = `你是企业WAF安全运营的事件降噪评估器。给定一个按确定性指纹聚合的重复安全事件簇的证据摘要，判断该簇是否为疑似误报。
规则：
1) 只输出一个 JSON 对象，格式 {"verdict":"TRUE_POSITIVE|LIKELY_FALSE_POSITIVE|UNKNOWN","confidence":0.0-1.0,"reason":"不超过100字的中文理由"}，不得输出任何其他文本；
2) 只能基于给定证据判断，禁止编造任何证据中不存在的规则、IP、URI、时间或数字；
3) 证据不足时 verdict 必须为 UNKNOWN；
4) 高频重复、单一低风险规则命中、明显为扫描器指纹或无实际危害载荷的簇倾向 LIKELY_FALSE_POSITIVE；明确攻击特征（注入/文件包含/RCE 等高危命中且动作 BLOCK）倾向 TRUE_POSITIVE。`

// Evaluate 对簇评分；任何失败（LLM 不可用/超时/输出非法）降级 UNKNOWN，不返回错误。
// 返回消耗的 token 数（输入+输出；失败时为 0）。
func (e *VerdictEvaluator) Evaluate(ctx context.Context, ev *Evidence) (VerdictResult, int) {
	if e == nil || e.gw == nil || ev == nil {
		return VerdictResult{Verdict: VerdictUnknown, Reason: "评估器不可用"}, 0
	}
	res, err := e.gw.Chat(ctx, aimodel.ComplexityStandard, aimodel.ChatRequest{
		Messages: []aimodel.ChatMessage{
			{Role: "system", Content: verdictSystemPrompt},
			{Role: "user", Content: buildVerdictPrompt(ev)},
		},
		MaxTokens:   256,
		Temperature: 0,
		JSONMode:    true,
	})
	if err != nil {
		slog.Warn("ai noise verdict llm failed, degrade to UNKNOWN", "cluster_id", ev.Cluster.ID, "error", err)
		return VerdictResult{Verdict: VerdictUnknown, Reason: "LLM 不可用"}, 0
	}
	out, err := ParseVerdict(res.Content)
	if err != nil {
		slog.Warn("ai noise verdict parse failed, degrade to UNKNOWN", "cluster_id", ev.Cluster.ID, "error", err)
		return VerdictResult{Verdict: VerdictUnknown, Reason: "LLM 输出无法解析"}, res.InputTokens + res.OutputTokens
	}
	return out, res.InputTokens + res.OutputTokens
}

// buildVerdictPrompt 组装证据摘要（仅数据库事实）。
func buildVerdictPrompt(ev *Evidence) string {
	c := ev.Cluster
	var b strings.Builder
	fmt.Fprintf(&b, "事件簇证据：\n来源: %s\n主机: %s\n归一化URI: %s\n", c.Source, c.Host, c.NormalizedURI)
	if c.RuleID != nil {
		fmt.Fprintf(&b, "主命中规则ID: %d\n", *c.RuleID)
	}
	if c.DetectorCode != "" {
		fmt.Fprintf(&b, "检测器: %s\n", c.DetectorCode)
	}
	fmt.Fprintf(&b, "客户端IP: %s\n事件数: %d\n首次出现: %s\n最近出现: %s\n频率(次/分钟): %.2f\n",
		c.ClientIP, c.EventCount, c.FirstSeen.Format("2006-01-02 15:04:05"), c.LastSeen.Format("2006-01-02 15:04:05"), ev.EventsPerMinute)
	if ev.AttackType != "" {
		fmt.Fprintf(&b, "攻击类型: %s\n", ev.AttackType)
	}
	if ev.Severity != "" {
		fmt.Fprintf(&b, "严重级别: %s\n", ev.Severity)
	}
	if ev.Action != "" {
		fmt.Fprintf(&b, "处置动作: %s\n", ev.Action)
	}
	if len(ev.RuleHits) > 0 {
		fmt.Fprintf(&b, "代表事件规则命中: %s\n", strings.Join(ev.RuleHits, "; "))
	}
	return b.String()
}

// ParseVerdict 解析 LLM 输出为评分结果（容忍 ```json 代码围栏与首尾杂文本）。
func ParseVerdict(content string) (VerdictResult, error) {
	s := strings.TrimSpace(content)
	if i := strings.Index(s, "```"); i >= 0 {
		s = strings.ReplaceAll(s, "```json", "")
		s = strings.ReplaceAll(s, "```", "")
	}
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start < 0 || end <= start {
		return VerdictResult{}, fmt.Errorf("no json object in llm output")
	}
	var out VerdictResult
	if err := json.Unmarshal([]byte(s[start:end+1]), &out); err != nil {
		return VerdictResult{}, fmt.Errorf("unmarshal verdict: %w", err)
	}
	switch out.Verdict {
	case VerdictTruePositive, VerdictLikelyFalsePositive, VerdictUnknown:
	default:
		return VerdictResult{}, fmt.Errorf("invalid verdict %q", out.Verdict)
	}
	if out.Confidence < 0 {
		out.Confidence = 0
	}
	if out.Confidence > 1 {
		out.Confidence = 1
	}
	if len([]rune(out.Reason)) > 200 {
		out.Reason = string([]rune(out.Reason)[:200])
	}
	return out, nil
}
