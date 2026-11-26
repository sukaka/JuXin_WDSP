package semantic

import (
	"context"
	"errors"
	"strconv"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// EvalOutcome 单次语义防火墙评估的统一输出（包含脱敏后的 DetectorMatch 与处置语义）。
type EvalOutcome struct {
	Channel         string
	RuleID          string
	Result          ClassifyResult
	Match           *dsctx.DetectorMatch
	Observed        bool // 命中观察档或 OBSERVE 模式高分（不阻断）
	Blocked         bool // PROTECT 模式且 score >= block_threshold（403 攻击阻断）
	Unavailable     bool // sidecar 不可用/超时/并发满载/熔断打开
	FailClosedBlock bool // PROTECT + FAIL_CLOSED 下 sidecar 不可用（必须返回 503，绝不伪装 403）
	ActionTaken     string
	Reason          string
}

// Engine 封装策略与本地 Unix Socket 客户端，供 jiuzhang_guard 热路径并发调用。
type Engine struct {
	policy *Policy
	client *Client
}

// NewEngine 根据已校验策略构造语义防火墙引擎（mode=OFF 也可构造以便测试，guard 装配侧按 OFF 跳过）。
func NewEngine(pol *Policy, opts ...ClientOptions) (*Engine, error) {
	if err := ValidatePolicy(pol); err != nil {
		return nil, err
	}
	cli, err := NewClient(pol, opts...)
	if err != nil {
		return nil, err
	}
	return &Engine{
		policy: pol.Clone(),
		client: cli,
	}, nil
}

// Policy 返回生效策略的只读副本。
func (e *Engine) Policy() *Policy {
	if e == nil || e.policy == nil {
		return nil
	}
	return e.policy.Clone()
}

// Client 返回底层客户端（用于健康探测与测试观测）。
func (e *Engine) Client() *Client {
	if e == nil {
		return nil
	}
	return e.client
}

// Close 释放底层连接池资源（幂等）。
func (e *Engine) Close() {
	if e == nil || e.client == nil {
		return
	}
	e.client.Close()
}

// Evaluate 调用本地 sidecar 分类并按两级阈值（observe_threshold / block_threshold）
// 与故障策略（FAIL_OPEN / FAIL_CLOSED）生成脱敏 DetectorMatch。
// 任何情况下 Evidence 中绝不写入原始提示词、参数或请求/响应体文本。
func (e *Engine) Evaluate(ctx context.Context, requestID, channel, text string) EvalOutcome {
	if e == nil || e.policy == nil || e.policy.Mode == ModeOff {
		return EvalOutcome{Channel: channel}
	}
	if strings.TrimSpace(text) == "" {
		return EvalOutcome{Channel: channel}
	}
	res, err := e.client.Classify(ctx, ClassifyRequest{
		RequestID: requestID,
		Channel:   channel,
		Text:      text,
	})
	if err != nil {
		return EvaluateError(e.policy, channel, res.InputRunes, err)
	}
	return EvaluateResult(e.policy, channel, res)
}

// EvaluateResult 对已获取的 sidecar 分类结果执行纯函数两级评分决策。
// Evidence 仅包含 channel / label / score / model_id / latency_ms / input_runes，绝不含原文。
func EvaluateResult(pol *Policy, channel string, res ClassifyResult) EvalOutcome {
	out := EvalOutcome{
		Channel: channel,
		Result:  res,
	}
	if pol == nil || pol.Mode == ModeOff {
		return out
	}
	label := strings.ToLower(strings.TrimSpace(res.Label))
	if label == "" || label == LabelSafe || label == "benign" {
		return out
	}
	if !isFiniteFloat(res.Score) || res.Score < pol.ObserveThreshold {
		return out
	}

	ruleID := ruleIDForClassification(channel, label)
	out.RuleID = ruleID

	evidence := map[string]string{
		"channel":     sanitizeToken(channel, 32),
		"label":       sanitizeToken(label, 64),
		"score":       strconv.FormatFloat(res.Score, 'f', 4, 64),
		"model_id":    sanitizeToken(res.ModelID, 128),
		"latency_ms":  strconv.FormatInt(res.LatencyMS, 10),
		"input_runes": strconv.Itoa(res.InputRunes),
	}

	if res.Score >= pol.BlockThreshold {
		if pol.Mode == ModeProtect {
			out.Blocked = true
			out.ActionTaken = "BLOCKED"
			out.Reason = "score_exceeds_block_threshold"
			out.Match = &dsctx.DetectorMatch{
				Detector:   DetectorName,
				RuleID:     ruleID,
				Category:   "BLOCK",
				Severity:   "HIGH",
				Message:    "semantic firewall blocked high-confidence malicious content",
				Evidence:   evidence,
				ScoreDelta: 80,
				Confidence: res.Score,
			}
			return out
		}
		// OBSERVE 模式：高分命中也只记录不实断，ScoreDelta < 50 避免 decision 引擎误升格为 BLOCK。
		out.Observed = true
		out.ActionTaken = "OBSERVED"
		out.Reason = "observe_mode_above_block_threshold"
		out.Match = &dsctx.DetectorMatch{
			Detector:   DetectorName,
			RuleID:     ruleID,
			Category:   "OBSERVE",
			Severity:   "HIGH",
			Message:    "semantic firewall observed high-confidence malicious content",
			Evidence:   evidence,
			ScoreDelta: 30,
			Confidence: res.Score,
		}
		return out
	}

	// 两级评分中间档：observe_threshold <= score < block_threshold → 无论 OBSERVE/PROTECT 均仅观察。
	out.Observed = true
	out.ActionTaken = "OBSERVED"
	out.Reason = "score_in_observe_band"
	out.Match = &dsctx.DetectorMatch{
		Detector:   DetectorName,
		RuleID:     ruleID,
		Category:   "OBSERVE",
		Severity:   "MEDIUM",
		Message:    "semantic firewall observed suspicious content",
		Evidence:   evidence,
		ScoreDelta: 15,
		Confidence: res.Score,
	}
	return out
}

// EvaluateError 将 sidecar 不可用/超时/满载/熔断错误映射为语义不可用结论与脱敏 DetectorMatch。
// PROTECT + FAIL_CLOSED 返回 FailClosedBlock=true（挂点侧必须返回 HTTP 503 semantic_guard_unavailable，
// 绝不伪装成 403 攻击阻断）；OBSERVE 或 FAIL_OPEN 恒放行并如实记录 semantic.sidecar_unavailable。
func EvaluateError(pol *Policy, channel string, inputRunes int, err error) EvalOutcome {
	reason := unavailableReason(err)
	failPolicy := FailOpen
	if pol != nil && pol.FailPolicy != "" {
		failPolicy = pol.FailPolicy
	}
	failClosedBlock := pol != nil && pol.Mode == ModeProtect && pol.FailPolicy == FailClosed
	actionTaken := "FAIL_OPEN"
	severity := "MEDIUM"
	msg := "semantic firewall sidecar unavailable (fail-open)"
	if failClosedBlock {
		actionTaken = "UNAVAILABLE_503"
		severity = "HIGH"
		msg = "semantic firewall sidecar unavailable (fail-closed 503)"
	}

	// 注意：Category 恒为 OBSERVE 且 ScoreDelta=0，防止 decision.Decide 将基础设施不可用
	// 误判为 403 攻击阻断；FAIL_CLOSED 503 由挂点侧根据 FailClosedBlock 显式回包。
	evidence := map[string]string{
		"channel":     sanitizeToken(channel, 32),
		"label":       "unavailable",
		"score":       "0.0000",
		"model_id":    "",
		"latency_ms":  "0",
		"input_runes": strconv.Itoa(inputRunes),
		"reason":      reason,
		"fail_policy": failPolicy,
	}
	return EvalOutcome{
		Channel:         channel,
		RuleID:          RuleSidecarUnavailable,
		Result:          ClassifyResult{InputRunes: inputRunes},
		Unavailable:     true,
		FailClosedBlock: failClosedBlock,
		ActionTaken:     actionTaken,
		Reason:          reason,
		Match: &dsctx.DetectorMatch{
			Detector:   DetectorName,
			RuleID:     RuleSidecarUnavailable,
			Category:   "OBSERVE",
			Severity:   severity,
			Message:    msg,
			Evidence:   evidence,
			ScoreDelta: 0,
			Confidence: 1.0,
		},
	}
}

func ruleIDForClassification(channel, label string) string {
	switch label {
	case LabelPromptInjection:
		return RulePromptInjection
	case LabelJailbreak:
		return RuleJailbreak
	case LabelIndirectInjection:
		return RuleIndirectInjection
	case LabelWebPayload:
		return RuleWebPayload
	default:
		switch channel {
		case ChannelMCPContent:
			return RuleIndirectInjection
		case ChannelWebGrayzone:
			return RuleWebPayload
		default:
			return RulePromptInjection
		}
	}
}

func unavailableReason(err error) string {
	switch {
	case errors.Is(err, ErrCircuitOpen):
		return "circuit_open"
	case errors.Is(err, ErrConcurrencySaturated):
		return "concurrency_saturated"
	case errors.Is(err, ErrTimeout):
		return "timeout"
	case errors.Is(err, ErrResponseTooLarge):
		return "response_too_large"
	case errors.Is(err, ErrInvalidResponse):
		return "invalid_response"
	default:
		return "sidecar_unavailable"
	}
}
