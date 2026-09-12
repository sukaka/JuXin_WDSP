package detectors

import (
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 生命周期检测：已知端点表（endpoint_key → asset_status）由发布通道下发。
// 不在表中的 API 端点为 SHADOW 候选；DEPRECATED 状态仍被调用为异常使用。

// CheckLifecycle 生命周期检测：未知端点 → NEW_ENDPOINT；DEPRECATED 调用 → DEPRECATED_API_CALL。
// known 为 nil 表示无基线（未下发），跳过检测。
func CheckLifecycle(ctx *dsctx.RequestContext, endpointKey string, known map[string]string) {
	if ctx == nil || endpointKey == "" || known == nil {
		return
	}
	status, ok := known[endpointKey]
	if !ok {
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "lifecycle",
			RuleID:   "lifecycle.new_endpoint",
			Category: "OBSERVE",
			Severity: "LOW",
			Message:  "endpoint not in known baseline (shadow candidate)",
			Evidence: map[string]string{
				"endpoint_key": endpointKey,
				"signal":       "shadow_candidate",
			},
			ScoreDelta: 5,
		})
		return
	}
	if strings.EqualFold(status, "DEPRECATED") {
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "lifecycle",
			RuleID:   "lifecycle.deprecated_api_call",
			Category: "OBSERVE",
			Severity: "MEDIUM",
			Message:  "deprecated api still called",
			Evidence: map[string]string{
				"endpoint_key": endpointKey,
				"asset_status": "DEPRECATED",
			},
			ScoreDelta: 10,
		})
	}
}
