package detectors

import (
	"strconv"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 行为基线：identity 指纹（或客户端 IP）+ endpoint_key 维度的进程内 1 分钟窗口计数。
// 纯内存实现（单节点限制，见 window.go 注释）；无外部存储依赖。
const (
	behaviorMaxKeys       = 10000 // LRU 容量上限
	behaviorMinHistory    = 5     // 判定所需最少历史窗口样本数
	behaviorSpikeMultiple = 3     // 突增倍数（相对历史均值）
	behaviorMinSpikeCount = 20    // 突增绝对下限（阈值 = max(20, 3×均值)）
)

// defaultBehaviorTracker 包级默认行为基线计数器。
var defaultBehaviorTracker = newWindowTracker(behaviorMaxKeys, nil)

// CheckBehavior 行为基线检测：当前窗口计数 > max(20, 3×历史均值) 且历史样本 ≥5 窗口
// → RATE_SPIKE（只 AddMatch，不定案）。
func CheckBehavior(ctx *dsctx.RequestContext, identity, endpointKey string) {
	if ctx == nil || identity == "" || endpointKey == "" {
		return
	}
	count, history := defaultBehaviorTracker.add(identity + "|" + endpointKey)
	threshold, ok := behaviorSpikeThreshold(count, history)
	if !ok {
		return
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "behavior",
		RuleID:   "behavior.rate_spike",
		Category: "OBSERVE",
		Severity: "MEDIUM",
		Message:  "request rate spike vs baseline",
		Evidence: map[string]string{
			"window_count":    strconv.Itoa(count),
			"threshold":       strconv.Itoa(threshold),
			"history_windows": strconv.Itoa(len(history)),
		},
		ScoreDelta: 15,
	})
}

// behaviorSpikeThreshold 计算突增阈值；不满足样本量或未突增返回 ok=false。
func behaviorSpikeThreshold(count int, history []int) (threshold int, ok bool) {
	if len(history) < behaviorMinHistory {
		return 0, false
	}
	sum := 0
	for _, c := range history {
		sum += c
	}
	mean := sum / len(history)
	threshold = behaviorMinSpikeCount
	if behaviorSpikeMultiple*mean > threshold {
		threshold = behaviorSpikeMultiple * mean
	}
	if count <= threshold {
		return 0, false
	}
	return threshold, true
}
