package detectors

import (
	"strconv"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// API 限速信号：写方法 API 请求按 identity+endpoint_key 进程内 1 分钟窗口计数，
// 超阈值 → API_WRITE_RATE（RATE_LIMIT 类；决策引擎映射 RATE_LIMIT，网关侧 429）。
// 纯内存实现（单节点限制，见 window.go 注释）；与阶段5 CC 限速互补，维度更细。
const (
	// DefaultAPIWriteRatePerMinute 写方法 API 默认每分钟上限（Config 未显式传入时）。
	DefaultAPIWriteRatePerMinute = 60
	apiWriteMaxKeys              = 10000
)

// defaultAPIWriteTracker 包级默认 API 写限速计数器。
var defaultAPIWriteTracker = newWindowTracker(apiWriteMaxKeys, nil)

// IsWriteMethod 写方法判定（POST/PUT/PATCH/DELETE）。
func IsWriteMethod(method string) bool {
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

// CheckAPIWriteRate 写方法 API 限速信号：窗口计数超 limit → API_WRITE_RATE（只 AddMatch，不定案）。
// limit ≤ 0 时使用 DefaultAPIWriteRatePerMinute。
func CheckAPIWriteRate(ctx *dsctx.RequestContext, identity, endpointKey string, limit int) {
	if ctx == nil || identity == "" || endpointKey == "" {
		return
	}
	if limit <= 0 {
		limit = DefaultAPIWriteRatePerMinute
	}
	count, _ := defaultAPIWriteTracker.add(identity + "|" + endpointKey)
	if count <= limit {
		return
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "api_ratelimit",
		RuleID:   "ratelimit.api_write_rate",
		Category: "RATE_LIMIT",
		Severity: "HIGH",
		Message:  "api write rate exceeded",
		Evidence: map[string]string{
			"window_count": strconv.Itoa(count),
			"limit":        strconv.Itoa(limit),
			"window":       "1m",
		},
		ScoreDelta: 30,
	})
}
