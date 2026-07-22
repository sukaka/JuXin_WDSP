// Package metrics 统一指标模型（阶段6）：指标名、标签约束、时间粒度。
// 原则：UTC 存储、指标名固定、标签维度受控、不含敏感数据、聚合可重算。
package metrics

// 指标名（固定枚举，禁止用户输入作为指标名）。
const (
	HTTPRequestsTotal       = "http_requests_total"
	HTTPRequestDurationMs   = "http_request_duration_ms"
	WAFEventsTotal          = "waf_events_total"
	WAFBlocksTotal          = "waf_blocks_total"
	WAFObserveTotal         = "waf_observes_total"
	CCExceededTotal         = "cc_threshold_exceeded_total"
	CCRejectedTotal         = "cc_request_rejected_total"
	CCTempBlockCreatedTotal = "cc_temp_block_created_total"
	IPDenyMatchesTotal      = "ip_deny_matches_total"
	IPAllowMatchesTotal     = "ip_allow_matches_total"
	EventsUnprocessed       = "security_events_unprocessed"
	EventCollectorLagSec    = "event_collector_lag_seconds"
	EventParseFailuresTotal = "event_parse_failures_total"
	GatewayUp               = "gateway_up"
	UpstreamHealthy         = "upstream_healthy"
	CertDaysRemaining       = "certificate_days_remaining"
	DatabaseSizeBytes       = "database_size_bytes"
	DiskFreeBytes           = "disk_free_bytes"
)

// DurationBucketsMs HTTP 响应时长直方图桶（毫秒）。
var DurationBucketsMs = []int{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}

// BucketIndex 返回时长所属桶下标（越界归最后一桶）。
func BucketIndex(durationMs float64) int {
	for i, le := range DurationBucketsMs {
		if durationMs <= float64(le) {
			return i
		}
	}
	return len(DurationBucketsMs)
}

// PercentileFromBuckets 从直方图桶计数估算分位数（毫秒，线性插值近似）。
func PercentileFromBuckets(counts []int, p float64) float64 {
	var total int
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		return 0
	}
	target := float64(total) * p
	var cum int
	prevLe := 0.0
	for i, c := range counts {
		cum += c
		if float64(cum) >= target {
			le := float64(DurationBucketsMs[i])
			if c == 0 {
				return le
			}
			frac := (target - float64(cum-c)) / float64(c)
			return prevLe + frac*(le-prevLe)
		}
		prevLe = float64(DurationBucketsMs[i])
	}
	return float64(DurationBucketsMs[len(DurationBucketsMs)-1])
}

// 允许的标签键（受控维度，防高基数攻击）。
var allowedLabelKeys = map[string]bool{
	"app": true, "attack_type": true, "severity": true, "action": true,
	"status_class": true, "scope": true, "component": true, "policy": true,
	"method": true, "content_type": true,
}

// ValidateLabels 校验标签键集合（未知键返回 false）。
func ValidateLabels(labels map[string]string) bool {
	for k, v := range labels {
		if !allowedLabelKeys[k] {
			return false
		}
		if len(v) > 128 {
			return false
		}
	}
	return true
}
