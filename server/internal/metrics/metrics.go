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

// API 专项指标（阶段8 / 补全任务书 §158 口径；仅实现有真实数据源者，数据源见各注释）。
// 均为 DB 周期聚合的 gauge（当前值快照），由 APICollector 采集，见 api_collector.go；
// 速率/耗时类为 float gauge（APISnapshot.Floats）。
// 网关进程侧指标（检测/解析耗时、内存占用）在 gateway/dynamic_security/metrics
// 进程内指标包（ParseRequest 已埋点，内存经 runtime.ReadMemStats 实时采样）；
// 仍无数据源而未实现的指标（不造假）：API 检测耗时与响应解析耗时（计时挂点在
// pipeline 请求/响应相位，本波 pipeline 归其他任务）、事件积压（apiruntime 采集器
// 断点-文件大小差值，需装配层把采集器实例接进 APICollector）。
const (
	APIAssetsTotal       = "api_assets_total"       // 数据源：api_endpoints 全表计数（is_api=TRUE）
	APIAssetsNew         = "api_assets_new"         // 数据源：api_endpoints.first_seen_at 近 24h 新发现
	APILearningJobs      = "api_learning_jobs"      // 数据源：api_learning_jobs status='RUNNING'
	APILearningSamples   = "api_learning_samples"   // 数据源：api_learning_samples 全表计数
	APILearningExcluded  = "api_learning_excluded"  // 数据源：api_learning_samples accepted=FALSE
	APICandidatesCreated = "api_candidates_created" // 数据源：api_model_versions status IN (CANDIDATE,IN_REVIEW)
	APIModelsConfirmed   = "api_models_confirmed"   // 数据源：api_model_versions status='FORMAL'
	RuntimeCompileTotal  = "runtime_compile_total"  // 数据源：api_runtime_policies 全表计数（每行一次编译产物）
	RuntimeCompileError  = "runtime_compile_error"  // 数据源：api_runtime_policies status='FAILED'
	SchemaFindings       = "schema_findings"        // 数据源：api_runtime_findings finding_type 前缀 SCHEMA_/API_SCHEMA
	AuthFindings         = "auth_findings"          // 数据源：api_runtime_findings finding_type 前缀 AUTH_/AUTHENTICATION
	AuthzFindings        = "authz_findings"         // 数据源：api_runtime_findings finding_type 前缀 BOLA/BFLA/AUTHZ_
	SensitiveFindings    = "sensitive_findings"     // 数据源：api_runtime_findings finding_type 前缀 SENSITIVE_
	BehaviorFindings     = "behavior_findings"      // 数据源：api_runtime_findings finding_type 前缀 BEHAVIOR
	MaskResponseTotal    = "mask_response_total"    // 数据源：api_runtime_events final_action='MASK_RESPONSE'
	APIShadowTotal       = "api_shadow_total"       // 数据源：api_runtime_findings finding_type='SHADOW' 且未关闭（NEW/CONFIRMED/IN_PROGRESS，口径同 reports findingOpenStatuses）
	APIZombieTotal       = "api_zombie_total"       // 数据源：api_endpoints asset_status='ZOMBIE'（is_api=TRUE，口径同 reports is_zombie）
	APIGraphEdgesTotal   = "api_graph_edges_total"  // 数据源：api_call_edges 全表计数
	AIToolCallsTotal     = "ai_tool_calls_total"    // 数据源：ai_tool_calls 全表计数

	// float gauge（速率/耗时类；整型 map 装不下的小数口径）
	APIDiscoveryPerSecond     = "api_discovery_per_second"     // 数据源：api_endpoints.first_seen_at 近 60s 新识别数 / 60
	APILearningLatencySeconds = "api_learning_latency_seconds" // 数据源：api_learning_jobs 近 24h COMPLETED 任务平均时长（stopped_at-started_at）
)

// APM 阶段1 端点级 RED 指标（ADR docs/APM_STAGE0_ADR.md D7/D9；数据源：access_logs 全量
// 访问日志分钟聚合，见 aggregations/endpoint_red.go；labels：app/endpoint/status_class/action）。
const (
	HTTPEndpointRequestsTotal = "http_endpoint_requests_total" // 端点级请求数
	HTTPEndpointDurationMs    = "http_endpoint_duration_ms"    // 端点级总耗时直方图（extra.buckets）
	HTTPEndpointTTFBMs        = "http_endpoint_ttfb_ms"        // 端点级 TTFB 直方图（extra.buckets）
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
// endpoint 为 APM 阶段1 端点级 RED 维度：值经网关归一化（METHOD /path/{id}）+
// 聚合侧 Top-N 护栏（__OTHER__/__UNCLASSIFIED__），不引入原始 path 基数。
var allowedLabelKeys = map[string]bool{
	"app": true, "attack_type": true, "severity": true, "action": true,
	"status_class": true, "scope": true, "component": true, "policy": true,
	"method": true, "content_type": true, "endpoint": true,
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
