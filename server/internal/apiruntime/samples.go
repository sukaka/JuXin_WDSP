// samples.go 学习样本采集挂点（学习自动化闭环 P0-1）：
// Collector 每条网关事件（成功解析的记录）经 recordSample 判定过滤规则，
// 交 SampleRecorder 落 api_learning_samples；未注入 recorder（nil）时零开销跳过，
// 纯 WAF 形态无行为变化。
package apiruntime

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jiuzhang-waf/server/internal/apiassets"
)

// SampleRecorder 学习样本落库接口（*apiassets.Store 实现，可为 nil）。
// 返回 recorded=false 表示该端点无 RUNNING 学习任务（正常跳过，非错误）。
type SampleRecorder interface {
	RecordLearningSample(ctx context.Context, in apiassets.LearningSampleInput) (bool, error)
}

// 样本排除原因（exclude_reason；任务书 §25 在数据可得范围内的子集，见 docs/API_LEARNING_SECURITY.md §三）。
const (
	// ExcludeReasonBlockedByDecision 被统一决策阻断/限速（BLOCK/RATE_LIMIT/TEMP_BLOCK）。
	ExcludeReasonBlockedByDecision = "blocked_by_decision"
	// ExcludeReasonWAFHit 检测明细含 WAF/Coraza 命中（detector=waf）。
	ExcludeReasonWAFHit = "waf_hit"
	// ExcludeReasonSchemaDeviation 检测明细含 schema 偏离命中（detector=api_schema）。
	ExcludeReasonSchemaDeviation = "schema_deviation"
	// ExcludeReasonScannerTraffic 扫描器流量（任务书 §25"扫描器流量"排除项；
	// docs/API_ACTIVE_SCANNING.md §8.2）：details 含扫描标记明细（detector=scanner）。
	// 识别消费链已闭环：网关统一引擎请求相位校验 X-JiuZhang-Scan 签名头并产出该明细
	// （gateway/dynamic_security/detectors/scanner.go CheckScannerSignal，挂点
	// pipeline/pipeline.go；签名密钥经发布通道 api_scan_verification.key_hex 下发，
	// 见 guardconfig/scan_verify.go），本规则消费该明细排除学习样本。
	ExcludeReasonScannerTraffic = "scanner_traffic"
)

// sampleVerdict 样本过滤判定（纯函数）：返回 accepted 与排除原因。
// 规则顺序即优先级，命中即排除：
//  0. details 含扫描标记明细（detector=scanner）：主动扫描流量一律不进学习样本
//     （最先判定：来源身份优先于一切结果维度，扫描无论放行/阻断都不是真实流量样本）；
//  1. final_action 为 BLOCK/RATE_LIMIT/TEMP_BLOCK（被统一决策阻断/限速，含 §25 的 CC 超限形态；
//     先于状态码规则：此时的 403/429 是本系统决策产生而非上游响应）；
//  2. 响应状态码（response_status ∈ {401,403,429} 或 ≥500）：网关已改为响应后输出事件，
//     状态码为真实回包状态（含放行请求的上游响应码）；0 = 未采集到（旧版网关或异常场景），
//     跳过该规则；
//  3. details 含 WAF/Coraza 命中（detector=waf）；
//  4. details 含 schema 偏离命中（detector=api_schema）；
//     其余 accepted。来源占比上限（source_ratio_cap）在落库侧按任务计数判定。
func sampleVerdict(rec *Record) (accepted bool, excludeReason string) {
	for i := range rec.Details {
		if rec.Details[i].Detector == "scanner" {
			return false, ExcludeReasonScannerTraffic
		}
	}
	switch rec.FinalAction {
	case "BLOCK", "RATE_LIMIT", "TEMP_BLOCK":
		return false, ExcludeReasonBlockedByDecision
	}
	if rec.ResponseStatus >= 500 {
		return false, fmt.Sprintf("response_status_%d", rec.ResponseStatus)
	}
	switch rec.ResponseStatus {
	case 401, 403, 429:
		return false, fmt.Sprintf("response_status_%d", rec.ResponseStatus)
	}
	for i := range rec.Details {
		if rec.Details[i].Detector == "waf" {
			return false, ExcludeReasonWAFHit
		}
	}
	for i := range rec.Details {
		if rec.Details[i].Detector == "api_schema" {
			return false, ExcludeReasonSchemaDeviation
		}
	}
	return true, ""
}

// recordSample 学习样本落样（错误仅记录日志，不影响采集主流程，与端点发现同一纪律）。
// 空 request_id 跳过：无法按 (endpoint, request_id) 幂等去重的样本不落库。
func (c *Collector) recordSample(ctx context.Context, rec *Record) {
	if c.samples == nil || rec.EndpointKey == "" || rec.RequestID == "" {
		return
	}
	accepted, reason := sampleVerdict(rec)
	if _, err := c.samples.RecordLearningSample(ctx, apiassets.LearningSampleInput{
		EndpointKey:         rec.EndpointKey,
		RequestID:           rec.RequestID,
		SourceFingerprint:   rec.SourceFingerprint,
		IdentityFingerprint: rec.IdentityFingerprint,
		ResponseStatus:      rec.ResponseStatus,
		Accepted:            accepted,
		ExcludeReason:       reason,
	}); err != nil {
		slog.Error("record learning sample failed",
			"collector", c.collectorID, "endpoint_key", rec.EndpointKey,
			"request_id", rec.RequestID, "error", err)
	}
}
