// respdeviation.go 响应偏离检测（W9-GW，背景B 响应结构基线的运行时消费；任务书 §64
// UNKNOWN_RESPONSE/UNKNOWN_STATUS 侧）：
//   - 管理面 api_response_schemas 表 sample_count≥20 的学习行经发布通道
//     api_response_baselines 下发（端点×状态码 → 一级字段路径/类型）；
//   - 端点有下发基线时按响应相位事实比对：基线外新字段 / 基线字段缺失 / 未见状态码
//     各产一条 OBSERVE 明细；无基线下发时零行为（基线缺失不判，与授权基线同一纪律）。
//
// 纪律：
//   - 只比对一级字段路径（与学习生产方 response.BuildObservation 同一口径：
//     根占位与含 "." 的深层路径不参与比对）；
//   - 证据只含字段路径与状态码，绝不落响应值；
//   - 偏离为「学习基线成员判定」，置信保守取 0.7（基线本身为学习产物，
//     见 context.defaultConfidenceByDetector 的取值纪律）。
package detectors

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// ResponseBaseline 发布通道下发的端点响应结构基线
// （server api_response_schemas 表达阈值学习行镜像；该表由迁移 000018 建立、000051 补齐运行时学习列）。
// json tag 为跨分片契约，不得改动。
type ResponseBaseline struct {
	EndpointKey string            `json:"endpoint_key"` // 作用端点（METHOD + 空格 + 路径模板）
	StatusCode  int               `json:"status_code"`  // 学习到的响应状态码
	Fields      map[string]string `json:"fields"`       // 一级字段路径 → 类型（只含路径与类型标签，不落值）
}

// maxResponseDeviationFindings 单响应每类偏离明细上限（防超大报文撑爆事件，
// 与 maxResponseSensitiveFindings/maxAuthzFieldMatches 同纪律）。
const maxResponseDeviationFindings = 20

// CheckResponseDeviation 响应偏离检测：baselines 为本端点响应结构基线（装配层按端点解析后传入）；
// fields 为响应相位 JSON 解析产物（字段路径→类型全集），isJSON 标识响应是否完整解析为 JSON。
//
// 判定语义：
//   - 无端点基线零行为（基线缺失不判——未稳定学习的端点不得放大为误报）；
//   - 响应状态码无任何基线行 → response.schema_new_status（OBSERVE/INFO），不再比对字段；
//   - 状态码有基线且响应完整解析为 JSON：响应一级字段超出基线 → response.schema_new_field
//     （OBSERVE/MEDIUM，每字段一条，封顶）；基线字段在响应中缺失 → response.schema_missing_field
//     （OBSERVE/LOW，每字段一条，封顶）；
//   - 非 JSON / 截断 / 流式响应无法观测字段：仅做状态码判定，字段比对跳过（不凭空判缺失）。
//
// 证据只含字段路径与状态码，不落值。本检测只产 OBSERVE 明细，不定案。
func CheckResponseDeviation(ctx *dsctx.RequestContext, status int, isJSON bool, fields map[string]string, baselines []ResponseBaseline) {
	if ctx == nil || len(baselines) == 0 {
		return
	}
	var matched *ResponseBaseline
	for i := range baselines {
		if baselines[i].StatusCode == status {
			matched = &baselines[i]
			break
		}
	}
	if matched == nil {
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "api_response",
			RuleID:     "response.schema_new_status",
			Category:   "OBSERVE",
			Severity:   "INFO",
			Message:    "response status not covered by learned response schema baseline",
			Evidence:   map[string]string{"status": strconv.Itoa(status)},
			Confidence: 0.7,
		})
		return
	}
	if !isJSON || len(matched.Fields) == 0 {
		return // 非 JSON 无法观测字段；空字段基线下发方本不产出（防御性跳过）
	}
	// 稳定遍历序（map 乱序会让事件明细序抖动，与既有检测器同一纪律）
	respPaths := make([]string, 0, len(fields))
	for p := range fields {
		if p == "" || strings.Contains(p, ".") {
			continue // 根占位与深层路径不参与比对（与学习口径一致：仅一级字段）
		}
		respPaths = append(respPaths, p)
	}
	sort.Strings(respPaths)
	n := 0
	for _, p := range respPaths {
		if n >= maxResponseDeviationFindings {
			break
		}
		if _, ok := matched.Fields[p]; ok {
			continue
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "api_response",
			RuleID:     "response.schema_new_field",
			Category:   "OBSERVE",
			Severity:   "MEDIUM",
			Message:    "response field not present in learned response schema baseline",
			Evidence:   map[string]string{"field": p, "status": strconv.Itoa(status)},
			Confidence: 0.7,
			ScoreDelta: 10,
		})
		n++
	}
	basePaths := make([]string, 0, len(matched.Fields))
	for p := range matched.Fields {
		basePaths = append(basePaths, p)
	}
	sort.Strings(basePaths)
	n = 0
	for _, p := range basePaths {
		if n >= maxResponseDeviationFindings {
			break
		}
		if _, ok := fields[p]; ok {
			continue
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "api_response",
			RuleID:     "response.schema_missing_field",
			Category:   "OBSERVE",
			Severity:   "LOW",
			Message:    "learned baseline field missing from response",
			Evidence:   map[string]string{"field": p, "status": strconv.Itoa(status)},
			Confidence: 0.7,
			ScoreDelta: 5,
		})
		n++
	}
}

// GroupResponseBaselines 按 endpoint_key 归组响应结构基线（装配层调用；
// 运行期按端点直接选取，避免逐请求全量扫描，纪律同 GroupRoleBaselines）。
func GroupResponseBaselines(in []ResponseBaseline) map[string][]ResponseBaseline {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]ResponseBaseline, len(in))
	for _, b := range in {
		out[b.EndpointKey] = append(out[b.EndpointKey], b)
	}
	return out
}

// ValidateResponseBaselines 装配期校验响应结构基线下发内容（配置错误显式返回，不静默吞错）：
// endpoint_key 非空、status_code 为合法 HTTP 状态码、fields 非空（空字段基线无比对语义）。
func ValidateResponseBaselines(in []ResponseBaseline) error {
	for i, b := range in {
		if b.EndpointKey == "" {
			return fmt.Errorf("api_response_baselines[%d]: endpoint_key must be non-empty", i)
		}
		if b.StatusCode < 100 || b.StatusCode > 599 {
			return fmt.Errorf("api_response_baselines[%d]: invalid status_code %d", i, b.StatusCode)
		}
		if len(b.Fields) == 0 {
			return fmt.Errorf("api_response_baselines[%d]: fields must be non-empty", i)
		}
	}
	return nil
}
