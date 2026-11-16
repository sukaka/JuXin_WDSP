// recommended.go 参数 observed/recommended 约束自动生成（三微模型框架 §四.5，第二批）：
// 纯函数，输入参数统计画像（ParameterProfile），输出钉死词汇约束，便于单测。
//
// 保守规则（样本量分级，观测不足一律不生成、不虚构）：
//   - 样本量 <100：不生成 recommended（观测不足以支撑建议）；
//   - 100–999：上限取观测区间×安全系数（P95×2，无 P95 用观测最大值×2），下限取观测最小值；
//   - ≥1000：允许上限收紧到 P95（无 P95 保持观测最大值，不放大）；
//   - enum：有明文候选值时仅 distinct_count ≤20 且样本量 ≥100 才生成；无候选值时
//     基数可封闭即生成「疑似枚举」推荐（enum_suspected+distinct_count，人工确认具体值）。
//
// observed 只承载观测事实（长度/值域区间与达到阈值的固定格式候选），无观测为空。
package apimodels

import "sort"

// 样本量分级阈值与保守系数。
const (
	// RecommendMinSamples 生成 recommended 的最小样本量（低于此值不生成）。
	RecommendMinSamples = 100
	// RecommendTightSamples 允许上限收紧到 P95 的样本量。
	RecommendTightSamples = 1000
	// RecommendSafetyFactor 100–999 样本量档的上限安全系数。
	RecommendSafetyFactor = 2
	// EnumMaxDistinct enum 护栏：去重值基数超过该值视为不可封闭，不生成枚举约束。
	EnumMaxDistinct = 20
	// ExampleHashesCap 统计画像 example_hashes 留存上限（最近 accepted 样本哈希）。
	ExampleHashesCap = 20
)

// ParameterProfile 参数统计画像输入（api_parameter_statistics 行的内存形态与枚举候选）。
// 指针字段对应可空统计；生成逻辑对缺失观测一律保守不输出对应约束键。
type ParameterProfile struct {
	SampleCount          int      // accepted 学习样本数
	MinLength            *int     // 观测最小长度（字符数）
	MaxLength            *int     // 观测最大长度（字符数）
	P95Length            *int     // 长度 P95
	MinValue             *float64 // 观测数值下界
	MaxValue             *float64 // 观测数值上界
	P95Value             *float64 // 数值 P95
	DistinctCount        *int     // 去重值基数
	EnumCandidates       []string // 枚举候选值（预留：当前无数据源）
	FormatCandidate      string   // 达到样本量与占比阈值的固定格式候选
	FormatCandidateRatio *float64 // 固定格式候选占合格字符串样本的比例
}

// ObservedConstraints 由画像生成观测约束（学习侧事实，词汇：min_length/max_length/
// minimum/maximum/format_candidate/format_candidate_ratio）。只写有真实观测的键；无观测返回空 map。
func ObservedConstraints(p ParameterProfile) map[string]any {
	out := map[string]any{}
	if p.MinLength != nil {
		out["min_length"] = *p.MinLength
	}
	if p.MaxLength != nil {
		out["max_length"] = *p.MaxLength
	}
	if p.MinValue != nil {
		out["minimum"] = *p.MinValue
	}
	if p.MaxValue != nil {
		out["maximum"] = *p.MaxValue
	}
	if IsFormatCandidate(p.FormatCandidate) && p.FormatCandidateRatio != nil {
		out["format_candidate"] = p.FormatCandidate
		out["format_candidate_ratio"] = *p.FormatCandidateRatio
	}
	return out
}

// RecommendedConstraints 由画像生成推荐约束（系统建议，供人工采纳为 confirmed）。
// 样本量 <RecommendMinSamples 或无任何观测时返回空 map（不为空指针，便于直接序列化）。
func RecommendedConstraints(p ParameterProfile) map[string]any {
	out := map[string]any{}
	if p.SampleCount < RecommendMinSamples {
		return out
	}
	// 上限按样本量分级；下限取观测最小值（不随样本量放大）。
	if upper, ok := upperBoundLength(p.SampleCount, p.MaxLength, p.P95Length); ok {
		out["max_length"] = upper
	}
	if p.MinLength != nil {
		out["min_length"] = *p.MinLength
	}
	if upper, ok := upperBoundValue(p.SampleCount, p.MaxValue, p.P95Value); ok {
		out["maximum"] = upper
	}
	if p.MinValue != nil {
		out["minimum"] = *p.MinValue
	}
	// enum 分支（P0-02 加深激活）：
	// 1. 有明文候选值（未来数据源）时照旧生成 enum 钉死值；
	// 2. 无候选值但基数可封闭（0<distinct_count≤EnumMaxDistinct）时生成「疑似枚举」推荐
	//    （enum_suspected=true + distinct_count），由人工确认具体值。
	//    不落明文枚举值是数据最小化纪律：观测链路只有不可逆 value_hashes（16 hex 截断），
	//    逆推/穷举明文既不可行也不合规；疑似标记只承载「值得人工钉死」的信号，
	//    网关约束执行侧忽略未知键（detectors/schema.go 读取侧宽容），确认前无阻断效果。
	if p.DistinctCount != nil && *p.DistinctCount > 0 && *p.DistinctCount <= EnumMaxDistinct &&
		len(p.EnumCandidates) > 0 && len(p.EnumCandidates) <= EnumMaxDistinct {
		if values := sortedUnique(p.EnumCandidates); len(values) > 0 {
			out["enum"] = values
		}
	} else if p.DistinctCount != nil && *p.DistinctCount > 0 && *p.DistinctCount <= EnumMaxDistinct {
		out["enum_suspected"] = true
		out["distinct_count"] = *p.DistinctCount
	}
	return out
}

// upperBoundLength 长度上限分级：≥RecommendTightSamples 收紧到 P95（无 P95 保持观测
// 最大值，不放大）；100–999 取 P95×2（无 P95 用观测最大值×2）。无观测返回 ok=false。
// 仅由 RecommendedConstraints 在样本量 ≥RecommendMinSamples 时调用。
func upperBoundLength(samples int, maxLen, p95 *int) (int, bool) {
	if samples >= RecommendTightSamples {
		if p95 != nil {
			return *p95, true
		}
		if maxLen != nil {
			return *maxLen, true
		}
		return 0, false
	}
	if p95 != nil {
		return *p95 * RecommendSafetyFactor, true
	}
	if maxLen != nil {
		return *maxLen * RecommendSafetyFactor, true
	}
	return 0, false
}

// upperBoundValue 数值上限分级（规则同 upperBoundLength，float64 形态）。
func upperBoundValue(samples int, maxVal, p95 *float64) (float64, bool) {
	if samples >= RecommendTightSamples {
		if p95 != nil {
			return *p95, true
		}
		if maxVal != nil {
			return *maxVal, true
		}
		return 0, false
	}
	if p95 != nil {
		return *p95 * RecommendSafetyFactor, true
	}
	if maxVal != nil {
		return *maxVal * RecommendSafetyFactor, true
	}
	return 0, false
}

// sortedUnique 去空串、去重并按字典序排序（enum 候选归一化，输出确定性）。
func sortedUnique(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
