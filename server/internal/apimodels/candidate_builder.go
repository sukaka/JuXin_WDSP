// candidate_builder.go 学习达标自动候选构建（P0-01 闭环加深）：
// 从 api_parameter_value_obs + 既有 FORMAL schema 构建非空候选 schema_json，
// 替代旧行为「learning_threshold 空 Schema 候选 + 纯手工完善」。
//
// 数据源取舍：api_parameter_statistics 是 api_parameter_value_obs 的周期回填下游
// （见 statistics.go 1b），且首学端点尚无 FORMAL 版本/参数行（统计行依附参数行），
// 故候选构建以端点级观测表为权威源；观测样本数（sample_count）即字段出现次数，
// 与任务有效样本数共同构成 presence 判定原料。
//
// 构建规则（仅 BODY 字段进 schema_json；QUERY/PATH 无 schema 载体，由 Confirm 时
// 按观测物化参数行，见 parameters.go）：
//   - base_type 由观测推断：value_hashes ⊆ {sha256("true"),sha256("false")} 且
//     distinct≤2 → bool；数值上下界存在 → number；否则 string（观测不落明文值，
//     布尔只能经已知明文哈希比对识别，见 inferObservedBaseType）；
//     字符串语义护栏：口令/令牌等参数名命中词表时强制 string 并弃置数值上下界
//     （见 semantic.go——口令可能是任意复杂字符串，纯数字样本不应产生数值约束）；
//   - required 按出现率 ≥95% 判定（分母=任务有效样本数，观测数超过分母时截断为 1）；
//   - min/max_length（与数值上下界）取 observed 值，随参数行 observed_constraints 落库；
//   - 既有 FORMAL 已确认字段的类型不自动改写（人工基线优先），仅补充新观测字段；
//   - 无观测数据时回退为空 Schema（保持旧行为，人工完善）。
//
// confirmed 约束绝不自动触碰：本文件只向「新候选版本」写参数行的
// observed_constraints/required，不写任何 confirmed_constraints。
package apimodels

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// CandidateRequiredPresence 必填判定出现率阈值（presence ≥ 95% → required=true）。
const CandidateRequiredPresence = 0.95

// candidateSummaryFieldCap change_summary 字段摘要行数上限（超出折叠为「等 N 个字段」）。
const candidateSummaryFieldCap = 20

// boolValueHashes 布尔明文 "true"/"false" 的网关观测哈希（sha256 截断 8 字节 hex，
// 与 gateway/dynamic_security/detectors/paramobs.go observeScalar 口径一致）：
// 观测侧不落明文值，布尔类型只能经已知明文哈希比对识别。
var boolValueHashes = map[string]struct{}{
	truncatedValueHash("true"):  {},
	truncatedValueHash("false"): {},
}

func truncatedValueHash(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:8])
}

// CandidateField 候选字段画像（schema 类型之外的统计摘要：参数行 observed 与
// change_summary 统计摘要共用）。
type CandidateField struct {
	Path          string   // BODY 结构化路径
	BaseType      string   // 观测推断类型 string/number/bool
	Samples       int64    // 观测出现次数
	Presence      float64  // 出现率（0,1]
	Required      bool     // Presence ≥ CandidateRequiredPresence
	MinLength     *int     // 观测最小长度
	MaxLength     *int     // 观测最大长度
	MinValue      *float64 // 观测数值下界
	MaxValue      *float64 // 观测数值上界
	DistinctCount *int     // 去重值基数
}

// CandidateBlueprint 自动候选构建结果。
type CandidateBlueprint struct {
	Schema   map[string]string // 候选 schema_json；无观测时为 nil（回退空 Schema 行为）
	Fields   []CandidateField  // 观测字段画像（按路径排序，输出确定性）
	Observed bool              // 是否有观测数据（false → 空 Schema 回退）
	Summary  string            // change_summary（注明自动生成 + 统计摘要）
}

// inferObservedBaseType 由脱敏观测推断标量类型（bool/number/string）。
// value_hashes 全部命中布尔明文哈希且基数 ≤2 → bool；数值上下界存在 → number；否则 string。
// QUERY/PATH 参数行物化（parameters.go）复用同一推断口径。
func inferObservedBaseType(minValue, maxValue *float64, distinctCount *int, valueHashes []string) string {
	if distinctCount != nil && *distinctCount > 0 && *distinctCount <= 2 &&
		len(valueHashes) > 0 && len(valueHashes) <= 2 {
		allBool := true
		for _, h := range valueHashes {
			if _, ok := boolValueHashes[h]; !ok {
				allBool = false
				break
			}
		}
		if allBool {
			return "bool"
		}
	}
	if minValue != nil || maxValue != nil {
		return "number"
	}
	return "string"
}

// BuildLearnedCandidate 构建学习达标自动候选（纯读取，不写库）：
// 端点级 BODY 观测 + 既有 FORMAL schema → 非空 schema_json 与字段画像。
// validSamples 为任务有效样本数（presence 分母；观测数超过分母时按观测数截断，presence≤1）。
func (s *Store) BuildLearnedCandidate(ctx context.Context, endpointKey string, validSamples int) (*CandidateBlueprint, error) {
	rows, err := s.db.Query(ctx, `
SELECT structured_path, parameter_name, sample_count,
       min_length, max_length, min_value, max_value, distinct_count, value_hashes
FROM api_parameter_value_obs
WHERE endpoint_key=$1 AND location='BODY'
ORDER BY structured_path, parameter_name`, endpointKey)
	if err != nil {
		return nil, fmt.Errorf("load body observations: %w", err)
	}
	defer rows.Close()
	fields := []CandidateField{}
	for rows.Next() {
		var f CandidateField
		var name string
		var hashesRaw []byte
		if err := rows.Scan(&f.Path, &name, &f.Samples,
			&f.MinLength, &f.MaxLength, &f.MinValue, &f.MaxValue, &f.DistinctCount, &hashesRaw); err != nil {
			return nil, err
		}
		if f.Path == "" {
			f.Path = name // 无结构化路径时以参数名为身份
		}
		var hashes []string
		if len(hashesRaw) > 0 {
			_ = json.Unmarshal(hashesRaw, &hashes)
		}
		f.BaseType = inferObservedBaseType(f.MinValue, f.MaxValue, f.DistinctCount, hashes)
		guardCandidateField(name, f.Path, &f)
		denom := int64(validSamples)
		if f.Samples > denom {
			denom = f.Samples
		}
		if denom > 0 {
			f.Presence = float64(f.Samples) / float64(denom)
		}
		f.Required = f.Presence >= CandidateRequiredPresence
		fields = append(fields, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 无观测数据：回退为空 Schema 行为（旧 learning_threshold 形态，人工完善）。
	if len(fields) == 0 {
		return &CandidateBlueprint{
			Observed: false,
			Summary: fmt.Sprintf("学习达标（有效样本 %d）自动生成并提交评审：无参数观测数据，Schema 为空待人工完善",
				validSamples),
		}, nil
	}

	// 合并既有 FORMAL schema：已确认字段类型不自动改写（人工基线优先），仅补充新观测字段。
	formal, err := s.FormalSchema(ctx, endpointKey)
	if err != nil {
		return nil, fmt.Errorf("load formal schema: %w", err)
	}
	schema := map[string]string{}
	for k, v := range formal {
		schema[k] = v
	}
	added := 0
	for _, f := range fields {
		if _, ok := schema[f.Path]; ok {
			continue
		}
		schema[f.Path] = f.BaseType
		added++
	}
	bp := &CandidateBlueprint{
		Schema:   schema,
		Fields:   fields,
		Observed: true,
	}
	bp.Summary = buildCandidateSummary(validSamples, fields, added, len(formal))
	return bp, nil
}

// buildCandidateSummary change_summary：注明自动生成 + 统计摘要（字段数/新增/沿用 +
// 逐字段类型/出现率/必填/长度区间，超 cap 折叠）。
func buildCandidateSummary(validSamples int, fields []CandidateField, added, formalKept int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "学习达标（有效样本 %d）自动生成并提交评审：观测字段 %d 个（新增 %d / 沿用正式模型 %d）",
		validSamples, len(fields), added, formalKept)
	for i, f := range fields {
		if i >= candidateSummaryFieldCap {
			fmt.Fprintf(&b, "；等 %d 个字段", len(fields))
			break
		}
		fmt.Fprintf(&b, "；%s: %s，出现率 %.0f%%", f.Path, f.BaseType, f.Presence*100)
		if f.Required {
			b.WriteString("（必填）")
		}
		if f.MinLength != nil && f.MaxLength != nil {
			fmt.Fprintf(&b, "，长度 %d~%d", *f.MinLength, *f.MaxLength)
		}
	}
	return b.String()
}

// CreateLearnedCandidate 学习达标自动候选闭环（janitor 调用，包内既有逻辑组合，非 HTTP 自调）：
// 构建候选蓝图 → 创建候选（created_reason=learning_threshold）→ 观测字段物化为候选版本
// 参数行（observed_constraints + required；confirmed 不触碰）→ 自动提交 IN_REVIEW。
// 各步独立事务：候选已建后任一步失败向上返回（任务侧记 last_error，可人工补建/提交），
// 不做半截回滚——与旧 completeJob「完成不回滚」纪律一致。
func (s *Store) CreateLearnedCandidate(ctx context.Context, endpointID uuid.UUID, endpointKey string, validSamples int) (*Version, error) {
	bp, err := s.BuildLearnedCandidate(ctx, endpointKey, validSamples)
	if err != nil {
		return nil, err
	}
	v, err := s.CreateCandidateWithReason(ctx, endpointID, endpointKey, bp.Summary,
		CreatedReasonLearningThreshold, bp.Schema, uuid.Nil)
	if err != nil {
		return nil, err
	}
	if bp.Observed {
		if err := s.materializeLearnedParameters(ctx, v.ID, bp.Fields); err != nil {
			return nil, fmt.Errorf("materialize learned parameters: %w", err)
		}
	}
	out, err := s.SubmitReview(ctx, v.ID, uuid.Nil, "学习达标自动提交评审")
	if err != nil {
		return nil, fmt.Errorf("auto submit review: %w", err)
	}
	return out, nil
}

// materializeLearnedParameters 观测字段物化为候选版本参数行（REQUEST/BODY，
// observed_constraints 带 min/max_length 与数值上下界，required 按 presence≥95% 判定）。
// 幂等：身份键 (model_version_id, direction, location, structured_path) 先查后插，
// 与 Confirm 物化（materializeRequestParameters）同口径——Confirm 时既有行保留，
// 此处写入的 observed/required 得以延续到 FORMAL。
func (s *Store) materializeLearnedParameters(ctx context.Context, versionID uuid.UUID, fields []CandidateField) error {
	ordered := make([]CandidateField, len(fields))
	copy(ordered, fields)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	for _, f := range ordered {
		name := deriveParameterName(f.Path)
		if name == "" {
			continue // 空字段名无身份可落，跳过
		}
		observed := map[string]any{}
		if f.MinLength != nil {
			observed["min_length"] = *f.MinLength
		}
		if f.MaxLength != nil {
			observed["max_length"] = *f.MaxLength
		}
		if f.MinValue != nil {
			observed["minimum"] = *f.MinValue
		}
		if f.MaxValue != nil {
			observed["maximum"] = *f.MaxValue
		}
		raw, _ := json.Marshal(observed)
		if _, err := s.db.Exec(ctx, `
INSERT INTO api_parameter_models
  (model_version_id, direction, location, structured_path, parameter_name, base_type, required, observed_constraints, confidence)
SELECT $1,'REQUEST','BODY',$2::varchar,$3::varchar,$4::varchar,$5,$6::jsonb,1.0
WHERE NOT EXISTS (
    SELECT 1 FROM api_parameter_models
    WHERE model_version_id=$1 AND direction='REQUEST' AND location='BODY' AND structured_path=$2::varchar
)`, versionID, f.Path, name, f.BaseType, f.Required, raw); err != nil {
			return err
		}
	}
	return nil
}
