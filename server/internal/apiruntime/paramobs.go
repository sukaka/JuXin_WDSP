// paramobs.go 网关参数值脱敏观测入库（三微模型参数微模型值观测通路）。
// 事件 JSONL 中的 param_observations → UPSERT api_parameter_value_obs（按 endpoint_key×位置×路径×名）。
// 阶段8 §16/§17 扩展（迁移 000145/000206）：null 计数、长度/数值蓄水池、字符直方图、
// 前后缀脱敏哈希计数、固定格式样本与候选计数，供 statistics.go 整窗重算覆盖。
package apiruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jiuzhang-waf/server/internal/apimodels"
)

// ParamObservation 采集端镜像（与网关 apievents.ParamObservation JSON 字段一致）。
// null/char_hist/prefix_hash/suffix_hash/format_sample/format_candidate 为扩展键：
// 旧版网关不上报时 json 缺省解析为零值，合并写入全程容忍（零值即无扩展观测）。
type ParamObservation struct {
	Location  string   `json:"location"`
	Name      string   `json:"name"`
	Path      string   `json:"path"`
	BaseType  string   `json:"base_type"`
	Length    int      `json:"length"`
	ValueHash string   `json:"value_hash"`
	NumValue  *float64 `json:"num_value"`
	// Null 显式 null 值标记（JSON null 字面量观测；计入 null_count 与样本数）。
	Null bool `json:"null"`
	// CharHist 字符直方图增量（稀疏桶：字节值十进制串 → 计数，仅非零桶）。
	CharHist map[string]int64 `json:"char_hist"`
	// PrefixHash/SuffixHash 前/后缀脱敏哈希（只落哈希，明文不出网关）。
	PrefixHash      string `json:"prefix_hash"`
	SuffixHash      string `json:"suffix_hash"`
	FormatSample    bool   `json:"format_sample,omitempty"`
	FormatCandidate string `json:"format_candidate,omitempty"`
}

// ParamObsRecorder 参数观测聚合写入接口。
type ParamObsRecorder interface {
	RecordParamObservations(ctx context.Context, endpointKey string, obs []ParamObservation) error
}

// ParamObsStore pgx 实现。
type ParamObsStore struct {
	db DBTX
}

// NewParamObsStore 创建观测写入方。
func NewParamObsStore(db *pgxpool.Pool) *ParamObsStore {
	return &ParamObsStore{db: db}
}

// WithDB 返回绑定到给定句柄的浅拷贝（W22 批次事务化，语义同 Store.WithDB）。
func (s *ParamObsStore) WithDB(db DBTX) *ParamObsStore {
	return &ParamObsStore{db: db}
}

const valueHashCap = 64 // 每键保留的 distinct hash 上限

// paramObsRow api_parameter_value_obs 单行合并状态（扩展列对应迁移 000145/000206）。
type paramObsRow struct {
	sampleCount       int64
	minLen, maxLen    *int
	minVal, maxVal    *float64
	hashes            []string
	nullCount         int64
	lengthReservoir   []float64
	valueReservoir    []float64
	charHistogram     []int64
	prefixCounts      map[string]int64
	suffixCounts      map[string]int64
	formatSampleCount int64
	formatCounts      map[string]int64
}

// merge 合并单条观测（纯函数，供 RecordParamObservations 与单测复用）：
// 蓄水池/直方图/前后缀计数复用 apimodels 可合并纯函数（确定性、逐桶/逐键相加），
// 与 statistics.go 从观测源整窗重算覆盖的幂等语义一致；观测列即重算数据源。
func (r *paramObsRow) merge(o ParamObservation) {
	r.sampleCount++
	if o.Null {
		r.nullCount++
	}
	if o.Length > 0 || o.ValueHash != "" {
		if r.minLen == nil || o.Length < *r.minLen {
			v := o.Length
			r.minLen = &v
		}
		if r.maxLen == nil || o.Length > *r.maxLen {
			v := o.Length
			r.maxLen = &v
		}
		r.lengthReservoir = apimodels.MergeReservoir(r.lengthReservoir, []float64{float64(o.Length)}, apimodels.ReservoirCap)
	}
	if o.NumValue != nil {
		nv := *o.NumValue
		if r.minVal == nil || nv < *r.minVal {
			r.minVal = &nv
		}
		if r.maxVal == nil || nv > *r.maxVal {
			r.maxVal = &nv
		}
		r.valueReservoir = apimodels.MergeReservoir(r.valueReservoir, []float64{nv}, apimodels.ReservoirCap)
	}
	if h := denseHistogram(o.CharHist); h != nil {
		r.charHistogram = apimodels.MergeHistogram(r.charHistogram, h)
	}
	if o.PrefixHash != "" {
		r.prefixCounts = apimodels.MergeCounts(r.prefixCounts, map[string]int64{o.PrefixHash: 1})
	}
	if o.SuffixHash != "" {
		r.suffixCounts = apimodels.MergeCounts(r.suffixCounts, map[string]int64{o.SuffixHash: 1})
	}
	if o.FormatSample && !o.Null && o.BaseType == "string" && o.Length > 0 && o.ValueHash != "" {
		r.formatSampleCount++
		if apimodels.IsFormatCandidate(o.FormatCandidate) {
			r.formatCounts = apimodels.MergeCounts(r.formatCounts, map[string]int64{o.FormatCandidate: 1})
		}
	}
	if o.ValueHash != "" {
		r.hashes = mergeHash(r.hashes, o.ValueHash, valueHashCap)
	}
}

// denseHistogram 网关稀疏直方图（字节值十进制串 → 计数）转 256 桶密数组；
// 键越界/非正计数的非法桶丢弃（入口容忍，不让脏数据污染熵重算）；全空返回 nil。
func denseHistogram(sparse map[string]int64) []int64 {
	if len(sparse) == 0 {
		return nil
	}
	var dense []int64
	for k, c := range sparse {
		b, err := strconv.Atoi(k)
		if err != nil || b < 0 || b > 255 || c <= 0 {
			continue
		}
		if dense == nil {
			dense = make([]int64, 256)
		}
		dense[b] += c
	}
	return dense
}

// RecordParamObservations 合并观测到 api_parameter_value_obs（幂等增量 UPSERT）。
func (s *ParamObsStore) RecordParamObservations(ctx context.Context, endpointKey string, obs []ParamObservation) error {
	if s == nil || s.db == nil || endpointKey == "" || len(obs) == 0 {
		return nil
	}
	for _, o := range obs {
		if o.Name == "" && o.Path == "" {
			continue
		}
		path := o.Path
		name := o.Name
		if name == "" {
			name = path
		}
		loc := o.Location
		if loc == "" {
			loc = "BODY"
		}
		// 读取既有行再合并（简单正确；高并发下用 SQL 聚合亦可）
		var row paramObsRow
		var distinct *int
		var hashesRaw, lenRaw, valRaw, histRaw, prefixRaw, suffixRaw, formatRaw []byte
		err := s.db.QueryRow(ctx, `
SELECT sample_count, min_length, max_length, min_value, max_value, distinct_count, value_hashes,
       null_count, length_reservoir, value_reservoir, char_histogram, prefix_counts, suffix_counts,
       format_sample_count, format_counts
FROM api_parameter_value_obs
WHERE endpoint_key=$1 AND location=$2 AND structured_path=$3 AND parameter_name=$4`,
			endpointKey, loc, path, name).Scan(&row.sampleCount, &row.minLen, &row.maxLen,
			&row.minVal, &row.maxVal, &distinct, &hashesRaw,
			&row.nullCount, &lenRaw, &valRaw, &histRaw, &prefixRaw, &suffixRaw,
			&row.formatSampleCount, &formatRaw)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("load param obs: %w", err)
		}
		row.hashes = decodeHashList(hashesRaw)
		// 扩展列解析失败返回错误（不静默重置既有蓄水池/直方图为空集造成统计回退）。
		if err := json.Unmarshal(lenRaw, &row.lengthReservoir); len(lenRaw) > 0 && err != nil {
			return fmt.Errorf("decode length reservoir: %w", err)
		}
		if err := json.Unmarshal(valRaw, &row.valueReservoir); len(valRaw) > 0 && err != nil {
			return fmt.Errorf("decode value reservoir: %w", err)
		}
		if err := json.Unmarshal(histRaw, &row.charHistogram); len(histRaw) > 0 && err != nil {
			return fmt.Errorf("decode char histogram: %w", err)
		}
		if err := json.Unmarshal(prefixRaw, &row.prefixCounts); len(prefixRaw) > 0 && err != nil {
			return fmt.Errorf("decode prefix counts: %w", err)
		}
		if err := json.Unmarshal(suffixRaw, &row.suffixCounts); len(suffixRaw) > 0 && err != nil {
			return fmt.Errorf("decode suffix counts: %w", err)
		}
		if err := json.Unmarshal(formatRaw, &row.formatCounts); len(formatRaw) > 0 && err != nil {
			return fmt.Errorf("decode format counts: %w", err)
		}
		row.merge(o)
		dc := len(row.hashes)
		distinct = &dc
		hb, _ := json.Marshal(row.hashes)
		lb, _ := json.Marshal(floatsOrEmpty(row.lengthReservoir))
		vb, _ := json.Marshal(floatsOrEmpty(row.valueReservoir))
		cb, _ := json.Marshal(intsOrEmpty(row.charHistogram))
		pb, _ := json.Marshal(countsOrEmpty(row.prefixCounts))
		sb, _ := json.Marshal(countsOrEmpty(row.suffixCounts))
		fb, _ := json.Marshal(countsOrEmpty(row.formatCounts))
		_, err = s.db.Exec(ctx, `
INSERT INTO api_parameter_value_obs
  (endpoint_key, location, structured_path, parameter_name, sample_count,
   min_length, max_length, min_value, max_value, distinct_count, value_hashes,
   null_count, length_reservoir, value_reservoir, char_histogram,
   prefix_counts, suffix_counts, format_sample_count, format_counts, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,
        $12,$13::jsonb,$14::jsonb,$15::jsonb,$16::jsonb,$17::jsonb,$18,$19::jsonb, now())
ON CONFLICT (endpoint_key, location, structured_path, parameter_name) DO UPDATE SET
  sample_count = EXCLUDED.sample_count,
  min_length = EXCLUDED.min_length,
  max_length = EXCLUDED.max_length,
  min_value = EXCLUDED.min_value,
  max_value = EXCLUDED.max_value,
  distinct_count = EXCLUDED.distinct_count,
  value_hashes = EXCLUDED.value_hashes,
  null_count = EXCLUDED.null_count,
  length_reservoir = EXCLUDED.length_reservoir,
  value_reservoir = EXCLUDED.value_reservoir,
  char_histogram = EXCLUDED.char_histogram,
  prefix_counts = EXCLUDED.prefix_counts,
  suffix_counts = EXCLUDED.suffix_counts,
  format_sample_count = EXCLUDED.format_sample_count,
  format_counts = EXCLUDED.format_counts,
  updated_at = now()`,
			endpointKey, loc, path, name, row.sampleCount,
			row.minLen, row.maxLen, row.minVal, row.maxVal, distinct, string(hb),
			row.nullCount, string(lb), string(vb), string(cb), string(pb), string(sb),
			row.formatSampleCount, string(fb))
		if err != nil {
			return fmt.Errorf("upsert param obs: %w", err)
		}
	}
	return nil
}

// floatsOrEmpty/intsOrEmpty/countsOrEmpty 保证空集合落 JSON []/{}（与迁移 000145
// 列默认值及 statistics.go 读取口径一致），不落 JSON null。
func floatsOrEmpty(v []float64) []float64 {
	if v == nil {
		return []float64{}
	}
	return v
}

func intsOrEmpty(v []int64) []int64 {
	if v == nil {
		return []int64{}
	}
	return v
}

func countsOrEmpty(v map[string]int64) map[string]int64 {
	if v == nil {
		return map[string]int64{}
	}
	return v
}

func decodeHashList(raw []byte) []string {
	var out []string
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

func mergeHash(list []string, h string, capN int) []string {
	for _, x := range list {
		if x == h {
			return list
		}
	}
	if len(list) >= capN {
		// 环形替换最旧
		list = append(list[1:], h)
		return list
	}
	return append(list, h)
}
