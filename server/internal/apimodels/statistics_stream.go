// statistics_stream.go 参数微模型流式统计算法（阶段8 §16/§17 统计增强批）：
// 蓄水池分位数 / 字符直方图香农熵 / 前后缀 TopN / IQR 离群计数，全部为纯函数，
// 供 statistics.go 窗口全量重算与未来观测增量写入方（apiruntime paramobs）共用。
//
// 选型说明：
//   - 分位数：定长蓄水池（ReservoirCap）+ 排序 + 线性插值。不选 t-digest/P²：
//     蓄水池跨窗口可直接合并（确定性等距抽样，同输入同输出），实现简单可单测；
//     近似误差随蓄水池容量收敛，1024 容量对 API 参数长度/值域分布足够。
//   - 熵：字符直方图（256 桶计数）天然精确可合并（逐桶相加），由直方图算
//     Shannon 熵（bits/字符）；不落明文，符合观测链路数据最小化纪律。
//   - 前后缀 TopN：脱敏哈希 → 计数 map 精确可合并（逐键相加），排序确定性
//     （计数降序、键升序兜底），输出 TopN。
//   - 离群：IQR 栅栏法（Q1−1.5·IQR / Q3+1.5·IQR 之外记离群），在排序蓄水池上
//     计数；样本 <4 时四分位估计不稳定，返回 ok=false 不虚构。
//
// 合并语义与 statistics.go 一致：蓄水池/直方图/计数 map 的合并满足幂等重算
// （同一观测集重复合并结果一致），窗口重算时整体覆盖旧值。
package apimodels

import (
	"math"
	"sort"
)

// 统计增强参数。
const (
	// ReservoirCap 长度/数值观测蓄水池容量上限（分位数近似精度与存储的权衡）。
	ReservoirCap = 1024
	// AffixTopNLimit 常见前后缀保留条数。
	AffixTopNLimit = 10
	// OutlierIQRFactor IQR 栅栏系数（1.5 = 常规离群口径）。
	OutlierIQRFactor = 1.5
	// outlierMinSamples IQR 离群计数的最小样本量（低于此值四分位估计不稳定）。
	outlierMinSamples = 4
)

// MergeReservoir 合并两个蓄水池，输出升序、长度 ≤ capN 的确定性样本。
// 合并后总量不超 capN 时为全量并集排序；超限时对排序并集做等距抽样
// （保留首尾极值），同输入恒得同输出，保证窗口重算幂等。capN < 2 时退化为
// 取排序后前 capN 个（实际使用固定 ReservoirCap，该分支仅为防御）。
func MergeReservoir(a, b []float64, capN int) []float64 {
	merged := make([]float64, 0, len(a)+len(b))
	merged = append(merged, a...)
	merged = append(merged, b...)
	sort.Float64s(merged)
	if capN <= 0 || len(merged) <= capN {
		return merged
	}
	if capN == 1 {
		return merged[:1]
	}
	out := make([]float64, capN)
	for i := range out {
		out[i] = merged[i*(len(merged)-1)/(capN-1)]
	}
	return out
}

// MergeHistogram 字符直方图逐桶相加（任一侧可为空/长度不足，按 256 桶对齐；
// 长度超过 256 的桶原样保留并相加，防御性容忍写入方扩展桶数）。
func MergeHistogram(a, b []int64) []int64 {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	out := make([]int64, n)
	for i := 0; i < n; i++ {
		if i < len(a) {
			out[i] += a[i]
		}
		if i < len(b) {
			out[i] += b[i]
		}
	}
	return out
}

// MergeCounts 计数 map 逐键相加（前后缀计数合并）。
func MergeCounts(a, b map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(a)+len(b))
	for k, v := range a {
		out[k] += v
	}
	for k, v := range b {
		out[k] += v
	}
	return out
}

// Quantile 线性插值分位数（输入必须升序；与 numpy 默认 'linear' 口径一致）。
// 空输入或 q 越界返回 ok=false。
func Quantile(sorted []float64, q float64) (float64, bool) {
	n := len(sorted)
	if n == 0 || q < 0 || q > 1 || math.IsNaN(q) {
		return 0, false
	}
	if n == 1 {
		return sorted[0], true
	}
	pos := q * float64(n-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return sorted[lo], true
	}
	frac := pos - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac, true
}

// QuantileStats 一组分位数（指针语义对应可空统计列：无观测为 nil）。
type QuantileStats struct {
	P50 *float64
	P90 *float64
	P95 *float64
	P99 *float64
}

// QuantilesOf 由无序样本计算 P50/P90/P95/P99（内部排序副本，不改入参）。
// 空样本返回全 nil。
func QuantilesOf(samples []float64) QuantileStats {
	var out QuantileStats
	if len(samples) == 0 {
		return out
	}
	sorted := make([]float64, len(samples))
	copy(sorted, samples)
	sort.Float64s(sorted)
	for _, q := range []struct {
		q   float64
		dst **float64
	}{
		{0.50, &out.P50},
		{0.90, &out.P90},
		{0.95, &out.P95},
		{0.99, &out.P99},
	} {
		if v, ok := Quantile(sorted, q.q); ok {
			v := v
			*q.dst = &v
		}
	}
	return out
}

// ShannonEntropy 由字符直方图计算香农熵（bits/字符）。
// 直方图全空返回 ok=false；负计数为非法输入，返回 ok=false 不虚构。
func ShannonEntropy(hist []int64) (float64, bool) {
	var total int64
	for _, c := range hist {
		if c < 0 {
			return 0, false
		}
		total += c
	}
	if total == 0 {
		return 0, false
	}
	var h float64
	for _, c := range hist {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(total)
		h -= p * math.Log2(p)
	}
	return h, true
}

// CountItem 前后缀 TopN 条目（Key 为脱敏哈希，不落明文）。
type CountItem struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// TopNCounts 计数 map → TopN 列表（计数降序，计数相同按键升序，输出确定性；
// 跳过空键与非正计数）。n ≤ 0 表示不限条数。
func TopNCounts(counts map[string]int64, n int) []CountItem {
	out := make([]CountItem, 0, len(counts))
	for k, c := range counts {
		if k == "" || c <= 0 {
			continue
		}
		out = append(out, CountItem{Key: k, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// OutlierCountIQR IQR 栅栏法离群计数（输入必须升序）：统计落在
// [Q1−k·IQR, Q3+k·IQR] 之外的样本数。样本 <outlierMinSamples 返回 ok=false。
func OutlierCountIQR(sorted []float64, k float64) (int64, bool) {
	if len(sorted) < outlierMinSamples {
		return 0, false
	}
	q1, ok1 := Quantile(sorted, 0.25)
	q3, ok3 := Quantile(sorted, 0.75)
	if !ok1 || !ok3 {
		return 0, false
	}
	iqr := q3 - q1
	lo := q1 - k*iqr
	hi := q3 + k*iqr
	var c int64
	for _, v := range sorted {
		if v < lo || v > hi {
			c++
		}
	}
	return c, true
}
