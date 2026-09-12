// rank.go 排行与直方图合并的纯函数（可单测，不依赖 DB）。
package analytics

import (
	"sort"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/metrics"
)

// KV 通用排行项。
type KV struct {
	Key   string  `json:"key"`
	Value float64 `json:"value"`
}

// SortKVSlice 原地排序：值降序，值相同按键升序（保证确定性输出）。
func SortKVSlice(kvs []KV) {
	sort.Slice(kvs, func(i, j int) bool {
		if kvs[i].Value != kvs[j].Value {
			return kvs[i].Value > kvs[j].Value
		}
		return kvs[i].Key < kvs[j].Key
	})
}

// SortKVsDesc map → 有序排行切片。
func SortKVsDesc(m map[string]float64) []KV {
	out := make([]KV, 0, len(m))
	for k, v := range m {
		out = append(out, KV{Key: k, Value: v})
	}
	SortKVSlice(out)
	return out
}

// TopN 取前 n 个；n<=0 或超过长度时返回全部。
func TopN(kvs []KV, n int) []KV {
	if n <= 0 || n > len(kvs) {
		return kvs
	}
	return kvs[:n]
}

// 分布统计的归一桶名（无值时归入，避免空键）。
const (
	methodUnknownBucket      = "(未知)"
	contentTypeNoneBucket    = "(无)"
	ipSourceUnknownBucket    = "(未知)"
	trustedProxyDirectBucket = "(直连)"
)

// normalizeMethod 请求方法归一：去空白、大写、截断 16 字符（access_logs.request_method
// 列宽上限），空串归入“(未知)”。
func normalizeMethod(m string) string {
	m = strings.ToUpper(strings.TrimSpace(m))
	if m == "" {
		return methodUnknownBucket
	}
	if len(m) > 16 {
		m = m[:16]
	}
	return m
}

// NormalizeContentType Content-Type 归一为主类型：去参数（; 后部分）、小写、
// 截断 64 字符，空串归入“(无)”。只处理头值本身，不涉及请求体。
func NormalizeContentType(ct string) string {
	ct = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	if ct == "" {
		return contentTypeNoneBucket
	}
	if len(ct) > 64 {
		ct = ct[:64]
	}
	return ct
}

// NormalizeClientIPSource 客户端 IP 识别来源归一：去空白、大写、截断 32 字符
// （access_logs.client_ip_source 列宽上限），空串归入“(未知)”
// （口径：CONNECTION/X_FORWARDED_FOR/X_REAL_IP/FORWARDED/CUSTOM_HEADER）。
func NormalizeClientIPSource(src string) string {
	src = strings.ToUpper(strings.TrimSpace(src))
	if src == "" {
		return ipSourceUnknownBucket
	}
	if len(src) > 32 {
		src = src[:32]
	}
	return src
}

// normalizeTrustedProxy 可信代理名归一：去空白、截断 128 字符
// （access_logs.trusted_proxy_used 列宽上限），空串归入“(直连)”。
func normalizeTrustedProxy(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return trustedProxyDirectBucket
	}
	if len(name) > 128 {
		name = name[:128]
	}
	return name
}

// MergeCounts 直方图桶计数合并（dst 长度不足时扩展）。
func MergeCounts(dst, src []int) []int {
	if len(dst) < len(src) {
		nd := make([]int, len(src))
		copy(nd, dst)
		dst = nd
	}
	for i, c := range src {
		dst[i] += c
	}
	return dst
}

// normalizeCounts 把桶计数规整为 metrics.DurationBucketsMs 的长度：
// 溢出桶（>最大 le）并入最后一桶，避免 PercentileFromBuckets 越界。
func normalizeCounts(counts []int) []int {
	n := len(metrics.DurationBucketsMs)
	out := make([]int, n)
	for i, c := range counts {
		if i >= n {
			out[n-1] += c
		} else {
			out[i] += c
		}
	}
	return out
}

// seriesPoint 透视前的原始点（桶时间 + 维度键 + 值）。
type seriesPoint struct {
	t   time.Time
	key string
	v   float64
}

// pivotSeries 把散点透视为对齐序列：时间升序、键升序，缺失桶补 0。
func pivotSeries(points []seriesPoint) (times []time.Time, keys []string, series map[string][]float64) {
	tset := map[time.Time]struct{}{}
	kset := map[string]struct{}{}
	for _, p := range points {
		tset[p.t] = struct{}{}
		kset[p.key] = struct{}{}
	}
	for t := range tset {
		times = append(times, t)
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	for k := range kset {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	idx := make(map[time.Time]int, len(times))
	for i, t := range times {
		idx[t] = i
	}
	series = make(map[string][]float64, len(keys))
	for _, k := range keys {
		series[k] = make([]float64, len(times))
	}
	for _, p := range points {
		series[p.key][idx[p.t]] += p.v
	}
	return times, keys, series
}
