package apimodels

import (
	"math"
	"reflect"
	"testing"
)

// MergeReservoir：合并后不超 cap 为全量并集排序。
func TestMergeReservoir_UnderCap(t *testing.T) {
	got := MergeReservoir([]float64{5, 1}, []float64{3, 2}, 10)
	want := []float64{1, 2, 3, 5}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("MergeReservoir=%v want %v", got, want)
	}
}

// MergeReservoir：超 cap 时确定性等距抽样——同输入恒得同输出（幂等重算前提），
// 长度恰为 cap，首尾极值保留。
func TestMergeReservoir_OverCapDeterministic(t *testing.T) {
	a := make([]float64, 800)
	b := make([]float64, 800)
	for i := range a {
		a[i] = float64(i)
		b[i] = float64(1000 + i)
	}
	first := MergeReservoir(a, b, ReservoirCap)
	second := MergeReservoir(a, b, ReservoirCap)
	if len(first) != ReservoirCap {
		t.Fatalf("len=%d want %d", len(first), ReservoirCap)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("MergeReservoir not deterministic")
	}
	if first[0] != 0 || first[len(first)-1] != 1799 {
		t.Errorf("extremes not preserved: [%v, %v]", first[0], first[len(first)-1])
	}
	for i := 1; i < len(first); i++ {
		if first[i] < first[i-1] {
			t.Fatalf("output not sorted at %d: %v", i, first[i-1:i+1])
		}
	}
}

// MergeReservoir：防御边界（空输入、cap≤1）。
func TestMergeReservoir_Edges(t *testing.T) {
	if got := MergeReservoir(nil, nil, 10); len(got) != 0 {
		t.Errorf("empty merge=%v", got)
	}
	if got := MergeReservoir(nil, []float64{2, 1}, 10); !reflect.DeepEqual(got, []float64{1, 2}) {
		t.Errorf("one-side merge=%v", got)
	}
	if got := MergeReservoir([]float64{3, 1, 2}, nil, 0); !reflect.DeepEqual(got, []float64{1, 2, 3}) {
		t.Errorf("cap=0 不限长=%v", got)
	}
	if got := MergeReservoir([]float64{3, 1, 2}, nil, 1); !reflect.DeepEqual(got, []float64{1}) {
		t.Errorf("cap=1=%v", got)
	}
}

// MergeHistogram：逐桶相加、长度对齐、空侧容忍。
func TestMergeHistogram(t *testing.T) {
	got := MergeHistogram([]int64{1, 2}, []int64{10, 20, 30})
	want := []int64{11, 22, 30}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("MergeHistogram=%v want %v", got, want)
	}
	if got := MergeHistogram(nil, nil); len(got) != 0 {
		t.Errorf("empty MergeHistogram=%v", got)
	}
}

// MergeCounts：逐键相加。
func TestMergeCounts(t *testing.T) {
	got := MergeCounts(map[string]int64{"a": 1, "b": 2}, map[string]int64{"b": 3, "c": 4})
	want := map[string]int64{"a": 1, "b": 5, "c": 4}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("MergeCounts=%v want %v", got, want)
	}
}

// Quantile：精度边界（空/单点/端点/线性插值/越界）。
func TestQuantile(t *testing.T) {
	if _, ok := Quantile(nil, 0.5); ok {
		t.Error("empty input should not be ok")
	}
	if _, ok := Quantile([]float64{1}, -0.1); ok {
		t.Error("q<0 should not be ok")
	}
	if _, ok := Quantile([]float64{1}, 1.1); ok {
		t.Error("q>1 should not be ok")
	}
	if _, ok := Quantile([]float64{1}, math.NaN()); ok {
		t.Error("q=NaN should not be ok")
	}
	if v, ok := Quantile([]float64{42}, 0.95); !ok || v != 42 {
		t.Errorf("single element=(%v,%v)", v, ok)
	}
	if v, _ := Quantile([]float64{1, 2, 3, 4}, 0); v != 1 {
		t.Errorf("q=0 min=%v", v)
	}
	if v, _ := Quantile([]float64{1, 2, 3, 4}, 1); v != 4 {
		t.Errorf("q=1 max=%v", v)
	}
	// 偶数样本中位数：线性插值 2.5。
	if v, _ := Quantile([]float64{1, 2, 3, 4}, 0.5); v != 2.5 {
		t.Errorf("p50=%v want 2.5", v)
	}
	// 两样本 p90：pos=0.9 → 1×0.1 + 10×0.9 = 9.1。
	if v, _ := Quantile([]float64{1, 10}, 0.9); math.Abs(v-9.1) > 1e-9 {
		t.Errorf("p90=%v want 9.1", v)
	}
	// 1..100 的 p95：pos=94.05 → 95 + 0.05 = 95.05。
	s := make([]float64, 100)
	for i := range s {
		s[i] = float64(i + 1)
	}
	if v, _ := Quantile(s, 0.95); math.Abs(v-95.05) > 1e-9 {
		t.Errorf("p95=%v want 95.05", v)
	}
}

// QuantilesOf：空样本全 nil；无序输入不改入参且输出正确。
func TestQuantilesOf(t *testing.T) {
	if q := QuantilesOf(nil); q.P50 != nil || q.P90 != nil || q.P95 != nil || q.P99 != nil {
		t.Errorf("empty QuantilesOf=%+v want all nil", q)
	}
	in := []float64{100, 1, 50, 25, 75}
	q := QuantilesOf(in)
	if !reflect.DeepEqual(in, []float64{100, 1, 50, 25, 75}) {
		t.Error("QuantilesOf mutated input")
	}
	// 排序后 [1 25 50 75 100]：P50=50；P90 pos=3.6 → 75×0.4+100×0.6=90；
	// P95 pos=3.8 → 95；P99 pos=3.96 → 99。
	if q.P50 == nil || *q.P50 != 50 {
		t.Errorf("P50=%v", q.P50)
	}
	if q.P90 == nil || math.Abs(*q.P90-90) > 1e-9 {
		t.Errorf("P90=%v", q.P90)
	}
	if q.P95 == nil || math.Abs(*q.P95-95) > 1e-9 {
		t.Errorf("P95=%v", q.P95)
	}
	if q.P99 == nil || math.Abs(*q.P99-99) > 1e-9 {
		t.Errorf("P99=%v", q.P99)
	}
}

// ShannonEntropy：空/非法不虚构，单符号 0 bit，均匀分布 log2(n)。
func TestShannonEntropy(t *testing.T) {
	if _, ok := ShannonEntropy(nil); ok {
		t.Error("empty histogram should not be ok")
	}
	if _, ok := ShannonEntropy([]int64{1, -1}); ok {
		t.Error("negative count should not be ok")
	}
	if v, ok := ShannonEntropy([]int64{0, 10, 0}); !ok || v != 0 {
		t.Errorf("single symbol=(%v,%v) want (0,true)", v, ok)
	}
	if v, _ := ShannonEntropy([]int64{5, 5}); math.Abs(v-1) > 1e-9 {
		t.Errorf("two uniform=%v want 1 bit", v)
	}
	hist := make([]int64, 256)
	for i := range hist {
		hist[i] = 1
	}
	if v, _ := ShannonEntropy(hist); math.Abs(v-8) > 1e-9 {
		t.Errorf("256 uniform=%v want 8 bits", v)
	}
	// 偏斜分布：p=(0.5,0.25,0.25) → 1.5 bits。
	if v, _ := ShannonEntropy([]int64{2, 1, 1}); math.Abs(v-1.5) > 1e-9 {
		t.Errorf("skewed=%v want 1.5 bits", v)
	}
}

// TopNCounts：计数降序、键升序兜底、限条数、过滤空键与非正计数；确定性。
func TestTopNCounts(t *testing.T) {
	counts := map[string]int64{
		"b": 5, "a": 5, "c": 3, "d": 1, "": 9, "z": 0, "y": -2,
	}
	got := TopNCounts(counts, 10)
	want := []CountItem{{"a", 5}, {"b", 5}, {"c", 3}, {"d", 1}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TopNCounts=%v want %v", got, want)
	}
	if got := TopNCounts(counts, 2); !reflect.DeepEqual(got, want[:2]) {
		t.Errorf("TopNCounts n=2=%v", got)
	}
	if got := TopNCounts(counts, 0); !reflect.DeepEqual(got, want) {
		t.Errorf("TopNCounts 不限=%v", got)
	}
	if got := TopNCounts(nil, 10); len(got) != 0 {
		t.Errorf("nil map=%v", got)
	}
}

// OutlierCountIQR：样本不足不虚构；正态样例无离群；极端值被计入。
func TestOutlierCountIQR(t *testing.T) {
	if _, ok := OutlierCountIQR([]float64{1, 2, 3}, OutlierIQRFactor); ok {
		t.Error("<4 samples should not be ok")
	}
	normal := make([]float64, 100)
	for i := range normal {
		normal[i] = float64(i + 1)
	}
	if c, ok := OutlierCountIQR(normal, OutlierIQRFactor); !ok || c != 0 {
		t.Errorf("uniform 1..100=(%v,%v) want (0,true)", c, ok)
	}
	// Q1=25.75, Q3=75.25, IQR=49.5 → 上栅栏 149.5：10000 离群，下栅栏 -48.5 无离群。
	withOutlier := append(append([]float64{}, normal...), 10000)
	if c, ok := OutlierCountIQR(withOutlier, OutlierIQRFactor); !ok || c != 1 {
		t.Errorf("with outlier=(%v,%v) want (1,true)", c, ok)
	}
	// 恒定样本：IQR=0，栅栏即值本身，无离群。
	if c, ok := OutlierCountIQR([]float64{7, 7, 7, 7, 7}, OutlierIQRFactor); !ok || c != 0 {
		t.Errorf("constant=(%v,%v)", c, ok)
	}
}

// 蓄水池分位数精度：大样本下与精确分位数的偏差有界（选型依据的实证）。
func TestReservoirQuantileAccuracy(t *testing.T) {
	full := make([]float64, 5000)
	for i := range full {
		full[i] = float64(i)
	}
	reservoir := MergeReservoir(full[:2500], full[2500:], ReservoirCap)
	exact, _ := Quantile(full, 0.99)
	approx, ok := Quantile(reservoir, 0.99)
	if !ok {
		t.Fatal("reservoir quantile not ok")
	}
	// 等距抽样保留分布形状：p99 偏差应远小于值域 1%。
	if math.Abs(approx-exact) > 50 {
		t.Errorf("p99 approx=%v exact=%v dev too large", approx, exact)
	}
}

// roundPtr：长度分位数取整。
func TestRoundPtr(t *testing.T) {
	if v := roundPtr(95.05); v == nil || *v != 95 {
		t.Errorf("roundPtr(95.05)=%v", v)
	}
	if v := roundPtr(95.5); v == nil || *v != 96 {
		t.Errorf("roundPtr(95.5)=%v", v)
	}
}
