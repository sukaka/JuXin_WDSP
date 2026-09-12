package apimodels

import (
	"reflect"
	"testing"
)

func pint(v int) *int           { return &v }
func pfloat(v float64) *float64 { return &v }

// ObservedConstraints：观测事实有哪项写哪项，无观测为空（不虚构）。
func TestObservedConstraints(t *testing.T) {
	tests := []struct {
		name string
		in   ParameterProfile
		want map[string]any
	}{
		{"空画像", ParameterProfile{}, map[string]any{}},
		{"仅样本数无观测", ParameterProfile{SampleCount: 500}, map[string]any{}},
		{"部分观测只写已有键", ParameterProfile{SampleCount: 10, MinLength: pint(3)},
			map[string]any{"min_length": 3}},
		{"长度与值域全量", ParameterProfile{
			SampleCount: 10, MinLength: pint(1), MaxLength: pint(32),
			MinValue: pfloat(0.5), MaxValue: pfloat(99.5)},
			map[string]any{"min_length": 1, "max_length": 32, "minimum": 0.5, "maximum": 99.5}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ObservedConstraints(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ObservedConstraints(%+v)=%v want %v", tt.in, got, tt.want)
			}
		})
	}
}

// RecommendedConstraints 样本量分级阈值：<100 不生成（含带观测的情形）。
func TestRecommendedConstraintsSampleThreshold(t *testing.T) {
	full := ParameterProfile{
		MinLength: pint(2), MaxLength: pint(16), P95Length: pint(12),
		MinValue: pfloat(1), MaxValue: pfloat(50), P95Value: pfloat(40),
		DistinctCount: pint(3), EnumCandidates: []string{"a", "b"},
	}
	for _, n := range []int{0, 1, 99} {
		in := full
		in.SampleCount = n
		if got := RecommendedConstraints(in); len(got) != 0 {
			t.Errorf("SampleCount=%d: got %v, want empty", n, got)
		}
	}
	// 边界：100 起步生成
	in := full
	in.SampleCount = RecommendMinSamples
	if got := RecommendedConstraints(in); len(got) == 0 {
		t.Error("SampleCount=100: got empty, want constraints")
	}
}

// RecommendedConstraints 上限分级：100–999 观测区间×安全系数；≥1000 收紧到 P95；
// 无 P95 时 100–999 用观测最大值×2、≥1000 保持观测最大值（不放大）。
// upperBoundCase 上限分级用例（数值维度与长度维度同规则对齐：maxVal=50，有 P95 时 p95Val=40）。
type upperBoundCase struct {
	name       string
	samples    int
	maxLen     *int
	p95        *int
	wantMaxLen int
	wantMax    float64
}

// p95Value 数值维度的 P95 与长度维度用例对齐（有 P95 用 40，无则 nil）。
func (tt upperBoundCase) p95Value() *float64 {
	if tt.p95 != nil {
		return pfloat(40)
	}
	return nil
}

func TestRecommendedConstraintsUpperBound(t *testing.T) {
	tests := []upperBoundCase{
		{"下限边界100_无P95_最大值x2", 100, pint(16), nil, 32, 100},
		{"中段500_无P95_最大值x2", 500, pint(16), nil, 32, 100},
		{"中段999_有P95_P95x2", 999, pint(16), pint(12), 24, 80},
		{"收紧边界1000_有P95_收紧到P95", 1000, pint(16), pint(12), 12, 40},
		{"高量5000_无P95_保持观测最大值", 5000, pint(16), nil, 16, 50},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := ParameterProfile{
				SampleCount: tt.samples,
				MaxLength:   tt.maxLen, P95Length: tt.p95,
				MaxValue: pfloat(50), P95Value: tt.p95Value(),
			}
			got := RecommendedConstraints(in)
			if got["max_length"] != tt.wantMaxLen {
				t.Errorf("max_length=%v want %d", got["max_length"], tt.wantMaxLen)
			}
			if got["maximum"] != tt.wantMax {
				t.Errorf("maximum=%v want %v", got["maximum"], tt.wantMax)
			}
		})
	}
}

// RecommendedConstraints 下限：各样本量档一律取观测最小值（不放大）。
func TestRecommendedConstraintsLowerBound(t *testing.T) {
	for _, n := range []int{100, 999, 1000, 5000} {
		in := ParameterProfile{SampleCount: n, MinLength: pint(2), MinValue: pfloat(1.5)}
		got := RecommendedConstraints(in)
		if got["min_length"] != 2 {
			t.Errorf("samples=%d min_length=%v want 2", n, got["min_length"])
		}
		if got["minimum"] != 1.5 {
			t.Errorf("samples=%d minimum=%v want 1.5", n, got["minimum"])
		}
	}
	// 无观测：上下限键均不生成
	got := RecommendedConstraints(ParameterProfile{SampleCount: 5000})
	if len(got) != 0 {
		t.Errorf("no observations: got %v, want empty", got)
	}
}

// RecommendedConstraints enum 护栏：distinct ≤20 且样本量 ≥100 且有候选值才生成；
// 候选去空串、去重、排序。
func TestRecommendedConstraintsEnumGuard(t *testing.T) {
	base := ParameterProfile{SampleCount: 100, DistinctCount: pint(3),
		EnumCandidates: []string{"b", "a", "b", "", "c"}}
	got := RecommendedConstraints(base)
	wantEnum := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got["enum"], wantEnum) {
		t.Errorf("enum=%v want %v（去重排序去空串）", got["enum"], wantEnum)
	}

	// distinct 超护栏：不生成
	in := base
	in.DistinctCount = pint(21)
	in.EnumCandidates = []string{"a"}
	if _, ok := RecommendedConstraints(in)["enum"]; ok {
		t.Error("distinct_count=21 should not generate enum")
	}
	// distinct=0（观测到矛盾基数）：不生成
	in.DistinctCount = pint(0)
	if _, ok := RecommendedConstraints(in)["enum"]; ok {
		t.Error("distinct_count=0 should not generate enum")
	}
	// 无候选值：不生成
	in = ParameterProfile{SampleCount: 1000, DistinctCount: pint(5)}
	if _, ok := RecommendedConstraints(in)["enum"]; ok {
		t.Error("no candidates should not generate enum")
	}
	// 候选数量超护栏：不生成
	many := make([]string, 0, 21)
	for i := 0; i < 21; i++ {
		many = append(many, string(rune('a'+i)))
	}
	in = ParameterProfile{SampleCount: 1000, DistinctCount: pint(20), EnumCandidates: many}
	if _, ok := RecommendedConstraints(in)["enum"]; ok {
		t.Error("21 candidates should not generate enum")
	}
	// 候选全空串：归一化后为空，不落 enum 键（防空枚举）
	in = ParameterProfile{SampleCount: 1000, DistinctCount: pint(1), EnumCandidates: []string{"", ""}}
	if _, ok := RecommendedConstraints(in)["enum"]; ok {
		t.Error("all-empty candidates should not generate enum key")
	}
	// 样本量不足：即使基数封闭也不生成
	in = ParameterProfile{SampleCount: 99, DistinctCount: pint(2), EnumCandidates: []string{"a", "b"}}
	if _, ok := RecommendedConstraints(in)["enum"]; ok {
		t.Error("samples<100 should not generate enum")
	}
}

// RecommendedConstraints enum 疑似分支（P0-02 加深）：distinct ≤20 且样本量达标、
// 无明文候选值时生成 enum_suspected=true+distinct_count（不落明文枚举值，人工确认）；
// 有候选值时仍生成 enum 钉死值，不重复标记疑似。
func TestRecommendedConstraintsEnumSuspected(t *testing.T) {
	// 无候选值 + 基数可封闭 + 样本达标 → 疑似枚举
	got := RecommendedConstraints(ParameterProfile{SampleCount: 100, DistinctCount: pint(4)})
	if got["enum_suspected"] != true || got["distinct_count"] != 4 {
		t.Errorf("enum_suspected branch: got %v", got)
	}
	if _, ok := got["enum"]; ok {
		t.Errorf("no candidates must not emit plaintext enum: %v", got)
	}

	// 有候选值 → enum 钉死值优先，不标疑似
	got = RecommendedConstraints(ParameterProfile{SampleCount: 100, DistinctCount: pint(2),
		EnumCandidates: []string{"b", "a"}})
	if _, ok := got["enum_suspected"]; ok {
		t.Errorf("plaintext enum should not double-mark suspected: %v", got)
	}
	if _, ok := got["enum"]; !ok {
		t.Errorf("candidates should still emit enum: %v", got)
	}

	// 基数超护栏 → 两者皆不生成
	got = RecommendedConstraints(ParameterProfile{SampleCount: 1000, DistinctCount: pint(21)})
	if _, ok := got["enum_suspected"]; ok {
		t.Errorf("distinct=21 should not emit enum_suspected: %v", got)
	}
	// 样本量不足 → 两者皆不生成
	got = RecommendedConstraints(ParameterProfile{SampleCount: 99, DistinctCount: pint(4)})
	if _, ok := got["enum_suspected"]; ok {
		t.Errorf("samples<100 should not emit enum_suspected: %v", got)
	}
	// distinct=0（矛盾基数）→ 不生成
	got = RecommendedConstraints(ParameterProfile{SampleCount: 1000, DistinctCount: pint(0)})
	if _, ok := got["enum_suspected"]; ok {
		t.Errorf("distinct=0 should not emit enum_suspected: %v", got)
	}
}
