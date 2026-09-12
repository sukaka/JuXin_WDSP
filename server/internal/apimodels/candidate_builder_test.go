package apimodels

import (
	"strconv"
	"strings"
	"testing"
)

// inferObservedBaseType 观测推断类型：布尔明文哈希全命中且基数 ≤2 → bool；
// 数值上下界存在 → number；否则 string。
func TestInferObservedBaseType(t *testing.T) {
	hashTrue := truncatedValueHash("true")
	hashFalse := truncatedValueHash("false")
	num := 1.5
	one, two, three := 1, 2, 3

	cases := []struct {
		name     string
		min, max *float64
		distinct *int
		hashes   []string
		want     string
	}{
		{"布尔两值", nil, nil, &two, []string{hashTrue, hashFalse}, "bool"},
		{"布尔多值", nil, nil, &one, []string{hashTrue}, "bool"},
		{"布尔哈希但基数超2", nil, nil, &three, []string{hashTrue, hashFalse}, "string"},
		{"混非布尔哈希", nil, nil, &two, []string{hashTrue, "aaaa1111bbbb2222"}, "string"},
		{"数值上下界", &num, &num, nil, nil, "number"},
		{"仅数值下界", &num, nil, nil, nil, "number"},
		{"数值优先于空哈希", &num, nil, &two, []string{}, "number"},
		{"无观测信号", nil, nil, nil, nil, "string"},
		{"哈希存在但无基数值", nil, nil, nil, []string{hashTrue}, "string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := inferObservedBaseType(tc.min, tc.max, tc.distinct, tc.hashes); got != tc.want {
				t.Fatalf("inferObservedBaseType=%q, want %q", got, tc.want)
			}
		})
	}
}

// buildCandidateSummary 摘要注明自动生成与统计摘要；字段超上限折叠。
func TestBuildCandidateSummary(t *testing.T) {
	minLen, maxLen := 3, 32
	fields := []CandidateField{
		{Path: "amount", BaseType: "number", Samples: 100, Presence: 1.0, Required: true},
		{Path: "note", BaseType: "string", Samples: 60, Presence: 0.6, MinLength: &minLen, MaxLength: &maxLen},
	}
	s := buildCandidateSummary(100, fields, 2, 0)
	for _, want := range []string{"自动生成", "有效样本 100", "观测字段 2 个", "新增 2",
		"amount: number", "出现率 100%", "（必填）", "note: string", "长度 3~32"} {
		if !strings.Contains(s, want) {
			t.Fatalf("summary missing %q: %s", want, s)
		}
	}
	if strings.Contains(s, "等 2 个字段") {
		t.Fatalf("should not fold with 2 fields: %s", s)
	}

	// 超 cap 折叠
	many := make([]CandidateField, candidateSummaryFieldCap+5)
	for i := range many {
		many[i] = CandidateField{Path: strings.Repeat("f", i+1), BaseType: "string", Samples: 1, Presence: 0.01}
	}
	s = buildCandidateSummary(100, many, len(many), 0)
	if !strings.Contains(s, "等 "+strconv.Itoa(candidateSummaryFieldCap+5)+" 个字段") {
		t.Fatalf("should fold beyond cap: %s", s)
	}
}
