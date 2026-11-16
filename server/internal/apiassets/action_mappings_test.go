package apiassets

import (
	"strings"
	"testing"
)

func TestNormalizeEndpointAction(t *testing.T) {
	for _, tc := range []struct {
		name  string
		raw   string
		want  string
		valid bool
	}{
		{name: "小写规范化", raw: " login ", want: "LOGIN", valid: true},
		{name: "内置动作", raw: "read_detail", want: "READ_DETAIL", valid: true},
		{name: "词表外自定义动作", raw: " manual_review_v2 ", want: "MANUAL_REVIEW_V2", valid: true},
		{name: "64字节上限", raw: strings.Repeat("A", maxEndpointActionLength), want: strings.Repeat("A", maxEndpointActionLength), valid: true},
		{name: "空值", raw: "  "},
		{name: "非法字符", raw: "READ-LIST"},
		{name: "含空格", raw: "READ LIST"},
		{name: "数字开头", raw: "1READ"},
		{name: "下划线开头", raw: "_READ"},
		{name: "非ASCII", raw: "人工审核"},
		{name: "超长", raw: strings.Repeat("A", maxEndpointActionLength+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeEndpointAction(tc.raw)
			if tc.valid {
				if err != nil || got != tc.want {
					t.Fatalf("normalizeEndpointAction(%q) = %q, %v; want %q", tc.raw, got, err, tc.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("normalizeEndpointAction(%q) must fail", tc.raw)
			}
		})
	}
}

func TestBuiltInEndpointActionsRemainValid(t *testing.T) {
	actions := []string{"CREATE", "READ_DETAIL", "UPDATE", "PATCH", "DELETE", "CUSTOM"}
	for _, rule := range actionRules {
		actions = append(actions, rule.action)
	}
	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			got, err := normalizeEndpointAction(action)
			if err != nil || got != action {
				t.Fatalf("normalizeEndpointAction(%q) = %q, %v", action, got, err)
			}
		})
	}
}
