package apigroups

import (
	"strings"
	"testing"
)

func TestNormalizeEndpointGroupCode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		raw   string
		want  string
		valid bool
	}{
		{name: "小写规范化", raw: " sales_read ", want: "SALES_READ", valid: true},
		{name: "数字下划线", raw: "group_2", want: "GROUP_2", valid: true},
		{name: "空值", raw: "  "},
		{name: "数字开头", raw: "1GROUP"},
		{name: "非法字符", raw: "SALES-READ"},
		{name: "含空格", raw: "SALES READ"},
		{name: "超长", raw: strings.Repeat("A", maxCodeLength+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeEndpointGroupCode(tc.raw)
			if tc.valid {
				if err != nil || got != tc.want {
					t.Fatalf("normalizeEndpointGroupCode(%q) = %q, %v; want %q", tc.raw, got, err, tc.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("normalizeEndpointGroupCode(%q) must fail", tc.raw)
			}
		})
	}
}
