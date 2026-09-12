// pagination_test.go 分页参数夹取单测（page_size 上限 100，与兄弟包口径一致）。
package apiscan

import (
	"net/http/httptest"
	"testing"
)

func TestQueryPageSizeClamped(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"", 20},       // 缺省回退默认
		{"0", 20},      // 非正回退默认
		{"abc", 20},    // 非法回退默认
		{"50", 50},     // 正常值
		{"100", 100},   // 上限边界
		{"101", 100},   // 超限夹取
		{"10000", 100}, // 大值夹取
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/x?page_size="+c.raw, nil)
		if got := queryPageSize(r, 20); got != c.want {
			t.Errorf("page_size=%q: got %d, want %d", c.raw, got, c.want)
		}
	}
}
