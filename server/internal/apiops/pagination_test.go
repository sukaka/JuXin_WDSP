// pagination_test.go 分页参数夹取单测（page_size 上限 100，与兄弟包口径一致）。
package apiops

import (
	"net/http/httptest"
	"testing"
)

func TestQueryPageSizeClamped(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"", 20}, {"0", 20}, {"abc", 20}, {"50", 50}, {"100", 100}, {"101", 100}, {"10000", 100},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/x?page_size="+c.raw, nil)
		if got := queryPageSize(r, 20); got != c.want {
			t.Errorf("page_size=%q: got %d, want %d", c.raw, got, c.want)
		}
	}
}
