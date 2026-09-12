// pagination_test.go 分页参数夹取单测（page_size 上限 100，与兄弟包口径一致）。
package apidata

import (
	"context"
	"net/http/httptest"
	"strconv"
	"strings"
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

// TestNormPageClamped MemStore 分页归一同步夹取（上限 100）。
func TestNormPageClamped(t *testing.T) {
	if _, ps := normPage(1, 10000); ps != 100 {
		t.Errorf("normPage pageSize = %d, want 100", ps)
	}
	if _, ps := normPage(0, 0); ps != 20 {
		t.Errorf("normPage 默认值 = %d, want 20", ps)
	}
}

// TestListAllTypesNotTruncatedByClamp 全量导出不走分页夹取（类型超过 100 不截断）。
func TestListAllTypesNotTruncatedByClamp(t *testing.T) {
	m := NewMemStore()
	for i := 0; i < 150; i++ {
		n := "t" + strings.Repeat("x", 3) + strconv.Itoa(i)
		if err := m.CreateType(context.Background(), &SensitiveDataType{Name: n, Level: LevelGeneral}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := m.ListAllTypes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 150 {
		t.Fatalf("ListAllTypes 返回 %d 条, want 150（全量导出不得被分页夹取截断）", len(list))
	}
	// 分页接口仍夹取
	page, _, err := m.ListTypes(context.Background(), TypeFilter{Page: 1, PageSize: 10000})
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 100 {
		t.Fatalf("ListTypes pageSize=10000 返回 %d 条, want 100", len(page))
	}
}
