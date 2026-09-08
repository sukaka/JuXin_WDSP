// pagination_test.go 分页参数解析与夹取单测（page_size 上限 100，与兄弟包口径一致）。
package protectedaddresses

import (
	"net/http/httptest"
	"testing"
)

func TestQueryPageClamped(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"", 1},    // 缺省回退默认
		{"0", 1},   // 非正回退默认
		{"-3", 1},  // 负数回退默认
		{"abc", 1}, // 非法回退默认
		{"2", 2},   // 正常值
		// page 越界（大于总页数）参数层不夹取，数据侧 offset 落空自然返回空页
		{"9999", 9999},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/x?page="+c.raw, nil)
		if got := queryInt(r, "page", 1); got != c.want {
			t.Errorf("page=%q: got %d, want %d", c.raw, got, c.want)
		}
	}
}

func TestQueryPageSizeClamped(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"", 20},     // 缺省回退默认
		{"0", 20},    // 非正回退默认
		{"abc", 20},  // 非法回退默认
		{"50", 50},   // 正常值
		{"100", 100}, // 上限边界
		{"101", 100}, // 超限夹取
		{"10000", 100},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/x?page_size="+c.raw, nil)
		if got := queryPageSize(r, 20); got != c.want {
			t.Errorf("page_size=%q: got %d, want %d", c.raw, got, c.want)
		}
	}
}

func TestNormalizePage(t *testing.T) {
	cases := []struct {
		page, pageSize int
		wantPage       int
		wantSize       int
	}{
		{0, 0, 1, 20},
		{-1, -5, 1, 20},
		{1, 1, 1, 1},
		{3, 50, 3, 50},
		{1, 100, 1, 100},
		{1, 101, 1, 20}, // 超过上限回退默认（store 层直接调用的兜底）
		{2, 10000, 2, 20},
	}
	for _, c := range cases {
		gotPage, gotSize := normalizePage(c.page, c.pageSize)
		if gotPage != c.wantPage || gotSize != c.wantSize {
			t.Errorf("normalizePage(%d,%d) = (%d,%d), want (%d,%d)",
				c.page, c.pageSize, gotPage, gotSize, c.wantPage, c.wantSize)
		}
	}
}

// 页偏移计算：page 越界（大于总页数）时 offset 指向空区间，SQL 自然返回空页。
func TestPageOffsetBeyondRange(t *testing.T) {
	page, pageSize := normalizePage(5, 20)
	if off := (page - 1) * pageSize; off != 80 {
		t.Errorf("offset = %d, want 80", off)
	}
}
