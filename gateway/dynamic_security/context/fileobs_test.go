package context

import (
	"strings"
	"testing"
)

// 文件名归一化：basename 剥离（\ 与 / 两种分隔）、控制字符去除、128 字符截断。
func TestSanitizeFileName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"report.pdf", "report.pdf"},
		{`C:\fakepath\报表.xlsx`, "报表.xlsx"}, // 浏览器全路径形态
		{"../../etc/passwd", "passwd"},     // 穿越形态归一为 basename
		{"dir/sub/file.csv", "file.csv"},
		{"  spaced name.txt ", "spaced name.txt"}, // 首尾空白剥离
		{"a\x00b\x1fc.ttf", "abc.ttf"},            // 控制字符去除
		{"/", ""},                                 // 纯目录前缀 → 空
		{`\`, ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := SanitizeFileName(c.in); got != c.want {
			t.Fatalf("SanitizeFileName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// 128 字符截断（按字符数，与列宽口径一致）
	long := strings.Repeat("文", 130) + ".txt"
	got := SanitizeFileName(long)
	if n := len([]rune(got)); n != MaxFileNameLen {
		t.Fatalf("truncate runes = %d, want %d", n, MaxFileNameLen)
	}
}

// 扩展名提取：小写化、隐藏文件/无点/点结尾/超长后缀不识别。
func TestFileExtension(t *testing.T) {
	cases := []struct{ in, want string }{
		{"report.PDF", "pdf"},
		{"a.tar.gz", "gz"},
		{"noext", ""},
		{".profile", ""},
		{"file.", ""},
		{"file." + strings.Repeat("a", 17), ""}, // 超长后缀不识别为扩展名
		{"file." + strings.Repeat("a", 16), strings.Repeat("a", 16)},
		{"", ""},
	}
	for _, c := range cases {
		if got := FileExtension(c.in); got != c.want {
			t.Fatalf("FileExtension(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// MIME 归一化：主类型小写、参数剥离、畸形降级、截断。
func TestSanitizeMIME(t *testing.T) {
	cases := []struct{ in, want string }{
		{"application/pdf", "application/pdf"},
		{"Text/CSV; charset=utf-8", "text/csv"},
		{"application/octet-stream", "application/octet-stream"},
		{"garbage value without slash", "garbage value without slash"}, // 畸形降级 ';' 前缀
		{"", ""},
	}
	for _, c := range cases {
		if got := SanitizeMIME(c.in); got != c.want {
			t.Fatalf("SanitizeMIME(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := SanitizeMIME(strings.Repeat("a", 200)); len(got) != MaxFileMIMELen {
		t.Fatalf("mime truncate = %d, want %d", len(got), MaxFileMIMELen)
	}
}
