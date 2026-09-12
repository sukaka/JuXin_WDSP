package response

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 下载观测提取：attachment/inline 携带 filename 产出 DOWNLOAD 观测（含 RFC 5987 filename*）。
// 入参为挂点侧原始（未截断未脱敏）Content-Disposition/Content-Type 头值。
func TestBuildDownloadFileObservation(t *testing.T) {
	cases := []struct {
		name string
		cd   string
		ct   string
		size int64
		want *dsctx.FileObservation
	}{
		{
			name: "attachment quoted filename",
			cd:   `attachment; filename="report.pdf"`,
			ct:   "application/pdf",
			size: 4096,
			want: &dsctx.FileObservation{
				Direction: dsctx.FileDirectionDownload, FileName: "report.pdf", MatchName: "report.pdf",
				Extension: "pdf", MIME: "application/pdf", Size: 4096,
			},
		},
		{
			name: "inline with rfc5987 filename*",
			cd:   "inline; filename*=utf-8''%E6%8A%A5%E8%A1%A8.xlsx",
			ct:   "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
			size: 10,
			want: &dsctx.FileObservation{
				Direction: dsctx.FileDirectionDownload, FileName: "报表.xlsx", MatchName: "报表.xlsx",
				Extension: "xlsx", MIME: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", Size: 10,
			},
		},
		{
			name: "attachment strips directory prefix",
			cd:   `attachment; filename="..\..\evil\dump.sql"`,
			ct:   "application/sql; charset=utf-8",
			size: 7,
			want: &dsctx.FileObservation{
				Direction: dsctx.FileDirectionDownload, FileName: "dump.sql", MatchName: "dump.sql",
				Extension: "sql", MIME: "application/sql", Size: 7,
			},
		},
	}
	for _, c := range cases {
		got := BuildDownloadFileObservation(c.cd, c.ct, c.size)
		if got == nil || *got != *c.want {
			t.Fatalf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

// 超长文件名回归（HIGH-6）：挂点侧响应头快照按 256 字节截断值，超长 Content-Disposition
// 经快照解析必然失败、观测整体缺失；观测改由原始头值提取后，扩展名按未截断完整名提取
// （先截断会把后缀截掉，EXT 规则与双扩展名信号被绕过），FileName 截断 128 仅供证据落库。
func TestBuildDownloadFileObservation_LongFileName(t *testing.T) {
	long := strings.Repeat("A", 300) + ".exe"
	// 构造原始头值（长度远超快照 256 字节截断线；快照口径下本头解析必然失败）
	cd := `attachment; filename="` + long + `"`
	if len(cd) <= 256 {
		t.Fatalf("test header must exceed snapshot truncation: %d", len(cd))
	}
	got := BuildDownloadFileObservation(cd, "application/octet-stream", 100)
	if got == nil {
		t.Fatal("long filename from raw header must yield observation")
	}
	if got.Extension != "exe" {
		t.Fatalf("extension must be extracted from untruncated name, got %q", got.Extension)
	}
	if got.MatchName != long {
		t.Fatalf("MatchName must keep full name for rule matching, got len=%d", len(got.MatchName))
	}
	if n := len([]rune(got.FileName)); n != dsctx.MaxFileNameLen {
		t.Fatalf("FileName must be truncated to %d runes for evidence, got %d", dsctx.MaxFileNameLen, n)
	}
	if strings.HasSuffix(got.FileName, ".exe") {
		t.Fatalf("truncated evidence name unexpectedly retains suffix: %q", got.FileName)
	}
}

// 零产出口径：无 Content-Disposition / 无 filename / 非下载语义 / 畸形头。
func TestBuildDownloadFileObservation_None(t *testing.T) {
	noneCases := []struct{ cd, ct string }{
		{"", ""},
		{"", "application/json"},
		{"attachment", "application/octet-stream"},                       // 无 filename
		{"attachment; filename=", "application/octet-stream"},            // 空 filename
		{`form-data; name="f"; filename="a.txt"`, "multipart/form-data"}, // 非下载语义
		{";;; garbage", "application/octet-stream"},                      // 畸形头
	}
	for i, c := range noneCases {
		if got := BuildDownloadFileObservation(c.cd, c.ct, 100); got != nil {
			t.Fatalf("case %d: want nil, got %+v", i, got)
		}
	}
}
