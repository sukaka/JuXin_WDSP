package parser

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 上传观测提取：仅文件 part 产出、元数据齐全、表单字段与无名 part 跳过。
func TestBuildUploadFileObservations(t *testing.T) {
	parts := []PartMeta{
		{FieldName: "desc", FileName: "", ContentType: "", Size: 12},                                       // 表单字段
		{FieldName: "file", FileName: `C:\fakepath\Report.PDF`, ContentType: "Application/PDF", Size: 100}, // 文件
		{FieldName: "file2", FileName: "data.csv", ContentType: "text/csv; charset=utf-8", Size: 0},        // 空文件
		{FieldName: "odd", FileName: "/", ContentType: "application/octet-stream", Size: 5},                // 归一化后无名
	}
	out := BuildUploadFileObservations(parts)
	if len(out) != 2 {
		t.Fatalf("obs count = %d, want 2 (%+v)", len(out), out)
	}
	first := out[0]
	if first.Direction != dsctx.FileDirectionUpload || first.FileName != "Report.PDF" ||
		first.Extension != "pdf" || first.MIME != "application/pdf" || first.Size != 100 {
		t.Fatalf("first obs = %+v", first)
	}
	second := out[1]
	if second.FileName != "data.csv" || second.Extension != "csv" || second.MIME != "text/csv" || second.Size != 0 {
		t.Fatalf("second obs = %+v", second)
	}
}

// 无文件 part / 空输入：零产出（nil，事件键省略）。
func TestBuildUploadFileObservations_None(t *testing.T) {
	if out := BuildUploadFileObservations(nil); out != nil {
		t.Fatalf("nil parts must yield nil, got %+v", out)
	}
	out := BuildUploadFileObservations([]PartMeta{{FieldName: "a", FileName: "", Size: 3}})
	if out != nil {
		t.Fatalf("form-only parts must yield nil, got %+v", out)
	}
}

// 超长文件名回归（HIGH-6）：FileName 截断 128 仅供证据/落库（资产键不超列宽），
// 扩展名与规则匹配口径（MatchName）必须基于未截断完整名——先截断会把后缀截掉
// （A×200.exe 扩展名丢失），EXT 规则与双扩展名信号被静默绕过。
func TestBuildUploadFileObservations_Truncation(t *testing.T) {
	name := strings.Repeat("x", 200) + ".txt"
	out := BuildUploadFileObservations([]PartMeta{{FileName: name, Size: 1}})
	if len(out) != 1 || len([]rune(out[0].FileName)) != dsctx.MaxFileNameLen {
		t.Fatalf("truncated obs = %+v", out)
	}
	if out[0].Extension != "txt" {
		t.Fatalf("extension must be extracted from untruncated name, got %q", out[0].Extension)
	}
	if out[0].MatchName != name {
		t.Fatalf("MatchName must keep full name for rule matching, got len=%d", len(out[0].MatchName))
	}
	// 未触截断时扩展名正常提取
	keep := strings.Repeat("x", 120) + ".TXT"
	out = BuildUploadFileObservations([]PartMeta{{FileName: keep, Size: 1}})
	if len(out) != 1 || out[0].Extension != "txt" || out[0].FileName != keep {
		t.Fatalf("untruncated obs = %+v", out)
	}
}
