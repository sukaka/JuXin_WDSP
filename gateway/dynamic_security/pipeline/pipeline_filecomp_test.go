// pipeline_filecomp_test.go 文件合规检测管线贯通（W13-GW / P2-03）：
// 上传方向在请求相位（multipart 观测点）评估——BLOCK 动作 PROTECT 定案 BLOCK（挂点侧映射 403）；
// 下载方向在响应相位（Content-Disposition 观测点）评估——PROTECT 定案 BLOCK（挂点侧抑制 403）；
// OBSERVE 模式恒记录不定案；无下发规则零行为。
package pipeline

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// fileCompUploadReq 构造 multipart 文件上传请求。
func fileCompUploadReq(t *testing.T, filename, content string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest(http.MethodPost, "http://h/v1/files/upload", &buf)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", w.FormDataContentType())
	r.Header.Set("X-Request-Id", "pipe-filecomp-"+filename)
	return r
}

func fileCompRules(t *testing.T, rules []detectors.FileComplianceRule) *detectors.FileComplianceRuleSet {
	t.Helper()
	set, err := detectors.CompileFileComplianceRules(rules)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return set
}

// 上传 EXT BLOCK 规则：PROTECT 定案 BLOCK（上传 403 由挂点侧按决策映射）；OBSERVE 仅记录。
func TestProcessFileComplianceUpload(t *testing.T) {
	rules := fileCompRules(t, []detectors.FileComplianceRule{
		{Direction: "UPLOAD", Match: "EXT", Value: "exe", Action: "BLOCK", Reason: "可执行文件"},
	})
	// PROTECT：BLOCK 类定案
	res, err := Process(fileCompUploadReq(t, "evil.exe", "MZ-fake"), Config{
		Enabled: true, Mode: "PROTECT", FileComplianceRules: rules,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "file.compliance_violation") {
		t.Fatalf("expected file.compliance_violation, got %+v", res.Context.CopyMatches())
	}
	if res.FinalAction != dsctx.ActionBlock {
		t.Fatalf("final=%s, want BLOCK", res.FinalAction)
	}
	// OBSERVE：同一规则不定案阻断
	res, err = Process(fileCompUploadReq(t, "evil.exe", "MZ-fake"), Config{
		Enabled: true, Mode: "OBSERVE", FileComplianceRules: rules,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "file.compliance_violation") || res.FinalAction == dsctx.ActionBlock {
		t.Fatalf("observe mode must not block: final=%s", res.FinalAction)
	}
	// 双扩展名上传：.pdf.exe 末段 exe 命中并产双扩展名信号
	res, err = Process(fileCompUploadReq(t, "invoice.pdf.exe", "MZ-fake"), Config{
		Enabled: true, Mode: "PROTECT", FileComplianceRules: rules,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "file.double_extension") || res.FinalAction != dsctx.ActionBlock {
		t.Fatalf("double extension upload: final=%s matches=%+v", res.FinalAction, res.Context.CopyMatches())
	}
	// 合法文件：零命中
	res, err = Process(fileCompUploadReq(t, "notes.txt", "hello"), Config{
		Enabled: true, Mode: "PROTECT", FileComplianceRules: rules,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(res, "file.compliance_violation") {
		t.Fatalf("txt upload must not hit exe rule: %+v", res.Context.CopyMatches())
	}
	// 无下发规则：零行为
	res, err = Process(fileCompUploadReq(t, "evil.exe", "MZ-fake"), Config{
		Enabled: true, Mode: "PROTECT",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(res, "file.compliance_violation") {
		t.Fatal("no rules must be zero-behavior")
	}
}

// 下载 FILENAME_REGEX BLOCK 规则：响应相位评估——PROTECT 定案 BLOCK（挂点侧抑制 403）；
// OBSERVE 仅记录；无下载观测零行为。
func TestProcessResponseFileComplianceDownload(t *testing.T) {
	rules := fileCompRules(t, []detectors.FileComplianceRule{
		{Direction: "DOWNLOAD", Match: "FILENAME_REGEX", Value: `(?i)\.(exe|scr)$`, Action: "BLOCK", Reason: "可执行文件下载"},
		{Direction: "UPLOAD", Match: "EXT", Value: "exe", Action: "BLOCK"}, // 方向过滤：不评估下载
	})
	downloadHeaders := map[string]string{
		"content-disposition": `attachment; filename="setup.scr"`,
		"content-type":        "application/octet-stream",
	}
	// PROTECT：BLOCK 类定案
	ctx := dsctx.New("resp-filecomp-1", dsctx.DefaultParseLimits())
	act, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, Headers: downloadHeaders, ContentType: "application/octet-stream",
		Body: []byte("MZ-fake"), BodySize: 7,
	}, ResponseConfig{Mode: "PROTECT", FileComplianceRules: rules})
	if err != nil {
		t.Fatal(err)
	}
	if act != dsctx.ActionBlock {
		t.Fatalf("action=%s, want BLOCK", act)
	}
	if !hasRule(&Result{Context: ctx}, "file.compliance_violation") {
		t.Fatalf("expected file.compliance_violation, got %+v", ctx.CopyMatches())
	}
	// OBSERVE：恒记录不定案阻断
	ctx2 := dsctx.New("resp-filecomp-2", dsctx.DefaultParseLimits())
	act, err = ProcessResponse(ctx2, ResponseInput{
		Status: 200, Headers: downloadHeaders, ContentType: "application/octet-stream",
		Body: []byte("MZ-fake"), BodySize: 7,
	}, ResponseConfig{Mode: "OBSERVE", FileComplianceRules: rules})
	if err != nil {
		t.Fatal(err)
	}
	if act == dsctx.ActionBlock {
		t.Fatalf("observe mode must not block: %s", act)
	}
	if !hasRule(&Result{Context: ctx2}, "file.compliance_violation") {
		t.Fatalf("observe mode must still record: %+v", ctx2.CopyMatches())
	}
	// 无下载观测（普通 JSON 响应）：零行为
	ctx3 := dsctx.New("resp-filecomp-3", dsctx.DefaultParseLimits())
	act, err = ProcessResponse(ctx3, ResponseInput{
		Status: 200, ContentType: "application/json", Body: []byte(`{"ok":true}`), BodySize: 11,
	}, ResponseConfig{Mode: "PROTECT", FileComplianceRules: rules})
	if err != nil {
		t.Fatal(err)
	}
	if act == dsctx.ActionBlock || hasRule(&Result{Context: ctx3}, "file.compliance_violation") {
		t.Fatalf("non-download response must be zero-behavior: %s %+v", act, ctx3.CopyMatches())
	}
}
