// apifilecomp_test.go 文件合规检测端到端（W13-GW / P2-03，任务书 §44 子集）：
// 上传 EXT BLOCK 规则 PROTECT 403 拦截（请求相位定案）、OBSERVE 仅记录；
// 下载 EXT/MIME 规则在响应相位评估——PROTECT 抑制已缓冲下载为 403（空明细 JSON，
// 原内容一字节不外发）、OBSERVE 直通仅记录；直通/溢出无法撤回的下载诚实降级
// （file.download_block_unavailable + final_action 按实回落 OBSERVE）；
// 证据只含文件名/扩展名/MIME/规则不落内容；无下发规则零行为。
package jiuzhang_guard

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// newFileComplianceTestGuard 构造注入文件合规规则的测试 Guard（编译规则集，绕过 Provision）。
func newFileComplianceTestGuard(t *testing.T, mode string, rules []detectors.FileComplianceRule) (*Guard, string) {
	t.Helper()
	g, logPath := newAPITestGuard(t, mode, nil)
	set, err := detectors.CompileFileComplianceRules(rules)
	if err != nil {
		t.Fatalf("compile compliance rules: %v", err)
	}
	g.apiFileCompliance = set
	return g, logPath
}

// fileCompUploadRequest 构造 multipart 文件上传请求（API 路径形态）。
func fileCompUploadRequest(id, filename, content string) *http.Request {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, _ := w.CreateFormFile("file", filename)
	_, _ = fw.Write([]byte(content))
	_ = w.Close()
	req := httptest.NewRequest(http.MethodPost, "http://shop.example.com/v1/files/upload", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer fc-e2e-token-0123456789abcdef")
	req.Header.Set("X-Request-Id", id)
	req.RemoteAddr = "203.0.113.9:5001"
	return req
}

// 上传 EXT BLOCK 规则：PROTECT 403 拦截（next 不执行）、事件 BLOCK + 违规明细；
// 证据只含文件名/扩展名/MIME/规则，不含文件内容。
func TestServeNext_FileComplianceUploadBlock(t *testing.T) {
	g, logPath := newFileComplianceTestGuard(t, "PROTECT", []detectors.FileComplianceRule{
		{Direction: "UPLOAD", Match: "EXT", Value: "exe", Action: "BLOCK", Reason: "可执行文件"},
	})

	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	err := g.serveNext(httptest.NewRecorder(), fileCompUploadRequest("req-fc-up-1", "evil.exe", "MZ-FAKE-CONTENT"), next)
	if err == nil {
		t.Fatal("expect block error")
	}
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 HandlerError, got %v", err)
	}
	if called {
		t.Fatal("next handler must not run when blocked")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 || recs[0].FinalAction != "BLOCK" {
		t.Fatalf("want 1 BLOCK event, got %+v", recs)
	}
	var found bool
	for _, d := range recs[0].Details {
		if d.RuleID != "file.compliance_violation" {
			continue
		}
		found = true
		if d.Category != "BLOCK" || d.Severity != "HIGH" {
			t.Fatalf("block detail discipline broken: %+v", d)
		}
		if d.Evidence["filename"] != "evil.exe" || d.Evidence["ext"] != "exe" ||
			d.Evidence["match"] != "EXT" || d.Evidence["direction"] != "UPLOAD" {
			t.Fatalf("evidence = %+v", d.Evidence)
		}
		for k, v := range d.Evidence {
			if strings.Contains(v, "MZ-FAKE-CONTENT") {
				t.Fatalf("evidence must not contain file content: %s=%s", k, v)
			}
		}
	}
	if !found {
		t.Fatalf("file.compliance_violation missing: %+v", recs[0].Details)
	}
}

// 上传 EXT BLOCK 规则 OBSERVE 模式：放行 + would-block 明细（OBSERVE/MEDIUM），不定案阻断。
func TestServeNext_FileComplianceUploadObserve(t *testing.T) {
	g, logPath := newFileComplianceTestGuard(t, "OBSERVE", []detectors.FileComplianceRule{
		{Direction: "UPLOAD", Match: "EXT", Value: "exe", Action: "BLOCK"},
	})

	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
		return nil
	})
	if err := g.serveNext(httptest.NewRecorder(), fileCompUploadRequest("req-fc-up-2", "evil.exe", "MZ"), next); err != nil {
		t.Fatalf("observe mode must not block: %v", err)
	}
	if !called {
		t.Fatal("next handler must run in observe mode")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 || recs[0].FinalAction == "BLOCK" {
		t.Fatalf("observe mode must not finalize BLOCK: %+v", recs)
	}
	var found bool
	for _, d := range recs[0].Details {
		if d.RuleID == "file.compliance_violation" && d.Category == "OBSERVE" && d.Severity == "MEDIUM" {
			found = true
		}
	}
	if !found {
		t.Fatalf("would-block detail missing: %+v", recs[0].Details)
	}
}

// 下载 EXT BLOCK 规则：PROTECT 抑制已缓冲下载为 403（空明细 JSON 体；原内容一字节不外发；
// Content-Disposition 清除）、事件 BLOCK + 违规明细 + 状态 403。
func TestServeNext_FileComplianceDownloadBlock(t *testing.T) {
	g, logPath := newFileComplianceTestGuard(t, "PROTECT", []detectors.FileComplianceRule{
		{Direction: "DOWNLOAD", Match: "EXT", Value: "exe", Action: "BLOCK", Reason: "可执行文件下载"},
	})

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="setup.exe"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "MZ-FAKE-CONTENT-ORIGINAL")
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-fc-dl-1"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	s := string(body)
	if strings.Contains(s, "MZ-FAKE-CONTENT-ORIGINAL") || !strings.Contains(s, "file_compliance_blocked") {
		t.Fatalf("suppressed body must not leak original content: %q", s)
	}
	if resp.Header.Get("Content-Disposition") != "" {
		t.Fatalf("suppressed response must not carry Content-Disposition: %v", resp.Header)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 || recs[0].FinalAction != "BLOCK" || recs[0].ResponseStatus != http.StatusForbidden {
		t.Fatalf("want 1 BLOCK/403 event, got %+v", recs)
	}
	var found bool
	for _, d := range recs[0].Details {
		if d.RuleID == "file.compliance_violation" && d.Category == "BLOCK" {
			found = true
		}
	}
	if !found {
		t.Fatalf("block detail missing: %+v", recs[0].Details)
	}
}

// 下载 MIME OBSERVE 规则：直通交付 + 违规明细恒记录（OBSERVE/LOW）。
func TestServeNext_FileComplianceDownloadObserve(t *testing.T) {
	g, logPath := newFileComplianceTestGuard(t, "PROTECT", []detectors.FileComplianceRule{
		{Direction: "DOWNLOAD", Match: "MIME", Value: "image/", Action: "OBSERVE", Reason: "图片外发审计"},
	})

	const payload = "FAKE-PNG-BYTES"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Disposition", `attachment; filename="chart.png"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-fc-dl-2"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != payload {
		t.Fatalf("OBSERVE rule must not suppress: %d %q", resp.StatusCode, body)
	}
	var found bool
	for _, d := range readAPIRecords(t, logPath)[0].Details {
		if d.RuleID == "file.compliance_violation" && d.Category == "OBSERVE" && d.Severity == "LOW" &&
			d.Evidence["mime"] == "image/png" && d.Evidence["match"] == "MIME" {
			found = true
		}
	}
	if !found {
		t.Fatalf("observe detail missing: %+v", readAPIRecords(t, logPath)[0].Details)
	}
}

// 下载 BLOCK 规则但响应溢出直通（超捕获上限 FAIL_OPEN）：无法撤回已外发字节——
// 诚实降级：原响应完整交付，补记 file.download_block_unavailable，final_action 按实回落 OBSERVE。
func TestServeNext_FileComplianceDownloadBlockSpillDegrade(t *testing.T) {
	g, logPath := newFileComplianceTestGuard(t, "PROTECT", []detectors.FileComplianceRule{
		{Direction: "DOWNLOAD", Match: "EXT", Value: "exe", Action: "BLOCK"},
	})
	g.APIResponseCaptureMaxBytes = 16 // 极小上限强制溢出直通

	payload := strings.Repeat("Z", 4096)
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="setup.exe"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-fc-dl-3"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != payload {
		t.Fatalf("spilled response must be delivered intact: %d len=%d", resp.StatusCode, len(body))
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	if recs[0].FinalAction == "BLOCK" {
		t.Fatalf("unenforced block must not be reported as BLOCK: %+v", recs[0])
	}
	var violation, unavailable bool
	for _, d := range recs[0].Details {
		switch d.RuleID {
		case "file.compliance_violation":
			violation = true
		case "file.download_block_unavailable":
			unavailable = true
			if d.Category != "OBSERVE" || d.Severity != "HIGH" {
				t.Fatalf("degrade detail discipline broken: %+v", d)
			}
		}
	}
	if !violation || !unavailable {
		t.Fatalf("violation=%v unavailable=%v: %+v", violation, unavailable, recs[0].Details)
	}
}

// 无下发规则：上传/下载均零行为（直通交付、无合规明细）。
func TestServeNext_FileComplianceZeroRules(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)

	const payload = "MZ-FAKE"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="setup.exe"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-fc-zero-1"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != payload {
		t.Fatalf("no rules must not touch body: %q", body)
	}
	for _, d := range readAPIRecords(t, logPath)[0].Details {
		if strings.HasPrefix(d.RuleID, "file.compliance") || d.RuleID == "file.double_extension" {
			t.Fatalf("no rules must be zero-behavior: %+v", d)
		}
	}
}
