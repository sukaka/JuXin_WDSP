// apifileobs_test.go 文件传输观测端到端（P1-04 文件资产）：
// multipart 上传提取 part 元数据观测（不落内容）、响应侧 Content-Disposition
// 下载观测（经响应捕获路径，流式直通同样计数）、无文件流量事件零变化。
package jiuzhang_guard

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"strings"
	"testing"
)

// multipartBody 构造两文件一字段的 multipart 体；返回体与 Content-Type。
// 文件内容含探针明文（断言绝不进事件日志）。
func multipartBody(t *testing.T, secret string) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	// 文件 part 1：自定义 Content-Type
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", `form-data; name="file"; filename="C:\fakepath\合同扫描.PDF"`)
	h.Set("Content-Type", "Application/PDF")
	pw, err := w.CreatePart(h)
	if err != nil {
		t.Fatalf("create part: %v", err)
	}
	if _, err := pw.Write([]byte(secret)); err != nil {
		t.Fatalf("write part: %v", err)
	}
	// 文件 part 2：CreateFormFile 默认 application/octet-stream
	fw, err := w.CreateFormFile("attach", "notes.csv")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write([]byte("a,b,c")); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	// 纯表单字段（无文件名，不产生观测）
	if err := w.WriteField("desc", "hello"); err != nil {
		t.Fatalf("write field: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return &buf, w.FormDataContentType()
}

// 上传观测：API 流量 multipart → file_observations 两条 UPLOAD（元数据齐全）；
// 文件内容不落事件（不落内存纪律的端到端断言）。
func TestServeNext_FileObservationUpload(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)

	const secret = "SECRET-UPLOAD-CONTENT-9f3a"
	body, ct := multipartBody(t, secret)
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/files/upload", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Request-Id", "req-file-up-1")
	req.RemoteAddr = "203.0.113.9:5001"
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}

	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	obs := recs[0].FileObservations
	if !recs[0].IsAPI {
		t.Fatalf("upload request must classify as API: %+v", recs[0])
	}
	if len(obs) != 2 {
		t.Fatalf("file_observations = %+v, want 2 upload entries", obs)
	}
	first, second := obs[0], obs[1]
	if first.Direction != "UPLOAD" || first.FileName != "合同扫描.PDF" ||
		first.Extension != "pdf" || first.MIME != "application/pdf" || first.Size != int64(len(secret)) {
		t.Fatalf("first upload obs = %+v", first)
	}
	if second.Direction != "UPLOAD" || second.FileName != "notes.csv" ||
		second.Extension != "csv" || second.MIME != "application/octet-stream" || second.Size != 5 {
		t.Fatalf("second upload obs = %+v", second)
	}
	// 不落内容：整条事件日志不含文件内容探针
	data, _ := os.ReadFile(logPath)
	if strings.Contains(string(data), secret) {
		t.Fatalf("event log must not contain file content: %s", data)
	}
}

// 下载观测：响应 Content-Disposition 携带 filename（非 JSON → 直通捕获路径），
// 事件挂一条 DOWNLOAD 观测（size = 实际传输字节数）；响应体不落事件。
func TestServeNext_FileObservationDownload(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)

	const payload = "FAKE-PDF-BINARY-SECRET-7d21"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="statement.pdf"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-file-dl-1")
	req.RemoteAddr = "203.0.113.9:5001"
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}

	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	obs := recs[0].FileObservations
	if len(obs) != 1 {
		t.Fatalf("file_observations = %+v, want 1 download entry", obs)
	}
	dl := obs[0]
	if dl.Direction != "DOWNLOAD" || dl.FileName != "statement.pdf" ||
		dl.Extension != "pdf" || dl.MIME != "application/pdf" || dl.Size != int64(len(payload)) {
		t.Fatalf("download obs = %+v", dl)
	}
	data, _ := os.ReadFile(logPath)
	if strings.Contains(string(data), payload) {
		t.Fatalf("event log must not contain response body: %s", data)
	}
}

// 下载观测（code-review HIGH-6 回归）：超长 Content-Disposition（>256 字节，超 Headers
// 快照单值截断上限）仍须产出 DOWNLOAD 观测——挂点侧须传原始头值（ResponseInput.
// ContentDisposition），走 256 字节截断快照回退会解析失败、观测静默缺失。
func TestServeNext_FileObservationDownloadLongDisposition(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)

	// 头值 >256 字节：截断快照截断后引号不闭合，mime.ParseMediaType 必失败
	longName := strings.Repeat("a", 300) + ".pdf"
	const payload = "FAKE-PDF-BINARY-SECRET-long-cd"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+longName+`"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.9:5001"
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}

	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	obs := recs[0].FileObservations
	if len(obs) != 1 {
		t.Fatalf("long Content-Disposition must still produce download observation: %+v", obs)
	}
	dl := obs[0]
	// FileName 落库口径截断 128（超长名的 .pdf 后缀被截掉）；扩展名/MIME/方向仍须正确
	if dl.Direction != "DOWNLOAD" || dl.Extension != "pdf" || dl.MIME != "application/pdf" ||
		dl.Size != int64(len(payload)) || len(dl.FileName) != 128 {
		t.Fatalf("download obs = %+v", dl)
	}
}

// 无文件流量：事件零变化——原始日志行不含 file_observations 键（omitempty 纪律）。
func TestServeNext_FileObservationZeroChange(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.9:5001"
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	if len(recs[0].FileObservations) != 0 {
		t.Fatalf("no-file traffic must carry no observations: %+v", recs[0].FileObservations)
	}
	data, _ := os.ReadFile(logPath)
	if strings.Contains(string(data), "file_observations") {
		t.Fatalf("event line must omit file_observations key when empty: %s", data)
	}
}

// 响应无 filename（普通 octet-stream 直通）：v1 不产出下载观测（精度优先口径）。
func TestServeNext_FileObservationDownloadNoFilename(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "raw-bytes")
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.9:5001"
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	if len(recs[0].FileObservations) != 0 {
		t.Fatalf("octet-stream without filename must not produce observation: %+v", recs[0].FileObservations)
	}
}
