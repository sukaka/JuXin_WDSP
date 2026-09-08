package jiuzhang_guard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"go.uber.org/zap"
)

// newAPIResponseTestGuard 构造启用响应侧能力的测试 Guard（编译脱敏规则，绕过 Provision）。
func newAPIResponseTestGuard(t *testing.T, mode string, rules []maskRuleJSON) (*Guard, string) {
	t.Helper()
	g, logPath := newAPITestGuard(t, mode, nil)
	compiled, err := compileAPIMaskRules(rules)
	if err != nil {
		t.Fatalf("compile mask rules: %v", err)
	}
	g.apiMaskRules = compiled
	return g, logPath
}

// MASK_RESPONSE 端到端：PROTECT + 命中规则 → 响应体真实改写、Content-Length 修正、事件含新字段。
func TestServeNext_MaskResponseProtect(t *testing.T) {
	g, logPath := newAPIResponseTestGuard(t, "PROTECT", []maskRuleJSON{
		{EndpointKey: "POST /v1/users", FieldPath: "users[].phone", DataType: "phone", Algorithm: "MASK"},
		{EndpointKey: "POST /v1/users", FieldPath: "token", DataType: "credential", Algorithm: "REMOVE"},
	})
	g.APIPolicyVersion = "pv-20260816"
	g.APIFormalModelVersions = map[string]string{"POST /v1/users": "mv-7"}

	upstreamBody := `{"users":[{"phone":"13800138000","name":"a"},{"phone":"13900139000","name":"b"}],"token":"secret-token","ok":true}`
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, upstreamBody)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/users?page=2", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-mask-1")
	req.RemoteAddr = "203.0.113.9:5001"
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)

	// 响应体真实改写：phone 掩码、token 删除、无关字段不动
	if strings.Contains(string(body), "13800138000") || strings.Contains(string(body), "secret-token") {
		t.Fatalf("plaintext leaked: %s", body)
	}
	if !strings.Contains(string(body), "138****8000") || !strings.Contains(string(body), "139****9000") {
		t.Fatalf("masked phones missing: %s", body)
	}
	if !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("unrelated field changed: %s", body)
	}
	// Content-Length 修正为改写后长度；失效 ETag 清除
	if resp.Header.Get("ETag") != "" {
		t.Fatalf("stale ETag must be removed after mask: %v", resp.Header)
	}
	if cl := resp.Header.Get("Content-Length"); cl != strconv.Itoa(len(body)) {
		t.Fatalf("content-length = %q, want %d (masked body)", cl, len(body))
	}

	// 事件：响应完成后输出，真实状态码 + 新字段 + 响应侧明细
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d: %+v", len(recs), recs)
	}
	ev := recs[0]
	if ev.FinalAction != "MASK_RESPONSE" {
		t.Fatalf("final_action = %q", ev.FinalAction)
	}
	if ev.ResponseStatus != http.StatusOK {
		t.Fatalf("response_status = %d", ev.ResponseStatus)
	}
	if ev.PolicyVersion != "pv-20260816" || ev.ModelVersion != "mv-7" {
		t.Fatalf("versions: policy=%q model=%q", ev.PolicyVersion, ev.ModelVersion)
	}
	if ev.RawPath != "/v1/users" {
		t.Fatalf("raw_path must strip query: %q", ev.RawPath)
	}
	if ev.ClientIP != "203.0.113.9" {
		t.Fatalf("client_ip = %q", ev.ClientIP)
	}
	var planFound, appliedFound bool
	for _, d := range ev.Details {
		switch d.RuleID {
		case "response.mask_plan":
			planFound = true
		case "response.mask_applied":
			appliedFound = true
			if d.Evidence["applied_fields"] != "3" {
				t.Fatalf("applied_fields = %q (2 phones + 1 token)", d.Evidence["applied_fields"])
			}
		}
		for _, v := range d.Evidence {
			if strings.Contains(v, "13800138000") || strings.Contains(v, "secret-token") {
				t.Fatalf("evidence must not contain values: %+v", d.Evidence)
			}
		}
	}
	if !planFound || !appliedFound {
		t.Fatalf("mask details missing: %+v", ev.Details)
	}
}

// OBSERVE 模式：计划仅记录，响应体不改写。
func TestServeNext_MaskResponseObserveOnly(t *testing.T) {
	g, logPath := newAPIResponseTestGuard(t, "OBSERVE", []maskRuleJSON{
		{EndpointKey: "POST /v1/users", FieldPath: "phone", DataType: "phone", Algorithm: "MASK"},
	})
	upstreamBody := `{"phone":"13800138000"}`
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, upstreamBody)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != upstreamBody {
		t.Fatalf("OBSERVE must not modify body: %s", body)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	if recs[0].FinalAction != "OBSERVE" {
		t.Fatalf("final_action = %q", recs[0].FinalAction)
	}
	found := false
	for _, d := range recs[0].Details {
		if d.RuleID == "response.mask_plan" {
			found = true
		}
	}
	if !found {
		t.Fatalf("mask_plan detail missing: %+v", recs[0].Details)
	}
}

// gzip 编码 + FAIL_OPEN：无法安全重编码，原响应直通不改写。
func TestServeNext_MaskSkippedNonIdentityEncoding(t *testing.T) {
	g, logPath := newAPIResponseTestGuard(t, "PROTECT", []maskRuleJSON{
		{EndpointKey: "POST /v1/users", FieldPath: "phone", Algorithm: "MASK"},
	})
	compressed := []byte{0x1f, 0x8b, 0x08, 0x00, 0x01, 0x02} // 伪造 gzip 字节流（直通不解析）
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(compressed)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if len(body) != len(compressed) {
		t.Fatalf("encoded body must pass through intact: %d vs %d", len(body), len(compressed))
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	if recs[0].FinalAction == "MASK_RESPONSE" {
		t.Fatal("non-identity encoding must not mask")
	}
	if recs[0].ResponseStatus != http.StatusOK {
		t.Fatalf("response_status = %d", recs[0].ResponseStatus)
	}
}

// Range 分段响应（206 + Content-Range）命中脱敏规则：与水印/签名同一口径跳过改写
// （分段体经字段级改写会破坏断点续传重组），原体直通、Content-Range 保留，
// 补记 response.mask_skipped 明细（不静默）。
func TestServeNext_MaskSkippedPartialContent(t *testing.T) {
	g, logPath := newAPIResponseTestGuard(t, "PROTECT", []maskRuleJSON{
		{EndpointKey: "POST /v1/users", FieldPath: "phone", Algorithm: "MASK"},
	})
	upstreamBody := `{"phone":"13800138000"}`
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Range", "bytes 0-22/100")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, upstreamBody)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusPartialContent || string(body) != upstreamBody {
		t.Fatalf("partial content must pass through unmodified: status=%d body=%q", resp.StatusCode, body)
	}
	if cr := resp.Header.Get("Content-Range"); cr != "bytes 0-22/100" {
		t.Fatalf("Content-Range must be preserved on skip: %q", cr)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	skipped := false
	for _, d := range recs[0].Details {
		switch d.RuleID {
		case "response.mask_applied":
			t.Fatal("partial content must not be masked")
		case "response.mask_skipped":
			skipped = true
		}
	}
	if !skipped {
		t.Fatalf("mask_skipped detail missing: %+v", recs[0].Details)
	}
}

// writeBufferedResponse 头部修正口径：改写后清除失效校验头（ETag/Content-MD5/Content-Range）并
// 按新体修正 Content-Length；未改写的 206 分段保留 Content-Range 并按缓冲长度补 Content-Length；
// 声明 Trailer（公告头或 TrailerPrefix 键）的响应不强制 Content-Length——net/http 仅在
// 分块编码下外发 Trailer，强制长度会让 Trailer 值静默丢失（语义漂移）。
func TestWriteBufferedResponseHeaders(t *testing.T) {
	g := &Guard{logger: zap.NewNop()}
	newCapture := func(rec *httptest.ResponseRecorder, status int) *apiResponseCapture {
		return &apiResponseCapture{base: rec, status: status, mode: captureBuffered, logger: zap.NewNop()}
	}

	// 改写后：ETag/Content-MD5/Content-Range 一并清除，Content-Length 按新体修正
	rec := httptest.NewRecorder()
	rec.Header().Set("ETag", `"v1"`)
	rec.Header().Set("Content-MD5", "1B2M2Y8AsgTpgAmY7PhCfg==")
	rec.Header().Set("Content-Range", "bytes 0-3/10")
	g.writeBufferedResponse(rec, newCapture(rec, http.StatusOK), []byte("new-body"), true)
	resp := rec.Result()
	if resp.Header.Get("ETag") != "" || resp.Header.Get("Content-MD5") != "" || resp.Header.Get("Content-Range") != "" {
		t.Fatalf("stale validators must be removed after rewrite: %v", resp.Header)
	}
	if cl := resp.Header.Get("Content-Length"); cl != "8" {
		t.Fatalf("content-length = %q, want 8 (rewritten body)", cl)
	}

	// 未改写的 206 分段：Content-Range 保留，Content-Length 按缓冲长度补齐
	rec2 := httptest.NewRecorder()
	rec2.Header().Set("Content-Range", "bytes 0-3/10")
	g.writeBufferedResponse(rec2, newCapture(rec2, http.StatusPartialContent), []byte("abcd"), false)
	resp2 := rec2.Result()
	if cr := resp2.Header.Get("Content-Range"); cr != "bytes 0-3/10" {
		t.Fatalf("unmodified partial response must keep Content-Range: %q", cr)
	}
	if cl := resp2.Header.Get("Content-Length"); cl != "4" {
		t.Fatalf("content-length = %q, want 4", cl)
	}

	// Trailer 公告头：不强制 Content-Length（处理器已设置的也移除），公告保留
	rec3 := httptest.NewRecorder()
	rec3.Header().Set("Trailer", "X-Checksum")
	rec3.Header().Set("Content-Length", "4")
	g.writeBufferedResponse(rec3, newCapture(rec3, http.StatusOK), []byte("abcd"), false)
	resp3 := rec3.Result()
	if cl := resp3.Header.Get("Content-Length"); cl != "" {
		t.Fatalf("trailered response must not force content-length, got %q", cl)
	}
	if tr := resp3.Header.Get("Trailer"); tr != "X-Checksum" {
		t.Fatalf("trailer announcement must be preserved: %q", tr)
	}

	// TrailerPrefix 键同样视为声明 Trailer
	rec4 := httptest.NewRecorder()
	rec4.Header().Set(http.TrailerPrefix+"X-Checksum", "abc123")
	g.writeBufferedResponse(rec4, newCapture(rec4, http.StatusOK), []byte("abcd"), false)
	if cl := rec4.Result().Header.Get("Content-Length"); cl != "" {
		t.Fatalf("trailer-prefix response must not force content-length, got %q", cl)
	}
}

// FAIL_CLOSED + 端点有规则 + 非 identity 编码：原响应被抑制，客户端收到 500 空明细体。
func TestServeNext_FailClosedSuppressesUnprocessable(t *testing.T) {
	g, logPath := newAPIResponseTestGuard(t, "PROTECT", []maskRuleJSON{
		{EndpointKey: "POST /v1/users", FieldPath: "phone", Algorithm: "MASK"},
	})
	g.APIResponseFailPolicy = "FAIL_CLOSED"
	secret := []byte{0x1f, 0x8b, 0x08, 0x99}
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(secret)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-fc-1")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
	if strings.Contains(string(body), "\x1f\x8b") {
		t.Fatalf("original body must not leak: %v", body)
	}
	if !strings.Contains(string(body), "response_processing_failed") || !strings.Contains(string(body), "req-fc-1") {
		t.Fatalf("fail-closed body: %s", body)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	if recs[0].ResponseStatus != http.StatusInternalServerError {
		t.Fatalf("event status = %d", recs[0].ResponseStatus)
	}
	found := false
	for _, d := range recs[0].Details {
		if d.RuleID == "response.fail_closed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("fail_closed detail missing: %+v", recs[0].Details)
	}
}

// 超限响应：FAIL_OPEN 溢出直通（原响应完整外发，不截断）；FAIL_CLOSED 抑制。
func TestServeNext_OversizedBodyPolicies(t *testing.T) {
	big := strings.Repeat("x", 4096)
	mkReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(`{"name":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		return req
	}
	// FAIL_OPEN：完整外发
	g, _ := newAPIResponseTestGuard(t, "PROTECT", []maskRuleJSON{
		{EndpointKey: "POST /v1/users", FieldPath: "phone", Algorithm: "MASK"},
	})
	g.APIResponseCaptureMaxBytes = 1024
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"phone":"13800138000","pad":"`+big+`"}`)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, mkReq(), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if len(body) != len(`{"phone":"13800138000","pad":"`+big+`"}`) {
		t.Fatalf("fail-open spill must deliver full body: %d", len(body))
	}
	if !strings.Contains(string(body), "13800138000") {
		t.Fatal("fail-open spill delivers original (unmasked) body")
	}

	// FAIL_CLOSED：抑制为 500
	g2, logPath2 := newAPIResponseTestGuard(t, "PROTECT", []maskRuleJSON{
		{EndpointKey: "POST /v1/users", FieldPath: "phone", Algorithm: "MASK"},
	})
	g2.APIResponseFailPolicy = "FAIL_CLOSED"
	g2.APIResponseCaptureMaxBytes = 1024
	rec2 := httptest.NewRecorder()
	if err := g2.serveNext(rec2, mkReq(), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	resp2 := rec2.Result()
	if resp2.StatusCode != http.StatusInternalServerError {
		t.Fatalf("fail-closed oversized status = %d", resp2.StatusCode)
	}
	body2, _ := io.ReadAll(resp2.Body)
	if strings.Contains(string(body2), "13800138000") {
		t.Fatal("fail-closed must not leak original body")
	}
	recs := readAPIRecords(t, logPath2)
	if len(recs) != 1 || recs[0].ResponseStatus != http.StatusInternalServerError {
		t.Fatalf("fail-closed event: %+v", recs)
	}
}

// 溢出（spill）响应的 BodySize 口径：已缓冲前缀经 bytesStreamed 外发记账，
// 不再被 body.Len() 双重计入（code-review LOW-G10）——下载观测 Size 等于实际外发字节数。
func TestServeNext_SpillBodySizeNoDoubleCount(t *testing.T) {
	g, logPath := newAPIResponseTestGuard(t, "PROTECT", nil)
	g.APIResponseCaptureMaxBytes = 1024
	full := `{"pad":"` + strings.Repeat("x", 4096) + `"}`
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("Content-Disposition", `attachment; filename="big.json"`)
		_, _ = io.WriteString(w, full)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if len(body) != len(full) {
		t.Fatalf("spill must deliver full body: %d, want %d", len(body), len(full))
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	if len(recs[0].FileObservations) != 1 {
		t.Fatalf("want 1 download file observation, got %+v", recs[0].FileObservations)
	}
	if got := recs[0].FileObservations[0].Size; got != int64(len(full)) {
		t.Fatalf("spilled body size = %d, want %d (buffered prefix double-counted?)", got, len(full))
	}
}

// 非 JSON 响应（text/plain）：直通不改写，事件仍携真实状态码与耗时。
func TestServeNext_NonJSONResponsePassthrough(t *testing.T) {
	g, logPath := newAPIResponseTestGuard(t, "PROTECT", []maskRuleJSON{
		{EndpointKey: "POST /v1/users", FieldPath: "phone", Algorithm: "MASK"},
	})
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		time.Sleep(2 * time.Millisecond) // 保证 latency_ms > 0
		_, _ = io.WriteString(w, "phone=13800138000")
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated || string(body) != "phone=13800138000" {
		t.Fatalf("passthrough changed: %d %s", resp.StatusCode, body)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	if recs[0].ResponseStatus != http.StatusCreated {
		t.Fatalf("response_status = %d", recs[0].ResponseStatus)
	}
	if recs[0].LatencyMS <= 0 {
		t.Fatalf("latency_ms must be positive, got %d", recs[0].LatencyMS)
	}
}

// 响应错误签名：上游 500 + 堆栈特征 → 事件含 response.error_signature 明细。
func TestServeNext_ResponseErrorSignature(t *testing.T) {
	g, logPath := newAPIResponseTestGuard(t, "PROTECT", nil)
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"panic: runtime error"}`)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if rec.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("status must pass through: %d", rec.Result().StatusCode)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	if recs[0].ResponseStatus != http.StatusInternalServerError {
		t.Fatalf("response_status = %d", recs[0].ResponseStatus)
	}
	found := false
	for _, d := range recs[0].Details {
		if d.RuleID == "response.error_signature" {
			found = true
			if !strings.Contains(d.Evidence["signatures"], "http_5xx") {
				t.Fatalf("signatures evidence: %+v", d.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("error_signature detail missing: %+v", recs[0].Details)
	}
}

// 下游返回错误：事件仍尽力输出（状态码 0 = 未采集），错误原样上抛。
func TestServeNext_DownstreamErrorStillEmits(t *testing.T) {
	g, logPath := newAPIResponseTestGuard(t, "PROTECT", nil)
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyHTTPTestError{status: http.StatusBadGateway}
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	err := g.serveNext(httptest.NewRecorder(), req, next)
	if err == nil {
		t.Fatal("downstream error must propagate")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event even on downstream error, got %d", len(recs))
	}
	if recs[0].ResponseStatus != 0 {
		t.Fatalf("status must be 0 (not captured) on downstream error, got %d", recs[0].ResponseStatus)
	}
}

// caddyHTTPTestError 测试用下游错误（实现 error，带状态码）。
type caddyHTTPTestError struct{ status int }

func (e caddyHTTPTestError) Error() string { return "downstream error" }

// Validate 校验响应侧新配置键（失败策略/捕获上限/规则/版本戳/模型版本）。
func TestValidate_APIResponseConfig(t *testing.T) {
	base := func() *Guard { return &Guard{EventsLog: "x", APIDynamicProtection: true} }

	// 失败策略：缺省/FAIL_OPEN/FAIL_CLOSED 合法，其余拒绝
	for _, v := range []string{"", "FAIL_OPEN", "FAIL_CLOSED"} {
		g := base()
		g.APIResponseFailPolicy = v
		if err := g.Validate(); err != nil {
			t.Fatalf("api_response_fail_policy=%q must be valid: %v", v, err)
		}
	}
	g := base()
	g.APIResponseFailPolicy = "IGNORE"
	if err := g.Validate(); err == nil {
		t.Fatal("bad fail policy must be rejected")
	}

	// 捕获上限：0=默认合法；负数与超硬上限拒绝
	g = base()
	g.APIResponseCaptureMaxBytes = -1
	if err := g.Validate(); err == nil {
		t.Fatal("negative capture max must be rejected")
	}
	g = base()
	g.APIResponseCaptureMaxBytes = maxAPIResponseCaptureMaxBytes + 1
	if err := g.Validate(); err == nil {
		t.Fatal("oversized capture max must be rejected")
	}
	g = base()
	g.APIResponseCaptureMaxBytes = 1 << 20
	if err := g.Validate(); err != nil {
		t.Fatalf("1MiB capture max must be valid: %v", err)
	}

	// 脱敏规则：合法通过；坏算法/坏路径/坏参数/超量拒绝
	g = base()
	g.APIMaskRules = []maskRuleJSON{
		{EndpointKey: "GET /v1/users", FieldPath: "users[].phone", DataType: "phone", Algorithm: "MASK",
			Params: map[string]any{"keep_head": float64(2), "keep_tail": float64(4)}},
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("valid mask rule must pass: %v", err)
	}
	g = base()
	g.APIMaskRules = []maskRuleJSON{{EndpointKey: "GET /v1/users", FieldPath: "phone", Algorithm: "ENCRYPT"}}
	if err := g.Validate(); err == nil {
		t.Fatal("bad algorithm must be rejected")
	}
	g = base()
	g.APIMaskRules = []maskRuleJSON{{EndpointKey: "GET /v1/users", FieldPath: "a..b", Algorithm: "MASK"}}
	if err := g.Validate(); err == nil {
		t.Fatal("bad field_path must be rejected")
	}
	g = base()
	g.APIMaskRules = []maskRuleJSON{{EndpointKey: "GET /v1/users", FieldPath: "phone", Algorithm: "MASK",
		Params: map[string]any{"keep_head": float64(-1)}}}
	if err := g.Validate(); err == nil {
		t.Fatal("negative keep_head must be rejected")
	}
	g = base()
	for i := 0; i < 513; i++ {
		g.APIMaskRules = append(g.APIMaskRules, maskRuleJSON{EndpointKey: "GET /v1/x", FieldPath: "a", Algorithm: "HASH"})
	}
	if err := g.Validate(); err == nil {
		t.Fatal("too many rules must be rejected")
	}

	// 版本戳/模型版本：超长或空版本拒绝
	g = base()
	g.APIPolicyVersion = strings.Repeat("v", 129)
	if err := g.Validate(); err == nil {
		t.Fatal("oversized policy version must be rejected")
	}
	g = base()
	g.APIFormalModelVersions = map[string]string{"GET /v1/users": ""}
	if err := g.Validate(); err == nil {
		t.Fatal("empty model version must be rejected")
	}
	g = base()
	g.APIFormalModelVersions = map[string]string{"GET /v1/users": "mv-1"}
	if err := g.Validate(); err != nil {
		t.Fatalf("valid model versions must pass: %v", err)
	}

	// 未启用 API 动态防护：新键不校验（零行为变化，与 api_protection_mode 一致）
	g = &Guard{EventsLog: "x"}
	g.APIResponseFailPolicy = "IGNORE"
	g.APIMaskRules = []maskRuleJSON{{EndpointKey: "", FieldPath: "", Algorithm: "ENCRYPT"}}
	if err := g.Validate(); err != nil {
		t.Fatalf("disabled protection must skip response config validation: %v", err)
	}
}

// 值级敏感规则配置校验：合法通过；坏正则/空字段/超长/超量拒绝（未启用防护时不校验，零行为变化）。
func TestGuardValidateSensitiveValueRules(t *testing.T) {
	base := func() *Guard { return &Guard{EventsLog: "x", APIDynamicProtection: true} }

	g := base()
	g.APISensitiveValueRules = []detectors.SensitiveValueRule{
		{DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"query", "json"}, Level: "SENSITIVE"},
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("valid sensitive value rule must pass: %v", err)
	}
	g = base()
	g.APISensitiveValueRules = []detectors.SensitiveValueRule{{DataType: "phone", Regex: "([bad", Locations: []string{"query"}}}
	if err := g.Validate(); err == nil {
		t.Fatal("bad regex must be rejected")
	}
	g = base()
	g.APISensitiveValueRules = []detectors.SensitiveValueRule{{DataType: "", Regex: "x", Locations: []string{"query"}}}
	if err := g.Validate(); err == nil {
		t.Fatal("empty data_type must be rejected")
	}
	g = base()
	for i := 0; i < 257; i++ {
		g.APISensitiveValueRules = append(g.APISensitiveValueRules,
			detectors.SensitiveValueRule{DataType: "t", Regex: "x", Locations: []string{"query"}})
	}
	if err := g.Validate(); err == nil {
		t.Fatal("too many rules must be rejected")
	}

	// 未启用 API 动态防护：新键不校验（零行为变化，与 api_mask_rules 一致）
	g = &Guard{EventsLog: "x"}
	g.APISensitiveValueRules = []detectors.SensitiveValueRule{{DataType: "phone", Regex: "([bad", Locations: []string{"query"}}}
	if err := g.Validate(); err != nil {
		t.Fatalf("disabled protection must skip sensitive value rule validation: %v", err)
	}
}
