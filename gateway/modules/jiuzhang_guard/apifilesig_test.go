// apifilesig_test.go 文件签名 v1 端到端（W13-GW / P2-02，任务书 §110 子集）：
// 文本/JSON 下载签名嵌入与 Content-Length 修正、token 按契约公式可复算
// （jzsig1.{kid}.{unixts}.{hmac_hex}，HMAC 覆盖最终交付内容）、与水印共存顺序
// （先水印后签名——签名盖水印产物）、file.signature_embedded INFO 明细
// （证据含 kid/filename，不含密钥与完整哈希）、未启用/非下载/超文本族零行为、
// JSON 解析失败 FAIL_OPEN 直通；OOXML ZIP 注释签名见 apifilesig_ooxml_test.go。
package jiuzhang_guard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
)

// sigE2EKeyHex 测试用签名密钥（32 字节 hex）。
var sigE2EKeyHex = hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

// newFileSignatureTestGuard 构造启用文件签名的测试 Guard（编译签名配置，绕过 Provision）。
func newFileSignatureTestGuard(t *testing.T, mode, kid string) (*Guard, string) {
	t.Helper()
	g, logPath := newAPITestGuard(t, mode, nil)
	cfg, err := response.NewFileSignatureConfig(true, kid, sigE2EKeyHex)
	if err != nil {
		t.Fatalf("new signature config: %v", err)
	}
	g.apiFileSignature = cfg
	return g, logPath
}

// extractSigToken 从签名后文本体提取末行 "# jzsig1..." token 与其前缀（被签名内容）。
func extractSigToken(t *testing.T, body string) (signedContent, token string) {
	t.Helper()
	i := strings.LastIndex(body, "\n# "+response.FileSignatureTokenPrefix+".")
	if i < 0 {
		t.Fatalf("signature line missing in body: %q", body)
	}
	return body[:i+1], strings.TrimPrefix(body[i+1:], "# ")
}

// recomputeSigToken 按契约公式独立复算 token 的 HMAC 段（模拟管理面验证侧）。
func recomputeSigToken(t *testing.T, kid, filename, signedContent, identityFP string, unixTS int64) string {
	t.Helper()
	sum := sha256.Sum256([]byte(signedContent))
	key, err := hex.DecodeString(sigE2EKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(kid + "|" + filename + "|" + hex.EncodeToString(sum[:]) + "|" +
		strconv.FormatInt(unixTS, 10) + "|" + identityFP))
	return hex.EncodeToString(mac.Sum(nil))
}

// 文本下载（text/csv）：文件尾追加 "# jzsig1.{kid}.{unixts}.{hmac}" 注释行；
// token 覆盖最终交付内容可复算；事件产 file.signature_embedded INFO 明细
// （证据含 kid/filename/mime，不含密钥、token 与完整内容哈希）。
func TestServeNext_FileSignatureTextDownload(t *testing.T) {
	g, logPath := newFileSignatureTestGuard(t, "OBSERVE", "k2026")

	const payload = "order,amount\nA1,100\n"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="orders.csv"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	req := wmDownloadRequest("req-sig-csv-1")
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)

	// 签名行追加在原始内容之后；token 分段格式
	signedContent, token := extractSigToken(t, string(body))
	if signedContent != payload {
		t.Fatalf("signed content must be original payload: %q", signedContent)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "jzsig1" || parts[1] != "k2026" || len(parts[3]) != 64 {
		t.Fatalf("token format = %q", token)
	}
	ts, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || ts <= 0 {
		t.Fatalf("bad unixts in token: %q", token)
	}
	// 可复算：身份指纹与挂点同一取值口径（仅凭据派生）
	want := recomputeSigToken(t, "k2026", "orders.csv", signedContent, detectors.CredentialKey(req, g.IdentitySalt), ts)
	if parts[3] != want {
		t.Fatalf("token hmac not recomputable: %q want %q", parts[3], want)
	}
	// Content-Length 修正为加签名后长度
	if cl := resp.Header.Get("Content-Length"); cl != strconv.Itoa(len(body)) {
		t.Fatalf("content-length = %q, want %d", cl, len(body))
	}

	// 事件：file.signature_embedded INFO 明细；证据含 kid/filename，不含密钥/token/完整哈希
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	var found bool
	for _, d := range recs[0].Details {
		if d.RuleID != "file.signature_embedded" {
			continue
		}
		found = true
		if d.Category != "INFO" || d.Severity != "INFO" {
			t.Fatalf("discipline broken: %s/%s", d.Category, d.Severity)
		}
		if d.Evidence["kid"] != "k2026" || d.Evidence["filename"] != "orders.csv" || d.Evidence["mime"] != "text/csv" {
			t.Fatalf("evidence = %+v", d.Evidence)
		}
		sum := sha256.Sum256([]byte(signedContent))
		for k, v := range d.Evidence {
			if strings.Contains(v, sigE2EKeyHex) || strings.Contains(v, token) || strings.Contains(v, hex.EncodeToString(sum[:])) {
				t.Fatalf("evidence must not contain key/token/full hash: %s=%s", k, v)
			}
		}
	}
	if !found {
		t.Fatalf("file.signature_embedded missing: %+v", recs[0].Details)
	}
}

// 与水印共存：先水印后签名——签名 token 的内容哈希覆盖水印产物（最终交付内容），
// 顺序可验证（水印行在前、签名行在尾）。
func TestServeNext_FileSignatureAfterWatermark(t *testing.T) {
	g, _ := newFileSignatureTestGuard(t, "OBSERVE", "k2026")
	wm, err := response.NewFileWatermarkConfig(true, "wm ip={ip}", nil, "")
	if err != nil {
		t.Fatalf("new watermark config: %v", err)
	}
	g.apiFileWatermark = wm

	const payload = "a,b\n1,2\n"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="orders.csv"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	req := wmDownloadRequest("req-sig-wm-1")
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	s := string(body)

	// 顺序：原内容 → 水印行 → 签名行（水印产物无尾换行，签名嵌入时补分隔换行）
	wmIdx := strings.Index(s, "# wm ip=203.0.113.9")
	_, token := extractSigToken(t, s)
	sigIdx := strings.Index(s, "# "+token)
	if wmIdx < 0 || sigIdx < 0 || wmIdx > sigIdx {
		t.Fatalf("watermark must precede signature: %q", s)
	}
	// 签名的内容快照 = 水印产物（原内容 + 水印行；原体含尾换行，水印行直接拼接无补换行）
	signedWant := payload + "# wm ip=203.0.113.9"
	if !strings.HasPrefix(s, signedWant) {
		t.Fatalf("signed content must be watermarked body: %q", s)
	}
	parts := strings.Split(token, ".")
	ts, _ := strconv.ParseInt(parts[2], 10, 64)
	want := recomputeSigToken(t, "k2026", "orders.csv", signedWant, detectors.CredentialKey(req, g.IdentitySalt), ts)
	if parts[3] != want {
		t.Fatalf("signature must cover watermarked content: %q want %q", parts[3], want)
	}
}

// JSON 下载：顶层加 "_sig" 字段；token 覆盖签名前捕获体（原始 JSON）可复算。
func TestServeNext_FileSignatureJSONDownload(t *testing.T) {
	g, _ := newFileSignatureTestGuard(t, "OBSERVE", "k2026")

	const payload = `{"ok":true}`
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="orders.json"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	req := wmDownloadRequest("req-sig-json-1")
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	s := string(body)
	if !strings.Contains(s, `"_sig":"jzsig1.k2026.`) || !strings.Contains(s, `"ok":true`) {
		t.Fatalf("json signature body = %s", s)
	}
	// token 覆盖签名前捕获体（原始 JSON）：提取 _sig 值严格复算
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("signed json must stay valid: %v (%s)", err, s)
	}
	token, _ := obj["_sig"].(string)
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		t.Fatalf("token parse = %q", token)
	}
	ts, _ := strconv.ParseInt(parts[2], 10, 64)
	want := recomputeSigToken(t, "k2026", "orders.json", payload, detectors.CredentialKey(req, g.IdentitySalt), ts)
	if parts[3] != want {
		t.Fatalf("json token not recomputable: %q want %q", parts[3], want)
	}
}

// 未启用（无配置）：体逐字节不变、无签名明细。
func TestServeNext_FileSignatureDisabledZeroChange(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)

	const payload = "a,b\n1,2\n"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="orders.csv"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-sig-off-1"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != payload {
		t.Fatalf("disabled signature must not touch body: %q", body)
	}
	for _, d := range readAPIRecords(t, logPath)[0].Details {
		if d.RuleID == "file.signature_embedded" {
			t.Fatal("disabled signature must not produce detail")
		}
	}
}

// 超出 v1 文本族类型（application/pdf）：直通不嵌入（下载观测照常）。
func TestServeNext_FileSignatureTypeOutOfScope(t *testing.T) {
	g, logPath := newFileSignatureTestGuard(t, "OBSERVE", "k2026")

	const payload = "FAKE-PDF-BYTES"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="statement.pdf"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-sig-pdf-1"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != payload {
		t.Fatalf("out-of-scope type must not be modified: %q", body)
	}
	for _, d := range readAPIRecords(t, logPath)[0].Details {
		if d.RuleID == "file.signature_embedded" {
			t.Fatal("pdf must not be signed")
		}
	}
}

// 无 Content-Disposition（普通文本响应，非下载观测命中）：零行为。
func TestServeNext_FileSignatureNoDownloadObservation(t *testing.T) {
	g, logPath := newFileSignatureTestGuard(t, "OBSERVE", "k2026")

	const payload = "plain text response"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-sig-nodl-1"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != payload {
		t.Fatalf("non-download response must not be modified: %q", body)
	}
	for _, d := range readAPIRecords(t, logPath)[0].Details {
		if d.RuleID == "file.signature_embedded" {
			t.Fatal("non-download must not be signed")
		}
	}
}

// JSON 解析失败（Content-Type 声明 JSON 但体非法）：FAIL_OPEN 直通原体，不 panic。
func TestServeNext_FileSignatureFailOpenBadJSON(t *testing.T) {
	g, logPath := newFileSignatureTestGuard(t, "OBSERVE", "k2026")

	const payload = `{bad json`
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="data.json"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-sig-badjson-1"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != payload {
		t.Fatalf("bad json must fail-open passthrough: %q", body)
	}
	for _, d := range readAPIRecords(t, logPath)[0].Details {
		if d.RuleID == "file.signature_embedded" {
			t.Fatal("failed signature must not be reported as embedded")
		}
	}
}
