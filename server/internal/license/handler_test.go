// handler_test.go 授权 HTTP 接口单元测试：路由权限点、导入两种上传方式、
// 错误状态码映射（400/422/409）、审计记录（不落签名与原文）。
package license

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// auditSpy 审计记录 spy。
type auditSpy struct {
	mu     sync.Mutex
	inputs []audits.RecordInput
}

func (s *auditSpy) Record(_ context.Context, in audits.RecordInput) error {
	s.mu.Lock()
	s.inputs = append(s.inputs, in)
	s.mu.Unlock()
	return nil
}

func (s *auditSpy) last() audits.RecordInput {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.inputs) == 0 {
		return audits.RecordInput{}
	}
	return s.inputs[len(s.inputs)-1]
}

// injectPrincipal 构造注入指定权限点主体的 authz 包装（仿 apiscan handler_test 模式）。
func injectPrincipal(userID uuid.UUID, perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: userID, Username: "tester", PermsSet: set}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}
}

// handlerEnv 测试 HTTP 环境。
type handlerEnv struct {
	env     *testSvcEnv
	handler http.Handler
	audits  *auditSpy
}

func newHandlerEnv(t *testing.T, hostFP string, perms ...string) *handlerEnv {
	t.Helper()
	env := newTestSvcEnv(t, hostFP)
	spy := &auditSpy{}
	h := NewHandler(env.svc).SetAudits(spy)
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPrincipal(uuid.New(), perms...), h)
	return &handlerEnv{env: env, handler: mux, audits: spy}
}

// apiBody 通用响应壳。
type apiBody struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func doJSON(t *testing.T, h http.Handler, method, path, body string) (int, apiBody) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out apiBody
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应非 JSON: %v body=%s", err, rec.Body.String())
	}
	return rec.Code, out
}

func (e *handlerEnv) sampleFile(t *testing.T, rec testLicenseRec) []byte {
	t.Helper()
	return signTestLicense(t, e.env.priv, buildPayloadForTest(rec, e.env.now, testKeyID))
}

func TestHandlerStatusNoPermission(t *testing.T) {
	he := newHandlerEnv(t, "") // 无任何权限点：status 登录即可
	code, body := doJSON(t, he.handler, http.MethodGet, "/api/v1/license/status", "")
	if code != http.StatusOK || body.Code != "SUCCESS" {
		t.Fatalf("status 应 200: code=%d body=%+v", code, body)
	}
	var st State
	if err := json.Unmarshal(body.Data, &st); err != nil {
		t.Fatalf("解析 status data: %v", err)
	}
	if st.Valid || st.Reason != "未导入授权" {
		t.Fatalf("初始状态应为未导入: %+v", st)
	}
	if st.IntegrityStatus != IntegrityNotImported {
		t.Fatalf("status 应暴露原始完整性状态: %+v", st)
	}
	if st.ProtectionState.ProtectionForm != "STANDARD_OFFLINE" ||
		st.ProtectionState.CommercialAuthorization != "NOT_IMPORTED" ||
		st.ProtectionState.ArtifactIntegrity != "UNVERIFIABLE" ||
		st.ProtectionState.GatewayProtection != "PRESERVE_EXISTING" ||
		st.ProtectionState.ConfidentialComputing != "DISABLED" {
		t.Fatalf("status 应暴露未导入时的多维保护事实: %+v", st.ProtectionState)
	}
}

func TestHandlerImportJSONSuccess(t *testing.T) {
	he := newHandlerEnv(t, "", PermManage)
	fileBytes := he.sampleFile(t, validSample())
	code, body := doJSON(t, he.handler, http.MethodPost, "/api/v1/license/import",
		`{"file_content":`+strconvQuote(string(fileBytes))+`}`)
	if code != http.StatusOK {
		t.Fatalf("导入应 200: code=%d msg=%s", code, body.Message)
	}
	// 响应返回最新 status
	var st State
	if err := json.Unmarshal(body.Data, &st); err != nil {
		t.Fatalf("解析导入响应: %v", err)
	}
	if !st.Valid || st.LicenseID != "LIC-2026-0001" {
		t.Fatalf("导入后状态应有效: %+v", st)
	}
	// 审计：module/action/风险等级与四要素摘要；绝不落签名与原文
	audit := he.audits.last()
	if audit.Module != "license" || audit.Action != "import" || audit.RiskLevel != audits.RiskHigh {
		t.Fatalf("审计字段错误: %+v", audit)
	}
	if audit.Result != audits.ResultSuccess || audit.ObjectID != "LIC-2026-0001" {
		t.Fatalf("审计结果错误: %+v", audit)
	}
	if !strings.Contains(audit.AfterSummary, "LIC-2026-0001") ||
		!strings.Contains(audit.AfterSummary, "2099-12-31") {
		t.Fatalf("审计摘要应含 license_id/expires_at: %s", audit.AfterSummary)
	}
	if strings.Contains(audit.AfterSummary, "signature") || strings.Contains(audit.AfterSummary, "payload") {
		t.Fatalf("审计摘要不得含签名与原文: %s", audit.AfterSummary)
	}
}

func TestHandlerImportForbidden(t *testing.T) {
	he := newHandlerEnv(t, "") // 无 license.manage
	code, _ := doJSON(t, he.handler, http.MethodPost, "/api/v1/license/import", `{"file_content":"x"}`)
	if code != http.StatusForbidden {
		t.Fatalf("无权限应 403，got %d", code)
	}
}

func TestHandlerImportMalformed(t *testing.T) {
	he := newHandlerEnv(t, "", PermManage)
	code, body := doJSON(t, he.handler, http.MethodPost, "/api/v1/license/import",
		`{"file_content":"not-a-lic-file"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("解析失败应 400，got %d", code)
	}
	if !strings.Contains(body.Message, "授权文件格式错误") {
		t.Fatalf("错误信息应为中文格式错误: %s", body.Message)
	}
	// 失败也记审计（FAILURE + RiskHigh）
	audit := he.audits.last()
	if audit.Result != audits.ResultFailure || audit.RiskLevel != audits.RiskHigh {
		t.Fatalf("失败审计错误: %+v", audit)
	}
}

func TestHandlerImportBadSignature422(t *testing.T) {
	he := newHandlerEnv(t, "", PermManage)
	payload := buildPayloadForTest(validSample(), he.env.now, testKeyID)
	fileBytes := signTestLicense(t, he.env.priv, payload)
	var file map[string]json.RawMessage
	if err := json.Unmarshal(fileBytes, &file); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(file["payload"], &m); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	m["customer"] = "篡改"
	tampered, _ := json.Marshal(m)
	repacked, _ := json.Marshal(map[string]interface{}{
		"payload":   json.RawMessage(tampered),
		"signature": json.RawMessage(file["signature"]),
	})
	code, body := doJSON(t, he.handler, http.MethodPost, "/api/v1/license/import",
		`{"file_content":`+strconvQuote(string(repacked))+`}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("验签失败应 422，got %d msg=%s", code, body.Message)
	}
	if body.Code != codeLicenseInvalid {
		t.Fatalf("业务码应为 LICENSE_INVALID: %s", body.Code)
	}
}

func TestHandlerImportFingerprintMismatch409(t *testing.T) {
	he := newHandlerEnv(t, "sha256:host-A", PermManage)
	rec := validSample()
	rec.MachineFingerprint = "sha256:host-B"
	fileBytes := he.sampleFile(t, rec)
	code, body := doJSON(t, he.handler, http.MethodPost, "/api/v1/license/import",
		`{"file_content":`+strconvQuote(string(fileBytes))+`}`)
	if code != http.StatusConflict {
		t.Fatalf("指纹不匹配应 409，got %d msg=%s", code, body.Message)
	}
	if !strings.Contains(body.Message, "指纹") {
		t.Fatalf("错误信息应说明指纹不匹配: %s", body.Message)
	}
}

func TestHandlerImportDuplicate409(t *testing.T) {
	he := newHandlerEnv(t, "", PermManage)
	fileBytes := he.sampleFile(t, validSample())
	body := `{"file_content":` + strconvQuote(string(fileBytes)) + `}`
	if code, _ := doJSON(t, he.handler, http.MethodPost, "/api/v1/license/import", body); code != http.StatusOK {
		t.Fatalf("首次导入应 200，got %d", code)
	}
	code, _ := doJSON(t, he.handler, http.MethodPost, "/api/v1/license/import", body)
	if code != http.StatusConflict {
		t.Fatalf("重复导入应 409，got %d", code)
	}
}

func TestHandlerImportProductBound409(t *testing.T) {
	he := newHandlerEnv(t, "", PermManage)
	recA := validSample()
	recA.Product = "waf"
	fileA := he.sampleFile(t, recA)
	if code, _ := doJSON(t, he.handler, http.MethodPost, "/api/v1/license/import",
		`{"file_content":`+strconvQuote(string(fileA))+`}`); code != http.StatusOK {
		t.Fatalf("首导 waf 应 200，got %d", code)
	}
	// 不同 product 导入：409 + LICENSE_PRODUCT_BOUND，提示重新安装
	recB := validSample()
	recB.LicenseID = "LIC-2026-0002"
	recB.Product = "wdsp"
	fileB := he.sampleFile(t, recB)
	code, body := doJSON(t, he.handler, http.MethodPost, "/api/v1/license/import",
		`{"file_content":`+strconvQuote(string(fileB))+`}`)
	if code != http.StatusConflict {
		t.Fatalf("产品形态绑定冲突应 409，got %d msg=%s", code, body.Message)
	}
	if body.Code != CodeLicenseProductBound {
		t.Fatalf("业务码应为 LICENSE_PRODUCT_BOUND: %s", body.Code)
	}
	if !strings.Contains(body.Message, "重新安装") {
		t.Fatalf("错误信息应提示重新安装: %s", body.Message)
	}
	// 失败审计沿用既有口径（FAILURE + RiskHigh）
	audit := he.audits.last()
	if audit.Result != audits.ResultFailure || audit.RiskLevel != audits.RiskHigh {
		t.Fatalf("失败审计错误: %+v", audit)
	}
}

func TestHandlerImportMultipart(t *testing.T) {
	he := newHandlerEnv(t, "", PermManage)
	fileBytes := he.sampleFile(t, validSample())
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", "license.lic")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write(fileBytes); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/license/import", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	he.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("multipart 导入应 200，got %d body=%s", rec.Code, rec.Body.String())
	}
	if !he.env.svc.State().Valid {
		t.Fatal("multipart 导入后状态应有效")
	}
}

func TestHandlerImportEmptyContent(t *testing.T) {
	he := newHandlerEnv(t, "", PermManage)
	code, _ := doJSON(t, he.handler, http.MethodPost, "/api/v1/license/import", `{"file_content":"  "}`)
	if code != http.StatusBadRequest {
		t.Fatalf("空内容应 400，got %d", code)
	}
}

func TestHandlerHistoryPermission(t *testing.T) {
	he := newHandlerEnv(t, "", PermRead, PermManage)
	if err := he.env.importSample(t, validSample()); err != nil {
		t.Fatalf("Import: %v", err)
	}
	code, body := doJSON(t, he.handler, http.MethodGet, "/api/v1/license/history?page=1&page_size=10", "")
	if code != http.StatusOK {
		t.Fatalf("history 应 200，got %d", code)
	}
	// 历史出参不得携带签名与 payload 原文
	raw := string(body.Data)
	if strings.Contains(raw, "signature") || strings.Contains(raw, "payload") {
		t.Fatalf("历史出参不得含敏感原文: %s", raw)
	}
	// 无 license.read 权限 → 403
	he2 := newHandlerEnv(t, "")
	code, _ = doJSON(t, he2.handler, http.MethodGet, "/api/v1/license/history", "")
	if code != http.StatusForbidden {
		t.Fatalf("无 license.read 应 403，got %d", code)
	}
}

// strconvQuote 把字符串转为 JSON 字符串字面量（测试构造请求体用）。
func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
