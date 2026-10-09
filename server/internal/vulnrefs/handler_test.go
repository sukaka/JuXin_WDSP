package vulnrefs

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newRequest 构造带 path 参数的测试请求（无鉴权上下文——校验失败路径不触达主体）。
func newRequest(method, target, body, cnnvdID string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if cnnvdID != "" {
		req.SetPathValue("cnnvd_id", cnnvdID)
	}
	return req
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return body
}

// TestCreateValidationMatrix 非法输入一律 400（INVALID_ARGUMENT），不触达存储层。
func TestCreateValidationMatrix(t *testing.T) {
	h := NewHandler(nil, nil)
	cases := []struct {
		name string
		body string
	}{
		{"缺 cnnvd_id", `{"title":"x"}`},
		{"cnnvd 格式非法", `{"cnnvd_id":"CNNVD-2024-1","title":"x"}`},
		{"cve 格式非法", `{"cnnvd_id":"CNNVD-202401-2345","cve_id":"CVE-2024-1"}`},
		{"published_at 非日期", `{"cnnvd_id":"CNNVD-202401-2345","published_at":"2024/01/15"}`},
		{"url 非 http", `{"cnnvd_id":"CNNVD-202401-2345","url":"ftp://x"}`},
		{"非法 JSON", `{not-json`},
		{"未知字段", `{"cnnvd_id":"CNNVD-202401-2345","bogus":1}`},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.Create(rec, newRequest(http.MethodPost, "/api/v1/waf/vuln-refs", c.body, ""))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", c.name, rec.Code)
			continue
		}
		if body := decodeBody(t, rec); body["code"] != "INVALID_ARGUMENT" {
			t.Errorf("%s: code = %v, want INVALID_ARGUMENT", c.name, body["code"])
		}
	}
}

// TestPathIDValidation 路径编号非法 → 400（不是 404）。
func TestPathIDValidation(t *testing.T) {
	h := NewHandler(nil, nil)
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		rec := httptest.NewRecorder()
		req := newRequest(method, "/api/v1/waf/vuln-refs/bad-id", "", "bad-id")
		if method == http.MethodGet {
			h.Get(rec, req)
		} else {
			h.Delete(rec, req)
		}
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s bad-id: status = %d, want 400", method, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.Update(rec, newRequest(http.MethodPut, "/api/v1/waf/vuln-refs/bad-id", `{}`, "bad-id"))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("PUT bad-id: status = %d, want 400", rec.Code)
	}
}

// TestUpdateImmutableCNNVD 更新体携带与路径不一致的 cnnvd_id → 400。
func TestUpdateImmutableCNNVD(t *testing.T) {
	h := NewHandler(nil, nil)
	rec := httptest.NewRecorder()
	h.Update(rec, newRequest(http.MethodPut, "/api/v1/waf/vuln-refs/CNNVD-202401-2345",
		`{"cnnvd_id":"CNNVD-202402-0007","title":"x"}`, "CNNVD-202401-2345"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if body := decodeBody(t, rec); body["message"] != "CNNVD 编号不可修改" {
		t.Errorf("unexpected message: %v", body["message"])
	}
}

// TestValidateRefRequestNormalize 归一化口径：编号大写、字段去空白、空 published_at 视为未填。
func TestValidateRefRequestNormalize(t *testing.T) {
	date := "2024-01-15"
	ref, msg := validateRefRequest(&refRequest{
		CNNVDID:     "cnnvd-202401-2345 ",
		CVEID:       " cve-2024-0001",
		Title:       "  测试漏洞  ",
		Severity:    "高危",
		PublishedAt: &date,
		URL:         " https://www.cnnvd.org.cn/home/loophole ",
	}, true)
	if ref == nil {
		t.Fatalf("valid request rejected: %s", msg)
	}
	if ref.CNNVDID != "CNNVD-202401-2345" || ref.CVEID != "CVE-2024-0001" {
		t.Errorf("ids not normalized: %q %q", ref.CNNVDID, ref.CVEID)
	}
	if ref.Title != "测试漏洞" || ref.URL != "https://www.cnnvd.org.cn/home/loophole" {
		t.Errorf("fields not trimmed: %+v", ref)
	}
	if ref.PublishedAt == nil || *ref.PublishedAt != "2024-01-15" {
		t.Errorf("published_at wrong: %v", ref.PublishedAt)
	}
	// 空日期指针 → nil（入库 NULL）
	empty := ""
	ref, _ = validateRefRequest(&refRequest{CNNVDID: "CNNVD-202401-2345", PublishedAt: &empty}, true)
	if ref == nil || ref.PublishedAt != nil {
		t.Errorf("empty published_at should become nil: %+v", ref)
	}
	// 超长字段
	long := strings.Repeat("x", 513)
	if ref, msg := validateRefRequest(&refRequest{CNNVDID: "CNNVD-202401-2345", Title: long}, true); ref != nil {
		t.Error("oversize title should be rejected")
	} else if msg == "" {
		t.Error("rejection must carry Chinese message")
	}
}
