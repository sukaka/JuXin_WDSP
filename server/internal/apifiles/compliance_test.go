// compliance_test.go 文件合规规则 HTTP 入口测试：权限矩阵 / 参数与 match_value 校验 /
// CRUD 往返 / 去重键冲突 / 列表过滤（内存仓储驱动真实 Handler 与路由）。
package apifiles

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apidata"
)

// newComplianceMux 装配合规规则路由（内存仓储，无审计服务——recordAudit 跳过不影响主流程）。
func newComplianceMux(store *MemComplianceStore, authzFn func(http.Handler) http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterComplianceRoutes(mux, authzFn, NewComplianceHandler(store, nil))
	return mux
}

// doJSON 发 JSON 请求。
func doJSON(t *testing.T, mux http.Handler, method, url, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, url, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, url, nil)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// createRule 造一条规则并返回其 ID。
func createRule(t *testing.T, mux http.Handler, body string) string {
	t.Helper()
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/file-compliance-rules", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("create: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if resp.Data.ID == "" {
		t.Fatalf("create returned empty id: %s", rr.Body.String())
	}
	return resp.Data.ID
}

// 权限矩阵：未登录 401 / 无权限 403 / read 可读 / manage 可写（read 写被拒）。
func TestCompliancePermissionMatrix(t *testing.T) {
	store := NewMemComplianceStore()
	ruleBody := `{"direction":"UPLOAD","match_type":"EXT","match_value":"exe","action":"BLOCK"}`
	cases := []struct {
		name   string
		method string
		url    string
		body   string
		perm   string // 正确权限点
	}{
		{"list", http.MethodGet, "/api/v1/api-security/file-compliance-rules", "", apidata.PermDataRead},
		{"create", http.MethodPost, "/api/v1/api-security/file-compliance-rules", ruleBody, apidata.PermDataManage},
		{"update", http.MethodPatch, "/api/v1/api-security/file-compliance-rules/" + uuid.NewString(), `{"enabled":false}`, apidata.PermDataManage},
		{"delete", http.MethodDelete, "/api/v1/api-security/file-compliance-rules/" + uuid.NewString(), "", apidata.PermDataManage},
	}
	for _, tc := range cases {
		if rr := doJSON(t, newComplianceMux(store, noPrincipal), tc.method, tc.url, tc.body); rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s anon: status=%d, want 401", tc.name, rr.Code)
		}
		if rr := doJSON(t, newComplianceMux(store, injectPrincipal("other.read")), tc.method, tc.url, tc.body); rr.Code != http.StatusForbidden {
			t.Fatalf("%s noperm: status=%d, want 403", tc.name, rr.Code)
		}
		// read 权限不可写
		if tc.perm == apidata.PermDataManage {
			if rr := doJSON(t, newComplianceMux(store, injectPrincipal(apidata.PermDataRead)), tc.method, tc.url, tc.body); rr.Code != http.StatusForbidden {
				t.Fatalf("%s with read perm: status=%d, want 403", tc.name, rr.Code)
			}
		}
		// 持正确权限点可达（update/delete 对随机 id 应 404 而非 401/403，即已过权限闸）
		rr := doJSON(t, newComplianceMux(store, injectPrincipal(tc.perm)), tc.method, tc.url, tc.body)
		if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
			t.Fatalf("%s authorized: status=%d body=%s", tc.name, rr.Code, rr.Body.String())
		}
	}
}

// match_value 校验：EXT 形态 / MIME 形态 / RE2 可编译 / 长度上限 / 必填。
func TestComplianceValidation(t *testing.T) {
	mux := newComplianceMux(NewMemComplianceStore(), injectPrincipal(apidata.PermDataRead, apidata.PermDataManage))
	bad := []string{
		`{"direction":"SIDEWAYS","match_type":"EXT","match_value":"exe","action":"BLOCK"}`,
		`{"direction":"UPLOAD","match_type":"SIZE","match_value":"exe","action":"BLOCK"}`,
		`{"direction":"UPLOAD","match_type":"EXT","match_value":"exe","action":"DENY"}`,
		`{"direction":"UPLOAD","match_type":"EXT","match_value":"","action":"BLOCK"}`,
		`{"direction":"UPLOAD","match_type":"EXT","match_value":"tar.gz","action":"BLOCK"}`, // EXT 不含内点
		`{"direction":"UPLOAD","match_type":"EXT","match_value":"` + strings.Repeat("a", 17) + `","action":"BLOCK"}`,
		`{"direction":"UPLOAD","match_type":"MIME","match_value":"applicationpdf","action":"BLOCK"}`, // 缺斜杠
		`{"direction":"UPLOAD","match_type":"MIME","match_value":"/pdf","action":"BLOCK"}`,           // 缺主类型
		`{"direction":"UPLOAD","match_type":"FILENAME_REGEX","match_value":"[unclosed","action":"BLOCK"}`,
		`{"direction":"UPLOAD","match_type":"EXT","match_value":"exe","action":"BLOCK","reason":"` + strings.Repeat("r", 257) + `"}`,
	}
	for _, body := range bad {
		if rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/file-compliance-rules", body); rr.Code != http.StatusBadRequest {
			t.Fatalf("body %s: status=%d, want 400 (%s)", body, rr.Code, rr.Body.String())
		}
	}
	// 归一正例：EXT 前导点剥离 + 大写归小写；MIME 参数剥离（紧贴分号无空格）
	good := []struct {
		body      string
		wantValue string
	}{
		{`{"direction":"UPLOAD","match_type":"EXT","match_value":".EXE","action":"BLOCK"}`, "exe"},
		{`{"direction":"UPLOAD","match_type":"MIME","match_value":"Application/PDF;charset=utf-8","action":"OBSERVE"}`, "application/pdf"},
		{`{"direction":"DOWNLOAD","match_type":"FILENAME_REGEX","match_value":"(?i)^secret_.*\\.csv$","action":"OBSERVE"}`, `(?i)^secret_.*\.csv$`},
	}
	for _, g := range good {
		rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/file-compliance-rules", g.body)
		if rr.Code != http.StatusOK {
			t.Fatalf("body %s: status=%d body=%s", g.body, rr.Code, rr.Body.String())
		}
		var resp struct {
			Data struct {
				MatchValue string `json:"match_value"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Data.MatchValue != g.wantValue {
			t.Fatalf("body %s: match_value=%q, want %q", g.body, resp.Data.MatchValue, g.wantValue)
		}
	}
}

// CRUD 往返：创建（默认 enabled）→ 列表过滤 → 部分更新 → 删除 → 404。
func TestComplianceCRUD(t *testing.T) {
	mux := newComplianceMux(NewMemComplianceStore(), injectPrincipal(apidata.PermDataRead, apidata.PermDataManage))

	id := createRule(t, mux, `{"direction":"UPLOAD","match_type":"EXT","match_value":"exe","action":"BLOCK","reason":"阻断可执行文件"}`)
	id2 := createRule(t, mux, `{"direction":"DOWNLOAD","match_type":"EXT","match_value":"sql","action":"OBSERVE","enabled":false}`)

	// 列表 + 过滤
	type listBody struct {
		Data struct {
			Total int64 `json:"total"`
			Items []struct {
				ID      string `json:"id"`
				Enabled bool   `json:"enabled"`
			} `json:"items"`
		} `json:"data"`
	}
	decodeList := func(rr *httptest.ResponseRecorder) listBody {
		var b listBody
		if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		return b
	}
	if b := decodeList(doJSON(t, mux, http.MethodGet, "/api/v1/api-security/file-compliance-rules", "")); b.Data.Total != 2 {
		t.Fatalf("list total=%d, want 2", b.Data.Total)
	}
	if b := decodeList(doJSON(t, mux, http.MethodGet, "/api/v1/api-security/file-compliance-rules?direction=UPLOAD", "")); b.Data.Total != 1 {
		t.Fatalf("direction filter total=%d, want 1", b.Data.Total)
	}
	b := decodeList(doJSON(t, mux, http.MethodGet, "/api/v1/api-security/file-compliance-rules?enabled=false", ""))
	if b.Data.Total != 1 || b.Data.Items[0].ID != id2 {
		t.Fatalf("enabled filter=%+v", b.Data)
	}
	// 非法过滤枚举 400
	if rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/file-compliance-rules?action=DENY", ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("action filter: status=%d, want 400", rr.Code)
	}

	// 部分更新：enabled=false + reason
	rr := doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/file-compliance-rules/"+id, `{"enabled":false,"reason":"调整"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("patch: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var upd struct {
		Data struct {
			Enabled bool   `json:"enabled"`
			Reason  string `json:"reason"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &upd); err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	if upd.Data.Enabled || upd.Data.Reason != "调整" {
		t.Fatalf("patched=%+v", upd.Data)
	}
	// 联动校验：只改 match_type 不改 match_value 产生形态错位 → 400
	if rr := doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/file-compliance-rules/"+id,
		`{"match_type":"MIME"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("patch type mismatch: status=%d, want 400", rr.Code)
	}
	// 不存在 id 404 / 非法 id 400
	if rr := doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/file-compliance-rules/"+uuid.NewString(),
		`{"enabled":true}`); rr.Code != http.StatusNotFound {
		t.Fatalf("patch missing: status=%d, want 404", rr.Code)
	}
	if rr := doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/file-compliance-rules/not-uuid",
		`{"enabled":true}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("patch bad id: status=%d, want 400", rr.Code)
	}

	// 删除 → 再删 404
	if rr := doJSON(t, mux, http.MethodDelete, "/api/v1/api-security/file-compliance-rules/"+id, ""); rr.Code != http.StatusOK {
		t.Fatalf("delete: status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr := doJSON(t, mux, http.MethodDelete, "/api/v1/api-security/file-compliance-rules/"+id, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("delete twice: status=%d, want 404", rr.Code)
	}
	if b := decodeList(doJSON(t, mux, http.MethodGet, "/api/v1/api-security/file-compliance-rules", "")); b.Data.Total != 1 {
		t.Fatalf("after delete total=%d, want 1", b.Data.Total)
	}
}

// 去重键冲突：同方向同类型同匹配值重复创建 409；更新撞他行同键 409。
func TestComplianceConflict(t *testing.T) {
	mux := newComplianceMux(NewMemComplianceStore(), injectPrincipal(apidata.PermDataRead, apidata.PermDataManage))
	body := `{"direction":"UPLOAD","match_type":"EXT","match_value":"exe","action":"BLOCK"}`
	createRule(t, mux, body)
	if rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/file-compliance-rules", body); rr.Code != http.StatusConflict {
		t.Fatalf("duplicate create: status=%d, want 409 (%s)", rr.Code, rr.Body.String())
	}
	// 不同方向同值不冲突
	createRule(t, mux, `{"direction":"DOWNLOAD","match_type":"EXT","match_value":"exe","action":"OBSERVE"}`)
	// 更新撞他行：把 DOWNLOAD 行改成 UPLOAD → 与首行同键
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/file-compliance-rules?direction=DOWNLOAD", "")
	var b struct {
		Data struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil || len(b.Data.Items) != 1 {
		t.Fatalf("list download: %v %+v", err, b)
	}
	if rr := doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/file-compliance-rules/"+b.Data.Items[0].ID,
		`{"direction":"UPLOAD"}`); rr.Code != http.StatusConflict {
		t.Fatalf("conflicting update: status=%d, want 409 (%s)", rr.Code, rr.Body.String())
	}
}
