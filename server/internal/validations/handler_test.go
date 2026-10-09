// handler_test.go 模拟管理面 HTTP 入口测试：权限矩阵（validate/read 分离）、
// 非法输入 400、创建 200 完整报告、STALE 读出分支、404/分页。
package validations

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// injectPrincipal 模拟认证链：注入持有给定权限点集合的主体。
func injectPrincipal(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "val-tester", PermsSet: set}
			ctx := authz.WithPrincipal(r.Context(), p)
			ctx = context.WithValue(ctx, response.RequestIDKey, "val-rid")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// noPrincipal 模拟未注入主体的认证链（权限中间件应 401）。
func noPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

const valPath = "/api/v1/api-security/protection/validations"

func newValMux(pol *fakePolicy, authzFn func(http.Handler) http.Handler) (*http.ServeMux, *fakeStore) {
	store := newFakeStore()
	mux := http.NewServeMux()
	RegisterRoutes(mux, authzFn, NewHandler(NewService(store, pol)))
	return mux, store
}

func doReq(t *testing.T, mux http.Handler, method, url, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, url, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, url, nil)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, r)
	return rr
}

const goodBody = `{"batches":[{"input_id":"req-1","matches":[{"detector":"api_schema","rule_id":"schema.type_mismatch","category":"BLOCK","severity":"CRITICAL","score_delta":10}]}]}`

// 权限矩阵：POST 未登录 401 / 仅 read 403 / validate 200；GET 未登录 401 /
// 仅 validate 403（read 与 validate 分离）/ read 200。
func TestValidationsPermissionMatrix(t *testing.T) {
	pol := &fakePolicy{mode: "PROTECT", digest: "pol-a"}
	if rr := doReq(t, func() *http.ServeMux { m, _ := newValMux(pol, noPrincipal); return m }(), "POST", valPath, goodBody); rr.Code != http.StatusUnauthorized {
		t.Fatalf("POST no principal: got %d", rr.Code)
	}
	if rr := doReq(t, func() *http.ServeMux { m, _ := newValMux(pol, injectPrincipal(PermProtectionRead)); return m }(), "POST", valPath, goodBody); rr.Code != http.StatusForbidden {
		t.Fatalf("POST read-only: got %d（创建需 validate，read 不够）", rr.Code)
	}
	if rr := doReq(t, func() *http.ServeMux { m, _ := newValMux(pol, injectPrincipal(PermProtectionValidate)); return m }(), "POST", valPath, goodBody); rr.Code != http.StatusOK {
		t.Fatalf("POST validate: got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr := doReq(t, func() *http.ServeMux { m, _ := newValMux(pol, noPrincipal); return m }(), "GET", valPath, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("GET no principal: got %d", rr.Code)
	}
	if rr := doReq(t, func() *http.ServeMux { m, _ := newValMux(pol, injectPrincipal(PermProtectionValidate)); return m }(), "GET", valPath, ""); rr.Code != http.StatusForbidden {
		t.Fatalf("GET validate-only: got %d（读取需 read，validate 不隐含）", rr.Code)
	}
	if rr := doReq(t, func() *http.ServeMux { m, _ := newValMux(pol, injectPrincipal(PermProtectionRead)); return m }(), "GET", valPath, ""); rr.Code != http.StatusOK {
		t.Fatalf("GET read: got %d body=%s", rr.Code, rr.Body.String())
	}
}

// 非法输入：坏 JSON / 空批次 / 101 批 / evidence 原文 / 超长字段 → 400 且不创建。
func TestValidationsCreateValidation400(t *testing.T) {
	pol := &fakePolicy{mode: "PROTECT", digest: "pol-a"}
	mux, store := newValMux(pol, injectPrincipal(PermProtectionValidate))
	bad101 := `{"batches":[` + strings.Repeat(`{"input_id":"r","matches":[]},`, 100) + `{"input_id":"r","matches":[]}]}`
	for _, body := range []string{
		`{bad`,
		`{"batches":[]}`,
		bad101,
		`{"batches":[{"input_id":"r","matches":[{"detector":"d","evidence":{"body":"raw"}}]}]}`,
		`{"batches":[{"input_id":"` + strings.Repeat("x", 257) + `","matches":[]}]}`,
	} {
		if rr := doReq(t, mux, "POST", valPath, body); rr.Code != http.StatusBadRequest {
			t.Fatalf("body %.60s…: got %d body=%s", body, rr.Code, rr.Body.String())
		}
	}
	if len(store.reports) != 0 {
		t.Fatal("400 拒绝后不得有落库")
	}
}

// 创建 200 带完整报告：id/status/verdicts/would_block/digests 齐全；
// GET {id} 复核一致；GET list 分页形状。
func TestValidationsCreateAndReadBack(t *testing.T) {
	pol := &fakePolicy{mode: "PROTECT", digest: "pol-a"}
	mux, _ := newValMux(pol, injectPrincipal(PermProtectionValidate, PermProtectionRead))
	rr := doReq(t, mux, "POST", valPath, goodBody)
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var created struct {
		Data Report `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	rep := created.Data
	if rep.ID == "" || rep.Status != "COMPLETED" || rep.PolicyDigest != "pol-a" ||
		rep.CorpusDigest == "" || rep.InputsDigest == "" || rep.CreatedAt.IsZero() {
		t.Fatalf("创建报告字段不全: %+v", rep)
	}
	if len(rep.Verdicts) != 1 || !rep.Verdicts[0].WouldBlock || rep.Verdicts[0].Status != VerdictEvaluated {
		t.Fatalf("would_block 语义不符: %+v", rep.Verdicts)
	}

	// GET {id} 复核
	rr = doReq(t, mux, "GET", valPath+"/"+rep.ID, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("get: %d %s", rr.Code, rr.Body.String())
	}
	var got struct {
		Data Report `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got.Data.ID != rep.ID || got.Data.Status != "COMPLETED" {
		t.Fatalf("回读不符: %+v", got.Data)
	}

	// list 分页
	rr = doReq(t, mux, "GET", valPath+"?page=1&page_size=10", "")
	var page struct {
		Data struct {
			Items []Report `json:"items"`
			Total int64    `json:"total"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &page)
	if page.Data.Total != 1 || len(page.Data.Items) != 1 || page.Data.Items[0].ID != rep.ID {
		t.Fatalf("分页不符: %+v", page.Data)
	}

	// 坏 id 400 / 不存在 404
	if rr := doReq(t, mux, "GET", valPath+"/not-a-uuid", ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad id: got %d", rr.Code)
	}
	if rr := doReq(t, mux, "GET", valPath+"/"+uuid.NewString(), ""); rr.Code != http.StatusNotFound {
		t.Fatalf("not found: got %d", rr.Code)
	}
}

// STALE 读出分支：创建后策略摘要变化 → GET {id} 响应 status=STALE（不回写）。
func TestValidationsGetStaleBranch(t *testing.T) {
	pol := &fakePolicy{mode: "PROTECT", digest: "pol-a"}
	mux, store := newValMux(pol, injectPrincipal(PermProtectionValidate, PermProtectionRead))
	rr := doReq(t, mux, "POST", valPath, goodBody)
	var created struct {
		Data Report `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	id := created.Data.ID

	pol.digest = "pol-b" // 模拟一次新发布
	rr = doReq(t, mux, "GET", valPath+"/"+id, "")
	var got struct {
		Data Report `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got.Data.Status != "STALE" {
		t.Fatalf("策略摘要变化后应为 STALE: %s", got.Data.Status)
	}
	uid, _ := uuid.Parse(id)
	rec, _ := store.GetReport(context.Background(), uid)
	if rec.Status != "COMPLETED" {
		t.Fatalf("落库行不得回写: %s", rec.Status)
	}
}

// 创建请求含 would_block 字段名原样（OpenAPI 注明模拟语义）。
func TestValidationsWouldBlockFieldName(t *testing.T) {
	pol := &fakePolicy{mode: "PROTECT", digest: "pol-a"}
	mux, _ := newValMux(pol, injectPrincipal(PermProtectionValidate))
	rr := doReq(t, mux, "POST", valPath, goodBody)
	if !strings.Contains(rr.Body.String(), `"would_block":true`) {
		t.Fatalf("响应必须含 would_block 字段: %s", rr.Body.String())
	}
}

var _ = fmt.Sprintf
