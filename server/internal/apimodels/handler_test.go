// handler_test.go 参数批量采纳接口（ConfirmParametersBatch）测试：
// 非法 body 明确 400 且不触达存取层（修复前静默吞错按全量采纳且误记成功审计）、
// 空 body/省略 ids 保持全量采纳语义、正常 ids 按列表透传（httptest + fake，不依赖数据库）。
package apimodels

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// fakeBatchConfirmer 内存版 ParameterBatchConfirmer（记录调用入参，可注入错误路径）。
type fakeBatchConfirmer struct {
	calls       int
	lastVersion uuid.UUID
	lastIDs     []uuid.UUID
	confirmed   int
	skipped     int
	err         error
}

func (f *fakeBatchConfirmer) ConfirmParametersBatch(_ context.Context, versionID uuid.UUID, ids []uuid.UUID) (int, int, error) {
	f.calls++
	f.lastVersion = versionID
	f.lastIDs = ids
	if f.err != nil {
		return 0, 0, f.err
	}
	return f.confirmed, f.skipped, nil
}

// injectBatchPrincipal 模拟认证链：注入持有 api_parameter.edit 权限点的主体与 Request ID。
func injectBatchPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: map[string]bool{"api_parameter.edit": true}}
		ctx := authz.WithPrincipal(r.Context(), p)
		ctx = context.WithValue(ctx, response.RequestIDKey, "test-rid")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newBatchTestMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectBatchPrincipal, h)
	return mux
}

// doBatchReq 以原始字符串 body 发起请求（非法 JSON 用例需要绕过 json.Marshal）。
func doBatchReq(t *testing.T, mux http.Handler, body *string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == nil {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(*body)
	}
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/api-security/models/"+uuid.NewString()+"/parameters/confirm-batch", reader)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func strPtr(s string) *string { return &s }

// TestConfirmParametersBatchInvalidBody 非法 body 明确 400 且存取层零调用：
// 非 JSON、未知字段（DisallowUnknownFields）、ids 含非法 UUID、路径版本 ID 非法。
func TestConfirmParametersBatchInvalidBody(t *testing.T) {
	fake := &fakeBatchConfirmer{}
	h := NewHandler(nil, nil)
	h.SetParameterBatchConfirmer(fake)
	mux := newBatchTestMux(h)

	cases := map[string]*string{
		"非 JSON body":  strPtr("not-json"),
		"JSON 数组而非对象":  strPtr(`["x"]`),
		"未知字段":         strPtr(`{"ids":[],"extra":1}`),
		"ids 含非法 UUID": strPtr(`{"ids":["not-a-uuid"]}`),
	}
	for name, body := range cases {
		if rr := doBatchReq(t, mux, body); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: status=%d, want 400, body=%s", name, rr.Code, rr.Body.String())
		}
	}

	// 路径版本 ID 非法 → 400
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-security/models/not-a-uuid/parameters/confirm-batch", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("路径版本ID非法: status=%d, want 400", rr.Code)
	}

	if fake.calls != 0 {
		t.Fatalf("非法请求不得触达存取层, calls=%d", fake.calls)
	}
}

// TestConfirmParametersBatchEmptyBody 空 body / 省略 ids / 显式空列表均保持
// 「采纳本版本全部参数」语义（存取层收到空 ids）。
func TestConfirmParametersBatchEmptyBody(t *testing.T) {
	cases := map[string]*string{
		"空 body":     nil,
		"空对象":        strPtr(`{}`),
		"显式空 ids 列表": strPtr(`{"ids":[]}`),
	}
	for name, body := range cases {
		fake := &fakeBatchConfirmer{confirmed: 3, skipped: 1}
		h := NewHandler(nil, nil)
		h.SetParameterBatchConfirmer(fake)
		mux := newBatchTestMux(h)

		rr := doBatchReq(t, mux, body)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status=%d, want 200, body=%s", name, rr.Code, rr.Body.String())
		}
		if fake.calls != 1 || len(fake.lastIDs) != 0 {
			t.Fatalf("%s: 全量语义应透传空 ids, calls=%d ids=%v", name, fake.calls, fake.lastIDs)
		}
		// 响应透传 confirmed/skipped
		var env struct {
			Code string         `json:"code"`
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if env.Data["confirmed"].(float64) != 3 || env.Data["skipped"].(float64) != 1 {
			t.Fatalf("%s: 响应未透传 confirmed/skipped: %v", name, env.Data)
		}
	}
}

// TestConfirmParametersBatchWithIDs 正常 ids 按列表透传（保序），存取错误映射 500。
func TestConfirmParametersBatchWithIDs(t *testing.T) {
	fake := &fakeBatchConfirmer{confirmed: 2}
	h := NewHandler(nil, nil)
	h.SetParameterBatchConfirmer(fake)
	mux := newBatchTestMux(h)

	id1, id2 := uuid.New(), uuid.New()
	rr := doBatchReq(t, mux, strPtr(`{"ids":["`+id1.String()+`","`+id2.String()+`"]}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200, body=%s", rr.Code, rr.Body.String())
	}
	if fake.calls != 1 || len(fake.lastIDs) != 2 || fake.lastIDs[0] != id1 || fake.lastIDs[1] != id2 {
		t.Fatalf("ids 应按列表保序透传: %+v", fake.lastIDs)
	}

	// 存取层错误 → 500
	fakeErr := &fakeBatchConfirmer{err: errors.New("db down")}
	h2 := NewHandler(nil, nil)
	h2.SetParameterBatchConfirmer(fakeErr)
	rr = doBatchReq(t, newBatchTestMux(h2), nil)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("存取错误: status=%d, want 500", rr.Code)
	}
}
