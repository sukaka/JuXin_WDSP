// handler_test.go 已吊销凭据 CRUD 单测（fake 仓储 + spy 审计，不依赖数据库）：
// 载荷校验（指纹格式/类型词汇/必填/窗口合法性）、登记/查询/调整/删除（404/409）、
// 写操作审计。pgx 路径由集成测试覆盖。
package apirevokedcreds

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// fakeRepo 内存仓储（镜像 Store 语义：入库校验 + 类型指纹复合唯一）。
type fakeRepo struct {
	items map[uuid.UUID]*Credential
}

func newFakeRepo() *fakeRepo { return &fakeRepo{items: map[uuid.UUID]*Credential{}} }

func (f *fakeRepo) Create(_ context.Context, in CreateInput, operator string) (*Credential, error) {
	if err := validateCreate(&in); err != nil {
		return nil, err
	}
	for _, c := range f.items {
		if c.CredentialType == in.CredentialType && c.Fingerprint == in.Fingerprint {
			return nil, ErrDuplicate
		}
	}
	from := time.Now()
	if in.EffectiveFrom != nil {
		from = *in.EffectiveFrom
	}
	c := &Credential{ID: uuid.New(), CredentialType: in.CredentialType, Fingerprint: in.Fingerprint,
		Reason: in.Reason, RevokedBy: operator, EffectiveFrom: from, EffectiveUntil: in.EffectiveUntil,
		CreatedBy: operator}
	f.items[c.ID] = c
	return c, nil
}

func (f *fakeRepo) List(_ context.Context, filter ListFilter) ([]Credential, error) {
	now := time.Now()
	out := []Credential{}
	for _, c := range f.items {
		if filter.CredentialType != "" && c.CredentialType != filter.CredentialType {
			continue
		}
		if filter.Active != nil {
			active := !c.EffectiveFrom.After(now) && (c.EffectiveUntil == nil || c.EffectiveUntil.After(now))
			if active != *filter.Active {
				continue
			}
		}
		out = append(out, *c)
	}
	return out, nil
}

func (f *fakeRepo) Get(_ context.Context, id uuid.UUID) (*Credential, error) {
	c, ok := f.items[id]
	if !ok {
		return nil, ErrNotFound
	}
	return c, nil
}

func (f *fakeRepo) Update(_ context.Context, id uuid.UUID, in UpdateInput) (*Credential, error) {
	c, ok := f.items[id]
	if !ok {
		return nil, ErrNotFound
	}
	if err := validateUpdate(&in); err != nil {
		return nil, err
	}
	c.Reason, c.EffectiveFrom, c.EffectiveUntil = in.Reason, in.EffectiveFrom, in.EffectiveUntil
	return c, nil
}

func (f *fakeRepo) Delete(_ context.Context, id uuid.UUID) error {
	if _, ok := f.items[id]; !ok {
		return ErrNotFound
	}
	delete(f.items, id)
	return nil
}

type spyAudits struct{ entries []audits.RecordInput }

func (s *spyAudits) Record(_ context.Context, in audits.RecordInput) error {
	s.entries = append(s.entries, in)
	return nil
}

const testFingerprint = "0123456789abcdef0123456789abcdef"

func withTester(r *http.Request) *http.Request {
	p := &authz.Principal{UserID: uuid.New(), Username: "tester"}
	return r.WithContext(authz.WithPrincipal(r.Context(), p))
}

func newJSONRequest(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if id := r.PathValue("id"); id == "" && strings.Contains(target, "/revoked-credentials/") {
		parts := strings.Split(target, "/revoked-credentials/")
		r.SetPathValue("id", parts[1])
	}
	return withTester(r)
}

func newTestHandler() (*Handler, *fakeRepo, *spyAudits) {
	repo := newFakeRepo()
	spy := &spyAudits{}
	h := &Handler{repo: repo, audits: spy}
	return h, repo, spy
}

func serve(h http.HandlerFunc, w *httptest.ResponseRecorder, r *http.Request) { h(w, r) }

func TestCreateValidation(t *testing.T) {
	h, _, _ := newTestHandler()
	cases := []struct {
		name string
		body string
	}{
		{"缺类型", `{"fingerprint":"` + testFingerprint + `","reason":"泄漏"}`},
		{"非法类型", `{"credential_type":"token","fingerprint":"` + testFingerprint + `","reason":"泄漏"}`},
		{"缺指纹", `{"credential_type":"auth","reason":"泄漏"}`},
		{"指纹非hex", `{"credential_type":"auth","fingerprint":"zzzz567890abcdef0123456789abcdef","reason":"泄漏"}`},
		{"指纹长度不足", `{"credential_type":"auth","fingerprint":"0123456789abcdef","reason":"泄漏"}`},
		{"缺原因", `{"credential_type":"auth","fingerprint":"` + testFingerprint + `"}`},
		{"窗口倒置", `{"credential_type":"auth","fingerprint":"` + testFingerprint + `","reason":"泄漏","effective_from":"2026-01-02T00:00:00Z","effective_until":"2026-01-01T00:00:00Z"}`},
		{"未知字段", `{"credential_type":"auth","fingerprint":"` + testFingerprint + `","reason":"泄漏","plaintext":"forbidden"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			serve(h.Create, w, newJSONRequest(t, "POST", "/api/v1/api-security/revoked-credentials", tc.body))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestCreateListGetUpdateDelete(t *testing.T) {
	h, repo, spy := newTestHandler()

	// 创建：201，吊销人取自登录主体
	w := httptest.NewRecorder()
	serve(h.Create, w, newJSONRequest(t, "POST", "/api/v1/api-security/revoked-credentials",
		`{"credential_type":"AUTH","fingerprint":"`+testFingerprint+`","reason":"凭据泄漏"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body: %s", w.Code, w.Body.String())
	}
	var created Credential
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created: %v", err)
	}
	// response.JSON 有统一信封？——直接解析顶层失败则说明信封包裹
	if created.ID == uuid.Nil {
		var env struct {
			Data Credential `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil || env.Data.ID == uuid.Nil {
			t.Fatalf("decode envelope: %v", err)
		}
		created = env.Data
	}
	if created.CredentialType != TypeAuth || created.Fingerprint != testFingerprint ||
		created.Reason != "凭据泄漏" || created.RevokedBy != "tester" {
		t.Fatalf("created = %+v", created)
	}

	// 重复登记：409
	w = httptest.NewRecorder()
	serve(h.Create, w, newJSONRequest(t, "POST", "/api/v1/api-security/revoked-credentials",
		`{"credential_type":"auth","fingerprint":"`+testFingerprint+`","reason":"重复"}`))
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d, want 409", w.Code)
	}
	// 同指纹不同类型：允许（201）
	w = httptest.NewRecorder()
	serve(h.Create, w, newJSONRequest(t, "POST", "/api/v1/api-security/revoked-credentials",
		`{"credential_type":"key","fingerprint":"`+testFingerprint+`","reason":"同值不同来源"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("same fingerprint different type status = %d, want 201, body: %s", w.Code, w.Body.String())
	}

	// 列表：总数 2；credential_type 过滤
	w = httptest.NewRecorder()
	serve(h.List, w, newJSONRequest(t, "GET", "/api/v1/api-security/revoked-credentials", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"total":2`) {
		t.Fatalf("list body = %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	serve(h.List, w, newJSONRequest(t, "GET", "/api/v1/api-security/revoked-credentials?credential_type=key", ""))
	if !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("filtered list body = %s", w.Body.String())
	}
	// 非法过滤值：400
	w = httptest.NewRecorder()
	serve(h.List, w, newJSONRequest(t, "GET", "/api/v1/api-security/revoked-credentials?credential_type=bogus", ""))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad filter status = %d, want 400", w.Code)
	}

	// 详情
	w = httptest.NewRecorder()
	serve(h.Get, w, newJSONRequest(t, "GET", "/api/v1/api-security/revoked-credentials/"+created.ID.String(), ""))
	if w.Code != http.StatusOK {
		t.Fatalf("get status = %d", w.Code)
	}

	// 调整：原因 + 到期窗口
	w = httptest.NewRecorder()
	serve(h.Update, w, newJSONRequest(t, "PUT", "/api/v1/api-security/revoked-credentials/"+created.ID.String(),
		`{"reason":"更新原因","effective_from":"2026-01-01T00:00:00Z","effective_until":"2027-01-01T00:00:00Z"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("update status = %d, body: %s", w.Code, w.Body.String())
	}
	if got := repo.items[created.ID]; got.Reason != "更新原因" || got.EffectiveUntil == nil {
		t.Fatalf("updated = %+v", got)
	}
	// PUT 缺 effective_from：400
	w = httptest.NewRecorder()
	serve(h.Update, w, newJSONRequest(t, "PUT", "/api/v1/api-security/revoked-credentials/"+created.ID.String(),
		`{"reason":"x"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("update missing effective_from status = %d, want 400", w.Code)
	}

	// 删除 + 404
	w = httptest.NewRecorder()
	serve(h.Delete, w, newJSONRequest(t, "DELETE", "/api/v1/api-security/revoked-credentials/"+created.ID.String(), ""))
	if w.Code != http.StatusOK {
		t.Fatalf("delete status = %d", w.Code)
	}
	w = httptest.NewRecorder()
	serve(h.Delete, w, newJSONRequest(t, "DELETE", "/api/v1/api-security/revoked-credentials/"+created.ID.String(), ""))
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete again status = %d, want 404", w.Code)
	}

	// 审计：create×2（含同值不同类型）+ update + delete = 4 条
	if len(spy.entries) != 4 {
		t.Fatalf("audit entries = %d, want 4", len(spy.entries))
	}
	if spy.entries[0].Action != "create" || spy.entries[0].ObjectType != "api_revoked_credential" ||
		spy.entries[0].ObjectName != "auth:"+testFingerprint {
		t.Fatalf("audit[0] = %+v", spy.entries[0])
	}
}
