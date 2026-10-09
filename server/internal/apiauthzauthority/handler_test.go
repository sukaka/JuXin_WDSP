// handler_test.go 权威关系接入 HTTP 入口测试：权限矩阵（read/manage/import 分离）、
// 登记/详情/启停/导入/状态视图、404/409 映射、审计、导入成功触发发布。
package apiauthzauthority

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// fakeService 内存 ServiceAPI。
type fakeService struct {
	source    *AuthoritySource
	keys      []SourceKey
	batch     *ImportBatch
	lastBody  []byte
	patchIn   *SourcePatch
	watermark SourceWatermark
}

func (f *fakeService) CreateSource(ctx context.Context, name string, scopes SourceScopes, maxAge *int64, keys []SourceKey) (*AuthoritySource, error) {
	f.source = &AuthoritySource{ID: uuid.New(), Name: name, Status: SourceStatusActive, Scopes: scopes, Version: 1}
	return f.source, nil
}

func (f *fakeService) PatchSource(ctx context.Context, id uuid.UUID, in SourcePatch) (*AuthoritySource, []SourceKey, error) {
	f.patchIn = &in
	if f.source == nil {
		return nil, nil, ErrNotFound
	}
	if in.Version != f.source.Version {
		return nil, nil, ErrVersionConflict
	}
	f.source.Version++
	return f.source, f.keys, nil
}

func (f *fakeService) Import(ctx context.Context, sourceID uuid.UUID, body []byte, actorID uuid.UUID) (*ImportBatch, error) {
	f.lastBody = body
	if f.batch != nil {
		return f.batch, nil
	}
	return &ImportBatch{ID: uuid.New(), SourceID: sourceID, Mode: ModeDelta, Status: BatchApplied}, nil
}

func (f *fakeService) GetSource(ctx context.Context, id uuid.UUID) (*AuthoritySource, error) {
	if f.source == nil || f.source.ID != id {
		return nil, ErrNotFound
	}
	return f.source, nil
}

func (f *fakeService) ListSources(ctx context.Context) ([]AuthoritySource, error) {
	if f.source == nil {
		return []AuthoritySource{}, nil
	}
	return []AuthoritySource{*f.source}, nil
}

func (f *fakeService) ListSourceKeys(ctx context.Context, sourceID uuid.UUID) ([]SourceKey, error) {
	return f.keys, nil
}

func (f *fakeService) ListBatches(ctx context.Context, sourceID uuid.UUID, limit int) ([]ImportBatch, error) {
	return []ImportBatch{}, nil
}

func (f *fakeService) GetWatermark(ctx context.Context, sourceID uuid.UUID) (SourceWatermark, error) {
	return f.watermark, nil
}

func (f *fakeService) ListConflicts(ctx context.Context, status string, limit int) ([]ConflictRecord, error) {
	return []ConflictRecord{}, nil
}

type spyAudits struct{ entries []audits.RecordInput }

func (s *spyAudits) Record(_ context.Context, in audits.RecordInput) error {
	s.entries = append(s.entries, in)
	return nil
}

func injectPerms(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "az-tester", PermsSet: set}
			ctx := authz.WithPrincipal(r.Context(), p)
			ctx = context.WithValue(ctx, response.RequestIDKey, "az-rid")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func noPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { next.ServeHTTP(w, r) })
}

const authBase = "/api/v1/api-security/authz/authorities"

func newAuthMux(svc ServiceAPI, spy auditRecorder, authzFn func(http.Handler) http.Handler) (*http.ServeMux, *Handler) {
	mux := http.NewServeMux()
	h := NewHandler(svc, spy)
	RegisterRoutes(mux, authzFn, h)
	return mux, h
}

func doAuth(t *testing.T, mux http.Handler, method, url, body string) *httptest.ResponseRecorder {
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

// 权限矩阵：GET 需 read；POST/PATCH 需 manage；imports 需 import（三者分离）。
func TestAuthorityPermissionMatrix(t *testing.T) {
	id := uuid.NewString()
	cases := []struct {
		method, path, body string
		perm               string
		wantOK             bool
	}{
		{"GET", authBase, "", PermAuthzRead, true},
		{"GET", authBase + "/" + id, "", PermAuthzRead, true},
		{"GET", authBase + "/" + id + "/status", "", PermAuthzRead, true},
		{"POST", authBase, `{"name":"x"}`, PermAuthorityManage, true},
		{"POST", authBase, `{"name":"x"}`, PermAuthzRead, false},
		{"PATCH", authBase + "/" + id, `{"version":1}`, PermAuthorityManage, true},
		{"PATCH", authBase + "/" + id, `{"version":1}`, PermAuthorityImport, false},
		{"POST", authBase + "/" + id + "/imports", `{}`, PermAuthorityImport, true},
		{"POST", authBase + "/" + id + "/imports", `{}`, PermAuthorityManage, false},
	}
	for _, c := range cases {
		svc := &fakeService{source: &AuthoritySource{ID: uuid.MustParse(id), Name: "x", Version: 1}}
		rr := doAuth(t, func() *http.ServeMux { m, _ := newAuthMux(svc, nil, injectPerms(c.perm)); return m }(), c.method, c.path, c.body)
		if c.wantOK && rr.Code == http.StatusForbidden {
			t.Fatalf("%s %s with %s 不应 403", c.method, c.path, c.perm)
		}
		if !c.wantOK && rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s with %s 应 403, got %d", c.method, c.path, c.perm, rr.Code)
		}
	}
	// 未登录 401
	svc := &fakeService{}
	if rr := doAuth(t, func() *http.ServeMux { m, _ := newAuthMux(svc, nil, noPrincipal); return m }(), "GET", authBase, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("no principal: %d", rr.Code)
	}
}

// 登记 200 + 审计；详情含公钥；PATCH 版本冲突 409；不存在 404。
func TestAuthorityCreateGetPatch(t *testing.T) {
	svc := &fakeService{}
	spy := &spyAudits{}
	mux, _ := newAuthMux(svc, spy, injectPerms(PermAuthorityManage, PermAuthzRead))

	rr := doAuth(t, mux, "POST", authBase,
		`{"name":"crm-prod","scopes":{"tenant_domains":["waf-s5.local"]},"keys":[{"key_id":"k1","public_key_hex":"`+strings.Repeat("ab", 32)+`"}]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	if len(spy.entries) != 1 || spy.entries[0].Action != "create" || spy.entries[0].RiskLevel != "HIGH" {
		t.Fatalf("登记审计不符: %+v", spy.entries)
	}

	// 详情（来源存在时）
	svc.keys = []SourceKey{{KeyID: "k1", PublicKeyHex: strings.Repeat("ab", 32), Status: KeyStatusActive}}
	rr = doAuth(t, mux, "GET", authBase+"/"+svc.source.ID.String(), "")
	var detail struct {
		Data sourceDetail `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &detail)
	if rr.Code != http.StatusOK || len(detail.Data.Keys) != 1 || detail.Data.Name != "crm-prod" {
		t.Fatalf("详情不符: %d %+v", rr.Code, detail.Data)
	}

	// PATCH 版本冲突 409
	rr = doAuth(t, mux, "PATCH", authBase+"/"+svc.source.ID.String(), `{"version":99,"status":"DISABLED"}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("版本冲突应 409: %d", rr.Code)
	}
	// PATCH 正确版本 200
	rr = doAuth(t, mux, "PATCH", authBase+"/"+svc.source.ID.String(), `{"version":1,"status":"DISABLED"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH: %d %s", rr.Code, rr.Body.String())
	}
	// 不存在 404
	rr = doAuth(t, mux, "GET", authBase+"/"+uuid.NewString(), "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("不存在应 404: %d", rr.Code)
	}
}

// 导入：原始体透传 service；APPLIED 触发发布 + 审计；REJECTED 不触发发布。
func TestAuthorityImportFlow(t *testing.T) {
	svc := &fakeService{source: &AuthoritySource{ID: uuid.New(), Name: "x", Version: 1}}
	spy := &spyAudits{}
	mux, h := newAuthMux(svc, spy, injectPerms(PermAuthorityImport))
	published := 0
	h.SetPublishFunc(func(ctx context.Context, uid uuid.UUID, rid string) { published++ })
	body := `{"batch_id":"b1","source_id":"x","mode":"delta","key_id":"k1","items":[],"batch_signature":"sig"}`
	rr := doAuth(t, mux, "POST", authBase+"/"+svc.source.ID.String()+"/imports", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rr.Code, rr.Body.String())
	}
	if string(svc.lastBody) != body {
		t.Fatalf("原始体须透传: %q", svc.lastBody)
	}
	if published != 1 {
		t.Fatalf("APPLIED 应触发发布: %d", published)
	}
	// REJECTED 不触发发布 + 失败审计
	svc.batch = &ImportBatch{ID: uuid.New(), SourceID: svc.source.ID, Mode: ModeDelta, Status: BatchRejected, Error: "校验链第 4 步失败"}
	rr = doAuth(t, mux, "POST", authBase+"/"+svc.source.ID.String()+"/imports", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("rejected import: %d", rr.Code)
	}
	if published != 1 {
		t.Fatal("REJECTED 不得触发发布")
	}
	var sawFail bool
	for _, e := range spy.entries {
		if e.Result == audits.ResultFailure {
			sawFail = true
		}
	}
	if !sawFail {
		t.Fatalf("拒绝批次应记失败审计: %+v", spy.entries)
	}
}

// 状态视图：gap_from 非空 → AUTHZ_SOURCE_GAP；零水位 → NO_DATA；正常 → OK。
func TestAuthorityStatusGapView(t *testing.T) {
	mkSvc := func(wm SourceWatermark) *fakeService {
		return &fakeService{source: &AuthoritySource{ID: uuid.New(), Name: "x", Version: 1}, watermark: wm}
	}
	for _, tc := range []struct {
		wm   SourceWatermark
		want string
	}{
		{SourceWatermark{}, "NO_DATA"},
		{SourceWatermark{LastSequence: 5}, "OK"},
		{SourceWatermark{LastSequence: 5, GapFrom: uint64Ptr(3)}, "AUTHZ_SOURCE_GAP"},
	} {
		fs := mkSvc(tc.wm)
		mux, _ := newAuthMux(fs, nil, injectPerms(PermAuthzRead))
		rr := doAuth(t, mux, "GET", authBase+"/"+fs.source.ID.String()+"/status", "")
		if !strings.Contains(rr.Body.String(), `"gap_status":"`+tc.want+`"`) {
			t.Fatalf("gap 视图应 %s: %s", tc.want, rr.Body.String())
		}
	}
}

func uint64Ptr(v uint64) *uint64 { return &v }
