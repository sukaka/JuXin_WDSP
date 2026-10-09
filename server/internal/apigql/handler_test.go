// handler_test.go GraphQL 策略管理 API 测试：权限矩阵（read/edit 分离）、
// 默认视图（无行 enabled=false）、写入校验 400、应用不存在 404、审计、删除。
package apigql

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
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/response"
)

// fakeStore 内存策略存储。
type fakeStore struct {
	views   map[uuid.UUID]PolicyView
	upsertN int
	deleteN int
	guard   map[string]*gatewayconfig.GuardGraphQLPolicy
}

func newFakeStore() *fakeStore { return &fakeStore{views: map[uuid.UUID]PolicyView{}} }

func (f *fakeStore) GetPolicy(ctx context.Context, appID uuid.UUID) (PolicyView, error) {
	if v, ok := f.views[appID]; ok {
		return v, nil
	}
	return PolicyView{ApplicationID: appID.String()}, nil
}

func (f *fakeStore) UpsertPolicy(ctx context.Context, appID uuid.UUID, p Policy, operatorID uuid.UUID) (PolicyView, error) {
	f.upsertN++
	v := PolicyView{ApplicationID: appID.String(), Policy: p, Version: 1}
	f.views[appID] = v
	return v, nil
}

func (f *fakeStore) DeletePolicy(ctx context.Context, appID uuid.UUID, operatorID uuid.UUID) error {
	f.deleteN++
	delete(f.views, appID)
	return nil
}

func (f *fakeStore) ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardGraphQLPolicy, error) {
	return f.guard, nil
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
			p := &authz.Principal{UserID: uuid.New(), Username: "gql-tester", PermsSet: set}
			ctx := authz.WithPrincipal(r.Context(), p)
			ctx = context.WithValue(ctx, response.RequestIDKey, "gql-rid")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func noPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { next.ServeHTTP(w, r) })
}

var testAppID = uuid.New()

func gqlPath() string { return "/api/v1/api-security/apps/" + testAppID.String() + "/graphql-policy" }

func newGQLMux(store Store, spy auditRecorder, authzFn func(http.Handler) http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, authzFn, NewHandler(store, spy))
	return mux
}

func doGQL(t *testing.T, mux http.Handler, method, url, body string) *httptest.ResponseRecorder {
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

// 权限矩阵：GET 未登录 401 / 无权限 403 / api_policy.read 200；PUT/DELETE 需 api_policy.edit。
func TestGQLPolicyPermissionMatrix(t *testing.T) {
	body := `{"enabled":true,"budget":{"per_request_budget":100}}`
	if rr := doGQL(t, newGQLMux(newFakeStore(), nil, noPrincipal), "GET", gqlPath(), ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("GET no principal: %d", rr.Code)
	}
	if rr := doGQL(t, newGQLMux(newFakeStore(), nil, injectPerms("other.read")), "GET", gqlPath(), ""); rr.Code != http.StatusForbidden {
		t.Fatalf("GET wrong perm: %d", rr.Code)
	}
	if rr := doGQL(t, newGQLMux(newFakeStore(), nil, injectPerms(permPolicyRead)), "GET", gqlPath(), ""); rr.Code != http.StatusOK {
		t.Fatalf("GET read: %d %s", rr.Code, rr.Body.String())
	}
	if rr := doGQL(t, newGQLMux(newFakeStore(), nil, injectPerms(permPolicyRead)), "PUT", gqlPath(), body); rr.Code != http.StatusForbidden {
		t.Fatalf("PUT read-only: %d（写需 edit）", rr.Code)
	}
	if rr := doGQL(t, newGQLMux(newFakeStore(), nil, injectPerms(permPolicyEdit)), "PUT", gqlPath(), body); rr.Code != http.StatusOK {
		t.Fatalf("PUT edit: %d %s", rr.Code, rr.Body.String())
	}
	if rr := doGQL(t, newGQLMux(newFakeStore(), nil, injectPerms(permPolicyRead)), "DELETE", gqlPath(), ""); rr.Code != http.StatusForbidden {
		t.Fatalf("DELETE read-only: %d", rr.Code)
	}
}

// GET 无行 → 200 默认视图（enabled=false、version=0；「无段=关闭」非 404）。
func TestGQLPolicyGetDefaultView(t *testing.T) {
	rr := doGQL(t, newGQLMux(newFakeStore(), nil, injectPerms(permPolicyRead)), "GET", gqlPath(), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET: %d", rr.Code)
	}
	var body struct {
		Data PolicyView `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.Enabled || body.Data.Version != 0 || body.Data.ApplicationID != testAppID.String() {
		t.Fatalf("默认视图不符: %+v", body.Data)
	}
	// 坏 id 400
	if rr := doGQL(t, newGQLMux(newFakeStore(), nil, injectPerms(permPolicyRead)),
		"GET", "/api/v1/api-security/apps/not-a-uuid/graphql-policy", ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad id: %d", rr.Code)
	}
}

// PUT 校验：合法写入 200 + 版本 + 审计；非法 digest/负值/未知字段 400。
func TestGQLPolicyPutValidationAndAudit(t *testing.T) {
	store := newFakeStore()
	spy := &spyAudits{}
	mux := newGQLMux(store, spy, injectPerms(permPolicyEdit))
	good := `{"enabled":true,"limits":{"max_doc_bytes":131072,"max_depth":8},` +
		`"weights":{"default_field_weight":2,"fields":{"Query.users":{"weight":5,"list_bound":50}}},` +
		`"budget":{"per_request_budget":100,"window_seconds":60,"window_budget":1000,"anonymous_budget":200},` +
		`"trusted_doc_digests":["0123456789abcdef0123456789abcdef"]}`
	rr := doGQL(t, mux, "PUT", gqlPath(), good)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT good: %d %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Data PolicyView `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if !body.Data.Enabled || body.Data.Version != 1 || body.Data.Limits.MaxDocBytes != 131072 ||
		body.Data.Weights.DefaultFieldWeight != 2 || body.Data.Weights.Fields["Query.users"].ListBound != 50 ||
		body.Data.Budget.AnonymousBudget != 200 || len(body.Data.TrustedDocDigests) != 1 {
		t.Fatalf("写入视图不符: %+v", body.Data)
	}
	if len(spy.entries) != 1 || spy.entries[0].Action != "update" || spy.entries[0].ObjectType != "api_graphql_policy" {
		t.Fatalf("审计不符: %+v", spy.entries)
	}

	for _, bad := range []string{
		`{"enabled":true,"trusted_doc_digests":["xyz"]}`,                              // digest 非 32hex
		`{"enabled":true,"trusted_doc_digests":["0123456789ABCDEF0123456789ABCDEF"]}`, // 大写 hex
		`{"enabled":true,"budget":{"per_request_budget":-1}}`,                         // 负值
		`{"enabled":true,"limits":{"max_doc_bytes":999999999}}`,                       // 超 64MiB
		`{"enabled":true,"nope":1}`,                                                   // 未知字段
		`{bad`,                                                                        // 坏 JSON
	} {
		if rr := doGQL(t, mux, "PUT", gqlPath(), bad); rr.Code != http.StatusBadRequest {
			t.Fatalf("PUT bad %.50s: got %d body=%s", bad, rr.Code, rr.Body.String())
		}
	}
	if store.upsertN != 1 {
		t.Fatalf("非法写入不得落库: upsert=%d", store.upsertN)
	}
}

// DELETE → 200 + 行删除 + 审计。
func TestGQLPolicyDelete(t *testing.T) {
	store := newFakeStore()
	store.views[testAppID] = PolicyView{ApplicationID: testAppID.String(), Policy: Policy{Enabled: true}, Version: 3}
	spy := &spyAudits{}
	mux := newGQLMux(store, spy, injectPerms(permPolicyEdit, permPolicyRead))
	rr := doGQL(t, mux, "DELETE", gqlPath(), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("DELETE: %d %s", rr.Code, rr.Body.String())
	}
	if _, ok := store.views[testAppID]; ok {
		t.Fatal("删除后行应不存在")
	}
	if len(spy.entries) != 1 || spy.entries[0].Action != "delete" {
		t.Fatalf("删除审计不符: %+v", spy.entries)
	}
	// GET 回默认视图
	rr = doGQL(t, mux, "GET", gqlPath(), "")
	if !strings.Contains(rr.Body.String(), `"enabled":false`) {
		t.Fatalf("删除后应为关闭默认视图: %s", rr.Body.String())
	}
}
