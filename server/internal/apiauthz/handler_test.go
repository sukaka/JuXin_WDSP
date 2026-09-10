// handler_test.go 授权实体层接口测试：权限、角色基线 CRUD/确认、对象权属只读查询、
// 字段权限 CRUD（默认行/覆盖行语义）、BOLA 评估接口。
package apiauthz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// testPerms 本端点组全部权限点。
var testPerms = []string{PermAuthzRead, PermAuthzManage, PermRelationManage, PermEvidenceRead}

// injectPrincipal 模拟认证链：注入持有全部权限点的主体与 Request ID。
func injectPrincipal(next http.Handler) http.Handler {
	perms := map[string]bool{}
	for _, p := range testPerms {
		perms[p] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: perms}
		ctx := authz.WithPrincipal(r.Context(), p)
		ctx = context.WithValue(ctx, response.RequestIDKey, "test-rid")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// noPerms 模拟无权限主体（权限点检查 403）。
func noPerms(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "outsider", PermsSet: map[string]bool{}}
		next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
	})
}

func authzReadOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "reader", PermsSet: map[string]bool{PermAuthzRead: true}}
		next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
	})
}

func principalWithPerms(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, perm := range perms {
		set[perm] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "matrix", PermsSet: set}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}
}

func newTestMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPrincipal, h)
	return mux
}

func doJSON(t *testing.T, mux http.Handler, method, url string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, url, reader)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// decodeData 解码统一响应的 data 字段。
func decodeData(t *testing.T, rr *httptest.ResponseRecorder, dst any) {
	t.Helper()
	decodeEnvelopeData(t, rr.Body.Bytes(), dst)
}

func decodeEnvelopeData(t *testing.T, body []byte, dst any) {
	t.Helper()
	var env struct {
		Code string          `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode: %v body=%s", err, body)
	}
	if env.Code != "SUCCESS" {
		t.Fatalf("code=%s body=%s", env.Code, body)
	}
	if err := json.Unmarshal(env.Data, dst); err != nil {
		t.Fatalf("decode data: %v body=%s", err, body)
	}
}

// seedEndpoint 登记端点并返回 ID（角色基线/字段权限引用必须有端点资产）。
func seedEndpoint(t *testing.T, store *MemStore, key, template string) uuid.UUID {
	t.Helper()
	return store.addEndpoint(key, template)
}

// TestPermissionGuard 无权限点主体一律 403。
func TestPermissionGuard(t *testing.T) {
	store := NewMemStore()
	mux := http.NewServeMux()
	RegisterRoutes(mux, noPerms, NewHandler(store, nil))
	for _, tc := range []struct{ method, url string }{
		{http.MethodGet, "/api/v1/api-security/authz/role-baselines"},
		{http.MethodPost, "/api/v1/api-security/authz/role-baselines"},
		{http.MethodGet, "/api/v1/api-security/authz/ownership"},
		{http.MethodGet, "/api/v1/api-security/authz/field-permissions"},
		{http.MethodPost, "/api/v1/api-security/authz/field-permissions"},
		{http.MethodGet, "/api/v1/api-security/authz/evaluate?endpoint_id=" + uuid.NewString() + "&object_id=1"},
		{http.MethodGet, "/api/v1/api-security/authz/relations/candidates"},
		{http.MethodPost, "/api/v1/api-security/authz/relations/candidates/" + uuid.NewString() + "/confirm"},
		{http.MethodPost, "/api/v1/api-security/authz/relations/candidates/" + uuid.NewString() + "/reject"},
		{http.MethodPost, "/api/v1/api-security/authz/relations"},
		{http.MethodPost, "/api/v1/api-security/authz/relations/" + uuid.NewString() + "/revoke"},
		{http.MethodPost, "/api/v1/api-security/authz/relations/" + uuid.NewString() + "/reauthorize"},
		{http.MethodGet, "/api/v1/api-security/authz/decisions"},
		{http.MethodGet, "/api/v1/api-security/authz/decisions/" + uuid.NewString()},
		{http.MethodGet, "/api/v1/api-security/authz/coverage"},
	} {
		rr := doJSON(t, mux, tc.method, tc.url, map[string]any{})
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s status=%d want 403", tc.method, tc.url, rr.Code)
		}
	}
}

func TestReauthorizeRelationIsExplicitAuditedAndPublishes(t *testing.T) {
	store := NewMemStore()
	appID := uuid.New()
	now := time.Now().UTC()
	oldConfirmed := now.Add(-time.Hour)
	rel := &ObjectRelation{ID: uuid.New(), ApplicationID: appID, ObjectType: "invoice", ObjectRef: "objref:reauthorize", PrincipalID: "user-1", Relation: RelationOwner, Source: RelationSourceManual, Status: RelationStatusRevoked, ValidFrom: now.Add(-2 * time.Hour), ConfirmedBy: "old", ConfirmedAt: oldConfirmed, Reason: "old", CreatedAt: oldConfirmed, UpdatedAt: oldConfirmed}
	store.relations[rel.ID] = rel
	var published int
	h := NewHandler(store, nil)
	h.SetPublishFunc(func(context.Context, uuid.UUID, string) { published++ })
	validFrom, validUntil := now.Add(time.Minute), now.Add(time.Hour)
	rr := doJSON(t, newTestMux(h), http.MethodPost, "/api/v1/api-security/authz/relations/"+rel.ID.String()+"/reauthorize", map[string]any{"reason": "ticket-reauthorize", "valid_from": validFrom, "valid_until": validUntil})
	if rr.Code != http.StatusOK {
		t.Fatalf("reauthorize status=%d body=%s", rr.Code, rr.Body.String())
	}
	var got ObjectRelation
	decodeData(t, rr, &got)
	if got.Status != RelationStatusConfirmed || got.ConfirmedBy != "tester" || got.Reason != "ticket-reauthorize" || published != 1 || !got.ConfirmedAt.After(oldConfirmed) {
		t.Fatalf("relation=%+v published=%d", got, published)
	}
	if got.ValidFrom.UTC() != validFrom.UTC() || got.ValidUntil == nil || !got.ValidUntil.Equal(validUntil) {
		t.Fatalf("validity=%v/%v want %v/%v", got.ValidFrom, got.ValidUntil, validFrom, validUntil)
	}
	if rel.PreviousStatus != RelationStatusRevoked {
		t.Fatalf("audit trace previous status=%q, want %q", rel.PreviousStatus, RelationStatusRevoked)
	}
	rr = doJSON(t, newTestMux(h), http.MethodPost, "/api/v1/api-security/authz/relations/"+rel.ID.String()+"/reauthorize", map[string]any{"reason": "must-conflict", "valid_from": validFrom})
	if rr.Code != http.StatusConflict || published != 1 {
		t.Fatalf("confirmed retry status=%d published=%d body=%s", rr.Code, published, rr.Body.String())
	}
}

func TestReauthorizeExpiredAndCreateRemainExplicit(t *testing.T) {
	store := NewMemStore()
	appID := uuid.New()
	now := time.Now().UTC()
	until := now.Add(-time.Minute)
	rel := &ObjectRelation{ID: uuid.New(), ApplicationID: appID, ObjectType: "invoice", ObjectRef: "objref:expired", PrincipalID: "user-1", Relation: RelationOwner, Source: RelationSourceManual, Status: RelationStatusExpired, ValidFrom: now.Add(-time.Hour), ValidUntil: &until, ConfirmedBy: "seed", ConfirmedAt: now, Reason: "expired", CreatedAt: now, UpdatedAt: now}
	store.relations[rel.ID] = rel
	duplicate := *rel
	duplicate.ID = uuid.Nil
	duplicate.Status = ""
	if err := store.CreateObjectRelation(context.Background(), &duplicate); !errors.Is(err, ErrRelationConflict) {
		t.Fatalf("ordinary create after expiry err=%v, want conflict", err)
	}
	if _, err := store.ReauthorizeObjectRelation(context.Background(), rel.ID, ReauthorizeRelationInput{Reason: "", ValidFrom: now}); err == nil {
		t.Fatal("empty reason accepted")
	}
	if _, err := store.ReauthorizeObjectRelation(context.Background(), rel.ID, ReauthorizeRelationInput{
		Reason: strings.Repeat("界", maxReauthorizeReasonRunes+1), ValidFrom: now, ConfirmedBy: "operator",
	}); err == nil {
		t.Fatal("reason exceeding the 512-rune limit must be rejected")
	}
	reauthorized, err := store.ReauthorizeObjectRelation(context.Background(), rel.ID, ReauthorizeRelationInput{Reason: "renewed", ValidFrom: now, ConfirmedBy: "operator"})
	if err != nil || reauthorized.Status != RelationStatusConfirmed {
		t.Fatalf("reauthorized=%+v err=%v", reauthorized, err)
	}
	if reauthorized.PreviousStatus != RelationStatusExpired {
		t.Fatalf("audit trace previous status=%q, want %q", reauthorized.PreviousStatus, RelationStatusExpired)
	}
}

func TestRevokeRelationRequiresPermissionAuditsAndPublishes(t *testing.T) {
	store := NewMemStore()
	appID := uuid.New()
	now := time.Now().UTC()
	rel := &ObjectRelation{ID: uuid.New(), ApplicationID: appID, ObjectType: "invoice", ObjectRef: "objref:test", PrincipalID: "user-1", Relation: RelationOwner, Source: RelationSourceManual, Status: RelationStatusConfirmed, ValidFrom: now.Add(-time.Hour), ConfirmedBy: "seed", ConfirmedAt: now, Reason: "seed", CreatedAt: now, UpdatedAt: now}
	store.relations[rel.ID] = rel
	var published int
	h := NewHandler(store, nil)
	h.SetPublishFunc(func(context.Context, uuid.UUID, string) { published++ })
	rr := doJSON(t, newTestMux(h), http.MethodPost, "/api/v1/api-security/authz/relations/"+rel.ID.String()+"/revoke", map[string]any{"reason": "ticket-42"})
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", rr.Code, rr.Body.String())
	}
	var got ObjectRelation
	decodeData(t, rr, &got)
	if got.Status != RelationStatusRevoked || published != 1 {
		t.Fatalf("relation=%+v published=%d", got, published)
	}
	if _, err := store.RevokeObjectRelation(context.Background(), rel.ID); !errors.Is(err, ErrRelationConflict) {
		t.Fatalf("second revoke err=%v, want conflict", err)
	}
}

func TestExpireRelationsUsesLocalTimeAndIsIdempotent(t *testing.T) {
	store := NewMemStore()
	appID := uuid.New()
	now := time.Now().UTC()
	for _, until := range []time.Time{now.Add(-time.Second), now.Add(time.Second)} {
		id := uuid.New()
		store.relations[id] = &ObjectRelation{ID: id, ApplicationID: appID, ObjectType: "invoice", ObjectRef: "objref:" + id.String(), PrincipalID: "user-1", Relation: RelationOwner, Source: RelationSourceManual, Status: RelationStatusConfirmed, ValidFrom: now.Add(-time.Hour), ValidUntil: &until, ConfirmedBy: "seed", ConfirmedAt: now, Reason: "seed", CreatedAt: now, UpdatedAt: now}
	}
	expired, err := store.ExpireObjectRelations(context.Background(), now)
	if err != nil || len(expired) != 1 || expired[0].Status != RelationStatusExpired {
		t.Fatalf("expired=%+v err=%v", expired, err)
	}
	if expired, err = store.ExpireObjectRelations(context.Background(), now); err != nil || len(expired) != 0 {
		t.Fatalf("second expiration=%+v err=%v", expired, err)
	}
}

func TestAuthorizationPermissionMatrix(t *testing.T) {
	request := func(t *testing.T, auth func(http.Handler) http.Handler, method, path string, body any) int {
		t.Helper()
		mux := http.NewServeMux()
		RegisterRoutes(mux, auth, NewHandler(NewMemStore(), nil))
		return doJSON(t, mux, method, path, body).Code
	}

	// relation_manage is deliberately separate from the generic read/manage
	// permissions: a reviewer may list candidates but cannot mutate relations.
	relationCreate := "/api/v1/api-security/authz/relations"
	candidateConfirm := "/api/v1/api-security/authz/relations/candidates/" + uuid.NewString() + "/confirm"
	if code := request(t, principalWithPerms(PermAuthzRead), http.MethodPost, relationCreate, map[string]any{}); code != http.StatusForbidden {
		t.Fatalf("authz_read must not create relation: status=%d", code)
	}
	if code := request(t, principalWithPerms(PermAuthzManage), http.MethodPost, candidateConfirm, map[string]any{"relation": "OWNER"}); code != http.StatusForbidden {
		t.Fatalf("authz_manage must not confirm relation candidate: status=%d", code)
	}
	if code := request(t, principalWithPerms(PermRelationManage), http.MethodPost, relationCreate, map[string]any{}); code == http.StatusForbidden {
		t.Fatalf("relation_manage should pass relation route permission: status=%d", code)
	}

	// evidence_read alone cannot bypass the generic decision read gate.
	detail := "/api/v1/api-security/authz/decisions/" + uuid.NewString()
	if code := request(t, principalWithPerms(PermEvidenceRead), http.MethodGet, detail, nil); code != http.StatusForbidden {
		t.Fatalf("evidence_read alone must not read decision detail: status=%d", code)
	}
	if code := request(t, principalWithPerms(PermAuthzRead), http.MethodGet, detail, nil); code != http.StatusForbidden {
		t.Fatalf("authz_read alone must not read decision evidence: status=%d", code)
	}
}

func TestAuthorizationApplicationFiltersCoverRelationsCandidatesAndCoverage(t *testing.T) {
	store := NewMemStore()
	appA, appB := uuid.New(), uuid.New()
	store.addRelationCandidate(RelationCandidate{ApplicationID: appA, ObjectType: "invoice", ObjectRef: "objref:a"})
	store.addRelationCandidate(RelationCandidate{ApplicationID: appB, ObjectType: "invoice", ObjectRef: "objref:b"})
	store.relations[uuid.New()] = &ObjectRelation{
		ApplicationID: appA, ObjectType: "invoice", ObjectRef: "objref:a", PrincipalID: "principal-a",
		Relation: RelationOwner, Source: RelationSourceManual, Status: RelationStatusConfirmed,
		ValidFrom: time.Now().UTC(), CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	store.relations[uuid.New()] = &ObjectRelation{
		ApplicationID: appB, ObjectType: "invoice", ObjectRef: "objref:b", PrincipalID: "principal-b",
		Relation: RelationOwner, Source: RelationSourceManual, Status: RelationStatusConfirmed,
		ValidFrom: time.Now().UTC(), CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	mux := newTestMux(NewHandler(store, nil))

	for _, tc := range []struct {
		path string
		want int64
	}{
		{"/api/v1/api-security/authz/relations/candidates?application_id=" + appA.String(), 1},
		{"/api/v1/api-security/authz/relations?application_id=" + appA.String(), 1},
	} {
		var page struct {
			Total int64 `json:"total"`
		}
		rr := doJSON(t, mux, http.MethodGet, tc.path, nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("filtered list %s status=%d body=%s", tc.path, rr.Code, rr.Body.String())
		}
		decodeData(t, rr, &page)
		if page.Total != tc.want {
			t.Fatalf("filtered list %s total=%d want %d", tc.path, page.Total, tc.want)
		}
	}

	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/coverage?application_id="+appA.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("filtered coverage status=%d body=%s", rr.Code, rr.Body.String())
	}
	var coverage AuthorizationCoverage
	decodeData(t, rr, &coverage)
	if coverage.ApplicationID == nil || *coverage.ApplicationID != appA || coverage.PendingCandidates != 1 || coverage.ConfirmedRelations != 1 {
		t.Fatalf("filtered coverage=%+v", coverage)
	}
}

func TestAuthorizationDecisionDetailPermissionAndApplicationIsolation(t *testing.T) {
	store := NewMemStore()
	appA, appB := uuid.New(), uuid.New()
	d := store.addAuthorizationDecision(AuthorizationDecision{
		ApplicationID: &appA, EndpointKey: "GET /v1/invoices/{id}", PolicyVersion: "authz-v1",
		Decision: "OBSERVE_VIOLATION", Checks: []any{"identity", "OWNER"},
		Evidence: map[string]any{"object_ref": "hmac:abc", "principal": "hmac:p1"},
	})

	fullMux := newTestMux(NewHandler(store, nil))
	rr := doJSON(t, fullMux, http.MethodGet,
		"/api/v1/api-security/authz/decisions/"+d.ID.String()+"?application_id="+appA.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("detail status=%d body=%s", rr.Code, rr.Body.String())
	}
	var got AuthorizationDecision
	decodeData(t, rr, &got)
	if got.ID != d.ID || got.ApplicationID == nil || *got.ApplicationID != appA || got.Evidence["object_ref"] != "hmac:abc" {
		t.Fatalf("detail=%+v", got)
	}
	var fullPage struct {
		Items []AuthorizationDecision `json:"items"`
		Total int64                   `json:"total"`
	}
	rr = doJSON(t, fullMux, http.MethodGet,
		"/api/v1/api-security/authz/decisions?application_id="+appA.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("full list status=%d body=%s", rr.Code, rr.Body.String())
	}
	decodeData(t, rr, &fullPage)
	if fullPage.Total != 1 || len(fullPage.Items) != 1 || fullPage.Items[0].Evidence["principal"] != "hmac:p1" {
		t.Fatalf("full list=%+v", fullPage)
	}

	readOnlyMux := http.NewServeMux()
	RegisterRoutes(readOnlyMux, authzReadOnly, NewHandler(store, nil))
	var redactedPage struct {
		Items []AuthorizationDecision `json:"items"`
		Total int64                   `json:"total"`
	}
	rr = doJSON(t, readOnlyMux, http.MethodGet,
		"/api/v1/api-security/authz/decisions?application_id="+appA.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("read-only list status=%d body=%s", rr.Code, rr.Body.String())
	}
	decodeData(t, rr, &redactedPage)
	if redactedPage.Total != 1 || len(redactedPage.Items) != 1 || redactedPage.Items[0].Evidence != nil {
		t.Fatalf("read-only list=%+v", redactedPage)
	}
	rr = doJSON(t, readOnlyMux, http.MethodGet, "/api/v1/api-security/authz/decisions/"+d.ID.String(), nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("without evidence_read status=%d body=%s", rr.Code, rr.Body.String())
	}

	// A caller asking for another application must not learn whether the row exists.
	rr = doJSON(t, fullMux, http.MethodGet,
		"/api/v1/api-security/authz/decisions/"+d.ID.String()+"?application_id="+appB.String(), nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("cross-application status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, fullMux, http.MethodGet, "/api/v1/api-security/authz/decisions/"+uuid.NewString(), nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown decision status=%d body=%s", rr.Code, rr.Body.String())
	}
}

// TestAuthorizationHTTPPermissionAndApplicationIsolation exercises the
// management routes through a real HTTP server/client boundary. The in-process
// route tests above catch handler behavior; this test also verifies that
// middleware, path matching, JSON encoding, and application scoping remain
// intact after crossing the HTTP boundary.
func TestAuthorizationHTTPPermissionAndApplicationIsolation(t *testing.T) {
	store := NewMemStore()
	appA, appB := uuid.New(), uuid.New()
	principalID := "principal-http-a"
	candidate := store.addRelationCandidate(RelationCandidate{
		ApplicationID: appA, ObjectType: "invoice", ObjectRef: "objref:http-a",
		PrincipalID: &principalID, Source: CandidateSourceObserved,
	})
	candidateB := store.addRelationCandidate(RelationCandidate{
		ApplicationID: appB, ObjectType: "invoice", ObjectRef: "objref:http-b",
		PrincipalID: &principalID, Source: CandidateSourceObserved,
	})
	decision := store.addAuthorizationDecision(AuthorizationDecision{
		ApplicationID: &appA, EndpointKey: "GET /v1/invoices/{id}", PolicyVersion: "authz-v1",
		Decision: "OBSERVE_VIOLATION", Checks: []any{"BOLA"},
		Evidence: map[string]any{"object_ref": "hmac:http-object"},
	})

	newServer := func(auth func(http.Handler) http.Handler) *httptest.Server {
		mux := http.NewServeMux()
		RegisterRoutes(mux, auth, NewHandler(store, nil))
		return httptest.NewServer(mux)
	}
	request := func(t *testing.T, client *http.Client, baseURL, method, path string, body any) (int, []byte) {
		t.Helper()
		var payload io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			payload = bytes.NewReader(raw)
		}
		req, err := http.NewRequest(method, baseURL+path, payload)
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		responseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, responseBody
	}

	fullServer := newServer(injectPrincipal)
	defer fullServer.Close()
	client := fullServer.Client()
	status, body := request(t, client, fullServer.URL, http.MethodGet,
		"/api/v1/api-security/authz/relations/candidates?application_id="+appA.String(), nil)
	if status != http.StatusOK {
		t.Fatalf("candidate list status=%d body=%s", status, body)
	}
	var candidates struct {
		Total int64 `json:"total"`
	}
	decodeEnvelopeData(t, body, &candidates)
	if candidates.Total != 1 {
		t.Fatalf("candidate list total=%d want 1", candidates.Total)
	}

	status, body = request(t, client, fullServer.URL, http.MethodPost,
		"/api/v1/api-security/authz/relations/candidates/"+candidate.ID.String()+"/confirm",
		map[string]any{"relation": "OWNER", "reason": "http boundary review"})
	if status != http.StatusOK {
		t.Fatalf("candidate confirm status=%d body=%s", status, body)
	}
	status, body = request(t, client, fullServer.URL, http.MethodGet,
		"/api/v1/api-security/authz/relations?application_id="+appA.String(), nil)
	if status != http.StatusOK {
		t.Fatalf("relation list status=%d body=%s", status, body)
	}
	var relations struct {
		Total int64 `json:"total"`
	}
	decodeEnvelopeData(t, body, &relations)
	if relations.Total != 1 {
		t.Fatalf("relation list total=%d want 1", relations.Total)
	}

	status, body = request(t, client, fullServer.URL, http.MethodGet,
		"/api/v1/api-security/authz/decisions/"+decision.ID.String()+"?application_id="+appA.String(), nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"object_ref":"hmac:http-object"`)) {
		t.Fatalf("same-application detail status=%d body=%s", status, body)
	}
	status, body = request(t, client, fullServer.URL, http.MethodGet,
		"/api/v1/api-security/authz/decisions/"+decision.ID.String()+"?application_id="+appB.String(), nil)
	if status != http.StatusNotFound {
		t.Fatalf("cross-application detail status=%d body=%s", status, body)
	}
	relationServer := newServer(principalWithPerms(PermRelationManage))
	defer relationServer.Close()
	status, body = request(t, relationServer.Client(), relationServer.URL, http.MethodPost,
		"/api/v1/api-security/authz/relations/candidates/"+candidateB.ID.String()+"/confirm",
		map[string]any{"relation": "OWNER", "reason": "relation manager review"})
	if status != http.StatusOK {
		t.Fatalf("relation_manage candidate confirm status=%d body=%s", status, body)
	}

	readOnlyServer := newServer(authzReadOnly)
	defer readOnlyServer.Close()
	status, body = request(t, readOnlyServer.Client(), readOnlyServer.URL, http.MethodGet,
		"/api/v1/api-security/authz/decisions?application_id="+appA.String(), nil)
	if status != http.StatusOK {
		t.Fatalf("read-only decision list status=%d body=%s", status, body)
	}
	var readOnlyPage struct {
		Items []AuthorizationDecision `json:"items"`
	}
	decodeEnvelopeData(t, body, &readOnlyPage)
	if len(readOnlyPage.Items) != 1 || readOnlyPage.Items[0].Evidence != nil {
		t.Fatalf("read-only decision list=%+v", readOnlyPage)
	}
	status, body = request(t, readOnlyServer.Client(), readOnlyServer.URL, http.MethodGet,
		"/api/v1/api-security/authz/decisions/"+decision.ID.String(), nil)
	if status != http.StatusForbidden {
		t.Fatalf("read-only decision detail status=%d body=%s", status, body)
	}

	readServer := newServer(principalWithPerms(PermAuthzRead))
	defer readServer.Close()
	status, body = request(t, readServer.Client(), readServer.URL, http.MethodPost,
		"/api/v1/api-security/authz/relations", map[string]any{})
	if status != http.StatusForbidden {
		t.Fatalf("authz_read relation create status=%d body=%s", status, body)
	}
	manageServer := newServer(principalWithPerms(PermAuthzManage))
	defer manageServer.Close()
	status, body = request(t, manageServer.Client(), manageServer.URL, http.MethodPost,
		"/api/v1/api-security/authz/relations/candidates/"+uuid.NewString()+"/confirm",
		map[string]any{"relation": "OWNER", "reason": "must be forbidden"})
	if status != http.StatusForbidden {
		t.Fatalf("authz_manage candidate confirm status=%d body=%s", status, body)
	}
}

func TestTrustedRelationWorkflow(t *testing.T) {
	store := NewMemStore()
	appID := uuid.New()
	legacy := store.addRelationCandidate(RelationCandidate{
		ApplicationID: appID, ObjectType: "invoice", ObjectRef: "objref:legacy",
		LegacyIdentityFingerprint: strPtr("old-fingerprint"), Source: CandidateSourceObserved,
	})
	principal := "principal-hmac-a"
	verified := store.addRelationCandidate(RelationCandidate{
		ApplicationID: appID, ObjectType: "invoice", ObjectRef: "objref:verified",
		PrincipalID: &principal, Source: CandidateSourceObserved,
	})
	mux := newTestMux(NewHandler(store, nil))

	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/relations/candidates/"+legacy.ID.String()+"/confirm",
		map[string]any{"relation": "OWNER", "reason": "reviewed evidence"})
	if rr.Code != http.StatusConflict {
		t.Fatalf("legacy confirm status=%d want 409 body=%s", rr.Code, rr.Body.String())
	}

	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/relations/candidates/"+verified.ID.String()+"/confirm",
		map[string]any{"relation": "OWNER", "reason": "verified create binding"})
	if rr.Code != http.StatusOK {
		t.Fatalf("verified confirm status=%d body=%s", rr.Code, rr.Body.String())
	}
	var rel ObjectRelation
	decodeData(t, rr, &rel)
	if rel.PrincipalID != principal || rel.Status != RelationStatusConfirmed || rel.Relation != RelationOwner {
		t.Fatalf("relation=%+v", rel)
	}

	// 并发/重复确认必须冲突，不得重复创建 confirmed 关系。
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/relations/candidates/"+verified.ID.String()+"/confirm",
		map[string]any{"relation": "OWNER", "reason": "retry"})
	if rr.Code != http.StatusConflict {
		t.Fatalf("repeat confirm status=%d want 409", rr.Code)
	}

	var page struct {
		Items []ObjectRelation `json:"items"`
		Total int64            `json:"total"`
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/relations?application_id="+appID.String(), nil)
	decodeData(t, rr, &page)
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("relations=%+v", page)
	}
}

func TestTrustedRelationConfirmationTriggersConfiguredPublish(t *testing.T) {
	store := NewMemStore()
	appID := uuid.New()
	legacy := store.addRelationCandidate(RelationCandidate{
		ApplicationID: appID, ObjectType: "invoice", ObjectRef: "objref:legacy-publish",
		LegacyIdentityFingerprint: strPtr("legacy-fingerprint"), Source: CandidateSourceObserved,
	})
	principal := "principal-hmac-publish"
	verified := store.addRelationCandidate(RelationCandidate{
		ApplicationID: appID, ObjectType: "invoice", ObjectRef: "objref:verified-publish",
		PrincipalID: &principal, Source: CandidateSourceObserved,
	})

	var calls int
	var callbackContext context.Context
	var callbackUID uuid.UUID
	var callbackRequestID string
	h := NewHandler(store, nil)
	h.SetPublishFunc(func(ctx context.Context, uid uuid.UUID, requestID string) {
		calls++
		callbackContext = ctx
		callbackUID = uid
		callbackRequestID = requestID
	})
	mux := newTestMux(h)

	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/relations/candidates/"+legacy.ID.String()+"/confirm",
		map[string]any{"relation": "OWNER", "reason": "legacy must remain unconfirmed"})
	if rr.Code != http.StatusConflict {
		t.Fatalf("legacy confirm status=%d want 409 body=%s", rr.Code, rr.Body.String())
	}
	if calls != 0 {
		t.Fatalf("publish calls after rejected confirmation=%d want 0", calls)
	}

	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/relations/candidates/"+verified.ID.String()+"/confirm",
		map[string]any{"relation": "OWNER", "reason": "verified binding reviewed"})
	if rr.Code != http.StatusOK {
		t.Fatalf("verified confirm status=%d body=%s", rr.Code, rr.Body.String())
	}
	if calls != 1 {
		t.Fatalf("publish calls after confirmed relation=%d want 1", calls)
	}
	if callbackContext == nil || callbackUID == uuid.Nil || callbackRequestID != "test-rid" {
		t.Fatalf("publish callback context=%v uid=%s request_id=%q", callbackContext, callbackUID, callbackRequestID)
	}
}

func TestManualRelationCreationTriggersConfiguredPublish(t *testing.T) {
	store := NewMemStore()
	var calls int
	var callbackUID uuid.UUID
	var callbackRequestID string
	h := NewHandler(store, nil)
	h.SetPublishFunc(func(_ context.Context, uid uuid.UUID, requestID string) {
		calls++
		callbackUID = uid
		callbackRequestID = requestID
	})
	mux := newTestMux(h)

	appID := uuid.New()
	principalID := "principal-manual-publish"
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/relations", map[string]any{
		"application_id": appID.String(), "object_type": "invoice", "object_ref": "objref:manual-publish",
		"principal_id": principalID, "relation": "OWNER", "source": "MANUAL", "reason": "approved ticket",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("manual relation status=%d body=%s", rr.Code, rr.Body.String())
	}
	if calls != 1 {
		t.Fatalf("publish calls after manual relation=%d want 1", calls)
	}
	if callbackUID == uuid.Nil || callbackRequestID != "test-rid" {
		t.Fatalf("publish callback uid=%s request_id=%q", callbackUID, callbackRequestID)
	}

	// 校验失败不得触发发布，也不得留下关系。
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/relations", map[string]any{
		"application_id": appID.String(), "object_type": "invoice", "object_ref": "raw-id",
		"principal_id": principalID, "relation": "OWNER", "source": "MANUAL", "reason": "invalid ref",
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid manual relation status=%d body=%s", rr.Code, rr.Body.String())
	}
	if calls != 1 {
		t.Fatalf("publish calls after rejected manual relation=%d want 1", calls)
	}
}

func TestManualRelationRejectsReservedKindsAndRawRefs(t *testing.T) {
	store := NewMemStore()
	mux := newTestMux(NewHandler(store, nil))
	body := map[string]any{
		"application_id": uuid.NewString(), "object_type": "invoice", "object_ref": "12345",
		"principal_id": "principal-a", "relation": "SHARED_WITH", "source": "MANUAL", "reason": "ticket-1",
	}
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/relations", body)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("reserved/raw relation status=%d want 400 body=%s", rr.Code, rr.Body.String())
	}
}

func TestMemStoreRelationDefaultsValidFromBeforeValidityCheck(t *testing.T) {
	store := NewMemStore()
	validUntil := time.Now().UTC().Add(time.Minute)
	relation := &ObjectRelation{
		ApplicationID: uuid.New(), ObjectType: "invoice", ObjectRef: "objref:validity",
		PrincipalID: "principal-a", Relation: RelationOwner, Source: RelationSourceManual,
		Reason: "ticket-1", ValidUntil: &validUntil,
	}

	if err := store.CreateObjectRelation(context.Background(), relation); err != nil {
		t.Fatalf("create relation: %v", err)
	}
	if relation.ValidFrom.IsZero() {
		t.Fatal("valid_from must be defaulted before validation")
	}
	if relation.ValidUntil == nil || !relation.ValidUntil.After(relation.ValidFrom) {
		t.Fatalf("validity window=%+v", relation)
	}
}

func strPtr(v string) *string { return &v }

// TestBaselineCRUD 创建（候选）→ 读取 → 列表过滤 → 编辑 → 确认 → 删除；冲突与校验。
func TestBaselineCRUD(t *testing.T) {
	store := NewMemStore()
	endpointID := seedEndpoint(t, store, "GET /v1/users/{id}", "/v1/users/{id}")
	mux := newTestMux(NewHandler(store, nil))

	create := map[string]any{
		"endpoint_id": endpointID.String(),
		"role":        "OPS_ADMIN", "method": "get", "action": "read",
		"allowed": true, "confidence": 0.9,
	}
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/role-baselines", create)
	if rr.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	var created RoleBaseline
	decodeData(t, rr, &created)
	if created.ID == uuid.Nil || created.Method != "GET" || created.Action != "READ" ||
		created.Source != SourceManual || created.Confirmed || created.Confidence != 0.9 {
		t.Fatalf("created=%+v", created)
	}
	if created.CreatedBy == nil || *created.CreatedBy != "tester" {
		t.Fatalf("created_by=%v", created.CreatedBy)
	}

	// 重复创建 → 409
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/role-baselines", create)
	if rr.Code != http.StatusConflict {
		t.Fatalf("duplicate status=%d want 409", rr.Code)
	}

	// 校验失败矩阵 → 400
	for name, bad := range map[string]map[string]any{
		"缺 endpoint_id": {"role": "R", "method": "GET", "action": "READ"},
		"非法 method":     {"endpoint_id": endpointID.String(), "role": "R", "method": "FETCH", "action": "READ"},
		"非法 source":     {"endpoint_id": endpointID.String(), "role": "R", "method": "GET", "action": "READ", "source": "GUESSED"},
		"confidence 越界": {"endpoint_id": endpointID.String(), "role": "R", "method": "GET", "action": "READ", "confidence": 1.5},
		"role 非法字符":     {"endpoint_id": endpointID.String(), "role": "a b", "method": "GET", "action": "READ"},
		"不存在端点":         {"endpoint_id": uuid.NewString(), "role": "R", "method": "GET", "action": "READ"},
	} {
		rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/role-baselines", bad)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d want 400 body=%s", name, rr.Code, rr.Body.String())
		}
	}

	// 读取
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/role-baselines/"+created.ID.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("get status=%d", rr.Code)
	}

	// 列表过滤：confirmed=false 命中、source=OBSERVED 不命中
	var page struct {
		Items []RoleBaseline `json:"items"`
		Total int64          `json:"total"`
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/role-baselines?confirmed=false&method=GET", nil)
	decodeData(t, rr, &page)
	if page.Total != 1 {
		t.Fatalf("list total=%d want 1", page.Total)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/role-baselines?source=OBSERVED", nil)
	decodeData(t, rr, &page)
	if page.Total != 0 {
		t.Fatalf("source filter total=%d want 0", page.Total)
	}

	// 编辑（改 allowed + action；confirmed 不随编辑变更）
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/authz/role-baselines/"+created.ID.String(),
		map[string]any{"allowed": false, "action": "export"})
	if rr.Code != http.StatusOK {
		t.Fatalf("patch status=%d body=%s", rr.Code, rr.Body.String())
	}
	var updated RoleBaseline
	decodeData(t, rr, &updated)
	if updated.Allowed || updated.Action != "EXPORT" || updated.Confirmed {
		t.Fatalf("updated=%+v", updated)
	}

	// 确认（候选 → 正式基线），再撤回
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/role-baselines/"+created.ID.String()+"/confirm",
		map[string]any{"confirmed": true})
	if rr.Code != http.StatusOK {
		t.Fatalf("confirm status=%d body=%s", rr.Code, rr.Body.String())
	}
	var confirmed RoleBaseline
	decodeData(t, rr, &confirmed)
	if !confirmed.Confirmed {
		t.Fatalf("confirmed=%+v", confirmed)
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/role-baselines/"+created.ID.String()+"/confirm",
		map[string]any{"confirmed": false})
	decodeData(t, rr, &confirmed)
	if confirmed.Confirmed {
		t.Fatalf("unconfirm=%+v", confirmed)
	}
	// confirm 缺 confirmed 字段 → 400
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/role-baselines/"+created.ID.String()+"/confirm",
		map[string]any{})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("confirm empty status=%d want 400", rr.Code)
	}

	// 删除 → 再读 404
	rr = doJSON(t, mux, http.MethodDelete, "/api/v1/api-security/authz/role-baselines/"+created.ID.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/role-baselines/"+created.ID.String(), nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("get after delete status=%d want 404", rr.Code)
	}
}

// TestOwnershipQuery 权属只读查询（数据由 SweepOnce 生产；无写接口）。
func TestOwnershipQuery(t *testing.T) {
	store := NewMemStore()
	epKey := "GET /v1/users/{id}"
	endpointID := store.addEndpoint(epKey, "/v1/users/{id}")
	base := time.Now().UTC().Add(-time.Hour)
	store.addRuntimeEvent(epKey, "fp-a", "/v1/users/1001", base)
	store.addRuntimeEvent(epKey, "fp-a", "/v1/users/1002", base.Add(time.Minute))
	store.addRuntimeEvent(epKey, "fp-b", "/v1/users/1001", base.Add(2*time.Minute))
	if _, err := store.SweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	mux := newTestMux(NewHandler(store, nil))

	var page struct {
		Items []ObjectOwnership `json:"items"`
		Total int64             `json:"total"`
	}
	// 全量（按端点）
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/ownership?endpoint_id="+endpointID.String(), nil)
	decodeData(t, rr, &page)
	if page.Total != 3 {
		t.Fatalf("total=%d want 3 body", page.Total)
	}
	// 按身份过滤
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/ownership?identity=fp-a", nil)
	decodeData(t, rr, &page)
	if page.Total != 2 {
		t.Fatalf("identity filter total=%d want 2", page.Total)
	}
	// 按对象过滤（查属主）
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/ownership?object_id=1001", nil)
	decodeData(t, rr, &page)
	if page.Total != 2 {
		t.Fatalf("object filter total=%d want 2", page.Total)
	}
	owners := map[string]bool{}
	for _, o := range page.Items {
		owners[o.IdentityFingerprint] = true
		if o.ObjectType != "users" || o.ObjectID != "1001" || o.AccessCount != 1 {
			t.Fatalf("row=%+v", o)
		}
	}
	if !owners["fp-a"] || !owners["fp-b"] {
		t.Fatalf("owners=%v", owners)
	}
	// 非法 endpoint_id → 400
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/ownership?endpoint_id=bad", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad endpoint_id status=%d want 400", rr.Code)
	}
}

// TestFieldPermissionCRUD 创建（默认行/覆盖行）→ 列表过滤 → 编辑（清除覆盖回默认行）→
// 冲突 → 删除；校验矩阵。
func TestFieldPermissionCRUD(t *testing.T) {
	store := NewMemStore()
	endpointID := seedEndpoint(t, store, "POST /v1/users", "/v1/users")
	mux := newTestMux(NewHandler(store, nil))

	// 默认行（role/tenant 缺省 = NULL）
	create := map[string]any{
		"endpoint_id": endpointID.String(), "field_path": "json.role",
		"direction": "request", "attribute": "admin_writable",
	}
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/field-permissions", create)
	if rr.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	var created FieldPermission
	decodeData(t, rr, &created)
	if created.ID == uuid.Nil || created.Direction != DirectionRequest || created.Attribute != AttrAdminWritable ||
		created.Role != nil || created.Tenant != nil {
		t.Fatalf("created=%+v", created)
	}

	// 角色覆盖行（同字段同方向，role 非空 → 不冲突）
	override := map[string]any{
		"endpoint_id": endpointID.String(), "field_path": "json.role",
		"direction": "REQUEST", "attribute": "WRITABLE", "role": "SUPER_ADMIN",
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/field-permissions", override)
	if rr.Code != http.StatusOK {
		t.Fatalf("override status=%d body=%s", rr.Code, rr.Body.String())
	}
	// 重复默认行 → 409（NULL 归一口径）
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/field-permissions", create)
	if rr.Code != http.StatusConflict {
		t.Fatalf("duplicate default status=%d want 409", rr.Code)
	}
	// 重复覆盖行 → 409
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/field-permissions", override)
	if rr.Code != http.StatusConflict {
		t.Fatalf("duplicate override status=%d want 409", rr.Code)
	}

	// 列表：defaults_only=true 只出默认行；role 过滤只出覆盖行
	var page struct {
		Items []FieldPermission `json:"items"`
		Total int64             `json:"total"`
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/field-permissions?defaults_only=true", nil)
	decodeData(t, rr, &page)
	if page.Total != 1 || page.Items[0].Role != nil {
		t.Fatalf("defaults_only=%+v", page)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/field-permissions?role=SUPER_ADMIN", nil)
	decodeData(t, rr, &page)
	if page.Total != 1 || page.Items[0].Role == nil || *page.Items[0].Role != "SUPER_ADMIN" {
		t.Fatalf("role filter=%+v", page)
	}

	// 校验失败矩阵 → 400
	for name, bad := range map[string]map[string]any{
		"非法 direction": {"endpoint_id": endpointID.String(), "field_path": "json.a", "direction": "UPLOAD", "attribute": "READABLE"},
		"非法 attribute": {"endpoint_id": endpointID.String(), "field_path": "json.a", "direction": "REQUEST", "attribute": "HIDDEN"},
		"缺 field_path": {"endpoint_id": endpointID.String(), "direction": "REQUEST", "attribute": "READABLE"},
		"不存在端点":        {"endpoint_id": uuid.NewString(), "field_path": "json.a", "direction": "REQUEST", "attribute": "READABLE"},
	} {
		rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/field-permissions", bad)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d want 400 body=%s", name, rr.Code, rr.Body.String())
		}
	}

	// 编辑覆盖行：role 显式空串清除 → 与既有默认行撞键 → 409
	var overrideRow FieldPermission
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/field-permissions?role=SUPER_ADMIN", nil)
	decodeData(t, rr, &page)
	overrideRow = page.Items[0]
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/authz/field-permissions/"+overrideRow.ID.String(),
		map[string]any{"role": "", "attribute": "ADMIN_WRITABLE"})
	if rr.Code != http.StatusConflict {
		t.Fatalf("clear role status=%d want 409 body=%s", rr.Code, rr.Body.String())
	}
	// 正常编辑（改 attribute，role 保持）
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/authz/field-permissions/"+overrideRow.ID.String(),
		map[string]any{"attribute": "READABLE"})
	if rr.Code != http.StatusOK {
		t.Fatalf("patch status=%d body=%s", rr.Code, rr.Body.String())
	}
	var updated FieldPermission
	decodeData(t, rr, &updated)
	if updated.Attribute != AttrReadable || updated.Role == nil || *updated.Role != "SUPER_ADMIN" {
		t.Fatalf("updated=%+v", updated)
	}

	// 删除
	rr = doJSON(t, mux, http.MethodDelete, "/api/v1/api-security/authz/field-permissions/"+created.ID.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/field-permissions/"+created.ID.String(), nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("get after delete status=%d want 404", rr.Code)
	}
}

// TestEvaluateEndpoint 评估接口：参数校验 + 五档结论经 HTTP 输出。
func TestEvaluateEndpoint(t *testing.T) {
	store := NewMemStore()
	epKey := "GET /v1/users/{id}"
	endpointID := store.addEndpoint(epKey, "/v1/users/{id}")
	store.addRuntimeEvent(epKey, "fp-a", "/v1/users/1001", time.Now().UTC())
	if _, err := store.SweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	mux := newTestMux(NewHandler(store, nil))

	// 参数校验
	for name, url := range map[string]string{
		"缺 endpoint_id": "/api/v1/api-security/authz/evaluate?object_id=1",
		"缺 object_id":   "/api/v1/api-security/authz/evaluate?endpoint_id=" + endpointID.String(),
		"非法 endpoint":   "/api/v1/api-security/authz/evaluate?endpoint_id=bad&object_id=1",
	} {
		rr := doJSON(t, mux, http.MethodGet, url, nil)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d want 400", name, rr.Code)
		}
	}
	// 端点不存在 → 404
	rr := doJSON(t, mux, http.MethodGet,
		"/api/v1/api-security/authz/evaluate?endpoint_id="+uuid.NewString()+"&object_id=1", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown endpoint status=%d want 404", rr.Code)
	}
	// 权属匹配 → POLICY_CONFIRMED
	rr = doJSON(t, mux, http.MethodGet,
		"/api/v1/api-security/authz/evaluate?endpoint_id="+endpointID.String()+"&identity=fp-a&object_id=1001", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("evaluate status=%d body=%s", rr.Code, rr.Body.String())
	}
	var result EvaluateResult
	decodeData(t, rr, &result)
	if result.Verdict != VerdictPolicyConfirmed || result.Allowed == nil || !*result.Allowed ||
		result.Evidence == nil || !result.Evidence.OwnMatch {
		t.Fatalf("result=%+v", result)
	}
	// 他人对象 → HIGH_CONFIDENCE
	rr = doJSON(t, mux, http.MethodGet,
		"/api/v1/api-security/authz/evaluate?endpoint_id="+endpointID.String()+"&identity=fp-x&object_id=1001", nil)
	decodeData(t, rr, &result)
	if result.Verdict != VerdictHighConfidence || result.Allowed == nil || *result.Allowed {
		t.Fatalf("high confidence result=%+v", result)
	}
}
