package apigroups

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
)

type memoryRepository struct {
	mu        sync.Mutex
	apps      map[uuid.UUID]string
	endpoints map[uuid.UUID]Endpoint
	groups    map[uuid.UUID]Group
	members   map[uuid.UUID]map[uuid.UUID]time.Time
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{
		apps:      map[uuid.UUID]string{},
		endpoints: map[uuid.UUID]Endpoint{},
		groups:    map[uuid.UUID]Group{},
		members:   map[uuid.UUID]map[uuid.UUID]time.Time{},
	}
}

func (m *memoryRepository) addApp(name string) uuid.UUID {
	id := uuid.New()
	m.apps[id] = name
	return id
}

func (m *memoryRepository) addEndpoint(appID *uuid.UUID, method, path string) Endpoint {
	e := Endpoint{ID: uuid.New(), ApplicationID: appID, HTTPMethod: method, NormalizedPath: path,
		EndpointKey: method + " " + path, AssetStatus: "CONFIRMED"}
	m.endpoints[e.ID] = e
	return e
}

func cloneGroup(g Group) Group { return g }

func (m *memoryRepository) Create(_ context.Context, in CreateInput) (*Group, error) {
	if err := validateCreate(&in); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	appName, ok := m.apps[in.ApplicationID]
	if !ok {
		return nil, ErrApplicationNotFound
	}
	for _, g := range m.groups {
		if g.ApplicationID == in.ApplicationID && g.Code == in.Code {
			return nil, ErrDuplicate
		}
	}
	now := time.Now().UTC()
	g := Group{ID: uuid.New(), ApplicationID: in.ApplicationID, ApplicationName: appName,
		Code: in.Code, Name: in.Name, Description: in.Description, Enabled: in.Enabled,
		CreatedAt: now, UpdatedAt: now}
	m.groups[g.ID] = g
	m.members[g.ID] = map[uuid.UUID]time.Time{}
	copy := cloneGroup(g)
	return &copy, nil
}

func (m *memoryRepository) List(_ context.Context, filter ListFilter) ([]Group, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	filter.Page, filter.PageSize = normalizePage(filter.Page, filter.PageSize)
	all := []Group{}
	for _, g := range m.groups {
		if filter.ApplicationID != nil && g.ApplicationID != *filter.ApplicationID {
			continue
		}
		g.EndpointCount = int64(len(m.members[g.ID]))
		all = append(all, cloneGroup(g))
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].ID.String() > all[j].ID.String()
		}
		return all[i].CreatedAt.After(all[j].CreatedAt)
	})
	total := int64(len(all))
	start := (filter.Page - 1) * filter.PageSize
	if start >= len(all) {
		return []Group{}, total, nil
	}
	end := start + filter.PageSize
	if end > len(all) {
		end = len(all)
	}
	return all[start:end], total, nil
}

func (m *memoryRepository) Get(_ context.Context, id uuid.UUID) (*Group, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[id]
	if !ok {
		return nil, ErrNotFound
	}
	g.EndpointCount = int64(len(m.members[id]))
	copy := cloneGroup(g)
	return &copy, nil
}

func (m *memoryRepository) Update(_ context.Context, id uuid.UUID, in UpdateInput) (*Group, error) {
	if err := validateUpdate(&in); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[id]
	if !ok {
		return nil, ErrNotFound
	}
	for _, other := range m.groups {
		if other.ID != id && other.ApplicationID == g.ApplicationID && other.Code == in.Code {
			return nil, ErrDuplicate
		}
	}
	g.Code, g.Name, g.Description, g.Enabled = in.Code, in.Name, in.Description, in.Enabled
	g.UpdatedAt = time.Now().UTC()
	m.groups[id] = g
	g.EndpointCount = int64(len(m.members[id]))
	copy := cloneGroup(g)
	return &copy, nil
}

func (m *memoryRepository) Delete(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.groups[id]; !ok {
		return ErrNotFound
	}
	delete(m.groups, id)
	delete(m.members, id)
	return nil
}

func (m *memoryRepository) ListEndpoints(_ context.Context, groupID uuid.UUID, page, pageSize int) ([]Endpoint, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.groups[groupID]; !ok {
		return nil, 0, ErrNotFound
	}
	page, pageSize = normalizePage(page, pageSize)
	all := []Endpoint{}
	for endpointID, addedAt := range m.members[groupID] {
		e, ok := m.endpoints[endpointID]
		if !ok {
			continue
		}
		e.AddedAt = addedAt
		all = append(all, e)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].AddedAt.Equal(all[j].AddedAt) {
			return all[i].ID.String() > all[j].ID.String()
		}
		return all[i].AddedAt.After(all[j].AddedAt)
	})
	total := int64(len(all))
	start := (page - 1) * pageSize
	if start >= len(all) {
		return []Endpoint{}, total, nil
	}
	end := start + pageSize
	if end > len(all) {
		end = len(all)
	}
	return all[start:end], total, nil
}

func (m *memoryRepository) AddEndpoint(_ context.Context, groupID, endpointID uuid.UUID) (*Member, error) {
	if endpointID == uuid.Nil {
		return nil, invalidf("endpoint_id 必填")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[groupID]
	if !ok {
		return nil, ErrNotFound
	}
	e, ok := m.endpoints[endpointID]
	if !ok {
		return nil, ErrEndpointNotFound
	}
	if e.ApplicationID == nil || *e.ApplicationID != g.ApplicationID {
		return nil, ErrApplicationMismatch
	}
	if _, exists := m.members[groupID][endpointID]; exists {
		return nil, ErrDuplicateMember
	}
	now := time.Now().UTC()
	m.members[groupID][endpointID] = now
	return &Member{GroupID: groupID, EndpointID: endpointID, CreatedAt: now}, nil
}

func (m *memoryRepository) RemoveEndpoint(_ context.Context, groupID, endpointID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.members[groupID][endpointID]; !ok {
		return ErrMemberNotFound
	}
	delete(m.members[groupID], endpointID)
	return nil
}

type auditSpy struct{ entries []audits.RecordInput }

func (s *auditSpy) Record(_ context.Context, in audits.RecordInput) error {
	s.entries = append(s.entries, in)
	return nil
}

func newTestMux(repo Repository, spy auditRecorder, permissions ...string) *http.ServeMux {
	mux := http.NewServeMux()
	h := &Handler{repo: repo, audits: spy}
	authenticate := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			perms := map[string]bool{}
			for _, permission := range permissions {
				perms[permission] = true
			}
			p := &authz.Principal{UserID: uuid.New(), Username: "group-tester", PermsSet: perms}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}
	RegisterRoutes(mux, authenticate, h)
	return mux
}

func request(t *testing.T, mux http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func decodeData[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var envelope struct {
		Data T `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, w.Body.String())
	}
	return envelope.Data
}

func expectStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body.String())
	}
}

func createForTest(t *testing.T, mux http.Handler, appID uuid.UUID, code, name string) Group {
	t.Helper()
	body := `{"application_id":"` + appID.String() + `","code":` + strconvQuote(code) + `,"name":` + strconvQuote(name) + `}`
	w := request(t, mux, http.MethodPost, "/api/v1/api-security/endpoint-groups", body)
	expectStatus(t, w, http.StatusCreated)
	return decodeData[Group](t, w)
}

func strconvQuote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func TestNormalizeGroupFields(t *testing.T) {
	code, name, description, err := normalizeFields("  sales_order_2  ", " 订单接口 ", " 同应用订单查询 ")
	if err != nil || code != "SALES_ORDER_2" || name != "订单接口" || description != "同应用订单查询" {
		t.Fatalf("normalizeFields=(%q,%q,%q,%v)", code, name, description, err)
	}
	for _, tc := range []struct{ name, code, groupName, description string }{
		{"empty code", "", "name", ""},
		{"leading digit", "1SALES", "name", ""},
		{"hyphen", "SALES-ORDER", "name", ""},
		{"code too long", strings.Repeat("A", 65), "name", ""},
		{"empty name", "SALES", " ", ""},
		{"name too long", "SALES", strings.Repeat("名", 129), ""},
		{"description too long", "SALES", "name", strings.Repeat("述", 513)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := normalizeFields(tc.code, tc.groupName, tc.description); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestGroupCRUDMembersPaginationAndAudit(t *testing.T) {
	repo := newMemoryRepository()
	spy := &auditSpy{}
	mux := newTestMux(repo, spy, PermRead, PermManage)
	app1, app2 := repo.addApp("订单系统"), repo.addApp("库存系统")
	app1ID := app1
	e1 := repo.addEndpoint(&app1ID, "GET", "/orders/{id}")
	e2 := repo.addEndpoint(&app1ID, "POST", "/orders")
	e3 := repo.addEndpoint(&app2, "GET", "/inventory")
	unassigned := repo.addEndpoint(nil, "GET", "/unassigned")

	groupA := createForTest(t, mux, app1, "sales_order", "订单接口")
	if groupA.Code != "SALES_ORDER" || groupA.ApplicationName != "订单系统" || !groupA.Enabled || groupA.EndpointCount != 0 {
		t.Fatalf("created group=%+v", groupA)
	}
	groupOtherApp := createForTest(t, mux, app2, "SALES_ORDER", "另一应用同名编码")
	groupB := createForTest(t, mux, app1, "SALES_WRITE", "订单写入")

	w := request(t, mux, http.MethodPost, "/api/v1/api-security/endpoint-groups",
		`{"application_id":"`+app1.String()+`","code":"sales_order","name":"重复"}`)
	expectStatus(t, w, http.StatusConflict)
	w = request(t, mux, http.MethodPost, "/api/v1/api-security/endpoint-groups",
		`{"application_id":"`+uuid.NewString()+`","code":"GHOST","name":"不存在应用"}`)
	expectStatus(t, w, http.StatusNotFound)

	w = request(t, mux, http.MethodGet, "/api/v1/api-security/endpoint-groups?page=1&page_size=2", "")
	expectStatus(t, w, http.StatusOK)
	page := decodeData[struct {
		Items    []Group `json:"items"`
		Page     int     `json:"page"`
		PageSize int     `json:"page_size"`
		Total    int64   `json:"total"`
	}](t, w)
	if page.Total != 3 || len(page.Items) != 2 || page.Page != 1 || page.PageSize != 2 {
		t.Fatalf("group page=%+v", page)
	}
	w = request(t, mux, http.MethodGet, "/api/v1/api-security/endpoint-groups?application_id="+app1.String(), "")
	page = decodeData[struct {
		Items    []Group `json:"items"`
		Page     int     `json:"page"`
		PageSize int     `json:"page_size"`
		Total    int64   `json:"total"`
	}](t, w)
	if page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("filtered page=%+v", page)
	}
	for _, target := range []string{
		"/api/v1/api-security/endpoint-groups?page=0",
		"/api/v1/api-security/endpoint-groups?page_size=abc",
		"/api/v1/api-security/endpoint-groups?page_size=101",
		"/api/v1/api-security/endpoint-groups?application_id=bad",
	} {
		expectStatus(t, request(t, mux, http.MethodGet, target, ""), http.StatusBadRequest)
	}

	w = request(t, mux, http.MethodPut, "/api/v1/api-security/endpoint-groups/"+groupA.ID.String(),
		`{"code":"sales_read","name":"订单读取","description":"更新","enabled":false}`)
	expectStatus(t, w, http.StatusOK)
	updated := decodeData[Group](t, w)
	if updated.Code != "SALES_READ" || updated.Name != "订单读取" || updated.Enabled {
		t.Fatalf("updated=%+v", updated)
	}
	w = request(t, mux, http.MethodPut, "/api/v1/api-security/endpoint-groups/"+groupB.ID.String(),
		`{"code":"SALES_READ","name":"编码冲突","enabled":true}`)
	expectStatus(t, w, http.StatusConflict)
	w = request(t, mux, http.MethodPut, "/api/v1/api-security/endpoint-groups/"+groupA.ID.String(),
		`{"application_id":"`+app2.String()+`","code":"SALES_READ","name":"禁止改应用"}`)
	expectStatus(t, w, http.StatusBadRequest)

	add := func(groupID, endpointID uuid.UUID) *httptest.ResponseRecorder {
		return request(t, mux, http.MethodPost, "/api/v1/api-security/endpoint-groups/"+groupID.String()+"/endpoints",
			`{"endpoint_id":"`+endpointID.String()+`"}`)
	}
	expectStatus(t, add(groupA.ID, e1.ID), http.StatusCreated)
	expectStatus(t, add(groupA.ID, e2.ID), http.StatusCreated)
	expectStatus(t, add(groupB.ID, e1.ID), http.StatusCreated)
	expectStatus(t, add(groupA.ID, e1.ID), http.StatusConflict)
	expectStatus(t, add(groupA.ID, e3.ID), http.StatusBadRequest)
	expectStatus(t, add(groupA.ID, unassigned.ID), http.StatusBadRequest)
	expectStatus(t, add(groupA.ID, uuid.New()), http.StatusNotFound)
	expectStatus(t, add(uuid.New(), e1.ID), http.StatusNotFound)
	expectStatus(t, add(groupOtherApp.ID, e3.ID), http.StatusCreated)

	w = request(t, mux, http.MethodGet, "/api/v1/api-security/endpoint-groups/"+groupA.ID.String()+"/endpoints?page=1&page_size=1", "")
	expectStatus(t, w, http.StatusOK)
	memberPage := decodeData[struct {
		Items    []Endpoint `json:"items"`
		Page     int        `json:"page"`
		PageSize int        `json:"page_size"`
		Total    int64      `json:"total"`
	}](t, w)
	if memberPage.Total != 2 || len(memberPage.Items) != 1 || memberPage.Items[0].NormalizedPath == "" {
		t.Fatalf("member page=%+v", memberPage)
	}
	w = request(t, mux, http.MethodGet, "/api/v1/api-security/endpoint-groups/"+groupA.ID.String(), "")
	if got := decodeData[Group](t, w).EndpointCount; got != 2 {
		t.Fatalf("endpoint_count=%d want=2", got)
	}

	w = request(t, mux, http.MethodDelete, "/api/v1/api-security/endpoint-groups/"+groupA.ID.String()+"/endpoints/"+e1.ID.String(), "")
	expectStatus(t, w, http.StatusOK)
	expectStatus(t, request(t, mux, http.MethodDelete,
		"/api/v1/api-security/endpoint-groups/"+groupA.ID.String()+"/endpoints/"+e1.ID.String(), ""), http.StatusNotFound)
	w = request(t, mux, http.MethodGet, "/api/v1/api-security/endpoint-groups/"+groupB.ID.String()+"/endpoints", "")
	memberPage = decodeData[struct {
		Items    []Endpoint `json:"items"`
		Page     int        `json:"page"`
		PageSize int        `json:"page_size"`
		Total    int64      `json:"total"`
	}](t, w)
	if memberPage.Total != 1 || memberPage.Items[0].ID != e1.ID {
		t.Fatalf("same endpoint in another group must remain: %+v", memberPage)
	}

	expectStatus(t, request(t, mux, http.MethodDelete, "/api/v1/api-security/endpoint-groups/"+groupA.ID.String(), ""), http.StatusOK)
	expectStatus(t, request(t, mux, http.MethodGet, "/api/v1/api-security/endpoint-groups/"+groupA.ID.String(), ""), http.StatusNotFound)
	expectStatus(t, request(t, mux, http.MethodDelete, "/api/v1/api-security/endpoint-groups/"+groupA.ID.String(), ""), http.StatusNotFound)
	if len(spy.entries) != 10 {
		t.Fatalf("audit entries=%d want=10: %+v", len(spy.entries), spy.entries)
	}
	for i, action := range []string{"create", "create", "create", "update", "member_add", "member_add", "member_add", "member_add", "member_remove", "delete"} {
		if spy.entries[i].Action != action || spy.entries[i].Result != audits.ResultSuccess {
			t.Errorf("audit[%d]=%+v want action=%s", i, spy.entries[i], action)
		}
	}
}

func TestGroupRequestValidationAndPermissions(t *testing.T) {
	repo := newMemoryRepository()
	appID := repo.addApp("应用")
	mux := newTestMux(repo, &auditSpy{}, PermRead, PermManage)
	for _, body := range []string{
		`{"code":"SALES","name":"缺应用"}`,
		`{"application_id":"` + appID.String() + `","code":"bad-code","name":"非法编码"}`,
		`{"application_id":"` + appID.String() + `","code":"SALES","name":"` + strings.Repeat("名", 129) + `"}`,
		`{"application_id":"` + appID.String() + `","code":"SALES","name":"未知字段","members":[]}`,
		`{"application_id":"` + appID.String() + `","code":"SALES","name":"多余JSON"} {}`,
	} {
		expectStatus(t, request(t, mux, http.MethodPost, "/api/v1/api-security/endpoint-groups", body), http.StatusBadRequest)
	}
	expectStatus(t, request(t, mux, http.MethodGet, "/api/v1/api-security/endpoint-groups/not-a-uuid", ""), http.StatusBadRequest)

	readOnly := newTestMux(repo, &auditSpy{}, PermRead)
	expectStatus(t, request(t, readOnly, http.MethodGet, "/api/v1/api-security/endpoint-groups", ""), http.StatusOK)
	expectStatus(t, request(t, readOnly, http.MethodPost, "/api/v1/api-security/endpoint-groups", `{}`), http.StatusForbidden)
	noPermissions := newTestMux(repo, &auditSpy{})
	expectStatus(t, request(t, noPermissions, http.MethodGet, "/api/v1/api-security/endpoint-groups", ""), http.StatusForbidden)
	expectStatus(t, request(t, noPermissions, http.MethodDelete, "/api/v1/api-security/endpoint-groups/"+uuid.NewString(), ""), http.StatusForbidden)
}
