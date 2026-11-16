package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

func TestAPIEndpointGroupMigration000210Static(t *testing.T) {
	up := readMigration(t, "000210_api_endpoint_groups.up.sql")
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS api_endpoint_groups",
		"CREATE TABLE IF NOT EXISTS api_endpoint_group_members",
		"REFERENCES applications(id) ON DELETE CASCADE",
		"REFERENCES api_endpoints(id) ON DELETE CASCADE",
		"PRIMARY KEY (group_id, endpoint_id)",
		"UNIQUE (application_id, code)",
		"code ~ '^[A-Z][A-Z0-9_]*$'",
		"VARCHAR(64)", "VARCHAR(128)", "VARCHAR(512)",
		"'api_endpoint_group.read'", "'api_endpoint_group.manage'",
		"r.code = 'SECURITY_ADMIN'", "r.code = 'AUDIT_ADMIN'",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("000210 up missing %q", fragment)
		}
	}
	down := readMigration(t, "000210_api_endpoint_groups.down.sql")
	for _, fragment := range []string{
		"DROP TABLE IF EXISTS api_endpoint_group_members",
		"DROP TABLE IF EXISTS api_endpoint_groups",
		"DELETE FROM role_permissions", "DELETE FROM permissions",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("000210 down missing %q", fragment)
		}
	}
}

func seedEndpointGroupApp(t *testing.T, env *testEnv, prefix, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	code := fmt.Sprintf("%s-%s", prefix, strings.ReplaceAll(uuid.NewString()[:8], "-", ""))
	if err := env.db.QueryRow(context.Background(),
		`INSERT INTO applications (code, name) VALUES ($1, $2) RETURNING id`, code, name).Scan(&id); err != nil {
		t.Fatalf("seed application: %v", err)
	}
	return id
}

func seedEndpointGroupEndpoint(t *testing.T, env *testEnv, appID uuid.UUID, method, path string) uuid.UUID {
	t.Helper()
	e, err := apiassets.NewStore(env.db).UpsertDiscovery(context.Background(), apiassets.DiscoveryInput{
		Method: method, PathTemplate: path, Confidence: 1, IsAPI: true, ApplicationID: &appID,
	})
	if err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	return e.ID
}

func endpointGroupData(t *testing.T, resp *http.Response, want int) map[string]interface{} {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("status=%d want=%d body=%s", resp.StatusCode, want, readBodyString(t, resp))
	}
	var result apiResp
	readJSON(t, resp, &result)
	return result.Data
}

func TestAPIEndpointGroupsE2E000210(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	app1 := seedEndpointGroupApp(t, env, "eg-orders", "订单系统")
	app2 := seedEndpointGroupApp(t, env, "eg-inventory", "库存系统")
	endpoint1 := seedEndpointGroupEndpoint(t, env, app1, "GET", "/endpoint-groups/orders/{id}")
	endpoint2 := seedEndpointGroupEndpoint(t, env, app1, "POST", "/endpoint-groups/orders")
	otherAppEndpoint := seedEndpointGroupEndpoint(t, env, app2, "GET", "/endpoint-groups/inventory")

	securityCookies, securityCSRF := env.s5Login(t, "egsec", "SECURITY_ADMIN")
	auditCookies, auditCSRF := env.s5Login(t, "egaudit", "AUDIT_ADMIN")
	systemCookies, _ := env.login(t, "test_sysadmin", env.adminPwd)
	base := "/api/v1/api-security/endpoint-groups"

	if n := s8Count(t, env, `SELECT count(*) FROM role_permissions rp
JOIN roles r ON r.id=rp.role_id JOIN permissions p ON p.id=rp.permission_id
WHERE r.code='SECURITY_ADMIN' AND p.code IN ('api_endpoint_group.read','api_endpoint_group.manage')`); n != 2 {
		t.Fatalf("SECURITY_ADMIN grants=%d want=2", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM role_permissions rp
JOIN roles r ON r.id=rp.role_id JOIN permissions p ON p.id=rp.permission_id
WHERE r.code='AUDIT_ADMIN' AND p.code='api_endpoint_group.read'`); n != 1 {
		t.Fatalf("AUDIT_ADMIN read grant=%d want=1", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM role_permissions rp
JOIN roles r ON r.id=rp.role_id JOIN permissions p ON p.id=rp.permission_id
WHERE r.code='SYSTEM_ADMIN' AND p.code IN ('api_endpoint_group.read','api_endpoint_group.manage')`); n != 0 {
		t.Fatalf("SYSTEM_ADMIN unexpected grants=%d", n)
	}

	s5Expect(t, env.get(t, base, nil), http.StatusUnauthorized, "anonymous list")
	s5Expect(t, env.get(t, base, auditCookies), http.StatusOK, "audit admin read")
	s5Expect(t, env.get(t, base, systemCookies), http.StatusForbidden, "system admin read")
	createBody := fmt.Sprintf(`{"application_id":%q,"code":"orders_read","name":"订单读取","description":"真实接口组"}`, app1)
	s5Expect(t, env.post(t, base, createBody, auditCookies, auditCSRF), http.StatusForbidden, "audit admin create")
	s5Expect(t, env.post(t, base, createBody, securityCookies, ""), http.StatusForbidden, "create without CSRF")

	created := endpointGroupData(t, env.post(t, base, createBody, securityCookies, securityCSRF), http.StatusCreated)
	groupID := created["id"].(string)
	if created["code"] != "ORDERS_READ" || created["application_name"] != "订单系统" ||
		created["enabled"] != true || created["endpoint_count"] != float64(0) {
		t.Fatalf("created group=%+v", created)
	}
	second := endpointGroupData(t, env.post(t, base,
		fmt.Sprintf(`{"application_id":%q,"code":"orders_write","name":"订单写入"}`, app1),
		securityCookies, securityCSRF), http.StatusCreated)
	secondID := second["id"].(string)
	otherAppGroup := endpointGroupData(t, env.post(t, base,
		fmt.Sprintf(`{"application_id":%q,"code":"orders_read","name":"其他应用同编码"}`, app2),
		securityCookies, securityCSRF), http.StatusCreated)

	s5Expect(t, env.post(t, base, createBody, securityCookies, securityCSRF), http.StatusConflict, "duplicate normalized code")
	s5Expect(t, env.post(t, base,
		fmt.Sprintf(`{"application_id":%q,"code":"GHOST","name":"不存在应用"}`, uuid.New()),
		securityCookies, securityCSRF), http.StatusNotFound, "unknown application")
	s5Expect(t, env.post(t, base,
		fmt.Sprintf(`{"application_id":%q,"code":"bad-code","name":"非法编码"}`, app1),
		securityCookies, securityCSRF), http.StatusBadRequest, "invalid code")

	page := s8Page(t, env.get(t, base+"?page=1&page_size=2", securityCookies), "group page")
	if page.Data.Total != 3 || len(page.Data.Items) != 2 || page.Data.Page != 1 || page.Data.PageSize != 2 {
		t.Fatalf("group page=%+v", page.Data)
	}
	filtered := s8Page(t, env.get(t, base+"?application_id="+app1.String(), securityCookies), "filtered group page")
	if filtered.Data.Total != 2 || len(filtered.Data.Items) != 2 {
		t.Fatalf("filtered group page=%+v", filtered.Data)
	}
	s5Expect(t, env.get(t, base+"?page_size=101", securityCookies), http.StatusBadRequest, "page size guard")
	s5Expect(t, env.get(t, base+"?application_id=bad", securityCookies), http.StatusBadRequest, "application filter validation")

	addEndpoint := func(groupID string, endpointID uuid.UUID, want int) {
		t.Helper()
		s5Expect(t, env.post(t, base+"/"+groupID+"/endpoints",
			fmt.Sprintf(`{"endpoint_id":%q}`, endpointID), securityCookies, securityCSRF), want, "add endpoint")
	}
	addEndpoint(groupID, endpoint1, http.StatusCreated)
	addEndpoint(groupID, endpoint2, http.StatusCreated)
	addEndpoint(secondID, endpoint1, http.StatusCreated)
	addEndpoint(otherAppGroup["id"].(string), otherAppEndpoint, http.StatusCreated)
	addEndpoint(groupID, endpoint1, http.StatusConflict)
	addEndpoint(groupID, otherAppEndpoint, http.StatusBadRequest)
	addEndpoint(groupID, uuid.New(), http.StatusNotFound)
	addEndpoint(uuid.NewString(), endpoint1, http.StatusNotFound)

	members := s8Page(t, env.get(t, base+"/"+groupID+"/endpoints?page=1&page_size=1", securityCookies), "member page")
	if members.Data.Total != 2 || len(members.Data.Items) != 1 {
		t.Fatalf("member page=%+v", members.Data)
	}
	member := members.Data.Items[0]
	if member["id"] == "" || member["application_id"] != app1.String() || member["normalized_path"] == "" || member["added_at"] == "" {
		t.Fatalf("member must come from api_endpoints: %+v", member)
	}
	detail := endpointGroupData(t, env.get(t, base+"/"+groupID, securityCookies), http.StatusOK)
	if detail["endpoint_count"] != float64(2) {
		t.Fatalf("group detail=%+v", detail)
	}

	updated := endpointGroupData(t, env.do(t, http.MethodPut, base+"/"+groupID,
		`{"code":"orders_query","name":"订单查询","enabled":false}`, securityCookies, securityCSRF), http.StatusOK)
	if updated["code"] != "ORDERS_QUERY" || updated["enabled"] != false || updated["application_id"] != app1.String() {
		t.Fatalf("updated group=%+v", updated)
	}
	s5Expect(t, env.do(t, http.MethodDelete, base+"/"+groupID+"/endpoints/"+endpoint1.String(), "", securityCookies, securityCSRF),
		http.StatusOK, "remove member")
	s5Expect(t, env.do(t, http.MethodDelete, base+"/"+groupID+"/endpoints/"+endpoint1.String(), "", securityCookies, securityCSRF),
		http.StatusNotFound, "remove missing member")
	secondMembers := s8Page(t, env.get(t, base+"/"+secondID+"/endpoints", securityCookies), "second group members")
	if secondMembers.Data.Total != 1 || secondMembers.Data.Items[0]["id"] != endpoint1.String() {
		t.Fatalf("endpoint must remain in another group: %+v", secondMembers.Data)
	}

	s5Expect(t, env.do(t, http.MethodDelete, base+"/"+groupID, "", securityCookies, securityCSRF), http.StatusOK, "delete group")
	s5Expect(t, env.get(t, base+"/"+groupID, securityCookies), http.StatusNotFound, "get deleted group")
	if n := s8Count(t, env, `SELECT count(*) FROM api_endpoint_group_members WHERE group_id=$1`, groupID); n != 0 {
		t.Fatalf("deleted group members remain=%d", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM operation_audits
WHERE module='api_security' AND object_id=$1
AND action IN ('create','update','member_add','member_remove','delete')`, groupID); n != 6 {
		t.Fatalf("group audit count=%d want=6", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_endpoint_group_members WHERE group_id=$1 AND endpoint_id=$2`, secondID, endpoint1); n != 1 {
		t.Fatalf("other group membership was changed: %d", n)
	}

	var applied int
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=210`).Scan(&applied); err != nil || applied != 1 {
		t.Fatalf("migration 210 applied=%d err=%v", applied, err)
	}
}

func TestAPIEndpointGroupMigration000210Integration(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	up := readMigration(t, "000210_api_endpoint_groups.up.sql")
	down := readMigration(t, "000210_api_endpoint_groups.down.sql")
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, up); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	appID := seedEndpointGroupApp(t, env, "eg-migration", "迁移约束")
	if _, err := env.db.Exec(ctx, `INSERT INTO api_endpoint_groups(application_id,code,name)
VALUES ($1,'bad-code','非法编码')`, appID); err == nil {
		t.Fatal("database must reject non-normalized code")
	}
	if _, err := env.db.Exec(ctx, down); err != nil {
		t.Fatalf("down: %v", err)
	}
	for _, table := range []string{"api_endpoint_group_members", "api_endpoint_groups"} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.tables WHERE table_name=$1`, table); n != 0 {
			t.Fatalf("table %s remains after down", table)
		}
	}
	if n := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code IN ('api_endpoint_group.read','api_endpoint_group.manage')`); n != 0 {
		t.Fatalf("permissions remain after down=%d", n)
	}
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code IN ('api_endpoint_group.read','api_endpoint_group.manage')`); n != 2 {
		t.Fatalf("permissions after re-up=%d want=2", n)
	}
}
