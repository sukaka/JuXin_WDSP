package restores

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/backups"
)

func allAvailable() map[string]bool {
	m := map[string]bool{}
	for _, td := range backups.Tables {
		m[td.Name] = true
	}
	return m
}

// TestValidScope 范围二次校验。
func TestValidScope(t *testing.T) {
	for _, s := range []string{ScopeFull, ScopeConfig, ScopeDatabase, ScopeCertificate} {
		if !ValidScope(s) {
			t.Errorf("valid scope rejected: %s", s)
		}
	}
	for _, bad := range []string{"", "ALL", "full", "AUDIT"} {
		if ValidScope(bad) {
			t.Errorf("invalid scope accepted: %q", bad)
		}
	}
}

// TestScopeTablesSelection 范围 → 表集合。
func TestScopeTablesSelection(t *testing.T) {
	avail := allAvailable()

	full, err := ScopeTables(ScopeFull, avail)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range full {
		if n == "operation_audits" {
			t.Error("audit archive must never be restored")
		}
	}
	auditCount := 0
	for _, td := range backups.Tables {
		if td.Group == backups.GroupAudit {
			auditCount++
		}
	}
	if len(full) != len(backups.Tables)-auditCount {
		t.Errorf("FULL scope tables = %d, want %d", len(full), len(backups.Tables)-auditCount)
	}

	cert, err := ScopeTables(ScopeCertificate, avail)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert) != 1 || cert[0] != "certificates" {
		t.Errorf("CERTIFICATE scope = %v", cert)
	}

	dbScope, err := ScopeTables(ScopeDatabase, avail)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range dbScope {
		td, _ := backups.TableByName(n)
		if td.Group != backups.GroupDatabase {
			t.Errorf("DATABASE scope includes %s group table %s", td.Group, n)
		}
	}

	cfg, err := ScopeTables(ScopeConfig, avail)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range cfg {
		td, _ := backups.TableByName(n)
		if td.Group != backups.GroupConfig {
			t.Errorf("CONFIG scope includes %s group table %s", td.Group, n)
		}
	}
}

// TestScopeTablesAvailableFilter CONFIG_ONLY 备份无审计段时 FULL 恢复自动降级；
// 备份缺失范围所需表时返回空集合（由 Create 判 EMPTY_SCOPE 拒绝）。
func TestScopeTablesAvailableFilter(t *testing.T) {
	avail := map[string]bool{}
	for _, td := range backups.TablesForBackup(backups.TypeConfigOnly) {
		avail[td.Name] = true
	}
	full, err := ScopeTables(ScopeFull, avail)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != len(avail) {
		t.Errorf("filtered tables = %d, want %d", len(full), len(avail))
	}
	// 备份无证书表时 CERTIFICATE 范围为空
	cert, err := ScopeTables(ScopeCertificate, avail)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert) != 1 { // CONFIG_ONLY 备份含 certificates 表
		t.Errorf("CERTIFICATE scope on CONFIG_ONLY backup = %v", cert)
	}
	delete(avail, "certificates")
	cert, err = ScopeTables(ScopeCertificate, avail)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert) != 0 {
		t.Error("CERTIFICATE scope without certificates table should be empty")
	}
}

func TestScopeTablesForRestoreIncludesCurrentTablesWhenLegacyBackupOmitsThem(t *testing.T) {
	legacy := map[string]bool{"applications": true, "api_endpoints": true}
	available, err := ScopeTables(ScopeConfig, legacy)
	if err != nil {
		t.Fatalf("ScopeTables() error = %v", err)
	}
	if len(available) != 1 || available[0] != "api_endpoints" {
		t.Fatalf("legacy available tables = %v, want only api_endpoints", available)
	}
	current, err := ScopeTablesForRestore(ScopeConfig)
	if err != nil {
		t.Fatalf("ScopeTablesForRestore() error = %v", err)
	}
	pos := map[string]int{}
	for i, name := range current {
		pos[name] = i
	}
	for child, parent := range map[string]string{
		"application_policies": "applications",
		"api_endpoints":        "applications",
		"api_model_versions":   "api_endpoints",
		"api_response_schemas": "api_model_versions",
	} {
		if pos[parent] >= pos[child] {
			t.Fatalf("%s must be restored before %s: %v", parent, child, current)
		}
	}
}

// TestScopeTablesTopology 恢复顺序满足依赖（parent 先于 child）。
func TestScopeTablesTopology(t *testing.T) {
	full, err := ScopeTables(ScopeFull, allAvailable())
	if err != nil {
		t.Fatal(err)
	}
	pos := map[string]int{}
	for i, n := range full {
		pos[n] = i
	}
	checks := [][2]string{
		{"roles", "user_roles"}, {"users", "user_roles"},
		{"roles", "role_permissions"}, {"permissions", "role_permissions"},
		{"applications", "upstreams"}, {"applications", "application_domains"},
		{"protection_policies", "exception_policies"}, {"applications", "ip_access_rules"},
	}
	for _, c := range checks {
		if pos[c[0]] >= pos[c[1]] {
			t.Errorf("%s should come before %s", c[0], c[1])
		}
	}
}

// TestStagingSchema 隔离 schema 名派生与校验。
func TestStagingSchema(t *testing.T) {
	for i := 0; i < 100; i++ {
		id := uuid.New()
		name := StagingSchema(id)
		if !ValidStagingSchema(name) {
			t.Errorf("generated schema name invalid: %s", name)
		}
	}
	// 确定性
	id := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	if StagingSchema(id) != "jzrestore_123e4567" {
		t.Errorf("unexpected schema name: %s", StagingSchema(id))
	}
	for _, bad := range []string{"public", "jzrestore_", "jzrestore_xyz12345", "jzrestore_123e456G", "pg_catalog"} {
		if ValidStagingSchema(bad) {
			t.Errorf("invalid schema name accepted: %s", bad)
		}
	}
}

// TestIntersectColumns 列交集保持备份列序，剔除当前不存在的列。
func TestIntersectColumns(t *testing.T) {
	backupCols := []string{"id", "name", "legacy_col", "created_at"}
	current := map[string]bool{"id": true, "name": true, "created_at": true}
	got := intersectColumns(backupCols, current)
	if len(got) != 3 || got[0] != "id" || got[1] != "name" || got[2] != "created_at" {
		t.Errorf("intersect = %v", got)
	}
	if len(intersectColumns(backupCols, map[string]bool{})) != 0 {
		t.Error("empty intersect expected")
	}
}

// TestQuotedColumnList 列名引用防注入。
func TestQuotedColumnList(t *testing.T) {
	got := quotedColumnList([]string{"id", "user_name"})
	if got != `"id", "user_name"` {
		t.Errorf("quoted = %s", got)
	}
	// 恶意列名被安全引用（pgx.Identifier.Sanitize 转义）
	evil := quotedColumnList([]string{`x"; DROP TABLE users; --`})
	if evil != `"x""; DROP TABLE users; --"` {
		t.Errorf("evil quoting = %s", evil)
	}
}

func TestExtendImportDeadlinesAllowsSlowBody(t *testing.T) {
	const serverTimeout = 300 * time.Millisecond
	entered := make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extendImportDeadlines(w)
		defer restoreImportDeadlines(w)
		close(entered)
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.Config.ReadTimeout = serverTimeout
	srv.Config.WriteTimeout = serverTimeout
	srv.Start()
	defer srv.Close()

	pr, pw := io.Pipe()
	go func() {
		defer func() { _ = pw.Close() }()
		_, _ = pw.Write([]byte("part1"))
		<-entered
		time.Sleep(2 * serverTimeout)
		_, _ = pw.Write([]byte("part2"))
	}()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/restores/import", pr)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Timeout = 5 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("slow import body interrupted: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
}
