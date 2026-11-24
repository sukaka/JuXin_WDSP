package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/users"
)

type fakeBootstrapStore struct {
	roleUsers   map[string][]*users.User
	takenNames  map[string]bool
	raceSkipped map[string]bool
	created     []*users.User
}

func newFakeBootstrapStore() *fakeBootstrapStore {
	return &fakeBootstrapStore{
		roleUsers:   map[string][]*users.User{},
		takenNames:  map[string]bool{},
		raceSkipped: map[string]bool{},
	}
}

func (f *fakeBootstrapStore) seedRoleUser(roleCode, username string) {
	u := &users.User{ID: uuid.New(), Username: username, Status: users.StatusActive}
	f.roleUsers[roleCode] = append(f.roleUsers[roleCode], u)
	f.takenNames[strings.ToLower(username)] = true
}

func (f *fakeBootstrapStore) HasRoleUsers(_ context.Context, roleCode string) (bool, error) {
	return len(f.roleUsers[roleCode]) > 0, nil
}

func (f *fakeBootstrapStore) EnsureInitialRoleUser(_ context.Context, roleCode string, u *users.User) (bool, error) {
	if len(f.roleUsers[roleCode]) > 0 || f.raceSkipped[roleCode] {
		return false, nil
	}
	lower := strings.ToLower(u.Username)
	if f.takenNames[lower] {
		return false, users.ErrUsernameExists
	}
	u.ID = uuid.New()
	cp := *u
	f.roleUsers[roleCode] = append(f.roleUsers[roleCode], &cp)
	f.takenNames[lower] = true
	f.created = append(f.created, &cp)
	return true, nil
}

func defaultTestCfg() *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			InitialAdminUsername:      "admin",
			InitialOperAdminUsername:  "operadmin",
			InitialAuditAdminUsername: "auditor",
		},
	}
}

func TestEnsureInitialAdmins_FreshDBGeneratesThreeAccountsIdempotently(t *testing.T) {
	store := newFakeBootstrapStore()
	var buf bytes.Buffer

	if err := ensureInitialAdmins(context.Background(), store, defaultTestCfg(), &buf); err != nil {
		t.Fatalf("ensureInitialAdmins() error = %v", err)
	}
	if len(store.created) != 3 {
		t.Fatalf("created count = %d, want 3", len(store.created))
	}

	want := []struct {
		role        string
		username    string
		displayName string
	}{
		{authz.RoleSystemAdmin, "admin", "系统管理员"},
		{authz.RoleSecurityAdmin, "operadmin", "运维管理员"},
		{authz.RoleAuditAdmin, "auditor", "审计管理员"},
	}
	banner := buf.String()
	for i, w := range want {
		got := store.created[i]
		if got.Username != w.username || got.DisplayName != w.displayName {
			t.Errorf("account[%d] = (%q, %q), want (%q, %q)", i, got.Username, got.DisplayName, w.username, w.displayName)
		}
		if !got.MustChangePassword {
			t.Errorf("account %s MustChangePassword = false, want true", got.Username)
		}
		if got.Status != users.StatusActive {
			t.Errorf("account %s Status = %q, want ACTIVE", got.Username, got.Status)
		}
		if !strings.Contains(banner, w.username) || !strings.Contains(banner, w.displayName) || !strings.Contains(banner, w.role) {
			t.Errorf("banner missing account %s (%s / %s):\n%s", w.username, w.displayName, w.role, banner)
		}
	}

	// 验证横幅中打印的临时密码能通过 Argon2id 哈希校验
	var printedPasswords []string
	for _, line := range strings.Split(banner, "\n") {
		if idx := strings.Index(line, "临时密码:"); idx >= 0 {
			pwd := strings.TrimSpace(line[idx+len("临时密码:"):])
			printedPasswords = append(printedPasswords, pwd)
		}
	}
	if len(printedPasswords) != 3 {
		t.Fatalf("printed passwords = %d, want 3", len(printedPasswords))
	}
	for i, pwd := range printedPasswords {
		if err := security.VerifyPassword(pwd, store.created[i].PasswordHash); err != nil {
			t.Errorf("password[%d] failed verification: %v", i, err)
		}
	}

	// 二次执行完全幂等，不重复创建、不重复打印
	var buf2 bytes.Buffer
	if err := ensureInitialAdmins(context.Background(), store, defaultTestCfg(), &buf2); err != nil {
		t.Fatalf("second ensureInitialAdmins() error = %v", err)
	}
	if len(store.created) != 3 {
		t.Fatalf("after second run created count = %d, want 3", len(store.created))
	}
	if buf2.Len() != 0 {
		t.Errorf("second run should not print banner, got:\n%s", buf2.String())
	}
}

func TestEnsureInitialAdmins_UsesEnvPasswordsWithoutBanner(t *testing.T) {
	store := newFakeBootstrapStore()
	cfg := defaultTestCfg()
	cfg.Security.InitialAdminPassword = "Sys@Strong2026!A"
	cfg.Security.InitialOperAdminPassword = "Oper@Strong2026!B"
	cfg.Security.InitialAuditAdminPassword = "Aud@Strong2026!C"
	var buf bytes.Buffer

	if err := ensureInitialAdmins(context.Background(), store, cfg, &buf); err != nil {
		t.Fatalf("ensureInitialAdmins() error = %v", err)
	}
	if len(store.created) != 3 {
		t.Fatalf("created count = %d, want 3", len(store.created))
	}
	if buf.Len() != 0 {
		t.Errorf("env-injected passwords must not print stdout banner, got:\n%s", buf.String())
	}
	pwds := []string{
		cfg.Security.InitialAdminPassword,
		cfg.Security.InitialOperAdminPassword,
		cfg.Security.InitialAuditAdminPassword,
	}
	for i, pwd := range pwds {
		if err := security.VerifyPassword(pwd, store.created[i].PasswordHash); err != nil {
			t.Errorf("env password[%d] verification failed: %v", i, err)
		}
		if !store.created[i].MustChangePassword {
			t.Errorf("account[%d] MustChangePassword = false, want true", i)
		}
	}
}

func TestEnsureInitialAdmins_PartialLegacyDBCreatesMissingRolesOnly(t *testing.T) {
	store := newFakeBootstrapStore()
	// 模拟老库升级：已有 jiuzhang_admin 作为 SYSTEM_ADMIN，但缺少运维与审计管理员
	store.seedRoleUser(authz.RoleSystemAdmin, "jiuzhang_admin")

	var buf bytes.Buffer
	if err := ensureInitialAdmins(context.Background(), store, defaultTestCfg(), &buf); err != nil {
		t.Fatalf("ensureInitialAdmins() error = %v", err)
	}
	if len(store.created) != 2 {
		t.Fatalf("created count = %d, want 2 (operadmin + auditor)", len(store.created))
	}
	if store.created[0].Username != "operadmin" || store.created[1].Username != "auditor" {
		t.Fatalf("created usernames = [%s, %s], want [operadmin, auditor]", store.created[0].Username, store.created[1].Username)
	}
	if len(store.roleUsers[authz.RoleSystemAdmin]) != 1 || store.roleUsers[authz.RoleSystemAdmin][0].Username != "jiuzhang_admin" {
		t.Fatalf("legacy SYSTEM_ADMIN modified unexpectedly: %+v", store.roleUsers[authz.RoleSystemAdmin])
	}
	if strings.Contains(buf.String(), "SYSTEM_ADMIN") {
		t.Errorf("banner should not include existing SYSTEM_ADMIN:\n%s", buf.String())
	}
}

func TestEnsureInitialAdmins_SkipsUsernameCollisionWithoutBlockingStartup(t *testing.T) {
	store := newFakeBootstrapStore()
	// 假设 operadmin 用户名已被历史逻辑删除或其它角色占用
	store.takenNames["operadmin"] = true

	var buf bytes.Buffer
	if err := ensureInitialAdmins(context.Background(), store, defaultTestCfg(), &buf); err != nil {
		t.Fatalf("ensureInitialAdmins() should not fail on username collision, got: %v", err)
	}
	if len(store.created) != 2 {
		t.Fatalf("created count = %d, want 2 (admin + auditor)", len(store.created))
	}
	if store.created[0].Username != "admin" || store.created[1].Username != "auditor" {
		t.Fatalf("created = [%s, %s], want [admin, auditor]", store.created[0].Username, store.created[1].Username)
	}
}

func TestEnsureInitialAdmins_SkipsInvalidUsernameAndFallsBackEmptyUsername(t *testing.T) {
	store := newFakeBootstrapStore()
	cfg := &config.Config{
		Security: config.SecurityConfig{
			InitialAdminUsername:      "   ",  // 空串应回落默认 admin
			InitialOperAdminUsername:  "root", // 保留词：告警跳过，不阻塞
			InitialAuditAdminUsername: "auditor",
		},
	}

	var buf bytes.Buffer
	if err := ensureInitialAdmins(context.Background(), store, cfg, &buf); err != nil {
		t.Fatalf("ensureInitialAdmins() error = %v", err)
	}
	if len(store.created) != 2 {
		t.Fatalf("created count = %d, want 2", len(store.created))
	}
	if store.created[0].Username != "admin" || store.created[1].Username != "auditor" {
		t.Fatalf("created = [%s, %s], want [admin, auditor]", store.created[0].Username, store.created[1].Username)
	}
}
