package tests

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/accesscontrolversions"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/guardconfig"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
	"github.com/jiuzhang-waf/server/internal/ratelimitpolicies"
	"github.com/jiuzhang-waf/server/internal/securityidentities"
	"github.com/jiuzhang-waf/server/internal/trustedproxies"
)

func TestIdentityManualBlocksMigration000214Static(t *testing.T) {
	up := readMigration(t, "000214_identity_manual_blocks.up.sql")
	for _, fragment := range []string{
		"blocked_reason", "blocked_by", "blocked_at", "unblocked_by", "unblocked_at",
		"CHECK (status IN ('NORMAL','BLOCKED'))", "security_identities.block",
		"r.code IN ('SYSTEM_ADMIN','SECURITY_ADMIN')",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("000214 up missing %q: %s", fragment, up)
		}
	}
	down := readMigration(t, "000214_identity_manual_blocks.down.sql")
	for _, fragment := range []string{
		"DELETE FROM role_permissions", "DELETE FROM permissions", "DROP CONSTRAINT IF EXISTS client_identity_status_check",
		"DROP COLUMN IF EXISTS blocked_reason", "DROP COLUMN IF EXISTS unblocked_at",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("000214 down missing %q: %s", fragment, down)
		}
	}
}

func TestIdentityManualBlocksMigration000214Integration(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	up := readMigration(t, "000214_identity_manual_blocks.up.sql")
	down := readMigration(t, "000214_identity_manual_blocks.down.sql")
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, up); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	if got := s8Count(t, env, `SELECT count(DISTINCT r.code) FROM roles r
		JOIN role_permissions rp ON rp.role_id=r.id JOIN permissions p ON p.id=rp.permission_id
		WHERE p.code='security_identities.block' AND r.code IN ('SYSTEM_ADMIN','SECURITY_ADMIN','AUDIT_ADMIN')`); got != 2 {
		t.Fatalf("block permission roles = %d, want 2", got)
	}
	identityID := uuid.New()
	if _, err := env.db.Exec(ctx, `INSERT INTO client_identity(id,identity_key,status) VALUES ($1,'migration-normal','NORMAL')`, identityID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.db.Exec(ctx, down); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM information_schema.columns WHERE table_name='client_identity'
		AND column_name IN ('blocked_reason','blocked_by','blocked_at','unblocked_by','unblocked_at')`); got != 0 {
		t.Fatalf("block columns remain after down: %d", got)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code='security_identities.block'`); got != 0 {
		t.Fatalf("block permission remains after down: %d", got)
	}
	var status string
	if err := env.db.QueryRow(ctx, `SELECT status FROM client_identity WHERE id=$1`, identityID).Scan(&status); err != nil || status != "NORMAL" {
		t.Fatalf("existing NORMAL not preserved: status=%s err=%v", status, err)
	}
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM information_schema.columns WHERE table_name='client_identity'
		AND column_name IN ('blocked_reason','blocked_by','blocked_at','unblocked_by','unblocked_at')`); got != 5 {
		t.Fatalf("block columns after re-up = %d, want 5", got)
	}
}

func identityBlocksProvider(env *testEnv, apiEnabled bool) *guardconfig.Provider {
	provider := guardconfig.NewProvider(
		trustedproxies.NewStore(env.db), protectedaddresses.NewStore(env.db),
		accessrules.NewStore(env.db), ratelimitpolicies.NewStore(env.db),
		accesscontrolversions.NewStore(env.db),
		guardconfig.Config{APIDynamicProtection: apiEnabled, APIProtectionMode: "OBSERVE"},
	)
	provider.SetIdentityBlockLister(securityidentities.NewStore(env.db))
	return provider
}

func TestIdentityManualBlockPublishAndAuditIntegration(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	systemCookies, systemCSRF := env.login(t, "test_sysadmin", env.adminPwd)
	securityCookies, securityCSRF := env.s5Login(t, "imbsec", "SECURITY_ADMIN")
	auditCookies, auditCSRF := env.s5Login(t, "imbaudit", "AUDIT_ADMIN")
	identityID := uuid.New()
	identityKey := "sensitive-identity-key"
	if _, err := env.db.Exec(ctx, `INSERT INTO client_identity(id,identity_key,status) VALUES ($1,$2,'NORMAL')`, identityID, identityKey); err != nil {
		t.Fatal(err)
	}
	blockPath := "/api/v1/security/identities/" + identityID.String() + "/block"
	unblockPath := "/api/v1/security/identities/" + identityID.String() + "/unblock"

	s5Expect(t, env.post(t, blockPath, `{"reason":"confirmed abuse"}`, auditCookies, auditCSRF), http.StatusForbidden, "audit admin cannot block")
	if status := env.post(t, blockPath, `{"reason":"confirmed abuse"}`, systemCookies, systemCSRF); status.StatusCode != http.StatusOK {
		t.Fatalf("system admin block status=%d", status.StatusCode)
	} else {
		var result apiResp
		readJSON(t, status, &result)
		status.Body.Close()
		if result.Data["changed"] != true {
			t.Fatalf("first block changed=%v", result.Data["changed"])
		}
	}
	if status := env.post(t, blockPath, `{"reason":"replacement must not win"}`, securityCookies, securityCSRF); status.StatusCode != http.StatusOK {
		t.Fatalf("repeat block status=%d", status.StatusCode)
	} else {
		var result apiResp
		readJSON(t, status, &result)
		status.Body.Close()
		if result.Data["changed"] != false {
			t.Fatalf("repeat block changed=%v", result.Data["changed"])
		}
	}
	s5Expect(t, env.post(t, "/api/v1/security/identities/"+uuid.NewString()+"/block",
		`{"reason":"missing"}`, systemCookies, systemCSRF), http.StatusNotFound, "block missing identity")
	s5Expect(t, env.post(t, blockPath, `{"reason":" "}`, systemCookies, systemCSRF), http.StatusBadRequest, "blank reason")
	s5Expect(t, env.post(t, unblockPath, `{}`, systemCookies, systemCSRF), http.StatusBadRequest, "non-empty unblock")

	provider := identityBlocksProvider(env, true)
	blockedCfg, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build blocked config: %v", err)
	}
	if len(blockedCfg.APIIdentityBlocks) != 1 || blockedCfg.APIIdentityBlocks[0].ID != identityID.String() ||
		blockedCfg.APIIdentityBlocks[0].IdentityKey != identityKey {
		t.Fatalf("published blocks = %+v", blockedCfg.APIIdentityBlocks)
	}
	if generated := s8GenerateGuardJSON(t, blockedCfg); !strings.Contains(generated, `"api_identity_blocks"`) || !strings.Contains(generated, identityKey) {
		t.Fatalf("blocked config missing current identity: %s", generated)
	}
	blockedVersion := blockedCfg.APIPolicyVersion
	versionID, err := provider.SaveVersionSnapshot(ctx, blockedCfg, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("save blocked snapshot: %v", err)
	}

	if status := env.post(t, unblockPath, "", securityCookies, securityCSRF); status.StatusCode != http.StatusOK {
		t.Fatalf("security admin unblock status=%d", status.StatusCode)
	} else {
		var result apiResp
		readJSON(t, status, &result)
		status.Body.Close()
		if result.Data["changed"] != true {
			t.Fatalf("first unblock changed=%v", result.Data["changed"])
		}
	}
	if status := env.post(t, unblockPath, "", systemCookies, systemCSRF); status.StatusCode != http.StatusOK {
		t.Fatalf("repeat unblock status=%d", status.StatusCode)
	} else {
		var result apiResp
		readJSON(t, status, &result)
		status.Body.Close()
		if result.Data["changed"] != false {
			t.Fatalf("repeat unblock changed=%v", result.Data["changed"])
		}
	}

	identity, err := securityidentities.NewStore(env.db).GetByID(ctx, identityID)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Status != "NORMAL" || identity.BlockedReason != "confirmed abuse" || identity.BlockedBy == nil || identity.BlockedAt == nil ||
		identity.UnblockedBy == nil || identity.UnblockedAt == nil {
		t.Fatalf("identity transition fields = %+v", identity)
	}
	normalCfg, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build NORMAL config: %v", err)
	}
	if len(normalCfg.APIIdentityBlocks) != 0 || normalCfg.APIPolicyVersion == blockedVersion {
		t.Fatalf("NORMAL config incorrectly retained blocks: %+v", normalCfg.APIIdentityBlocks)
	}
	if generated := s8GenerateGuardJSON(t, normalCfg); strings.Contains(generated, "api_identity_blocks") {
		t.Fatalf("NORMAL config contains identity blocks: %s", generated)
	}
	rolledBack, err := provider.GetVersionConfig(ctx, versionID)
	if err != nil {
		t.Fatalf("replay blocked snapshot after unblock: %v", err)
	}
	if len(rolledBack.APIIdentityBlocks) != 0 {
		t.Fatalf("rollback re-blocked NORMAL identity: %+v", rolledBack.APIIdentityBlocks)
	}

	if got := s8Count(t, env, `SELECT count(*) FROM operation_audits
		WHERE module='security_identities' AND object_id=$1 AND action IN ('block','unblock') AND risk_level='HIGH'`, identityID.String()); got != 2 {
		t.Fatalf("HIGH audit count = %d, want 2", got)
	}
	var summaries string
	if err := env.db.QueryRow(ctx, `SELECT COALESCE(string_agg(before_summary||after_summary,''),'')
		FROM operation_audits WHERE module='security_identities' AND object_id=$1`, identityID.String()).Scan(&summaries); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(summaries, identityKey) || strings.Contains(summaries, "confirmed abuse") || strings.Contains(summaries, "replacement must not win") {
		t.Fatalf("audit leaked identity key or reason: %s", summaries)
	}
}
