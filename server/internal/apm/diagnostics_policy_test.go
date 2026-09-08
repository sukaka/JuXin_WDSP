// diagnostics_policy_test.go 诊断叠加/基线恢复策略机制测试（复用 WP8 签名与版本纪律：
// 叠加只在 diagnostics 子树、信封 expires_at=会话硬截止；恢复剥除叠加、版本单调递增、
// 签名覆盖真实落库版本）。
package apm

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testSession(t *testing.T, appID uuid.UUID) *DiagnosticSession {
	t.Helper()
	now := time.Now().UTC()
	return &DiagnosticSession{
		ID:              uuid.New(),
		Scope:           DiagnosticScope{ApplicationID: appID, Service: "shop-svc", InstanceIDs: []string{"i-1"}},
		Capabilities:    []string{DiagCapSQLDetail, DiagCapFunctionProbe},
		SamplingRate:    0.5,
		DurationMinutes: 30,
		Status:          DiagnosticStatusActive,
		CreatedAt:       now, ExpiresAt: now.Add(30 * time.Minute),
	}
}

func TestOverlayAndStripDiagnosticPolicy(t *testing.T) {
	appID := uuid.New()
	sess := testSession(t, appID)
	base := DefaultBaselinePolicy()

	overlay, err := overlayDiagnosticPolicy(base, sess)
	if err != nil {
		t.Fatalf("overlay: %v", err)
	}
	// 入参不被修改（基线保持默认关闭）
	diag, _ := base["diagnostics"].(map[string]interface{})
	if diag["enabled"] != false {
		t.Error("overlay 必须深拷贝，不得改入参基线")
	}
	diag, _ = overlay["diagnostics"].(map[string]interface{})
	if diag["enabled"] != true {
		t.Fatalf("overlay diagnostics.enabled = %v", diag["enabled"])
	}
	session, _ := diag["session"].(map[string]interface{})
	if session["id"] != sess.ID.String() || session["sampling_rate"] != 0.5 {
		t.Errorf("session overlay = %v", session)
	}
	if session["expires_at"] != sess.ExpiresAt.UTC().Format(time.RFC3339) {
		t.Errorf("expires_at 硬截止 = %v", session["expires_at"])
	}
	caps, _ := session["capabilities"].([]interface{})
	if len(caps) != 2 {
		t.Errorf("capabilities = %v", caps)
	}
	scope, _ := session["scope"].(map[string]interface{})
	if scope["application_id"] != appID.String() || scope["service"] != "shop-svc" {
		t.Errorf("scope = %v", scope)
	}
	// 基线其余键保留（叠加只动 diagnostics 子树）
	if overlay["sampling_rate"] != base["sampling_rate"] || overlay["sql_mode"] != base["sql_mode"] {
		t.Error("基线其余键必须原样保留")
	}

	// 剥除恢复：diagnostics 复位关闭；其余键保留；幂等
	stripped, err := stripDiagnosticOverlay(overlay)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	diag, _ = stripped["diagnostics"].(map[string]interface{})
	if diag["enabled"] != false {
		t.Errorf("stripped diagnostics.enabled = %v", diag["enabled"])
	}
	if _, hasSession := diag["session"]; hasSession {
		t.Error("stripped 不得残留 session 子树")
	}
	if stripped["sql_mode"] != base["sql_mode"] {
		t.Error("strip 不得改动其余基线键")
	}
	again, err := stripDiagnosticOverlay(stripped)
	if err != nil || again["diagnostics"].(map[string]interface{})["enabled"] != false {
		t.Error("strip 对无叠加基线必须幂等")
	}
	// 剥除结果必须过基线白名单校验（恢复发布内容=合法基线）
	if err := ValidateBaselinePolicy(stripped); err != nil {
		t.Errorf("恢复策略须为合法基线: %v", err)
	}
}

func TestPublishScopedPolicyVersionDiscipline(t *testing.T) {
	repo := newFakeAgentRepo()
	ca, _ := newTestCA(t)
	ctx := context.Background()
	appID := uuid.New()
	scope := ApplicationPolicyScope(appID)

	// 发布 v1（诊断叠加，信封 expires_at=硬截止）
	sess := testSession(t, appID)
	overlay, err := overlayDiagnosticPolicy(DefaultBaselinePolicy(), sess)
	if err != nil {
		t.Fatalf("overlay: %v", err)
	}
	row1, err := publishScopedPolicy(ctx, repo, ca, scope, overlay, sess.ExpiresAt, time.Now(), nil)
	if err != nil {
		t.Fatalf("publish v1: %v", err)
	}
	if row1.Version != 1 || row1.ExpiresAt != sess.ExpiresAt.UTC() {
		t.Errorf("v1 = version %d expires %v", row1.Version, row1.ExpiresAt)
	}
	if err := VerifyPolicySignature(ca.PublicKeyHex(), row1.Envelope()); err != nil {
		t.Errorf("v1 签名无效: %v", err)
	}

	// 恢复发布 v2（剥除叠加，信封有效期回归 30 天）
	row2, err := restoreBaselinePolicy(ctx, repo, ca, appID, defaultPolicyValidity, time.Now(), nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if row2.Version != 2 {
		t.Errorf("restore version = %d, want 2（单调递增）", row2.Version)
	}
	if d := row2.Policy["diagnostics"].(map[string]interface{}); d["enabled"] != false {
		t.Errorf("restore 后 diagnostics.enabled = %v", d["enabled"])
	}
	if err := VerifyPolicySignature(ca.PublicKeyHex(), row2.Envelope()); err != nil {
		t.Errorf("v2 签名无效: %v", err)
	}

	// 无版本作用域恢复 → nil, nil（无需恢复）
	row, err := restoreBaselinePolicy(ctx, repo, ca, uuid.New(), defaultPolicyValidity, time.Now(), nil)
	if row != nil || err != nil {
		t.Errorf("空作用域恢复 = %v, %v；应 nil, nil", row, err)
	}

	// 叠加底稿解析：应用级优先且剥叠加自愈（恢复失败残留场景）
	base, err := resolveBaselineForDiagnostic(ctx, repo, appID)
	if err != nil {
		t.Fatalf("resolve baseline: %v", err)
	}
	if d := base["diagnostics"].(map[string]interface{}); d["enabled"] != false {
		t.Error("叠加底稿必须剥离诊断叠加（防恢复失败残留叠加被二次叠加）")
	}
	// 全局回退与内置默认
	base, err = resolveBaselineForDiagnostic(ctx, repo, uuid.New())
	if err != nil || base["sql_mode"] != DefaultBaselinePolicy()["sql_mode"] {
		t.Errorf("无策略环境应回退内置默认基线: %v, %v", base, err)
	}
}
