// diagnostics_sweeper_test.go 到期扫描与基线恢复对账单元测试（fake 仓储 + 真实 CA 签名：
// 到期迁移、恢复发布、pending 对账重试、无到期空转）。
package apm

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newDiagSweeper(t *testing.T) (*DiagnosticsSweeper, *fakeDiagRepo, *fakeAgentRepo) {
	t.Helper()
	diag := newFakeDiagRepo()
	agents := newFakeAgentRepo()
	ca, _ := newTestCA(t)
	return NewDiagnosticsSweeper(diag, agents, ca, NewAgentControlConfig("", 72, 10)), diag, agents
}

func TestDiagnosticsSweeperExpireAndRestore(t *testing.T) {
	sweeper, diag, agents := newDiagSweeper(t)
	ctx := context.Background()
	appID := uuid.New()

	// 到期会话 + 既有诊断叠加策略 v1
	sess := testSession(t, appID)
	sess.ExpiresAt = time.Now().Add(-time.Minute)
	diag.sessions[sess.ID] = sess
	overlay, _ := overlayDiagnosticPolicy(DefaultBaselinePolicy(), sess)
	if _, err := publishScopedPolicy(ctx, agents, sweeper.ca, ApplicationPolicyScope(appID), overlay, sess.ExpiresAt, time.Now(), nil); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	// 未到期会话不受影响
	fresh := testSession(t, uuid.New())
	fresh.ExpiresAt = time.Now().Add(30 * time.Minute)
	diag.sessions[fresh.ID] = fresh

	expired, restored, err := sweeper.SweepOnce(ctx, time.Now())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if expired != 1 || restored != 1 {
		t.Errorf("expired=%d restored=%d, want 1/1", expired, restored)
	}
	if diag.sessions[sess.ID].Status != DiagnosticStatusExpired || !diag.sessions[sess.ID].BaselineRestored {
		t.Errorf("session = %s/%v", diag.sessions[sess.ID].Status, diag.sessions[sess.ID].BaselineRestored)
	}
	if diag.sessions[fresh.ID].Status != DiagnosticStatusActive {
		t.Error("未到期会话不得被迁移")
	}
	// 恢复策略：v2、诊断叠加剥除、签名可验
	rows := agents.policies[ApplicationPolicyScope(appID)]
	if len(rows) != 2 {
		t.Fatalf("policy versions = %d, want 2", len(rows))
	}
	latest := rows[1]
	if latest.Policy["diagnostics"].(map[string]interface{})["enabled"] != false {
		t.Error("恢复策略必须剥除诊断叠加")
	}
	if err := VerifyPolicySignature(sweeper.ca.PublicKeyHex(), latest.Envelope()); err != nil {
		t.Errorf("恢复策略签名无效: %v", err)
	}

	// 幂等：再次扫描无新增动作
	expired, restored, err = sweeper.SweepOnce(ctx, time.Now())
	if err != nil || expired != 0 || restored != 0 {
		t.Errorf("重复扫描 = %d/%d/%v，应空转", expired, restored, err)
	}
}

func TestDiagnosticsSweeperPendingRestoreReconcile(t *testing.T) {
	sweeper, diag, agents := newDiagSweeper(t)
	ctx := context.Background()
	appID := uuid.New()

	// stop/kill 同步恢复失败的残留态：终态 + baseline_restored=false + 作用域叠加策略仍在
	sess := testSession(t, appID)
	sess.Status = DiagnosticStatusStopped
	sess.BaselineRestored = false
	now := time.Now()
	sess.StoppedAt = &now
	diag.sessions[sess.ID] = sess
	overlay, _ := overlayDiagnosticPolicy(DefaultBaselinePolicy(), sess)
	if _, err := publishScopedPolicy(ctx, agents, sweeper.ca, ApplicationPolicyScope(appID), overlay, sess.ExpiresAt, time.Now(), nil); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	expired, restored, err := sweeper.SweepOnce(ctx, time.Now())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if expired != 0 || restored != 1 {
		t.Errorf("expired=%d restored=%d, want 0/1（对账重试补齐）", expired, restored)
	}
	if !diag.sessions[sess.ID].BaselineRestored {
		t.Error("对账后 baseline_restored 必须置位")
	}
	if rows := agents.policies[ApplicationPolicyScope(appID)]; len(rows) != 2 {
		t.Errorf("恢复策略版本数 = %d, want 2", len(rows))
	}
}
