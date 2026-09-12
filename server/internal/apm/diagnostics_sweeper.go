// diagnostics_sweeper.go APM 阶段4 深度诊断到期扫描与基线恢复对账（每分钟周期任务，
// 挂 app.StartStage6Workers；恒装配，APM 总开关关闭时每轮空转——运行期热生效，
// 见 SetEnabledFunc）。
//
// 职责（设计 §6.3 第 5 步 / §21.2"诊断结束 1 分钟内恢复基线策略"）：
//  1. 到期迁移：ACTIVE 且过 expires_at 硬截止 → EXPIRED（同事务把关联应用的
//  2. DIAGNOSING Agent 回 CONNECTED_BASELINE）；
//  3. 基线恢复对账：终态会话 baseline_restored=false → 重新下发基线恢复策略
//     （覆盖 stop/kill 路径同步发布失败的场景；发布本身是幂等的单调新版本）。
//
// Agent 失联兜底不在本任务：诊断策略信封 expires_at=会话硬截止，控制面不可达时
// 过期诊断策略由 Agent 本地自动失效（§9.2），不依赖本任务可达性。
package apm

import (
	"context"
	"log/slog"
	"time"
)

// diagnosticSweepInterval 到期扫描周期（WP17 SLO 评估同口径：每分钟）。
const diagnosticSweepInterval = time.Minute

// diagnosticPendingRestoreLimit 单轮对账重试上限（会话为低频操作，100 充足；
// 超出部分下轮继续——反复失败说明存在系统性故障，须留痕迹而非风暴重试）。
const diagnosticPendingRestoreLimit = 100

// DiagnosticsSweeper 诊断会话周期工人（无状态；全部副作用经仓储落库，重启安全）。
type DiagnosticsSweeper struct {
	store  DiagnosticsRepository
	agents AgentRepository
	ca     *AgentCA
	cfg    AgentControlConfig
	now    func() time.Time
	// enabledFn APM 运行期总开关判定（nil = 恒 true，兼容既有测试与装配）
	enabledFn func(ctx context.Context) bool
}

// NewDiagnosticsSweeper 创建诊断会话周期工人。
func NewDiagnosticsSweeper(store DiagnosticsRepository, agents AgentRepository, ca *AgentCA, cfg AgentControlConfig) *DiagnosticsSweeper {
	return &DiagnosticsSweeper{store: store, agents: agents, ca: ca, cfg: cfg, now: time.Now}
}

// SetEnabledFunc 注入 APM 运行期总开关判定（生产为 RuntimeConfig.Enabled；
// 关闭时 Run 每轮空转，界面重新开启即恢复扫描，无需重启）。
func (s *DiagnosticsSweeper) SetEnabledFunc(fn func(ctx context.Context) bool) *DiagnosticsSweeper {
	s.enabledFn = fn
	return s
}

// Run 周期循环（每分钟一轮；ctx 取消即退出；首轮延迟一个周期——进程启动期
// 不存在"刚到期"的紧迫语义）。
func (s *DiagnosticsSweeper) Run(ctx context.Context) {
	t := time.NewTicker(diagnosticSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// APM 总开关关闭：本轮空转（运行期热生效，开启后下轮自动恢复）
			if s.enabledFn != nil && !s.enabledFn(ctx) {
				continue
			}
			if _, _, err := s.SweepOnce(ctx, s.now()); err != nil {
				slog.Warn("apm diagnostics sweep failed", "error", err)
			}
		}
	}
}

// SweepOnce 单轮扫描（测试可直接驱动）：到期迁移 → 逐会话下发基线恢复策略 →
// 对账重试存量未恢复会话。返回到期迁移数与本轮新完成恢复数。
// 单会话恢复失败不中断整轮（如实记日志，下轮重试）。
func (s *DiagnosticsSweeper) SweepOnce(ctx context.Context, now time.Time) (expired, restored int, err error) {
	expiredSessions, err := s.store.ExpireDueSessions(ctx, now.UTC())
	if err != nil {
		return 0, 0, err
	}
	expired = len(expiredSessions)
	handled := map[string]bool{}
	for i := range expiredSessions {
		handled[expiredSessions[i].ID.String()] = true
		if s.restoreBaseline(ctx, &expiredSessions[i], now) {
			restored++
		}
	}
	// 对账：终态但未恢复的存量会话（stop/kill 同步发布失败、进程重启等场景）
	pending, err := s.store.ListPendingRestore(ctx, diagnosticPendingRestoreLimit)
	if err != nil {
		return expired, restored, err
	}
	for i := range pending {
		if handled[pending[i].ID.String()] {
			continue // 本轮已处理
		}
		if s.restoreBaseline(ctx, &pending[i], now) {
			restored++
		}
	}
	return expired, restored, nil
}

// restoreBaseline 为终态会话下发基线恢复策略并置位（与 handler 侧同语义：
// 发布/标记失败如实记日志并返回 false，交由下轮对账）。
func (s *DiagnosticsSweeper) restoreBaseline(ctx context.Context, sess *DiagnosticSession, now time.Time) bool {
	row, err := restoreBaselinePolicy(ctx, s.agents, s.ca, sess.Scope.ApplicationID, s.cfg.PolicyValidity, now, nil)
	if err != nil {
		slog.Warn("apm diagnostics: 基线恢复策略下发失败（下轮对账重试）",
			"session_id", sess.ID, "application_id", sess.Scope.ApplicationID, "error", err)
		return false
	}
	if row == nil {
		slog.Warn("apm diagnostics: 作用域无策略版本，无需恢复（异常态，如实记录）",
			"session_id", sess.ID, "application_id", sess.Scope.ApplicationID)
	}
	if err := s.store.MarkBaselineRestored(ctx, sess.ID); err != nil {
		slog.Warn("apm diagnostics: 标记 baseline_restored 失败", "session_id", sess.ID, "error", err)
		return false
	}
	return true
}
