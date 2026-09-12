// diagnostics_store.go APM 阶段4 深度诊断会话仓储（迁移 000093）。
// 纪律（与 agents_store.go 同则）：全部 SQL 参数化；会话状态迁移经条件 UPDATE
// （WHERE status='ACTIVE'）原子落库，天然拒绝终态重复迁移与并发竞争；诊断叠加策略
// 版本沿用 WP8 纪律（作用域咨询锁串行化取 max+1，(scope,version) 唯一约束兜底）；
// 会话插入与策略发布在同一事务，防"会话已建策略未发"半态。
package apm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// kill switch 设置键（种子见迁移 000093；接口修改白名单登记 settings.AllowedSettingKeys）。
const (
	killSwitchGroup = "apm_diagnostics"
	killSwitchKey   = "kill_switch"
)

// DiagnosticsRepository 诊断会话存取抽象（handler/sweeper 单测以 fake 注入；生产 *DiagnosticsStore）。
type DiagnosticsRepository interface {
	// MatchOnlineAgents 匹配 scope 内的在线 Agent（存态非 REVOKED 且心跳未超 offlineAfter）。
	MatchOnlineAgents(ctx context.Context, scope DiagnosticScope, offlineAfter time.Duration, now time.Time) ([]uuid.UUID, error)
	// KillSwitchEnabled 读取 kill switch（设置行缺失按 false 处理——种子缺失属迁移异常，
	// 如实按关闭放行而非阻断管理面）。
	KillSwitchEnabled(ctx context.Context) (bool, error)
	// SetKillSwitch 写 kill switch；enabled=true 时同事务把全部 ACTIVE 会话置 KILLED
	// 并回基线 Agent 状态，返回被终止会话（供调用侧下发基线恢复策略与逐会话审计）。
	SetKillSwitch(ctx context.Context, enabled bool, operatorID *uuid.UUID, now time.Time) ([]DiagnosticSession, error)
	// CreateSessionWithPolicy 单事务创建会话 + 发布诊断叠加策略版本 + 匹配 Agent 置
	// DIAGNOSING；expectedVersion 为调用侧读取的当前策略版本（乐观并发复核，防
	// 签名版本与落库版本错配）；kill switch 在事务内带行锁复检（与 SetKillSwitch
	// 串行化，防 check-then-insert 竞态）。sess.PolicyVersion 成功时回填。
	CreateSessionWithPolicy(ctx context.Context, sess *DiagnosticSession, policy map[string]interface{},
		signature, keyID string, issuedAt time.Time, expectedVersion int64, matchedAgentIDs []uuid.UUID) error
	// GetSession 按 ID 取会话（不存在 → ErrDiagnosticNotFound）。
	GetSession(ctx context.Context, id uuid.UUID) (*DiagnosticSession, error)
	// ListSessions 分页列表（status 空 = 全部；page/pageSize 已由 handler 夹紧）。
	ListSessions(ctx context.Context, status string, page, pageSize int) ([]DiagnosticSession, int64, error)
	// StopSession 人工提前停止（ACTIVE→STOPPED 条件迁移 + 该应用 DIAGNOSING Agent 回基线；
	// 并发下已被迁移 → ErrDiagnosticTerminal）。
	StopSession(ctx context.Context, id uuid.UUID, stoppedBy *uuid.UUID, reason string, now time.Time) (*DiagnosticSession, error)
	// ExpireDueSessions 到期扫描（ACTIVE 且 expires_at<=now → EXPIRED + Agent 回基线；
	// 返回迁移行供调用侧下发基线恢复策略）。
	ExpireDueSessions(ctx context.Context, now time.Time) ([]DiagnosticSession, error)
	// ListPendingRestore 终态但尚未下发基线恢复策略的会话（对账重试源，§21.2 1 分钟口径）。
	ListPendingRestore(ctx context.Context, limit int) ([]DiagnosticSession, error)
	// MarkBaselineRestored 标记基线恢复策略已下发（幂等）。
	MarkBaselineRestored(ctx context.Context, id uuid.UUID) error
}

// DiagnosticsStore 诊断会话仓储。
type DiagnosticsStore struct {
	db *pgxpool.Pool
}

// NewDiagnosticsStore 创建诊断会话仓储。
func NewDiagnosticsStore(db *pgxpool.Pool) *DiagnosticsStore { return &DiagnosticsStore{db: db} }

// diagnosticSessionColumns 会话行全列（扫描顺序与 scanDiagnosticSession 一致）。
const diagnosticSessionColumns = `id, scope, capabilities, sampling_rate, duration_minutes, status,
       created_by, created_at, expires_at, stopped_at, stopped_by, stop_reason,
       policy_version, baseline_restored`

// scanDiagnosticSession 扫描会话行（scope/capabilities jsonb → 结构体）。
func scanDiagnosticSession(row agentScanner) (*DiagnosticSession, error) {
	var s DiagnosticSession
	var scopeRaw, capsRaw []byte
	if err := row.Scan(&s.ID, &scopeRaw, &capsRaw, &s.SamplingRate, &s.DurationMinutes, &s.Status,
		&s.CreatedBy, &s.CreatedAt, &s.ExpiresAt, &s.StoppedAt, &s.StoppedBy, &s.StopReason,
		&s.PolicyVersion, &s.BaselineRestored); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(scopeRaw, &s.Scope); err != nil {
		return nil, fmt.Errorf("decode scope: %w", err)
	}
	s.Capabilities = []string{}
	if err := json.Unmarshal(capsRaw, &s.Capabilities); err != nil {
		return nil, fmt.Errorf("decode capabilities: %w", err)
	}
	return &s, nil
}

// MatchOnlineAgents 匹配 scope 内在线 Agent（在线 = 非 REVOKED 且最近心跳/注册时间
// 未超 offlineAfter，与列表展示态 OFFLINE 推导同口径；instance_ids 空 = 不限制实例）。
func (s *DiagnosticsStore) MatchOnlineAgents(ctx context.Context, scope DiagnosticScope, offlineAfter time.Duration, now time.Time) ([]uuid.UUID, error) {
	rows, err := s.db.Query(ctx, `
SELECT a.id
FROM apm_agents a JOIN apm_services s ON s.id = a.service_id
WHERE a.status <> 'REVOKED'
  AND COALESCE(a.last_heartbeat_at, a.registered_at) > $1
  AND s.application_id = $2
  AND ($3::text = '' OR s.service_name = $3)
  AND ($4::text = '' OR s.environment = $4)
  AND (COALESCE(cardinality($5::text[]), 0) = 0 OR a.instance_id = ANY($5))
ORDER BY a.registered_at`,
		now.UTC().Add(-offlineAfter), scope.ApplicationID, scope.Service, scope.Environment, scope.InstanceIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// KillSwitchEnabled 读取 kill switch（缺失/值非法按 false 放行——种子由迁移保证）。
func (s *DiagnosticsStore) KillSwitchEnabled(ctx context.Context) (bool, error) {
	var raw []byte
	err := s.db.QueryRow(ctx,
		`SELECT setting_value FROM system_settings WHERE setting_group = $1 AND setting_key = $2`,
		killSwitchGroup, killSwitchKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var enabled bool
	if err := json.Unmarshal(raw, &enabled); err != nil {
		return false, nil
	}
	return enabled, nil
}

// setKillSwitchTx 事务内写 kill switch（upsert；ON CONFLICT 只动值/操作人/版本，
// value_type 保持迁移种子的 boolean）。
func setKillSwitchTx(ctx context.Context, tx pgx.Tx, enabled bool, operatorID *uuid.UUID) error {
	value := "false"
	if enabled {
		value = "true"
	}
	_, err := tx.Exec(ctx, `
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description, updated_by)
VALUES ($1, $2, $3::jsonb, 'boolean', 'APM深度诊断全局kill switch：开启后全部活跃会话置KILLED、下发基线恢复策略并拒绝新建（高风险）', $4)
ON CONFLICT (setting_group, setting_key) DO UPDATE
SET setting_value = EXCLUDED.setting_value, updated_by = EXCLUDED.updated_by,
    updated_at = now(), version = system_settings.version + 1`,
		killSwitchGroup, killSwitchKey, value, operatorID)
	return err
}

// killSwitchEnabledTx 事务内带行锁读 kill switch（FOR UPDATE 与 setKillSwitchTx 串行化：
// kill 提交前阻塞的新建检查在 kill 提交后重读，必然看到开启态——防并发新建漏杀）。
func killSwitchEnabledTx(ctx context.Context, tx pgx.Tx) (bool, error) {
	var raw []byte
	err := tx.QueryRow(ctx,
		`SELECT setting_value FROM system_settings WHERE setting_group = $1 AND setting_key = $2 FOR UPDATE`,
		killSwitchGroup, killSwitchKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var enabled bool
	if err := json.Unmarshal(raw, &enabled); err != nil {
		return false, nil
	}
	return enabled, nil
}

// resetDiagnosingAgentsSQL 状态迁移 CTE 的 Agent 回基线段（DIAGNOSING→CONNECTED_BASELINE，
// §8.3 合法迁移；按被迁移会话的应用归属圈定——同一应用同一时刻仅一个 ACTIVE 会话
// 由部分唯一索引保证，故应用级回基线语义无歧义）。
const resetDiagnosingAgentsSQL = `
UPDATE apm_agents a SET status = 'CONNECTED_BASELINE'
FROM apm_services s
WHERE a.service_id = s.id AND a.status = 'DIAGNOSING'
  AND s.application_id IN (SELECT (scope->>'application_id')::uuid FROM tr)`

// SetKillSwitch 写 kill switch；开启时同事务终止全部 ACTIVE 会话（KILLED 终态 +
// 关联应用 DIAGNOSING Agent 回基线）并返回被终止会话。
func (s *DiagnosticsStore) SetKillSwitch(ctx context.Context, enabled bool, operatorID *uuid.UUID, now time.Time) ([]DiagnosticSession, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err := setKillSwitchTx(ctx, tx, enabled, operatorID); err != nil {
		return nil, err
	}
	if !enabled {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, nil
	}
	rows, err := tx.Query(ctx, `
WITH tr AS (
  UPDATE apm_diagnostic_sessions
  SET status = $1, stopped_at = $2, stopped_by = $3, stop_reason = $4
  WHERE status = 'ACTIVE'
  RETURNING `+diagnosticSessionColumns+`
), reset AS (`+resetDiagnosingAgentsSQL+`)
SELECT * FROM tr ORDER BY created_at`,
		DiagnosticStatusKilled, now.UTC(), operatorID, diagnosticStopReasonKillSwitch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	killed := []DiagnosticSession{}
	for rows.Next() {
		sess, err := scanDiagnosticSession(rows)
		if err != nil {
			return nil, err
		}
		killed = append(killed, *sess)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return killed, nil
}

// CreateSessionWithPolicy 单事务：kill switch 行锁复检 → 作用域咨询锁取策略版本
// max+1（复核 expectedVersion）→ 诊断叠加策略落库（信封 expires_at = 会话硬截止）
// → 会话落库（policy_version 回填）→ 匹配 Agent 置 DIAGNOSING。
func (s *DiagnosticsStore) CreateSessionWithPolicy(ctx context.Context, sess *DiagnosticSession,
	policy map[string]interface{}, signature, keyID string, issuedAt time.Time,
	expectedVersion int64, matchedAgentIDs []uuid.UUID) error {
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("encode policy: %w", err)
	}
	scopeJSON, err := json.Marshal(sess.Scope)
	if err != nil {
		return fmt.Errorf("encode scope: %w", err)
	}
	capsJSON, err := json.Marshal(sess.Capabilities)
	if err != nil {
		return fmt.Errorf("encode capabilities: %w", err)
	}
	policyScope := diagnosticPolicyScope(sess)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	killOn, err := killSwitchEnabledTx(ctx, tx)
	if err != nil {
		return err
	}
	if killOn {
		return ErrDiagnosticKillSwitch
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, policyScope); err != nil {
		return err
	}
	var maxVersion int64
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM apm_agent_policies WHERE scope = $1`, policyScope).Scan(&maxVersion); err != nil {
		return err
	}
	if maxVersion != expectedVersion {
		return ErrPolicyVersionConflict
	}
	version := maxVersion + 1
	if _, err := tx.Exec(ctx, `
INSERT INTO apm_agent_policies (scope, version, policy, signature, key_id, issued_at, expires_at, created_by)
VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8)`,
		policyScope, version, policyJSON, signature, keyID, issuedAt.UTC(), sess.ExpiresAt.UTC(), sess.CreatedBy); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO apm_diagnostic_sessions
  (id, scope, capabilities, sampling_rate, duration_minutes, status,
   created_by, created_at, expires_at, policy_version)
VALUES ($1, $2::jsonb, $3::jsonb, $4, $5, 'ACTIVE', $6, $7, $8, $9)`,
		sess.ID, scopeJSON, capsJSON, sess.SamplingRate, sess.DurationMinutes,
		sess.CreatedBy, sess.CreatedAt.UTC(), sess.ExpiresAt.UTC(), version); err != nil {
		if isUniqueViolation(err) {
			return ErrDiagnosticScopeBusy
		}
		return err
	}
	if len(matchedAgentIDs) > 0 {
		if _, err := tx.Exec(ctx, `
UPDATE apm_agents SET status = $2 WHERE id = ANY($1) AND status = 'CONNECTED_BASELINE'`,
			matchedAgentIDs, AgentStatusDiagnosing); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	sess.PolicyVersion = version
	return nil
}

// GetSession 按 ID 取会话。
func (s *DiagnosticsStore) GetSession(ctx context.Context, id uuid.UUID) (*DiagnosticSession, error) {
	sess, err := scanDiagnosticSession(s.db.QueryRow(ctx,
		`SELECT `+diagnosticSessionColumns+` FROM apm_diagnostic_sessions WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDiagnosticNotFound
	}
	return sess, err
}

// ListSessions 分页列表（创建时间倒序；status 空 = 全部）。
func (s *DiagnosticsStore) ListSessions(ctx context.Context, status string, page, pageSize int) ([]DiagnosticSession, int64, error) {
	rows, err := s.db.Query(ctx, `
SELECT `+diagnosticSessionColumns+`, count(*) OVER () AS total
FROM apm_diagnostic_sessions
WHERE ($1::text = '' OR status = $1)
ORDER BY created_at DESC
LIMIT $2 OFFSET $3`, status, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	list := []DiagnosticSession{}
	var total int64
	for rows.Next() {
		var s DiagnosticSession
		var scopeRaw, capsRaw []byte
		if err := rows.Scan(&s.ID, &scopeRaw, &capsRaw, &s.SamplingRate, &s.DurationMinutes, &s.Status,
			&s.CreatedBy, &s.CreatedAt, &s.ExpiresAt, &s.StoppedAt, &s.StoppedBy, &s.StopReason,
			&s.PolicyVersion, &s.BaselineRestored, &total); err != nil {
			return nil, 0, err
		}
		if err := json.Unmarshal(scopeRaw, &s.Scope); err != nil {
			return nil, 0, fmt.Errorf("decode scope: %w", err)
		}
		s.Capabilities = []string{}
		if err := json.Unmarshal(capsRaw, &s.Capabilities); err != nil {
			return nil, 0, fmt.Errorf("decode capabilities: %w", err)
		}
		list = append(list, s)
	}
	return list, total, rows.Err()
}

// transitionSession 终态迁移共用实现（to 须为状态机合法终态；条件 UPDATE 仅命中
// ACTIVE，并发/重复迁移返回 ErrDiagnosticTerminal）。
func (s *DiagnosticsStore) transitionSession(ctx context.Context, id uuid.UUID, to string,
	stoppedBy *uuid.UUID, reason string, now time.Time) (*DiagnosticSession, error) {
	if !CanTransitionDiagnosticSession(DiagnosticStatusActive, to) {
		return nil, fmt.Errorf("apm: 非法诊断会话终态 %q", to)
	}
	row := s.db.QueryRow(ctx, `
WITH tr AS (
  UPDATE apm_diagnostic_sessions
  SET status = $2, stopped_at = $3, stopped_by = $4, stop_reason = $5
  WHERE id = $1 AND status = 'ACTIVE'
  RETURNING `+diagnosticSessionColumns+`
), reset AS (`+resetDiagnosingAgentsSQL+`)
SELECT * FROM tr`, id, to, now.UTC(), stoppedBy, reason)
	sess, err := scanDiagnosticSession(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDiagnosticTerminal
	}
	return sess, err
}

// StopSession 人工提前停止（ACTIVE→STOPPED）。
func (s *DiagnosticsStore) StopSession(ctx context.Context, id uuid.UUID, stoppedBy *uuid.UUID, reason string, now time.Time) (*DiagnosticSession, error) {
	return s.transitionSession(ctx, id, DiagnosticStatusStopped, stoppedBy, reason, now)
}

// ExpireDueSessions 到期迁移（ACTIVE 且过硬截止 → EXPIRED；返回迁移行，无迁移为空集）。
func (s *DiagnosticsStore) ExpireDueSessions(ctx context.Context, now time.Time) ([]DiagnosticSession, error) {
	rows, err := s.db.Query(ctx, `
WITH tr AS (
  UPDATE apm_diagnostic_sessions
  SET status = $2, stopped_at = $1, stop_reason = $3
  WHERE status = 'ACTIVE' AND expires_at <= $1
  RETURNING `+diagnosticSessionColumns+`
), reset AS (`+resetDiagnosingAgentsSQL+`)
SELECT * FROM tr ORDER BY created_at`,
		now.UTC(), DiagnosticStatusExpired, diagnosticStopReasonExpired)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	expired := []DiagnosticSession{}
	for rows.Next() {
		sess, err := scanDiagnosticSession(rows)
		if err != nil {
			return nil, err
		}
		expired = append(expired, *sess)
	}
	return expired, rows.Err()
}

// ListPendingRestore 终态但未下发基线恢复策略的会话（停止时间升序，上限夹紧防异常放大）。
func (s *DiagnosticsStore) ListPendingRestore(ctx context.Context, limit int) ([]DiagnosticSession, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(ctx, `
SELECT `+diagnosticSessionColumns+` FROM apm_diagnostic_sessions
WHERE status <> 'ACTIVE' AND baseline_restored = FALSE
ORDER BY stopped_at LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []DiagnosticSession{}
	for rows.Next() {
		sess, err := scanDiagnosticSession(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, *sess)
	}
	return list, rows.Err()
}

// MarkBaselineRestored 标记基线恢复策略已下发（幂等；不存在的 ID 如实报错）。
func (s *DiagnosticsStore) MarkBaselineRestored(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.Exec(ctx,
		`UPDATE apm_diagnostic_sessions SET baseline_restored = TRUE WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrDiagnosticNotFound
	}
	return nil
}
