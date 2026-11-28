package rulepacks

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

// Store 封装 waf_rule_packs / waf_rule_pack_jobs / waf_rule_pack_node_states 持久化读写。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建规则包持久化仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// PolicyOverrideRef 用于规则包预检扫描客户已启用的规则覆盖。
type PolicyOverrideRef struct {
	ID         uuid.UUID
	RuleID     int
	Action     string
	ScopeType  string
	Reason     string
}

// PolicyExceptionRef 用于规则包预检扫描客户已启用的例外策略。
type PolicyExceptionRef struct {
	ID              uuid.UUID
	Name            string
	RuleIDs         []int
	RuleTags        []string
	ResolvedRuleIDs []int
}

// EnsureBuiltinPack 若数据库尚无任何 APPLIED 规则包，幂等插入或激活内置基线记录。
func (s *Store) EnsureBuiltinPack(ctx context.Context, builtinVersion, crsVersion string) (*RulePack, error) {
	if s.db == nil {
		return nil, errors.New("database pool is nil")
	}
	if cur, err := s.GetAppliedPack(ctx); err == nil && cur != nil {
		return cur, nil
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	now := time.Now().UTC()
	manifestJSON, _ := json.Marshal(map[string]interface{}{
		"schema_version":   SchemaVersion,
		"product":          ProductWDSP,
		"package_type":     PackageTypeRulePack,
		"rulepack_version": builtinVersion,
		"crs_version":      crsVersion,
		"is_builtin":       true,
	})
	// 幂等插入内置基线（若并发已插入则查询返回）
	_, err := s.db.Exec(ctx, `
INSERT INTO waf_rule_packs (
  rulepack_version, crs_version, is_builtin, file_name, file_size,
  file_sha256, manifest_sha256, manifest_json, preview_report, status, applied_at
) VALUES ($1, $2, TRUE, $3, 0, '', '', $4, '{}'::jsonb, $5, $6)
ON CONFLICT (rulepack_version) DO NOTHING`,
		builtinVersion, crsVersion, builtinVersion+" (系统内置基线)", manifestJSON, StatusApplied, now)
	if err != nil {
		return nil, fmt.Errorf("seed builtin rule pack: %w", err)
	}
	return s.GetAppliedPack(ctx)
}

// GetAppliedPack 返回当前处于 APPLIED 状态的唯一规则包；无记录返回 ErrNotFound。
func (s *Store) GetAppliedPack(ctx context.Context) (*RulePack, error) {
	row := s.db.QueryRow(ctx, `
SELECT id, rulepack_version, crs_version, min_system_version, coraza_compat, is_builtin,
       file_name, file_size, file_sha256, manifest_sha256, manifest_json, preview_report,
       archive_path, status, reject_reason, uploaded_by, uploaded_at, applied_by, applied_at,
       created_at, updated_at
FROM waf_rule_packs
WHERE status = $1
LIMIT 1`, StatusApplied)
	return scanRulePack(row)
}

// GetPack 按 ID 查询规则包。
func (s *Store) GetPack(ctx context.Context, id uuid.UUID) (*RulePack, error) {
	row := s.db.QueryRow(ctx, `
SELECT id, rulepack_version, crs_version, min_system_version, coraza_compat, is_builtin,
       file_name, file_size, file_sha256, manifest_sha256, manifest_json, preview_report,
       archive_path, status, reject_reason, uploaded_by, uploaded_at, applied_by, applied_at,
       created_at, updated_at
FROM waf_rule_packs
WHERE id = $1`, id)
	return scanRulePack(row)
}

// GetPackByVersion 按版本号查询规则包。
func (s *Store) GetPackByVersion(ctx context.Context, version string) (*RulePack, error) {
	row := s.db.QueryRow(ctx, `
SELECT id, rulepack_version, crs_version, min_system_version, coraza_compat, is_builtin,
       file_name, file_size, file_sha256, manifest_sha256, manifest_json, preview_report,
       archive_path, status, reject_reason, uploaded_by, uploaded_at, applied_by, applied_at,
       created_at, updated_at
FROM waf_rule_packs
WHERE rulepack_version = $1`, version)
	return scanRulePack(row)
}

// ListPacks 分页列出全部规则包档案（按创建时间倒序）。
func (s *Store) ListPacks(ctx context.Context, page, pageSize int) ([]RulePack, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM waf_rule_packs`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `
SELECT id, rulepack_version, crs_version, min_system_version, coraza_compat, is_builtin,
       file_name, file_size, file_sha256, manifest_sha256, manifest_json, preview_report,
       archive_path, status, reject_reason, uploaded_by, uploaded_at, applied_by, applied_at,
       created_at, updated_at
FROM waf_rule_packs
ORDER BY created_at DESC, rulepack_version DESC
LIMIT $1 OFFSET $2`, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var items []RulePack
	for rows.Next() {
		p, err := scanRulePack(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, *p)
	}
	return items, total, rows.Err()
}

// CreatePack 写入新的规则包记录。
func (s *Store) CreatePack(ctx context.Context, p *RulePack) (*RulePack, error) {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	if len(p.ManifestJSON) == 0 {
		p.ManifestJSON = json.RawMessage("{}")
	}
	if len(p.PreviewReport) == 0 {
		p.PreviewReport = json.RawMessage("{}")
	}
	row := s.db.QueryRow(ctx, `
INSERT INTO waf_rule_packs (
  id, rulepack_version, crs_version, min_system_version, coraza_compat, is_builtin,
  file_name, file_size, file_sha256, manifest_sha256, manifest_json, preview_report,
  archive_path, status, reject_reason, uploaded_by
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
RETURNING id, rulepack_version, crs_version, min_system_version, coraza_compat, is_builtin,
          file_name, file_size, file_sha256, manifest_sha256, manifest_json, preview_report,
          archive_path, status, reject_reason, uploaded_by, uploaded_at, applied_by, applied_at,
          created_at, updated_at`,
		p.ID, p.RulePackVersion, p.CRSVersion, p.MinSystemVersion, p.CorazaCompat, p.IsBuiltin,
		p.FileName, p.FileSize, p.FileSHA256, p.ManifestSHA256, p.ManifestJSON, p.PreviewReport,
		p.ArchivePath, p.Status, p.RejectReason, p.UploadedBy,
	)
	return scanRulePack(row)
}

// UpdatePackPreview 刷新已验证规则包的最新预检报告（例如同包幂等重传时）。
func (s *Store) UpdatePackPreview(ctx context.Context, id uuid.UUID, preview json.RawMessage) error {
	_, err := s.db.Exec(ctx, `
UPDATE waf_rule_packs SET preview_report = $1, updated_at = now() WHERE id = $2`, preview, id)
	return err
}

// ActivatePack 在单个数据库事务中将原 APPLIED 规则包置为 previousTargetStatus（SUPERSEDED 或 ROLLED_BACK），
// 并将 targetPackID 切换为唯一 APPLIED 状态。
func (s *Store) ActivatePack(ctx context.Context, targetPackID uuid.UUID, previousTargetStatus string, appliedBy *uuid.UUID) error {
	if previousTargetStatus != StatusSuperseded && previousTargetStatus != StatusRolledBack {
		previousTargetStatus = StatusSuperseded
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
UPDATE waf_rule_packs
SET status = $1, updated_at = now()
WHERE status = $2 AND id <> $3`, previousTargetStatus, StatusApplied, targetPackID); err != nil {
		return err
	}
	res, err := tx.Exec(ctx, `
UPDATE waf_rule_packs
SET status = $1, applied_by = $2, applied_at = now(), updated_at = now()
WHERE id = $3`, StatusApplied, appliedBy, targetPackID)
	if err != nil {
		return err
	}
	if res.RowsAffected() != 1 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

// HasActiveJob 判断当前是否存在未终结的规则包应用/回滚任务。
func (s *Store) HasActiveJob(ctx context.Context) (bool, error) {
	var count int
	err := s.db.QueryRow(ctx, `
SELECT count(*) FROM waf_rule_pack_jobs
WHERE status NOT IN ($1, $2, $3)`, JobSuccess, JobRolledBack, JobFailed).Scan(&count)
	return count > 0, err
}

// CreateJobIfNoActive 原子检查无活跃任务后创建新执行任务。
func (s *Store) CreateJobIfNoActive(ctx context.Context, job *Job) (*Job, error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var active int
	if err := tx.QueryRow(ctx, `
SELECT count(*) FROM waf_rule_pack_jobs
WHERE status NOT IN ($1, $2, $3)`, JobSuccess, JobRolledBack, JobFailed).Scan(&active); err != nil {
		return nil, err
	}
	if active > 0 {
		return nil, ErrActiveJob
	}
	if job.ID == uuid.Nil {
		job.ID = uuid.New()
	}
	if len(job.SyncReport) == 0 {
		job.SyncReport = json.RawMessage("{}")
	}
	now := time.Now().UTC()
	row := tx.QueryRow(ctx, `
INSERT INTO waf_rule_pack_jobs (
  id, job_type, target_pack_id, previous_pack_id, status, current_step, progress,
  allow_degraded_ha, degraded_reason, sync_report, requested_by, request_id, started_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
RETURNING id, job_type, target_pack_id, previous_pack_id, publish_task_id, status,
          current_step, progress, allow_degraded_ha, degraded_reason, sync_report,
          failure_code, failure_message, requested_by, request_id, started_at, finished_at, created_at`,
		job.ID, job.JobType, job.TargetPackID, job.PreviousPackID, job.Status, job.CurrentStep, job.Progress,
		job.AllowDegradedHA, job.DegradedReason, job.SyncReport, job.RequestedBy, job.RequestID, now,
	)
	created, err := scanJob(row)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return created, nil
}

// UpdateJobStep 更新执行任务当前状态与进度。
func (s *Store) UpdateJobStep(ctx context.Context, jobID uuid.UUID, status, step string, progress int) error {
	_, err := s.db.Exec(ctx, `
UPDATE waf_rule_pack_jobs
SET status = $1, current_step = $2, progress = $3
WHERE id = $4`, status, step, progress, jobID)
	return err
}

// SetJobPublishTask 绑定关联的配置发布任务 ID。
func (s *Store) SetJobPublishTask(ctx context.Context, jobID, publishTaskID uuid.UUID) error {
	_, err := s.db.Exec(ctx, `
UPDATE waf_rule_pack_jobs SET publish_task_id = $1 WHERE id = $2`, publishTaskID, jobID)
	return err
}

// FinishJob 将执行任务置为终态并落库同步报告或失败信息。
func (s *Store) FinishJob(ctx context.Context, jobID uuid.UUID, status, step, failureCode, failureMsg string, syncReport json.RawMessage) error {
	if len(syncReport) == 0 {
		syncReport = json.RawMessage("{}")
	}
	_, err := s.db.Exec(ctx, `
UPDATE waf_rule_pack_jobs
SET status = $1, current_step = $2, progress = 100,
    failure_code = $3, failure_message = $4, sync_report = $5, finished_at = now()
WHERE id = $6`, status, step, failureCode, failureMsg, syncReport, jobID)
	return err
}

// GetJob 查询单个执行任务（含目标/前序版本号与 HA 逐节点明细）。
func (s *Store) GetJob(ctx context.Context, id uuid.UUID) (*Job, error) {
	row := s.db.QueryRow(ctx, `
SELECT j.id, j.job_type, j.target_pack_id, j.previous_pack_id, j.publish_task_id, j.status,
       j.current_step, j.progress, j.allow_degraded_ha, j.degraded_reason, j.sync_report,
       j.failure_code, j.failure_message, j.requested_by, j.request_id, j.started_at, j.finished_at, j.created_at,
       COALESCE(tp.rulepack_version, ''), COALESCE(pp.rulepack_version, '')
FROM waf_rule_pack_jobs j
LEFT JOIN waf_rule_packs tp ON tp.id = j.target_pack_id
LEFT JOIN waf_rule_packs pp ON pp.id = j.previous_pack_id
WHERE j.id = $1`, id)
	job, err := scanJobWithVersions(row)
	if err != nil {
		return nil, err
	}
	states, err := s.ListNodeStates(ctx, id)
	if err != nil {
		return nil, err
	}
	job.NodeStates = states
	return job, nil
}

// GetLatestJob 返回最近一条执行任务（无任务返回 (nil, nil)）。
func (s *Store) GetLatestJob(ctx context.Context) (*Job, error) {
	row := s.db.QueryRow(ctx, `
SELECT j.id, j.job_type, j.target_pack_id, j.previous_pack_id, j.publish_task_id, j.status,
       j.current_step, j.progress, j.allow_degraded_ha, j.degraded_reason, j.sync_report,
       j.failure_code, j.failure_message, j.requested_by, j.request_id, j.started_at, j.finished_at, j.created_at,
       COALESCE(tp.rulepack_version, ''), COALESCE(pp.rulepack_version, '')
FROM waf_rule_pack_jobs j
LEFT JOIN waf_rule_packs tp ON tp.id = j.target_pack_id
LEFT JOIN waf_rule_packs pp ON pp.id = j.previous_pack_id
ORDER BY j.created_at DESC
LIMIT 1`)
	job, err := scanJobWithVersions(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	states, err := s.ListNodeStates(ctx, job.ID)
	if err == nil {
		job.NodeStates = states
	}
	return job, nil
}

// UpsertNodeState 写入或更新单个节点执行明细。
func (s *Store) CreateNodeState(ctx context.Context, st *NodeState) (*NodeState, error) {
	if st.ID == uuid.Nil {
		st.ID = uuid.New()
	}
	_, err := s.db.Exec(ctx, `
INSERT INTO waf_rule_pack_node_states (
  id, job_id, node_id, node_name, role, stage_status, load_status, activate_status, error_code, error_message
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		st.ID, st.JobID, st.NodeID, st.NodeName, st.Role, st.StageStatus, st.LoadStatus, st.ActivateStatus, st.ErrorCode, st.ErrorMessage)
	if err != nil {
		return nil, err
	}
	return st, nil
}

// UpdateNodeState 更新节点执行明细。
func (s *Store) UpdateNodeState(ctx context.Context, id uuid.UUID, stage, load, activate, errCode, errMsg string) error {
	_, err := s.db.Exec(ctx, `
UPDATE waf_rule_pack_node_states
SET stage_status = $1, load_status = $2, activate_status = $3,
    error_code = $4, error_message = $5, updated_at = now()
WHERE id = $6`, stage, load, activate, errCode, errMsg, id)
	return err
}

// ListNodeStates 查询指定任务的全部节点执行明细。
func (s *Store) ListNodeStates(ctx context.Context, jobID uuid.UUID) ([]NodeState, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, job_id, node_id, node_name, role, stage_status, load_status, activate_status,
       error_code, error_message, updated_at
FROM waf_rule_pack_node_states
WHERE job_id = $1
ORDER BY role ASC, node_name ASC`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NodeState
	for rows.Next() {
		var st NodeState
		if err := rows.Scan(&st.ID, &st.JobID, &st.NodeID, &st.NodeName, &st.Role,
			&st.StageStatus, &st.LoadStatus, &st.ActivateStatus, &st.ErrorCode, &st.ErrorMessage, &st.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// ProtectedConfigRulePackVersions 返回当前与最近上一版 gateway_config_versions 引用的规则包版本，
// 供快照 GC 保护使用（确保最近配置回滚不会因规则快照被清理而失败）。
func (s *Store) ProtectedConfigRulePackVersions(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	if s.db == nil {
		return out, nil
	}
	rows, err := s.db.Query(ctx, `
SELECT DISTINCT rulepack_version
FROM (
  SELECT rulepack_version FROM gateway_config_versions WHERE is_current = TRUE
  UNION ALL
  SELECT rulepack_version FROM gateway_config_versions WHERE publish_result = 'SUCCESS' ORDER BY created_at DESC LIMIT 2
) t
WHERE rulepack_version <> ''`)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return out, err
		}
		if v != "" {
			out[v] = true
		}
	}
	return out, rows.Err()
}

// QueryPolicyImpactTargets 查询当前已启用的规则覆盖与例外策略，用于预检生成客户影响提示（只读）。
func (s *Store) QueryPolicyImpactTargets(ctx context.Context) ([]PolicyOverrideRef, []PolicyExceptionRef, error) {
	if s.db == nil {
		return nil, nil, nil
	}
	var overrides []PolicyOverrideRef
	oRows, err := s.db.Query(ctx, `
SELECT id, rule_id, action, scope_type, COALESCE(reason, '')
FROM rule_overrides
WHERE enabled = TRUE
ORDER BY rule_id ASC`)
	if err != nil {
		return nil, nil, fmt.Errorf("query active rule overrides: %w", err)
	}
	for oRows.Next() {
		var o PolicyOverrideRef
		if err := oRows.Scan(&o.ID, &o.RuleID, &o.Action, &o.ScopeType, &o.Reason); err != nil {
			oRows.Close()
			return nil, nil, err
		}
		overrides = append(overrides, o)
	}
	oRows.Close()

	var excs []PolicyExceptionRef
	eRows, err := s.db.Query(ctx, `
SELECT id, name, COALESCE(rule_ids, '[]'::jsonb), COALESCE(rule_tags, '[]'::jsonb), COALESCE(resolved_rule_ids, '[]'::jsonb)
FROM exceptions
WHERE status = 'ENABLED' AND deleted_at IS NULL
ORDER BY name ASC`)
	if err != nil {
		return overrides, nil, fmt.Errorf("query active exceptions: %w", err)
	}
	defer eRows.Close()
	for eRows.Next() {
		var e PolicyExceptionRef
		var ridsRaw, tagsRaw, resolvedRaw []byte
		if err := eRows.Scan(&e.ID, &e.Name, &ridsRaw, &tagsRaw, &resolvedRaw); err != nil {
			return overrides, nil, err
		}
		_ = json.Unmarshal(ridsRaw, &e.RuleIDs)
		_ = json.Unmarshal(tagsRaw, &e.RuleTags)
		_ = json.Unmarshal(resolvedRaw, &e.ResolvedRuleIDs)
		excs = append(excs, e)
	}
	return overrides, excs, eRows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRulePack(r rowScanner) (*RulePack, error) {
	var p RulePack
	err := r.Scan(
		&p.ID, &p.RulePackVersion, &p.CRSVersion, &p.MinSystemVersion, &p.CorazaCompat, &p.IsBuiltin,
		&p.FileName, &p.FileSize, &p.FileSHA256, &p.ManifestSHA256, &p.ManifestJSON, &p.PreviewReport,
		&p.ArchivePath, &p.Status, &p.RejectReason, &p.UploadedBy, &p.UploadedAt, &p.AppliedBy, &p.AppliedAt,
		&p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

func scanJob(r rowScanner) (*Job, error) {
	var j Job
	err := r.Scan(
		&j.ID, &j.JobType, &j.TargetPackID, &j.PreviousPackID, &j.PublishTaskID, &j.Status,
		&j.CurrentStep, &j.Progress, &j.AllowDegradedHA, &j.DegradedReason, &j.SyncReport,
		&j.FailureCode, &j.FailureMessage, &j.RequestedBy, &j.RequestID, &j.StartedAt, &j.FinishedAt, &j.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &j, nil
}

func scanJobWithVersions(r rowScanner) (*Job, error) {
	var j Job
	err := r.Scan(
		&j.ID, &j.JobType, &j.TargetPackID, &j.PreviousPackID, &j.PublishTaskID, &j.Status,
		&j.CurrentStep, &j.Progress, &j.AllowDegradedHA, &j.DegradedReason, &j.SyncReport,
		&j.FailureCode, &j.FailureMessage, &j.RequestedBy, &j.RequestID, &j.StartedAt, &j.FinishedAt, &j.CreatedAt,
		&j.TargetVersion, &j.PreviousVersion,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &j, nil
}
