package gatewayconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jiuzhang-waf/server/internal/applications"
)

// ConfigVersion 是配置版本。
type ConfigVersion struct {
	ID                uuid.UUID  `json:"id"`
	VersionNumber     string     `json:"version_number"`
	ConfigurationJSON string     `json:"configuration_json"`
	ConfigurationHash string     `json:"configuration_hash"`
	BusinessSnapshot  string     `json:"business_snapshot"`
	ChangeSummary     string     `json:"change_summary"`
	PreviousVersionID *uuid.UUID `json:"previous_version_id"`
	PublishTaskID     *uuid.UUID `json:"publish_task_id"`
	PublishResult     string     `json:"publish_result"`
	ValidationResult  string     `json:"validation_result"`
	IsCurrent         bool       `json:"is_current"`
	CreatedBy         *uuid.UUID `json:"created_by"`
	CreatedAt         time.Time  `json:"created_at"`
	PublishedBy       *uuid.UUID `json:"published_by"`
	PublishedAt       *time.Time `json:"published_at"`
	RulePackVersion   string     `json:"rulepack_version,omitempty"`
}

// publishApplicationState 保存 activatePublishedVersion 会覆盖的应用字段，
// 使激活后失去发布租约时可以原子恢复数据库指针与发布状态。
type publishApplicationState struct {
	id                uuid.UUID
	deploymentStatus  string
	lastPublishResult string
	currentVersionID  *uuid.UUID
	lastPublishAt     *time.Time
	updatedAt         time.Time
	version           int
}

type publishActivationState struct {
	currentVersionID *uuid.UUID
	applications     []publishApplicationState
}

func (p *Publisher) snapshotCurrentVersionState(ctx context.Context) (*publishActivationState, error) {
	state := &publishActivationState{}
	var currentID uuid.UUID
	if err := p.db.QueryRow(ctx, `SELECT id FROM gateway_config_versions WHERE is_current = TRUE LIMIT 1`).Scan(&currentID); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("snapshot current gateway version: %w", err)
		}
	} else {
		state.currentVersionID = &currentID
	}
	return state, nil
}

// snapshotActivationState 必须在激活前读取。appIDs 为空时与激活 SQL 使用完全
// 相同的 ACTIVE 且未删除条件，避免恢复集合与实际被激活集合不一致。
func (p *Publisher) snapshotActivationState(ctx context.Context, appIDs []uuid.UUID) (*publishActivationState, error) {
	state, err := p.snapshotCurrentVersionState(ctx)
	if err != nil {
		return nil, err
	}

	query := `
SELECT id, deployment_status, last_publish_result, current_version_id, last_publish_at, updated_at, version
FROM applications WHERE status='ACTIVE' AND deleted_at IS NULL`
	args := []interface{}{}
	if len(appIDs) > 0 {
		query = `
SELECT id, deployment_status, last_publish_result, current_version_id, last_publish_at, updated_at, version
FROM applications WHERE id = ANY($1) AND deleted_at IS NULL`
		args = append(args, appIDs)
	}
	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("snapshot application publish state: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var app publishApplicationState
		if err := rows.Scan(&app.id, &app.deploymentStatus, &app.lastPublishResult,
			&app.currentVersionID, &app.lastPublishAt, &app.updatedAt, &app.version); err != nil {
			return nil, fmt.Errorf("scan application publish state: %w", err)
		}
		state.applications = append(state.applications, app)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read application publish state: %w", err)
	}
	return state, nil
}

// restoreActivationState 在一个事务中恢复版本 current 标记和所有受影响应用的
// current_version_id/发布字段，避免租约丢失后留下 DB 与网关分裂状态。
func (p *Publisher) restoreActivationState(ctx context.Context, state *publishActivationState) error {
	if state == nil {
		return nil
	}
	tx, err := p.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE gateway_config_versions SET is_current = FALSE WHERE is_current = TRUE`); err != nil {
		return err
	}
	if state.currentVersionID != nil {
		res, err := tx.Exec(ctx, `UPDATE gateway_config_versions SET is_current = TRUE WHERE id = $1`, *state.currentVersionID)
		if err != nil {
			return err
		}
		if res.RowsAffected() != 1 {
			return fmt.Errorf("previous gateway config version %s not found during restore", *state.currentVersionID)
		}
	}
	for _, app := range state.applications {
		res, err := tx.Exec(ctx, `
UPDATE applications
SET deployment_status=$1, last_publish_result=$2, current_version_id=$3,
  last_publish_at=$4, updated_at=$5, version=$6
WHERE id=$7`, app.deploymentStatus, app.lastPublishResult, app.currentVersionID,
			app.lastPublishAt, app.updatedAt, app.version, app.id)
		if err != nil {
			return err
		}
		if res.RowsAffected() != 1 {
			return fmt.Errorf("application %s not found during activation restore", app.id)
		}
	}
	return tx.Commit(ctx)
}

// createTask 创建发布任务。
func (p *Publisher) createTask(ctx context.Context, taskType string, requestedBy uuid.UUID, requestID, idempotencyKey string) (*PublishTask, error) {
	task := &PublishTask{
		TaskType:    taskType,
		Status:      TaskPending,
		RequestedBy: &requestedBy,
		RequestID:   requestID,
	}
	err := p.db.QueryRow(ctx, `
INSERT INTO gateway_publish_tasks (task_type, status, requested_by, request_id, idempotency_key)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, requested_at`,
		taskType, TaskPending, requestedBy, requestID, idempotencyKey,
	).Scan(&task.ID, &task.RequestedAt)
	if err != nil {
		return nil, err
	}
	return task, nil
}

// getTaskByIdempotencyKey 按幂等键查询任务。
func (p *Publisher) getTaskByIdempotencyKey(ctx context.Context, key string) (*PublishTask, error) {
	row := p.db.QueryRow(ctx, `
SELECT id, task_type, status, requested_by, requested_at, started_at, finished_at,
  target_version_id, previous_version_id, current_step, progress, result_summary,
  failure_code, failure_message, request_id
FROM gateway_publish_tasks WHERE idempotency_key = $1`, key)
	return scanTask(row)
}

// GetTask 查询发布任务。
func (p *Publisher) GetTask(ctx context.Context, id uuid.UUID) (*PublishTask, error) {
	row := p.db.QueryRow(ctx, `
SELECT id, task_type, status, requested_by, requested_at, started_at, finished_at,
  target_version_id, previous_version_id, current_step, progress, result_summary,
  failure_code, failure_message, request_id
FROM gateway_publish_tasks WHERE id = $1`, id)
	return scanTask(row)
}

// ListTasks 分页查询发布任务。
func (p *Publisher) ListTasks(ctx context.Context, status string, page, pageSize int) ([]PublishTask, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	where := "1=1"
	args := []interface{}{}
	argIdx := 1
	if status != "" {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	var total int64
	if err := p.db.QueryRow(ctx, `SELECT count(*) FROM gateway_publish_tasks WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `
SELECT id, task_type, status, requested_by, requested_at, started_at, finished_at,
  target_version_id, previous_version_id, current_step, progress, result_summary,
  failure_code, failure_message, request_id
FROM gateway_publish_tasks WHERE ` + where + fmt.Sprintf(" ORDER BY requested_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := p.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []PublishTask
	for rows.Next() {
		t, err := scanTaskRows(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *t)
	}
	return out, total, rows.Err()
}

func scanTask(row pgx.Row) (*PublishTask, error) {
	var t PublishTask
	err := row.Scan(&t.ID, &t.TaskType, &t.Status, &t.RequestedBy, &t.RequestedAt, &t.StartedAt,
		&t.FinishedAt, &t.TargetVersionID, &t.PreviousVersionID, &t.CurrentStep, &t.Progress,
		&t.ResultSummary, &t.FailureCode, &t.FailureMessage, &t.RequestID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("task not found")
		}
		return nil, err
	}
	return &t, nil
}

func scanTaskRows(rows pgx.Rows) (*PublishTask, error) {
	var t PublishTask
	err := rows.Scan(&t.ID, &t.TaskType, &t.Status, &t.RequestedBy, &t.RequestedAt, &t.StartedAt,
		&t.FinishedAt, &t.TargetVersionID, &t.PreviousVersionID, &t.CurrentStep, &t.Progress,
		&t.ResultSummary, &t.FailureCode, &t.FailureMessage, &t.RequestID)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// updateTaskStep 更新任务步骤与进度。
func (p *Publisher) updateTaskStep(ctx context.Context, taskID uuid.UUID, status, step string, progress int) {
	_, _ = p.db.Exec(ctx, `
UPDATE gateway_publish_tasks SET status=$1, current_step=$2, progress=$3, started_at=COALESCE(started_at, now())
WHERE id=$4`, status, step, progress, taskID)
}

// finishTask 完成任务（成功或失败）。
func (p *Publisher) finishTask(ctx context.Context, taskID uuid.UUID, status, failureCode, message string, versionID *uuid.UUID) {
	_, _ = p.db.Exec(ctx, `
UPDATE gateway_publish_tasks SET status=$1, failure_code=$2, failure_message=$3, result_summary=$4,
  target_version_id=COALESCE($5, target_version_id), finished_at=now(), progress=100
WHERE id=$6`, status, failureCode, message, message, versionID, taskID)
}

// setTaskTargetVersion 设置任务目标版本。
func (p *Publisher) setTaskTargetVersion(ctx context.Context, taskID, versionID uuid.UUID) error {
	_, err := p.db.Exec(ctx, `UPDATE gateway_publish_tasks SET target_version_id=$1 WHERE id=$2`, versionID, taskID)
	return err
}

// saveVersion 保存配置版本（不可变）。
// 版本号：V<UTC 毫秒时间戳>-<哈希前8>；同秒同配置的快速连续发布会冲突，
// 撞唯一约束时追加序号重试（不静默失败，超出次数如实返回错误）。
// 密钥纪律：版本表不再保存密钥明文，回滚时重注入当前密钥（见 config_secrets.go）——
// configuration_json 存储脱敏形态（guard 段 valkey 密码、identity_salt、扫描/文件签名
// key_hex、TLS 票据键以 "***" 占位）；configuration_hash 仍为实发配置哈希（生效校验口径不变）。
func (p *Publisher) saveVersion(ctx context.Context, gen *Generated, snapshot map[string]interface{}, in PublishInput, taskID uuid.UUID, rulePackVersion string) (*ConfigVersion, error) {
	base := fmt.Sprintf("V%s-%s", time.Now().UTC().Format("20060102.150405.000"), gen.Hash[:8])

	snapshotJSON, _ := json.Marshal(snapshot)
	storedJSON, err := RedactConfigSecrets(gen.JSON)
	if err != nil {
		return nil, fmt.Errorf("redact config version secrets: %w", err)
	}
	// 上一版本（无生效版本属正常：首轮发布；其余查询错误如实上抛，不静默吞掉）
	var prevID *uuid.UUID
	err = p.db.QueryRow(ctx,
		`SELECT id FROM gateway_config_versions WHERE is_current = TRUE LIMIT 1`).Scan(&prevID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("query previous config version: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		versionNum := base
		if attempt > 0 {
			versionNum = fmt.Sprintf("%s-%d", base, attempt+1)
		}
		v := &ConfigVersion{
			VersionNumber:     versionNum,
			ConfigurationJSON: storedJSON,
			ConfigurationHash: gen.Hash,
			BusinessSnapshot:  string(snapshotJSON),
			ChangeSummary:     fmt.Sprintf("发布 %d 个应用", len(snapshot["apps"].([]map[string]interface{}))),
			PublishTaskID:     &taskID,
			CreatedBy:         &in.RequestedBy,
			PreviousVersionID: prevID,
			RulePackVersion:   rulePackVersion,
		}
		err := p.db.QueryRow(ctx, `
INSERT INTO gateway_config_versions (version_number, configuration_json, configuration_hash,
  business_snapshot, change_summary, previous_version_id, publish_task_id, created_by, rulepack_version)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
RETURNING id, created_at`,
			v.VersionNumber, v.ConfigurationJSON, v.ConfigurationHash, v.BusinessSnapshot,
			v.ChangeSummary, v.PreviousVersionID, v.PublishTaskID, v.CreatedBy, v.RulePackVersion,
		).Scan(&v.ID, &v.CreatedAt)
		if err == nil {
			// 写入版本配置文件（与版本表同口径脱敏存储）
			_, _ = WriteVersionConfig(p.dataDir, v.VersionNumber, storedJSON)
			return v, nil
		}
		lastErr = err
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
			return nil, err
		}
	}
	return nil, fmt.Errorf("save config version: version_number conflict after retries: %w", lastErr)
}

// markVersionResult 标记版本发布结果。
func (p *Publisher) markVersionResult(ctx context.Context, versionID uuid.UUID, result string) {
	_, _ = p.db.Exec(ctx,
		`UPDATE gateway_config_versions SET publish_result=$1, published_at=now() WHERE id=$2`, result, versionID)
}

// setCurrentVersion 设置当前生效版本（原子切换）。
func (p *Publisher) setCurrentVersion(ctx context.Context, versionID uuid.UUID) error {
	tx, err := p.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE gateway_config_versions SET is_current = FALSE WHERE is_current = TRUE`); err != nil {
		return err
	}
	res, err := tx.Exec(ctx, `UPDATE gateway_config_versions SET is_current = TRUE WHERE id = $1`, versionID)
	if err != nil {
		return err
	}
	if res.RowsAffected() != 1 {
		return fmt.Errorf("gateway config version %s not found", versionID)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	// 写入生效配置文件
	var gen string
	if err := p.db.QueryRow(ctx, `SELECT configuration_json FROM gateway_config_versions WHERE id=$1`, versionID).Scan(&gen); err == nil {
		_, _ = WriteActiveConfig(p.dataDir, "current", gen)
	}
	return nil
}

// activatePublishedVersion 原子切换当前版本并回填相关应用的部署状态。
func (p *Publisher) activatePublishedVersion(ctx context.Context, versionID uuid.UUID, appIDs []uuid.UUID) error {
	tx, err := p.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `UPDATE gateway_config_versions SET is_current = FALSE WHERE is_current = TRUE`); err != nil {
		return err
	}
	res, err := tx.Exec(ctx, `
UPDATE gateway_config_versions
SET is_current = TRUE, publish_result = 'SUCCESS', published_at = now()
WHERE id = $1`, versionID)
	if err != nil {
		return err
	}
	if res.RowsAffected() != 1 {
		return fmt.Errorf("gateway config version %s not found", versionID)
	}

	if len(appIDs) == 0 {
		if _, err := tx.Exec(ctx, `
UPDATE applications
SET deployment_status=$1, last_publish_result='SUCCESS', current_version_id=$2,
  last_publish_at=now(), updated_at=now(), version=version+1
WHERE status='ACTIVE' AND deleted_at IS NULL`, applications.DeployPublished, versionID); err != nil {
			return err
		}
	} else {
		for _, appID := range appIDs {
			res, err := tx.Exec(ctx, `
UPDATE applications
SET deployment_status=$1, last_publish_result='SUCCESS', current_version_id=$2,
  last_publish_at=now(), updated_at=now(), version=version+1
WHERE id=$3 AND deleted_at IS NULL`, applications.DeployPublished, versionID, appID)
			if err != nil {
				return err
			}
			if res.RowsAffected() != 1 {
				return fmt.Errorf("application %s not found during gateway activation", appID)
			}
		}
	}

	return tx.Commit(ctx)
}

// getVersion 查询配置版本。
func (p *Publisher) getVersion(ctx context.Context, id uuid.UUID) (*ConfigVersion, error) {
	row := p.db.QueryRow(ctx, `
SELECT id, version_number, configuration_json, configuration_hash, business_snapshot, change_summary,
  previous_version_id, publish_task_id, publish_result, validation_result, is_current,
  created_by, created_at, published_by, published_at, COALESCE(rulepack_version, '')
FROM gateway_config_versions WHERE id = $1`, id)
	return scanVersion(row)
}

// GetVersion 查询配置版本（公开）。
func (p *Publisher) GetVersion(ctx context.Context, id uuid.UUID) (*ConfigVersion, error) {
	return p.getVersion(ctx, id)
}

// ListVersions 分页查询配置版本。
func (p *Publisher) ListVersions(ctx context.Context, page, pageSize int) ([]ConfigVersion, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	var total int64
	if err := p.db.QueryRow(ctx, `SELECT count(*) FROM gateway_config_versions`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := p.db.Query(ctx, `
SELECT id, version_number, configuration_json, configuration_hash, business_snapshot, change_summary,
  previous_version_id, publish_task_id, publish_result, validation_result, is_current,
  created_by, created_at, published_by, published_at, COALESCE(rulepack_version, '')
FROM gateway_config_versions ORDER BY created_at DESC LIMIT $1 OFFSET $2`, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []ConfigVersion
	for rows.Next() {
		v, err := scanVersionRows(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *v)
	}
	return out, total, rows.Err()
}

// GetCurrentVersion 查询当前生效版本。
// 无生效版本（从未发布）返回 (nil, nil)；其余扫描/查询错误如实上抛，不吞成 (nil, nil)。
func (p *Publisher) GetCurrentVersion(ctx context.Context) (*ConfigVersion, error) {
	row := p.db.QueryRow(ctx, `
SELECT id, version_number, configuration_json, configuration_hash, business_snapshot, change_summary,
  previous_version_id, publish_task_id, publish_result, validation_result, is_current,
  created_by, created_at, published_by, published_at, COALESCE(rulepack_version, '')
FROM gateway_config_versions WHERE is_current = TRUE LIMIT 1`)
	v, err := scanVersion(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return v, nil
}

func scanVersion(row pgx.Row) (*ConfigVersion, error) {
	var v ConfigVersion
	err := row.Scan(&v.ID, &v.VersionNumber, &v.ConfigurationJSON, &v.ConfigurationHash,
		&v.BusinessSnapshot, &v.ChangeSummary, &v.PreviousVersionID, &v.PublishTaskID,
		&v.PublishResult, &v.ValidationResult, &v.IsCurrent, &v.CreatedBy, &v.CreatedAt,
		&v.PublishedBy, &v.PublishedAt, &v.RulePackVersion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("version not found: %w", err)
		}
		return nil, err
	}
	return &v, nil
}

func scanVersionRows(rows pgx.Rows) (*ConfigVersion, error) {
	var v ConfigVersion
	err := rows.Scan(&v.ID, &v.VersionNumber, &v.ConfigurationJSON, &v.ConfigurationHash,
		&v.BusinessSnapshot, &v.ChangeSummary, &v.PreviousVersionID, &v.PublishTaskID,
		&v.PublishResult, &v.ValidationResult, &v.IsCurrent, &v.CreatedBy, &v.CreatedAt,
		&v.PublishedBy, &v.PublishedAt, &v.RulePackVersion)
	if err != nil {
		return nil, err
	}
	return &v, nil
}
