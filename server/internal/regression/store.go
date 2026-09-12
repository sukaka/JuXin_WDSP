// store.go 安全回归证据登记仓储（迁移 000134）。纪律：
//   - 导入事务化：run + cases + 对象引用单事务，失败整体回滚，不残留可用的半份报告；
//   - 幂等：同 run_id 同 manifest 哈希返回既有登记；同 run_id 异内容 ErrConflict（409 审计）；
//   - 不可变：runs/cases/gate_decisions 只插入不更新（除导入时把对象置 CONSUMED）；
//   - 原始大文件不进数据库行（对象内容在受控本地存储，行内仅存引用与哈希）。
package regression

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

// Store 安全回归仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// ---------- 受控对象元数据 ----------

// InsertObject 登记对象元数据（EvidenceStore.Register 落盘后调用）。
func (s *Store) InsertObject(ctx context.Context, obj EvidenceObject) error {
	_, err := s.db.Exec(ctx, `INSERT INTO security_regression_objects
		(id, kind, sha256, size_bytes, storage_path, state, uploaded_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		obj.ID, obj.Kind, obj.SHA256, obj.SizeBytes, obj.StoragePath, obj.State, obj.UploadedBy)
	return err
}

// GetObject 读取对象元数据；不存在返回 ErrNotFound（调用方不得据此外泄差异）。
func (s *Store) GetObject(ctx context.Context, id uuid.UUID) (*EvidenceObject, error) {
	var obj EvidenceObject
	var createdAt time.Time
	err := s.db.QueryRow(ctx, `SELECT id, kind, sha256, size_bytes, storage_path, state, uploaded_by, created_at
		FROM security_regression_objects WHERE id = $1`, id).
		Scan(&obj.ID, &obj.Kind, &obj.SHA256, &obj.SizeBytes, &obj.StoragePath, &obj.State, &obj.UploadedBy, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	obj.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	return &obj, nil
}

// ---------- 运行摘要与用例 ----------

// Run 回归运行摘要（不可变）。
type Run struct {
	ID                  uuid.UUID       `json:"id"`
	RunID               string          `json:"run_id"`
	ManifestSHA256      string          `json:"manifest_sha256"`
	Level               string          `json:"level"`
	DeclaredStatus      string          `json:"declared_status"`
	VerificationStatus  string          `json:"verification_status"`
	VerificationReasons json.RawMessage `json:"verification_reasons"`
	SignatureAlgorithm  string          `json:"signature_algorithm"`
	SignatureKeyID      string          `json:"signature_key_id"`
	ConfigFingerprint   string          `json:"config_fingerprint"`
	BuildDigest         string          `json:"build_digest"`
	Compiler            string          `json:"compiler"`
	CorpusID            string          `json:"corpus_id"`
	CorpusVersion       int             `json:"corpus_version"`
	CorpusSHA256        string          `json:"corpus_sha256"`
	PlanSHA256          string          `json:"plan_sha256"`
	Counts              ManifestCounts  `json:"counts"`
	RunStartedAt        *time.Time      `json:"run_started_at,omitempty"`
	RunFinishedAt       *time.Time      `json:"run_finished_at,omitempty"`
	PolicyVersion       int             `json:"policy_version"`
	ImportedBy          string          `json:"imported_by"`
	CreatedAt           time.Time       `json:"created_at"`
}

// CaseEntry 用例索引行。
type CaseEntry struct {
	ID          uuid.UUID       `json:"id"`
	CaseID      string          `json:"case_id"`
	CaseVersion int             `json:"case_version"`
	Family      string          `json:"family"`
	Truth       string          `json:"truth"`
	Criticality string          `json:"criticality"`
	Status      string          `json:"status"`
	DiffSummary json.RawMessage `json:"diff_summary,omitempty"`
}

// runColumns 查询列（与 scanRun 顺序一致）。
const runColumns = `id, run_id, manifest_sha256, level, declared_status, verification_status,
	verification_reasons, signature_algorithm, signature_key_id, config_fingerprint,
	build_digest, compiler, corpus_id, corpus_version, corpus_sha256, plan_sha256,
	planned_count, executed_count, skipped_count, blocked_count, not_run_count,
	passed_count, failed_count, mandatory_total, mandatory_failed,
	run_started_at, run_finished_at, policy_version, imported_by, created_at`

func scanRun(row pgx.Row) (*Run, error) {
	var r Run
	err := row.Scan(&r.ID, &r.RunID, &r.ManifestSHA256, &r.Level, &r.DeclaredStatus, &r.VerificationStatus,
		&r.VerificationReasons, &r.SignatureAlgorithm, &r.SignatureKeyID, &r.ConfigFingerprint,
		&r.BuildDigest, &r.Compiler, &r.CorpusID, &r.CorpusVersion, &r.CorpusSHA256, &r.PlanSHA256,
		&r.Counts.Planned, &r.Counts.Executed, &r.Counts.Skipped, &r.Counts.Blocked, &r.Counts.NotRun,
		&r.Counts.Passed, &r.Counts.Failed, &r.Counts.MandatoryTotal, &r.Counts.MandatoryFailed,
		&r.RunStartedAt, &r.RunFinishedAt, &r.PolicyVersion, &r.ImportedBy, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// GetRun 按内部 ID 读取运行。
func (s *Store) GetRun(ctx context.Context, id uuid.UUID) (*Run, error) {
	return scanRun(s.db.QueryRow(ctx, `SELECT `+runColumns+` FROM security_regression_runs WHERE id = $1`, id))
}

// GetRunByRunID 按外部 run_id 读取（幂等判重用）。
func (s *Store) GetRunByRunID(ctx context.Context, runID string) (*Run, error) {
	return scanRun(s.db.QueryRow(ctx, `SELECT `+runColumns+` FROM security_regression_runs WHERE run_id = $1`, runID))
}

// ListFilter 运行列表过滤（按候选指纹、时间、级别、状态分页）。
type ListFilter struct {
	Fingerprint string
	Level       string
	Status      string // verification_status
	Since       *time.Time
	Until       *time.Time
	Page        int
	PageSize    int
}

// ListRuns 分页查询（默认 20、最多 100，由 handler 层钳制）。
func (s *Store) ListRuns(ctx context.Context, f ListFilter) ([]Run, int64, error) {
	where := "WHERE 1=1"
	args := []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		where += fmt.Sprintf(" AND "+cond, len(args))
	}
	if f.Fingerprint != "" {
		add("config_fingerprint = $%d", f.Fingerprint)
	}
	if f.Level != "" {
		add("level = $%d", f.Level)
	}
	if f.Status != "" {
		add("verification_status = $%d", f.Status)
	}
	if f.Since != nil {
		add("created_at >= $%d", *f.Since)
	}
	if f.Until != nil {
		add("created_at <= $%d", *f.Until)
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM security_regression_runs `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `SELECT `+runColumns+` FROM security_regression_runs `+where+
		fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Run{}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *r)
	}
	return out, total, rows.Err()
}

// ListCases 分页返回用例索引（禁止一次返回全部原始正文——行内本就不含正文，
// 分页上限由 handler 钳制）。
func (s *Store) ListCases(ctx context.Context, runRef uuid.UUID, status string, page, pageSize int) ([]CaseEntry, int64, error) {
	where := "WHERE run_ref = $1"
	args := []any{runRef}
	if status != "" {
		args = append(args, status)
		where += fmt.Sprintf(" AND status = $%d", len(args))
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM security_regression_cases `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `SELECT id, case_id, case_version, family, truth, criticality, status, diff_summary
		FROM security_regression_cases `+where+
		fmt.Sprintf(` ORDER BY case_id LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []CaseEntry{}
	for rows.Next() {
		var c CaseEntry
		if err := rows.Scan(&c.ID, &c.CaseID, &c.CaseVersion, &c.Family, &c.Truth, &c.Criticality, &c.Status, &c.DiffSummary); err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// ImportObjectRef 运行 ↔ 对象引用。
type ImportObjectRef struct {
	ObjectID uuid.UUID
	Role     string
	SHA256   string
}

// ImportRun 单事务登记运行（run + cases + 对象引用 + 对象置 CONSUMED）。
// 幂等：同 run_id 同 manifest 哈希返回既有运行（idempotent=true）；
// 同 run_id 异内容返回 ErrConflict。任何校验应在调用方完成后进入本函数——
// 本函数只保证原子性，不重复业务校验。
func (s *Store) ImportRun(ctx context.Context, run *Run, cases []CaseEntry, refs []ImportObjectRef) (stored *Run, idempotent bool, err error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 先锁读既有 run_id（存在则判定幂等/冲突，不插入）
	var existID uuid.UUID
	var existHash string
	err = tx.QueryRow(ctx, `SELECT id, manifest_sha256 FROM security_regression_runs WHERE run_id = $1 FOR UPDATE`, run.RunID).
		Scan(&existID, &existHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}
	if err == nil {
		if existHash == run.ManifestSHA256 {
			if err := tx.Commit(ctx); err != nil {
				return nil, false, err
			}
			existing, gerr := s.GetRun(ctx, existID)
			return existing, gerr == nil, gerr
		}
		return nil, false, fmt.Errorf("%w: run_id %s already registered with different manifest", ErrConflict, run.RunID)
	}

	var id uuid.UUID
	var createdAt time.Time
	err = tx.QueryRow(ctx, `INSERT INTO security_regression_runs
		(run_id, manifest_sha256, level, declared_status, verification_status, verification_reasons,
		 signature_algorithm, signature_key_id, config_fingerprint, build_digest, compiler,
		 corpus_id, corpus_version, corpus_sha256, plan_sha256,
		 planned_count, executed_count, skipped_count, blocked_count, not_run_count,
		 passed_count, failed_count, mandatory_total, mandatory_failed,
		 run_started_at, run_finished_at, policy_version, imported_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)
		RETURNING id, created_at`,
		run.RunID, run.ManifestSHA256, run.Level, run.DeclaredStatus, run.VerificationStatus, run.VerificationReasons,
		run.SignatureAlgorithm, run.SignatureKeyID, run.ConfigFingerprint, run.BuildDigest, run.Compiler,
		run.CorpusID, run.CorpusVersion, run.CorpusSHA256, run.PlanSHA256,
		run.Counts.Planned, run.Counts.Executed, run.Counts.Skipped, run.Counts.Blocked, run.Counts.NotRun,
		run.Counts.Passed, run.Counts.Failed, run.Counts.MandatoryTotal, run.Counts.MandatoryFailed,
		run.RunStartedAt, run.RunFinishedAt, run.PolicyVersion, run.ImportedBy).
		Scan(&id, &createdAt)
	if err != nil {
		return nil, false, err
	}
	for _, c := range cases {
		diff := c.DiffSummary
		if len(diff) == 0 {
			diff = json.RawMessage(`{}`)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO security_regression_cases
			(run_ref, case_id, case_version, family, truth, criticality, status, diff_summary)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			id, c.CaseID, c.CaseVersion, c.Family, c.Truth, c.Criticality, c.Status, diff); err != nil {
			return nil, false, err
		}
	}
	for _, ref := range refs {
		if _, err := tx.Exec(ctx, `INSERT INTO security_regression_run_objects (run_ref, object_ref, role, sha256)
			VALUES ($1,$2,$3,$4)`, id, ref.ObjectID, ref.Role, ref.SHA256); err != nil {
			return nil, false, err
		}
		// 对象置 CONSUMED（只能消费 REGISTERED 状态对象；失败整体回滚）
		ct, err := tx.Exec(ctx, `UPDATE security_regression_objects SET state = $2
			WHERE id = $1 AND state = $3`, ref.ObjectID, ObjectConsumed, ObjectRegistered)
		if err != nil {
			return nil, false, err
		}
		if ct.RowsAffected() != 1 {
			return nil, false, fmt.Errorf("%w: object %s not in REGISTERED state", ErrConflict, ref.ObjectID)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	stored, err = s.GetRun(ctx, id)
	return stored, false, err
}

// ---------- 门禁策略 ----------

// Policy 发布门禁策略（单行；version 乐观锁）。
type Policy struct {
	Mode                  string    `json:"mode"`
	RequiredLevel         string    `json:"required_level"`
	RequiredCorpusID      string    `json:"required_corpus_id"`
	EvidenceMaxAgeSeconds int64     `json:"evidence_max_age_seconds"`
	Version               int       `json:"version"`
	UpdatedBy             string    `json:"updated_by"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// GetPolicy 读取门禁策略（无行时返回默认 OFF；行缺失属首次启动自举，不算依赖不可用）。
func (s *Store) GetPolicy(ctx context.Context) (*Policy, error) {
	var p Policy
	err := s.db.QueryRow(ctx, `SELECT mode, required_level, required_corpus_id,
		evidence_max_age_seconds, version, updated_by, updated_at
		FROM security_regression_policy WHERE id = 1`).
		Scan(&p.Mode, &p.RequiredLevel, &p.RequiredCorpusID, &p.EvidenceMaxAgeSeconds, &p.Version, &p.UpdatedBy, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return &Policy{Mode: ModeOff, RequiredLevel: LevelFull, EvidenceMaxAgeSeconds: DefaultEvidenceMaxAge, Version: 0}, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// PutPolicy 乐观锁更新（expected_version 不匹配返回 ErrConflict；并发修改 409）。
func (s *Store) PutPolicy(ctx context.Context, p *Policy, expectedVersion int, operator string) error {
	ct, err := s.db.Exec(ctx, `UPDATE security_regression_policy
		SET mode=$1, required_level=$2, required_corpus_id=$3, evidence_max_age_seconds=$4,
		    version=version+1, updated_by=$5, updated_at=now()
		WHERE id = 1 AND version = $6`,
		p.Mode, p.RequiredLevel, p.RequiredCorpusID, p.EvidenceMaxAgeSeconds, operator, expectedVersion)
	if err != nil {
		return err
	}
	if ct.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

// ---------- 门禁判定留痕与证据查找 ----------

// GateDecision 门禁判定记录（追加式不可变）。
type GateDecision struct {
	ID             uuid.UUID       `json:"id"`
	PublishTaskID  *uuid.UUID      `json:"publish_task_id,omitempty"`
	VersionID      *uuid.UUID      `json:"version_id,omitempty"`
	Fingerprint    string          `json:"fingerprint"`
	Mode           string          `json:"mode"`
	Decision       string          `json:"decision"`
	RestoreChannel bool            `json:"restore_channel"`
	Reasons        json.RawMessage `json:"reasons"`
	RunRef         *uuid.UUID      `json:"run_ref,omitempty"`
	PolicyVersion  int             `json:"policy_version"`
	CreatedAt      time.Time       `json:"created_at"`
}

// InsertGateDecision 记录一次门禁判定。
func (s *Store) InsertGateDecision(ctx context.Context, d GateDecision) error {
	_, err := s.db.Exec(ctx, `INSERT INTO security_regression_gate_decisions
		(publish_task_id, version_id, fingerprint, mode, decision, restore_channel, reasons, run_ref, policy_version)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		d.PublishTaskID, d.VersionID, d.Fingerprint, d.Mode, d.Decision, d.RestoreChannel, d.Reasons, d.RunRef, d.PolicyVersion)
	return err
}

// LatestVerifiedRunForFingerprint 查找绑定指定候选指纹、服务端核验 PASSED 的
// 最新登记运行（门禁证据候选；级别/有效期/撤销判定在 gate 层完成）。
func (s *Store) LatestVerifiedRunForFingerprint(ctx context.Context, fingerprint string) (*Run, error) {
	return scanRun(s.db.QueryRow(ctx, `SELECT `+runColumns+` FROM security_regression_runs
		WHERE config_fingerprint = $1 AND verification_status = $2
		ORDER BY created_at DESC LIMIT 1`, fingerprint, VerifyPassed))
}

// RunObjects 运行引用的对象清单（证据完整性核对：清理过期原始证据后报告
// 标记证据不完整，不能继续支撑新发布）。
func (s *Store) RunObjects(ctx context.Context, runRef uuid.UUID) ([]ImportObjectRef, error) {
	rows, err := s.db.Query(ctx, `SELECT object_ref, role, sha256 FROM security_regression_run_objects WHERE run_ref = $1`, runRef)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ImportObjectRef{}
	for rows.Next() {
		var r ImportObjectRef
		if err := rows.Scan(&r.ObjectID, &r.Role, &r.SHA256); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
