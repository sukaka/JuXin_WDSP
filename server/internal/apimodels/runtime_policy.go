// runtime_policy.go 端点级运行时策略版本（api_runtime_policies，迁移 000037）：
// 类型、仓储方法与生命周期状态机联动（P0-03/P0-21 补全）。
//
// 状态机语义（与迁移注释一致）：
//
//	DRAFT       模型 Confirm(→FORMAL) 后由编译器自动创建，尚未纳入发布；
//	VALIDATED   模型 Activate 后标记「待发布」（等待下次整站发布生效）；
//	PUBLISHED   预留中间态（本波发布成功直接落 ACTIVE，保留供后续多阶段生效校验扩展）；
//	ACTIVE      整站发布成功且生效校验通过，网关当前实际生效版本；
//	ROLLED_BACK 曾生效后退出（被新版本取代或人工回滚退出），作为「已知良好版本」供回滚溯源；
//	FAILED      发布失败，error 记录发布侧失败原因。
package apimodels

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 运行时策略状态机取值。
const (
	PolicyStatusDraft      = "DRAFT"
	PolicyStatusValidated  = "VALIDATED"
	PolicyStatusPublished  = "PUBLISHED"
	PolicyStatusActive     = "ACTIVE"
	PolicyStatusRolledBack = "ROLLED_BACK"
	PolicyStatusFailed     = "FAILED"
)

var (
	// ErrRuntimePolicyNotFound 运行时策略不存在。
	ErrRuntimePolicyNotFound = errors.New("runtime policy not found")
	// ErrNoPreviousGoodPolicy 端点无上一已知良好版本（曾生效后退出的策略），无法回滚。
	ErrNoPreviousGoodPolicy = errors.New("no previous known-good runtime policy")
	// ErrModelNotRestorable 上一已知良好版本的来源模型不可恢复（已归档或状态异常），无法回滚。
	ErrModelNotRestorable = errors.New("source model version not restorable")
)

// ValidPolicyStatus 校验策略状态取值（白名单外拒绝，不静默改写）。
func ValidPolicyStatus(s string) bool {
	switch s {
	case PolicyStatusDraft, PolicyStatusValidated, PolicyStatusPublished,
		PolicyStatusActive, PolicyStatusRolledBack, PolicyStatusFailed:
		return true
	}
	return false
}

// pendingPolicyStatuses 待发布集合：整站发布成功/失败时参与状态迁移的状态。
var pendingPolicyStatuses = []string{PolicyStatusDraft, PolicyStatusValidated, PolicyStatusPublished}

// RuntimePolicy 端点级运行时策略版本（api_runtime_policies）。
type RuntimePolicy struct {
	ID                   uuid.UUID       `json:"id"`
	EndpointID           uuid.UUID       `json:"endpoint_id"`
	EndpointKey          string          `json:"endpoint_key"` // JOIN api_endpoints 带出（展示用）
	SourceModelVersionID uuid.UUID       `json:"source_model_version_id"`
	RuntimeVersion       string          `json:"runtime_version"` // 端点内自增 "vN"
	CompilerVersion      string          `json:"compiler_version"`
	Content              json.RawMessage `json:"content"` // CompiledEndpointPolicy 规范序列化
	ContentHash          string          `json:"content_hash"`
	Status               string          `json:"status"`
	Error                string          `json:"error,omitempty"`
	CreatedAt            time.Time       `json:"created_at"`
	PublishedAt          *time.Time      `json:"published_at,omitempty"`
	ActivatedAt          *time.Time      `json:"activated_at,omitempty"`
}

// policyColumns 策略全列（SELECT/RETURNING 共用，顺序与 scanRuntimePolicy 一致）。
const policyColumns = `id, endpoint_id, source_model_version_id, runtime_version, compiler_version,
content_json, content_hash, status, error, created_at, published_at, activated_at`

// scanRuntimePolicy 按 policyColumns + endpoint_key（JOIN 列）扫描一行策略。
func scanRuntimePolicy(row scanner) (*RuntimePolicy, error) {
	var p RuntimePolicy
	err := row.Scan(&p.ID, &p.EndpointID, &p.SourceModelVersionID, &p.RuntimeVersion, &p.CompilerVersion,
		&p.Content, &p.ContentHash, &p.Status, &p.Error, &p.CreatedAt, &p.PublishedAt, &p.ActivatedAt,
		&p.EndpointKey)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// ---------- 生命周期联动（Confirm / Activate 事务内调用） ----------

// createDraftRuntimePolicyTx 编译 FORMAL 模型版本为 DRAFT 运行时策略（Confirm 事务内调用）。
// 输入：版本快照 + 端点信息 + 该版本 REQUEST 方向参数行（Confirm 事务刚物化，confirmed 词汇原样编入）。
// runtime_version 端点内自增 vN（count+1；(endpoint_id, runtime_version) 唯一约束兜底并发，冲突如实报错）。
func (s *Store) createDraftRuntimePolicyTx(ctx context.Context, tx pgx.Tx, v *Version) error {
	var in CompileInput
	in.ModelVersionID = v.ID
	in.ModelVersionNumber = v.VersionNumber
	in.Schema = v.Schema
	in.EndpointID = v.EndpointID
	in.EndpointKey = v.EndpointKey
	err := tx.QueryRow(ctx, `
SELECT http_method, normalized_path, protocol_type, asset_status
FROM api_endpoints WHERE id=$1`, v.EndpointID).
		Scan(&in.Method, &in.NormalizedPath, &in.ProtocolType, &in.AssetStatus)
	if err != nil {
		return fmt.Errorf("load endpoint for compile: %w", err)
	}
	rows, err := tx.Query(ctx, `
SELECT `+parameterColumns+`
FROM api_parameter_models
WHERE model_version_id=$1 AND direction='REQUEST'
ORDER BY location, structured_path, parameter_name`, v.ID)
	if err != nil {
		return fmt.Errorf("load parameters for compile: %w", err)
	}
	for rows.Next() {
		p, err := scanParameter(rows)
		if err != nil {
			rows.Close()
			return fmt.Errorf("scan parameter for compile: %w", err)
		}
		in.Parameters = append(in.Parameters, *p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("list parameters for compile: %w", err)
	}

	policy, err := Compile(in)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	hash, raw, err := ContentHash(policy)
	if err != nil {
		return fmt.Errorf("hash compiled policy: %w", err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO api_runtime_policies
  (endpoint_id, source_model_version_id, runtime_version, compiler_version, content_json, content_hash, status)
VALUES ($1,$2,
  'v' || ((SELECT count(*) FROM api_runtime_policies WHERE endpoint_id=$1) + 1),
  $3,$4,$5,$6)`,
		v.EndpointID, v.ID, CompilerVersion, raw, hash, PolicyStatusDraft); err != nil {
		return fmt.Errorf("insert runtime policy: %w", err)
	}
	return nil
}

// ---------- 发布结果回写（整站发布联动，guardconfig.Provider 注入调用） ----------

// MarkRuntimePoliciesPublishResult 整站发布结果回写（事务）：
// 成功——每端点待发布集合（DRAFT/VALIDATED/PUBLISHED）取最新一条 → ACTIVE（记录 published_at/activated_at），
// 同端点旧 ACTIVE → ROLLED_BACK（退出即生效集合，作为回滚溯源的「已知良好版本」）；
// 失败——全部待发布集合 → FAILED 并记录失败原因。
// 语义注释：发布内容含全部 FORMAL 模型，故回写按全量端点执行；无待发布策略的端点保持原 ACTIVE 不变。
func (s *Store) MarkRuntimePoliciesPublishResult(ctx context.Context, success bool, failReason string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if !success {
		if _, err := tx.Exec(ctx, `
UPDATE api_runtime_policies SET status=$2, error=$3
WHERE status = ANY($1)`, pendingPolicyStatuses, PolicyStatusFailed, failReason); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	// 成功：先迁新 ACTIVE（每端点待发布集合取最新一条），收集本次新生效的端点与策略 ID
	rows, err := tx.Query(ctx, `
WITH latest AS (
    SELECT DISTINCT ON (endpoint_id) id
    FROM api_runtime_policies
    WHERE status = ANY($1)
    ORDER BY endpoint_id, created_at DESC, id DESC
)
UPDATE api_runtime_policies p
SET status=$2, published_at=now(), activated_at=now(), error=''
FROM latest l
WHERE p.id = l.id
RETURNING p.id, p.endpoint_id`, pendingPolicyStatuses, PolicyStatusActive)
	if err != nil {
		return err
	}
	var endpointIDs, policyIDs []uuid.UUID
	for rows.Next() {
		var pid, eid uuid.UUID
		if err := rows.Scan(&pid, &eid); err != nil {
			rows.Close()
			return err
		}
		policyIDs = append(policyIDs, pid)
		endpointIDs = append(endpointIDs, eid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	// 同端点旧 ACTIVE → ROLLED_BACK（仅本次有新生效版本的端点；新 ACTIVE 行显式排除）
	if len(endpointIDs) > 0 {
		if _, err := tx.Exec(ctx, `
UPDATE api_runtime_policies SET status=$3
WHERE status=$1 AND endpoint_id = ANY($2) AND NOT (id = ANY($4))`,
			PolicyStatusActive, endpointIDs, PolicyStatusRolledBack, policyIDs); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ---------- 只读查询（列表 / 溯源 / 详情） ----------

// RuntimePolicyFilter 策略列表过滤。
type RuntimePolicyFilter struct {
	EndpointID *uuid.UUID // nil 表示全部端点
	Status     string     // 空表示全部状态（取值由 ValidPolicyStatus 白名单校验）
	Page       int
	PageSize   int
}

// policySelect 列表/溯源/详情共用的查询片段（JOIN api_endpoints 带出 endpoint_key）。
// 列与 policyColumns 顺序一致且必须逐列带 p. 前缀——JOIN 后 created_at 等列两表同名，无前缀会歧义（SQLSTATE 42702）。
const policySelect = `
SELECT p.id, p.endpoint_id, p.source_model_version_id, p.runtime_version, p.compiler_version,
p.content_json, p.content_hash, p.status, p.error, p.created_at, p.published_at, p.activated_at, e.endpoint_key
FROM api_runtime_policies p
JOIN api_endpoints e ON e.id = p.endpoint_id`

// ListRuntimePolicies 按过滤条件分页列出策略版本（按创建时间倒序）。
func (s *Store) ListRuntimePolicies(ctx context.Context, f RuntimePolicyFilter) ([]RuntimePolicy, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	var endpointID any
	if f.EndpointID != nil {
		endpointID = *f.EndpointID
	}
	var total int64
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM api_runtime_policies p
WHERE ($1::uuid IS NULL OR p.endpoint_id=$1) AND ($2='' OR p.status=$2)`,
		endpointID, f.Status).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, policySelect+`
WHERE ($1::uuid IS NULL OR p.endpoint_id=$1) AND ($2='' OR p.status=$2)
ORDER BY p.created_at DESC, p.id DESC LIMIT $3 OFFSET $4`,
		endpointID, f.Status, f.PageSize, (f.Page-1)*f.PageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []RuntimePolicy{}
	for rows.Next() {
		p, err := scanRuntimePolicy(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *p)
	}
	return out, total, rows.Err()
}

// ListRuntimePoliciesByModel 模型 → 策略溯源：列出由该模型版本编译产生的全部策略（按创建时间倒序）。
func (s *Store) ListRuntimePoliciesByModel(ctx context.Context, modelVersionID uuid.UUID) ([]RuntimePolicy, error) {
	rows, err := s.db.Query(ctx, policySelect+`
WHERE p.source_model_version_id=$1
ORDER BY p.created_at DESC, p.id DESC`, modelVersionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RuntimePolicy{}
	for rows.Next() {
		p, err := scanRuntimePolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// GetRuntimePolicyByID 按 ID 读取策略。
func (s *Store) GetRuntimePolicyByID(ctx context.Context, id uuid.UUID) (*RuntimePolicy, error) {
	p, err := scanRuntimePolicy(s.db.QueryRow(ctx, policySelect+` WHERE p.id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRuntimePolicyNotFound
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// ---------- 回滚 ----------

// RuntimePolicyRollback 回滚结果（RollbackToKnownGood 事务产物）。
type RuntimePolicyRollback struct {
	// Draft 克隆上一良好版本内容创建的新 DRAFT 策略（随整站发布落 ACTIVE）。
	Draft *RuntimePolicy
	// RestoredModel 恢复为 FORMAL 的模型版本（发布内容源随之回到旧模型；
	// 幂等重试时其已是 FORMAL，原样返回）。
	RestoredModel *Version
}

// RollbackToKnownGood 将端点回退到上一已知良好版本（单事务 + FOR UPDATE）：
//  1. 目标策略 {id} 须处于 ACTIVE 或 FAILED（当前生效异常/发布失败才允许回退）；
//  2. 上一已知良好版本 = 同端点最近一个曾生效后退出的策略（ROLLED_BACK 且 activated_at 非空，
//     按 activated_at 倒序取首条）；不存在则 ErrNoPreviousGoodPolicy；
//  3. 受控恢复通道：将其来源模型版本 SUPERSEDED→FORMAL（restoreFormalModelTx）——
//     发布内容源（guardconfig ListFormalSchemas 等全部按 FORMAL 选取）随之回到旧模型，
//     回滚后网关实际下发内容=旧模型内容、api_policy_version 随之变化；
//  4. 克隆其编译内容创建新 DRAFT（新 runtime_version，content_hash 与原良好版本一致），
//     由调用方随后重触发整站发布，发布成功后经 MarkRuntimePoliciesPublishResult 落 ACTIVE，
//     台账标记与网关事实一致。
func (s *Store) RollbackToKnownGood(ctx context.Context, id, operatorID uuid.UUID) (*RuntimePolicyRollback, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	cur, err := scanRuntimePolicy(tx.QueryRow(ctx, policySelect+` WHERE p.id=$1 FOR UPDATE OF p`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRuntimePolicyNotFound
	}
	if err != nil {
		return nil, err
	}
	if cur.Status != PolicyStatusActive && cur.Status != PolicyStatusFailed {
		return nil, ErrInvalidTransition
	}
	var prevID, prevModelID uuid.UUID
	err = tx.QueryRow(ctx, `
SELECT id, source_model_version_id FROM api_runtime_policies
WHERE endpoint_id=$1 AND id<>$2 AND status=$3 AND activated_at IS NOT NULL
ORDER BY activated_at DESC, created_at DESC LIMIT 1`,
		cur.EndpointID, id, PolicyStatusRolledBack).Scan(&prevID, &prevModelID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoPreviousGoodPolicy
	}
	if err != nil {
		return nil, err
	}
	restored, err := s.restoreFormalModelTx(ctx, tx, cur.EndpointID, prevModelID, operatorID)
	if err != nil {
		return nil, err
	}
	draft, err := scanRuntimePolicy(tx.QueryRow(ctx, `
INSERT INTO api_runtime_policies
  (endpoint_id, source_model_version_id, runtime_version, compiler_version, content_json, content_hash, status)
SELECT endpoint_id, source_model_version_id,
       'v' || ((SELECT count(*) FROM api_runtime_policies p2 WHERE p2.endpoint_id=$1) + 1),
       compiler_version, content_json, content_hash, $3
FROM api_runtime_policies WHERE id=$2
RETURNING `+policyColumns+`, (SELECT endpoint_key FROM api_endpoints WHERE id=$1)`,
		cur.EndpointID, prevID, PolicyStatusDraft))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &RuntimePolicyRollback{Draft: draft, RestoredModel: restored}, nil
}

// restoreFormalModelTx 受控模型恢复通道（仅回滚路径可达 SUPERSEDED→FORMAL，事务内）：
// 同端点当前 FORMAL 降级 SUPERSEDED，目标版本恢复 FORMAL 并记录操作者与确认/激活时间，
// api_endpoints.current_model_version_id 同步指向恢复版本（与 Activate 语义一致）。
// 目标版本已是 FORMAL 时幂等返回（发布触发失败后的重试场景）；ARCHIVED 等其余状态
// 一律 ErrModelNotRestorable，不提供回滚以外的恢复入口。
func (s *Store) restoreFormalModelTx(ctx context.Context, tx pgx.Tx, endpointID, targetID, operatorID uuid.UUID) (*Version, error) {
	v, err := scanVersion(tx.QueryRow(ctx, `SELECT `+versionColumns+` FROM api_model_versions WHERE id=$1 FOR UPDATE`, targetID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrModelNotRestorable
	}
	if err != nil {
		return nil, err
	}
	switch v.Status {
	case StatusFormal: // 幂等：模型已恢复（上次回滚发布未成功前的重试）
		return v, nil
	case StatusSuperseded:
	default:
		return nil, ErrModelNotRestorable
	}
	// 当前正式模型降级为 SUPERSEDED（与 Confirm 的降级语义一致）
	if _, err := tx.Exec(ctx, `
UPDATE api_model_versions SET status=$1 WHERE api_endpoint_id=$2 AND status=$3 AND id<>$4`,
		StatusSuperseded, endpointID, StatusFormal, targetID); err != nil {
		return nil, err
	}
	out, err := scanVersion(tx.QueryRow(ctx, `
UPDATE api_model_versions
SET status=$2, confirmed_by=$3, confirmed_at=now(), activated_at=now()
WHERE id=$1
RETURNING `+versionColumns, targetID, StatusFormal, nullUUID(operatorID)))
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
UPDATE api_endpoints SET current_model_version_id=$1, updated_at=now() WHERE id=$2`, targetID, endpointID); err != nil {
		return nil, err
	}
	return out, nil
}

// MarkRuntimePolicyFailed 单条待发布策略标记 FAILED 并记录原因（回滚发布触发失败的兜底）：
// 触发失败后草稿若滞留 DRAFT，会在下一次无关发布时被静默带生效（操作者无感知的孤儿 DRAFT），
// 故落 FAILED 使其在列表中可见且终态；恢复路径与发布失败一致（重新激活 + 重新发布）。
// 仅允许待发布集合（DRAFT/VALIDATED/PUBLISHED）迁入，ACTIVE/ROLLED_BACK 行不触碰；
// 0 行命中（并发下已被发布回写落定）视为幂等成功。
func (s *Store) MarkRuntimePolicyFailed(ctx context.Context, id uuid.UUID, reason string) error {
	_, err := s.db.Exec(ctx, `
UPDATE api_runtime_policies SET status=$2, error=$3
WHERE id=$1 AND status = ANY($4)`, id, PolicyStatusFailed, reason, pendingPolicyStatuses)
	return err
}
