// relations.go 参数条件关系（P0-02）：候选生成 + 确认闭环（W11-REL）。
// 对同一 FORMAL 版本内同时具备统计画像的参数对，写入 CO_OCCURS 候选（低置信度）；
// 候选 confirmed=false 不生效，人工确认（confirmed=true）后才经发布通道下发网关强制检测。
package apimodels

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 参数条件关系类型词表（与迁移 000068 + 000147 + 000154 + 000159 CHECK 一致）。
const (
	// RelationRequires A 存在要求 B 必须存在（单向：source → target）。
	RelationRequires = "REQUIRES"
	// RelationMutex A 与 B 互斥（同现即违例）。
	RelationMutex = "MUTEX"
	// RelationCoOccurs 统计共现（单侧出现为偏离；仅观察，永不阻断）。
	RelationCoOccurs = "CO_OCCURS"
	// RelationExcludes 历史词表（000018 注释记载，语义同 MUTEX；不开放手工新建）。
	RelationExcludes = "EXCLUDES"
	// RelationEquals 等值：两端值字符串相等（000147，任务书 §23）。
	RelationEquals = "EQUALS"
	// RelationNotEquals 不等值：两端值字符串须不相等（000154；EQUALS 严格对偶，字符串比较无类型要求）。
	RelationNotEquals = "NOT_EQUALS"
	// RelationGreaterThan A 值数值严格大于 B 值（可解析为数值才判定）。
	RelationGreaterThan = "GREATER_THAN"
	// RelationLessThan A 值数值严格小于 B 值（可解析为数值才判定）。
	RelationLessThan = "LESS_THAN"
	// RelationTimeBefore A 值时间严格早于 B 值（可解析为时间才判定）。
	RelationTimeBefore = "TIME_BEFORE"
	// RelationTimeAfter A 值时间严格晚于 B 值（可解析为时间才判定）。
	RelationTimeAfter = "TIME_AFTER"
	// RelationCountMatches 数量一致：A 整数值须等于 B 数组长度（000159，任务书 §23；
	// B 须为 BODY 数组路径，网关数组长度留存，截断/类型不符不判定）。
	RelationCountMatches = "COUNT_MATCHES"
	// RelationSumMatches 汇总关系：A 数值须等于 B 数组元素数值和（000159，任务书 §23；
	// B 须为 BODY 数组元素数值路径，浮点混合容差 1e-9，截断/超聚合预算不判定）。
	RelationSumMatches = "SUM_MATCHES"
)

// manualRelationTypes 开放手工新建的关系类型（CO_OCCURS 由统计候选产生、EXCLUDES 为历史词表，
// 均不开放手工新建；值比较六类与数组聚合两类语义明确、可确定性判定，任务书 §23 支持人工确认；
// §23 其余三类——父子对象/租户/所有者——请求内无可判定证据，不纳入词表，
// 降级论证见 gateway detectors/relationvalue.go 头注释）。
var manualRelationTypes = map[string]bool{
	RelationRequires:     true,
	RelationMutex:        true,
	RelationEquals:       true,
	RelationNotEquals:    true,
	RelationGreaterThan:  true,
	RelationLessThan:     true,
	RelationTimeBefore:   true,
	RelationTimeAfter:    true,
	RelationCountMatches: true,
	RelationSumMatches:   true,
}

var (
	// ErrRelationNotFound 参数关系不存在。
	ErrRelationNotFound = errors.New("parameter relation not found")
	// ErrRelationAlreadyConfirmed 关系已确认（重复确认）。
	ErrRelationAlreadyConfirmed = errors.New("parameter relation already confirmed")
	// ErrRelationNotConfirmed 关系未确认（仅已确认关系可撤回）。
	ErrRelationNotConfirmed = errors.New("parameter relation not confirmed")
	// ErrRelationInvalidType 手工新建仅支持 manualRelationTypes 词表（REQUIRES/MUTEX + 值比较六类 + 数组聚合两类）。
	ErrRelationInvalidType = errors.New("invalid relation type for manual creation")
	// ErrRelationParamMismatch 关系两端参数必须为同一模型版本内不同的请求侧参数。
	ErrRelationParamMismatch = errors.New("relation parameters must be distinct request parameters of the same model version")
	// ErrRelationDuplicate 同版本同参数对同类型关系已存在。
	ErrRelationDuplicate = errors.New("parameter relation already exists")
)

// ParameterRelation 参数条件关系（api_parameter_relations，含 000068 确认列）。
type ParameterRelation struct {
	ID                uuid.UUID      `json:"id"`
	ModelVersionID    uuid.UUID      `json:"model_version_id"`
	SourceParameterID uuid.UUID      `json:"source_parameter_id"`
	TargetParameterID uuid.UUID      `json:"target_parameter_id"`
	RelationType      string         `json:"relation_type"`
	Condition         map[string]any `json:"condition"`
	Confidence        float64        `json:"confidence"`
	Confirmed         bool           `json:"confirmed"`
	ConfirmedBy       *uuid.UUID     `json:"confirmed_by,omitempty"`
	ConfirmedAt       *time.Time     `json:"confirmed_at,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
}

// relationColumns 关系全列（SELECT/RETURNING 共用，顺序与 scanRelation 一致）。
const relationColumns = `id, model_version_id, source_parameter_id, target_parameter_id,
relation_type, condition, confidence, confirmed, confirmed_by, confirmed_at, created_at`

// scanRelation 按 relationColumns 顺序扫描一行关系。
func scanRelation(row scanner) (*ParameterRelation, error) {
	var r ParameterRelation
	var cond []byte
	err := row.Scan(&r.ID, &r.ModelVersionID, &r.SourceParameterID, &r.TargetParameterID,
		&r.RelationType, &cond, &r.Confidence, &r.Confirmed, &r.ConfirmedBy, &r.ConfirmedAt, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	r.Condition = decodeConstraints(cond)
	return &r, nil
}

// GetParameterRelation 按 ID 读取关系。
func (s *Store) GetParameterRelation(ctx context.Context, id uuid.UUID) (*ParameterRelation, error) {
	r, err := scanRelation(s.db.QueryRow(ctx,
		`SELECT `+relationColumns+` FROM api_parameter_relations WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRelationNotFound
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// ConfirmParameterRelation 确认关系：候选 → confirmed（记录 confirmed_by/at）。
// 条件更新原子完成（confirmed=false 才生效）；已确认行重复确认返回
// ErrRelationAlreadyConfirmed（状态机冲突），不存在返回 ErrRelationNotFound。
func (s *Store) ConfirmParameterRelation(ctx context.Context, id, operatorID uuid.UUID) (*ParameterRelation, error) {
	r, err := scanRelation(s.db.QueryRow(ctx, `
UPDATE api_parameter_relations
SET confirmed=true, confirmed_by=$2, confirmed_at=now()
WHERE id=$1 AND confirmed=false
RETURNING `+relationColumns, id, nullUUID(operatorID)))
	if errors.Is(err, pgx.ErrNoRows) {
		// 区分「不存在」与「已确认」（条件未命中）
		if _, gerr := s.GetParameterRelation(ctx, id); gerr != nil {
			return nil, gerr
		}
		return nil, ErrRelationAlreadyConfirmed
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// RejectParameterRelation 撤回确认：confirmed → 候选（清空 confirmed_by/at）。
// 条件更新原子完成（confirmed=true 才生效）；仅已确认行可撤回（未确认候选本就不下发，
// 无需驳回动作）；行保留不删除——删除 CO_OCCURS 候选会被
// RefreshParameterRelationCandidates 的 NOT EXISTS 守卫重新生成。
func (s *Store) RejectParameterRelation(ctx context.Context, id uuid.UUID) (*ParameterRelation, error) {
	r, err := scanRelation(s.db.QueryRow(ctx, `
UPDATE api_parameter_relations
SET confirmed=false, confirmed_by=NULL, confirmed_at=NULL
WHERE id=$1 AND confirmed=true
RETURNING `+relationColumns, id))
	if errors.Is(err, pgx.ErrNoRows) {
		// 区分「不存在」与「未确认」（条件未命中）
		if _, gerr := s.GetParameterRelation(ctx, id); gerr != nil {
			return nil, gerr
		}
		return nil, ErrRelationNotConfirmed
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// CreateParameterRelation 手工新建关系（manualRelationTypes 词表；初始为候选 confirmed=false，
// 确认走 confirm 接口，与 apiauthz 角色基线同一纪律）。
// 校验：两端参数必须存在、同属于给定模型版本、为请求侧（REQUEST）且互不相同；
// 同版本同参数对同类型重复新建返回 ErrRelationDuplicate。
func (s *Store) CreateParameterRelation(ctx context.Context, versionID, srcID, tgtID uuid.UUID, relationType string) (*ParameterRelation, error) {
	if !manualRelationTypes[relationType] {
		return nil, ErrRelationInvalidType
	}
	if srcID == tgtID {
		return nil, ErrRelationParamMismatch
	}
	var n int
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM api_parameter_models
WHERE model_version_id=$1 AND direction='REQUEST' AND id IN ($2,$3)`,
		versionID, srcID, tgtID).Scan(&n); err != nil {
		return nil, err
	}
	if n != 2 {
		return nil, ErrRelationParamMismatch
	}
	var exists bool
	if err := s.db.QueryRow(ctx, `
SELECT EXISTS(SELECT 1 FROM api_parameter_relations
WHERE model_version_id=$1 AND source_parameter_id=$2 AND target_parameter_id=$3 AND relation_type=$4)`,
		versionID, srcID, tgtID, relationType).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrRelationDuplicate
	}
	// 人工登记置信度记 1.0（操作者显式断言，区别于 CO_OCCURS 统计候选 0.3）
	return scanRelation(s.db.QueryRow(ctx, `
INSERT INTO api_parameter_relations (model_version_id, source_parameter_id, target_parameter_id, relation_type, condition, confidence)
VALUES ($1,$2,$3,$4,'{}'::jsonb,1.0)
RETURNING `+relationColumns, versionID, srcID, tgtID, relationType))
}

// RefreshParameterRelationCandidates 为最新 FORMAL 版本生成 CO_OCCURS 候选关系。
// 幂等：同版本同 pair 同类型不重复插入。返回新插入行数。
func (s *Store) RefreshParameterRelationCandidates(ctx context.Context) (int, error) {
	// 删除过旧候选后重建较难定义；采用 NOT EXISTS 插入
	tag, err := s.db.Exec(ctx, `
WITH formal AS (
    SELECT DISTINCT ON (v.api_endpoint_id) v.id AS version_id
    FROM api_model_versions v
    WHERE v.status = 'FORMAL'
    ORDER BY v.api_endpoint_id, v.confirmed_at DESC NULLS LAST
),
params AS (
    SELECT p.id, p.model_version_id
    FROM api_parameter_models p
    JOIN formal f ON f.version_id = p.model_version_id
    JOIN api_parameter_statistics st ON st.parameter_id = p.id AND st.sample_count >= 10
    WHERE p.direction = 'REQUEST'
),
pairs AS (
    SELECT a.model_version_id, a.id AS src, b.id AS tgt
    FROM params a
    JOIN params b ON a.model_version_id = b.model_version_id AND a.id < b.id
)
INSERT INTO api_parameter_relations (model_version_id, source_parameter_id, target_parameter_id, relation_type, condition, confidence)
SELECT p.model_version_id, p.src, p.tgt, 'CO_OCCURS', '{}'::jsonb, 0.3
FROM pairs p
WHERE NOT EXISTS (
    SELECT 1 FROM api_parameter_relations r
    WHERE r.model_version_id = p.model_version_id
      AND r.source_parameter_id = p.src AND r.target_parameter_id = p.tgt
      AND r.relation_type = 'CO_OCCURS'
)`)
	if err != nil {
		return 0, fmt.Errorf("insert relation candidates: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// ListParameterRelations 按版本列出参数关系（含确认状态；confirmed=false 为候选不生效）。
func (s *Store) ListParameterRelations(ctx context.Context, versionID uuid.UUID) ([]map[string]any, error) {
	rows, err := s.db.Query(ctx, `
SELECT id::text, source_parameter_id::text, target_parameter_id::text, relation_type, confidence, condition,
       confirmed, confirmed_by::text, confirmed_at
FROM api_parameter_relations WHERE model_version_id=$1
ORDER BY relation_type, confidence DESC`, versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, src, tgt, rel string
		var conf float64
		var cond []byte
		var confirmed bool
		var confirmedBy *string
		var confirmedAt *time.Time
		if err := rows.Scan(&id, &src, &tgt, &rel, &conf, &cond, &confirmed, &confirmedBy, &confirmedAt); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id": id, "source_parameter_id": src, "target_parameter_id": tgt,
			"relation_type": rel, "confidence": conf, "condition": decodeConstraints(cond),
			"confirmed": confirmed, "confirmed_by": confirmedBy, "confirmed_at": confirmedAt,
		})
	}
	return out, rows.Err()
}

// ---------- 发布通道下发（仅 confirmed 关系进入强制检测，任务书 §45） ----------

// ParamRelationRef 关系一端参数引用（发布通道下发；JSON 契约与网关侧镜像一致）。
type ParamRelationRef struct {
	Location string `json:"location"` // QUERY / HEADER / BODY / PATH / COOKIE
	Path     string `json:"path"`     // 结构化路径（BODY 点路径）
	Name     string `json:"name"`     // 参数名
}

// ParamRelation 已确认参数条件关系（发布通道下发网关；endpoint_key 由 FORMAL 版本解析）。
type ParamRelation struct {
	EndpointKey  string           `json:"endpoint_key"`
	RelationType string           `json:"relation_type"` // REQUIRES / MUTEX / CO_OCCURS + 值比较六类 + 数组聚合两类（词表见迁移 000068/000147/000154/000159）
	ParamA       ParamRelationRef `json:"param_a"`
	ParamB       ParamRelationRef `json:"param_b"`
}

// ListConfirmedParameterRelations 返回全部 FORMAL 端点的已确认参数条件关系（平铺列表，
// endpoint_key 由关系所属 FORMAL 版本解析），供发布通道下发网关。
// 端点选取语义与 ListFormalParameterConstraints 一致（DISTINCT ON 取最近确认的 FORMAL 版本）；
// 仅取 confirmed=true 行——候选（CO_OCCURS 低置信度/待确认手工关系）不下发不生效。
func (s *Store) ListConfirmedParameterRelations(ctx context.Context) ([]ParamRelation, error) {
	rows, err := s.db.Query(ctx, `
WITH formal AS (
    SELECT DISTINCT ON (endpoint_key) id, endpoint_key
    FROM api_model_versions WHERE status='FORMAL'
    ORDER BY endpoint_key, confirmed_at DESC NULLS LAST
)
SELECT f.endpoint_key, r.relation_type,
       a.location, a.structured_path, a.parameter_name,
       b.location, b.structured_path, b.parameter_name
FROM formal f
JOIN api_parameter_relations r ON r.model_version_id = f.id AND r.confirmed
JOIN api_parameter_models a ON a.id = r.source_parameter_id
JOIN api_parameter_models b ON b.id = r.target_parameter_id
ORDER BY f.endpoint_key, r.relation_type, a.parameter_name, b.parameter_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ParamRelation{}
	for rows.Next() {
		var rel ParamRelation
		if err := rows.Scan(&rel.EndpointKey, &rel.RelationType,
			&rel.ParamA.Location, &rel.ParamA.Path, &rel.ParamA.Name,
			&rel.ParamB.Location, &rel.ParamB.Path, &rel.ParamB.Name); err != nil {
			return nil, err
		}
		out = append(out, rel)
	}
	return out, rows.Err()
}
