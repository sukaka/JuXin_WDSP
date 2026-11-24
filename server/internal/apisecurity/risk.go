// risk.go API 风险中心（Risk Center，任务书 P0-13 Risk/Weakness 分离之 Risk 侧）：
// 运行时风险发现的处置状态机、降噪聚合视图与详情查询。
//
// 风险/弱点语义边界（互不混用）：
//
//	Risk（本文件，api_runtime_findings）= 运行时异常信号：谁、何时、命中了什么，
//	  由 apiruntime 采集器按 dedup_fingerprint 物化（同指纹 count 累计），
//	  处置闭环为 确认→处理→解决/误报/忽略→归档；
//	Weakness（apiweakness 包，api_weaknesses）= 长期缺陷：确认→指派→整改→
//	  复测→关闭，跨天持续跟踪。
//	本文件只读写 api_runtime_findings，不写弱点表；弱点派生只读本表不回写。
package apisecurity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrInvalidRiskTransition 非法风险状态迁移（当前状态不允许该操作）。
var ErrInvalidRiskTransition = errors.New("invalid risk finding status transition")

// 风险状态（与迁移 000042 chk_api_runtime_findings_status 一致）。
const (
	RiskStatusNew           = "NEW"            // 采集器物化，待确认
	RiskStatusConfirmed     = "CONFIRMED"      // 已确认为真实风险
	RiskStatusInProgress    = "IN_PROGRESS"    // 处理中
	RiskStatusFalsePositive = "FALSE_POSITIVE" // 误报（须填原因）
	RiskStatusIgnored       = "IGNORED"        // 接受风险，不再提示
	RiskStatusResolved      = "RESOLVED"       // 已解决（须填处置说明）
	RiskStatusArchived      = "ARCHIVED"       // 归档关闭，终态
)

// 处置动作（TransitionFinding action 入参取值）。
const (
	RiskActionConfirm       = "CONFIRM"        // 确认风险
	RiskActionStart         = "START"          // 开始处理
	RiskActionResolve       = "RESOLVE"        // 解决（必填 resolution）
	RiskActionFalsePositive = "FALSE_POSITIVE" // 标记误报（必填 reason）
	RiskActionIgnore        = "IGNORE"         // 忽略（接受风险）
	RiskActionArchive       = "ARCHIVE"        // 归档
)

// riskTransitions 风险状态机迁移表：action → 允许的源状态 → 目标状态。
// 表外组合一律非法（ErrInvalidRiskTransition，HTTP 400）。
var riskTransitions = map[string]map[string]string{
	RiskActionConfirm:       {RiskStatusNew: RiskStatusConfirmed},
	RiskActionStart:         {RiskStatusConfirmed: RiskStatusInProgress},
	RiskActionResolve:       {RiskStatusConfirmed: RiskStatusResolved, RiskStatusInProgress: RiskStatusResolved},
	RiskActionFalsePositive: {RiskStatusNew: RiskStatusFalsePositive, RiskStatusConfirmed: RiskStatusFalsePositive, RiskStatusInProgress: RiskStatusFalsePositive},
	RiskActionIgnore:        {RiskStatusNew: RiskStatusIgnored, RiskStatusConfirmed: RiskStatusIgnored, RiskStatusInProgress: RiskStatusIgnored},
	RiskActionArchive:       {RiskStatusResolved: RiskStatusArchived, RiskStatusFalsePositive: RiskStatusArchived, RiskStatusIgnored: RiskStatusArchived},
}

// ResolveRiskTransition 计算 (action, from) 的目标状态；非法组合返回 false。
func ResolveRiskTransition(action, from string) (string, bool) {
	byFrom, ok := riskTransitions[action]
	if !ok {
		return "", false
	}
	to, ok := byFrom[from]
	return to, ok
}

// riskActiveStatuses 未闭环的活动状态（态势统计「未闭环风险」口径）。
var riskActiveStatuses = map[string]bool{
	RiskStatusNew: true, RiskStatusConfirmed: true, RiskStatusInProgress: true,
}

// IsRiskActiveStatus 判断风险状态是否为活动（未闭环）状态。
func IsRiskActiveStatus(s string) bool { return riskActiveStatuses[s] }

// validRiskStatuses 状态白名单（列表过滤/入参校验用）。
var validRiskStatuses = map[string]bool{
	RiskStatusNew: true, RiskStatusConfirmed: true, RiskStatusInProgress: true,
	RiskStatusFalsePositive: true, RiskStatusIgnored: true,
	RiskStatusResolved: true, RiskStatusArchived: true,
}

// IsValidRiskStatus 校验风险状态取值。
func IsValidRiskStatus(s string) bool { return validRiskStatuses[s] }

// IsValidRiskSeverity 校验严重度取值（与迁移 000018 api_runtime_findings.severity
// 注释词表一致：INFO/LOW/MEDIUM/HIGH/CRITICAL；词表单一来源为 riskSeverityRank，
// 生产方缺 severity 时保守落 INFO，见 apiruntime/findings.go）。
func IsValidRiskSeverity(s string) bool { return riskSeverityRank(s) > 0 }

// riskFindingTypeMaxLen finding_type 过滤值长度上限（与列 VARCHAR(64) 及生产方
// apiruntime maxFindingTypeLen 同一口径）。
const riskFindingTypeMaxLen = 64

// IsValidRiskFindingType 校验 finding_type 过滤值形态。finding_type 词表开放
// （生产方按 detector/rule_id 大写下划线化生成，迁移无 CHECK，故不做封闭枚举），
// 按形态校验：1-64 字符、仅大写字母/数字/下划线；非法形态由调用方明确 400，
// 不静默返回空列表。
func IsValidRiskFindingType(s string) bool {
	if s == "" || len(s) > riskFindingTypeMaxLen {
		return false
	}
	for _, c := range s {
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// riskSeverityRank 严重度排序（INFO<LOW<MEDIUM<HIGH<CRITICAL；未识别 0，与
// api_runtime_events risk_level 词表同源的展示口径，SQL 聚合与内存聚合共用）。
func riskSeverityRank(s string) int {
	switch s {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	}
	return 0
}

// riskSeverityFromRank rank → 严重度词（0 兜底 INFO：生产方缺 severity 时保守落 INFO，
// 见 apiruntime/findings.go 物化规则）。
func riskSeverityFromRank(r int) string {
	switch r {
	case 5:
		return "CRITICAL"
	case 4:
		return "HIGH"
	case 3:
		return "MEDIUM"
	case 2:
		return "LOW"
	default:
		return "INFO"
	}
}

// riskSummaryLimit 聚合视图每维返回桶数上限（降噪：风险中心只看头部风险）。
const riskSummaryLimit = 100

// riskRelatedLimit 详情关联 request_id 上限。
const riskRelatedLimit = 20

// RiskFinding 风险发现详情（api_runtime_findings 全列视图，含 000036 物化列）。
type RiskFinding struct {
	ID            uuid.UUID       `json:"id"`
	EndpointID    *uuid.UUID      `json:"endpoint_id,omitempty"`
	EndpointKey   string          `json:"endpoint_key"` // LEFT JOIN api_endpoints 带出；端点已删除时为空
	RequestID     string          `json:"request_id"`   // 首次命中请求（dedup upsert 只保留首次，后续命中仅计数）
	FindingType   string          `json:"finding_type"`
	Severity      string          `json:"severity"`
	Status        string          `json:"status"`
	Title         string          `json:"title"`
	Detail        json.RawMessage `json:"detail"` // 首次命中上下文（detector/rule_id 等）+ detail.handling 处置记录
	SubjectType   string          `json:"subject_type"`
	SubjectID     string          `json:"subject_id"` // 身份指纹或来源指纹（永不落明文）
	RiskScore     *int            `json:"risk_score,omitempty"`
	RiskLevel     string          `json:"risk_level"`
	Count         int             `json:"count"` // 同指纹累计命中次数
	Evidence      json.RawMessage `json:"evidence"`
	ModelVersion  string          `json:"model_version"`
	PolicyVersion string          `json:"policy_version"`
	FirstSeenAt   time.Time       `json:"first_seen_at"`
	LastSeenAt    time.Time       `json:"last_seen_at"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     *time.Time      `json:"updated_at,omitempty"`
}

// RiskSummaryBucket 降噪聚合桶（三视图共用；按视图取用相应维度字段）。
type RiskSummaryBucket struct {
	SubjectType string     `json:"subject_type,omitempty"`
	SubjectID   string     `json:"subject_id,omitempty"`
	EndpointID  *uuid.UUID `json:"endpoint_id,omitempty"`
	EndpointKey string     `json:"endpoint_key,omitempty"`
	FindingType string     `json:"finding_type,omitempty"`
	Count       int64      `json:"count"`        // 聚合的 finding 条目数（dedup 去重后）
	Hits        int64      `json:"hits"`         // 累计命中次数（sum(count)）
	MaxSeverity string     `json:"max_severity"` // 桶内最高严重度
	LastSeenAt  time.Time  `json:"last_seen_at"`
}

// RiskSummary 风险降噪聚合（主体 / 端点 / 类型三视图）。
type RiskSummary struct {
	BySubject     []RiskSummaryBucket `json:"by_subject"`
	ByEndpoint    []RiskSummaryBucket `json:"by_endpoint"`
	ByFindingType []RiskSummaryBucket `json:"by_finding_type"`
}

// RiskHandleInput 一次风险处置输入。
type RiskHandleInput struct {
	Actor string    // 操作者用户名
	Note  string    // resolution / reason（按动作语义；落 detail.handling）
	Now   time.Time // 流转发生时间（测试可注入）
}

// RiskRepository 风险中心仓储（SQL 与内存实现共用，便于诚实单测；仿 apiweakness.Repository）。
type RiskRepository interface {
	// GetFinding 风险详情（不存在返回 ErrNotFound）
	GetFinding(ctx context.Context, id uuid.UUID) (*RiskFinding, error)
	// TransitionFinding 状态机流转（行锁读当前状态 → 状态机校验 → 更新 +
	// detail.handling 处置记录，一个事务；非法迁移返回 ErrInvalidRiskTransition）
	TransitionFinding(ctx context.Context, id uuid.UUID, action string, in RiskHandleInput) (*RiskFinding, error)
	// SummarizeFindings 降噪聚合（主体/端点/类型三视图，各取头部 riskSummaryLimit 桶）
	SummarizeFindings(ctx context.Context) (*RiskSummary, error)
	// ListRelatedRequestIDs 关联请求 ID 列表。来源注释：api_runtime_events 按
	// endpoint_key 点查最近事件，subject_type=IDENTITY 时附带身份指纹过滤；
	// dedup upsert 只保留首次 request_id，故此为「同端点（同身份）近期请求」的
	// 近似关联，非精确命中回放。
	ListRelatedRequestIDs(ctx context.Context, endpointKey, subjectType, subjectID string, limit int) ([]string, error)
}

// 确保 *Store / *RiskMemStore 实现 RiskRepository。
var (
	_ RiskRepository = (*Store)(nil)
	_ RiskRepository = (*RiskMemStore)(nil)
)

// ---------- SQL 实现（*Store；000042 迁移后的七态词表） ----------

// riskFindingCols 风险详情查询列（f 别名；endpoint_key 由 JOIN 带出）。
const riskFindingCols = `
f.id, f.endpoint_id, COALESCE(e.endpoint_key, ''), f.request_id, f.finding_type, f.severity, f.status,
f.title, f.detail, COALESCE(f.subject_type, ''), COALESCE(f.subject_id, ''),
f.risk_score, COALESCE(f.risk_level, ''), f.count, COALESCE(f.evidence_json, '{}'::jsonb),
COALESCE(f.model_version, ''), COALESCE(f.policy_version, ''),
f.first_seen_at, f.last_seen_at, f.created_at, f.updated_at`

// scanRiskFinding 扫描一行风险详情。
func scanRiskFinding(row pgx.Row) (*RiskFinding, error) {
	var f RiskFinding
	err := row.Scan(&f.ID, &f.EndpointID, &f.EndpointKey, &f.RequestID, &f.FindingType, &f.Severity,
		&f.Status, &f.Title, &f.Detail, &f.SubjectType, &f.SubjectID, &f.RiskScore, &f.RiskLevel,
		&f.Count, &f.Evidence, &f.ModelVersion, &f.PolicyVersion,
		&f.FirstSeenAt, &f.LastSeenAt, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		return nil, err
	}
	f.Title = localizeFindingTitle(f.FindingType, f.Title, f.Detail)
	return &f, nil
}

// GetFinding 风险详情（不存在返回 ErrNotFound）。
func (s *Store) GetFinding(ctx context.Context, id uuid.UUID) (*RiskFinding, error) {
	f, err := scanRiskFinding(s.db.QueryRow(ctx, `
SELECT `+riskFindingCols+`
FROM api_runtime_findings f
LEFT JOIN api_endpoints e ON e.id = f.endpoint_id
WHERE f.id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return f, nil
}

// TransitionFinding 风险处置流转：行锁读当前状态 → 状态机校验 → 更新状态并把
// 处置记录合并进 detail.handling（JSONB 浅合并，保留首次命中上下文），一个事务。
func (s *Store) TransitionFinding(ctx context.Context, id uuid.UUID, action string, in RiskHandleInput) (*RiskFinding, error) {
	if in.Now.IsZero() {
		in.Now = time.Now().UTC()
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var from string
	err = tx.QueryRow(ctx, `SELECT status FROM api_runtime_findings WHERE id = $1 FOR UPDATE`, id).Scan(&from)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	to, ok := ResolveRiskTransition(action, from)
	if !ok {
		return nil, fmt.Errorf("%w: %s 状态不允许 %s", ErrInvalidRiskTransition, from, action)
	}

	handling, _ := json.Marshal(map[string]any{
		"action": action, "actor": in.Actor, "note": in.Note, "at": in.Now,
	})
	ct, err := tx.Exec(ctx, `
UPDATE api_runtime_findings
SET status = $1, updated_at = $2, detail = detail || jsonb_build_object('handling', $3::jsonb)
WHERE id = $4`, to, in.Now, string(handling), id)
	if err != nil {
		return nil, err
	}
	if ct.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetFinding(ctx, id)
}

// 三视图聚合 SQL 片段：严重度取词表 rank 最大值，Go 侧映射回严重度词。
const riskSeverityRankExpr = `max(CASE f.severity
  WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3
  WHEN 'LOW' THEN 2 WHEN 'INFO' THEN 1 ELSE 0 END)`

// SummarizeFindings 降噪聚合：主体 / 端点 / 类型三视图，各按最高严重度+累计命中
// 排序取头部 riskSummaryLimit 桶。
func (s *Store) SummarizeFindings(ctx context.Context) (*RiskSummary, error) {
	sum := &RiskSummary{
		BySubject:     []RiskSummaryBucket{},
		ByEndpoint:    []RiskSummaryBucket{},
		ByFindingType: []RiskSummaryBucket{},
	}

	// 主体视图（subject_type/subject_id 可空：无主体信息的发现聚为 ('','') 匿名桶）
	rows, err := s.db.Query(ctx, `
SELECT COALESCE(f.subject_type, ''), COALESCE(f.subject_id, ''),
       count(*), COALESCE(sum(f.count), 0), `+riskSeverityRankExpr+`, max(f.last_seen_at)
FROM api_runtime_findings f
GROUP BY f.subject_type, f.subject_id
ORDER BY 5 DESC, 4 DESC, 1, 2
LIMIT `+fmt.Sprint(riskSummaryLimit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b RiskSummaryBucket
		var rank int
		if err := rows.Scan(&b.SubjectType, &b.SubjectID, &b.Count, &b.Hits, &rank, &b.LastSeenAt); err != nil {
			return nil, err
		}
		b.MaxSeverity = riskSeverityFromRank(rank)
		sum.BySubject = append(sum.BySubject, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 端点视图（endpoint_id 可空：端点未解析的发现聚为 NULL 桶，endpoint_key 空串）
	rows2, err := s.db.Query(ctx, `
SELECT f.endpoint_id, COALESCE(e.endpoint_key, ''),
       count(*), COALESCE(sum(f.count), 0), `+riskSeverityRankExpr+`, max(f.last_seen_at)
FROM api_runtime_findings f
LEFT JOIN api_endpoints e ON e.id = f.endpoint_id
GROUP BY f.endpoint_id, e.endpoint_key
ORDER BY 5 DESC, 4 DESC, 2
LIMIT `+fmt.Sprint(riskSummaryLimit))
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var b RiskSummaryBucket
		var rank int
		if err := rows2.Scan(&b.EndpointID, &b.EndpointKey, &b.Count, &b.Hits, &rank, &b.LastSeenAt); err != nil {
			return nil, err
		}
		b.MaxSeverity = riskSeverityFromRank(rank)
		sum.ByEndpoint = append(sum.ByEndpoint, b)
	}
	if err := rows2.Err(); err != nil {
		return nil, err
	}

	// 类型视图
	rows3, err := s.db.Query(ctx, `
SELECT f.finding_type, count(*), COALESCE(sum(f.count), 0), `+riskSeverityRankExpr+`, max(f.last_seen_at)
FROM api_runtime_findings f
GROUP BY f.finding_type
ORDER BY 4 DESC, 3 DESC, 1
LIMIT `+fmt.Sprint(riskSummaryLimit))
	if err != nil {
		return nil, err
	}
	defer rows3.Close()
	for rows3.Next() {
		var b RiskSummaryBucket
		var rank int
		if err := rows3.Scan(&b.FindingType, &b.Count, &b.Hits, &rank, &b.LastSeenAt); err != nil {
			return nil, err
		}
		b.MaxSeverity = riskSeverityFromRank(rank)
		sum.ByFindingType = append(sum.ByFindingType, b)
	}
	return sum, rows3.Err()
}

// ListRelatedRequestIDs 关联请求 ID（来源见 RiskRepository 接口注释；occurred_at 倒序）。
func (s *Store) ListRelatedRequestIDs(ctx context.Context, endpointKey, subjectType, subjectID string, limit int) ([]string, error) {
	if limit <= 0 || limit > riskRelatedLimit {
		limit = riskRelatedLimit
	}
	// IDENTITY 主体附带身份指纹过滤；IP 主体为来源指纹（事件表无对应列），
	// 匿名主体无过滤条件，均退化为同端点近期请求
	identity := ""
	if subjectType == "IDENTITY" {
		identity = subjectID
	}
	rows, err := s.db.Query(ctx, `
SELECT request_id FROM api_runtime_events
WHERE endpoint_key = $1 AND ($2 = '' OR identity_fingerprint = $2)
ORDER BY occurred_at DESC LIMIT $3`, endpointKey, identity, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var rid string
		if err := rows.Scan(&rid); err != nil {
			return nil, err
		}
		out = append(out, rid)
	}
	return out, rows.Err()
}
