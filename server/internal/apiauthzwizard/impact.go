// impact.go 影响评估（§1.3）：切换前预览——该端点近 N 天 OBSERVE_VIOLATION 命中数
// （切换后将被 403 的请求量近似）、UNKNOWN 分桶、涉及主体数、最近命中样本。
// 只读评估（不产生任何写副作用）；评估结果不入库（确认单才入库）。
package apiauthzwizard

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ImpactWindow 评估窗口词表（§1.3 冻结：1~30 天，词表外 400 不夹紧猜义）。
const (
	impactWindowMinDays = 1
	impactWindowMaxDays = 30
	impactSampleLimit   = 5
)

// ImpactRequest 影响评估请求。
type ImpactRequest struct {
	EndpointID    string `json:"endpoint_id"`
	WindowDays    int    `json:"window_days"`
	ObjectSegment string `json:"object_segment,omitempty"` // 端点多对象模型行时指定（缺省恰一行自动选定）
}

// UnknownReasonBucket UNKNOWN 分桶（按 checks 展开 reason_code 计数——
// 一 UNKNOWN 行可含 BOLA+BFLA 两 check 各带 reason，分桶总和可超 unknown_total）。
type UnknownReasonBucket struct {
	ReasonCode string `json:"reason_code"`
	Count      int64  `json:"count"`
}

// ImpactSample 最近命中样本（脱敏：时刻/决策/原因码；evidence_read 权限才返回）。
type ImpactSample struct {
	OccurredAt time.Time `json:"occurred_at"`
	Decision   string    `json:"decision"`
	ReasonCode string    `json:"reason_code"`
}

// ImpactResult 影响评估响应（§1.3 逐键冻结）。
type ImpactResult struct {
	EndpointID             uuid.UUID             `json:"endpoint_id"`
	EndpointKey            string                `json:"endpoint_key"`
	ObjectSegment          string                `json:"object_segment"`
	WindowDays             int                   `json:"window_days"`
	EvaluatedAt            time.Time             `json:"evaluated_at"`
	ObserveViolationCount  int64                 `json:"observe_violation_count"`
	UnknownTotal           int64                 `json:"unknown_total"`
	UnknownByReason        []UnknownReasonBucket `json:"unknown_by_reason"`
	DistinctPrincipalCount int64                 `json:"distinct_principal_count"`
	VerifiedViolationCount int64                 `json:"verified_violation_count"`
	RecentSamples          []ImpactSample        `json:"recent_samples,omitempty"`
	Readiness              string                `json:"readiness"`
	ReadinessReasons       []string              `json:"readiness_reasons"`
	ConfirmToken           *uuid.UUID            `json:"confirm_token,omitempty"`
	ConfirmTokenExpiresAt  *time.Time            `json:"confirm_token_expires_at,omitempty"`
}

// decisionCounts 决策计数（按 application_id+endpoint_key 族+窗口；decisions 表
// (application_id, occurred_at DESC) 索引有界扫描）。
// 键族口径（联调修正）：决策/事件落库的 endpoint_key 是请求路径归一化后的键——
// 纯数字段归一为 {id}（恰等于模板键），不可归一对象值（如 t001）保留字面（每值一键）；
// 同一端点（模板）对应一族键，按模板派生 LIKE 模式匹配（占位段 → %，LIKE 特殊字符转义）。
func (s *Store) decisionCounts(ctx context.Context, applicationID uuid.UUID, endpointKey string, since time.Time) (observeViolation, unknownTotal, verifiedViolation int64, err error) {
	err = s.db.QueryRow(ctx, `SELECT
	count(*) FILTER (WHERE decision='OBSERVE_VIOLATION'),
	count(*) FILTER (WHERE decision='UNKNOWN'),
	count(*) FILTER (WHERE decision='VERIFIED_VIOLATION')
	FROM api_authorization_decisions
	WHERE application_id=$1 AND endpoint_key LIKE $2 ESCAPE '\' AND occurred_at>=$3`,
		applicationID, endpointKeyPattern(endpointKey), since).Scan(&observeViolation, &unknownTotal, &verifiedViolation)
	return
}

// unknownByReason UNKNOWN 分桶（checks jsonb 展开 reason_code）。
func (s *Store) unknownByReason(ctx context.Context, applicationID uuid.UUID, endpointKey string, since time.Time) ([]UnknownReasonBucket, error) {
	rows, err := s.db.Query(ctx, `SELECT c->>'reason_code', count(*)
	FROM api_authorization_decisions, jsonb_array_elements(checks) c
	WHERE application_id=$1 AND endpoint_key LIKE $2 ESCAPE '\' AND occurred_at>=$3 AND decision='UNKNOWN'
	  AND c->>'reason_code' IS NOT NULL
	GROUP BY 1 ORDER BY 2 DESC, 1`, applicationID, endpointKeyPattern(endpointKey), since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UnknownReasonBucket{}
	for rows.Next() {
		var b UnknownReasonBucket
		if err := rows.Scan(&b.ReasonCode, &b.Count); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// distinctPrincipalCount 涉及主体数（VERIFIED 主体指纹 distinct；
// api_runtime_events 时间索引有界扫描 + endpoint_key 过滤）。
func (s *Store) distinctPrincipalCount(ctx context.Context, endpointKey string, since time.Time) (int64, error) {
	var n int64
	err := s.db.QueryRow(ctx, `SELECT count(DISTINCT jwt_verification->>'verified_principal_id')
	FROM api_runtime_events
	WHERE endpoint_key LIKE $1 ESCAPE '\' AND occurred_at>=$2 AND jwt_verification->>'verified_principal_id' IS NOT NULL`,
		endpointKeyPattern(endpointKey), since).Scan(&n)
	return n, err
}

// recentSamples 最近命中样本（非 ALLOW 决策 ≤5 条，reason_code 取首个非空 check）。
func (s *Store) recentSamples(ctx context.Context, applicationID uuid.UUID, endpointKey string, since time.Time) ([]ImpactSample, error) {
	rows, err := s.db.Query(ctx, `SELECT occurred_at, decision,
	COALESCE((SELECT c->>'reason_code' FROM jsonb_array_elements(checks) c
	          WHERE c->>'reason_code' IS NOT NULL LIMIT 1), '')
	FROM api_authorization_decisions
	WHERE application_id=$1 AND endpoint_key LIKE $2 ESCAPE '\' AND occurred_at>=$3 AND decision<>'ALLOW'
	ORDER BY occurred_at DESC, id LIMIT $4`, applicationID, endpointKeyPattern(endpointKey), since, impactSampleLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ImpactSample{}
	for rows.Next() {
		var smp ImpactSample
		if err := rows.Scan(&smp.OccurredAt, &smp.Decision, &smp.ReasonCode); err != nil {
			return nil, err
		}
		out = append(out, smp)
	}
	return out, rows.Err()
}

// endpointKeys 端点事实（endpoint_id → application_id+endpoint_key；不存在 ErrNotFound）。
func (s *Store) endpointKeys(ctx context.Context, endpointID uuid.UUID) (uuid.UUID, string, error) {
	var appID uuid.UUID
	var key string
	err := s.db.QueryRow(ctx, `SELECT application_id, endpoint_key FROM api_endpoints WHERE id=$1`, endpointID).
		Scan(&appID, &key)
	if err == pgx.ErrNoRows {
		return uuid.Nil, "", ErrNotFound
	}
	return appID, key, err
}

// endpointKeyPattern 端点键族 LIKE 模式：模板键（METHOD + normalized_path，占位段
// {…}）→ LIKE 模式（占位段 → %；字面段转义 LIKE 特殊字符 %_\，ESCAPE '\'）。
// 决策/事件落库的 endpoint_key 是请求路径归一化后的键：纯数字段归一为 {id}
// （恰等于模板键），不可归一对象值保留字面（每值一键）——同端点对应一族键。
func endpointKeyPattern(endpointKey string) string {
	esc := func(seg string) string {
		r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
		return r.Replace(seg)
	}
	parts := strings.Split(endpointKey, "/")
	for i, p := range parts {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			parts[i] = "%"
		} else {
			parts[i] = esc(p)
		}
	}
	return strings.Join(parts, "/")
}

// validateWindow 窗口词表（词表外返回违规描述，空串=合法）。
func validateWindow(days int) string {
	if days < impactWindowMinDays || days > impactWindowMaxDays {
		return fmt.Sprintf("window_days 词表外（%d~%d 天；词表外拒收不夹紧猜义）", impactWindowMinDays, impactWindowMaxDays)
	}
	return ""
}

// selectModelRow 选定评估粒度的对象模型行：恰一行自动选定；多行须显式
// object_segment（§1.3 请求扩展字段——token 绑定粒度=对象模型行，多行不猜义）。
func selectModelRow(rows []ObjectModelRow, segment string) (ObjectModelRow, string) {
	if len(rows) == 0 {
		return ObjectModelRow{}, "端点无对象模型行"
	}
	if segment == "" {
		if len(rows) == 1 {
			return rows[0], ""
		}
		segments := ""
		for i, r := range rows {
			if i > 0 {
				segments += ", "
			}
			segments += r.ObjectSegment
		}
		return ObjectModelRow{}, "端点存在多个对象模型行，须指定 object_segment（候选：" + segments + "）"
	}
	for _, r := range rows {
		if r.ObjectSegment == segment {
			return r, ""
		}
	}
	return ObjectModelRow{}, "object_segment 与端点对象模型行不匹配"
}
