// runtime.go 任务书 51.6：风险发现 / Schema 违例 / 安全态势 / 运行时统计与事件。
package apisecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RuntimeFinding 运行时发现（api_runtime_findings）。
type RuntimeFinding struct {
	ID          uuid.UUID       `json:"id"`
	EndpointID  *uuid.UUID      `json:"endpoint_id,omitempty"`
	RequestID   string          `json:"request_id"`
	FindingType string          `json:"finding_type"`
	Severity    string          `json:"severity"`
	Status      string          `json:"status"`
	Title       string          `json:"title"`
	Detail      json.RawMessage `json:"detail"`
	FirstSeenAt time.Time       `json:"first_seen_at"`
	LastSeenAt  time.Time       `json:"last_seen_at"`
	CreatedAt   time.Time       `json:"created_at"`
}

// ListFindings 风险发现分页列表（过滤 finding_type/severity/status）。
func (s *Store) ListFindings(ctx context.Context, findingType, severity, status string, page, pageSize int) ([]RuntimeFinding, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	// 过滤条件按白名单字段拼接，值一律参数化
	where := []string{}
	args := []any{}
	if findingType != "" {
		args = append(args, findingType)
		where = append(where, fmt.Sprintf("finding_type = $%d", len(args)))
	}
	if severity != "" {
		args = append(args, severity)
		where = append(where, fmt.Sprintf("severity = $%d", len(args)))
	}
	if status != "" {
		args = append(args, status)
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_runtime_findings"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `
SELECT id, endpoint_id, request_id, finding_type, severity, status, title, detail, first_seen_at, last_seen_at, created_at
FROM api_runtime_findings`+cond+fmt.Sprintf(" ORDER BY last_seen_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []RuntimeFinding{}
	for rows.Next() {
		var f RuntimeFinding
		if err := rows.Scan(&f.ID, &f.EndpointID, &f.RequestID, &f.FindingType, &f.Severity, &f.Status,
			&f.Title, &f.Detail, &f.FirstSeenAt, &f.LastSeenAt, &f.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, f)
	}
	return out, total, rows.Err()
}

// SchemaViolation Schema 违例记录（api_schema_violations）。
type SchemaViolation struct {
	ID             uuid.UUID  `json:"id"`
	EndpointID     *uuid.UUID `json:"endpoint_id,omitempty"`
	ModelVersionID *uuid.UUID `json:"model_version_id,omitempty"`
	RequestID      string     `json:"request_id"`
	ViolationType  string     `json:"violation_type"`
	FieldPath      string     `json:"field_path"`
	Expected       string     `json:"expected"`
	Observed       string     `json:"observed"`
	ActionTaken    string     `json:"action_taken"`
	OccurredAt     time.Time  `json:"occurred_at"`
}

// ListViolations Schema 违例分页列表（过滤 endpoint_id/violation_type）。
func (s *Store) ListViolations(ctx context.Context, endpointID, violationType string, page, pageSize int) ([]SchemaViolation, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	where := []string{}
	args := []any{}
	if endpointID != "" {
		id, err := uuid.Parse(endpointID)
		if err != nil {
			// 非法 UUID 直接视为无匹配（交由 HTTP 层 400 亦可，此处返回空集）
			return []SchemaViolation{}, 0, nil
		}
		args = append(args, id)
		where = append(where, fmt.Sprintf("endpoint_id = $%d", len(args)))
	}
	if violationType != "" {
		args = append(args, violationType)
		where = append(where, fmt.Sprintf("violation_type = $%d", len(args)))
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_schema_violations"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `
SELECT id, endpoint_id, model_version_id, request_id, violation_type, field_path, expected, observed, action_taken, occurred_at
FROM api_schema_violations`+cond+fmt.Sprintf(" ORDER BY occurred_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []SchemaViolation{}
	for rows.Next() {
		var v SchemaViolation
		if err := rows.Scan(&v.ID, &v.EndpointID, &v.ModelVersionID, &v.RequestID, &v.ViolationType,
			&v.FieldPath, &v.Expected, &v.Observed, &v.ActionTaken, &v.OccurredAt); err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}

// ---------- 安全态势 ----------

// EndpointPosture 端点维度态势。
type EndpointPosture struct {
	Total            int64          `json:"total"`
	ByAssetStatus    map[string]int `json:"by_asset_status"`
	ByLearningStatus map[string]int `json:"by_learning_status"`
}

// FindingPosture 风险发现维度态势。
type FindingPosture struct {
	OpenTotal      int64          `json:"open_total"`
	OpenBySeverity map[string]int `json:"open_by_severity"`
}

// Posture API 安全态势聚合。
type Posture struct {
	Endpoints          EndpointPosture `json:"endpoints"`
	Findings           FindingPosture  `json:"findings"`
	LearningCoverage   float64         `json:"learning_coverage"`   // LEARNED 端点占比（0-1）
	LearningCovered    int64           `json:"learning_covered"`    // LEARNED 端点数
	ModelFreezeRate    float64         `json:"model_freeze_rate"`   // FORMAL 模型版本占比（0-1）
	ModelVersionTotal  int64           `json:"model_version_total"` // 模型版本总数
	ModelVersionFrozen int64           `json:"model_version_frozen"`
}

// GetPosture 聚合端点/发现/学习覆盖率/模型冻结率。
func (s *Store) GetPosture(ctx context.Context) (*Posture, error) {
	p := &Posture{
		Endpoints: EndpointPosture{
			ByAssetStatus:    map[string]int{},
			ByLearningStatus: map[string]int{},
		},
		Findings: FindingPosture{OpenBySeverity: map[string]int{}},
	}
	// 端点：按 asset_status / learning_status 计数
	rows, err := s.db.Query(ctx, `SELECT asset_status, count(*) FROM api_endpoints GROUP BY asset_status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var c int
		if err := rows.Scan(&k, &c); err != nil {
			return nil, err
		}
		p.Endpoints.ByAssetStatus[k] = c
		p.Endpoints.Total += int64(c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows2, err := s.db.Query(ctx, `SELECT learning_status, count(*) FROM api_endpoints GROUP BY learning_status`)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var k string
		var c int
		if err := rows2.Scan(&k, &c); err != nil {
			return nil, err
		}
		p.Endpoints.ByLearningStatus[k] = c
		if k == "LEARNED" {
			p.LearningCovered = int64(c)
		}
	}
	if err := rows2.Err(); err != nil {
		return nil, err
	}

	// 风险发现：OPEN 状态按 severity 计数
	rows3, err := s.db.Query(ctx, `SELECT severity, count(*) FROM api_runtime_findings WHERE status = 'OPEN' GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	defer rows3.Close()
	for rows3.Next() {
		var k string
		var c int
		if err := rows3.Scan(&k, &c); err != nil {
			return nil, err
		}
		p.Findings.OpenBySeverity[k] = c
		p.Findings.OpenTotal += int64(c)
	}
	if err := rows3.Err(); err != nil {
		return nil, err
	}

	// 学习覆盖率 = LEARNED 端点 / 端点总数
	if p.Endpoints.Total > 0 {
		p.LearningCoverage = round4(float64(p.LearningCovered) / float64(p.Endpoints.Total))
	}

	// 模型冻结率 = FORMAL（已确认冻结为正式）版本 / 版本总数
	if err := s.db.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE status = 'FORMAL') FROM api_model_versions`).
		Scan(&p.ModelVersionTotal, &p.ModelVersionFrozen); err != nil {
		return nil, err
	}
	if p.ModelVersionTotal > 0 {
		p.ModelFreezeRate = round4(float64(p.ModelVersionFrozen) / float64(p.ModelVersionTotal))
	}
	return p, nil
}

// round4 保留 4 位小数，避免浮点长尾。
func round4(v float64) float64 { return float64(int(v*10000+0.5)) / 10000 }

// ---------- 运行时统计 / 事件（api_runtime_events，000016） ----------

// EndpointEventCount Top 端点事件计数。
type EndpointEventCount struct {
	EndpointKey string `json:"endpoint_key"`
	Count       int64  `json:"count"`
}

// RuntimeStatistics 运行时事件统计。
type RuntimeStatistics struct {
	Total         int64                `json:"total"`
	ByFinalAction map[string]int       `json:"by_final_action"`
	ByRiskLevel   map[string]int       `json:"by_risk_level"`
	TopEndpoints  []EndpointEventCount `json:"top_endpoints"`
}

// GetRuntimeStatistics 总量 + final_action/risk_level 分布 + Top10 端点。
func (s *Store) GetRuntimeStatistics(ctx context.Context) (*RuntimeStatistics, error) {
	st := &RuntimeStatistics{
		ByFinalAction: map[string]int{},
		ByRiskLevel:   map[string]int{},
		TopEndpoints:  []EndpointEventCount{},
	}
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_runtime_events`).Scan(&st.Total); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT final_action, count(*) FROM api_runtime_events GROUP BY final_action`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var c int
		if err := rows.Scan(&k, &c); err != nil {
			return nil, err
		}
		st.ByFinalAction[k] = c
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows2, err := s.db.Query(ctx, `SELECT risk_level, count(*) FROM api_runtime_events GROUP BY risk_level`)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var k string
		var c int
		if err := rows2.Scan(&k, &c); err != nil {
			return nil, err
		}
		st.ByRiskLevel[k] = c
	}
	if err := rows2.Err(); err != nil {
		return nil, err
	}

	rows3, err := s.db.Query(ctx, `
SELECT endpoint_key, count(*) AS c FROM api_runtime_events
WHERE endpoint_key <> '' GROUP BY endpoint_key ORDER BY c DESC, endpoint_key LIMIT 10`)
	if err != nil {
		return nil, err
	}
	defer rows3.Close()
	for rows3.Next() {
		var it EndpointEventCount
		if err := rows3.Scan(&it.EndpointKey, &it.Count); err != nil {
			return nil, err
		}
		st.TopEndpoints = append(st.TopEndpoints, it)
	}
	return st, rows3.Err()
}

// RuntimeEvent 运行时主事件（api_runtime_events）。
type RuntimeEvent struct {
	ID          uuid.UUID       `json:"id"`
	RequestID   string          `json:"request_id"`
	EndpointKey string          `json:"endpoint_key"`
	RiskScore   int             `json:"risk_score"`
	RiskLevel   string          `json:"risk_level"`
	FinalAction string          `json:"final_action"`
	Details     json.RawMessage `json:"details"`
	OccurredAt  time.Time       `json:"occurred_at"`
}

// ListRuntimeEvents 运行时事件分页列表（过滤 endpoint_key/final_action）。
func (s *Store) ListRuntimeEvents(ctx context.Context, endpointKey, finalAction string, page, pageSize int) ([]RuntimeEvent, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	where := []string{}
	args := []any{}
	if endpointKey != "" {
		args = append(args, endpointKey)
		where = append(where, fmt.Sprintf("endpoint_key = $%d", len(args)))
	}
	if finalAction != "" {
		args = append(args, finalAction)
		where = append(where, fmt.Sprintf("final_action = $%d", len(args)))
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_runtime_events"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `
SELECT id, request_id, endpoint_key, risk_score, risk_level, final_action, details_json, occurred_at
FROM api_runtime_events`+cond+fmt.Sprintf(" ORDER BY occurred_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []RuntimeEvent{}
	for rows.Next() {
		var ev RuntimeEvent
		if err := rows.Scan(&ev.ID, &ev.RequestID, &ev.EndpointKey, &ev.RiskScore,
			&ev.RiskLevel, &ev.FinalAction, &ev.Details, &ev.OccurredAt); err != nil {
			return nil, 0, err
		}
		out = append(out, ev)
	}
	return out, total, rows.Err()
}
