// runtime.go 任务书 51.6：风险发现 / Schema 违例 / 安全态势 / 运行时统计与事件。
package apisecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apigeo"
)

// RuntimeFinding 运行时发现（api_runtime_findings）。
type RuntimeFinding struct {
	ID         uuid.UUID  `json:"id"`
	EndpointID *uuid.UUID `json:"endpoint_id,omitempty"`
	// EndpointKey 关联端点的「METHOD 路径模板」，LEFT JOIN api_endpoints 带出；端点已删除或未匹配时为空
	EndpointKey string          `json:"endpoint_key"`
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
		where = append(where, fmt.Sprintf("f.finding_type = $%d", len(args)))
	}
	if severity != "" {
		args = append(args, severity)
		where = append(where, fmt.Sprintf("f.severity = $%d", len(args)))
	}
	if status != "" {
		args = append(args, status)
		where = append(where, fmt.Sprintf("f.status = $%d", len(args)))
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_runtime_findings f"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `
SELECT f.id, f.endpoint_id, COALESCE(e.endpoint_key, ''), f.request_id, f.finding_type, f.severity, f.status, f.title, f.detail, f.first_seen_at, f.last_seen_at, f.created_at
FROM api_runtime_findings f
LEFT JOIN api_endpoints e ON e.id = f.endpoint_id`+cond+fmt.Sprintf(" ORDER BY f.last_seen_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []RuntimeFinding{}
	for rows.Next() {
		var f RuntimeFinding
		if err := rows.Scan(&f.ID, &f.EndpointID, &f.EndpointKey, &f.RequestID, &f.FindingType, &f.Severity, &f.Status,
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

// ListViolations Schema 违例分页列表（过滤 endpoint_id/violation_type/start_time/end_time）。
func (s *Store) ListViolations(ctx context.Context, endpointID, violationType string, startTime, endTime *time.Time, page, pageSize int) ([]SchemaViolation, int64, error) {
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
	if startTime != nil {
		args = append(args, startTime.UTC())
		where = append(where, fmt.Sprintf("occurred_at >= $%d", len(args)))
	}
	if endTime != nil {
		args = append(args, endTime.UTC())
		where = append(where, fmt.Sprintf("occurred_at <= $%d", len(args)))
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
// 000042 七态词表后「未闭环」口径为活动状态 NEW/CONFIRMED/IN_PROGRESS
// （字段名 open_* 为既有 API 契约，保持不变）。
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

	// 风险发现：活动状态（NEW/CONFIRMED/IN_PROGRESS，000042 七态词表）按 severity 计数
	rows3, err := s.db.Query(ctx, `SELECT severity, count(*) FROM api_runtime_findings WHERE status IN ('NEW','CONFIRMED','IN_PROGRESS') GROUP BY severity`)
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

// ---------- W9-P101 态势总览与按天趋势（任务书 §6 态势） ----------

// postureProtectedActions 防护量口径：实际处置动作（BLOCK/TEMP_BLOCK/RATE_LIMIT/MASK_RESPONSE，
// 词表见 gateway/dynamic_security/context FinalAction）；ALLOW/OBSERVE 等观察性动作不计入。
// CHALLENGE（Bot 挑战）刻意不计入防护量也不计入业务成功——挑战是中间态处置，
// 单独统计（BOT-022），避免与攻击拦截混算。
const postureProtectedActions = "('BLOCK','TEMP_BLOCK','RATE_LIMIT','MASK_RESPONSE')"

// PostureOverview 顶部核心指标（GET /posture/overview，口径逐字段注明）。
type PostureOverview struct {
	GeneratedAt time.Time `json:"generated_at"`
	// API 访问量：近 24h 全量请求（api_endpoint_traffic_buckets 端点×5分钟桶求和；
	// 桶留存 7 天、由采集器对全量请求计数，见迁移 000034，api_runtime_events 只落 notable 记录故不作访问量源）
	Traffic24h int64 `json:"traffic_24h"`
	// 防护量：近 24h 处置动作事件数（api_runtime_events.final_action ∈ postureProtectedActions）
	Protected24h int64 `json:"protected_24h"`
	// 资产总数：api_endpoints 全量（含 IGNORED，与 GetPosture endpoints.total 同口径）
	AssetsTotal int64 `json:"assets_total"`
	// 新增 API：近 24h 新建端点（api_endpoints.created_at）
	AssetsNew24h int64 `json:"assets_new_24h"`
	// Shadow：finding_type=SHADOW 且未闭环（NEW/CONFIRMED/IN_PROGRESS，
	// 000042 七态词表，与 GetPosture findings open 口径一致）
	ShadowOpen int64 `json:"shadow_open"`
	// Zombie：asset_status=ZOMBIE（000045 生命周期词表：DEPRECATED 后仍有流量判定）
	ZombieTotal int64 `json:"zombie_total"`
	// Deprecated：asset_status=DEPRECATED
	DeprecatedTotal int64 `json:"deprecated_total"`
	// 涉敏 API：api_sensitive_fields 去重端点数（REQUEST/RESPONSE 双向合并去重）
	SensitiveEndpoints int64 `json:"sensitive_endpoints"`
	// 高风险 API：asset_value ∈ HIGH/CRITICAL（000045 资产价值评分；未评分 NULL 不计）
	HighRiskAssets int64 `json:"high_risk_assets"`
	// 无认证 API：从未观测到带认证类型（auth_type 非空）身份画像的端点
	// （画像来自 api_identity_profiles 离线聚合；无画像或画像 auth_type 全空即无认证观测）
	UnauthenticatedEndpoints int64 `json:"unauthenticated_endpoints"`
	// 待确认模型：api_model_versions status ∈ CANDIDATE/IN_REVIEW
	// （同 metrics.APICandidatesCreated「未确认在途」口径）
	ModelsPending int64 `json:"models_pending"`
	// 运行时 Schema 偏离：近 24h api_schema_violations
	SchemaDeviations24h int64 `json:"schema_deviations_24h"`
}

// GetPostureOverview 聚合顶部核心指标（常数个聚合查询，无 N+1；不改动既有 GetPosture 契约）。
func (s *Store) GetPostureOverview(ctx context.Context) (*PostureOverview, error) {
	o := &PostureOverview{}
	now := time.Now().UTC()
	o.GeneratedAt = now
	since := now.Add(-24 * time.Hour)

	// 访问量（近 24h 流量桶求和）
	if err := s.db.QueryRow(ctx, `
SELECT COALESCE(sum(request_count), 0) FROM api_endpoint_traffic_buckets WHERE bucket_start >= $1`, since).
		Scan(&o.Traffic24h); err != nil {
		return nil, err
	}
	// 防护量（近 24h 处置动作事件）
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM api_runtime_events
WHERE occurred_at >= $1 AND final_action IN `+postureProtectedActions, since).
		Scan(&o.Protected24h); err != nil {
		return nil, err
	}
	// 端点资产单次扫描：总数 / 近24h新增 / Zombie / Deprecated / 高风险
	if err := s.db.QueryRow(ctx, `
SELECT count(*),
       count(*) FILTER (WHERE created_at >= $1),
       count(*) FILTER (WHERE asset_status = 'ZOMBIE'),
       count(*) FILTER (WHERE asset_status = 'DEPRECATED'),
       count(*) FILTER (WHERE asset_value IN ('HIGH','CRITICAL'))
FROM api_endpoints`, since).
		Scan(&o.AssetsTotal, &o.AssetsNew24h, &o.ZombieTotal, &o.DeprecatedTotal, &o.HighRiskAssets); err != nil {
		return nil, err
	}
	// Shadow（未闭环）
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM api_runtime_findings
WHERE finding_type = 'SHADOW' AND status IN ('NEW','CONFIRMED','IN_PROGRESS')`).
		Scan(&o.ShadowOpen); err != nil {
		return nil, err
	}
	// 涉敏端点（去重）
	if err := s.db.QueryRow(ctx, `
SELECT count(DISTINCT endpoint_id) FROM api_sensitive_fields`).Scan(&o.SensitiveEndpoints); err != nil {
		return nil, err
	}
	// 无认证端点：不存在 auth_type 非空的身份画像
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM api_endpoints e
WHERE NOT EXISTS (
    SELECT 1 FROM api_identity_profiles p
    WHERE p.endpoint_id = e.id AND p.auth_type <> '')`).Scan(&o.UnauthenticatedEndpoints); err != nil {
		return nil, err
	}
	// 待确认模型版本
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM api_model_versions WHERE status IN ('CANDIDATE','IN_REVIEW')`).Scan(&o.ModelsPending); err != nil {
		return nil, err
	}
	// 近 24h Schema 偏离
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM api_schema_violations WHERE occurred_at >= $1`, since).Scan(&o.SchemaDeviations24h); err != nil {
		return nil, err
	}
	return o, nil
}

// PostureTrendPoint 单日趋势点（Date 为 UTC 日界，YYYY-MM-DD）。
type PostureTrendPoint struct {
	Date string `json:"date"`
	// 访问量：流量桶当日求和（留存 7 天，days>7 时更早日期如实为 0）
	Traffic   int64 `json:"traffic"`
	Protected int64 `json:"protected"`
	// 风险：findings 当日新增（created_at）
	Risk int64 `json:"risk"`
	// 新增 API：端点当日新建（created_at）
	NewEndpoints int64 `json:"new_endpoints"`
	// Schema 偏离：违例当日发生（occurred_at）
	SchemaDeviations int64 `json:"schema_deviations"`
	// 敏感数据命中：details_json 含 detector=sensitive_data 明细的事件当日计数
	SensitiveHits int64 `json:"sensitive_hits"`
}

// PostureTrends 按天桶趋势（GET /posture/trends?days=N）。
type PostureTrends struct {
	Days   int                 `json:"days"`
	Points []PostureTrendPoint `json:"points"`
}

// postureDayAgg 执行「SELECT 日, 计数 ... GROUP BY 日」聚合查询并返回 日期→计数 映射
// （日界统一 UTC：timestamptz AT TIME ZONE 'UTC' 后取 date，扫描为 time.Time 再格式化键）。
func (s *Store) postureDayAgg(ctx context.Context, query string, since time.Time) (map[string]int64, error) {
	rows, err := s.db.Query(ctx, query, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var d time.Time
		var n int64
		if err := rows.Scan(&d, &n); err != nil {
			return nil, err
		}
		out[d.UTC().Format("2006-01-02")] = n
	}
	return out, rows.Err()
}

// GetPostureTrends 按天聚合访问/防护/风险/新增/Schema偏离/敏感命中六条曲线，
// 服务端补零为连续 days 天点列（含今天；days 由 HTTP 层校验 1-30，此处防御性兜底）。
func (s *Store) GetPostureTrends(ctx context.Context, days int) (*PostureTrends, error) {
	if days < 1 || days > 30 {
		days = 7
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	start := today.AddDate(0, 0, -(days - 1))

	traffic, err := s.postureDayAgg(ctx, `
SELECT (bucket_start AT TIME ZONE 'UTC')::date AS d, sum(request_count)
FROM api_endpoint_traffic_buckets WHERE bucket_start >= $1 GROUP BY d`, start)
	if err != nil {
		return nil, err
	}
	// 防护量与敏感命中同次事件扫描（details_json 可能为 JSON null，jsonb_array_elements 前 typeof 守卫）
	protected := map[string]int64{}
	sensitive := map[string]int64{}
	rows, err := s.db.Query(ctx, `
SELECT (occurred_at AT TIME ZONE 'UTC')::date AS d,
       count(*) FILTER (WHERE final_action IN `+postureProtectedActions+`),
       count(*) FILTER (WHERE jsonb_typeof(details_json) = 'array' AND EXISTS (
           SELECT 1 FROM jsonb_array_elements(details_json) m WHERE m->>'detector' = 'sensitive_data'))
FROM api_runtime_events WHERE occurred_at >= $1 GROUP BY d`, start)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var d time.Time
		var p, sen int64
		if err := rows.Scan(&d, &p, &sen); err != nil {
			rows.Close()
			return nil, err
		}
		key := d.UTC().Format("2006-01-02")
		protected[key] = p
		sensitive[key] = sen
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	risk, err := s.postureDayAgg(ctx, `
SELECT (created_at AT TIME ZONE 'UTC')::date AS d, count(*)
FROM api_runtime_findings WHERE created_at >= $1 GROUP BY d`, start)
	if err != nil {
		return nil, err
	}
	newEndpoints, err := s.postureDayAgg(ctx, `
SELECT (created_at AT TIME ZONE 'UTC')::date AS d, count(*)
FROM api_endpoints WHERE created_at >= $1 GROUP BY d`, start)
	if err != nil {
		return nil, err
	}
	deviations, err := s.postureDayAgg(ctx, `
SELECT (occurred_at AT TIME ZONE 'UTC')::date AS d, count(*)
FROM api_schema_violations WHERE occurred_at >= $1 GROUP BY d`, start)
	if err != nil {
		return nil, err
	}

	out := &PostureTrends{Days: days, Points: make([]PostureTrendPoint, 0, days)}
	for d := start; !d.After(today); d = d.AddDate(0, 0, 1) {
		key := d.Format("2006-01-02")
		out.Points = append(out.Points, PostureTrendPoint{
			Date:             key,
			Traffic:          traffic[key],
			Protected:        protected[key],
			Risk:             risk[key],
			NewEndpoints:     newEndpoints[key],
			SchemaDeviations: deviations[key],
			SensitiveHits:    sensitive[key],
		})
	}
	return out, nil
}

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
	ID                  uuid.UUID       `json:"id"`
	RequestID           string          `json:"request_id"`
	EndpointKey         string          `json:"endpoint_key"`
	RiskScore           int             `json:"risk_score"`
	RiskLevel           string          `json:"risk_level"`
	FinalAction         string          `json:"final_action"`
	Details             json.RawMessage `json:"details"`
	OccurredAt          time.Time       `json:"occurred_at"`
	IdentityFingerprint string          `json:"identity_fingerprint"`
	AuthType            string          `json:"auth_type"`
	// 以下为请求级审计补全列（000030/000035 迁移新增；旧版网关事件为 NULL）
	ResponseStatus *int    `json:"response_status,omitempty"`
	ClientIP       *string `json:"client_ip,omitempty"`
	Method         *string `json:"method,omitempty"`
	RawPath        *string `json:"raw_path,omitempty"`
	LatencyMs      *int64  `json:"latency_ms,omitempty"`
	ModelVersion   *string `json:"model_version,omitempty"`
	PolicyVersion  *string `json:"policy_version,omitempty"`
	// JWTVerification JWT 信任链验证摘要（WDSP P0-03，迁移 000127；JSONB 可空列原文透传，
	// 内容为网关 dynamic_security/events.JWTVerification：status/reason_code/policy_version/
	// issuer_config_id/keyset_version/verified_principal_id/verified_tenant_id/evaluated_at）。
	// 网关未上报或请求未经 jwt_trust 范围评估时为 NULL，历史事件不回填；消费端必须容忍缺失。
	JWTVerification json.RawMessage `json:"jwt_verification,omitempty"`
	// FinalDecision 请求最终处置上下文（WDSP P0-04，迁移 000131；JSONB 可空列原文透传，
	// final_decision JSON schema_version=1——completion_status/security_action/
	// executor_module/response_source/steps/matched_exceptions 等，契约
	// S4_DESIGN_BASELINE §2）。网关未上报或处置事实未确定时为 NULL，历史事件不回填；
	// 消费端必须容忍缺失。
	FinalDecision json.RawMessage `json:"final_decision,omitempty"`
}

// ListRuntimeEvents 运行时事件分页列表（过滤 endpoint_key/final_action/identity_fingerprint）。
// identity_fingerprint 精确匹配，空串不过滤（匿名事件指纹为空串，不参与过滤）。
func (s *Store) ListRuntimeEvents(ctx context.Context, endpointKey, finalAction, identityFingerprint string, page, pageSize int) ([]RuntimeEvent, int64, error) {
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
	if identityFingerprint != "" {
		args = append(args, identityFingerprint)
		where = append(where, fmt.Sprintf("identity_fingerprint = $%d", len(args)))
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
SELECT id, request_id, endpoint_key, risk_score, risk_level, final_action, details_json, occurred_at, identity_fingerprint, auth_type,
       response_status, client_ip, method, raw_path, latency_ms, model_version, policy_version, jwt_verification, final_decision
FROM api_runtime_events`+cond+fmt.Sprintf(" ORDER BY occurred_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []RuntimeEvent{}
	for rows.Next() {
		var ev RuntimeEvent
		// jwt_verification / final_decision 可空（迁移 000127/000131；历史事件 NULL）：
		// 两段式扫描与 apiruntime/events.go List 同口径，NULL 时原始字节为 nil、字段省略
		var jwtRaw, fdRaw []byte
		if err := rows.Scan(&ev.ID, &ev.RequestID, &ev.EndpointKey, &ev.RiskScore,
			&ev.RiskLevel, &ev.FinalAction, &ev.Details, &ev.OccurredAt,
			&ev.IdentityFingerprint, &ev.AuthType,
			&ev.ResponseStatus, &ev.ClientIP, &ev.Method, &ev.RawPath,
			&ev.LatencyMs, &ev.ModelVersion, &ev.PolicyVersion, &jwtRaw, &fdRaw); err != nil {
			return nil, 0, err
		}
		if len(jwtRaw) > 0 {
			ev.JWTVerification = json.RawMessage(jwtRaw)
		}
		if len(fdRaw) > 0 {
			ev.FinalDecision = json.RawMessage(fdRaw)
		}
		out = append(out, ev)
	}
	return out, total, rows.Err()
}

// ---------- W10-SEC 态势访问维度：访问来源与访问目标排名（任务书 §6.4/§6.5 残余） ----------
//
// User-Agent 族维度说明：api_runtime_events 自建表（000016）至今（000029 身份列 /
// 000030 响应状态码 / 000035 审计六列增补后）均无 UA 列，事件落库不携带 UA；
// 按任务书「events 无 UA 列则如实不做该维」纪律，本接口不提供 UA 聚合，待事件审计列
// 扩展 UA 后再补。
//
// 来源聚合口径：api_runtime_events 只落安全相关（notable）事件而非全量请求
// （见 GetPostureOverview 访问量口径注释），故本组 Top 反映「安全事件来源分布」。

const (
	// postureTopLimit 各 Top 榜单条数上限
	postureTopLimit = 10
	// postureGeoIPCap Geo 逐 IP 判定（MMDB 内存查询）的 distinct 客户端 IP 上限，
	// 超出时按事件数截取头部并置 geo_truncated=true 如实标注
	postureGeoIPCap = 1000
	// postureFingerprintPreviewLen 身份指纹截断展示长度（HMAC-SHA256 hex 共 64 字符，仅取前缀便于辨认）
	postureFingerprintPreviewLen = 12
)

// PostureSourceIP 客户端 IP 计数项（IP 已脱敏展示）。
type PostureSourceIP struct {
	ClientIP string `json:"client_ip"`
	Count    int64  `json:"count"`
}

// PostureGeoScope 地域归属分桶计数（HOME/FOREIGN/INTERNAL/UNKNOWN 四桶零补齐）。
type PostureGeoScope struct {
	Scope string `json:"scope"`
	Count int64  `json:"count"`
}

// PostureSourceCountry 国家码计数项（ISO 3166-1 alpha-2，仅 GeoIP 可用时有数据）。
type PostureSourceCountry struct {
	Country string `json:"country"`
	Count   int64  `json:"count"`
}

// PostureSourceIdentity 身份指纹计数项（指纹截断展示；指纹本身即不可逆 HMAC，不落明文凭据）。
type PostureSourceIdentity struct {
	Fingerprint string `json:"fingerprint"`
	Count       int64  `json:"count"`
}

// PostureSourceAuthType 认证类型分布项（auth_type 空串 = 匿名流量，由前端标注「匿名」；
// 词表见迁移 000029：bearer_or_basic / api_key / cookie_session）。
type PostureSourceAuthType struct {
	AuthType string `json:"auth_type"`
	Count    int64  `json:"count"`
}

// PostureSources 访问来源聚合（GET /posture/sources?days=N）。
type PostureSources struct {
	Days int `json:"days"`
	// GeoEnabled GeoIP 数据源是否可用（未装配 lookup 时 false，Geo 维度如实为空；
	// 与数据出境看板 geo_enabled 同一降级语义）
	GeoEnabled bool `json:"geo_enabled"`
	// GeoTruncated distinct 客户端 IP 超 postureGeoIPCap 时截断标注（仅 GeoEnabled 时有意义）
	GeoTruncated  bool                    `json:"geo_truncated"`
	TopClientIPs  []PostureSourceIP       `json:"top_client_ips"`
	GeoScopes     []PostureGeoScope       `json:"geo_scopes"`
	TopCountries  []PostureSourceCountry  `json:"top_countries"`
	TopIdentities []PostureSourceIdentity `json:"top_identities"`
	AuthTypes     []PostureSourceAuthType `json:"auth_types"`
}

// GetPostureSources 访问来源聚合：客户端 IP Top（脱敏）/ 地域分桶与国家 Top（geo 为 nil 或
// 未启用时如实留空）/ 身份指纹 Top（截断）/ 认证类型分布。窗口与 GetPostureTrends 同口径
// （UTC 日界，含今天共 days 天；days 由 HTTP 层校验 1-30，此处防御性兜底）。
func (s *Store) GetPostureSources(ctx context.Context, days int, geo *apigeo.GeoResolver) (*PostureSources, error) {
	if days < 1 || days > 30 {
		days = 7
	}
	start := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -(days - 1))
	out := &PostureSources{
		Days:          days,
		GeoEnabled:    geo.Enabled(), // Enabled 已处理 nil 接收者
		TopClientIPs:  []PostureSourceIP{},
		GeoScopes:     []PostureGeoScope{},
		TopCountries:  []PostureSourceCountry{},
		TopIdentities: []PostureSourceIdentity{},
		AuthTypes:     []PostureSourceAuthType{},
	}

	// 客户端 IP Top（脱敏展示；空串/NULL 为旧版网关未上报，不参与排名）
	rows, err := s.db.Query(ctx, `
SELECT client_ip, count(*) AS c FROM api_runtime_events
WHERE occurred_at >= $1 AND client_ip IS NOT NULL AND client_ip <> ''
GROUP BY client_ip ORDER BY c DESC, client_ip LIMIT 10`, start)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		var it PostureSourceIP
		if err := rows.Scan(&ip, &it.Count); err != nil {
			return nil, err
		}
		it.ClientIP = maskPostureClientIP(ip)
		out.TopClientIPs = append(out.TopClientIPs, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 地域归属分桶 + 国家 Top（复用 apigeo 判定；GeoIP 不可用时整维留空并 geo_enabled=false）
	if out.GeoEnabled {
		scopeCounts, countryCounts, truncated, err := s.postureGeoClassify(ctx, start, geo)
		if err != nil {
			return nil, err
		}
		out.GeoTruncated = truncated
		// 四桶零补齐（INVALID 脏数据已并入 UNKNOWN，见 postureGeoClassify）
		for _, scope := range []apigeo.Scope{apigeo.ScopeHome, apigeo.ScopeForeign, apigeo.ScopeInternal, apigeo.ScopeUnknown} {
			out.GeoScopes = append(out.GeoScopes, PostureGeoScope{Scope: string(scope), Count: scopeCounts[scope]})
		}
		out.TopCountries = postureTopCounts(countryCounts, postureTopLimit,
			func(k string, c int64) PostureSourceCountry { return PostureSourceCountry{Country: k, Count: c} })
	}

	// 身份指纹 Top（匿名空串不参与；截断展示）
	rows2, err := s.db.Query(ctx, `
SELECT identity_fingerprint, count(*) AS c FROM api_runtime_events
WHERE occurred_at >= $1 AND identity_fingerprint <> ''
GROUP BY identity_fingerprint ORDER BY c DESC, identity_fingerprint LIMIT 10`, start)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var fp string
		var it PostureSourceIdentity
		if err := rows2.Scan(&fp, &it.Count); err != nil {
			return nil, err
		}
		it.Fingerprint = truncateFingerprintPreview(fp)
		out.TopIdentities = append(out.TopIdentities, it)
	}
	if err := rows2.Err(); err != nil {
		return nil, err
	}

	// 认证类型分布（含匿名空串，词表稳定小基数，全量返回不截断）
	rows3, err := s.db.Query(ctx, `
SELECT auth_type, count(*) AS c FROM api_runtime_events
WHERE occurred_at >= $1 GROUP BY auth_type ORDER BY c DESC, auth_type`, start)
	if err != nil {
		return nil, err
	}
	defer rows3.Close()
	for rows3.Next() {
		var it PostureSourceAuthType
		if err := rows3.Scan(&it.AuthType, &it.Count); err != nil {
			return nil, err
		}
		out.AuthTypes = append(out.AuthTypes, it)
	}
	return out, rows3.Err()
}

// postureGeoClassify 对窗口内 distinct 客户端 IP 逐一判定归属（事件数降序截取前
// postureGeoIPCap 个，超出截断标注）。返回 分桶计数 / 国家计数 / 是否截断；
// Classify 的 error 仅来自底层数据损坏，如实上抛不逐条吞掉。
func (s *Store) postureGeoClassify(ctx context.Context, start time.Time, geo *apigeo.GeoResolver) (map[apigeo.Scope]int64, map[string]int64, bool, error) {
	var distinct int64
	if err := s.db.QueryRow(ctx, `
SELECT count(DISTINCT client_ip) FROM api_runtime_events
WHERE occurred_at >= $1 AND client_ip IS NOT NULL AND client_ip <> ''`, start).Scan(&distinct); err != nil {
		return nil, nil, false, err
	}
	rows, err := s.db.Query(ctx, `
SELECT client_ip, count(*) AS c FROM api_runtime_events
WHERE occurred_at >= $1 AND client_ip IS NOT NULL AND client_ip <> ''
GROUP BY client_ip ORDER BY c DESC, client_ip LIMIT 1000`, start)
	if err != nil {
		return nil, nil, false, err
	}
	defer rows.Close()
	scopeCounts := map[apigeo.Scope]int64{}
	countryCounts := map[string]int64{}
	for rows.Next() {
		var ip string
		var c int64
		if err := rows.Scan(&ip, &c); err != nil {
			return nil, nil, false, err
		}
		scope, country, err := geo.Classify(ip)
		if err != nil {
			return nil, nil, false, err
		}
		if scope == apigeo.ScopeInvalid {
			scope = apigeo.ScopeUnknown // 脏数据并入未知桶（四桶词表与前端固定展示对齐）
		}
		scopeCounts[scope] += c
		if country != "" {
			countryCounts[country] += c
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, false, err
	}
	return scopeCounts, countryCounts, distinct > postureGeoIPCap, nil
}

// postureTopCounts 国家等 map 计数转 Top-N 有序切片（计数降序、键升序兜底，结果确定）。
func postureTopCounts[T any](counts map[string]int64, n int, wrap func(key string, count int64) T) []T {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	out := []T{}
	for i, k := range keys {
		if i >= n {
			break
		}
		out = append(out, wrap(k, counts[k]))
	}
	return out
}

// maskPostureClientIP 客户端 IP 脱敏展示：IPv4 隐藏末段（1.2.3.*），IPv6 仅保留前 48bit
// 站点前缀（2001:db8:85a3:*），非法输入按脏数据返回 "*"。态势排行展示口径；
// 审计溯源仍走 ListRuntimeEvents 明细（client_ip 明文列）。
func maskPostureClientIP(ip string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "*"
	}
	addr = addr.Unmap()
	if addr.Is4() {
		b := addr.As4()
		return fmt.Sprintf("%d.%d.%d.*", b[0], b[1], b[2])
	}
	parts := strings.Split(addr.String(), ":")
	if len(parts) < 3 {
		return "*"
	}
	return strings.Join(parts[:3], ":") + ":*"
}

// truncateFingerprintPreview 身份指纹截断展示（前缀 + 省略号，防界面过宽且不复原全量）。
func truncateFingerprintPreview(fp string) string {
	if len(fp) <= postureFingerprintPreviewLen {
		return fp
	}
	return fp[:postureFingerprintPreviewLen] + "…"
}

// getSettingString 读取 system_settings 字符串设置（JSONB 存储；无记录回退 def，
// 数据库错误与非字符串值如实报错不静默回退——与 settings.Service.GetStringWithSource 同一纪律）。
func (s *Store) getSettingString(ctx context.Context, group, key, def string) (string, error) {
	var raw []byte
	err := s.db.QueryRow(ctx,
		`SELECT setting_value FROM system_settings WHERE setting_group = $1 AND setting_key = $2`,
		group, key).Scan(&raw)
	if err != nil {
		if isNoRows(err) {
			return def, nil
		}
		return "", err
	}
	var str string
	if err := json.Unmarshal(raw, &str); err != nil {
		return "", fmt.Errorf("system_settings %s.%s 非字符串值: %w", group, key, err)
	}
	return str, nil
}

// PostureTargetTraffic API 访问量 Top 项（流量桶窗口求和；桶留存 7 天，days>7 时更早日期不计）。
type PostureTargetTraffic struct {
	EndpointID   uuid.UUID `json:"endpoint_id"`
	EndpointKey  string    `json:"endpoint_key"`
	RequestCount int64     `json:"request_count"`
}

// PostureTargetFindings API 风险发现 Top 项（窗口内 findings 新增计数）。
type PostureTargetFindings struct {
	EndpointID    uuid.UUID `json:"endpoint_id"`
	EndpointKey   string    `json:"endpoint_key"`
	FindingsCount int64     `json:"findings_count"`
}

// PostureTargetApplication 应用访问量 Top 项（application_id 空 = 未分组端点聚合）。
type PostureTargetApplication struct {
	ApplicationID   *uuid.UUID `json:"application_id,omitempty"`
	ApplicationName string     `json:"application_name"`
	RequestCount    int64      `json:"request_count"`
}

// PostureTargetSensitive 涉敏 API Top 项（api_sensitive_fields 去重端点，按窗口访问量降序）。
type PostureTargetSensitive struct {
	EndpointID      uuid.UUID `json:"endpoint_id"`
	EndpointKey     string    `json:"endpoint_key"`
	RequestCount    int64     `json:"request_count"`
	SensitiveFields int64     `json:"sensitive_fields"`
}

// PostureTargetHighRisk 高风险 API Top 项（asset_value ∈ HIGH/CRITICAL，按窗口访问量降序）。
type PostureTargetHighRisk struct {
	EndpointID   uuid.UUID `json:"endpoint_id"`
	EndpointKey  string    `json:"endpoint_key"`
	AssetValue   string    `json:"asset_value"`
	RequestCount int64     `json:"request_count"`
}

// PostureTargets 访问目标排名（GET /posture/targets?days=N）。
type PostureTargets struct {
	Days            int                        `json:"days"`
	TopByTraffic    []PostureTargetTraffic     `json:"top_by_traffic"`
	TopByFindings   []PostureTargetFindings    `json:"top_by_findings"`
	TopApplications []PostureTargetApplication `json:"top_applications"`
	TopSensitive    []PostureTargetSensitive   `json:"top_sensitive"`
	TopHighRisk     []PostureTargetHighRisk    `json:"top_high_risk"`
}

// postureTrafficWindowSubquery 窗口内端点流量求和子查询（敏感/高风险两榜共用，$1 = 窗口起点）。
const postureTrafficWindowSubquery = `
LEFT JOIN (
    SELECT endpoint_id, sum(request_count) AS reqs FROM api_endpoint_traffic_buckets
    WHERE bucket_start >= $1 GROUP BY endpoint_id
) t ON t.endpoint_id = e.id`

// GetPostureTargets 访问目标排名：API Top（请求量 / 风险发现双口径）、应用 Top、
// 涉敏 API Top、高风险 API Top（asset_value ∈ HIGH/CRITICAL 的窗口访问量）。
// 窗口与 GetPostureTrends 同口径（UTC 日界含今天；days 由 HTTP 层校验 1-30，此处防御性兜底）。
func (s *Store) GetPostureTargets(ctx context.Context, days int) (*PostureTargets, error) {
	if days < 1 || days > 30 {
		days = 7
	}
	start := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -(days - 1))
	out := &PostureTargets{
		Days:            days,
		TopByTraffic:    []PostureTargetTraffic{},
		TopByFindings:   []PostureTargetFindings{},
		TopApplications: []PostureTargetApplication{},
		TopSensitive:    []PostureTargetSensitive{},
		TopHighRisk:     []PostureTargetHighRisk{},
	}

	// API Top · 请求量口径
	rows, err := s.db.Query(ctx, `
SELECT e.id, e.endpoint_key, sum(b.request_count) AS reqs
FROM api_endpoint_traffic_buckets b
JOIN api_endpoints e ON e.id = b.endpoint_id
WHERE b.bucket_start >= $1
GROUP BY e.id, e.endpoint_key ORDER BY reqs DESC, e.endpoint_key LIMIT 10`, start)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var it PostureTargetTraffic
		if err := rows.Scan(&it.EndpointID, &it.EndpointKey, &it.RequestCount); err != nil {
			return nil, err
		}
		out.TopByTraffic = append(out.TopByTraffic, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// API Top · 风险发现口径（findings.endpoint_id 可空，内连接自动剔除未关联端点的发现）
	rows2, err := s.db.Query(ctx, `
SELECT e.id, e.endpoint_key, count(*) AS c
FROM api_runtime_findings f
JOIN api_endpoints e ON e.id = f.endpoint_id
WHERE f.created_at >= $1
GROUP BY e.id, e.endpoint_key ORDER BY c DESC, e.endpoint_key LIMIT 10`, start)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var it PostureTargetFindings
		if err := rows2.Scan(&it.EndpointID, &it.EndpointKey, &it.FindingsCount); err != nil {
			return nil, err
		}
		out.TopByFindings = append(out.TopByFindings, it)
	}
	if err := rows2.Err(); err != nil {
		return nil, err
	}

	// 应用 Top（未分组端点聚合为一行，application_name 空串由前端标注「未分组」）
	rows3, err := s.db.Query(ctx, `
SELECT e.application_id, COALESCE(a.name, '') AS app_name, sum(b.request_count) AS reqs
FROM api_endpoint_traffic_buckets b
JOIN api_endpoints e ON e.id = b.endpoint_id
LEFT JOIN applications a ON a.id = e.application_id
WHERE b.bucket_start >= $1
GROUP BY e.application_id, app_name ORDER BY reqs DESC, app_name LIMIT 10`, start)
	if err != nil {
		return nil, err
	}
	defer rows3.Close()
	for rows3.Next() {
		var it PostureTargetApplication
		if err := rows3.Scan(&it.ApplicationID, &it.ApplicationName, &it.RequestCount); err != nil {
			return nil, err
		}
		out.TopApplications = append(out.TopApplications, it)
	}
	if err := rows3.Err(); err != nil {
		return nil, err
	}

	// 涉敏 API Top（敏感字段数附带展示；窗口无访问量如实为 0）
	rows4, err := s.db.Query(ctx, `
SELECT e.id, e.endpoint_key, COALESCE(t.reqs, 0) AS reqs, s.field_count
FROM (
    SELECT endpoint_id, count(*) AS field_count FROM api_sensitive_fields GROUP BY endpoint_id
) s
JOIN api_endpoints e ON e.id = s.endpoint_id`+postureTrafficWindowSubquery+`
ORDER BY reqs DESC, e.endpoint_key LIMIT 10`, start)
	if err != nil {
		return nil, err
	}
	defer rows4.Close()
	for rows4.Next() {
		var it PostureTargetSensitive
		if err := rows4.Scan(&it.EndpointID, &it.EndpointKey, &it.RequestCount, &it.SensitiveFields); err != nil {
			return nil, err
		}
		out.TopSensitive = append(out.TopSensitive, it)
	}
	if err := rows4.Err(); err != nil {
		return nil, err
	}

	// 高风险 API Top（asset_value ∈ HIGH/CRITICAL；窗口无访问量如实为 0）
	rows5, err := s.db.Query(ctx, `
SELECT e.id, e.endpoint_key, e.asset_value, COALESCE(t.reqs, 0) AS reqs
FROM api_endpoints e`+postureTrafficWindowSubquery+`
WHERE e.asset_value IN ('HIGH','CRITICAL')
ORDER BY reqs DESC, e.endpoint_key LIMIT 10`, start)
	if err != nil {
		return nil, err
	}
	defer rows5.Close()
	for rows5.Next() {
		var it PostureTargetHighRisk
		if err := rows5.Scan(&it.EndpointID, &it.EndpointKey, &it.AssetValue, &it.RequestCount); err != nil {
			return nil, err
		}
		out.TopHighRisk = append(out.TopHighRisk, it)
	}
	return out, rows5.Err()
}
