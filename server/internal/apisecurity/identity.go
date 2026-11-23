// identity.go 身份画像只读 API + 质量分（三微模型身份微模型）。
package apisecurity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jiuzhang-waf/server/internal/response"
)

// IdentityProfile 身份画像行。
type IdentityProfile struct {
	IdentityFingerprint string    `json:"identity_fingerprint"`
	EndpointID          uuid.UUID `json:"endpoint_id"`
	EndpointKey         string    `json:"endpoint_key,omitempty"`
	ApplicationName     string    `json:"application_name,omitempty"`   // LEFT JOIN applications 带出；未归属为空
	ApplicationDomain   string    `json:"application_domain,omitempty"` // 主域名（application_domains 主记录）
	AuthType            string    `json:"auth_type"`
	RequestCount        int64     `json:"request_count"`
	FirstSeenAt         time.Time `json:"first_seen_at"`
	LastSeenAt          time.Time `json:"last_seen_at"`
	QualityScore        int       `json:"quality_score"` // 0-100，越高越“像正常稳定身份”
}

// ListIdentityProfiles 画像分页（过滤 identity_fingerprint / endpoint_id / application_id）。
// endpoint_id/application_id 非法 UUID 视为无匹配返回空集（同 ListBehaviorProfiles 纪律）。
func (s *Store) ListIdentityProfiles(ctx context.Context, endpointID, identityFingerprint, applicationID string, page, pageSize int) ([]IdentityProfile, int64, error) {
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
			return []IdentityProfile{}, 0, nil
		}
		args = append(args, id)
		where = append(where, fmt.Sprintf("p.endpoint_id = $%d", len(args)))
	}
	if identityFingerprint != "" {
		args = append(args, identityFingerprint)
		where = append(where, fmt.Sprintf("p.identity_fingerprint = $%d", len(args)))
	}
	if applicationID != "" {
		id, err := uuid.Parse(applicationID)
		if err != nil {
			return []IdentityProfile{}, 0, nil
		}
		args = append(args, id)
		where = append(where, fmt.Sprintf("e.application_id = $%d", len(args)))
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	// count 与 select 同一 JOIN 形态：application_id 过滤挂在 e 上，count 不能省 JOIN。
	joins := `
FROM api_identity_profiles p
LEFT JOIN api_endpoints e ON e.id = p.endpoint_id
LEFT JOIN applications a ON a.id = e.application_id`
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) "+joins+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `
SELECT p.identity_fingerprint, p.endpoint_id, COALESCE(e.endpoint_key, ''), COALESCE(a.name, ''),
       COALESCE((SELECT d.hostname FROM application_domains d
         WHERE d.application_id = a.id ORDER BY d.is_primary DESC, d.created_at LIMIT 1), ''),
       COALESCE(p.auth_type, ''),
       p.request_count, p.first_seen_at, p.last_seen_at`+joins+cond+
		fmt.Sprintf(" ORDER BY p.last_seen_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []IdentityProfile{}
	for rows.Next() {
		var p IdentityProfile
		if err := rows.Scan(&p.IdentityFingerprint, &p.EndpointID, &p.EndpointKey, &p.ApplicationName,
			&p.ApplicationDomain, &p.AuthType,
			&p.RequestCount, &p.FirstSeenAt, &p.LastSeenAt); err != nil {
			return nil, 0, err
		}
		p.QualityScore = identityQualityScore(p)
		out = append(out, p)
	}
	return out, total, rows.Err()
}

// ListIdentityProfiles GET /api/v1/api-security/identity-profiles
// 查询参数：endpoint_id / identity_fingerprint / application_id / page / page_size。
func (h *Handler) ListIdentityProfiles(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	endpointID := strings.TrimSpace(q.Get("endpoint_id"))
	if endpointID != "" {
		if _, err := uuid.Parse(endpointID); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的接口ID")
			return
		}
	}
	applicationID := strings.TrimSpace(q.Get("application_id"))
	if applicationID != "" {
		if _, err := uuid.Parse(applicationID); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的站点ID")
			return
		}
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListIdentityProfiles(r.Context(),
		endpointID,
		strings.TrimSpace(q.Get("identity_fingerprint")),
		applicationID,
		page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// ---------- 身份画像详情 + 风险评估（GB/T 31509 修订稿 5.2.3/5.3 映射，只产信号不阻断） ----------

// IdentityRiskIndicators 威胁识别指标（威胁频率：数量 / 时间分布 / 严重程度；指南 5.2.3）。
type IdentityRiskIndicators struct {
	EventsTotal        int64 `json:"events_total"`         // 该指纹运行时事件总数
	Events24h          int64 `json:"events_24h"`           // 近 24h 事件数（时间分布密度）
	RiskyEventsTotal   int64 `json:"risky_events_total"`   // 高危事件数（risk_level HIGH/CRITICAL）
	BlockedEventsTotal int64 `json:"blocked_events_total"` // 已被拦截事件数（final_action BLOCK/TEMP_BLOCK，安全措施有效性证据）
	DistinctEndpoints  int64 `json:"distinct_endpoints"`   // 触达端点数
	ActiveDays         int   `json:"active_days"`          // 活跃跨度（首见 → 最近见，天）
	MaxRiskScore       int   `json:"max_risk_score"`       // 历史最高单事件风险分（0-100）
}

// IdentityRiskAssessment 风险评估结果。
// 可能性（likelihood）× 严重程度（severity）经 5×5 风险矩阵定级（指南 5.3.3 定性矩阵法）；
// 已被全部拦截的威胁按指南 5.2.4「已确认有效的安全措施降低威胁利用可能性」将可能性降一档。
type IdentityRiskAssessment struct {
	Level      string                 `json:"level"`      // VERY_LOW / LOW / MEDIUM / HIGH / VERY_HIGH
	Likelihood int                    `json:"likelihood"` // 威胁频率 → 可能性赋值 1-5
	Severity   int                    `json:"severity"`   // 事件严重程度赋值 1-5
	Indicators IdentityRiskIndicators `json:"indicators"`
	Summary    string                 `json:"summary"` // 中文一句话评估结论
}

// IdentityProfileDetail 身份画像详情（GET .../identity-profiles/detail 响应 data）。
type IdentityProfileDetail struct {
	Profile      IdentityProfile        `json:"profile"`
	Risk         IdentityRiskAssessment `json:"risk"`
	RecentEvents []RuntimeEvent         `json:"recent_events"` // 该指纹最近 10 条运行时事件
}

// GetIdentityProfileDetail 画像行 + 威胁指标聚合 + 近期事件；画像不存在返回 ErrNotFound。
func (s *Store) GetIdentityProfileDetail(ctx context.Context, fingerprint, endpointID string) (*IdentityProfileDetail, error) {
	id, err := uuid.Parse(endpointID)
	if err != nil {
		return nil, ErrNotFound
	}
	var p IdentityProfile
	err = s.db.QueryRow(ctx, `
SELECT p.identity_fingerprint, p.endpoint_id, COALESCE(e.endpoint_key, ''), COALESCE(a.name, ''),
       COALESCE((SELECT d.hostname FROM application_domains d
         WHERE d.application_id = a.id ORDER BY d.is_primary DESC, d.created_at LIMIT 1), ''),
       COALESCE(p.auth_type, ''),
       p.request_count, p.first_seen_at, p.last_seen_at
FROM api_identity_profiles p
LEFT JOIN api_endpoints e ON e.id = p.endpoint_id
LEFT JOIN applications a ON a.id = e.application_id
WHERE p.identity_fingerprint=$1 AND p.endpoint_id=$2`, fingerprint, id).Scan(
		&p.IdentityFingerprint, &p.EndpointID, &p.EndpointKey, &p.ApplicationName,
		&p.ApplicationDomain, &p.AuthType,
		&p.RequestCount, &p.FirstSeenAt, &p.LastSeenAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.QualityScore = identityQualityScore(p)

	ind := IdentityRiskIndicators{
		ActiveDays: int(p.LastSeenAt.Sub(p.FirstSeenAt).Hours() / 24),
	}
	// 威胁指标：全部来自该指纹的运行时主事件（跨端点，威胁主体视角）
	if err := s.db.QueryRow(ctx, `
SELECT count(*),
       count(*) FILTER (WHERE occurred_at >= now() - interval '24 hours'),
       count(*) FILTER (WHERE risk_level IN ('HIGH','CRITICAL')),
       count(*) FILTER (WHERE final_action IN ('BLOCK','TEMP_BLOCK')),
       count(DISTINCT endpoint_key),
       COALESCE(max(risk_score), 0)
FROM api_runtime_events WHERE identity_fingerprint=$1`, fingerprint).Scan(
		&ind.EventsTotal, &ind.Events24h, &ind.RiskyEventsTotal,
		&ind.BlockedEventsTotal, &ind.DistinctEndpoints, &ind.MaxRiskScore); err != nil {
		return nil, err
	}

	events, _, err := s.ListRuntimeEvents(ctx, "", "", fingerprint, 1, 10)
	if err != nil {
		return nil, err
	}
	return &IdentityProfileDetail{
		Profile:      p,
		Risk:         assessIdentityRisk(ind),
		RecentEvents: events,
	}, nil
}

// identityLikelihood 威胁频率 → 可能性赋值（1-5，指南 5.2.3 频率识别 + 附录F 赋值分档）。
// 高危事件分档定基线；近 24h 密集（≥20 事件）上调一档；威胁已全数被拦截（安全措施有效证据）下调一档。
func identityLikelihood(ind IdentityRiskIndicators) int {
	var l int
	switch {
	case ind.RiskyEventsTotal >= 50:
		l = 5
	case ind.RiskyEventsTotal >= 10:
		l = 4
	case ind.RiskyEventsTotal >= 3:
		l = 3
	case ind.RiskyEventsTotal >= 1:
		l = 2
	default:
		l = 1
	}
	if ind.Events24h >= 20 && l < 5 {
		l++
	}
	if ind.RiskyEventsTotal > 0 && ind.BlockedEventsTotal >= ind.RiskyEventsTotal && l > 1 {
		l--
	}
	return l
}

// identitySeverity 事件严重程度赋值（1-5）：历史最高单事件风险分分档（0-100 → 五档）。
func identitySeverity(maxRiskScore int) int {
	switch {
	case maxRiskScore >= 80:
		return 5
	case maxRiskScore >= 60:
		return 4
	case maxRiskScore >= 40:
		return 3
	case maxRiskScore >= 20:
		return 2
	default:
		return 1
	}
}

// identityRiskMatrix 5×5 定性风险矩阵（行=可能性，列=严重程度；值 1-5 对应 VERY_LOW…VERY_HIGH）。
var identityRiskMatrix = [5][5]int{
	{1, 1, 2, 2, 3},
	{1, 2, 2, 3, 3},
	{2, 2, 3, 3, 4},
	{2, 3, 3, 4, 4},
	{3, 3, 4, 4, 5},
}

var identityRiskLevelNames = [5]string{"VERY_LOW", "LOW", "MEDIUM", "HIGH", "VERY_HIGH"}

// assessIdentityRisk 可能性 × 严重程度 → 五级风险评价（纯函数，可测）。
func assessIdentityRisk(ind IdentityRiskIndicators) IdentityRiskAssessment {
	l := identityLikelihood(ind)
	sev := identitySeverity(ind.MaxRiskScore)
	level := identityRiskMatrix[l-1][sev-1]
	a := IdentityRiskAssessment{
		Level:      identityRiskLevelNames[level-1],
		Likelihood: l,
		Severity:   sev,
		Indicators: ind,
	}
	a.Summary = fmt.Sprintf("可能性%d级 × 严重程度%d级 → 风险%s；高危事件%d起、已拦截%d起、近24h事件%d起",
		l, sev, a.Level, ind.RiskyEventsTotal, ind.BlockedEventsTotal, ind.Events24h)
	return a
}

// IdentityProfileDetail GET /api/v1/api-security/identity-profiles/detail
// 查询参数：identity_fingerprint（必填）+ endpoint_id（必填，画像按指纹 × 端点定位）。
func (h *Handler) IdentityProfileDetail(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	fingerprint := strings.TrimSpace(q.Get("identity_fingerprint"))
	if fingerprint == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "缺少身份指纹")
		return
	}
	endpointID := strings.TrimSpace(q.Get("endpoint_id"))
	if _, err := uuid.Parse(endpointID); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的接口ID")
		return
	}
	detail, err := h.store.GetIdentityProfileDetail(r.Context(), fingerprint, endpointID)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "身份画像不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, detail)
}

// identityQualityScore 身份质量分（0-100，越高越“像正常稳定身份”，仅用于 SOC 排序）：
// 基础 40 + 认证类型（非空 +15）+ 请求量分档（≥5/10/20/50/100/500/1000 → +4/8/12/17/22/26/30）
// + 存活跨度分档（>1h/6h/24h/72h/168h → +3/6/9/12/15）。
// 分档为对数刻度：新身份在几十请求/小时级存活时即可拉开差距，避免早期全部同分。
func identityQualityScore(p IdentityProfile) int {
	score := 40
	if p.AuthType != "" {
		score += 15
	}
	switch {
	case p.RequestCount >= 1000:
		score += 30
	case p.RequestCount >= 500:
		score += 26
	case p.RequestCount >= 100:
		score += 22
	case p.RequestCount >= 50:
		score += 17
	case p.RequestCount >= 20:
		score += 12
	case p.RequestCount >= 10:
		score += 8
	case p.RequestCount >= 5:
		score += 4
	}
	switch span := p.LastSeenAt.Sub(p.FirstSeenAt); {
	case span > 168*time.Hour:
		score += 15
	case span > 72*time.Hour:
		score += 12
	case span > 24*time.Hour:
		score += 9
	case span > 6*time.Hour:
		score += 6
	case span > time.Hour:
		score += 3
	}
	if score > 100 {
		return 100
	}
	if score < 0 {
		return 0
	}
	return score
}
