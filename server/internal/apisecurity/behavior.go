// behavior.go 行为基线画像只读接口（WDSP 三微模型第二批，访问微模型）。
// 数据源 api_behavior_profiles：由 aggregations 离线画像任务从 api_runtime_events
// 聚合写入（aggregations/behavior.go），本文件只做管理面查询，无任何写入口。
package apisecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/response"
)

// BehaviorProfile 行为基线画像（api_behavior_profiles；endpoint × identity × window 一行）。
// IdentityFingerprint 空串表示端点级聚合行；StatusCodeDist/HourDist 为分布 JSON
// （状态码 2xx/4xx/5xx/unknown 计数、UTC 小时桶 "0"-"23" 计数）。
type BehaviorProfile struct {
	ID                  uuid.UUID       `json:"id"`
	EndpointID          uuid.UUID       `json:"endpoint_id"`
	EndpointKey         string          `json:"endpoint_key"`                 // LEFT JOIN api_endpoints 带出；端点已删除时为空
	ApplicationName     string          `json:"application_name,omitempty"`   // LEFT JOIN applications 带出；未归属为空
	ApplicationDomain   string          `json:"application_domain,omitempty"` // 主域名（application_domains 主记录）
	IdentityFingerprint string          `json:"identity_fingerprint"`
	WindowSeconds       int             `json:"window_seconds"`
	RequestCount        int64           `json:"request_count"`
	AvgRate             float64         `json:"avg_rate"`
	StatusCodeDist      json.RawMessage `json:"status_code_dist"`
	HourDist            json.RawMessage `json:"hour_dist"`
	UpdatedAt           time.Time       `json:"updated_at"`
}

// ListBehaviorProfiles 画像分页列表（过滤 endpoint_id/identity_fingerprint/application_id，
// 风格同 ListRuntimeEvents）。endpoint_id/application_id 非法 UUID 视为无匹配返回空集
// （同 ListViolations 纪律）；identity_fingerprint 精确匹配，空串不过滤。
func (s *Store) ListBehaviorProfiles(ctx context.Context, endpointID, identityFingerprint, applicationID string, page, pageSize int) ([]BehaviorProfile, int64, error) {
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
			return []BehaviorProfile{}, 0, nil
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
			return []BehaviorProfile{}, 0, nil
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
FROM api_behavior_profiles p
LEFT JOIN api_endpoints e ON e.id = p.endpoint_id
LEFT JOIN applications a ON a.id = e.application_id`
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) "+joins+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `
SELECT p.id, p.endpoint_id, COALESCE(e.endpoint_key, ''), COALESCE(a.name, ''),
       COALESCE((SELECT d.hostname FROM application_domains d
         WHERE d.application_id = a.id ORDER BY d.is_primary DESC, d.created_at LIMIT 1), ''),
       p.identity_fingerprint, p.window_seconds,
       p.request_count, p.avg_rate, p.status_code_dist, p.hour_dist, p.updated_at`+joins+cond+
		fmt.Sprintf(" ORDER BY p.updated_at DESC, p.id LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []BehaviorProfile{}
	for rows.Next() {
		var p BehaviorProfile
		if err := rows.Scan(&p.ID, &p.EndpointID, &p.EndpointKey, &p.ApplicationName, &p.ApplicationDomain,
			&p.IdentityFingerprint, &p.WindowSeconds,
			&p.RequestCount, &p.AvgRate, &p.StatusCodeDist, &p.HourDist, &p.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	return out, total, rows.Err()
}

// ListBehaviorProfiles GET /api/v1/api-security/behavior-profiles
// 查询参数：endpoint_id / identity_fingerprint / application_id / page / page_size。
func (h *Handler) ListBehaviorProfiles(w http.ResponseWriter, r *http.Request) {
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
	list, total, err := h.store.ListBehaviorProfiles(r.Context(), endpointID,
		strings.TrimSpace(q.Get("identity_fingerprint")),
		applicationID,
		page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}
