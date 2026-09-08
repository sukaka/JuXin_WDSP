// object_models.go 对象模型只读接口（WDSP 三微模型，访问微模型·对象维度）。
// 数据源 api_object_models：由 apiauthz.SweepObjectModelsOnce 扫描 api_runtime_events
// upsert 写入（路径占位段 / Query 对象参数形态），本文件只做管理面查询，无任何写入口。
package apisecurity

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/response"
)

// ObjectModel 对象模型（api_object_models；endpoint × object_segment 一行，BOLA 实体画像）。
// ObjectSegment 键口径："path:<pos>"（0 起段序号）/ "query:<参数名>"；
// ExampleHash 只落观测值 SHA-256 示例哈希（不落明文）；entropy_estimate 列保留 NULL 暂不出参。
type ObjectModel struct {
	ID                uuid.UUID `json:"id"`
	EndpointID        uuid.UUID `json:"endpoint_id"`
	EndpointKey       string    `json:"endpoint_key"`                 // LEFT JOIN api_endpoints 带出；端点已删除时为空
	ApplicationName   string    `json:"application_name,omitempty"`   // LEFT JOIN applications 带出；未归属为空
	ApplicationDomain string    `json:"application_domain,omitempty"` // 主域名（application_domains 主记录）
	ObjectSegment     string    `json:"object_segment"`
	IdentifierType    string    `json:"identifier_type"` // numeric / uuid / hash / mixed / unknown
	ExampleHash       string    `json:"example_hash"`
	SampleCount       int64     `json:"sample_count"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// ListObjectModels 对象模型分页列表（过滤 endpoint_id/object_segment/identifier_type/application_id，
// 风格同 ListBehaviorProfiles）。endpoint_id/application_id 非法 UUID 视为无匹配返回空集
// （同 ListViolations 纪律）；object_segment/identifier_type 精确匹配，空串不过滤。
func (s *Store) ListObjectModels(ctx context.Context, endpointID, segment, identifierType, applicationID string, page, pageSize int) ([]ObjectModel, int64, error) {
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
			return []ObjectModel{}, 0, nil
		}
		args = append(args, id)
		where = append(where, fmt.Sprintf("m.endpoint_id = $%d", len(args)))
	}
	if segment != "" {
		args = append(args, segment)
		where = append(where, fmt.Sprintf("m.object_segment = $%d", len(args)))
	}
	if identifierType != "" {
		args = append(args, identifierType)
		where = append(where, fmt.Sprintf("m.identifier_type = $%d", len(args)))
	}
	if applicationID != "" {
		id, err := uuid.Parse(applicationID)
		if err != nil {
			return []ObjectModel{}, 0, nil
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
FROM api_object_models m
LEFT JOIN api_endpoints e ON e.id = m.endpoint_id
LEFT JOIN applications a ON a.id = e.application_id`
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) "+joins+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `
SELECT m.id, m.endpoint_id, COALESCE(e.endpoint_key, ''), COALESCE(a.name, ''),
       COALESCE((SELECT d.hostname FROM application_domains d
         WHERE d.application_id = a.id ORDER BY d.is_primary DESC, d.created_at LIMIT 1), ''),
       m.object_segment, m.identifier_type,
       m.example_hash, m.sample_count, m.first_seen, m.last_seen, m.updated_at`+joins+cond+
		fmt.Sprintf(" ORDER BY m.last_seen DESC, m.id LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []ObjectModel{}
	for rows.Next() {
		var m ObjectModel
		if err := rows.Scan(&m.ID, &m.EndpointID, &m.EndpointKey, &m.ApplicationName, &m.ApplicationDomain,
			&m.ObjectSegment, &m.IdentifierType,
			&m.ExampleHash, &m.SampleCount, &m.FirstSeen, &m.LastSeen, &m.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, m)
	}
	return out, total, rows.Err()
}

// ListObjectModels GET /api/v1/api-security/object-models
// 查询参数：endpoint_id / object_segment / identifier_type / application_id / page / page_size。
func (h *Handler) ListObjectModels(w http.ResponseWriter, r *http.Request) {
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
	list, total, err := h.store.ListObjectModels(r.Context(), endpointID,
		strings.TrimSpace(q.Get("object_segment")),
		strings.TrimSpace(q.Get("identifier_type")),
		applicationID,
		page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}
