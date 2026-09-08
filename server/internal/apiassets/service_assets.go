// service_assets.go 服务资产聚合（WDSP 任务书 §14，P0-10 Known Gap ③）。
//
// 服务资产 = 源站主机:端口 视角的聚合视图：从阶段3 upstreams（normalized_host+port）
// 反聚 api 端点归属（api_endpoints.application_id ∈ 该服务承载的应用集合），
// 输出 server_ip / port / application_count / api_count / traffic_7d /
// sensitive_api_count / risk_count。
package apiassets

import (
	"context"
)

// ServiceAsset 服务资产（upstream 主机:端口 粒度）。
type ServiceAsset struct {
	ServerIP          string `json:"server_ip"`           // upstreams.normalized_host（主机名或 IP）
	Port              int    `json:"port"`                // upstreams.port
	ApplicationCount  int64  `json:"application_count"`   // 承载应用数（去重）
	APICount          int64  `json:"api_count"`           // 归属 API 端点数
	Traffic7d         int64  `json:"traffic_7d"`          // 近 7 天请求量（traffic buckets 留存窗口聚合）
	SensitiveAPICount int64  `json:"sensitive_api_count"` // 含敏感字段的端点数（api_sensitive_fields 去重）
	RiskCount         int64  `json:"risk_count"`          // 未闭环风险发现数（findings NEW/CONFIRMED/IN_PROGRESS）
}

// ListServiceAssets 服务资产分页列表（按 host,port 升序；应用软删 upstreams 不计）。
func (s *Store) ListServiceAssets(ctx context.Context, page, pageSize int) ([]ServiceAsset, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	var total int64
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM (
  SELECT 1 FROM upstreams WHERE deleted_at IS NULL
  GROUP BY normalized_host, port
) t`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `
WITH svc AS (
  SELECT u.normalized_host AS host, u.port,
         array_agg(DISTINCT u.application_id) AS app_ids,
         count(DISTINCT u.application_id) AS app_count
  FROM upstreams u
  WHERE u.deleted_at IS NULL
  GROUP BY u.normalized_host, u.port
)
SELECT s.host, s.port, s.app_count,
  (SELECT count(*) FROM api_endpoints e WHERE e.application_id = ANY(s.app_ids)),
  COALESCE((SELECT sum(b.request_count) FROM api_endpoint_traffic_buckets b
            JOIN api_endpoints e ON e.id = b.endpoint_id
            WHERE e.application_id = ANY(s.app_ids)), 0),
  (SELECT count(DISTINCT f.endpoint_id) FROM api_sensitive_fields f
   JOIN api_endpoints e ON e.id = f.endpoint_id
   WHERE e.application_id = ANY(s.app_ids)),
  (SELECT count(*) FROM api_runtime_findings r
   JOIN api_endpoints e ON e.id = r.endpoint_id
   WHERE e.application_id = ANY(s.app_ids)
     AND r.status IN ('NEW','CONFIRMED','IN_PROGRESS'))
FROM svc s
ORDER BY s.host, s.port
LIMIT $1 OFFSET $2`, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []ServiceAsset{}
	for rows.Next() {
		var sa ServiceAsset
		if err := rows.Scan(&sa.ServerIP, &sa.Port, &sa.ApplicationCount, &sa.APICount,
			&sa.Traffic7d, &sa.SensitiveAPICount, &sa.RiskCount); err != nil {
			return nil, 0, err
		}
		out = append(out, sa)
	}
	return out, total, rows.Err()
}
