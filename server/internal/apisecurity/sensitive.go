// sensitive.go 敏感字段识别结果（api_sensitive_fields）查询仓储。
package apisecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SensitiveField 敏感字段识别结果（api_sensitive_fields）。
type SensitiveField struct {
	ID              uuid.UUID       `json:"id"`
	EndpointID      uuid.UUID       `json:"endpoint_id"`
	EndpointKey     string          `json:"endpoint_key"` // METHOD PATH（JOIN api_endpoints；端点缺失时为空）
	Direction       string          `json:"direction"`    // REQUEST / RESPONSE
	StructuredPath  string          `json:"structured_path"`
	DataType        string          `json:"data_type"` // phone / id_card / bank_card / email / credential / ...
	Confidence      float64         `json:"confidence"`
	DetectionSource string          `json:"detection_source"` // AUTO / MANUAL
	OccurrenceCount int             `json:"occurrence_count"` // 累计命中次数（SweepOnce 维护）
	FirstSeen       *time.Time      `json:"first_seen"`
	LastSeen        *time.Time      `json:"last_seen"`
	SourceDetail    json.RawMessage `json:"source_detail"` // 最近一次命中摘要 {location, rule_id, event_id, data_type}
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// ListSensitiveFields 敏感字段分页列表（过滤 endpoint_id/direction/data_type，updated_at DESC）。
// endpointID 为空表示不过滤；非法 UUID 直接视为无匹配（HTTP 层负责 400 校验）。
func (s *Store) ListSensitiveFields(ctx context.Context, endpointID, direction, dataType string, page, pageSize int) ([]SensitiveField, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	// 过滤条件按白名单字段拼接，值一律参数化（f. 前缀避免 JOIN 后列名歧义）
	where := []string{}
	args := []any{}
	if endpointID != "" {
		id, err := uuid.Parse(endpointID)
		if err != nil {
			return []SensitiveField{}, 0, nil
		}
		args = append(args, id)
		where = append(where, fmt.Sprintf("f.endpoint_id = $%d", len(args)))
	}
	if direction != "" {
		args = append(args, direction)
		where = append(where, fmt.Sprintf("f.direction = $%d", len(args)))
	}
	if dataType != "" {
		args = append(args, dataType)
		where = append(where, fmt.Sprintf("f.data_type = $%d", len(args)))
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_sensitive_fields f"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `
SELECT f.id, f.endpoint_id, COALESCE(e.endpoint_key, ''), f.direction, f.structured_path, f.data_type,
       f.confidence, f.detection_source, f.occurrence_count, f.first_seen, f.last_seen, f.source_detail,
       f.created_at, f.updated_at
FROM api_sensitive_fields f
LEFT JOIN api_endpoints e ON e.id = f.endpoint_id`+cond+fmt.Sprintf(" ORDER BY f.updated_at DESC, f.id LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []SensitiveField{}
	for rows.Next() {
		var f SensitiveField
		if err := rows.Scan(&f.ID, &f.EndpointID, &f.EndpointKey, &f.Direction, &f.StructuredPath, &f.DataType,
			&f.Confidence, &f.DetectionSource, &f.OccurrenceCount, &f.FirstSeen, &f.LastSeen, &f.SourceDetail,
			&f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, f)
	}
	return out, total, rows.Err()
}

// DeleteSensitiveFieldsByIDs 按 ID 批量删除敏感字段识别结果，返回实际删除条数。
// 批量语义：部分 ID 不存在不视为错误（与逐条删除的 404 语义区分），由调用方如实反馈条数。
func (s *Store) DeleteSensitiveFieldsByIDs(ctx context.Context, ids []uuid.UUID) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	ct, err := s.db.Exec(ctx, `DELETE FROM api_sensitive_fields WHERE id = ANY($1)`, ids)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}
