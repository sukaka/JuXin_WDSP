// sensitive.go 敏感字段识别结果（api_sensitive_fields）查询仓储。
package apisecurity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SensitiveField 敏感字段识别结果（api_sensitive_fields）。
type SensitiveField struct {
	ID              uuid.UUID `json:"id"`
	EndpointID      uuid.UUID `json:"endpoint_id"`
	Direction       string    `json:"direction"` // REQUEST / RESPONSE
	StructuredPath  string    `json:"structured_path"`
	DataType        string    `json:"data_type"` // phone / id_card / bank_card / email / credential / ...
	Confidence      float64   `json:"confidence"`
	DetectionSource string    `json:"detection_source"` // AUTO / MANUAL
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
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
	// 过滤条件按白名单字段拼接，值一律参数化
	where := []string{}
	args := []any{}
	if endpointID != "" {
		id, err := uuid.Parse(endpointID)
		if err != nil {
			return []SensitiveField{}, 0, nil
		}
		args = append(args, id)
		where = append(where, fmt.Sprintf("endpoint_id = $%d", len(args)))
	}
	if direction != "" {
		args = append(args, direction)
		where = append(where, fmt.Sprintf("direction = $%d", len(args)))
	}
	if dataType != "" {
		args = append(args, dataType)
		where = append(where, fmt.Sprintf("data_type = $%d", len(args)))
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_sensitive_fields"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `
SELECT id, endpoint_id, direction, structured_path, data_type, confidence, detection_source, created_at, updated_at
FROM api_sensitive_fields`+cond+fmt.Sprintf(" ORDER BY updated_at DESC, id LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []SensitiveField{}
	for rows.Next() {
		var f SensitiveField
		if err := rows.Scan(&f.ID, &f.EndpointID, &f.Direction, &f.StructuredPath, &f.DataType,
			&f.Confidence, &f.DetectionSource, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, f)
	}
	return out, total, rows.Err()
}
