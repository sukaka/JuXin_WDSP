// response_schemas.go 响应 Schema 学习结果（P0-06）：运行时学习行的只读查询
// 与模型确认时的版本快照物化（最小 Diff 联动）。
// 写入方在 apiruntime（采集器 UPSERT 合并）；本包只读 + 快照，不改学习行。
package apimodels

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jiuzhang-waf/server/internal/response"
)

// ResponseSchema 端点响应结构学习结果（api_response_schemas 运行时学习行，
// 一 端点×状态码 一行；只含字段路径与类型标签，不落值）。
type ResponseSchema struct {
	ID          uuid.UUID         `json:"id"`
	EndpointKey string            `json:"endpoint_key"`
	StatusCode  int               `json:"status_code"`
	Fields      map[string]string `json:"fields"` // 一级字段路径 → 类型
	ContentType string            `json:"content_type,omitempty"`
	Truncated   bool              `json:"truncated"` // 观测曾超网关护栏被截断
	ContentHash string            `json:"content_hash"`
	SampleCount int64             `json:"sample_count"`
	FirstSeen   time.Time         `json:"first_seen"`
	LastSeen    time.Time         `json:"last_seen"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// ResponseSchemaReader 响应 Schema 学习结果只读存取（*Store 实现，包内单测可注入 fake）。
type ResponseSchemaReader interface {
	EndpointKey(ctx context.Context, endpointID uuid.UUID) (string, error)
	ListResponseSchemas(ctx context.Context, endpointKey string) ([]ResponseSchema, error)
}

// SetResponseSchemaReader 注入只读存取实现（默认 NewHandler 以 *Store 接线；测试注入 fake）。
func (h *Handler) SetResponseSchemaReader(r ResponseSchemaReader) { h.respSchemas = r }

// responseSchemaDoc schema_json 文档形态（与 apiruntime 写入方同一约定，只读解析）。
type responseSchemaDoc struct {
	Fields      map[string]string `json:"fields"`
	Truncated   bool              `json:"truncated"`
	ContentType string            `json:"content_type"`
}

// ListResponseSchemas 按端点查询运行时学习到的响应 Schema（按状态码升序，一状态码一行；
// 版本快照行 model_version_id 非空，不属于运行时学习结果，不返回）。
func (s *Store) ListResponseSchemas(ctx context.Context, endpointKey string) ([]ResponseSchema, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, endpoint_key, status_code, schema_json, content_hash, sample_count, first_seen, last_seen, updated_at
FROM api_response_schemas
WHERE endpoint_key=$1 AND model_version_id IS NULL
ORDER BY status_code`, endpointKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ResponseSchema{}
	for rows.Next() {
		var rs ResponseSchema
		var raw []byte
		var firstSeen, lastSeen *time.Time
		if err := rows.Scan(&rs.ID, &rs.EndpointKey, &rs.StatusCode, &raw, &rs.ContentHash,
			&rs.SampleCount, &firstSeen, &lastSeen, &rs.UpdatedAt); err != nil {
			return nil, err
		}
		doc := responseSchemaDoc{Fields: map[string]string{}}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &doc)
		}
		if doc.Fields == nil {
			doc.Fields = map[string]string{}
		}
		rs.Fields = doc.Fields
		rs.Truncated = doc.Truncated
		rs.ContentType = doc.ContentType
		if firstSeen != nil {
			rs.FirstSeen = *firstSeen
		}
		if lastSeen != nil {
			rs.LastSeen = *lastSeen
		}
		out = append(out, rs)
	}
	return out, rows.Err()
}

// ListResponseSchemas GET /api/v1/api-security/endpoints/{id}/response-schemas
// 按端点查响应 Schema 学习结果（按状态码分组：一状态码一行，升序返回）。
func (h *Handler) ListResponseSchemas(w http.ResponseWriter, r *http.Request) {
	endpointID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的接口ID")
		return
	}
	if h.respSchemas == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeInternalError, "响应 Schema 学习未启用")
		return
	}
	endpointKey, err := h.respSchemas.EndpointKey(r.Context(), endpointID)
	if errors.Is(err, ErrEndpointNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	list, err := h.respSchemas.ListResponseSchemas(r.Context(), endpointKey)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": list})
}

// snapshotResponseSchemas 模型确认联动（最小实现）：把当前运行时学习到的响应结构
// 按本版本物化快照行（model_version_id 关联版本；endpoint_key 保留便于溯源）。
// 快照行不参与运行时合并（唯一索引仅覆盖 model_version_id 为空的行）；
// 无学习数据时零影响。response_schema_set_id 留空（集合概念未建，快照经 model_version_id 可溯）。
func snapshotResponseSchemas(ctx context.Context, tx pgx.Tx, versionID uuid.UUID, endpointKey string) error {
	_, err := tx.Exec(ctx, `
INSERT INTO api_response_schemas
  (model_version_id, endpoint_key, status_code, schema_json, content_hash, first_seen, last_seen, sample_count, updated_at)
SELECT $1, endpoint_key, status_code, schema_json, content_hash, first_seen, last_seen, sample_count, now()
FROM api_response_schemas
WHERE endpoint_key=$2 AND model_version_id IS NULL`, versionID, endpointKey)
	return err
}
