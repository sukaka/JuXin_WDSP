// respschema.go 响应结构观测入库（P0-06 响应 Schema 学习生产方）。
// 事件 JSONL 中的 response_observations → UPSERT api_response_schemas 运行时学习行
// （按 endpoint_key×status_code 合并；model_version_id 为空标识运行时行，
// 版本快照行由模型确认时物化，不参与合并，见迁移 000051）。
package apiruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// RespSchemaRecorder 响应 Schema 学习写入接口。
type RespSchemaRecorder interface {
	RecordResponseObservations(ctx context.Context, endpointKey string, obs []dsctx.ResponseObservation) error
}

// RespSchemaStore pgx 实现。
type RespSchemaStore struct {
	db DBTX
}

// NewRespSchemaStore 创建响应 Schema 学习写入方。
func NewRespSchemaStore(db *pgxpool.Pool) *RespSchemaStore {
	return &RespSchemaStore{db: db}
}

// WithDB 返回绑定到给定句柄的浅拷贝（W22 批次事务化，语义同 Store.WithDB）。
func (s *RespSchemaStore) WithDB(db DBTX) *RespSchemaStore {
	return &RespSchemaStore{db: db}
}

// responseSchemaDoc schema_json 文档形态（运行时学习行与版本快照行共用）：
// {"fields": {一级字段路径: 类型}, "truncated": bool, "content_type": "..."}
// 只含字段路径与类型标签，不落值（与网关观测的证据纪律一致）。
type responseSchemaDoc struct {
	Fields      map[string]string `json:"fields"`
	Truncated   bool              `json:"truncated,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
}

// mergeResponseSchema 合并既有文档与新观测（纯函数，幂等可重放）：
//   - 字段集合取并集；同路径类型冲突保留既有（首次观测优先，
//     避免类型在 string/number 间随报文抖动；类型演化由模型 Diff 波次呈现）；
//   - truncated 任一为真即真（曾被截断的说明不丢）；
//   - content_type 取最新非空观测（响应形态随时间漂移时反映现状）。
func mergeResponseSchema(existing []byte, o dsctx.ResponseObservation) responseSchemaDoc {
	doc := responseSchemaDoc{Fields: map[string]string{}}
	if len(existing) > 0 {
		_ = json.Unmarshal(existing, &doc)
	}
	if doc.Fields == nil {
		doc.Fields = map[string]string{}
	}
	for p, typ := range o.Fields {
		if _, ok := doc.Fields[p]; !ok {
			doc.Fields[p] = typ
		}
	}
	doc.Truncated = doc.Truncated || o.Truncated
	if o.ContentType != "" {
		doc.ContentType = o.ContentType
	}
	return doc
}

// hashResponseSchema 内容哈希（sha256 hex；map 序列化键有序，输出确定）。
func hashResponseSchema(schemaJSON []byte) string {
	sum := sha256.Sum256(schemaJSON)
	return hex.EncodeToString(sum[:])
}

// RecordResponseObservations 合并观测到 api_response_schemas（幂等增量 UPSERT）。
// 读取既有运行时行合并后写回（与 paramobs 同一纪律：采集器单协程处理单日志文件，
// 简单正确；ON CONFLICT 兜底并发冲突）。无状态码或无字段的观测跳过（不产出空 Schema）。
func (s *RespSchemaStore) RecordResponseObservations(ctx context.Context, endpointKey string, obs []dsctx.ResponseObservation) error {
	if s == nil || s.db == nil || endpointKey == "" || len(obs) == 0 {
		return nil
	}
	for _, o := range obs {
		if o.StatusCode <= 0 || len(o.Fields) == 0 {
			continue
		}
		var raw []byte
		err := s.db.QueryRow(ctx, `
SELECT schema_json FROM api_response_schemas
WHERE endpoint_key=$1 AND status_code=$2 AND model_version_id IS NULL`,
			endpointKey, o.StatusCode).Scan(&raw)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("load response schema: %w", err)
		}
		doc := mergeResponseSchema(raw, o)
		mj, err := json.Marshal(doc)
		if err != nil {
			return fmt.Errorf("marshal response schema: %w", err)
		}
		_, err = s.db.Exec(ctx, `
INSERT INTO api_response_schemas
  (model_version_id, endpoint_key, status_code, schema_json, content_hash, first_seen, last_seen, sample_count, updated_at)
VALUES (NULL,$1,$2,$3::jsonb,$4,now(),now(),1,now())
ON CONFLICT (endpoint_key, status_code) WHERE endpoint_key IS NOT NULL AND model_version_id IS NULL
DO UPDATE SET
  schema_json  = EXCLUDED.schema_json,
  content_hash = EXCLUDED.content_hash,
  last_seen    = now(),
  sample_count = api_response_schemas.sample_count + 1,
  updated_at   = now()`,
			endpointKey, o.StatusCode, string(mj), hashResponseSchema(mj))
		if err != nil {
			return fmt.Errorf("upsert response schema: %w", err)
		}
	}
	return nil
}
