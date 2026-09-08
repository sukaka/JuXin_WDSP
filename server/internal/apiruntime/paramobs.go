// paramobs.go 网关参数值脱敏观测入库（三微模型参数微模型值观测通路）。
// 事件 JSONL 中的 param_observations → UPSERT api_parameter_value_obs（按 endpoint_key×位置×路径×名）。
package apiruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ParamObservation 采集端镜像（与网关 detectors.ParamObservation JSON 字段一致）。
type ParamObservation struct {
	Location  string   `json:"location"`
	Name      string   `json:"name"`
	Path      string   `json:"path"`
	BaseType  string   `json:"base_type"`
	Length    int      `json:"length"`
	ValueHash string   `json:"value_hash"`
	NumValue  *float64 `json:"num_value"`
}

// ParamObsRecorder 参数观测聚合写入接口。
type ParamObsRecorder interface {
	RecordParamObservations(ctx context.Context, endpointKey string, obs []ParamObservation) error
}

// ParamObsStore pgx 实现。
type ParamObsStore struct {
	db DBTX
}

// NewParamObsStore 创建观测写入方。
func NewParamObsStore(db *pgxpool.Pool) *ParamObsStore {
	return &ParamObsStore{db: db}
}

// WithDB 返回绑定到给定句柄的浅拷贝（W22 批次事务化，语义同 Store.WithDB）。
func (s *ParamObsStore) WithDB(db DBTX) *ParamObsStore {
	return &ParamObsStore{db: db}
}

const valueHashCap = 64 // 每键保留的 distinct hash 上限

// RecordParamObservations 合并观测到 api_parameter_value_obs（幂等增量 UPSERT）。
func (s *ParamObsStore) RecordParamObservations(ctx context.Context, endpointKey string, obs []ParamObservation) error {
	if s == nil || s.db == nil || endpointKey == "" || len(obs) == 0 {
		return nil
	}
	for _, o := range obs {
		if o.Name == "" && o.Path == "" {
			continue
		}
		path := o.Path
		name := o.Name
		if name == "" {
			name = path
		}
		loc := o.Location
		if loc == "" {
			loc = "BODY"
		}
		// 读取既有行再合并（简单正确；高并发下用 SQL 聚合亦可）
		var sampleCount int64
		var minLen, maxLen *int
		var minVal, maxVal *float64
		var distinct *int
		var hashesRaw []byte
		err := s.db.QueryRow(ctx, `
SELECT sample_count, min_length, max_length, min_value, max_value, distinct_count, value_hashes
FROM api_parameter_value_obs
WHERE endpoint_key=$1 AND location=$2 AND structured_path=$3 AND parameter_name=$4`,
			endpointKey, loc, path, name).Scan(&sampleCount, &minLen, &maxLen, &minVal, &maxVal, &distinct, &hashesRaw)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("load param obs: %w", err)
		}
		sampleCount++
		if o.Length > 0 || o.ValueHash != "" {
			if minLen == nil || o.Length < *minLen {
				v := o.Length
				minLen = &v
			}
			if maxLen == nil || o.Length > *maxLen {
				v := o.Length
				maxLen = &v
			}
		}
		if o.NumValue != nil {
			nv := *o.NumValue
			if minVal == nil || nv < *minVal {
				minVal = &nv
			}
			if maxVal == nil || nv > *maxVal {
				maxVal = &nv
			}
		}
		hashes := decodeHashList(hashesRaw)
		if o.ValueHash != "" {
			hashes = mergeHash(hashes, o.ValueHash, valueHashCap)
		}
		dc := len(hashes)
		distinct = &dc
		hb, _ := json.Marshal(hashes)
		_, err = s.db.Exec(ctx, `
INSERT INTO api_parameter_value_obs
  (endpoint_key, location, structured_path, parameter_name, sample_count,
   min_length, max_length, min_value, max_value, distinct_count, value_hashes, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb, now())
ON CONFLICT (endpoint_key, location, structured_path, parameter_name) DO UPDATE SET
  sample_count = EXCLUDED.sample_count,
  min_length = EXCLUDED.min_length,
  max_length = EXCLUDED.max_length,
  min_value = EXCLUDED.min_value,
  max_value = EXCLUDED.max_value,
  distinct_count = EXCLUDED.distinct_count,
  value_hashes = EXCLUDED.value_hashes,
  updated_at = now()`,
			endpointKey, loc, path, name, sampleCount,
			minLen, maxLen, minVal, maxVal, distinct, string(hb))
		if err != nil {
			return fmt.Errorf("upsert param obs: %w", err)
		}
	}
	return nil
}

func decodeHashList(raw []byte) []string {
	var out []string
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

func mergeHash(list []string, h string, capN int) []string {
	for _, x := range list {
		if x == h {
			return list
		}
	}
	if len(list) >= capN {
		// 环形替换最旧
		list = append(list[1:], h)
		return list
	}
	return append(list, h)
}
