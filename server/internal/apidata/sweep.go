// sweep.go api_sensitive_fields 生产写入方：扫描 api_runtime_events.details_json 中
// 敏感检测明细（detector=sensitive_data）的 evidence（字段名/位置/方向），
// upsert api_sensitive_fields（occurrence_count++/last_seen，detection_source='RUNTIME'）。
// 置信度口径：明细自带 confidence 透传落库（值级正则验证命中 1.0、字段名词表命中 0.8），
// 缺失/越界回落 sweepDefaultConfidence；重复命中取 GREATEST（只升不降）。
//
// 水位纪律：取 api_sensitive_fields 的 max(last_seen) 作为水位，只处理其后的新事件，
// 连续两次 SweepOnce 不重复计数（幂等）；首次无水位时全量回填。单次最多处理
// sweepBatchSize 条事件（防长事务），打满时 HasMore=true 提示调用方继续调度。
// 已知边界：与水位同刻（微秒精度 occurred_at）且超出批量的余量事件会被跳过，
// 概率极低；事件因 endpoint_key 未匹配资产被跳过时，水位仍随同批成功事件前移、
// 该事件不再重扫（端点发现正常先于事件落库，见 apiruntime.Collector）。
// 空表/无命中安全返回零值结果。
package apidata

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// sweepBatchSize 单次清扫事件批大小。
const sweepBatchSize = 2000

// sweepDefaultConfidence 明细缺失/非法置信度时的回落值（字段名词表命中口径 0.8；
// 值级正则验证命中由网关显式携带 1.0，见 detectors/sensitive.go addValueMatch）。
const sweepDefaultConfidence = 0.8

// maxStructuredPathLen api_sensitive_fields.structured_path 列宽。
const maxStructuredPathLen = 512

// maxMaskedSampleLen api_sensitive_fields.masked_sample 列宽（仅存储网关已脱敏样本）。
const maxMaskedSampleLen = 128

// SweepResult 一次清扫的结果统计。
type SweepResult struct {
	EventsScanned     int        `json:"events_scanned"`      // 扫描到的含敏感明细事件数
	Hits              int        `json:"hits"`                // 提取的敏感证据条目数
	FieldsUpserted    int        `json:"fields_upserted"`     // upsert 字段数（同一字段多次命中按次数累计）
	SkippedNoEndpoint int        `json:"skipped_no_endpoint"` // endpoint_key 未匹配资产而跳过的事件数
	HasMore           bool       `json:"has_more"`            // 本批打满，可能还有余量
	Watermark         *time.Time `json:"watermark"`           // 本次推进到的水位（最大事件时间）
}

// sweepDetail 运行时事件检测明细的敏感证据子集（镜像 dsctx.DetectorMatch 的 JSON 形状）。
type sweepDetail struct {
	Detector   string            `json:"detector"`
	RuleID     string            `json:"rule_id"`
	Evidence   map[string]string `json:"evidence"`
	Confidence float64           `json:"confidence"` // 明细自带置信度（0-1）；缺失/越界回落 sweepDefaultConfidence
}

// sweepHit 从一条事件明细中提取的敏感证据命中。
type sweepHit struct {
	Direction      string // REQUEST / RESPONSE（证据无方向时默认 REQUEST，兼容历史请求侧明细）
	StructuredPath string // location + "." + field（区分同名字段的不同位置）
	DataType       string
	RuleID         string
	Location       string
	MaskedSample   string // 网关内存脱敏后的值级样本（如 138****8000）；仅字段名命中为空
	Confidence     float64
}

// sanitizeMaskedSample 清理控制字符并按列宽截断脱敏样本（仅消费网关 evidence.masked_sample，绝不读取原始 value）。
func sanitizeMaskedSample(raw string) string {
	cleaned := strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, raw))
	if cleaned == "" {
		return ""
	}
	runes := []rune(cleaned)
	if len(runes) > maxMaskedSampleLen {
		return string(runes[:maxMaskedSampleLen])
	}
	return cleaned
}

// extractSweepHits 从 details_json 提取敏感证据命中（纯函数；非敏感明细/空字段跳过）。
func extractSweepHits(detailsJSON []byte) ([]sweepHit, error) {
	var details []sweepDetail
	if err := json.Unmarshal(detailsJSON, &details); err != nil {
		return nil, fmt.Errorf("parse details_json: %w", err)
	}
	hits := []sweepHit{}
	for _, d := range details {
		if d.Detector != "sensitive_data" || d.Evidence == nil {
			continue
		}
		field := d.Evidence["field"]
		if field == "" {
			continue
		}
		location := d.Evidence["location"]
		if IsIgnoredSensitiveFieldHit(location, field, d.RuleID) {
			continue
		}
		path := field
		if location != "" {
			path = location + "." + field
		}
		if len(path) > maxStructuredPathLen {
			path = path[:maxStructuredPathLen]
		}
		direction := d.Evidence["direction"]
		if direction != "REQUEST" && direction != "RESPONSE" {
			direction = "REQUEST"
		}
		confidence := d.Confidence
		if confidence <= 0 || confidence > 1 {
			confidence = sweepDefaultConfidence
		}
		hits = append(hits, sweepHit{
			Direction:      direction,
			StructuredPath: path,
			DataType:       d.Evidence["data_type"],
			RuleID:         d.RuleID,
			Location:       location,
			MaskedSample:   sanitizeMaskedSample(d.Evidence["masked_sample"]),
			Confidence:     confidence,
		})
	}
	return hits, nil
}

// SweepOnce 执行一次敏感证据清扫（SQL 实现）。
func (s *Store) SweepOnce(ctx context.Context) (*SweepResult, error) {
	res := &SweepResult{}
	// 水位：全部敏感字段行的 max(last_seen)（RUNTIME 行必带 last_seen；空表为 NULL → 全量回填）
	var wm *time.Time
	if err := s.db.QueryRow(ctx,
		`SELECT max(last_seen) FROM api_sensitive_fields`).Scan(&wm); err != nil {
		return nil, fmt.Errorf("sensitive sweep watermark: %w", err)
	}
	rows, err := s.db.Query(ctx, `
SELECT id, endpoint_key, details_json, occurred_at
FROM api_runtime_events
WHERE ($1::timestamptz IS NULL OR occurred_at > $1)
  AND details_json @> '[{"detector":"sensitive_data"}]'::jsonb
  AND EXISTS (
    SELECT 1
    FROM jsonb_array_elements(details_json) AS d
    WHERE d->>'detector' = 'sensitive_data'
      AND COALESCE(d->'evidence'->>'field', '') <> ''
      AND lower(COALESCE(d->>'rule_id', '')) <> 'sensitive.response_body_unchecked'
      AND NOT (
        lower(COALESCE(d->>'rule_id', '')) = 'sensitive.field'
        AND lower(COALESCE(d->'evidence'->>'location', '')) = 'path'
      )
      AND NOT (
        lower(COALESCE(d->>'rule_id', '')) = 'sensitive.field'
        AND lower(COALESCE(d->'evidence'->>'location', '')) = 'header'
        AND (
          lower(COALESCE(d->'evidence'->>'field', '')) LIKE 'sec-ch-%'
          OR lower(COALESCE(d->'evidence'->>'field', '')) LIKE 'sec-fetch-%'
          OR lower(COALESCE(d->'evidence'->>'field', '')) LIKE 'sec-websocket-%'
          OR lower(COALESCE(d->'evidence'->>'field', '')) = ANY($3::text[])
        )
      )
  )
ORDER BY occurred_at ASC, id ASC
LIMIT $2`, wm, sweepBatchSize, standardProtocolHeaderNames)
	if err != nil {
		return nil, fmt.Errorf("sensitive sweep query: %w", err)
	}
	defer rows.Close()

	type eventRow struct {
		id          uuid.UUID
		endpointKey string
		details     []byte
		occurredAt  time.Time
	}
	events := []eventRow{}
	for rows.Next() {
		var ev eventRow
		if err := rows.Scan(&ev.id, &ev.endpointKey, &ev.details, &ev.occurredAt); err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return res, nil // 空表/无命中安全
	}
	res.HasMore = len(events) >= sweepBatchSize

	// 端点键 → 资产 ID 解析缓存（同批内复用；未命中资产的事件跳过）
	endpointIDs := map[string]*uuid.UUID{}
	resolve := func(key string) (*uuid.UUID, error) {
		if id, ok := endpointIDs[key]; ok {
			return id, nil
		}
		var id uuid.UUID
		err := s.db.QueryRow(ctx, `SELECT id FROM api_endpoints WHERE endpoint_key = $1`, key).Scan(&id)
		if err != nil {
			idPtr := (*uuid.UUID)(nil)
			endpointIDs[key] = idPtr // 负缓存：同批不再重复查
			return nil, nil
		}
		endpointIDs[key] = &id
		return &id, nil
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, ev := range events {
		res.EventsScanned++
		hits, err := extractSweepHits(ev.details)
		if err != nil {
			return nil, fmt.Errorf("sensitive sweep event %s: %w", ev.id, err)
		}
		if len(hits) == 0 {
			continue
		}
		endpointID, err := resolve(ev.endpointKey)
		if err != nil {
			return nil, fmt.Errorf("sensitive sweep resolve endpoint %q: %w", ev.endpointKey, err)
		}
		if endpointID == nil {
			res.SkippedNoEndpoint++
			continue
		}
		res.Hits += len(hits)
		for _, h := range hits {
			detailMap := map[string]string{
				"location":  h.Location,
				"rule_id":   h.RuleID,
				"event_id":  ev.id.String(),
				"data_type": h.DataType,
			}
			if h.MaskedSample != "" {
				detailMap["masked_sample"] = h.MaskedSample
			}
			sourceDetail, err := json.Marshal(detailMap)
			if err != nil {
				return nil, err
			}
			// upsert：唯一键 (endpoint_id, direction, structured_path)；
			// occurrence_count 累加；last_seen 取较大者（乱序防御）；首末次时间不回头；
			// data_type 以最新非空观测为准；detection_source 保留首次来源（MANUAL 行不被改写）；
			// confidence 取历史与本次观测的较大者（值级验证命中 1.0 可抬升字段名命中 0.8，不反向降级）；
			// masked_sample 保留最新 1 条非空脱敏样本（后续仅字段名命中不覆盖既有值级样本）。
			if _, err := tx.Exec(ctx, `
INSERT INTO api_sensitive_fields
    (endpoint_id, direction, structured_path, data_type, confidence, detection_source,
     first_seen, last_seen, occurrence_count, source_detail, masked_sample)
VALUES ($1, $2, $3, $4, $5, 'RUNTIME', $6, $6, 1, $7, $8)
ON CONFLICT (endpoint_id, direction, structured_path) DO UPDATE SET
    occurrence_count = api_sensitive_fields.occurrence_count + 1,
    first_seen = LEAST(COALESCE(api_sensitive_fields.first_seen, 'infinity'::timestamptz), EXCLUDED.first_seen),
    last_seen  = GREATEST(COALESCE(api_sensitive_fields.last_seen, '-infinity'::timestamptz), EXCLUDED.last_seen),
    data_type  = CASE WHEN EXCLUDED.data_type <> '' THEN EXCLUDED.data_type ELSE api_sensitive_fields.data_type END,
    confidence = GREATEST(api_sensitive_fields.confidence, EXCLUDED.confidence),
    source_detail = EXCLUDED.source_detail,
    masked_sample = CASE WHEN EXCLUDED.masked_sample <> '' THEN EXCLUDED.masked_sample ELSE api_sensitive_fields.masked_sample END,
    updated_at = now()`,
				endpointID, h.Direction, h.StructuredPath, h.DataType, h.Confidence,
				ev.occurredAt, sourceDetail, h.MaskedSample); err != nil {
				return nil, fmt.Errorf("sensitive sweep upsert: %w", err)
			}
			res.FieldsUpserted++
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	last := events[len(events)-1].occurredAt
	res.Watermark = &last
	return res, nil
}
