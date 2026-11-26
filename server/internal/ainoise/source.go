// source.go 降噪事件源：WAF 读 security_events（UNPROCESSED/ANALYZING 且窗口内）；
// WDSP（API 动态防护开启）追加读 api_runtime_events，字段映射到同一指纹模型。
package ainoise

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// sweepFetchLimit 单次扫描每类事件源的最大读取量（防长窗口拉爆内存）。
const sweepFetchLimit = 5000

// EventSource 降噪事件源契约。
type EventSource interface {
	FetchWAF(ctx context.Context, start, end time.Time, limit int) ([]EventInput, error)
	FetchAPI(ctx context.Context, start, end time.Time, limit int) ([]EventInput, error)
}

// SQLEventSource PostgreSQL 事件源。wdsp=false 时 FetchAPI 恒返回空（纯 WAF 形态零行为）。
type SQLEventSource struct {
	db   *pgxpool.Pool
	wdsp bool
}

// NewEventSource 创建事件源（wdsp 取 cfg.Product.APIDynamicProtectionEnabled()）。
func NewEventSource(db *pgxpool.Pool, wdsp bool) *SQLEventSource {
	return &SQLEventSource{db: db, wdsp: wdsp}
}

// FetchWAF 读取窗口内未处置/分析中的安全事件；规则ID取异常分最高的命中（确定性）。
func (s *SQLEventSource) FetchWAF(ctx context.Context, start, end time.Time, limit int) ([]EventInput, error) {
	if limit <= 0 || limit > sweepFetchLimit {
		limit = sweepFetchLimit
	}
	rows, err := s.db.Query(ctx, `
SELECT e.id, e.application_id, COALESCE(e.domain,''), COALESCE(e.request_path,''),
  COALESCE(host(e.client_ip),''),
  (SELECT m.rule_id FROM security_event_matches m WHERE m.event_id = e.id
   AND m.event_occurred_at = e.occurred_at
   AND m.event_occurred_at >= $1 AND m.event_occurred_at < $2
   ORDER BY m.anomaly_score DESC, m.rule_id LIMIT 1),
  e.occurred_at
FROM security_events e
WHERE e.occurred_at >= $1 AND e.occurred_at < $2
  AND e.disposition_status IN ('UNPROCESSED','ANALYZING')
ORDER BY e.occurred_at LIMIT $3`, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EventInput{}
	for rows.Next() {
		var ev EventInput
		ev.Source = SourceWAF
		if err := rows.Scan(&ev.EventID, &ev.ApplicationID, &ev.Host, &ev.RawURI,
			&ev.ClientIP, &ev.RuleID, &ev.OccurredAt); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// FetchAPI 读取窗口内 API 运行时事件（仅 WDSP；endpoint_key 作归一化 URI，
// 评分最高的 detector 作 detector_code；api_runtime_events 无 client_ip/host 列，留空）。
func (s *SQLEventSource) FetchAPI(ctx context.Context, start, end time.Time, limit int) ([]EventInput, error) {
	if !s.wdsp {
		return nil, nil
	}
	if limit <= 0 || limit > sweepFetchLimit {
		limit = sweepFetchLimit
	}
	rows, err := s.db.Query(ctx, `
SELECT id, endpoint_key, details_json, occurred_at
FROM api_runtime_events
WHERE occurred_at >= $1 AND occurred_at < $2
ORDER BY occurred_at LIMIT $3`, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EventInput{}
	for rows.Next() {
		var ev EventInput
		var details []byte
		ev.Source = SourceAPI
		if err := rows.Scan(&ev.EventID, &ev.RawURI, &details, &ev.OccurredAt); err != nil {
			return nil, err
		}
		ev.DetectorCode = primaryDetectorCode(details)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// primaryDetectorCode 取 score_delta 最高的 detector（并列取首个），截断至 64 字符。
func primaryDetectorCode(detailsJSON []byte) string {
	var matches []dsctx.DetectorMatch
	if err := json.Unmarshal(detailsJSON, &matches); err != nil || len(matches) == 0 {
		return ""
	}
	best := matches[0]
	for _, m := range matches[1:] {
		if m.ScoreDelta > best.ScoreDelta {
			best = m
		}
	}
	code := best.Detector
	if best.RuleID != "" {
		code = best.Detector + ":" + best.RuleID
	}
	if len(code) > 64 {
		code = code[:64]
	}
	return code
}
