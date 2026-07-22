// event_tools.go 安全事件 Tool：查询/详情/关联/统计/处置摘要。
package aitools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/audits"
)

// eventTools 安全事件 Tool 组。
type eventTools struct{ db *pgxpool.Pool }

// NewEventTools 注册安全事件 Tool。
func NewEventTools(r *Registry, db *pgxpool.Pool) {
	e := &eventTools{db: db}
	r.Register(&eventSearch{baseTool: baseTool{meta: toolMeta{
		code: "security_event.search", name: "安全事件查询", version: "1.0",
		description: "按时间/攻击类型/严重级别/IP/应用/动作分页查询安全事件",
		risk: RiskReadOnly, permission: "security_events.read", timeout: 20, maxResults: 50,
		schema: obj(map[string]interface{}{
			"start_time": sch("string", "起始时间 RFC3339（默认最近24小时）"),
			"end_time":   sch("string", "结束时间"),
			"attack_type": sch("string", "攻击类型（可选）"),
			"severity":    sch("string", "严重级别（可选）"),
			"client_ip":   sch("string", "客户端IP（可选）"),
			"action":      sch("string", "动作 BLOCK/OBSERVE（可选）"),
			"rule_id":     sch("integer", "规则ID（可选）"),
			"page":        sch("integer", "页码"),
		})}}, db: db})
	r.Register(&eventGet{baseTool: baseTool{meta: toolMeta{
		code: "security_event.get", name: "安全事件详情", version: "1.0",
		description: "按事件ID获取完整详情（含匹配规则，载荷脱敏）",
		risk: RiskReadOnly, permission: "security_events.read", timeout: 10, maxResults: 1,
		schema: obj(map[string]interface{}{"event_id": sch("string", "事件ID")})}}, db: db})
	r.Register(&eventRelated{baseTool: baseTool{meta: toolMeta{
		code: "security_event.related", name: "关联事件", version: "1.0",
		description: "查询事件关联事件（同RequestID/同IP近邻）",
		risk: RiskReadOnly, permission: "security_events.read", timeout: 15, maxResults: 20,
		schema: obj(map[string]interface{}{"event_id": sch("string", "事件ID")})}}, db: db})
	r.Register(&eventStats{baseTool: baseTool{meta: toolMeta{
		code: "security_event.statistics", name: "事件统计", version: "1.0",
		description: "按维度统计安全事件（类型/级别/动作/来源IP/应用）",
		risk: RiskReadOnly, permission: "security_events.read", timeout: 30, maxResults: 100,
		schema: obj(map[string]interface{}{
			"start_time": sch("string", "起始时间"),
			"end_time":   sch("string", "结束时间"),
			"dimension":  sch("string", "attack_type|severity|action|client_ip|application"),
		})}}, db: db})
	r.Register(&eventDisposition{baseTool: baseTool{meta: toolMeta{
		code: "security_event.disposition_summary", name: "事件处置摘要", version: "1.0",
		description: "事件处置状态分布与未处置统计",
		risk: RiskReadOnly, permission: "security_events.read", timeout: 15, maxResults: 10,
		schema: obj(map[string]interface{}{
			"start_time": sch("string", "起始时间"),
			"end_time":   sch("string", "结束时间"),
		})}}, db: db})
	_ = e
}

// 时间解析（限制最大跨度 90 天）。
func parseTimeRange(m map[string]interface{}) (time.Time, time.Time, error) {
	end := time.Now().UTC()
	start := end.Add(-24 * time.Hour)
	if s := StrField(m, "start_time", 64); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return start, end, fmt.Errorf("%w: invalid start_time", ErrInvalidInput)
		}
		start = t.UTC()
	}
	if s := StrField(m, "end_time", 64); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return start, end, fmt.Errorf("%w: invalid end_time", ErrInvalidInput)
		}
		end = t.UTC()
	}
	if !start.Before(end) {
		return start, end, fmt.Errorf("%w: start_time must be before end_time", ErrInvalidInput)
	}
	if end.Sub(start) > 90*24*time.Hour {
		return start, end, fmt.Errorf("%w: time range exceeds 90 days", ErrInvalidInput)
	}
	return start, end, nil
}

type eventSearch struct {
	baseTool
	db *pgxpool.Pool
}

func (t *eventSearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	start, end, err := parseTimeRange(m)
	if err != nil {
		return nil, err
	}
	page := IntField(m, "page", 1)
	if page < 1 {
		page = 1
	}
	pageSize := 20
	where := "occurred_at >= $1 AND occurred_at < $2"
	args := []interface{}{start, end}
	idx := 3
	if v := StrField(m, "attack_type", 40); v != "" {
		where += fmt.Sprintf(" AND attack_type = $%d", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "severity", 20); v != "" {
		where += fmt.Sprintf(" AND severity = $%d", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "client_ip", 45); v != "" {
		where += fmt.Sprintf(" AND client_ip = $%d::inet", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "action", 20); v != "" {
		where += fmt.Sprintf(" AND action = $%d", idx)
		args = append(args, v)
		idx++
	}
	if rid := IntField(m, "rule_id", 0); rid > 0 {
		where += fmt.Sprintf(" AND id IN (SELECT event_id FROM security_event_matches WHERE rule_id = $%d)", idx)
		args = append(args, rid)
		idx++
	}
	var total int64
	if err := t.db.QueryRow(ctx, `SELECT count(*) FROM security_events WHERE `+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := t.db.Query(ctx, `
SELECT id, occurred_at, attack_type, severity, action, COALESCE(host(client_ip),''), domain,
       COALESCE(application_name_snapshot,''), request_method, left(request_path,255), anomaly_score
FROM security_events WHERE `+where+` ORDER BY occurred_at DESC LIMIT $`+fmt.Sprint(idx)+` OFFSET $`+fmt.Sprint(idx+1),
		append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id string
		var at time.Time
		var atType, sev, act, ip, domain, app, method, path string
		var score int
		if err := rows.Scan(&id, &at, &atType, &sev, &act, &ip, &domain, &app, &method, &path, &score); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"event_id": id, "occurred_at": at, "attack_type": atType, "severity": sev,
			"action": act, "client_ip": ip, "domain": domain, "application": app,
			"method": method, "path": path, "anomaly_score": score,
		})
	}
	return map[string]interface{}{
		"total": total, "page": page, "page_size": pageSize, "items": items,
		"range": map[string]string{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)},
	}, rows.Err()
}

type eventGet struct {
	baseTool
	db *pgxpool.Pool
}

func (t *eventGet) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	id := StrField(m, "event_id", 64)
	if id == "" {
		return nil, fmt.Errorf("%w: event_id required", ErrInvalidInput)
	}
	var e struct {
		id        string
		at        time.Time
		atType    string
		sev       string
		act       string
		ip        *string
		domain    string
		app       string
		method    string
		path      string
		score     int
		status    *int
		requestID string
		disp      string
	}
	err := t.db.QueryRow(ctx, `
SELECT id, occurred_at, attack_type, severity, action, host(client_ip), domain,
       COALESCE(application_name_snapshot,''), request_method, left(request_path,255),
       anomaly_score, response_status, request_id, disposition_status
FROM security_events WHERE id = $1`, id).Scan(
		&e.id, &e.at, &e.atType, &e.sev, &e.act, &e.ip, &e.domain, &e.app, &e.method, &e.path,
		&e.score, &e.status, &e.requestID, &e.disp)
	if err != nil {
		return nil, fmt.Errorf("event not found")
	}
	matchRows, err := t.db.Query(ctx, `
SELECT rule_id, COALESCE(rule_name,''), COALESCE(message,''), COALESCE(matched_data_masked,'')
FROM security_event_matches WHERE event_id = $1 LIMIT 20`, id)
	if err != nil {
		return nil, err
	}
	defer matchRows.Close()
	matches := []map[string]interface{}{}
	for matchRows.Next() {
		var rid int
		var rname, msg, data string
		if err := matchRows.Scan(&rid, &rname, &msg, &data); err != nil {
			return nil, err
		}
		matches = append(matches, map[string]interface{}{
			"rule_id": rid, "rule_name": rname, "message": msg, "data": audits.MaskSensitiveJSON(data),
		})
	}
	return map[string]interface{}{
		"event_id": e.id, "occurred_at": e.at, "attack_type": e.atType, "severity": e.sev,
		"action": e.act, "client_ip": e.ip, "domain": e.domain, "application": e.app,
		"method": e.method, "path": e.path, "anomaly_score": e.score,
		"response_status": e.status, "request_id": e.requestID, "disposition_status": e.disp,
		"matches": matches,
	}, matchRows.Err()
}

type eventRelated struct {
	baseTool
	db *pgxpool.Pool
}

func (t *eventRelated) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	id := StrField(m, "event_id", 64)
	if id == "" {
		return nil, fmt.Errorf("%w: event_id required", ErrInvalidInput)
	}
	rows, err := t.db.Query(ctx, `
SELECT id, occurred_at, attack_type, severity, action, COALESCE(host(client_ip),''), request_id
FROM security_events
WHERE request_id = (SELECT request_id FROM security_events WHERE id = $1) AND id <> $1
ORDER BY occurred_at LIMIT 20`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var rid, atType, sev, act, ip, reqID string
		var at time.Time
		if err := rows.Scan(&rid, &at, &atType, &sev, &act, &ip, &reqID); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"event_id": rid, "occurred_at": at, "attack_type": atType,
			"severity": sev, "action": act, "client_ip": ip, "request_id": reqID,
		})
	}
	return map[string]interface{}{"items": items}, rows.Err()
}

type eventStats struct {
	baseTool
	db *pgxpool.Pool
}

func (t *eventStats) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	start, end, err := parseTimeRange(m)
	if err != nil {
		return nil, err
	}
	dim := StrField(m, "dimension", 30)
	col := map[string]string{
		"attack_type": "attack_type", "severity": "severity", "action": "action",
		"client_ip":   "host(client_ip)", "application": "COALESCE(application_name_snapshot,'unknown')",
	}[dim]
	if col == "" {
		return nil, fmt.Errorf("%w: invalid dimension", ErrInvalidInput)
	}
	rows, err := t.db.Query(ctx, fmt.Sprintf(`
SELECT %s AS k, count(*) FROM security_events
WHERE occurred_at >= $1 AND occurred_at < $2
GROUP BY k ORDER BY 2 DESC LIMIT 20`, col), start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var k string
		var c int64
		if err := rows.Scan(&k, &c); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{"key": k, "count": c})
	}
	return map[string]interface{}{
		"dimension": dim, "items": items,
		"range": map[string]string{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)},
	}, rows.Err()
}

type eventDisposition struct {
	baseTool
	db *pgxpool.Pool
}

func (t *eventDisposition) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	start, end, err := parseTimeRange(m)
	if err != nil {
		return nil, err
	}
	rows, err := t.db.Query(ctx, `
SELECT disposition_status, count(*) FROM security_events
WHERE occurred_at >= $1 AND occurred_at < $2 GROUP BY 1`, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	dist := map[string]int64{}
	for rows.Next() {
		var s string
		var c int64
		if err := rows.Scan(&s, &c); err != nil {
			return nil, err
		}
		dist[s] = c
	}
	return map[string]interface{}{
		"distribution": dist,
		"range":        map[string]string{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)},
	}, rows.Err()
}

// 辅助构造（schema 简写）。
func obj(props map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"type": "object", "properties": props}
}

func sch(typ, desc string) map[string]interface{} {
	return map[string]interface{}{"type": typ, "description": desc}
}
