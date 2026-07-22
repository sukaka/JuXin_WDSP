// log_tools.go 日志 Tool：访问/WAF/CC/访问控制/审计/系统日志与 Request ID 链路。
package aitools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewLogTools 注册日志 Tool 组。
func NewLogTools(r *Registry, db *pgxpool.Pool) {
	// 访问日志：来自 metric/聚合表摘要（脱敏、限时限量）
	r.Register(&accessLogSearch{baseTool: baseTool{meta: toolMeta{
		code: "access_log.search", name: "访问日志摘要查询", version: "1.0",
		description: "按时间/域名/状态码查询访问聚合摘要（非原始日志全文）",
		risk: RiskReadOnly, permission: "analytics.security.read", timeout: 20, maxResults: 50,
		schema: obj(map[string]interface{}{
			"start_time": sch("string", "起始时间"), "end_time": sch("string", "结束时间"),
			"domain": sch("string", "域名（可选）"), "status_code": sch("integer", "状态码（可选）"),
			"page": sch("integer", "页码"),
		})}}, db: db})
	// WAF 日志：安全事件检索别名（载荷已脱敏）
	r.Register(&wafLogSearch{baseTool: baseTool{meta: toolMeta{
		code: "waf_log.search", name: "WAF日志查询", version: "1.0",
		description: "按时间/IP/规则/动作查询 WAF 安全事件（载荷脱敏）",
		risk: RiskReadOnly, permission: "security_events.read", timeout: 20, maxResults: 50,
		schema: obj(map[string]interface{}{
			"start_time": sch("string", "起始时间"), "end_time": sch("string", "结束时间"),
			"client_ip": sch("string", "IP（可选）"), "rule_id": sch("integer", "规则ID（可选）"),
			"action": sch("string", "BLOCK/OBSERVE（可选）"), "page": sch("integer", "页码"),
		})}}, db: db})
	// CC 日志：访问控制事件中 CC 类型
	r.Register(&ccLogSearch{baseTool: baseTool{meta: toolMeta{
		code: "cc_log.search", name: "CC日志查询", version: "1.0",
		description: "按时间/IP/策略查询 CC 相关访问控制事件",
		risk: RiskReadOnly, permission: "access_control_events.read", timeout: 20, maxResults: 50,
		schema: obj(map[string]interface{}{
			"start_time": sch("string", "起始时间"), "end_time": sch("string", "结束时间"),
			"client_ip": sch("string", "IP（可选）"), "policy_id": sch("string", "策略ID（可选）"),
			"page": sch("integer", "页码"),
		})}}, db: db})
	r.Register(&acEventSearch{baseTool: baseTool{meta: toolMeta{
		code: "access_control_log.search", name: "访问控制/CC事件查询", version: "1.0",
		description: "按时间/类型/IP/策略/RequestID 分页查询访问控制与CC事件",
		risk: RiskReadOnly, permission: "access_control_events.read", timeout: 20, maxResults: 50,
		schema: obj(map[string]interface{}{
			"start_time": sch("string", "起始时间"), "end_time": sch("string", "结束时间"),
			"event_type": sch("string", "事件类型（可选）"), "client_ip": sch("string", "IP（可选）"),
			"policy_id":  sch("string", "策略ID（可选）"), "request_id": sch("string", "Request ID（可选）"),
			"page":       sch("integer", "页码"),
		})}}, db: db})
	r.Register(&auditSearch{baseTool: baseTool{meta: toolMeta{
		code: "audit_log.search", name: "操作审计查询", version: "1.0",
		description: "按时间/用户/模块/动作查询操作审计",
		risk: RiskReadOnly, permission: "audits.read", timeout: 20, maxResults: 50,
		schema: obj(map[string]interface{}{
			"start_time": sch("string", "起始时间"), "end_time": sch("string", "结束时间"),
			"username":   sch("string", "用户名（可选）"), "module": sch("string", "模块（可选）"),
			"action":     sch("string", "动作（可选）"), "page": sch("integer", "页码"),
		})}}, db: db})
	r.Register(&requestTrace{baseTool: baseTool{meta: toolMeta{
		code: "request_trace.get", name: "Request ID 链路追踪", version: "1.0",
		description: "按 Request ID 聚合 WAF 事件与访问控制事件链路",
		risk: RiskReadOnly, permission: "security_events.read", timeout: 15, maxResults: 30,
		schema: obj(map[string]interface{}{"request_id": sch("string", "Request ID")})}}, db: db})
	r.Register(&systemLogSearch{baseTool: baseTool{meta: toolMeta{
		code: "system_log.search", name: "系统告警查询", version: "1.0",
		description: "按时间/类型/等级/组件/状态查询系统告警",
		risk: RiskReadOnly, permission: "system_alerts.read", timeout: 15, maxResults: 50,
		schema: obj(map[string]interface{}{
			"start_time": sch("string", "起始时间"), "end_time": sch("string", "结束时间"),
			"alert_type": sch("string", "告警类型（可选）"), "severity": sch("string", "等级（可选）"),
			"status":     sch("string", "状态（可选）"), "page": sch("integer", "页码"),
		})}}, db: db})
}

// ---------- 访问日志摘要 ----------

type accessLogSearch struct {
	baseTool
	db *pgxpool.Pool
}

func (t *accessLogSearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
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
	// 优先 metric 聚合；无数据时退回安全事件中的访问维度摘要
	where := "bucket_start >= $1 AND bucket_start < $2 AND metric IN ('http_requests_total','http_status_total')"
	args := []interface{}{start, end}
	idx := 3
	if v := StrField(m, "domain", 255); v != "" {
		where += fmt.Sprintf(" AND labels->>'domain' = $%d", idx)
		args = append(args, v)
		idx++
	}
	if sc := IntField(m, "status_code", 0); sc > 0 {
		where += fmt.Sprintf(" AND labels->>'status' = $%d", idx)
		args = append(args, fmt.Sprint(sc))
		idx++
	}
	rows, err := t.db.Query(ctx, `
SELECT bucket_start, metric, COALESCE(labels->>'domain',''), COALESCE(labels->>'status',''), COALESCE(SUM(value),0)
FROM metric_minute_aggregates WHERE `+where+`
GROUP BY bucket_start, metric, labels->>'domain', labels->>'status'
ORDER BY bucket_start DESC LIMIT $`+fmt.Sprint(idx)+` OFFSET $`+fmt.Sprint(idx+1),
		append(args, 30, (page-1)*30)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var b time.Time
		var metric, domain, status string
		var val float64
		if err := rows.Scan(&b, &metric, &domain, &status, &val); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"bucket_start": b, "metric": metric, "domain": domain, "status": status, "value": val,
		})
	}
	return map[string]interface{}{
		"page": page, "items": items, "note": "访问日志以分钟聚合摘要提供，不含完整请求体/Cookie",
		"range": map[string]string{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)},
	}, rows.Err()
}

// ---------- WAF 日志（安全事件） ----------

type wafLogSearch struct {
	baseTool
	db *pgxpool.Pool
}

func (t *wafLogSearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
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
	where := "e.occurred_at >= $1 AND e.occurred_at < $2"
	args := []interface{}{start, end}
	idx := 3
	if v := StrField(m, "client_ip", 45); v != "" {
		where += fmt.Sprintf(" AND e.client_ip = $%d::inet", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "action", 20); v != "" {
		where += fmt.Sprintf(" AND e.action = $%d", idx)
		args = append(args, v)
		idx++
	}
	join := ""
	if rid := IntField(m, "rule_id", 0); rid > 0 {
		join = " JOIN security_event_matches m ON m.event_id = e.id"
		where += fmt.Sprintf(" AND m.rule_id = $%d", idx)
		args = append(args, rid)
		idx++
	}
	rows, err := t.db.Query(ctx, `
SELECT e.id, e.occurred_at, e.attack_type, e.severity, e.action, COALESCE(host(e.client_ip),''),
  e.domain, left(e.request_path,200), COALESCE(e.request_id,'')
FROM security_events e`+join+` WHERE `+where+`
ORDER BY e.occurred_at DESC LIMIT $`+fmt.Sprint(idx)+` OFFSET $`+fmt.Sprint(idx+1),
		append(args, 20, (page-1)*20)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, atType, sev, act, ip, dom, path, rid string
		var at time.Time
		if err := rows.Scan(&id, &at, &atType, &sev, &act, &ip, &dom, &path, &rid); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"event_id": id, "occurred_at": at, "attack_type": atType, "severity": sev,
			"action": act, "client_ip": ip, "domain": dom, "path": path, "request_id": rid,
		})
	}
	return map[string]interface{}{"page": page, "items": items,
		"range": map[string]string{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}}, rows.Err()
}

// ---------- CC 日志 ----------

type ccLogSearch struct {
	baseTool
	db *pgxpool.Pool
}

func (t *ccLogSearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
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
	where := "occurred_at >= $1 AND occurred_at < $2 AND event_type LIKE 'CC%'"
	args := []interface{}{start, end}
	idx := 3
	if v := StrField(m, "client_ip", 45); v != "" {
		where += fmt.Sprintf(" AND client_ip = $%d::inet", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "policy_id", 40); v != "" {
		where += fmt.Sprintf(" AND policy_id = $%d", idx)
		args = append(args, v)
		idx++
	}
	rows, err := t.db.Query(ctx, `
SELECT id, occurred_at, event_type, COALESCE(host(client_ip),''), action,
  COALESCE(policy_id,''), COALESCE(request_id,''), response_status
FROM access_control_events WHERE `+where+` ORDER BY occurred_at DESC
LIMIT $`+fmt.Sprint(idx)+` OFFSET $`+fmt.Sprint(idx+1),
		append(args, 20, (page-1)*20)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, et, ip, act, pol, rid string
		var at time.Time
		var status *int
		if err := rows.Scan(&id, &at, &et, &ip, &act, &pol, &rid, &status); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"event_id": id, "occurred_at": at, "event_type": et, "client_ip": ip,
			"action": act, "policy_id": pol, "request_id": rid, "response_status": status,
		})
	}
	return map[string]interface{}{"page": page, "items": items,
		"range": map[string]string{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}}, rows.Err()
}

type acEventSearch struct {
	baseTool
	db *pgxpool.Pool
}

func (t *acEventSearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
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
	where := "occurred_at >= $1 AND occurred_at < $2"
	args := []interface{}{start, end}
	idx := 3
	if v := StrField(m, "event_type", 40); v != "" {
		where += fmt.Sprintf(" AND event_type = $%d", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "client_ip", 45); v != "" {
		where += fmt.Sprintf(" AND client_ip = $%d::inet", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "policy_id", 40); v != "" {
		where += fmt.Sprintf(" AND policy_id = $%d", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "request_id", 64); v != "" {
		where += fmt.Sprintf(" AND request_id = $%d", idx)
		args = append(args, v)
		idx++
	}
	var total int64
	if err := t.db.QueryRow(ctx, `SELECT count(*) FROM access_control_events WHERE `+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := t.db.Query(ctx, `
SELECT id, occurred_at, event_type, COALESCE(host(client_ip),''), COALESCE(application_code,''),
       action, COALESCE(policy_id,''), COALESCE(access_rule_id,''), COALESCE(request_id,''), response_status
FROM access_control_events WHERE `+where+` ORDER BY occurred_at DESC LIMIT $`+fmt.Sprint(idx)+` OFFSET $`+fmt.Sprint(idx+1),
		append(args, 20, (page-1)*20)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, et, ip, app, act, pol, rule, rid string
		var at time.Time
		var status *int
		if err := rows.Scan(&id, &at, &et, &ip, &app, &act, &pol, &rule, &rid, &status); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"event_id": id, "occurred_at": at, "event_type": et, "client_ip": ip,
			"application": app, "action": act, "policy_id": pol, "rule_id": rule,
			"request_id": rid, "response_status": status,
		})
	}
	return map[string]interface{}{"total": total, "page": page, "items": items,
		"range": map[string]string{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}}, rows.Err()
}

type auditSearch struct {
	baseTool
	db *pgxpool.Pool
}

func (t *auditSearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
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
	where := "occurred_at >= $1 AND occurred_at < $2"
	args := []interface{}{start, end}
	idx := 3
	if v := StrField(m, "username", 64); v != "" {
		where += fmt.Sprintf(" AND username = $%d", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "module", 40); v != "" {
		where += fmt.Sprintf(" AND module = $%d", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "action", 40); v != "" {
		where += fmt.Sprintf(" AND action = $%d", idx)
		args = append(args, v)
		idx++
	}
	var total int64
	if err := t.db.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE `+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := t.db.Query(ctx, `
SELECT id, occurred_at, username, module, action, object_type, object_name, result, risk_level
FROM operation_audits WHERE `+where+` ORDER BY occurred_at DESC LIMIT $`+fmt.Sprint(idx)+` OFFSET $`+fmt.Sprint(idx+1),
		append(args, 20, (page-1)*20)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, u, mod, act, ot, on, res, risk string
		var at time.Time
		if err := rows.Scan(&id, &at, &u, &mod, &act, &ot, &on, &res, &risk); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"id": id, "occurred_at": at, "username": u, "module": mod, "action": act,
			"object_type": ot, "object_name": on, "result": res, "risk_level": risk,
		})
	}
	return map[string]interface{}{"total": total, "page": page, "items": items,
		"range": map[string]string{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}}, rows.Err()
}

type requestTrace struct {
	baseTool
	db *pgxpool.Pool
}

func (t *requestTrace) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	rid := StrField(m, "request_id", 64)
	if rid == "" {
		return nil, fmt.Errorf("%w: request_id required", ErrInvalidInput)
	}
	out := map[string]interface{}{"request_id": rid, "waf_events": []interface{}{}, "access_control_events": []interface{}{}}
	rows, err := t.db.Query(ctx, `
SELECT id, occurred_at, attack_type, severity, action, COALESCE(host(client_ip),''), domain, left(request_path,255)
FROM security_events WHERE request_id = $1 ORDER BY occurred_at LIMIT 10`, rid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var waf []interface{}
	for rows.Next() {
		var id, atType, sev, act, ip, dom, path string
		var at time.Time
		if err := rows.Scan(&id, &at, &atType, &sev, &act, &ip, &dom, &path); err != nil {
			return nil, err
		}
		waf = append(waf, map[string]interface{}{
			"event_id": id, "occurred_at": at, "attack_type": atType, "severity": sev,
			"action": act, "client_ip": ip, "domain": dom, "path": path,
		})
	}
	out["waf_events"] = waf
	rows2, err := t.db.Query(ctx, `
SELECT id, occurred_at, event_type, COALESCE(host(client_ip),''), action, COALESCE(policy_id,'')
FROM access_control_events WHERE request_id = $1 ORDER BY occurred_at LIMIT 10`, rid)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	var ac []interface{}
	for rows2.Next() {
		var id, et, ip, act, pol string
		var at time.Time
		if err := rows2.Scan(&id, &at, &et, &ip, &act, &pol); err != nil {
			return nil, err
		}
		ac = append(ac, map[string]interface{}{
			"event_id": id, "occurred_at": at, "event_type": et, "client_ip": ip,
			"action": act, "policy_id": pol,
		})
	}
	out["access_control_events"] = ac
	return out, nil
}

type systemLogSearch struct {
	baseTool
	db *pgxpool.Pool
}

func (t *systemLogSearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	start, end, err := parseTimeRange(m)
	if err != nil {
		return nil, err
	}
	where := "last_seen_at >= $1 AND last_seen_at < $2"
	args := []interface{}{start, end}
	idx := 3
	if v := StrField(m, "alert_type", 50); v != "" {
		where += fmt.Sprintf(" AND alert_type = $%d", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "severity", 10); v != "" {
		where += fmt.Sprintf(" AND severity = $%d", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "status", 15); v != "" {
		where += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, v)
		idx++
	}
	rows, err := t.db.Query(ctx, `
SELECT id, alert_type, severity, component, title, status, first_seen_at, last_seen_at, occurrence_count
FROM system_alerts WHERE `+where+` ORDER BY last_seen_at DESC LIMIT $`+fmt.Sprint(idx), append(args, 30)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, at, sev, comp, title, st string
		var first, last time.Time
		var cnt int
		if err := rows.Scan(&id, &at, &sev, &comp, &title, &st, &first, &last, &cnt); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"id": id, "alert_type": at, "severity": sev, "component": comp, "title": title,
			"status": st, "first_seen_at": first, "last_seen_at": last, "occurrence_count": cnt,
		})
	}
	return map[string]interface{}{"items": items,
		"range": map[string]string{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}}, rows.Err()
}
