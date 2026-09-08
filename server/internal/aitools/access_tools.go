// access_tools.go 访问控制与统计 Tool：黑白名单/临时封禁/CC策略/可信代理/统计概览。
package aitools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewAccessTools 注册访问控制与统计 Tool 组。
func NewAccessTools(r *Registry, db *pgxpool.Pool) {
	r.Register(&accessRuleSearch{baseTool: baseTool{meta: toolMeta{
		code: "access_rule.search", name: "黑白名单查询", version: "1.0",
		description: "按类型/范围/状态查询IP黑白名单规则",
		risk:        RiskReadOnly, permission: "access_rules.read", timeout: 15, maxResults: 50,
		schema: obj(map[string]interface{}{
			"rule_type": sch("string", "ALLOW/DENY（可选）"), "scope_type": sch("string", "GLOBAL/APPLICATION（可选）"),
			"status": sch("string", "状态（可选）"), "page": sch("integer", "页码"),
		})}}, db: db})
	r.Register(&tempBlockSearch{baseTool: baseTool{meta: toolMeta{
		code: "temporary_block.search", name: "临时封禁查询", version: "1.0",
		description: "按状态/IP查询临时封禁",
		risk:        RiskReadOnly, permission: "temporary_blocks.read", timeout: 15, maxResults: 50,
		schema: obj(map[string]interface{}{
			"status": sch("string", "状态（可选）"), "client_ip": sch("string", "IP（可选）"),
			"page": sch("integer", "页码"),
		})}}, db: db})
	r.Register(&ccPolicySearch{baseTool: baseTool{meta: toolMeta{
		code: "rate_limit_policy.search", name: "CC策略查询", version: "1.0",
		description: "按范围/状态/动作查询CC防护策略",
		risk:        RiskReadOnly, permission: "rate_limits.read", timeout: 15, maxResults: 50,
		schema: obj(map[string]interface{}{
			"scope_type": sch("string", "范围（可选）"), "status": sch("string", "状态（可选）"),
			"action": sch("string", "动作（可选）"), "page": sch("integer", "页码"),
		})}}, db: db})
	r.Register(&trustedProxySummary{baseTool: baseTool{meta: toolMeta{
		code: "trusted_proxy.get_summary", name: "可信代理摘要", version: "1.0",
		description: "可信代理数量与启停摘要",
		risk:        RiskReadOnly, permission: "trusted_proxies.read", timeout: 10, maxResults: 10,
		schema: obj(map[string]interface{}{})}}, db: db})
	r.Register(&securityOverview{baseTool: baseTool{meta: toolMeta{
		code: "statistics.security_overview", name: "安全概览统计", version: "1.0",
		description: "今日请求/事件/阻断/CC/黑名单命中与未处置统计",
		risk:        RiskReadOnly, permission: "analytics.security.read", timeout: 30, maxResults: 1,
		schema: obj(map[string]interface{}{})}}, db: db})
	r.Register(&attackTrend{baseTool: baseTool{meta: toolMeta{
		code: "statistics.attack_trend", name: "攻击趋势统计", version: "1.0",
		description: "按时间桶统计攻击事件趋势",
		risk:        RiskReadOnly, permission: "analytics.security.read", timeout: 30, maxResults: 200,
		schema: obj(map[string]interface{}{
			"start_time": sch("string", "起始时间"), "end_time": sch("string", "结束时间"),
			"bucket": sch("string", "hour|day"),
		})}}, db: db})
	r.Register(&topSourceIPs{baseTool: baseTool{meta: toolMeta{
		code: "statistics.top_source_ips", name: "攻击源IP排行", version: "1.0",
		description: "按时间范围统计攻击源IP排行",
		risk:        RiskReadOnly, permission: "analytics.security.read", timeout: 30, maxResults: 20,
		schema: obj(map[string]interface{}{
			"start_time": sch("string", "起始时间"), "end_time": sch("string", "结束时间"),
			"limit": sch("integer", "数量"),
		})}}, db: db})
	r.Register(&topRules{baseTool: baseTool{meta: toolMeta{
		code: "statistics.top_rules", name: "规则命中排行", version: "1.0",
		description: "按时间范围统计规则命中与误报排行",
		risk:        RiskReadOnly, permission: "analytics.security.read", timeout: 30, maxResults: 20,
		schema: obj(map[string]interface{}{
			"start_time": sch("string", "起始时间"), "end_time": sch("string", "结束时间"),
			"limit": sch("integer", "数量"),
		})}}, db: db})
	r.Register(&topApplications{baseTool: baseTool{meta: toolMeta{
		code: "statistics.top_applications", name: "应用攻击排行", version: "1.0",
		description: "按时间范围统计受攻击应用排行",
		risk:        RiskReadOnly, permission: "analytics.security.read", timeout: 30, maxResults: 20,
		schema: obj(map[string]interface{}{
			"start_time": sch("string", "起始时间"), "end_time": sch("string", "结束时间"),
			"limit": sch("integer", "数量"),
		})}}, db: db})
	r.Register(&topURIs{baseTool: baseTool{meta: toolMeta{
		code: "statistics.top_uris", name: "URI攻击排行", version: "1.0",
		description: "按时间范围统计高风险URI排行",
		risk:        RiskReadOnly, permission: "analytics.security.read", timeout: 30, maxResults: 20,
		schema: obj(map[string]interface{}{
			"start_time": sch("string", "起始时间"), "end_time": sch("string", "结束时间"),
			"limit": sch("integer", "数量"),
		})}}, db: db})
	r.Register(&falsePositiveStats{baseTool: baseTool{meta: toolMeta{
		code: "statistics.false_positive", name: "误报统计", version: "1.0",
		description: "按时间范围统计误报数量与占比",
		risk:        RiskReadOnly, permission: "analytics.security.read", timeout: 30, maxResults: 10,
		schema: obj(map[string]interface{}{
			"start_time": sch("string", "起始时间"), "end_time": sch("string", "结束时间"),
		})}}, db: db})
	r.Register(&runtimeStats{baseTool: baseTool{meta: toolMeta{
		code: "statistics.runtime", name: "运行统计", version: "1.0",
		description: "组件健康快照与发布/报告成功率统计",
		risk:        RiskReadOnly, permission: "dashboard.runtime.read", timeout: 20, maxResults: 20,
		schema: obj(map[string]interface{}{})}}, db: db})
}

type accessRuleSearch struct {
	baseTool
	db *pgxpool.Pool
}

func (t *accessRuleSearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	where := "deleted_at IS NULL"
	args := []interface{}{}
	idx := 1
	if v := StrField(m, "rule_type", 10); v != "" {
		where += fmt.Sprintf(" AND rule_type = $%d", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "scope_type", 15); v != "" {
		where += fmt.Sprintf(" AND scope_type = $%d", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "status", 15); v != "" {
		where += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, v)
		idx++
	}
	page := IntField(m, "page", 1)
	if page < 1 {
		page = 1
	}
	rows, err := t.db.Query(ctx, `
SELECT id, name, rule_type, scope_type, address, status, validity_type, hit_count, created_at
FROM ip_access_rules WHERE `+where+` ORDER BY priority LIMIT $`+fmt.Sprint(idx)+` OFFSET $`+fmt.Sprint(idx+1),
		append(args, 20, (page-1)*20)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, name, rt, sc, addr, st, vt string
		var hits int64
		var at time.Time
		if err := rows.Scan(&id, &name, &rt, &sc, &addr, &st, &vt, &hits, &at); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"rule_id": id, "name": name, "rule_type": rt, "scope_type": sc, "address": addr,
			"status": st, "validity_type": vt, "hit_count": hits, "created_at": at,
		})
	}
	return map[string]interface{}{"page": page, "items": items}, rows.Err()
}

type tempBlockSearch struct {
	baseTool
	db *pgxpool.Pool
}

func (t *tempBlockSearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	where := "1=1"
	args := []interface{}{}
	idx := 1
	if v := StrField(m, "status", 20); v != "" {
		where += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "client_ip", 45); v != "" {
		where += fmt.Sprintf(" AND client_ip = $%d::inet", idx)
		args = append(args, v)
		idx++
	}
	page := IntField(m, "page", 1)
	if page < 1 {
		page = 1
	}
	rows, err := t.db.Query(ctx, `
SELECT id, host(client_ip), trigger_type, block_started_at, block_expires_at, status, hit_count
FROM temporary_blocks WHERE `+where+` ORDER BY block_started_at DESC LIMIT $`+fmt.Sprint(idx)+` OFFSET $`+fmt.Sprint(idx+1),
		append(args, 20, (page-1)*20)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, ip, tt, st string
		var started, expires time.Time
		var hits int64
		if err := rows.Scan(&id, &ip, &tt, &started, &expires, &st, &hits); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"block_id": id, "client_ip": ip, "trigger_type": tt, "block_started_at": started,
			"block_expires_at": expires, "status": st, "hit_count": hits,
		})
	}
	return map[string]interface{}{"page": page, "items": items}, rows.Err()
}

type ccPolicySearch struct {
	baseTool
	db *pgxpool.Pool
}

func (t *ccPolicySearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	where := "deleted_at IS NULL"
	args := []interface{}{}
	idx := 1
	if v := StrField(m, "scope_type", 15); v != "" {
		where += fmt.Sprintf(" AND scope_type = $%d", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "status", 15); v != "" {
		where += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "action", 15); v != "" {
		where += fmt.Sprintf(" AND action = $%d", idx)
		args = append(args, v)
		idx++
	}
	page := IntField(m, "page", 1)
	if page < 1 {
		page = 1
	}
	rows, err := t.db.Query(ctx, `
SELECT id, name, scope_type, dimension, algorithm, requests_limit, window_seconds, action, status, priority
FROM rate_limit_policies WHERE `+where+` ORDER BY priority LIMIT $`+fmt.Sprint(idx)+` OFFSET $`+fmt.Sprint(idx+1),
		append(args, 20, (page-1)*20)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, name, sc, dim, algo, act, st string
		var limit, win, prio int
		if err := rows.Scan(&id, &name, &sc, &dim, &algo, &limit, &win, &act, &st, &prio); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"policy_id": id, "name": name, "scope_type": sc, "dimension": dim, "algorithm": algo,
			"requests_limit": limit, "window_seconds": win, "action": act, "status": st, "priority": prio,
		})
	}
	return map[string]interface{}{"page": page, "items": items}, rows.Err()
}

type trustedProxySummary struct {
	baseTool
	db *pgxpool.Pool
}

func (t *trustedProxySummary) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var total, enabled int64
	_ = t.db.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE status='ENABLED') FROM trusted_proxies WHERE deleted_at IS NULL`).Scan(&total, &enabled)
	return map[string]interface{}{"total": total, "enabled": enabled}, nil
}

type securityOverview struct {
	baseTool
	db *pgxpool.Pool
}

func (t *securityOverview) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	out := map[string]interface{}{"date": today.Format("2006-01-02")}
	var v int64
	_ = t.db.QueryRow(ctx, `SELECT COALESCE(SUM(value),0) FROM metric_minute_aggregates
		WHERE metric='http_requests_total' AND bucket_start >= $1`, today).Scan(&v)
	out["requests_total"] = v
	_ = t.db.QueryRow(ctx, `SELECT count(*) FROM security_events WHERE occurred_at >= $1`, today).Scan(&v)
	out["waf_events"] = v
	_ = t.db.QueryRow(ctx, `SELECT count(*) FROM security_events WHERE occurred_at >= $1 AND action='BLOCK'`, today).Scan(&v)
	out["waf_blocks"] = v
	_ = t.db.QueryRow(ctx, `SELECT count(*) FROM access_control_events WHERE occurred_at >= $1 AND event_type LIKE 'CC%'`, today).Scan(&v)
	out["cc_events"] = v
	_ = t.db.QueryRow(ctx, `SELECT count(*) FROM access_control_events WHERE occurred_at >= $1 AND event_type='IP_DENY_MATCH'`, today).Scan(&v)
	out["ip_deny_matches"] = v
	_ = t.db.QueryRow(ctx, `SELECT count(*) FROM temporary_blocks WHERE status='ACTIVE' AND block_expires_at > now()`).Scan(&v)
	out["temp_blocked_ips"] = v
	_ = t.db.QueryRow(ctx, `SELECT count(*) FROM security_events WHERE disposition_status='UNPROCESSED' AND severity='HIGH'`).Scan(&v)
	out["unprocessed_high"] = v
	return out, nil
}

type attackTrend struct {
	baseTool
	db *pgxpool.Pool
}

func (t *attackTrend) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	start, end, err := parseTimeRange(m)
	if err != nil {
		return nil, err
	}
	bucket := StrField(m, "bucket", 10)
	if bucket != "day" {
		bucket = "hour"
	}
	rows, err := t.db.Query(ctx, fmt.Sprintf(`
SELECT date_trunc('%s', occurred_at) AS b, count(*), count(*) FILTER (WHERE action='BLOCK')
FROM security_events WHERE occurred_at >= $1 AND occurred_at < $2
GROUP BY b ORDER BY b`, bucket), start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var times, events, blocks []interface{}
	for rows.Next() {
		var b time.Time
		var e, bl int64
		if err := rows.Scan(&b, &e, &bl); err != nil {
			return nil, err
		}
		times = append(times, b)
		events = append(events, e)
		blocks = append(blocks, bl)
	}
	return map[string]interface{}{
		"bucket": bucket, "times": times, "events": events, "blocks": blocks,
		"range": map[string]string{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)},
	}, rows.Err()
}

type topSourceIPs struct {
	baseTool
	db *pgxpool.Pool
}

func (t *topSourceIPs) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	start, end, err := parseTimeRange(m)
	if err != nil {
		return nil, err
	}
	limit := IntField(m, "limit", 10)
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := t.db.Query(ctx, `
SELECT host(client_ip) AS ip, count(*), count(*) FILTER (WHERE action='BLOCK')
FROM security_events WHERE occurred_at >= $1 AND occurred_at < $2 AND client_ip IS NOT NULL
GROUP BY ip ORDER BY 2 DESC LIMIT $3`, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var ip string
		var e, b int64
		if err := rows.Scan(&ip, &e, &b); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{"ip": ip, "events": e, "blocks": b})
	}
	return map[string]interface{}{"items": items,
		"range": map[string]string{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}}, rows.Err()
}

type topRules struct {
	baseTool
	db *pgxpool.Pool
}

func (t *topRules) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	start, end, err := parseTimeRange(m)
	if err != nil {
		return nil, err
	}
	limit := IntField(m, "limit", 10)
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := t.db.Query(ctx, `
SELECT m.rule_id, count(*) AS hits,
  count(*) FILTER (WHERE e.disposition_status='CONFIRMED_FALSE_POSITIVE') AS fps
FROM security_event_matches m JOIN security_events e ON e.id = m.event_id AND e.occurred_at >= $1 AND e.occurred_at < $2
WHERE m.rule_id > 0
GROUP BY m.rule_id ORDER BY hits DESC LIMIT $3`, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var rid int
		var hits, fps int64
		if err := rows.Scan(&rid, &hits, &fps); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{"rule_id": rid, "hits": hits, "false_positives": fps})
	}
	return map[string]interface{}{"items": items,
		"range": map[string]string{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}}, rows.Err()
}

type topApplications struct {
	baseTool
	db *pgxpool.Pool
}

func (t *topApplications) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	start, end, err := parseTimeRange(m)
	if err != nil {
		return nil, err
	}
	limit := IntField(m, "limit", 10)
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := t.db.Query(ctx, `
SELECT COALESCE(NULLIF(application_name_snapshot,''), application_id::text, 'unknown'), count(*),
  count(*) FILTER (WHERE action='BLOCK')
FROM security_events WHERE occurred_at >= $1 AND occurred_at < $2
GROUP BY 1 ORDER BY 2 DESC LIMIT $3`, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var app string
		var e, b int64
		if err := rows.Scan(&app, &e, &b); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{"application": app, "events": e, "blocks": b})
	}
	return map[string]interface{}{"items": items,
		"range": map[string]string{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}}, rows.Err()
}

type topURIs struct {
	baseTool
	db *pgxpool.Pool
}

func (t *topURIs) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	start, end, err := parseTimeRange(m)
	if err != nil {
		return nil, err
	}
	limit := IntField(m, "limit", 10)
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := t.db.Query(ctx, `
SELECT left(request_path, 200), count(*), count(*) FILTER (WHERE action='BLOCK')
FROM security_events WHERE occurred_at >= $1 AND occurred_at < $2 AND request_path <> ''
GROUP BY 1 ORDER BY 2 DESC LIMIT $3`, start, end, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var uri string
		var e, b int64
		if err := rows.Scan(&uri, &e, &b); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{"uri": uri, "events": e, "blocks": b})
	}
	return map[string]interface{}{"items": items,
		"range": map[string]string{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}}, rows.Err()
}

type falsePositiveStats struct {
	baseTool
	db *pgxpool.Pool
}

func (t *falsePositiveStats) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	start, end, err := parseTimeRange(m)
	if err != nil {
		return nil, err
	}
	var total, fps int64
	if err := t.db.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE disposition_status='CONFIRMED_FALSE_POSITIVE')
FROM security_events WHERE occurred_at >= $1 AND occurred_at < $2`, start, end).Scan(&total, &fps); err != nil {
		return nil, err
	}
	rate := 0.0
	if total > 0 {
		rate = float64(fps) * 100 / float64(total)
	}
	return map[string]interface{}{
		"total_events": total, "false_positives": fps, "false_positive_rate_pct": rate,
		"range": map[string]string{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)},
	}, nil
}

type runtimeStats struct {
	baseTool
	db *pgxpool.Pool
}

func (t *runtimeStats) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	rows, err := t.db.Query(ctx, `
SELECT DISTINCT ON (component) component, status, taken_at FROM system_health_snapshots
ORDER BY component, taken_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	comps := []map[string]interface{}{}
	for rows.Next() {
		var c, s string
		var at time.Time
		if err := rows.Scan(&c, &s, &at); err != nil {
			return nil, err
		}
		comps = append(comps, map[string]interface{}{"component": c, "status": s, "taken_at": at})
	}
	var total, success int64
	_ = t.db.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE status='SUCCESS') FROM gateway_publish_tasks WHERE requested_at > now() - interval '30 days'`).Scan(&total, &success)
	return map[string]interface{}{
		"components": comps,
		"publish":    map[string]interface{}{"total_30d": total, "success_30d": success},
	}, rows.Err()
}
