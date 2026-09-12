// jobs.go 分钟/小时/天聚合任务：事件表 → 指标与汇总表，幂等可重算。
package aggregations

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jiuzhang-waf/server/internal/metrics"
)

// Jobs 聚合任务调度器。
type Jobs struct {
	store *Store
}

// NewJobs 创建聚合任务调度器。
func NewJobs(store *Store) *Jobs {
	return &Jobs{store: store}
}

// ---------- 分钟聚合（事件类指标，回看2分钟窗口修正迟到数据） ----------

// RunMinute 执行一分钟聚合（含迟到修正：重算 start 与上一分钟）。
func (j *Jobs) RunMinute(ctx context.Context, now time.Time) error {
	bucket := now.UTC().Truncate(time.Minute)
	total := 0
	for _, b := range []time.Time{bucket.Add(-time.Minute), bucket} {
		n, err := j.aggregateEventsMinute(ctx, b)
		if err != nil {
			_ = j.store.recordJob(ctx, "MINUTE", b, b.Add(time.Minute), "FAILED", n, err.Error())
			return err
		}
		total += n
	}
	return j.store.recordJob(ctx, "MINUTE", bucket.Add(-time.Minute), bucket.Add(time.Minute), "SUCCESS", total, "")
}

// aggregateEventsMinute 聚合指定分钟窗口的事件类指标。
func (j *Jobs) aggregateEventsMinute(ctx context.Context, bucket time.Time) (int, error) {
	start, end := bucket, bucket.Add(time.Minute)
	db := j.store.db
	n := 0

	// WAF 事件（按应用/攻击类型/严重度/动作）
	rows, err := db.Query(ctx, `
SELECT COALESCE(a.code,'unknown'), e.attack_type, e.severity, e.action, count(*)
FROM security_events e LEFT JOIN applications a ON a.id = e.application_id
WHERE e.occurred_at >= $1 AND e.occurred_at < $2
GROUP BY 1,2,3,4`, start, end)
	if err != nil {
		return 0, fmt.Errorf("waf events: %w", err)
	}
	var aggRows []AggRow
	appStats := map[string]*[6]float64{} // app -> [events, blocks, observes, high, 0, 0]
	for rows.Next() {
		var app, at, sev, act string
		var c float64
		if err := rows.Scan(&app, &at, &sev, &act, &c); err != nil {
			rows.Close()
			return 0, err
		}
		aggRows = append(aggRows, AggRow{Metric: metrics.WAFEventsTotal,
			Labels: map[string]string{"app": app, "attack_type": at, "severity": sev, "action": act}, Value: c})
		st := appStats[app]
		if st == nil {
			st = &[6]float64{}
			appStats[app] = st
		}
		st[0] += c
		if act == "BLOCK" {
			st[1] += c
			aggRows = append(aggRows, AggRow{Metric: metrics.WAFBlocksTotal, Labels: map[string]string{"app": app}, Value: c})
		} else {
			st[2] += c
			aggRows = append(aggRows, AggRow{Metric: metrics.WAFObserveTotal, Labels: map[string]string{"app": app}, Value: c})
		}
		if sev == "HIGH" {
			st[3] += c
		}
	}
	rows.Close()

	// CC 与访问控制事件
	rows2, err := db.Query(ctx, `
SELECT COALESCE(application_code,'unknown'), event_type, count(*)
FROM access_control_events
WHERE occurred_at >= $1 AND occurred_at < $2
GROUP BY 1,2`, start, end)
	if err != nil {
		return n, fmt.Errorf("ac events: %w", err)
	}
	for rows2.Next() {
		var app, et string
		var c float64
		if err := rows2.Scan(&app, &et, &c); err != nil {
			rows2.Close()
			return n, err
		}
		var m string
		switch et {
		case "CC_THRESHOLD_EXCEEDED":
			m = metrics.CCExceededTotal
		case "CC_REQUEST_REJECTED":
			m = metrics.CCRejectedTotal
		case "CC_TEMP_BLOCK_CREATED":
			m = metrics.CCTempBlockCreatedTotal
		case "IP_DENY_MATCH":
			m = metrics.IPDenyMatchesTotal
		case "IP_ALLOW_MATCH":
			m = metrics.IPAllowMatchesTotal
		default:
			continue
		}
		aggRows = append(aggRows, AggRow{Metric: m, Labels: map[string]string{"app": app}, Value: c})
	}
	rows2.Close()

	// 规则命中（WAF 匹配明细）
	rows3, err := db.Query(ctx, `
SELECT m.rule_id, COALESCE(e.attack_type,'OTHER'), count(*)
FROM security_event_matches m JOIN security_events e ON e.id = m.event_id AND e.occurred_at >= $1 AND e.occurred_at < $2
WHERE m.rule_id > 0
GROUP BY 1,2`, start, end)
	if err == nil {
		for rows3.Next() {
			var rid int
			var at string
			var c float64
			if err := rows3.Scan(&rid, &at, &c); err != nil {
				break
			}
			aggRows = append(aggRows, AggRow{Metric: "waf_rule_hits_total",
				Labels: map[string]string{"policy": fmt.Sprintf("%d", rid), "attack_type": at}, Value: c})
		}
		rows3.Close()
	}

	// 源 IP 汇总（排行数据源，防首页全表扫描）
	if _, err := db.Exec(ctx, `
INSERT INTO source_ip_summaries (bucket_start, client_ip, waf_events, cc_events, deny_hits, last_seen_at, updated_at)
SELECT $1, client_ip,
  count(*) FILTER (WHERE true),
  0,
  count(*) FILTER (WHERE action = 'BLOCK'),
  max(occurred_at), now()
FROM security_events
WHERE occurred_at >= $2 AND occurred_at < $3 AND client_ip IS NOT NULL
GROUP BY client_ip
ON CONFLICT (bucket_start, client_ip) DO UPDATE SET
  waf_events = EXCLUDED.waf_events, cc_events = EXCLUDED.cc_events,
  deny_hits = EXCLUDED.deny_hits, last_seen_at = EXCLUDED.last_seen_at, updated_at = now()`, bucket, start, end); err != nil {
		return n, fmt.Errorf("source ip summary: %w", err)
	}
	// URI 安全汇总
	if _, err := db.Exec(ctx, `
INSERT INTO uri_security_summaries (bucket_start, application_code, uri_path, waf_events, waf_blocks, cc_events, updated_at)
SELECT $1, COALESCE(a.code,'unknown'), left(request_path, 255),
  count(*), count(*) FILTER (WHERE action = 'BLOCK'), 0, now()
FROM security_events e LEFT JOIN applications a ON a.id = e.application_id
WHERE e.occurred_at >= $2 AND e.occurred_at < $3 AND request_path <> ''
GROUP BY 2, 3
ON CONFLICT (bucket_start, application_code, uri_path) DO UPDATE SET
  waf_events = EXCLUDED.waf_events, waf_blocks = EXCLUDED.waf_blocks,
  cc_events = EXCLUDED.cc_events, updated_at = now()`, bucket, start, end); err != nil {
		return n, fmt.Errorf("uri summary: %w", err)
	}

	w, err := j.store.upsertMinute(ctx, bucket, aggRows)
	n += w
	if err != nil {
		return n, err
	}

	// 应用安全汇总（每分钟全量重算当前分钟）
	for app, st := range appStats {
		_, err := db.Exec(ctx, `
INSERT INTO application_security_summaries (bucket_start, application_id, requests_total, waf_events, waf_blocks, waf_observes, high_severity, updated_at)
SELECT $1, a.id, 0, $2, $3, $4, $5, now() FROM applications a WHERE a.code = $6
ON CONFLICT (bucket_start, application_id) DO UPDATE SET
  waf_events = EXCLUDED.waf_events, waf_blocks = EXCLUDED.waf_blocks,
  waf_observes = EXCLUDED.waf_observes, high_severity = EXCLUDED.high_severity, updated_at = now()`,
			bucket, st[0], st[1], st[2], st[3], app)
		if err != nil {
			return n, fmt.Errorf("app summary: %w", err)
		}
	}
	return n, nil
}

// ---------- 小时聚合（分钟 → 小时，当前小时重算） ----------

// RunHour 执行一小时聚合（重算当前小时与上一小时）。
func (j *Jobs) RunHour(ctx context.Context, now time.Time) error {
	bucket := now.UTC().Truncate(time.Hour)
	total := 0
	for _, b := range []time.Time{bucket.Add(-time.Hour), bucket} {
		n, err := j.rollup(ctx, "metric_minute_aggregates", "metric_hour_aggregates", b, b.Add(time.Hour))
		if err != nil {
			_ = j.store.recordJob(ctx, "HOUR", b, b.Add(time.Hour), "FAILED", n, err.Error())
			return err
		}
		total += n
	}
	return j.store.recordJob(ctx, "HOUR", bucket.Add(-time.Hour), bucket.Add(time.Hour), "SUCCESS", total, "")
}

// ---------- 天聚合（小时 → 天，当天与昨天重算） ----------

// RunDaily 执行一天聚合。
func (j *Jobs) RunDaily(ctx context.Context, now time.Time) error {
	bucket := now.UTC().Truncate(24 * time.Hour)
	total := 0
	for _, b := range []time.Time{bucket.AddDate(0, 0, -1), bucket} {
		n, err := j.rollup(ctx, "metric_hour_aggregates", "metric_daily_aggregates", b, b.Add(24*time.Hour))
		if err != nil {
			_ = j.store.recordJob(ctx, "DAILY", b, b.Add(24*time.Hour), "FAILED", n, err.Error())
			return err
		}
		total += n
	}
	return j.store.recordJob(ctx, "DAILY", bucket.AddDate(0, 0, -1), bucket.Add(24*time.Hour), "SUCCESS", total, "")
}

// RunRuleEffectStats 重算规则版本按日效果统计。当前日与上一日都会重算，
// 以覆盖迟到的事件处置；删除后插入保证任务幂等且支持手工重算。
func (j *Jobs) RunRuleEffectStats(ctx context.Context, now time.Time) error {
	day := now.UTC().Truncate(24 * time.Hour)
	start := day.AddDate(0, 0, -1)
	end := day.AddDate(0, 0, 1)
	tx, err := j.store.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit 成功后回滚为空操作
	if _, err := tx.Exec(ctx, `DELETE FROM rule_statistics_daily WHERE stat_date >= $1::date AND stat_date < $2::date`, start, end); err != nil {
		return fmt.Errorf("delete rule effect statistics: %w", err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO rule_statistics_daily
  (rule_key, rule_id, rule_name, rule_source, rule_version, stat_date,
   observed_count, blocked_count, confirmed_attack_count, confirmed_false_positive_count, unresolved_count, updated_at)
SELECT CONCAT(m.rule_source, ':', m.rule_id::text), m.rule_id, m.rule_name, m.rule_source,
       COALESCE(m.rule_version, ''), (e.occurred_at AT TIME ZONE 'UTC')::date,
       COUNT(*),
       COUNT(*) FILTER (WHERE UPPER(COALESCE(e.action, '')) = 'BLOCK'),
       COUNT(*) FILTER (WHERE e.disposition_status = 'CONFIRMED_ATTACK'),
       COUNT(*) FILTER (WHERE e.disposition_status = 'CONFIRMED_FALSE_POSITIVE'),
       COUNT(*) FILTER (WHERE COALESCE(e.disposition_status, 'UNPROCESSED') NOT IN ('CONFIRMED_ATTACK', 'CONFIRMED_FALSE_POSITIVE')),
       now()
FROM security_event_matches m
JOIN security_events e ON e.id = m.event_id
WHERE e.occurred_at >= $1 AND e.occurred_at < $2
GROUP BY 1, 2, 3, 4, 5, 6
ON CONFLICT (rule_key, rule_version, stat_date) DO UPDATE SET
  rule_id = EXCLUDED.rule_id,
  rule_name = EXCLUDED.rule_name,
  rule_source = EXCLUDED.rule_source,
  observed_count = EXCLUDED.observed_count,
  blocked_count = EXCLUDED.blocked_count,
  confirmed_attack_count = EXCLUDED.confirmed_attack_count,
  confirmed_false_positive_count = EXCLUDED.confirmed_false_positive_count,
  unresolved_count = EXCLUDED.unresolved_count,
  updated_at = now()`, start, end); err != nil {
		return fmt.Errorf("insert rule effect statistics: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit rule effect statistics: %w", err)
	}
	return j.store.recordJob(ctx, "RULE_EFFECT", start, end, "SUCCESS", 0, "")
}

// rollup 下级表 → 上级表重算（Go 内聚合，幂等：先删后插窗口数据）。
func (j *Jobs) rollup(ctx context.Context, srcTable, dstTable string, start, end time.Time) (int, error) {
	db := j.store.db
	rows, err := db.Query(ctx, fmt.Sprintf(`
SELECT metric, labels, value, extra FROM %s WHERE bucket_start >= $1 AND bucket_start < $2`, srcTable), start, end)
	if err != nil {
		return 0, err
	}
	type key struct {
		metric string
		labels string
	}
	merged := map[key]*AggRow{}
	labelMaps := map[key]map[string]string{}
	for rows.Next() {
		var m string
		var lb []byte
		var v float64
		var ex []byte
		if err := rows.Scan(&m, &lb, &v, &ex); err != nil {
			rows.Close()
			return 0, err
		}
		k := key{m, string(lb)}
		r := merged[k]
		if r == nil {
			r = &AggRow{Metric: m, Value: 0, Extra: map[string]interface{}{}}
			merged[k] = r
			var lm map[string]string
			_ = json.Unmarshal(lb, &lm)
			r.Labels = lm
			labelMaps[k] = lm
		}
		r.Value += v
		// 合并直方图桶
		var exm map[string]interface{}
		if json.Unmarshal(ex, &exm) == nil {
			if buckets, ok := exm["buckets"].([]interface{}); ok {
				cur, _ := r.Extra["buckets"].([]int)
				if len(cur) == 0 {
					cur = make([]int, len(buckets))
				}
				for i, b := range buckets {
					if f, ok := b.(float64); ok {
						cur[i] += int(f)
					}
				}
				r.Extra["buckets"] = cur
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE bucket_start = $1`, dstTable), start); err != nil {
		return 0, err
	}
	n := 0
	for _, r := range merged {
		var extra []byte
		if b, ok := r.Extra["buckets"]; ok {
			extra, _ = json.Marshal(map[string]interface{}{"buckets": b})
		} else {
			extra = []byte("{}")
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(`
INSERT INTO %s (bucket_start, metric, labels, value, extra, updated_at)
VALUES ($1, $2, $3, $4, $5, now())`, dstTable),
			start, r.Metric, labelsJSON(r.Labels), r.Value, extra); err != nil {
			return n, err
		}
		n++
	}
	return n, tx.Commit(ctx)
}

// Run 周期调度（分钟任务每分钟，小时任务每小时，天任务每小时顺便）。
func (j *Jobs) Run(ctx context.Context) {
	minuteT := time.NewTicker(time.Minute)
	hourT := time.NewTicker(time.Hour)
	defer minuteT.Stop()
	defer hourT.Stop()
	slog.Info("aggregation jobs started")
	for {
		select {
		case <-ctx.Done():
			return
		case <-minuteT.C:
			if err := j.RunMinute(ctx, time.Now()); err != nil {
				slog.Error("minute aggregation failed", "error", err)
			}
			// API 调用边派生（api_runtime_events → api_call_edges，P1-09/10；轻量水位增量）
			if _, err := j.RunCallEdges(ctx); err != nil {
				slog.Error("call edge sweep failed", "error", err)
			}
			// APM 阶段1：端点级 RED 分钟聚合（access_logs → metric_minute_aggregates，ADR D7/D9）
			if err := j.RunEndpointRED(ctx, time.Now()); err != nil {
				slog.Error("endpoint red aggregation failed", "error", err)
			}
		case <-hourT.C:
			if err := j.RunHour(ctx, time.Now()); err != nil {
				slog.Error("hour aggregation failed", "error", err)
			}
			if err := j.RunDaily(ctx, time.Now()); err != nil {
				slog.Error("daily aggregation failed", "error", err)
			}
			if err := j.RunRuleEffectStats(ctx, time.Now()); err != nil {
				slog.Error("rule effect statistics aggregation failed", "error", err)
			}
			// WDSP 访问微模型：API 行为基线画像离线聚合（api_runtime_events → api_behavior_profiles）
			if err := j.RunBehaviorProfiles(ctx, time.Now()); err != nil {
				slog.Error("behavior profile aggregation failed", "error", err)
			}
			// WDSP 身份微模型：身份画像聚合（api_runtime_events → api_identity_profiles）
			if err := j.RunIdentityProfiles(ctx, time.Now()); err != nil {
				slog.Error("identity profile aggregation failed", "error", err)
			}
			// WDSP 接口流量趋势：清理 7 天前的流量桶（api_endpoint_traffic_buckets 留存窗口）
			if err := j.RunTrafficBucketCleanup(ctx, time.Now()); err != nil {
				slog.Error("traffic bucket cleanup failed", "error", err)
			}
		}
	}
}
