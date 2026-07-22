package reports

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/metrics"
)

// CollectInput 采集输入。
type CollectInput struct {
	ReportType     string
	Start          time.Time
	End            time.Time
	ApplicationIDs []uuid.UUID // 空 = 全部应用
}

// KV 通用计数对。
type KV struct {
	Key   string `json:"key"`
	Value int64  `json:"value"`
}

// Point 时间序列点。
type Point struct {
	Time  time.Time `json:"time"`
	Value int64     `json:"value"`
}

// AppInfo 应用范围信息。
type AppInfo struct {
	ID   uuid.UUID `json:"id"`
	Code string    `json:"code"`
	Name string    `json:"name"`
}

// RuleHit 规则命中统计。
type RuleHit struct {
	RuleID   int    `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Hits     int64  `json:"hits"`
}

// UpstreamHealth 源站健康状态。
type UpstreamHealth struct {
	Name           string     `json:"name"`
	Address        string     `json:"address"`
	Status         string     `json:"status"`
	CheckedAt      *time.Time `json:"checked_at"`
	ResponseTimeMs *int       `json:"response_time_ms"`
}

// CertStatus 证书状态。
type CertStatus struct {
	Name          string     `json:"name"`
	CommonName    string     `json:"common_name"`
	Status        string     `json:"status"`
	NotAfter      *time.Time `json:"not_after"`
	DaysRemaining int        `json:"days_remaining"`
}

// PublishItem 发布任务摘要。
type PublishItem struct {
	TaskType    string    `json:"task_type"`
	Status      string    `json:"status"`
	RequestedAt time.Time `json:"requested_at"`
	Summary     string    `json:"summary"`
}

// PublishSummary 发布统计。
type PublishSummary struct {
	Total   int64         `json:"total"`
	Success int64         `json:"success"`
	Failed  int64         `json:"failed"`
	Running int64         `json:"running"`
	Recent  []PublishItem `json:"recent"`
}

// ComponentHealth 系统组件健康状态。
type ComponentHealth struct {
	Component string    `json:"component"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	TakenAt   time.Time `json:"taken_at"`
}

// ReportData 报告统计数据（21节所需全部内容，均为聚合统计，不含未脱敏载荷）。
type ReportData struct {
	ReportType  string    `json:"report_type"`
	RangeStart  time.Time `json:"range_start"`
	RangeEnd    time.Time `json:"range_end"`
	GeneratedAt time.Time `json:"generated_at"`
	ScopeAll    bool      `json:"scope_all"`

	Applications []AppInfo `json:"applications"`

	// 请求流量
	TotalRequests int64   `json:"total_requests"`
	RequestsTrend []Point `json:"requests_trend"`

	// 安全事件总览
	EventsTotal    int64  `json:"events_total"`
	EventsBlocked  int64  `json:"events_blocked"`
	EventsObserved int64  `json:"events_observed"`
	HighSeverity   int64  `json:"high_severity"`
	RiskLevel      string `json:"risk_level"` // LOW / MEDIUM / HIGH / CRITICAL（确定性规则）

	SeverityDist []KV      `json:"severity_dist"`
	AttackTypes  []KV      `json:"attack_types"`
	AttackTrend  []Point   `json:"attack_trend"`
	TopSourceIPs []KV      `json:"top_source_ips"`
	AttackedApps []KV      `json:"attacked_apps"`
	TopRules     []RuleHit `json:"top_rules"`

	// CC防护 / 黑白名单
	CCExceeded   int64 `json:"cc_exceeded"`
	CCRejected   int64 `json:"cc_rejected"`
	CCTempBlocks int64 `json:"cc_temp_blocks"`
	IPAllowHits  int64 `json:"ip_allow_hits"`
	IPDenyHits   int64 `json:"ip_deny_hits"`

	// 事件处置 / 误报和例外
	Dispositions      []KV  `json:"dispositions"`
	Unprocessed       int64 `json:"unprocessed"`
	FalsePositives    int64 `json:"false_positives"`
	ExceptionsCreated int64 `json:"exceptions_created"`

	// 源站健康 / 证书 / 发布 / 系统
	Upstreams    []UpstreamHealth  `json:"upstreams"`
	Certificates []CertStatus      `json:"certificates"`
	Publish      PublishSummary    `json:"publish"`
	Components   []ComponentHealth `json:"components"`

	// 结论和建议（确定性模板规则）
	Conclusions []string `json:"conclusions"`
	Suggestions []string `json:"suggestions"`
}

// Collector 报告数据采集器。
type Collector struct {
	db  *pgxpool.Pool
	agg *aggregations.Store
}

// NewCollector 创建采集器。
func NewCollector(db *pgxpool.Pool, agg *aggregations.Store) *Collector {
	return &Collector{db: db, agg: agg}
}

// chooseAggTable 按时间跨度选择聚合表（>7天用天表，否则用小时表）。
func chooseAggTable(start, end time.Time) string {
	if end.Sub(start) > 7*24*time.Hour {
		return "metric_daily_aggregates"
	}
	return "metric_hour_aggregates"
}

// chooseTrendUnit 按时间跨度选择趋势粒度（>2天按天，否则按小时）。
func chooseTrendUnit(start, end time.Time) string {
	if end.Sub(start) > 2*24*time.Hour {
		return "day"
	}
	return "hour"
}

// computeRiskLevel 由统计数据确定性推导风险等级。
func computeRiskLevel(d *ReportData) string {
	if d.EventsTotal == 0 {
		return "LOW"
	}
	// 存在高危事件且未被阻断 → 最高风险
	if d.HighSeverity > 0 && d.EventsBlocked == 0 {
		return "CRITICAL"
	}
	if d.HighSeverity > 100 || float64(d.HighSeverity)/float64(d.EventsTotal) > 0.3 {
		return "HIGH"
	}
	if d.HighSeverity > 0 || d.EventsTotal > 1000 {
		return "MEDIUM"
	}
	return "LOW"
}

// Collect 采集报告数据。任何一步失败都返回明确错误（不静默吞错）。
func (c *Collector) Collect(ctx context.Context, in CollectInput) (*ReportData, error) {
	d := &ReportData{
		ReportType:  in.ReportType,
		RangeStart:  in.Start.UTC(),
		RangeEnd:    in.End.UTC(),
		GeneratedAt: time.Now().UTC(),
		ScopeAll:    len(in.ApplicationIDs) == 0,
	}
	appIDs := in.ApplicationIDs

	// 1. 应用范围
	apps, err := c.collectApplications(ctx, appIDs)
	if err != nil {
		return nil, fmt.Errorf("collect applications: %w", err)
	}
	d.Applications = apps
	appCodes := make([]string, 0, len(apps))
	for _, a := range apps {
		appCodes = append(appCodes, a.Code)
	}

	// 2. 请求流量（聚合表）
	if err := c.collectTraffic(ctx, d, appCodes); err != nil {
		return nil, fmt.Errorf("collect traffic: %w", err)
	}

	// 3. 安全事件（原始表）
	if err := c.collectEvents(ctx, d, appIDs); err != nil {
		return nil, fmt.Errorf("collect events: %w", err)
	}

	// 4. CC / 黑白名单（访问控制事件表）
	if err := c.collectAccessControl(ctx, d, appIDs); err != nil {
		return nil, fmt.Errorf("collect access control: %w", err)
	}

	// 5. 误报和例外
	if err := c.collectExceptions(ctx, d); err != nil {
		return nil, fmt.Errorf("collect exceptions: %w", err)
	}

	// 6. 源站健康
	if err := c.collectUpstreams(ctx, d, appIDs); err != nil {
		return nil, fmt.Errorf("collect upstreams: %w", err)
	}

	// 7. 证书状态
	if err := c.collectCertificates(ctx, d, appIDs); err != nil {
		return nil, fmt.Errorf("collect certificates: %w", err)
	}

	// 8. 策略发布
	if err := c.collectPublishTasks(ctx, d); err != nil {
		return nil, fmt.Errorf("collect publish tasks: %w", err)
	}

	// 9. 系统运行
	if err := c.collectSystemHealth(ctx, d); err != nil {
		return nil, fmt.Errorf("collect system health: %w", err)
	}

	// 10. 风险等级与结论建议（确定性规则）
	d.RiskLevel = computeRiskLevel(d)
	d.Conclusions = BuildConclusions(d)
	d.Suggestions = BuildSuggestions(d)
	return d, nil
}

// collectApplications 查询报告覆盖的应用。
func (c *Collector) collectApplications(ctx context.Context, appIDs []uuid.UUID) ([]AppInfo, error) {
	query := `SELECT id, code, name FROM applications WHERE deleted_at IS NULL`
	args := []interface{}{}
	if len(appIDs) > 0 {
		query += ` AND id = ANY($1)`
		args = append(args, appIDs)
	}
	query += ` ORDER BY name`
	rows, err := c.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppInfo
	for rows.Next() {
		var a AppInfo
		if err := rows.Scan(&a.ID, &a.Code, &a.Name); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// collectTraffic 请求流量（聚合表 http_requests_total）。
func (c *Collector) collectTraffic(ctx context.Context, d *ReportData, appCodes []string) error {
	table := chooseAggTable(d.RangeStart, d.RangeEnd)
	where := `metric = $1 AND bucket_start >= $2 AND bucket_start < $3`
	args := []interface{}{metrics.HTTPRequestsTotal, d.RangeStart, d.RangeEnd}
	// 应用过滤：聚合标签 app = 应用 code；未给应用范围则统计全部
	if !d.ScopeAll {
		where += ` AND labels->>'app' = ANY($4)`
		args = append(args, appCodes)
	}
	// 总量
	if err := c.db.QueryRow(ctx,
		fmt.Sprintf(`SELECT COALESCE(SUM(value),0) FROM %s WHERE %s`, table, where), args...).
		Scan(&d.TotalRequests); err != nil {
		return err
	}
	// 趋势
	rows, err := c.db.Query(ctx,
		fmt.Sprintf(`SELECT bucket_start, SUM(value) FROM %s WHERE %s GROUP BY 1 ORDER BY 1`, table, where), args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var t time.Time
		var v float64
		if err := rows.Scan(&t, &v); err != nil {
			return err
		}
		d.RequestsTrend = append(d.RequestsTrend, Point{Time: t, Value: int64(v)})
	}
	return rows.Err()
}

// collectEvents 安全事件统计（security_events 原始表 + 规则命中）。
func (c *Collector) collectEvents(ctx context.Context, d *ReportData, appIDs []uuid.UUID) error {
	where := `occurred_at >= $1 AND occurred_at < $2`
	args := []interface{}{d.RangeStart, d.RangeEnd}
	idx := 3
	if len(appIDs) > 0 {
		where += fmt.Sprintf(` AND application_id = ANY($%d)`, idx)
		args = append(args, appIDs)
		idx++
	}

	// 总览
	err := c.db.QueryRow(ctx, fmt.Sprintf(`
SELECT count(*),
       count(*) FILTER (WHERE action = 'BLOCK'),
       count(*) FILTER (WHERE action <> 'BLOCK'),
       count(*) FILTER (WHERE severity = 'HIGH' OR severity = 'CRITICAL')
FROM security_events WHERE %s`, where), args...).
		Scan(&d.EventsTotal, &d.EventsBlocked, &d.EventsObserved, &d.HighSeverity)
	if err != nil {
		return err
	}

	// 严重度分布
	d.SeverityDist, err = c.groupCount(ctx,
		fmt.Sprintf(`SELECT severity, count(*) FROM security_events WHERE %s GROUP BY 1 ORDER BY 2 DESC`, where), args...)
	if err != nil {
		return err
	}

	// 攻击类型 TOP10
	d.AttackTypes, err = c.groupCount(ctx,
		fmt.Sprintf(`SELECT attack_type, count(*) FROM security_events WHERE %s GROUP BY 1 ORDER BY 2 DESC LIMIT 10`, where), args...)
	if err != nil {
		return err
	}

	// 攻击趋势
	unit := chooseTrendUnit(d.RangeStart, d.RangeEnd)
	rows, err := c.db.Query(ctx, fmt.Sprintf(`
SELECT date_trunc('%s', occurred_at), count(*) FROM security_events WHERE %s
GROUP BY 1 ORDER BY 1`, unit, where), args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var t time.Time
		var v int64
		if err := rows.Scan(&t, &v); err != nil {
			return err
		}
		d.AttackTrend = append(d.AttackTrend, Point{Time: t, Value: v})
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// 攻击源IP TOP10
	d.TopSourceIPs, err = c.groupCount(ctx, fmt.Sprintf(`
SELECT host(client_ip), count(*) FROM security_events WHERE %s AND client_ip IS NOT NULL
GROUP BY 1 ORDER BY 2 DESC LIMIT 10`, where), args...)
	if err != nil {
		return err
	}

	// 被攻击应用 TOP10
	d.AttackedApps, err = c.groupCount(ctx, fmt.Sprintf(`
SELECT COALESCE(NULLIF(application_name_snapshot,''),'未知应用'), count(*)
FROM security_events WHERE %s GROUP BY 1 ORDER BY 2 DESC LIMIT 10`, where), args...)
	if err != nil {
		return err
	}

	// 命中规则 TOP10（仅规则ID/名称/次数，不含匹配载荷）
	ruleWhere := `e.occurred_at >= $1 AND e.occurred_at < $2`
	ruleArgs := []interface{}{d.RangeStart, d.RangeEnd}
	if len(appIDs) > 0 {
		ruleWhere += ` AND e.application_id = ANY($3)`
		ruleArgs = append(ruleArgs, appIDs)
	}
	ruleRows, err := c.db.Query(ctx, fmt.Sprintf(`
SELECT m.rule_id, COALESCE(MAX(m.rule_name),''), count(*)
FROM security_event_matches m
JOIN security_events e ON e.id = m.event_id
WHERE %s AND m.rule_id > 0
GROUP BY 1 ORDER BY 3 DESC LIMIT 10`, ruleWhere), ruleArgs...)
	if err != nil {
		return err
	}
	defer ruleRows.Close()
	for ruleRows.Next() {
		var rh RuleHit
		if err := ruleRows.Scan(&rh.RuleID, &rh.RuleName, &rh.Hits); err != nil {
			return err
		}
		if len(rh.RuleName) > 200 {
			rh.RuleName = rh.RuleName[:200]
		}
		d.TopRules = append(d.TopRules, rh)
	}
	return ruleRows.Err()
}

// collectAccessControl CC / 黑白名单统计。
func (c *Collector) collectAccessControl(ctx context.Context, d *ReportData, appIDs []uuid.UUID) error {
	where := `occurred_at >= $1 AND occurred_at < $2`
	args := []interface{}{d.RangeStart, d.RangeEnd}
	if len(appIDs) > 0 {
		where += ` AND application_id = ANY($3)`
		args = append(args, appIDs)
	}
	rows, err := c.db.Query(ctx, fmt.Sprintf(`
SELECT event_type, count(*) FROM access_control_events WHERE %s GROUP BY 1`, where), args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var et string
		var n int64
		if err := rows.Scan(&et, &n); err != nil {
			return err
		}
		switch et {
		case "CC_THRESHOLD_EXCEEDED":
			d.CCExceeded = n
		case "CC_REQUEST_REJECTED":
			d.CCRejected = n
		case "CC_TEMP_BLOCK_CREATED":
			d.CCTempBlocks = n
		case "IP_ALLOW_MATCH":
			d.IPAllowHits = n
		case "IP_DENY_MATCH":
			d.IPDenyHits = n
		}
	}
	return rows.Err()
}

// collectExceptions 误报和例外（例外策略创建数）。
func (c *Collector) collectExceptions(ctx context.Context, d *ReportData) error {
	return c.db.QueryRow(ctx, `
SELECT count(*) FROM exception_policies WHERE created_at >= $1 AND created_at < $2`,
		d.RangeStart, d.RangeEnd).Scan(&d.ExceptionsCreated)
}

// collectUpstreams 源站健康（最新一条健康检查记录/源站）。
func (c *Collector) collectUpstreams(ctx context.Context, d *ReportData, appIDs []uuid.UUID) error {
	where := `u.deleted_at IS NULL`
	args := []interface{}{}
	if len(appIDs) > 0 {
		where += ` AND u.application_id = ANY($1)`
		args = append(args, appIDs)
	}
	rows, err := c.db.Query(ctx, fmt.Sprintf(`
SELECT u.name, u.scheme || '://' || u.host || ':' || u.port,
       COALESCE(h.status, 'UNKNOWN'), h.checked_at, h.response_time_ms
FROM upstreams u
LEFT JOIN LATERAL (
  SELECT status, checked_at, response_time_ms FROM upstream_health_records
  WHERE upstream_id = u.id ORDER BY checked_at DESC LIMIT 1
) h ON TRUE
WHERE %s ORDER BY u.name LIMIT 50`, where), args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var u UpstreamHealth
		if err := rows.Scan(&u.Name, &u.Address, &u.Status, &u.CheckedAt, &u.ResponseTimeMs); err != nil {
			return err
		}
		d.Upstreams = append(d.Upstreams, u)
	}
	return rows.Err()
}

// collectCertificates 证书状态（按应用绑定过滤）。
func (c *Collector) collectCertificates(ctx context.Context, d *ReportData, appIDs []uuid.UUID) error {
	query := `
SELECT DISTINCT c.name, c.common_name, c.status, c.not_after
FROM certificates c`
	args := []interface{}{}
	if len(appIDs) > 0 {
		query += `
JOIN application_certificates ac ON ac.certificate_id = c.id AND ac.is_active
WHERE c.deleted_at IS NULL AND ac.application_id = ANY($1)`
		args = append(args, appIDs)
	} else {
		query += `
WHERE c.deleted_at IS NULL`
	}
	query += ` ORDER BY c.not_after NULLS LAST LIMIT 50`
	rows, err := c.db.Query(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cert CertStatus
		if err := rows.Scan(&cert.Name, &cert.CommonName, &cert.Status, &cert.NotAfter); err != nil {
			return err
		}
		if cert.NotAfter != nil {
			cert.DaysRemaining = int(time.Until(*cert.NotAfter).Hours() / 24)
		}
		d.Certificates = append(d.Certificates, cert)
	}
	return rows.Err()
}

// collectPublishTasks 策略发布统计（gateway_publish_tasks）。
func (c *Collector) collectPublishTasks(ctx context.Context, d *ReportData) error {
	err := c.db.QueryRow(ctx, `
SELECT count(*),
       count(*) FILTER (WHERE status = 'SUCCESS'),
       count(*) FILTER (WHERE status = 'FAILED'),
       count(*) FILTER (WHERE status NOT IN ('SUCCESS','FAILED','CANCELLED'))
FROM gateway_publish_tasks WHERE requested_at >= $1 AND requested_at < $2`,
		d.RangeStart, d.RangeEnd).
		Scan(&d.Publish.Total, &d.Publish.Success, &d.Publish.Failed, &d.Publish.Running)
	if err != nil {
		return err
	}
	rows, err := c.db.Query(ctx, `
SELECT task_type, status, requested_at, COALESCE(result_summary,'')
FROM gateway_publish_tasks WHERE requested_at >= $1 AND requested_at < $2
ORDER BY requested_at DESC LIMIT 10`, d.RangeStart, d.RangeEnd)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var p PublishItem
		if err := rows.Scan(&p.TaskType, &p.Status, &p.RequestedAt, &p.Summary); err != nil {
			return err
		}
		if len(p.Summary) > 200 {
			p.Summary = p.Summary[:200]
		}
		d.Publish.Recent = append(d.Publish.Recent, p)
	}
	return rows.Err()
}

// collectSystemHealth 系统组件健康（每组件最新快照）。
func (c *Collector) collectSystemHealth(ctx context.Context, d *ReportData) error {
	rows, err := c.db.Query(ctx, `
SELECT DISTINCT ON (component) component, status, message, taken_at
FROM system_health_snapshots
WHERE taken_at >= $1
ORDER BY component, taken_at DESC`, d.RangeStart.Add(-24*time.Hour))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var h ComponentHealth
		if err := rows.Scan(&h.Component, &h.Status, &h.Message, &h.TakenAt); err != nil {
			return err
		}
		d.Components = append(d.Components, h)
	}
	return rows.Err()
}

// groupCount 通用两列分组计数查询。
func (c *Collector) groupCount(ctx context.Context, query string, args ...interface{}) ([]KV, error) {
	rows, err := c.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KV
	for rows.Next() {
		var kv KV
		if err := rows.Scan(&kv.Key, &kv.Value); err != nil {
			return nil, err
		}
		out = append(out, kv)
	}
	return out, rows.Err()
}
