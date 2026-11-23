// analyze_context.go 结构化分析扩展（阶段7 §12.1 / §15.2 / §15.3 / §19）：
// 结构化维度入参逐一校验、按维度查询真实数据（security_events / access_control_events）
// 组装分析上下文、URI/应用画像 SQL 聚合、What-If 离线统计估算（纯统计估算，非回放引擎）。
// 缺数据口径对齐编排器兜底语义：如实声明「数据不足，无法确认」，不做推测。
package aihandlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 时间范围预设（结构化入参 time_range 的白名单取值）。
var analyzeTimeRangePresets = map[string]struct {
	d     time.Duration
	label string
}{
	"1h":  {time.Hour, "近 1 小时"},
	"6h":  {6 * time.Hour, "近 6 小时"},
	"24h": {24 * time.Hour, "近 24 小时"},
	"7d":  {7 * 24 * time.Hour, "近 7 天"},
	"30d": {30 * 24 * time.Hour, "近 30 天"},
}

// parseAnalyzeTimeRange 解析结构化时间范围（空串回退 defPreset）。
func parseAnalyzeTimeRange(s, defPreset string, now time.Time) (start, end time.Time, label string, err error) {
	if s == "" {
		s = defPreset
	}
	p, ok := analyzeTimeRangePresets[s]
	if !ok {
		return start, end, "", fmt.Errorf("无效的时间范围（支持 1h/6h/24h/7d/30d）")
	}
	return now.Add(-p.d), now, p.label, nil
}

// validAnalyzeURI 校验结构化 URI 入参（请求路径，防异常文本进入模板与 SQL 通配）。
func validAnalyzeURI(s string) bool {
	if len(s) < 2 || len(s) > 200 || !strings.HasPrefix(s, "/") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// validAnalyzeRequestID 校验 Request ID 入参（网关 X-Request-Id 形态，限长 64）。
func validAnalyzeRequestID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}

// What-If 模拟场景（结构化入参 scenario 的白名单取值，对应任务书 §19.1 八种模拟）。
const (
	whatIfScenarioDisableRule      = "disable_rule"      // 停用规则（默认，需 rule_id）
	whatIfScenarioEnableRule       = "enable_rule"       // 启用规则（需 rule_id）
	whatIfScenarioAnomalyThreshold = "anomaly_threshold" // 修改异常阈值（需 anomaly_threshold）
	whatIfScenarioPLSwitch         = "pl_switch"         // 切换 CRS 执行等级（需 paranoia_level）
	whatIfScenarioAddException     = "add_exception"     // 新增例外（需 rule_id，可选 application_id/uri）
	whatIfScenarioRemoveException  = "remove_exception"  // 删除例外（需 exception_id）
	whatIfScenarioCCThreshold      = "cc_threshold"      // 修改 CC 阈值（需 cc_threshold）
	whatIfScenarioBlockDuration    = "block_duration"    // 调整封禁时长（需 block_duration_seconds）
)

// validateAnalyzeStructured 结构化入参逐一校验（仅校验已提供的字段），返回首个错误消息。
func validateAnalyzeStructured(req *analyzeRequest) string {
	if req.EventID != "" && !validEventID(req.EventID) {
		return "无效的事件ID"
	}
	if req.IP != "" && net.ParseIP(req.IP) == nil {
		return "无效的IP地址"
	}
	if req.URI != "" && !validAnalyzeURI(req.URI) {
		return "无效的URI（需以 / 开头的请求路径，长度 2-200）"
	}
	if req.ApplicationID != "" {
		if _, err := uuid.Parse(req.ApplicationID); err != nil {
			return "无效的应用ID"
		}
	}
	if req.RuleID < 0 {
		return "无效的规则ID"
	}
	if req.RequestID != "" && !validAnalyzeRequestID(req.RequestID) {
		return "无效的Request ID"
	}
	if req.TimeRange != "" {
		if _, ok := analyzeTimeRangePresets[req.TimeRange]; !ok {
			return "无效的时间范围（支持 1h/6h/24h/7d/30d）"
		}
	}
	switch req.Scenario {
	case "", whatIfScenarioDisableRule, whatIfScenarioEnableRule, whatIfScenarioAnomalyThreshold,
		whatIfScenarioPLSwitch, whatIfScenarioAddException, whatIfScenarioRemoveException,
		whatIfScenarioCCThreshold, whatIfScenarioBlockDuration:
	default:
		return "无效的模拟场景（支持 disable_rule/enable_rule/anomaly_threshold/pl_switch/add_exception/remove_exception/cc_threshold/block_duration）"
	}
	if req.AnomalyThreshold < 0 || req.AnomalyThreshold > 10000 {
		return "无效的异常阈值（1-10000）"
	}
	if req.ParanoiaLevel < 0 || req.ParanoiaLevel > 4 {
		return "无效的执行等级（1-4）"
	}
	if req.ExceptionID != "" {
		if _, err := uuid.Parse(req.ExceptionID); err != nil {
			return "无效的例外ID"
		}
	}
	if req.CCThreshold < 0 || req.CCThreshold > 1000000 {
		return "无效的 CC 阈值（1-1000000）"
	}
	if req.BlockDurationSeconds < 0 || req.BlockDurationSeconds > 2592000 {
		return "无效的封禁时长（60-2592000 秒）"
	}
	return ""
}

// hasEventFilter 是否携带事件过滤维度（ip/uri/rule_id/request_id/application_id 任一）。
func hasEventFilter(req *analyzeRequest) bool {
	return req.IP != "" || req.URI != "" || req.RuleID > 0 || req.RequestID != "" || req.ApplicationID != ""
}

// countKV 分组计数项。
type countKV struct {
	Key   string
	Count int64
}

func formatKVs(items []countKV) string {
	if len(items) == 0 {
		return "无"
	}
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, fmt.Sprintf("%s(%d)", it.Key, it.Count))
	}
	return strings.Join(parts, "、")
}

// ---------- 事件多维度过滤分析（§12.1） ----------

// eventFilterSummary 按维度过滤的事件聚合结果。
type eventFilterSummary struct {
	Total        int64
	Blocked      int64
	FirstAt      time.Time
	LastAt       time.Time
	AttackTypes  []countKV
	SourceIPs    []countKV
	Paths        []countKV
	AccessEvents int64 // 同维度 access_control_events 事件数（CC/黑白名单等）
}

// eventFilterWhere 构造 security_events 维度过滤条件（全部参数化）。
func eventFilterWhere(req *analyzeRequest, start, end time.Time) (string, []interface{}) {
	where := "occurred_at >= $1 AND occurred_at < $2"
	args := []interface{}{start, end}
	idx := 3
	if req.ApplicationID != "" {
		where += fmt.Sprintf(" AND application_id = $%d", idx)
		args = append(args, req.ApplicationID)
		idx++
	}
	if req.IP != "" {
		where += fmt.Sprintf(" AND client_ip = $%d::inet", idx)
		args = append(args, req.IP)
		idx++
	}
	if req.URI != "" {
		where += fmt.Sprintf(" AND request_path = $%d", idx)
		args = append(args, req.URI)
		idx++
	}
	if req.RequestID != "" {
		where += fmt.Sprintf(" AND request_id = $%d", idx)
		args = append(args, req.RequestID)
		idx++
	}
	if req.RuleID > 0 {
		where += fmt.Sprintf(" AND EXISTS (SELECT 1 FROM security_event_matches m WHERE m.event_id = security_events.id AND m.rule_id = $%d)", idx)
		args = append(args, req.RuleID)
		idx++
	}
	return where, args
}

// queryEventFilterSummary 按维度聚合真实事件数据（security_events + access_control_events）。
func (d *Deps) queryEventFilterSummary(ctx context.Context, req *analyzeRequest, start, end time.Time) (*eventFilterSummary, error) {
	where, args := eventFilterWhere(req, start, end)
	s := &eventFilterSummary{}
	if err := d.DB.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE action='BLOCK'),
  COALESCE(min(occurred_at), 'epoch'::timestamptz), COALESCE(max(occurred_at), 'epoch'::timestamptz)
FROM security_events WHERE `+where, args...).Scan(&s.Total, &s.Blocked, &s.FirstAt, &s.LastAt); err != nil {
		return nil, err
	}
	groupQueries := []struct {
		col string
		dst *[]countKV
	}{
		{"attack_type", &s.AttackTypes},
		{"COALESCE(host(client_ip),'unknown')", &s.SourceIPs},
		{"left(request_path,120)", &s.Paths},
	}
	for _, g := range groupQueries {
		rows, err := d.DB.Query(ctx, `
SELECT `+g.col+`, count(*) FROM security_events WHERE `+where+`
GROUP BY 1 ORDER BY 2 DESC LIMIT 5`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var kv countKV
			if err := rows.Scan(&kv.Key, &kv.Count); err != nil {
				rows.Close()
				return nil, err
			}
			*g.dst = append(*g.dst, kv)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	// 同维度访问控制事件（仅 IP / Request ID 维度可关联）
	switch {
	case req.IP != "":
		if err := d.DB.QueryRow(ctx, `
SELECT count(*) FROM access_control_events
WHERE occurred_at >= $1 AND occurred_at < $2 AND client_ip = $3::inet`, start, end, req.IP).Scan(&s.AccessEvents); err != nil {
			return nil, err
		}
	case req.RequestID != "":
		if err := d.DB.QueryRow(ctx, `
SELECT count(*) FROM access_control_events
WHERE occurred_at >= $1 AND occurred_at < $2 AND request_id = $3`, start, end, req.RequestID).Scan(&s.AccessEvents); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// describeEventFilterDims 维度组合的可读描述（模板与审计用）。
func describeEventFilterDims(req *analyzeRequest) string {
	var dims []string
	if req.ApplicationID != "" {
		dims = append(dims, "应用ID "+req.ApplicationID)
	}
	if req.IP != "" {
		dims = append(dims, "IP "+req.IP)
	}
	if req.URI != "" {
		dims = append(dims, "URI "+req.URI)
	}
	if req.RuleID > 0 {
		dims = append(dims, "规则 "+itoa(req.RuleID))
	}
	if req.RequestID != "" {
		dims = append(dims, "Request ID "+req.RequestID)
	}
	return strings.Join(dims, "，")
}

// buildEventFilterContext 按维度聚合结果组装分析上下文（纯函数；缺数据如实声明）。
func buildEventFilterContext(req *analyzeRequest, label string, s *eventFilterSummary) string {
	var b strings.Builder
	b.WriteString("请基于以下按维度检索到的真实数据做安全事件分析，给出攻击类型分布、风险等级与处置建议。\n")
	b.WriteString("分析维度：" + describeEventFilterDims(req) + "；统计区间：" + label + "\n")
	if s.Total == 0 {
		b.WriteString(fmt.Sprintf("检索结果：该维度组合在%s内无安全事件记录（访问控制事件 %d 条）。数据不足，无法确认攻击情况；请如实说明数据不足，不得推测。", label, s.AccessEvents))
		if req.EventID != "" {
			b.WriteString("\n另请结合事件 " + req.EventID + " 的详情做关联分析")
		}
		if req.Question != "" {
			b.WriteString("\n分析侧重点：" + req.Question)
		}
		return b.String()
	}
	b.WriteString(fmt.Sprintf("检索结果（确定性数据）：安全事件 %d 条，其中阻断 %d 条；首次 %s，最近 %s。\n",
		s.Total, s.Blocked, s.FirstAt.Format("2006-01-02 15:04"), s.LastAt.Format("2006-01-02 15:04")))
	b.WriteString("攻击类型分布：" + formatKVs(s.AttackTypes) + "\n")
	b.WriteString("来源 IP TOP：" + formatKVs(s.SourceIPs) + "\n")
	b.WriteString("目标 URI TOP：" + formatKVs(s.Paths) + "\n")
	if req.IP != "" || req.RequestID != "" {
		b.WriteString(fmt.Sprintf("同维度访问控制事件（CC/黑白名单/封禁）：%d 条\n", s.AccessEvents))
	}
	if req.EventID != "" {
		b.WriteString("另请结合事件 " + req.EventID + " 的详情做关联分析\n")
	}
	if req.Question != "" {
		b.WriteString("分析侧重点：" + req.Question)
	}
	return b.String()
}

// ---------- URI / 应用画像（§15.2 / §15.3） ----------

// uriProfileSummary URI 画像聚合结果。
type uriProfileSummary struct {
	URI         string
	Total       int64
	Blocked     int64
	FirstAt     time.Time
	LastAt      time.Time
	AttackTypes []countKV
	SourceIPs   []countKV
	Rules       []countKV
}

// queryURIProfile URI 画像真实 SQL 聚合（事件分布/攻击类型/来源 IP/命中规则 Top）。
func (d *Deps) queryURIProfile(ctx context.Context, uri string, start, end time.Time) (*uriProfileSummary, error) {
	p := &uriProfileSummary{URI: uri}
	if err := d.DB.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE action='BLOCK'),
  COALESCE(min(occurred_at), 'epoch'::timestamptz), COALESCE(max(occurred_at), 'epoch'::timestamptz)
FROM security_events WHERE request_path = $1 AND occurred_at >= $2 AND occurred_at < $3`,
		uri, start, end).Scan(&p.Total, &p.Blocked, &p.FirstAt, &p.LastAt); err != nil {
		return nil, err
	}
	if p.Total == 0 {
		return p, nil
	}
	groupQueries := []struct {
		query string
		dst   *[]countKV
	}{
		{`SELECT attack_type, count(*) FROM security_events
WHERE request_path = $1 AND occurred_at >= $2 AND occurred_at < $3 GROUP BY 1 ORDER BY 2 DESC LIMIT 5`, &p.AttackTypes},
		{`SELECT COALESCE(host(client_ip),'unknown'), count(*) FROM security_events
WHERE request_path = $1 AND occurred_at >= $2 AND occurred_at < $3 GROUP BY 1 ORDER BY 2 DESC LIMIT 5`, &p.SourceIPs},
		{`SELECT m.rule_id::text, count(*) FROM security_event_matches m
JOIN security_events e ON e.id = m.event_id
WHERE e.request_path = $1 AND e.occurred_at >= $2 AND e.occurred_at < $3 AND m.rule_id > 0
GROUP BY 1 ORDER BY 2 DESC LIMIT 5`, &p.Rules},
	}
	for _, g := range groupQueries {
		rows, err := d.DB.Query(ctx, g.query, uri, start, end)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var kv countKV
			if err := rows.Scan(&kv.Key, &kv.Count); err != nil {
				rows.Close()
				return nil, err
			}
			*g.dst = append(*g.dst, kv)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// buildURIProfileContext URI 画像分析上下文（纯函数；缺数据如实声明）。
func buildURIProfileContext(label string, p *uriProfileSummary) string {
	var b strings.Builder
	b.WriteString("请基于以下真实聚合数据对 URI " + p.URI + " 做画像分析（统计区间：" + label + "），给出事件分布、攻击类型、来源 IP 特征与防护建议。\n")
	if p.Total == 0 {
		b.WriteString(fmt.Sprintf("检索结果：该 URI 在%s内无安全事件记录。数据不足，无法确认；请如实说明数据不足，不得推测。", label))
		return b.String()
	}
	b.WriteString(fmt.Sprintf("检索结果（确定性数据）：安全事件 %d 条，阻断 %d 条；首次 %s，最近 %s。\n",
		p.Total, p.Blocked, p.FirstAt.Format("2006-01-02 15:04"), p.LastAt.Format("2006-01-02 15:04")))
	b.WriteString("攻击类型分布：" + formatKVs(p.AttackTypes) + "\n")
	b.WriteString("来源 IP TOP：" + formatKVs(p.SourceIPs) + "\n")
	b.WriteString("命中规则 TOP：" + formatKVs(p.Rules))
	return b.String()
}

// appProfileSummary 应用画像聚合结果。
type appProfileSummary struct {
	AppID       string
	AppName     string
	Mode        string
	Status      string
	Total       int64
	Blocked     int64
	FirstAt     time.Time
	LastAt      time.Time
	AttackTypes []countKV
	SourceIPs   []countKV
	URIs        []countKV
}

// queryAppProfile 应用画像真实 SQL 聚合（应用维度事件分布/攻击类型/来源 IP/目标 URI Top）。
func (d *Deps) queryAppProfile(ctx context.Context, appID string, start, end time.Time) (*appProfileSummary, error) {
	p := &appProfileSummary{AppID: appID}
	if err := d.DB.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE action='BLOCK'),
  COALESCE(min(occurred_at), 'epoch'::timestamptz), COALESCE(max(occurred_at), 'epoch'::timestamptz),
  COALESCE(max(application_name_snapshot), '')
FROM security_events WHERE application_id = $1 AND occurred_at >= $2 AND occurred_at < $3`,
		appID, start, end).Scan(&p.Total, &p.Blocked, &p.FirstAt, &p.LastAt, &p.AppName); err != nil {
		return nil, err
	}
	if p.AppName == "" {
		// 事件快照无名称时回查应用表（应用可能已删除，仅尽力取名）
		_ = d.DB.QueryRow(ctx, `SELECT name FROM applications WHERE id = $1`, appID).Scan(&p.AppName)
	}
	if p.AppName != "" {
		_ = d.DB.QueryRow(ctx, `SELECT protection_mode, status FROM applications WHERE id = $1`, appID).Scan(&p.Mode, &p.Status)
	}
	if p.Total == 0 {
		return p, nil
	}
	groupQueries := []struct {
		col string
		dst *[]countKV
	}{
		{"attack_type", &p.AttackTypes},
		{"COALESCE(host(client_ip),'unknown')", &p.SourceIPs},
		{"left(request_path,120)", &p.URIs},
	}
	for _, g := range groupQueries {
		rows, err := d.DB.Query(ctx, `
SELECT `+g.col+`, count(*) FROM security_events
WHERE application_id = $1 AND occurred_at >= $2 AND occurred_at < $3
GROUP BY 1 ORDER BY 2 DESC LIMIT 5`, appID, start, end)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var kv countKV
			if err := rows.Scan(&kv.Key, &kv.Count); err != nil {
				rows.Close()
				return nil, err
			}
			*g.dst = append(*g.dst, kv)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// buildAppProfileContext 应用画像分析上下文（纯函数；缺数据如实声明）。
func buildAppProfileContext(label string, p *appProfileSummary) string {
	name := p.AppName
	if name == "" {
		name = p.AppID
	}
	var b strings.Builder
	b.WriteString("请基于以下真实聚合数据对应用「" + name + "」做画像分析（统计区间：" + label + "），给出事件分布、攻击类型、来源 IP 与被攻击 URI 特征及防护建议。\n")
	if p.Mode != "" {
		b.WriteString(fmt.Sprintf("应用当前防护模式 %s，状态 %s。\n", p.Mode, p.Status))
	}
	if p.Total == 0 {
		b.WriteString(fmt.Sprintf("检索结果：该应用在%s内无安全事件记录。数据不足，无法确认；请如实说明数据不足，不得推测。", label))
		return b.String()
	}
	b.WriteString(fmt.Sprintf("检索结果（确定性数据）：安全事件 %d 条，阻断 %d 条；首次 %s，最近 %s。\n",
		p.Total, p.Blocked, p.FirstAt.Format("2006-01-02 15:04"), p.LastAt.Format("2006-01-02 15:04")))
	b.WriteString("攻击类型分布：" + formatKVs(p.AttackTypes) + "\n")
	b.WriteString("来源 IP TOP：" + formatKVs(p.SourceIPs) + "\n")
	b.WriteString("被攻击 URI TOP：" + formatKVs(p.URIs))
	return b.String()
}

// ---------- What-If 离线统计估算（§19，纯统计估算，非回放引擎） ----------

// ccTriggerSample CC 超阈事件样本（access_control_events 记录的触发时计数）。
type ccTriggerSample struct {
	ClientIP      string
	CurrentCount  int64
	LimitValue    int64
	WindowSeconds int64
}

// ccThresholdEstimate 修改 CC 阈值的离线估算结果。
type ccThresholdEstimate struct {
	SampleTotal    int64 // 历史超阈事件样本数
	AvoidedTotal   int64 // 新阈值下不会触发的样本数（current_count < 新阈值）
	AffectedIPs    int64 // 涉及的去重来源 IP 数
	CurrentLimit   int64 // 样本中最常见（最小）的当前阈值（参考）
	WindowSeconds  int64 // 样本对应的统计窗口（参考；窗口不一致时口径见说明）
	EstimatedRatio int   // 估算触发量减少百分比（0-100）
}

// estimateCCThreshold 修改 CC 阈值离线估算（纯函数）。
// 口径：历史事件记录了触发时刻的窗口计数 current_count；假设流量速率分布不变、窗口不变，
// 则新阈值下该次触发不发生当且仅当 current_count < newThreshold。仅为统计估算，非逐请求回放。
func estimateCCThreshold(samples []ccTriggerSample, newThreshold int64) ccThresholdEstimate {
	est := ccThresholdEstimate{SampleTotal: int64(len(samples))}
	avoidedIPs := map[string]bool{}
	var minLimit, minWindow int64
	for _, s := range samples {
		if minLimit == 0 || (s.LimitValue > 0 && s.LimitValue < minLimit) {
			minLimit = s.LimitValue
			minWindow = s.WindowSeconds
		}
		if s.CurrentCount < newThreshold {
			est.AvoidedTotal++
			avoidedIPs[s.ClientIP] = true
		}
	}
	est.CurrentLimit = minLimit
	est.WindowSeconds = minWindow
	est.AffectedIPs = int64(len(avoidedIPs))
	if est.SampleTotal > 0 {
		est.EstimatedRatio = int(est.AvoidedTotal * 100 / est.SampleTotal)
	}
	return est
}

// queryCCThresholdSamples 读取 CC 超阈事件样本（上限 5000 条防全表扫）。
func (d *Deps) queryCCThresholdSamples(ctx context.Context, start, end time.Time) ([]ccTriggerSample, error) {
	rows, err := d.DB.Query(ctx, `
SELECT COALESCE(host(client_ip),''), current_count, limit_value, COALESCE(window_seconds,0)
FROM access_control_events
WHERE event_type='CC_THRESHOLD_EXCEEDED' AND occurred_at >= $1 AND occurred_at < $2
  AND current_count IS NOT NULL AND limit_value IS NOT NULL
ORDER BY occurred_at LIMIT 5000`, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	samples := []ccTriggerSample{}
	for rows.Next() {
		var s ccTriggerSample
		if err := rows.Scan(&s.ClientIP, &s.CurrentCount, &s.LimitValue, &s.WindowSeconds); err != nil {
			return nil, err
		}
		samples = append(samples, s)
	}
	return samples, rows.Err()
}

// buildCCThresholdContext CC 阈值模拟上下文（纯函数；缺数据如实声明）。
func buildCCThresholdContext(label string, newThreshold int64, est ccThresholdEstimate) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("请基于以下真实历史数据做 What-If 模拟：如果将 CC 频率限制阈值调整为每窗口 %d 次，会有什么影响？\n", newThreshold))
	if est.SampleTotal == 0 {
		b.WriteString(fmt.Sprintf("检索结果：%s内无 CC 超阈事件样本。数据不足，无法估算影响；请如实说明数据不足，不得推测。", label))
		return b.String()
	}
	b.WriteString(fmt.Sprintf("检索结果（确定性数据，%s）：CC 超阈事件 %d 条；当前阈值参考值 %d 次/%d 秒窗口。\n",
		label, est.SampleTotal, est.CurrentLimit, est.WindowSeconds))
	b.WriteString(fmt.Sprintf("离线统计估算：新阈值下约 %d 条历史触发不会发生（占 %d%%），涉及来源 IP %d 个。\n",
		est.AvoidedTotal, est.EstimatedRatio, est.AffectedIPs))
	b.WriteString("口径说明：以上基于历史事件记录的触发时刻窗口计数做统计估算（假设流量速率分布与统计窗口不变），非逐请求回放；阈值调高会减少触发但可能增加漏拦，调低反之。")
	return b.String()
}

// blockSample 临时封禁事件样本（创建时刻与到期时刻）。
type blockSample struct {
	ClientIP  string
	StartedAt time.Time
	ExpiresAt time.Time
}

// blockDurationEstimate 调整封禁时长的离线估算结果。
type blockDurationEstimate struct {
	SampleTotal      int64 // 历史封禁事件样本数
	DistinctIPs      int64 // 涉及去重 IP 数
	SubsumedBlocks   int64 // 新时长下被前次封禁覆盖（不会再次触发）的封禁数
	AvgCurrentSecond int64 // 当前平均封禁时长（秒）
}

// estimateBlockDuration 调整封禁时长离线估算（纯函数）。
// 口径：样本按 IP 分组、按发生时刻排序（调用方保证）；同一 IP 相邻两次封禁间隔小于新时长时，
// 后一次封禁在新时长下不会发生（IP 仍在封禁中）。仅为统计估算，非回放引擎。
func estimateBlockDuration(samples []blockSample, newDur time.Duration) blockDurationEstimate {
	est := blockDurationEstimate{SampleTotal: int64(len(samples))}
	ips := map[string]bool{}
	lastStart := map[string]time.Time{}
	var durSum int64
	var durCnt int64
	for _, s := range samples {
		ips[s.ClientIP] = true
		if !s.ExpiresAt.IsZero() && s.ExpiresAt.After(s.StartedAt) {
			durSum += int64(s.ExpiresAt.Sub(s.StartedAt).Seconds())
			durCnt++
		}
		if prev, ok := lastStart[s.ClientIP]; ok && s.StartedAt.Sub(prev) < newDur {
			est.SubsumedBlocks++
		}
		lastStart[s.ClientIP] = s.StartedAt
	}
	est.DistinctIPs = int64(len(ips))
	if durCnt > 0 {
		est.AvgCurrentSecond = durSum / durCnt
	}
	return est
}

// queryBlockSamples 读取临时封禁创建事件样本（按 IP+时刻排序，上限 5000 条）。
func (d *Deps) queryBlockSamples(ctx context.Context, start, end time.Time) ([]blockSample, error) {
	rows, err := d.DB.Query(ctx, `
SELECT COALESCE(host(client_ip),''), occurred_at, block_expires_at
FROM access_control_events
WHERE event_type='CC_TEMP_BLOCK_CREATED' AND occurred_at >= $1 AND occurred_at < $2
ORDER BY client_ip, occurred_at LIMIT 5000`, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	samples := []blockSample{}
	for rows.Next() {
		var s blockSample
		if err := rows.Scan(&s.ClientIP, &s.StartedAt, &s.ExpiresAt); err != nil {
			return nil, err
		}
		samples = append(samples, s)
	}
	return samples, rows.Err()
}

// buildBlockDurationContext 封禁时长模拟上下文（纯函数；缺数据如实声明）。
func buildBlockDurationContext(label string, newDur time.Duration, est blockDurationEstimate) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("请基于以下真实历史数据做 What-If 模拟：如果将 CC 临时封禁时长调整为 %d 秒，会有什么影响？\n", int64(newDur.Seconds())))
	if est.SampleTotal == 0 {
		b.WriteString(fmt.Sprintf("检索结果：%s内无临时封禁事件样本。数据不足，无法估算影响；请如实说明数据不足，不得推测。", label))
		return b.String()
	}
	b.WriteString(fmt.Sprintf("检索结果（确定性数据，%s）：临时封禁事件 %d 条，涉及来源 IP %d 个；当前平均封禁时长约 %d 秒。\n",
		label, est.SampleTotal, est.DistinctIPs, est.AvgCurrentSecond))
	b.WriteString(fmt.Sprintf("离线统计估算：新时长下约 %d 次历史重复封禁不会发生（前次封禁仍生效）；单个 IP 的封禁覆盖时长随新时长线性变化。\n",
		est.SubsumedBlocks))
	b.WriteString("口径说明：以上基于历史封禁事件的发生间隔做统计估算，非逐请求回放；时长调长可减少重复触发与告警噪声，但误伤时影响面同步扩大，建议配合白名单复核。")
	return b.String()
}

// ---------- What-If §19 其余五种场景（启用规则/异常阈值/PL 切换/新增例外/删除例外） ----------

// ruleEnableSummary 启用规则模拟的真实聚合数据。
type ruleEnableSummary struct {
	RuleID           int
	RuleExists       bool
	RuleName         string
	Severity         string
	AttackType       string
	DefaultState     string
	DisableOverrides int64 // 当前生效的 DISABLE 覆盖数
	HistHits         int64 // 窗口内该规则历史命中（关闭期间无记录，可能为 0）
	HistBlocks       int64
	HistFPs          int64
	SameTypeTotal    int64 // 窗口内同攻击类型事件量（该规则可见流量的上界参考）
	SameTypeObserve  int64 // 其中仅观察未阻断的事件数
}

// queryRuleEnableSummary 读取启用规则模拟所需的真实聚合（规则元数据 + 覆盖 + 历史命中 + 同类型事件量）。
func (d *Deps) queryRuleEnableSummary(ctx context.Context, ruleID int, start, end time.Time) (*ruleEnableSummary, error) {
	s := &ruleEnableSummary{RuleID: ruleID}
	err := d.DB.QueryRow(ctx, `
SELECT name, severity, attack_type, default_state FROM waf_rules WHERE rule_id = $1
ORDER BY crs_version DESC LIMIT 1`, ruleID).Scan(&s.RuleName, &s.Severity, &s.AttackType, &s.DefaultState)
	if err != nil {
		// 规则未同步到本地库：如实返回不存在
		return s, nil
	}
	s.RuleExists = true
	if err := d.DB.QueryRow(ctx, `
SELECT count(*) FROM rule_overrides
WHERE rule_id = $1 AND action = 'DISABLE' AND (effective_until IS NULL OR effective_until > now())`, ruleID).Scan(&s.DisableOverrides); err != nil {
		return nil, err
	}
	if err := d.DB.QueryRow(ctx, `
SELECT count(*),
  count(*) FILTER (WHERE e.action = 'BLOCK'),
  count(*) FILTER (WHERE e.disposition_status = 'CONFIRMED_FALSE_POSITIVE')
FROM security_event_matches m JOIN security_events e ON e.id = m.event_id
WHERE m.rule_id = $1 AND e.occurred_at >= $2 AND e.occurred_at < $3`,
		ruleID, start, end).Scan(&s.HistHits, &s.HistBlocks, &s.HistFPs); err != nil {
		return nil, err
	}
	if err := d.DB.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE action = 'OBSERVE')
FROM security_events WHERE attack_type = $1 AND occurred_at >= $2 AND occurred_at < $3`,
		s.AttackType, start, end).Scan(&s.SameTypeTotal, &s.SameTypeObserve); err != nil {
		return nil, err
	}
	return s, nil
}

// estimateRuleEnable 启用规则的风险分级（纯函数）。
// 口径：启用只可能增加检测与告警；历史阻断多说明规则曾有效拦截（回归风险低），
// 同类型仅观察事件多则启用后可能新增大量处置动作（告警噪声风险高）。
func estimateRuleEnable(s *ruleEnableSummary) (risk string) {
	switch {
	case !s.RuleExists:
		return "UNKNOWN"
	case s.SameTypeObserve > 0 && s.HistHits == 0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// buildEnableRuleContext 启用规则模拟上下文（纯函数；缺数据如实声明）。
func buildEnableRuleContext(label string, s *ruleEnableSummary) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("请基于以下真实历史数据做 What-If 模拟：如果启用规则 %d，会有什么影响？\n", s.RuleID))
	if !s.RuleExists {
		b.WriteString(fmt.Sprintf("检索结果：规则 %d 未在本地规则库中找到，无法确认其攻击类型与影响面；请如实说明规则不存在，不得推测。", s.RuleID))
		return b.String()
	}
	b.WriteString(fmt.Sprintf("检索结果（确定性数据，%s）：规则 %d（%s，%s/%s，默认状态 %s）；当前生效的停用覆盖 %d 条。\n",
		label, s.RuleID, s.RuleName, s.Severity, s.AttackType, s.DefaultState, s.DisableOverrides))
	b.WriteString(fmt.Sprintf("窗口内该规则历史命中 %d 条（阻断 %d 条，误报标记 %d 条）；同攻击类型（%s）事件共 %d 条，其中仅观察 %d 条。\n",
		s.HistHits, s.HistBlocks, s.HistFPs, s.AttackType, s.SameTypeTotal, s.SameTypeObserve))
	b.WriteString(fmt.Sprintf("离线统计估算：模拟风险等级 %s；启用后可能新增处置动作的历史事件上界约 %d 条（同类型仅观察事件）。\n",
		estimateRuleEnable(s), s.SameTypeObserve))
	b.WriteString("口径说明：规则关闭期间不产生命中记录，以上为同攻击类型事件量的上界参考与历史命中回放的统计估算，非逐请求回放；启用建议先 OBSERVE 观察。")
	return b.String()
}

// anomalySample 事件入站异常评分样本（security_events 记录的事件级评分）。
type anomalySample struct {
	Action string
	Score  int
}

// anomalyThresholdEstimate 修改异常阈值的离线估算结果。
type anomalyThresholdEstimate struct {
	SampleTotal      int64 // 历史带评分事件样本数
	CurrentlyBlocked int64 // 样本中当前被阻断数
	NewlyBlocked     int64 // 新阈值下新增阻断（当前未阻断且评分 >= 新阈值）
	NoLongerBlocked  int64 // 新阈值下不再阻断（当前阻断且评分 < 新阈值）
	NewBlockedRatio  int   // 新阈值下估算阻断占比（0-100）
}

// estimateAnomalyThreshold 修改异常阈值离线估算（纯函数）。
// 口径：security_events 记录事件级入站异常评分；假设规则集与流量评分分布不变，
// 新阈值下事件被阻断当且仅当评分 >= 新阈值。仅为统计估算，非逐请求回放。
func estimateAnomalyThreshold(samples []anomalySample, newThreshold int64) anomalyThresholdEstimate {
	est := anomalyThresholdEstimate{SampleTotal: int64(len(samples))}
	for _, s := range samples {
		blocked := s.Action == "BLOCK"
		if blocked {
			est.CurrentlyBlocked++
			if int64(s.Score) < newThreshold {
				est.NoLongerBlocked++
			}
		} else if int64(s.Score) >= newThreshold {
			est.NewlyBlocked++
		}
	}
	if est.SampleTotal > 0 {
		est.NewBlockedRatio = int((est.CurrentlyBlocked - est.NoLongerBlocked + est.NewlyBlocked) * 100 / est.SampleTotal)
	}
	return est
}

// anomalyThresholdData 异常阈值模拟数据（样本 + 当前策略阈值参考区间）。
type anomalyThresholdData struct {
	Samples []anomalySample
	RefMin  int64 // 生效策略中最小入站阈值（参考）
	RefMax  int64 // 生效策略中最大入站阈值（参考）
}

// queryAnomalyThresholdData 读取带评分事件样本（上限 5000 条）与当前策略阈值参考。
func (d *Deps) queryAnomalyThresholdData(ctx context.Context, start, end time.Time) (*anomalyThresholdData, error) {
	data := &anomalyThresholdData{Samples: []anomalySample{}}
	rows, err := d.DB.Query(ctx, `
SELECT action, anomaly_score FROM security_events
WHERE occurred_at >= $1 AND occurred_at < $2 AND anomaly_score > 0
ORDER BY occurred_at LIMIT 5000`, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s anomalySample
		if err := rows.Scan(&s.Action, &s.Score); err != nil {
			return nil, err
		}
		data.Samples = append(data.Samples, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := d.DB.QueryRow(ctx, `
SELECT COALESCE(min(inbound_anomaly_threshold), 0), COALESCE(max(inbound_anomaly_threshold), 0)
FROM protection_policies WHERE status = 'ACTIVE' AND deleted_at IS NULL`).Scan(&data.RefMin, &data.RefMax); err != nil {
		return nil, err
	}
	return data, nil
}

// buildAnomalyThresholdContext 异常阈值模拟上下文（纯函数；缺数据如实声明）。
func buildAnomalyThresholdContext(label string, newThreshold, refMin, refMax int64, est anomalyThresholdEstimate) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("请基于以下真实历史数据做 What-If 模拟：如果将入站异常阈值调整为 %d，会有什么影响？\n", newThreshold))
	if est.SampleTotal == 0 {
		b.WriteString(fmt.Sprintf("检索结果：%s内无带异常评分的事件样本。数据不足，无法估算影响；请如实说明数据不足，不得推测。", label))
		return b.String()
	}
	b.WriteString(fmt.Sprintf("检索结果（确定性数据，%s）：带评分事件 %d 条；当前生效策略入站阈值参考区间 %d-%d。\n",
		label, est.SampleTotal, refMin, refMax))
	b.WriteString(fmt.Sprintf("离线统计估算：新阈值下估算阻断占比约 %d%%；较当前约 %d 条历史阻断不再触发（误报减少候选），约 %d 条历史未阻断事件将新增阻断（可能影响正常流量）。\n",
		est.NewBlockedRatio, est.NoLongerBlocked, est.NewlyBlocked))
	b.WriteString("口径说明：以上基于事件记录的入站异常评分分布做统计估算（假设规则集与流量评分分布不变），非逐请求回放；阈值调低增加拦截与误报风险，调高反之。")
	return b.String()
}

// plSeverityCount 执行等级模拟的严重级别分布项。
type plSeverityCount struct {
	Severity string
	Total    int64
	Blocked  int64
}

// plSwitchSummary PL 切换模拟的真实聚合数据。
type plSwitchSummary struct {
	Events   []plSeverityCount // 窗口内事件按严重级别分布
	RuleLib  []countKV         // 本地规则库按严重级别规模（参考）
	EventSum int64
	RuleSum  int64
}

// queryPLSwitchSummary 读取窗口内事件严重级别分布与规则库规模。
func (d *Deps) queryPLSwitchSummary(ctx context.Context, start, end time.Time) (*plSwitchSummary, error) {
	s := &plSwitchSummary{Events: []plSeverityCount{}, RuleLib: []countKV{}}
	rows, err := d.DB.Query(ctx, `
SELECT severity, count(*), count(*) FILTER (WHERE action = 'BLOCK')
FROM security_events WHERE occurred_at >= $1 AND occurred_at < $2
GROUP BY 1 ORDER BY 2 DESC`, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var c plSeverityCount
		if err := rows.Scan(&c.Severity, &c.Total, &c.Blocked); err != nil {
			return nil, err
		}
		s.Events = append(s.Events, c)
		s.EventSum += c.Total
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rrows, err := d.DB.Query(ctx, `SELECT severity, count(*) FROM waf_rules GROUP BY 1 ORDER BY 2 DESC`)
	if err != nil {
		return nil, err
	}
	defer rrows.Close()
	for rrows.Next() {
		var kv countKV
		if err := rrows.Scan(&kv.Key, &kv.Count); err != nil {
			return nil, err
		}
		s.RuleLib = append(s.RuleLib, kv)
		s.RuleSum += kv.Count
	}
	return s, rrows.Err()
}

// estimatePLSwitch PL 切换的低级别事件参考量（纯函数）。
// 口径：PL 升高主要新增低严重级别（NOTICE/WARNING/LOW/MEDIUM）规则的检测，
// 返回窗口内该级别段的事件量作为可能新增命中的参考上界；PL 降低时同一段为可能减少量。
func estimatePLSwitch(events []plSeverityCount) (lowTotal, lowBlocked int64) {
	for _, c := range events {
		switch c.Severity {
		case "NOTICE", "WARNING", "LOW", "MEDIUM", "INFO":
			lowTotal += c.Total
			lowBlocked += c.Blocked
		}
	}
	return lowTotal, lowBlocked
}

// buildPLSwitchContext PL 切换模拟上下文（纯函数；缺数据如实声明）。
func buildPLSwitchContext(label string, target int, s *plSwitchSummary) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("请基于以下真实历史数据做 What-If 模拟：如果将 CRS 执行等级切换为 PL%d，会有什么影响？\n", target))
	if s.EventSum == 0 {
		b.WriteString(fmt.Sprintf("检索结果：%s内无安全事件记录。数据不足，无法估算影响；请如实说明数据不足，不得推测。", label))
		return b.String()
	}
	parts := make([]string, 0, len(s.Events))
	for _, c := range s.Events {
		parts = append(parts, fmt.Sprintf("%s %d 条（阻断 %d）", c.Severity, c.Total, c.Blocked))
	}
	b.WriteString(fmt.Sprintf("检索结果（确定性数据，%s）：事件严重级别分布 %s；本地规则库共 %d 条（%s）。\n",
		label, strings.Join(parts, "，"), s.RuleSum, formatKVs(s.RuleLib)))
	lowTotal, lowBlocked := estimatePLSwitch(s.Events)
	direction := "可能新增命中（误报风险上升）的参考上界"
	if target <= 1 {
		direction = "可能减少命中（漏拦风险上升）的参考量"
	}
	b.WriteString(fmt.Sprintf("离线统计估算：切换到 PL%d 时，低严重级别段历史事件 %d 条（其中阻断 %d 条）为%s。\n",
		target, lowTotal, lowBlocked, direction))
	b.WriteString("口径说明：PL 与单条规则的精确映射不在本地库（CRS 以跳规则实现 PL 门控），以上按事件严重级别分布做统计估算，非逐请求回放；建议先在 DetectionOnly/灰度应用验证 7 天。")
	return b.String()
}

// exceptionScope 例外策略的匹配范围（删除例外模拟用）。
type exceptionScope struct {
	Found     bool
	Name      string
	AppID     string
	URIExact  string
	URIPrefix string
	RuleIDs   []int
	Action    string
	Status    string
}

// queryExceptionScope 读取例外策略范围（未找到/已删除返回 Found=false）。
func (d *Deps) queryExceptionScope(ctx context.Context, exceptionID string) (*exceptionScope, error) {
	s := &exceptionScope{RuleIDs: []int{}}
	var ruleIDs []byte
	err := d.DB.QueryRow(ctx, `
SELECT name, COALESCE(application_id::text, ''), uri_exact, uri_prefix, rule_ids, exception_action, status
FROM exception_policies WHERE id = $1 AND deleted_at IS NULL`, exceptionID).
		Scan(&s.Name, &s.AppID, &s.URIExact, &s.URIPrefix, &ruleIDs, &s.Action, &s.Status)
	if err != nil {
		return s, nil
	}
	s.Found = true
	var raw []interface{}
	if err := json.Unmarshal(ruleIDs, &raw); err == nil {
		for _, v := range raw {
			if f, ok := v.(float64); ok {
				s.RuleIDs = append(s.RuleIDs, int(f))
			}
		}
	}
	return s, nil
}

// likeEscape 转义 LIKE 模式中的通配符（配合 ESCAPE '\'）。
func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// exceptionScopeWhere 由例外范围构造 security_events 过滤条件（纯函数，全部参数化）。
func exceptionScopeWhere(s *exceptionScope, start, end time.Time) (string, []interface{}) {
	where := "occurred_at >= $1 AND occurred_at < $2"
	args := []interface{}{start, end}
	idx := 3
	if s.AppID != "" {
		where += fmt.Sprintf(" AND application_id = $%d", idx)
		args = append(args, s.AppID)
		idx++
	}
	if s.URIExact != "" {
		where += fmt.Sprintf(" AND request_path = $%d", idx)
		args = append(args, s.URIExact)
		idx++
	} else if s.URIPrefix != "" {
		where += fmt.Sprintf(" AND request_path LIKE $%d ESCAPE '\\'", idx)
		args = append(args, likeEscape(s.URIPrefix)+"%")
		idx++
	}
	if len(s.RuleIDs) > 0 {
		where += fmt.Sprintf(" AND EXISTS (SELECT 1 FROM security_event_matches m WHERE m.event_id = security_events.id AND m.rule_id = ANY($%d::int[]))", idx)
		args = append(args, s.RuleIDs)
		idx++
	}
	return where, args
}

// describeExceptionScope 例外范围的可读描述。
func describeExceptionScope(s *exceptionScope) string {
	var dims []string
	if s.AppID != "" {
		dims = append(dims, "应用ID "+s.AppID)
	}
	if s.URIExact != "" {
		dims = append(dims, "URI 精确 "+s.URIExact)
	}
	if s.URIPrefix != "" {
		dims = append(dims, "URI 前缀 "+s.URIPrefix)
	}
	if len(s.RuleIDs) > 0 {
		ids := make([]string, 0, len(s.RuleIDs))
		for _, id := range s.RuleIDs {
			ids = append(ids, itoa(id))
		}
		dims = append(dims, "规则 "+strings.Join(ids, "/"))
	}
	if len(dims) == 0 {
		return "（无显式范围条件，按全部事件估算）"
	}
	return strings.Join(dims, "，")
}

// exceptionImpactSummary 例外增删模拟的范围内事件聚合结果。
type exceptionImpactSummary struct {
	Total   int64
	Blocked int64
	FPs     int64 // 已确认误报标记数
	URIs    []countKV
	Apps    []countKV
}

// queryExceptionImpact 按过滤条件聚合范围内事件（含 URI/应用 TOP，按需分组）。
func (d *Deps) queryExceptionImpact(ctx context.Context, where string, args []interface{}, groupURI, groupApp bool) (*exceptionImpactSummary, error) {
	s := &exceptionImpactSummary{URIs: []countKV{}, Apps: []countKV{}}
	if err := d.DB.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE action = 'BLOCK'),
  count(*) FILTER (WHERE disposition_status = 'CONFIRMED_FALSE_POSITIVE')
FROM security_events WHERE `+where, args...).Scan(&s.Total, &s.Blocked, &s.FPs); err != nil {
		return nil, err
	}
	if s.Total == 0 {
		return s, nil
	}
	groupQueries := []struct {
		run bool
		col string
		dst *[]countKV
	}{
		{groupURI, "left(request_path,120)", &s.URIs},
		{groupApp, "COALESCE(NULLIF(application_name_snapshot,''),'unknown')", &s.Apps},
	}
	for _, g := range groupQueries {
		if !g.run {
			continue
		}
		rows, err := d.DB.Query(ctx, `
SELECT `+g.col+`, count(*) FROM security_events WHERE `+where+`
GROUP BY 1 ORDER BY 2 DESC LIMIT 5`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var kv countKV
			if err := rows.Scan(&kv.Key, &kv.Count); err != nil {
				rows.Close()
				return nil, err
			}
			*g.dst = append(*g.dst, kv)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// estimateAddExceptionRisk 新增例外的风险分级（纯函数）。
// 口径：范围内有历史阻断且无/少误报标记时，新增例外可能放行真实攻击。
func estimateAddExceptionRisk(s *exceptionImpactSummary) string {
	switch {
	case s.Total == 0:
		return "UNKNOWN"
	case s.Blocked > 0 && s.FPs == 0:
		return "HIGH"
	case s.Blocked > 0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// estimateRemoveExceptionRisk 删除例外的风险分级（纯函数）。
// 口径：范围内有误报标记的历史事件在删除例外后可能重新被处置（误报回归）。
func estimateRemoveExceptionRisk(s *exceptionImpactSummary) string {
	switch {
	case s.Total == 0:
		return "UNKNOWN"
	case s.FPs > 0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// buildAddExceptionContext 新增例外模拟上下文（纯函数；缺数据如实声明）。
func buildAddExceptionContext(label, scopeDesc string, s *exceptionImpactSummary) string {
	var b strings.Builder
	b.WriteString("请基于以下真实历史数据做 What-If 模拟：如果新增例外（" + scopeDesc + "），会有什么影响？\n")
	if s.Total == 0 {
		b.WriteString(fmt.Sprintf("检索结果：该范围在%s内无匹配的安全事件记录。数据不足，无法估算影响；请如实说明数据不足，不得推测。", label))
		return b.String()
	}
	b.WriteString(fmt.Sprintf("检索结果（确定性数据，%s）：范围内历史事件 %d 条，其中阻断 %d 条，已确认误报标记 %d 条。\n",
		label, s.Total, s.Blocked, s.FPs))
	b.WriteString("受影响 URI TOP：" + formatKVs(s.URIs) + "；受影响应用 TOP：" + formatKVs(s.Apps) + "\n")
	b.WriteString(fmt.Sprintf("离线统计估算：模拟风险等级 %s；例外生效后范围内约 %d 条历史阻断将不再发生（其中误报减少候选 %d 条），约 %d 条观察事件不再产生该规则命中。\n",
		estimateAddExceptionRisk(s), s.Blocked, s.FPs, s.Total-s.Blocked))
	b.WriteString("口径说明：以上按例外范围条件过滤历史事件做统计估算，非逐请求回放；例外会放行范围内匹配流量，存在放行真实攻击的风险，需人工审核后生效。")
	return b.String()
}

// buildRemoveExceptionContext 删除例外模拟上下文（纯函数；缺数据如实声明）。
func buildRemoveExceptionContext(label string, exc *exceptionScope, s *exceptionImpactSummary) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("请基于以下真实历史数据做 What-If 模拟：如果删除例外「%s」（%s，动作 %s，状态 %s），会有什么影响？\n",
		exc.Name, describeExceptionScope(exc), exc.Action, exc.Status))
	if s.Total == 0 {
		b.WriteString(fmt.Sprintf("检索结果：该例外范围在%s内无匹配的安全事件记录。数据不足，无法估算影响；请如实说明数据不足，不得推测。", label))
		return b.String()
	}
	b.WriteString(fmt.Sprintf("检索结果（确定性数据，%s）：例外范围内历史事件 %d 条，其中阻断 %d 条，已确认误报标记 %d 条。\n",
		label, s.Total, s.Blocked, s.FPs))
	b.WriteString("受影响 URI TOP：" + formatKVs(s.URIs) + "；受影响应用 TOP：" + formatKVs(s.Apps) + "\n")
	b.WriteString(fmt.Sprintf("离线统计估算：模拟风险等级 %s；删除例外后范围内约 %d 条历史请求将重新按规则评估，其中误报标记 %d 条可能回归为拦截/告警。\n",
		estimateRemoveExceptionRisk(s), s.Total, s.FPs))
	b.WriteString("口径说明：以上按例外范围条件过滤历史事件做统计估算（例外存在期间部分请求可能未被记录为事件，存在低估），非逐请求回放；删除前建议先复核例外的创建原因。")
	return b.String()
}
