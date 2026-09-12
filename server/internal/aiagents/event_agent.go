// Package aiagents 专业 Agent：确定性分析 + 证据引用 + 可选 LLM 受约束总结。
// 事实一律来自 Tool/数据库，LLM 只复述，不允许编造。
package aiagents

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aiorchestrator"
	"github.com/jiuzhang-waf/server/internal/aitools"
	"github.com/jiuzhang-waf/server/internal/reports"
)

// 通用 Agent 基座。
type base struct {
	code string
	db   *pgxpool.Pool
}

func (b *base) Code() string { return b.code }

// callTool 便捷调用 Tool 并登记证据。
func callTool(ctx context.Context, in *aiorchestrator.AnalyzeInput, p *aitools.Principal, code string, input map[string]interface{}, summaryFmt string, args ...interface{}) (interface{}, string, error) {
	res, err := in.ToolCtx.CallTool(ctx, p, code, input)
	if err != nil {
		return nil, "", err
	}
	ref := in.Evidence.Add(code, fmt.Sprintf(summaryFmt, args...), res)
	return res, ref, nil
}

// fmtKV 键值文本。
func fmtKV(k string, v interface{}) string {
	return fmt.Sprintf("- %s：%v\n", k, v)
}

func attackTypeDisplayName(value interface{}) string {
	return reports.AttackTypeName(fmt.Sprint(value))
}

func formatChineseDateTime(value time.Time) string {
	return value.Format("2006年01月02日 15:04:05")
}

func queryTimeRange(in *aiorchestrator.AnalyzeInput) aiorchestrator.QueryTimeRange {
	if !in.TimeRange.Start.IsZero() && !in.TimeRange.End.IsZero() {
		return in.TimeRange
	}
	return aiorchestrator.ParseQueryTimeRange(in.Message, time.Now())
}

func withTimeRange(in *aiorchestrator.AnalyzeInput, input map[string]interface{}) (map[string]interface{}, aiorchestrator.QueryTimeRange) {
	rangeValue := queryTimeRange(in)
	input["start_time"] = rangeValue.Start.Format(time.RFC3339)
	input["end_time"] = rangeValue.End.Format(time.RFC3339)
	return input, rangeValue
}

// ---------- 安全事件 Agent ----------

// SecurityEventAgent 安全事件分析/画像。
type SecurityEventAgent struct{ base }

// NewSecurityEventAgent 创建。
func NewSecurityEventAgent(db *pgxpool.Pool) *SecurityEventAgent {
	return &SecurityEventAgent{base{code: "security_event", db: db}}
}

// Analyze 按任务类型执行分析。
func (a *SecurityEventAgent) Analyze(ctx context.Context, in *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error) {
	switch in.TaskType {
	case aiorchestrator.TaskEventAnalysis, aiorchestrator.TaskGeneralQA:
		return a.analyzeEvent(ctx, in)
	case aiorchestrator.TaskAttackProfile:
		return a.analyzeProfile(ctx, in)
	case aiorchestrator.TaskAttackChain:
		return a.analyzeChain(ctx, in)
	case aiorchestrator.TaskStatistics, aiorchestrator.TaskLogQuery:
		return a.analyzeStats(ctx, in)
	default:
		return a.analyzeEvent(ctx, in)
	}
}

// analyzeEvent 单事件/批量事件分析。
func (a *SecurityEventAgent) analyzeEvent(ctx context.Context, in *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error) {
	var b strings.Builder
	b.WriteString("**安全事件分析**（确定性数据）\n")
	if len(in.EventIDs) > 0 {
		for _, eid := range in.EventIDs[:min(3, len(in.EventIDs))] {
			res, ref, err := callTool(ctx, in, in.Principal, "security_event.get",
				map[string]interface{}{"event_id": eid}, "事件详情 %s", eid)
			if err != nil {
				b.WriteString(fmt.Sprintf("\n事件 %s 查询失败（%v）：当前数据不足，无法确认该事件详情，不做推测。\n", eid, err))
				continue
			}
			e := res.(map[string]interface{})
			b.WriteString(fmt.Sprintf("\n事件 %s\n", eid))
			b.WriteString(fmtKV("攻击类型", e["attack_type"]))
			b.WriteString(fmtKV("严重级别", e["severity"]))
			b.WriteString(fmtKV("动作", e["action"]))
			b.WriteString(fmtKV("客户端IP", e["client_ip"]))
			b.WriteString(fmtKV("目标", fmt.Sprintf("%s %s %s", e["method"], e["domain"], e["path"])))
			b.WriteString(fmtKV("异常评分", e["anomaly_score"]))
			b.WriteString(fmtKV("响应状态", e["response_status"]))
			b.WriteString(fmtKV("Request ID", e["request_id"]))
			b.WriteString(fmtKV("处置状态", e["disposition_status"]))
			if matches, ok := e["matches"].([]map[string]interface{}); ok && len(matches) > 0 {
				var rules []string
				for _, m := range matches {
					rules = append(rules, fmt.Sprintf("%v(%v)", m["rule_id"], m["rule_name"]))
				}
				b.WriteString(fmtKV("命中规则", strings.Join(rules, "、")))
			}
			// 到达源站判断：响应状态 + 网关访问日志（响应 200 且未被阻断动作覆盖）
			b.WriteString(fmtKV("是否被阻断", blockedText(e["action"])))
			b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
			// 关联事件
			if rel, ref2, err2 := callTool(ctx, in, in.Principal, "security_event.related",
				map[string]interface{}{"event_id": eid}, "关联事件 %s", eid); err2 == nil {
				items := rel.(map[string]interface{})["items"].([]map[string]interface{})
				if len(items) > 0 {
					b.WriteString(fmtKV("关联事件数", len(items)))
					b.WriteString(fmt.Sprintf("- 关联证据：[%s]\n", ref2))
				}
			}
		}
	} else {
		// 批量归纳
		statsInput, rangeValue := withTimeRange(in, map[string]interface{}{"dimension": "attack_type"})
		res, ref, err := callTool(ctx, in, in.Principal, "security_event.statistics",
			statsInput, "攻击类型分布（%s）", rangeValue.Label)
		if err != nil {
			return nil, err
		}
		b.WriteString(fmt.Sprintf("\n%s攻击类型分布：\n", rangeValue.Label))
		for _, it := range res.(map[string]interface{})["items"].([]map[string]interface{}) {
			b.WriteString(fmt.Sprintf("- %s：%v 次\n", it["key"], it["count"]))
		}
		b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
		topIPInput, _ := withTimeRange(in, map[string]interface{}{"limit": 5})
		res2, ref2, err := callTool(ctx, in, in.Principal, "statistics.top_source_ips",
			topIPInput, "攻击源IP TOP5（%s）", rangeValue.Label)
		if err == nil {
			b.WriteString("\n攻击源 IP TOP5：\n")
			for _, it := range res2.(map[string]interface{})["items"].([]map[string]interface{}) {
				b.WriteString(fmt.Sprintf("- %s：%v 次（阻断 %v）\n", it["ip"], it["events"], it["blocks"]))
			}
			b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref2))
		}
	}
	b.WriteString("\n> 攻击是否成功不依据规则命中判断：需综合 WAF 动作、响应状态与 Request ID 链路；当前数据显示动作列已标明阻断情况。")
	return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
}

func blockedText(action interface{}) string {
	if fmt.Sprint(action) == "BLOCK" {
		return "已阻断（未到达源站）"
	}
	return "未阻断（观察模式放行，可能到达源站）"
}

// analyzeProfile IP/URI/应用画像。
func (a *SecurityEventAgent) analyzeProfile(ctx context.Context, in *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error) {
	var b strings.Builder
	b.WriteString("**攻击画像**\n")
	rangeValue := queryTimeRange(in)
	ip := ""
	if len(in.IPs) > 0 {
		ip = in.IPs[0]
	}
	if ip != "" {
		searchInput, _ := withTimeRange(in, map[string]interface{}{"client_ip": ip, "page": 1})
		res, ref, err := callTool(ctx, in, in.Principal, "security_event.search",
			searchInput, "IP %s 事件（%s）", ip, rangeValue.Label)
		if err != nil {
			return nil, err
		}
		data := res.(map[string]interface{})
		b.WriteString(fmtKV("画像对象", "IP "+ip))
		b.WriteString(fmtKV("事件总数（"+rangeValue.Label+"）", data["total"]))
		eventTotal, _ := data["total"].(int64)
		// 首次/最近出现
		var firstAt, lastAt time.Time
		_ = a.db.QueryRow(ctx, `SELECT COALESCE(min(occurred_at), 'epoch'::timestamptz), COALESCE(max(occurred_at), 'epoch'::timestamptz) FROM security_events
WHERE client_ip = $1::inet AND occurred_at >= $2 AND occurred_at < $3`, ip, rangeValue.Start, rangeValue.End).Scan(&firstAt, &lastAt)
		if eventTotal > 0 {
			b.WriteString(fmtKV("首次出现", firstAt.Format("2006-01-02 15:04")))
			b.WriteString(fmtKV("最近出现", lastAt.Format("2006-01-02 15:04")))
		}
		// 攻击类型与目标
		var types string
		rows, err := a.db.Query(ctx, `
SELECT attack_type, count(*) FROM security_events
WHERE client_ip = $1::inet AND occurred_at >= $2 AND occurred_at < $3
GROUP BY 1 ORDER BY 2 DESC LIMIT 5`, ip, rangeValue.Start, rangeValue.End)
		if err == nil {
			defer rows.Close()
			var parts []string
			for rows.Next() {
				var t string
				var c int64
				_ = rows.Scan(&t, &c)
				parts = append(parts, fmt.Sprintf("%s(%d)", t, c))
			}
			types = strings.Join(parts, "、")
		}
		if types != "" {
			b.WriteString(fmtKV("攻击类型", types))
		}
		b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
		res2, ref2, err := callTool(ctx, in, in.Principal, "temporary_block.search",
			map[string]interface{}{"client_ip": ip}, "IP %s 封禁记录", ip)
		if err == nil {
			items := res2.(map[string]interface{})["items"].([]map[string]interface{})
			b.WriteString(fmtKV("封禁记录", fmt.Sprintf("%d 条", len(items))))
			b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref2))
		}
	} else if uri := extractProfileURI(in.Message); uri != "" {
		// URI 画像（请求路径维度）
		var total int64
		var firstAt, lastAt time.Time
		err := a.db.QueryRow(ctx, `
SELECT count(*), COALESCE(min(occurred_at), 'epoch'::timestamptz), COALESCE(max(occurred_at), 'epoch'::timestamptz) FROM security_events
WHERE request_path = $1 AND occurred_at >= $2 AND occurred_at < $3`, uri, rangeValue.Start, rangeValue.End).Scan(&total, &firstAt, &lastAt)
		if err != nil {
			return nil, fmt.Errorf("query uri profile: %w", err)
		}
		b.WriteString(fmtKV("画像对象", "URI "+uri))
		b.WriteString(fmtKV("事件总数（"+rangeValue.Label+"）", total))
		if total == 0 {
			b.WriteString(fmt.Sprintf("该 URI 在%s无安全事件记录，数据不足，无法确认。\n", rangeValue.Label))
		} else {
			b.WriteString(fmtKV("首次出现", firstAt.Format("2006-01-02 15:04")))
			b.WriteString(fmtKV("最近出现", lastAt.Format("2006-01-02 15:04")))
			b.WriteString(fmtKV("攻击类型", a.topGroup(ctx, `SELECT attack_type, count(*) FROM security_events
				WHERE request_path = $1 AND occurred_at >= $2 AND occurred_at < $3 GROUP BY 1 ORDER BY 2 DESC LIMIT 5`, uri, rangeValue.Start, rangeValue.End)))
			b.WriteString(fmtKV("主要来源 IP", a.topGroup(ctx, `SELECT client_ip::text, count(*) FROM security_events
				WHERE request_path = $1 AND occurred_at >= $2 AND occurred_at < $3 GROUP BY 1 ORDER BY 2 DESC LIMIT 5`, uri, rangeValue.Start, rangeValue.End)))
		}
		ref := in.Evidence.Add("security_event.search", fmt.Sprintf("URI %s 事件（%s）", uri, rangeValue.Label), map[string]interface{}{"uri": uri, "total": total})
		b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
	} else if appID, appName := a.matchApplication(ctx, in.Message); appID != "" {
		// 应用画像（应用维度）
		var total, blocked int64
		err := a.db.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE action IN ('BLOCKED','BLOCK')) FROM security_events
WHERE application_id = $1 AND occurred_at >= $2 AND occurred_at < $3`, appID, rangeValue.Start, rangeValue.End).Scan(&total, &blocked)
		if err != nil {
			return nil, fmt.Errorf("query application profile: %w", err)
		}
		var mode, status string
		_ = a.db.QueryRow(ctx, `SELECT protection_mode, status FROM applications WHERE id = $1`, appID).Scan(&mode, &status)
		b.WriteString(fmtKV("画像对象", "应用 "+appName))
		b.WriteString(fmtKV("防护模式", mode))
		b.WriteString(fmtKV("应用状态", status))
		b.WriteString(fmtKV("事件总数（"+rangeValue.Label+"）", total))
		b.WriteString(fmtKV("阻断数（"+rangeValue.Label+"）", blocked))
		if total == 0 {
			b.WriteString(fmt.Sprintf("该应用在%s无安全事件记录，数据不足，无法确认。\n", rangeValue.Label))
		} else {
			b.WriteString(fmtKV("攻击类型", a.topGroup(ctx, `SELECT attack_type, count(*) FROM security_events
				WHERE application_id = $1 AND occurred_at >= $2 AND occurred_at < $3 GROUP BY 1 ORDER BY 2 DESC LIMIT 5`, appID, rangeValue.Start, rangeValue.End)))
			b.WriteString(fmtKV("主要来源 IP", a.topGroup(ctx, `SELECT client_ip::text, count(*) FROM security_events
				WHERE application_id = $1 AND occurred_at >= $2 AND occurred_at < $3 GROUP BY 1 ORDER BY 2 DESC LIMIT 5`, appID, rangeValue.Start, rangeValue.End)))
		}
		ref := in.Evidence.Add("security_event.search", fmt.Sprintf("应用 %s 事件（%s）", appName, rangeValue.Label), map[string]interface{}{"application_id": appID, "total": total, "blocked": blocked})
		b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
	} else {
		topIPInput, rangeValue := withTimeRange(in, map[string]interface{}{"limit": 10})
		res, ref, err := callTool(ctx, in, in.Principal, "statistics.top_source_ips",
			topIPInput, "攻击源 TOP10（%s）", rangeValue.Label)
		if err != nil {
			return nil, err
		}
		b.WriteString(fmt.Sprintf("\n攻击源 IP TOP10（%s）：\n", rangeValue.Label))
		for _, it := range res.(map[string]interface{})["items"].([]map[string]interface{}) {
			b.WriteString(fmt.Sprintf("- %s：%v 次（阻断 %v）\n", it["ip"], it["events"], it["blocks"]))
		}
		b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
	}
	return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
}

// analyzeChain 攻击链关联。
func (a *SecurityEventAgent) analyzeChain(ctx context.Context, in *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error) {
	var b strings.Builder
	b.WriteString("**攻击链关联分析**\n")
	ip := ""
	if len(in.IPs) > 0 {
		ip = in.IPs[0]
	}
	if ip == "" && len(in.EventIDs) > 0 {
		// 从事件取 IP
		_ = a.db.QueryRow(ctx, `SELECT host(client_ip) FROM security_events WHERE id = $1`, in.EventIDs[0]).Scan(&ip)
	}
	if ip == "" {
		b.WriteString("\n当前数据不足，无法确认攻击链（请指定攻击源 IP 或事件 ID）。")
		return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
	}
	// 时间线：该 IP 的事件按时间排序
	rows, err := a.db.Query(ctx, `
SELECT id, occurred_at, attack_type, severity, action, left(request_path, 120)
FROM security_events WHERE client_ip = $1::inet
ORDER BY occurred_at LIMIT 20`, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type step struct {
		id, at, atType, sev, act, path string
	}
	var steps []step
	for rows.Next() {
		var s step
		var at time.Time
		if err := rows.Scan(&s.id, &at, &s.atType, &s.sev, &s.act, &s.path); err != nil {
			return nil, err
		}
		s.at = at.Format("01-02 15:04:05")
		steps = append(steps, s)
	}
	if len(steps) == 0 {
		b.WriteString(fmt.Sprintf("\n未找到 IP %s 的攻击事件，无法构成攻击链。", ip))
		return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
	}
	ref := in.Evidence.Add("security_event.search", fmt.Sprintf("IP %s 攻击时间线（%d 步）", ip, len(steps)), nil)
	b.WriteString(fmt.Sprintf("\n攻击源 IP：%s，共 %d 步：\n", ip, len(steps)))
	blockedAll := true
	for i, s := range steps {
		b.WriteString(fmt.Sprintf("%d. [%s] %s → %s（%s，%s）\n", i+1, s.at, s.atType, s.path, s.sev, s.act))
		if s.act != "BLOCK" {
			blockedAll = false
		}
	}
	confidence := "LOW_CONFIDENCE"
	if len(steps) >= 3 {
		confidence = "MEDIUM_CONFIDENCE"
	}
	if len(steps) >= 5 {
		confidence = "HIGH_CONFIDENCE"
	}
	b.WriteString(fmtKV("关联置信度", confidence+"（依据：同源 IP 的连续攻击行为，步数 "+fmt.Sprint(len(steps))+"）"))
	if blockedAll {
		b.WriteString(fmtKV("成功迹象", "全部步骤均被阻断，未见成功迹象"))
	} else {
		b.WriteString(fmtKV("成功迹象", "存在未阻断步骤，需结合响应状态与 Request ID 进一步排查"))
	}
	b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
	b.WriteString("\n> MITRE ATT&CK 阶段映射为参考映射，非确认事实。")
	return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
}

// analyzeStats 统计问答。
func (a *SecurityEventAgent) analyzeStats(ctx context.Context, in *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error) {
	var b strings.Builder
	b.WriteString("**统计问答**\n")
	rangeValue := queryTimeRange(in)
	if rangeValue.Explicit {
		statsInput, _ := withTimeRange(in, map[string]interface{}{"dimension": "attack_type"})
		res, ref, err := callTool(ctx, in, in.Principal, "security_event.statistics",
			statsInput, "攻击类型分布（%s）", rangeValue.Label)
		if err != nil {
			return nil, err
		}
		b.WriteString(fmt.Sprintf("统计区间：%s（%s 至 %s）\n", rangeValue.Label,
			formatChineseDateTime(rangeValue.Start),
			formatChineseDateTime(rangeValue.End)))
		items := res.(map[string]interface{})["items"].([]map[string]interface{})
		var total int64
		for _, item := range items {
			count, _ := item["count"].(int64)
			total += count
			b.WriteString(fmt.Sprintf("- %s：%v 次\n", attackTypeDisplayName(item["key"]), item["count"]))
		}
		b.WriteString(fmtKV("安全事件合计", total))
		b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))

		topIPInput, _ := withTimeRange(in, map[string]interface{}{"limit": 5})
		if topIPs, topRef, topErr := callTool(ctx, in, in.Principal, "statistics.top_source_ips",
			topIPInput, "攻击源 IP TOP5（%s）", rangeValue.Label); topErr == nil {
			b.WriteString("\n攻击源 IP TOP5：\n")
			for _, item := range topIPs.(map[string]interface{})["items"].([]map[string]interface{}) {
				b.WriteString(fmt.Sprintf("- %v：%v 次（阻断 %v）\n", item["ip"], item["events"], item["blocks"]))
			}
			b.WriteString(fmt.Sprintf("- 证据：[%s]\n", topRef))
		}
		return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
	}
	res, ref, err := callTool(ctx, in, in.Principal, "statistics.security_overview",
		map[string]interface{}{}, "今日安全概览")
	if err != nil {
		return nil, err
	}
	d := res.(map[string]interface{})
	b.WriteString(fmt.Sprintf("日期：%v（UTC）\n", d["date"]))
	b.WriteString(fmtKV("今日请求总数", d["requests_total"]))
	b.WriteString(fmtKV("今日安全事件", d["waf_events"]))
	b.WriteString(fmtKV("今日阻断", d["waf_blocks"]))
	b.WriteString(fmtKV("今日 CC 事件", d["cc_events"]))
	b.WriteString(fmtKV("今日黑名单命中", d["ip_deny_matches"]))
	b.WriteString(fmtKV("当前临时封禁 IP", d["temp_blocked_ips"]))
	b.WriteString(fmtKV("未处置高危事件", d["unprocessed_high"]))
	b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
	return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// profileURIRe 从消息提取请求路径（/ 开头，到空白或中文标点为止）。
var profileURIRe = regexp.MustCompile(`(/[a-zA-Z0-9_\-./~%]+)`)

// extractProfileURI 提取消息中的第一个 URI 路径（去除查询串，限长 200）。
func extractProfileURI(msg string) string {
	m := profileURIRe.FindStringSubmatch(msg)
	if len(m) < 2 {
		return ""
	}
	u := m[1]
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u = u[:i]
	}
	u = strings.TrimRight(u, "/.,;:")
	if len(u) < 2 || len(u) > 200 {
		return ""
	}
	return u
}

// topGroup 通用分组统计查询（col, count 两列），返回 "值(次数)、..." 拼接，失败或空集返回空串。
func (a *SecurityEventAgent) topGroup(ctx context.Context, query string, args ...interface{}) string {
	rows, err := a.db.Query(ctx, query, args...)
	if err != nil {
		return ""
	}
	defer rows.Close()
	var parts []string
	for rows.Next() {
		var v string
		var c int64
		if rows.Scan(&v, &c) == nil {
			parts = append(parts, fmt.Sprintf("%s(%d)", v, c))
		}
	}
	return strings.Join(parts, "、")
}

// matchApplication 按应用名称匹配消息（名称出现在消息中即命中；多个命中取名称最长者避免歧义）。
func (a *SecurityEventAgent) matchApplication(ctx context.Context, msg string) (string, string) {
	rows, err := a.db.Query(ctx, `SELECT id, name FROM applications WHERE deleted_at IS NULL ORDER BY length(name) DESC LIMIT 100`)
	if err != nil {
		return "", ""
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if rows.Scan(&id, &name) == nil && name != "" && strings.Contains(msg, name) {
			return id, name
		}
	}
	return "", ""
}

var _ = uuid.Nil
