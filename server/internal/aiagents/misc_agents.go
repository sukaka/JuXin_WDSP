// misc_agents.go 日志分析/资产/运维诊断/报告/知识库 Agent。
package aiagents

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aiorchestrator"
)

// ---------- 日志分析 Agent ----------

// LogAnalysisAgent 日志与链路分析。
type LogAnalysisAgent struct{ base }

// NewLogAnalysisAgent 创建。
func NewLogAnalysisAgent(db *pgxpool.Pool) *LogAnalysisAgent {
	return &LogAnalysisAgent{base{code: "log_analysis", db: db}}
}

// Analyze 日志查询与链路追踪。
func (a *LogAnalysisAgent) Analyze(ctx context.Context, in *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error) {
	var b strings.Builder
	b.WriteString("**日志分析**\n")
	// Request ID 追踪
	idRe := in.EventIDs
	if len(idRe) > 0 {
		res, ref, err := callTool(ctx, in, in.Principal, "request_trace.get",
			map[string]interface{}{"request_id": idRe[0]}, "Request ID 链路 %s", idRe[0])
		if err == nil {
			if t := safeMap(res); t != nil {
				b.WriteString(fmt.Sprintf("\nRequest ID %s：\n", idRe[0]))
				b.WriteString(fmtKV("WAF 事件数", len(safeAnySlice(t, "waf_events"))))
				b.WriteString(fmtKV("访问控制事件数", len(safeAnySlice(t, "access_control_events"))))
				b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
			}
		}
	}
	// 访问控制事件摘要
	res, ref, err := callTool(ctx, in, in.Principal, "access_control_log.search",
		map[string]interface{}{"page": 1}, "最近访问控制/CC事件")
	if err == nil {
		if d := safeMap(res); d != nil {
			b.WriteString(fmt.Sprintf("\n最近访问控制/CC事件（共 %v 条）：\n", d["total"]))
			items := safeMapSlice(d, "items")
			for _, it := range items[:min(5, len(items))] {
				b.WriteString(fmt.Sprintf("- %v %s %s（%s）\n", it["occurred_at"], it["event_type"], it["client_ip"], it["action"]))
			}
			b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
		}
	}
	// 审计摘要（运维类查询）
	res2, ref2, err := callTool(ctx, in, in.Principal, "audit_log.search",
		map[string]interface{}{"page": 1}, "最近操作审计")
	if err == nil {
		if d := safeMap(res2); d != nil {
			b.WriteString(fmt.Sprintf("\n最近操作审计（共 %v 条）：\n", d["total"]))
			items := safeMapSlice(d, "items")
			for _, it := range items[:min(5, len(items))] {
				b.WriteString(fmt.Sprintf("- %v %s %s/%s\n", it["occurred_at"], it["username"], it["module"], it["action"]))
			}
			b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref2))
		}
	}
	return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
}

// ---------- 资产 Agent ----------

// AssetAgent 应用/域名/证书资产分析。
type AssetAgent struct{ base }

// NewAssetAgent 创建。
func NewAssetAgent(db *pgxpool.Pool) *AssetAgent {
	return &AssetAgent{base{code: "asset", db: db}}
}

// Analyze 资产盘点。
func (a *AssetAgent) Analyze(ctx context.Context, in *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error) {
	var b strings.Builder
	b.WriteString("**资产概览**\n")
	res, ref, err := callTool(ctx, in, in.Principal, "application.search", map[string]interface{}{}, "应用清单")
	if err == nil {
		if d := safeMap(res); d != nil {
			b.WriteString(fmtKV("受保护应用数", d["total"]))
			items := safeMapSlice(d, "items")
			for _, it := range items[:min(5, len(items))] {
				b.WriteString(fmt.Sprintf("- %s（%s，%s）\n", it["name"], it["code"], it["protection_mode"]))
			}
			b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
		}
	}
	res2, ref2, err := callTool(ctx, in, in.Principal, "certificate.get_metadata",
		map[string]interface{}{"expiring_days": 30}, "30天内到期证书")
	if err == nil {
		items := safeMapSlice(safeMap(res2), "items")
		b.WriteString(fmtKV("30天内到期证书", len(items)))
		for _, it := range items[:min(5, len(items))] {
			b.WriteString(fmt.Sprintf("- %s（剩余 %v 天）\n", it["common_name"], it["days_remaining"]))
		}
		b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref2))
	}
	res3, ref3, err := callTool(ctx, in, in.Principal, "gateway.get_status", map[string]interface{}{}, "网关状态")
	if err == nil {
		if d := safeMap(res3); d != nil {
			b.WriteString(fmtKV("当前配置版本", d["current_version"]))
			b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref3))
		}
	}
	return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
}

// ---------- 运维诊断 Agent ----------

// OpsDiagnosticAgent 运行异常根因分析。
type OpsDiagnosticAgent struct{ base }

// NewOpsDiagnosticAgent 创建。
func NewOpsDiagnosticAgent(db *pgxpool.Pool) *OpsDiagnosticAgent {
	return &OpsDiagnosticAgent{base{code: "ops_diagnostic", db: db}}
}

// Analyze 根因分析。
func (a *OpsDiagnosticAgent) Analyze(ctx context.Context, in *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error) {
	var b strings.Builder
	b.WriteString("**根因分析**\n")
	// 组件状态
	res, ref, err := callTool(ctx, in, in.Principal, "statistics.runtime", map[string]interface{}{}, "组件健康快照")
	if err == nil {
		var downs []string
		for _, c := range safeMapSlice(safeMap(res), "components") {
			if c["status"] != "UP" {
				downs = append(downs, fmt.Sprintf("%s(%s)", c["component"], c["status"]))
			}
		}
		if len(downs) > 0 {
			b.WriteString(fmtKV("异常组件", strings.Join(downs, "、")))
		} else {
			b.WriteString(fmtKV("组件状态", "全部 UP"))
		}
		b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
	}
	// 系统告警
	res2, ref2, err := callTool(ctx, in, in.Principal, "system_log.search",
		map[string]interface{}{"status": "OPEN"}, "未关闭系统告警")
	if err == nil {
		items := safeMapSlice(safeMap(res2), "items")
		b.WriteString(fmtKV("未关闭告警", len(items)))
		for _, it := range items[:min(5, len(items))] {
			b.WriteString(fmt.Sprintf("- [%s] %s（%s）\n", it["severity"], it["title"], it["component"]))
		}
		b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref2))
	}
	// 最近发布/变更
	var pubFail, pubTotal int64
	if a.db != nil {
		_ = a.db.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE status='FAILED') FROM gateway_publish_tasks
WHERE requested_at > now() - interval '7 days'`).Scan(&pubTotal, &pubFail)
	}
	b.WriteString(fmtKV("近7天发布", fmt.Sprintf("%d 次（失败 %d）", pubTotal, pubFail)))
	// 采集滞后
	var lag float64
	if a.db != nil {
		_ = a.db.QueryRow(ctx, `
SELECT COALESCE(EXTRACT(EPOCH FROM (now() - max(updated_at))), 0) FROM event_collector_checkpoints`).Scan(&lag)
	}
	if lag > 120 {
		b.WriteString(fmtKV("事件采集滞后", fmt.Sprintf("%.0f 秒（超阈值 120s）", lag)))
	}
	// 结论分级
	b.WriteString("\n**原因分级**\n")
	confirmed := []string{}
	probable := []string{}
	toVerify := []string{}
	b.WriteString(fmtKV("已确认", joinOr(confirmed, "暂无直接证据确认的具体原因")))
	if lag > 120 {
		probable = append(probable, "事件采集滞后导致事件延迟（checkpoint 推进超时）")
	}
	if pubFail > 0 {
		probable = append(probable, fmt.Sprintf("近 7 天存在 %d 次发布失败，建议核查发布任务错误详情", pubFail))
	}
	b.WriteString(fmtKV("高概率", joinOr(probable, "暂无明显异常迹象")))
	toVerify = append(toVerify, "如需进一步定位，请提供具体组件或时间段")
	b.WriteString(fmtKV("待验证", joinOr(toVerify, "-")))
	b.WriteString("\n> 不执行重启/升级/恢复/配置修改等操作，以上仅为诊断建议。")
	return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
}

func joinOr(items []string, def string) string {
	if len(items) == 0 {
		return def
	}
	return strings.Join(items, "；")
}

// ---------- 报告 Agent ----------

// ReportAgent 报告总结（仅使用阶段6真实统计数据）。
type ReportAgent struct{ base }

// NewReportAgent 创建。
func NewReportAgent(db *pgxpool.Pool) *ReportAgent {
	return &ReportAgent{base{code: "report", db: db}}
}

// Analyze 报告总结。
func (a *ReportAgent) Analyze(ctx context.Context, in *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error) {
	var b strings.Builder
	b.WriteString("**安全运营报告总结**（数据均来自真实统计，时间范围：近 7 天）\n")
	start := time.Now().Add(-7 * 24 * time.Hour).UTC()
	// 事件总量与阻断
	var total, blocked, observes int64
	_ = a.db.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE action='BLOCK'), count(*) FILTER (WHERE action='OBSERVE')
FROM security_events WHERE occurred_at >= $1`, start).Scan(&total, &blocked, &observes)
	b.WriteString(fmtKV("安全事件总数", total))
	b.WriteString(fmtKV("阻断", blocked))
	b.WriteString(fmtKV("观察", observes))
	// 攻击类型 TOP
	rows, err := a.db.Query(ctx, `
SELECT attack_type, count(*) FROM security_events WHERE occurred_at >= $1
GROUP BY 1 ORDER BY 2 DESC LIMIT 5`, start)
	if err == nil {
		defer rows.Close()
		var parts []string
		for rows.Next() {
			var t string
			var c int64
			if rows.Scan(&t, &c) == nil {
				parts = append(parts, fmt.Sprintf("%s(%d)", t, c))
			}
		}
		if rows.Err() == nil {
			b.WriteString(fmtKV("主要攻击类型", strings.Join(parts, "、")))
		}
	}
	ref := in.Evidence.Add("statistics.security_overview", "近7天事件统计", nil)
	// 来源 IP TOP
	res, ref2, err := callTool(ctx, in, in.Principal, "statistics.top_source_ips",
		map[string]interface{}{"limit": 5, "start_time": start.Format(time.RFC3339)}, "近7天攻击源 TOP5")
	if err == nil {
		b.WriteString("\n主要攻击源：\n")
		for _, it := range safeMapSlice(safeMap(res), "items") {
			b.WriteString(fmt.Sprintf("- %s：%v 次\n", it["ip"], it["events"]))
		}
		b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref2))
	}
	// 误报与处置
	var fp, unprocessed int64
	_ = a.db.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE disposition_status='CONFIRMED_FALSE_POSITIVE'),
       count(*) FILTER (WHERE disposition_status='UNPROCESSED')
FROM security_events WHERE occurred_at >= $1`, start).Scan(&fp, &unprocessed)
	b.WriteString(fmtKV("误报标记", fp))
	b.WriteString(fmtKV("未处置事件", unprocessed))
	// CC 与访问控制
	var cc int64
	_ = a.db.QueryRow(ctx, `SELECT count(*) FROM access_control_events WHERE occurred_at >= $1 AND event_type LIKE 'CC%'`, start).Scan(&cc)
	b.WriteString(fmtKV("CC 事件", cc))
	// 组件健康
	var downs int64
	_ = a.db.QueryRow(ctx, `
SELECT count(*) FROM (SELECT DISTINCT ON (component) component, status FROM system_health_snapshots
  ORDER BY component, taken_at DESC) s WHERE status <> 'UP'`).Scan(&downs)
	b.WriteString(fmtKV("异常组件数", downs))
	b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
	b.WriteString("\n**建议**\n")
	b.WriteString("- 优先处置未处置高危事件；误报率高的规则做精确例外收敛；关注异常组件并复核告警。")
	return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
}

// ---------- 知识库 Agent ----------

// KnowledgeAgent CRS/产品文档知识问答（知识≠当前运行事实）。
type KnowledgeAgent struct{ base }

// NewKnowledgeAgent 创建。
func NewKnowledgeAgent(db *pgxpool.Pool) *KnowledgeAgent {
	return &KnowledgeAgent{base{code: "knowledge", db: db}}
}

// Analyze 知识问答（基于本地规则元数据与文档说明）。
func (a *KnowledgeAgent) Analyze(ctx context.Context, in *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error) {
	// 问候/能力询问不应查规则库（双保险；主路径已在意图分类短路）
	if aiorchestrator.IsGreetingOrHelp(in.Message) {
		return &aiorchestrator.AnalyzeResult{FactsText: aiorchestrator.CapabilityIntro()}, nil
	}
	var b strings.Builder
	b.WriteString("**知识解答**（基于 OWASP CRS 与产品文档，非当前运行事实）\n")
	if len(in.RuleIDs) > 0 {
		res, ref, err := callTool(ctx, in, in.Principal, "rule.get",
			map[string]interface{}{"rule_id": in.RuleIDs[0]}, "规则 %d 元数据", in.RuleIDs[0])
		if err == nil {
			if r := safeMap(res); r != nil {
				b.WriteString(fmtKV("规则", fmt.Sprintf("%d（%s / %s / %s）", r["rule_id"], r["name"], r["attack_type"], r["severity"])))
				b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
			}
		}
	} else {
		// 关键字搜索规则库：过短或明显非规则/攻击类问题不直接拿整句去 ILIKE（防「你好」「天气」类误查）
		kw := knowledgeSearchKeyword(in.Message)
		if kw == "" {
			b.WriteString("\n当前问题未指向具体规则或攻击类型。我专注于 WAF 安全运营（规则解释、事件分析、攻击统计、策略建议等）。\n")
			b.WriteString("建议换一种问法，例如：「942100 规则是干什么的」「SQL 注入相关规则」「XSS 防护说明」。\n")
		} else {
			rows, err := a.db.Query(ctx, `
SELECT rule_id, name, severity, attack_type FROM waf_rules
WHERE name ILIKE '%' || $1 || '%' OR message ILIKE '%' || $1 || '%' OR attack_type ILIKE '%' || $1 || '%'
ORDER BY rule_id LIMIT 5`, kw)
			if err == nil {
				defer rows.Close()
				found := false
				for rows.Next() {
					var rid int
					var n, s, at string
					if rows.Scan(&rid, &n, &s, &at) != nil {
						continue
					}
					if !found {
						b.WriteString("\n相关规则：\n")
						found = true
					}
					b.WriteString(fmt.Sprintf("- %d %s（%s，%s）\n", rid, n, s, at))
				}
				if rows.Err() != nil {
					found = false
				}
				if !found {
					b.WriteString(fmt.Sprintf("\n未在本地规则库中找到与「%s」直接相关的条目。可尝试：规则 ID（如 942100）、攻击类型英文代号（SQL_INJECTION / XSS）或更具体的规则名称关键词。\n", kw))
				}
			}
		}
	}
	b.WriteString("\n说明：知识解释不代表当前系统正发生对应攻击；当前运行事实请以事件与统计查询为准。")
	return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
}

// knowledgeSearchKeyword 从用户问题中提取适合规则库检索的关键字；无法安全检索时返回空串。
func knowledgeSearchKeyword(message string) string {
	kw := strings.TrimSpace(message)
	if kw == "" {
		return ""
	}
	// 过短（如「你好」「天气」）不当作规则关键字
	if len([]rune(kw)) < 2 {
		return ""
	}
	// 含安全/规则相关词时，优先抽核心术语，避免整句噪声
	termRe := regexp.MustCompile(`(?i)(sql\s*injection|sql注入|xss|rce|lfi|rfi|ssrf|csrf|命令注入|路径穿越|扫描|爬虫|暴力破解|cc攻击|owasp|crs|waf|异常评分|[a-z_]{3,}|[\p{Han}]{2,})`)
	// 若整句像完整自然语言问题且不含规则语义，拒绝盲搜
	lower := strings.ToLower(kw)
	securityHint := regexp.MustCompile(`(?i)规则|攻击|注入|xss|sql|拦截|阻断|防护|payload|漏洞|扫描|waf|crs|owasp|异常|评分`)
	if !securityHint.MatchString(lower) && !regexp.MustCompile(`\d{6,7}`).MatchString(kw) {
		// 非安全语义的通用问题（天气、闲聊等）
		if len([]rune(kw)) <= 20 {
			return ""
		}
	}
	// 截断检索串
	if len([]rune(kw)) > 40 {
		r := []rune(kw)
		kw = string(r[:40])
	}
	// 去掉常见问句前缀，提高命中
	for _, p := range []string{"请问", "请解释", "解释一下", "什么是", "什么叫", "帮我看看", "帮我查"} {
		kw = strings.TrimPrefix(kw, p)
	}
	kw = strings.TrimSpace(kw)
	if len([]rune(kw)) < 2 {
		return ""
	}
	_ = termRe // 保留扩展点：后续可改为术语抽取优先
	return kw
}

var _ = time.Now
