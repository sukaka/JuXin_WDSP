// policy_agent.go WAF策略 Agent：误报研判、规则解释、策略建议、What-If 模拟。
package aiagents

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aiorchestrator"
)

// WafPolicyAgent WAF 策略 Agent。
type WafPolicyAgent struct{ base }

// NewWafPolicyAgent 创建。
func NewWafPolicyAgent(db *pgxpool.Pool) *WafPolicyAgent {
	return &WafPolicyAgent{base{code: "waf_policy", db: db}}
}

// Analyze 按任务类型执行。
func (a *WafPolicyAgent) Analyze(ctx context.Context, in *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error) {
	switch in.TaskType {
	case aiorchestrator.TaskFalsePositive:
		return a.falsePositive(ctx, in)
	case aiorchestrator.TaskRuleExplanation:
		return a.ruleExplain(ctx, in)
	case aiorchestrator.TaskPolicyRec:
		return a.recommend(ctx, in)
	case aiorchestrator.TaskWhatIf:
		return a.whatIf(ctx, in)
	default:
		return a.ruleExplain(ctx, in)
	}
}

// falsePositive 误报研判。
func (a *WafPolicyAgent) falsePositive(ctx context.Context, in *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error) {
	var b strings.Builder
	b.WriteString("**误报研判**\n")
	if len(in.EventIDs) == 0 && len(in.RuleIDs) == 0 {
		b.WriteString("\n当前数据不足，无法确认。请提供事件 ID 或规则 ID。")
		return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
	}
	ruleID := 0
	if len(in.RuleIDs) > 0 {
		ruleID = in.RuleIDs[0]
	}
	var event map[string]interface{}
	if len(in.EventIDs) > 0 {
		res, ref, err := callTool(ctx, in, in.Principal, "security_event.get",
			map[string]interface{}{"event_id": in.EventIDs[0]}, "误报事件详情 %s", in.EventIDs[0])
		if err == nil {
			event = res.(map[string]interface{})
			if ruleID == 0 {
				if matches, ok := event["matches"].([]map[string]interface{}); ok && len(matches) > 0 {
					if rid, ok := matches[0]["rule_id"].(int); ok {
						ruleID = rid
					}
				}
			}
			b.WriteString(fmt.Sprintf("\n事件 %s：%s %s %s（%s）\n", in.EventIDs[0][:8]+"...",
				event["method"], event["domain"], event["path"], event["attack_type"]))
			b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
		}
	}
	if ruleID > 0 {
		res, ref, err := callTool(ctx, in, in.Principal, "rule.get",
			map[string]interface{}{"rule_id": ruleID}, "规则 %d 详情", ruleID)
		if err == nil {
			r := res.(map[string]interface{})
			b.WriteString(fmtKV("命中规则", fmt.Sprintf("%d（%s，%s，%s）", ruleID, r["name"], r["severity"], r["attack_type"])))
			b.WriteString(fmtKV("累计命中", r["hit_count"]))
			b.WriteString(fmtKV("历史误报标记", r["false_positive_count"]))
			b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
		}
		// 历史误报率
		var hits, fps int64
		_ = a.db.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE e.disposition_status='CONFIRMED_FALSE_POSITIVE')
FROM security_event_matches m JOIN security_events e ON e.id = m.event_id
WHERE m.rule_id = $1 AND e.occurred_at > now() - interval '30 days'`, ruleID).Scan(&hits, &fps)
		if hits > 0 {
			b.WriteString(fmtKV("近30天误报率", fmt.Sprintf("%d/%d（%.1f%%）", fps, hits, float64(fps)*100/float64(hits))))
		}
		// 已有例外
		res2, ref2, err := callTool(ctx, in, in.Principal, "exception.search",
			map[string]interface{}{"status": "ENABLED"}, "当前生效例外")
		if err == nil {
			items := res2.(map[string]interface{})["items"].([]map[string]interface{})
			b.WriteString(fmtKV("当前生效例外数", len(items)))
			b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref2))
		}
		// 推荐例外范围（精确优先）
		b.WriteString("\n**研判建议**（草稿需人工确认）\n")
		if event != nil {
			path := fmt.Sprint(event["path"])
			app := fmt.Sprint(event["application"])
			b.WriteString(fmt.Sprintf("- 推荐例外范围：应用「%s」+ URI「%s」+ 规则 %d（精确例外，不全局）\n", app, path, ruleID))
			b.WriteString("- 建议有效期：先 24 小时临时例外观察，确认无攻击后转永久\n")
		} else {
			b.WriteString(fmt.Sprintf("- 推荐例外范围：按应用 + 规则 %d 限定，禁止全局关闭\n", ruleID))
		}
		b.WriteString("- 验证方法：重放该请求确认放行，同时抽样同类攻击确认仍被拦截\n")
		b.WriteString("- 可通过 draft.exception.create 生成草稿（DRAFT，需人工审核）\n")
	}
	return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
}

// ruleExplain 规则解释。
func (a *WafPolicyAgent) ruleExplain(ctx context.Context, in *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error) {
	var b strings.Builder
	b.WriteString("**规则解释**\n")
	ruleID := 0
	if len(in.RuleIDs) > 0 {
		ruleID = in.RuleIDs[0]
	}
	if ruleID == 0 {
		b.WriteString("\n请提供规则 ID（如 942100）。")
		return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
	}
	res, ref, err := callTool(ctx, in, in.Principal, "rule.get",
		map[string]interface{}{"rule_id": ruleID}, "规则 %d 详情", ruleID)
	if err != nil {
		b.WriteString(fmt.Sprintf("\n规则 %d 不存在或未同步到本地库，无法确认。", ruleID))
		return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
	}
	r := res.(map[string]interface{})
	b.WriteString(fmtKV("规则", fmt.Sprintf("%d（来源 %s，CRS %s）", ruleID, r["rule_source"], crsVersion(a.db, ctx, ruleID))))
	b.WriteString(fmtKV("名称", r["name"]))
	b.WriteString(fmtKV("攻击类型", r["attack_type"]))
	b.WriteString(fmtKV("严重级别", r["severity"]))
	b.WriteString(fmtKV("检测阶段", r["phase"]))
	b.WriteString(fmtKV("命中次数", r["hit_count"]))
	b.WriteString(fmtKV("误报标记", r["false_positive_count"]))
	b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
	b.WriteString("\n说明：规则检测逻辑摘要基于本地元数据（名称/类型/阶段），不复制上游规则源代码；解释不等同于当前系统正遭受该类攻击。")
	return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
}

func crsVersion(db *pgxpool.Pool, ctx context.Context, ruleID int) string {
	var v string
	_ = db.QueryRow(ctx, `SELECT crs_version FROM waf_rules WHERE rule_id = $1`, ruleID).Scan(&v)
	return v
}

// recommend 策略建议。
func (a *WafPolicyAgent) recommend(ctx context.Context, in *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error) {
	var b strings.Builder
	b.WriteString("**策略优化建议**\n")
	res, ref, err := callTool(ctx, in, in.Principal, "policy.get", map[string]interface{}{}, "当前防护策略列表")
	if err != nil {
		return nil, err
	}
	items := res.(map[string]interface{})["items"].([]map[string]interface{})
	if len(items) == 0 {
		b.WriteString("\n当前无策略数据，无法给出建议。")
		return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
	}
	for _, p := range items[:3] {
		b.WriteString(fmt.Sprintf("- 策略「%s」：模式 %s，PL%d，阈值 入%d/出%d%s\n",
			p["name"], p["protection_mode"], p["paranoia_level"], p["inbound_threshold"], p["outbound_threshold"],
			map[bool]string{true: "（内置）", false: ""}[p["is_builtin"].(bool)]))
	}
	b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
	// 近 7 天事件统计支撑
	res2, ref2, err := callTool(ctx, in, in.Principal, "security_event.statistics",
		map[string]interface{}{"dimension": "attack_type"}, "近7天攻击类型分布")
	if err == nil {
		b.WriteString("\n近 7 天攻击类型分布：\n")
		for _, it := range res2.(map[string]interface{})["items"].([]map[string]interface{})[:min(5, len(res2.(map[string]interface{})["items"].([]map[string]interface{})))] {
			b.WriteString(fmt.Sprintf("- %s：%v 次\n", it["key"], it["count"]))
		}
		b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref2))
	}
	res3, ref3, err := callTool(ctx, in, in.Principal, "statistics.top_rules",
		map[string]interface{}{"limit": 5}, "近7天误报规则 TOP")
	if err == nil {
		b.WriteString("\n规则命中与误报 TOP5：\n")
		for _, it := range res3.(map[string]interface{})["items"].([]map[string]interface{}) {
			b.WriteString(fmt.Sprintf("- 规则 %v：命中 %v，误报 %v\n", it["rule_id"], it["hits"], it["false_positives"]))
		}
		b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref3))
	}
	b.WriteString("\n**建议项**\n")
	b.WriteString("- 误报率高的规则建议先做例外收敛而非停用；规则从未命中不等于应关闭（高风险规则保持启用）。\n")
	b.WriteString("- 新应用建议先 OBSERVE 观察 1-2 周再转 PROTECT；阈值调整建议每次不超过 ±2。\n")
	b.WriteString("- 建议均不改变生产配置；变更需走策略编辑 + 配置发布流程。")
	return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
}

// whatIf What-If 历史模拟（规则启停、误报影响；基于历史数据估算）。
func (a *WafPolicyAgent) whatIf(ctx context.Context, in *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error) {
	var b strings.Builder
	b.WriteString("**What-If 策略模拟**（基于历史数据估算，不代表未来确定结果）\n")
	msg := strings.ToLower(in.Message)
	// 模拟 PL 切换：给出近 30 天不同严重级别事件量作为参考
	if strings.Contains(msg, "pl1") || strings.Contains(msg, "pl2") || strings.Contains(msg, "paranoia") || strings.Contains(msg, "执行等级") {
		var crit, high, med, low int64
		_ = a.db.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE severity='CRITICAL'),
  count(*) FILTER (WHERE severity='HIGH' OR severity='ERROR'),
  count(*) FILTER (WHERE severity='MEDIUM' OR severity='WARNING'),
  count(*) FILTER (WHERE severity='LOW' OR severity='NOTICE')
FROM security_events WHERE occurred_at > now() - interval '30 days'`).Scan(&crit, &high, &med, &low)
		b.WriteString("\n**模拟：调整 CRS 执行等级 / 异常阈值（参考）**\n")
		b.WriteString(fmtKV("近30天 CRITICAL 事件", crit))
		b.WriteString(fmtKV("近30天 HIGH/ERROR 事件", high))
		b.WriteString(fmtKV("近30天 MEDIUM/WARNING 事件", med))
		b.WriteString(fmtKV("近30天 LOW/NOTICE 事件", low))
		b.WriteString("- 说明：提高 PL 通常增加命中与潜在误报；降低 PL 可能减少误报但增加漏拦风险。\n")
		b.WriteString("- 建议测试范围：先在 DetectionOnly 或灰度应用验证 7 天。\n")
		b.WriteString("\n> 基于历史数据估算，不代表未来确定结果。\n")
		return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
	}
	// 模拟修改 CC：给出近期 CC 事件量
	if strings.Contains(msg, "cc") || strings.Contains(msg, "限速") || strings.Contains(msg, "频率") {
		var ccTotal, ccReject int64
		_ = a.db.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE action IN ('REJECT','TEMP_BLOCK'))
FROM access_control_events WHERE occurred_at > now() - interval '7 days' AND event_type LIKE 'CC%'`).Scan(&ccTotal, &ccReject)
		b.WriteString("\n**模拟：调整 CC 频率/封禁时长（参考）**\n")
		b.WriteString(fmtKV("近7天 CC 事件", ccTotal))
		b.WriteString(fmtKV("近7天 拒绝/封禁动作", ccReject))
		b.WriteString("- 提高阈值：可能增加漏拦；降低频率：可能增加误伤共享出口。\n")
		b.WriteString("\n> 基于历史数据估算，不代表未来确定结果。\n")
		return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
	}
	ruleID := 0
	if len(in.RuleIDs) > 0 {
		ruleID = in.RuleIDs[0]
	}
	if ruleID == 0 {
		b.WriteString("\n请提供要模拟的规则 ID（如：如果关闭 942100 会怎样），或说明要模拟的 PL/CC 变更。")
		return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
	}
	// 模拟「关闭该规则」对近 30 天历史请求的影响
	var hits, fps, blocks int64
	_ = a.db.QueryRow(ctx, `
SELECT count(*),
  count(*) FILTER (WHERE e.disposition_status='CONFIRMED_FALSE_POSITIVE'),
  count(*) FILTER (WHERE e.action='BLOCK')
FROM security_event_matches m JOIN security_events e ON e.id = m.event_id
WHERE m.rule_id = $1 AND e.occurred_at > now() - interval '30 days'`, ruleID).Scan(&hits, &fps, &blocks)
	b.WriteString(fmt.Sprintf("\n模拟：关闭规则 %d（近 30 天历史回放）\n", ruleID))
	b.WriteString(fmtKV("受影响历史请求", hits))
	b.WriteString(fmtKV("可能减少的误报", fps))
	b.WriteString(fmtKV("可能漏拦的攻击", blocks))
	res, ref, err := callTool(ctx, in, in.Principal, "rule.get", map[string]interface{}{"rule_id": ruleID}, "规则 %d 详情", ruleID)
	if err == nil {
		r := res.(map[string]interface{})
		b.WriteString(fmtKV("规则风险", fmt.Sprintf("%s / %s", r["severity"], r["attack_type"])))
		b.WriteString(fmt.Sprintf("- 证据：[%s]\n", ref))
	}
	risk := "MEDIUM"
	if blocks > 0 {
		risk = "HIGH"
	}
	b.WriteString(fmtKV("模拟风险等级", risk))
	b.WriteString("建议：先对误报样本做精确例外（应用+URI+规则），而非直接停用；停用需 OBSERVE 观察 1 周评估。")
	return &aiorchestrator.AnalyzeResult{FactsText: b.String()}, nil
}

var _ = time.Now
