package reports

import "fmt"

// attackTypeNames 攻击类型 → 中文名称（展示与结论用）。
// 覆盖网关 attackTypeByTag 全集与自研规则包常见类别，未知类型原样返回。
var attackTypeNames = map[string]string{
	"SQL_INJECTION":          "SQL注入",
	"NOSQL_INJECTION":        "NoSQL注入",
	"LDAP_INJECTION":         "LDAP注入",
	"XSS":                    "跨站脚本（XSS）",
	"COMMAND_INJECTION":      "命令注入",
	"PATH_TRAVERSAL":         "路径穿越",
	"RCE":                    "远程代码执行",
	"REMOTE_CODE_EXECUTION":  "远程代码执行",
	"LFI":                    "本地文件包含",
	"LOCAL_FILE_INCLUSION":   "本地文件包含",
	"RFI":                    "远程文件包含",
	"REMOTE_FILE_INCLUSION":  "远程文件包含",
	"PHP_INJECTION":          "PHP注入",
	"JAVA_INJECTION":         "Java攻击",
	"SCANNER":                "扫描器探测",
	"SCANNER_DETECTION":      "扫描器探测",
	"PROTOCOL_VIOLATION":     "协议违规",
	"SESSION_FIXATION":       "会话固定",
	"INFORMATION_DISCLOSURE": "信息泄露",
	"SSRF":                   "服务端请求伪造（SSRF）",
	"FILE_UPLOAD":            "文件上传攻击",
	"TEMPLATE_INJECTION":     "模板注入",
	"XXE":                    "XML外部实体（XXE）",
	"XXE_INJECTION":          "XML外部实体注入（XXE）",
	"WEBSHELL":               "WebShell攻击",
	"DESERIALIZATION":        "不安全反序列化",
	"SSTI":                   "服务端模板注入（SSTI）",
	"DOS":                    "拒绝服务攻击（DoS）",
	"MASS_ASSIGNMENT":        "批量赋值攻击",
	"EXCLUSION":              "规则排除",
	"OTHER":                  "其他攻击",
}

// AttackTypeName 返回攻击类型中文名（未知类型原样返回）。
func AttackTypeName(t string) string {
	if n, ok := attackTypeNames[t]; ok {
		return n
	}
	return t
}

// pct 计算百分比（分母为0时返回0），保证确定性。
func pct(part, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return float64(part) * 100 / float64(total)
}

// BuildConclusions 由统计数据按确定性模板规则生成结论（禁止 AI/随机判断）。
// 规则按固定顺序评估，相同输入必然产生相同输出。
func BuildConclusions(d *ReportData) []string {
	var out []string
	if d.EventsTotal == 0 {
		out = append(out, "报告期内未检测到Web攻击事件，整体安全态势良好。")
	} else {
		out = append(out, fmt.Sprintf("报告期内共检测到安全事件%d起，其中阻断%d起（阻断率%.1f%%），观察%d起。",
			d.EventsTotal, d.EventsBlocked, pct(d.EventsBlocked, d.EventsTotal), d.EventsObserved))
		if d.HighSeverity > 0 {
			out = append(out, fmt.Sprintf("其中高危及以上事件%d起，占全部事件的%.1f%%。",
				d.HighSeverity, pct(d.HighSeverity, d.EventsTotal)))
		}
		if len(d.AttackTypes) > 0 {
			top := d.AttackTypes[0]
			out = append(out, fmt.Sprintf("%s为报告期内最主要的攻击类型，共%d起，占全部攻击事件的%.1f%%。",
				AttackTypeName(top.Key), top.Value, pct(top.Value, d.EventsTotal)))
		}
		if len(d.TopSourceIPs) > 0 {
			top := d.TopSourceIPs[0]
			out = append(out, fmt.Sprintf("攻击源IP %s 最为活跃，报告期内共产生安全事件%d起。", top.Key, top.Value))
		}
	}
	if d.CCRejected+d.CCExceeded > 0 {
		out = append(out, fmt.Sprintf("CC防护共触发阈值%d次，拦截异常请求%d次，创建临时封禁%d次。",
			d.CCExceeded, d.CCRejected, d.CCTempBlocks))
	}
	if d.TotalRequests > 0 {
		out = append(out, fmt.Sprintf("报告期内共处理请求%d次，攻击请求占比%.2f%%。",
			d.TotalRequests, pct(d.EventsTotal, d.TotalRequests)))
	}
	out = append(out, fmt.Sprintf("综合评估本期风险等级为：%s。", d.RiskLevel))
	return out
}

// BuildSuggestions 由统计数据按确定性模板规则生成建议。
// 每条规则相互独立、按固定顺序评估；无任何规则命中时给出默认建议。
func BuildSuggestions(d *ReportData) []string {
	var out []string

	// 规则1：阻断率过低
	if d.EventsTotal > 0 && pct(d.EventsBlocked, d.EventsTotal) < 50 {
		out = append(out, fmt.Sprintf("当前攻击阻断率仅为%.1f%%，建议将防护模式由观察模式切换为阻断模式，并复核防护策略配置。",
			pct(d.EventsBlocked, d.EventsTotal)))
	}

	// 规则2：主要攻击类型占比超30% → 定向建议
	if d.EventsTotal > 0 && len(d.AttackTypes) > 0 {
		top := d.AttackTypes[0]
		if p := pct(top.Value, d.EventsTotal); p >= 30 {
			out = append(out, attackTypeSuggestion(top.Key, p))
		}
	}

	// 规则3：未处置事件积压
	if d.Unprocessed > 0 && pct(d.Unprocessed, d.EventsTotal) > 30 {
		out = append(out, fmt.Sprintf("仍有%d起安全事件未处置（占%.1f%%），建议安全管理员及时分析与处置。",
			d.Unprocessed, pct(d.Unprocessed, d.EventsTotal)))
	}

	// 规则4：存在误报
	if d.FalsePositives > 0 {
		out = append(out, fmt.Sprintf("报告期内确认误报%d起，建议复核对应例外策略的匹配条件，避免例外范围过宽。",
			d.FalsePositives))
	}

	// 规则5：CC触发阈值但未拦截
	if d.CCExceeded > 0 && d.CCRejected == 0 {
		out = append(out, "CC防护阈值多次触发但未执行拦截，建议检查CC防护策略的动作配置。")
	}

	// 规则6：证书临期（≤30天）
	for _, c := range d.Certificates {
		if c.NotAfter != nil && c.DaysRemaining <= 30 {
			out = append(out, fmt.Sprintf("证书 %s 将于%d天后到期，请尽快完成证书更新与绑定。",
				c.Name, c.DaysRemaining))
		}
	}

	// 规则7：源站异常
	for _, u := range d.Upstreams {
		if u.Status == "DOWN" || u.Status == "DEGRADED" {
			out = append(out, fmt.Sprintf("源站 %s（%s）当前状态为%s，建议检查源站可用性与健康检查配置。",
				u.Name, u.Address, u.Status))
		}
	}

	// 规则8：发布失败
	if d.Publish.Failed > 0 {
		out = append(out, fmt.Sprintf("报告期内有%d次配置发布失败，建议检查网关运行状态并重新发布配置。",
			d.Publish.Failed))
	}

	if len(out) == 0 {
		out = append(out, "当前防护体系运行良好，建议保持现有防护策略并定期进行安全审查。")
	}
	return out
}

// attackTypeSuggestion 主要攻击类型的定向建议（确定性映射）。
func attackTypeSuggestion(attackType string, p float64) string {
	switch attackType {
	case "SQL_INJECTION":
		return fmt.Sprintf("SQL注入攻击占比%.1f%%，建议重点检查被攻击应用的输入校验与参数化查询实现，并确认SQL注入防护规则处于阻断模式。", p)
	case "XSS":
		return fmt.Sprintf("跨站脚本攻击占比%.1f%%，建议检查应用输出编码与CSP配置，并确认XSS防护规则处于阻断模式。", p)
	case "COMMAND_INJECTION":
		return fmt.Sprintf("命令注入攻击占比%.1f%%，建议排查应用中所有系统命令调用点，并对相关接口加强访问控制。", p)
	case "PATH_TRAVERSAL":
		return fmt.Sprintf("路径穿越攻击占比%.1f%%，建议检查应用文件访问接口的路径规范化处理，限制可访问目录范围。", p)
	case "RCE":
		return fmt.Sprintf("远程代码执行攻击占比%.1f%%，建议立即排查应用反序列化与模板注入风险，并对相关接口加强访问控制。", p)
	default:
		return fmt.Sprintf("%s占比%.1f%%，建议针对该攻击类型复核防护规则集与例外策略配置。", AttackTypeName(attackType), p)
	}
}
