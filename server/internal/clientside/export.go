// export.go PCI DSS 4.0 6.4.3 脚本授权台账与 11.6.1 违规摘要合规证据 CSV 导出。
// 强制输出 UTF-8 BOM、中文表头与 CSV 公式注入转义（= + - @ \t \r）。
package clientside

import (
	"fmt"
	"strings"
	"time"
)

const csvUTF8BOM = "\xef\xbb\xbf"

// ViolationSummary PCI DSS 4.0 11.6.1 违规统计摘要。
type ViolationSummary struct {
	Total              int64
	Open               int64
	Acknowledged       int64
	Resolved           int64
	FalsePositive      int64
	UnauthorizedScript int64
	ScriptTampered     int64
	CSPViolation       int64
	ProbeAlert         int64
}

var scriptStatusLabels = map[string]string{
	ScriptStatusDiscovered: "已发现待审",
	ScriptStatusAuthorized: "已授权",
	ScriptStatusBlocked:    "已封禁",
}

var scriptTypeLabels = map[string]string{
	ScriptTypeExternal:   "外部脚本",
	ScriptTypeInlineHash: "内联哈希",
}

var violationTypeLabels = map[string]string{
	ViolationUnauthorizedScript: "未授权脚本",
	ViolationScriptTampered:     "脚本完整性篡改",
	ViolationCSPViolation:       "CSP 策略违规",
	ViolationProbeAlert:         "敏感页探针告警",
}

var violationStatusLabels = map[string]string{
	ViolationStatusOpen:          "待处理",
	ViolationStatusAcknowledged:  "已确认",
	ViolationStatusResolved:      "已解决",
	ViolationStatusFalsePositive: "误报",
}

var actionTakenLabels = map[string]string{
	"OBSERVED":     "仅观测",
	"REPORTED":     "已上报",
	"STRIPPED":     "已剥离脚本",
	"CSP_ENFORCED": "CSP 强制阻断",
}

// RenderComplianceCSV 渲染 PCI DSS 4.0 6.4.3 脚本授权台账与 11.6.1 违规摘要 CSV。
func RenderComplianceCSV(scripts []Script, violations []Violation, summary ViolationSummary) string {
	var b strings.Builder
	b.WriteString(csvUTF8BOM)

	// Section 1: PCI DSS 4.0 6.4.3 脚本授权台账
	b.WriteString("PCI DSS 4.0 6.4.3 脚本授权台账\n")
	b.WriteString("应用编码,应用名称,脚本地址,脚本来源,脚本类型,授权状态,固定SRI哈希,观测SRI哈希,SRI一致性,业务必要性说明(6.4.3),审批人,审批时间,样例页面路径,首次发现时间,最近发现时间,观测次数\n")
	for _, s := range scripts {
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%d\n",
			csvCell(s.ApplicationCode),
			csvCell(s.ApplicationName),
			csvCell(s.ScriptURL),
			csvCell(s.ScriptOrigin),
			csvCell(labelOrRaw(scriptTypeLabels, s.ScriptType)),
			csvCell(labelOrRaw(scriptStatusLabels, s.Status)),
			csvCell(s.SRIHash),
			csvCell(s.ObservedSRI),
			csvCell(sriConsistencyLabel(s.SRIHash, s.ObservedSRI)),
			csvCell(s.Justification),
			csvCell(s.ApprovedBy),
			formatTimePtr(s.ApprovedAt),
			csvCell(s.SamplePagePath),
			formatTimeVal(s.FirstSeenAt),
			formatTimeVal(s.LastSeenAt),
			s.ObservedCount,
		)
	}

	b.WriteString("\n")

	// Section 2: PCI DSS 4.0 11.6.1 违规摘要与明细
	b.WriteString("PCI DSS 4.0 11.6.1 违规摘要\n")
	b.WriteString("违规总数,待处理(OPEN),已确认(ACKNOWLEDGED),已解决(RESOLVED),误报(FALSE_POSITIVE),未授权脚本,脚本完整性篡改,CSP策略违规,敏感页探针告警\n")
	fmt.Fprintf(&b, "%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
		summary.Total,
		summary.Open,
		summary.Acknowledged,
		summary.Resolved,
		summary.FalsePositive,
		summary.UnauthorizedScript,
		summary.ScriptTampered,
		summary.CSPViolation,
		summary.ProbeAlert,
	)

	b.WriteString("\n")
	b.WriteString("PCI DSS 4.0 11.6.1 违规告警明细\n")
	b.WriteString("发生时间,应用编码,应用名称,请求ID,违规类型,页面路径,脚本地址,阻断URI,违反指令,期望SRI,观测SRI,处置动作,原因说明,客户端IP,处置状态,处置备注,处置人,处置时间\n")
	for _, v := range violations {
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			formatTimeVal(v.OccurredAt),
			csvCell(v.ApplicationCode),
			csvCell(v.ApplicationName),
			csvCell(v.RequestID),
			csvCell(labelOrRaw(violationTypeLabels, v.ViolationType)),
			csvCell(v.PagePath),
			csvCell(v.ScriptURL),
			csvCell(v.BlockedURI),
			csvCell(v.ViolatedDirective),
			csvCell(v.ExpectedSRI),
			csvCell(v.ObservedSRI),
			csvCell(labelOrRaw(actionTakenLabels, v.ActionTaken)),
			csvCell(v.Reason),
			csvCell(v.ClientIP),
			csvCell(labelOrRaw(violationStatusLabels, v.Status)),
			csvCell(v.Note),
			csvCell(v.HandledBy),
			formatTimePtr(v.HandledAt),
		)
	}

	return b.String()
}

func sriConsistencyLabel(pinned, observed string) string {
	pinned = strings.TrimSpace(pinned)
	observed = strings.TrimSpace(observed)
	if pinned == "" {
		return "未固定"
	}
	if observed == "" {
		return "未观测"
	}
	if pinned == observed {
		return "一致"
	}
	return "不匹配"
}

func labelOrRaw(m map[string]string, k string) string {
	if v, ok := m[k]; ok {
		return v
	}
	return k
}

func formatTimeVal(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func formatTimePtr(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// csvCell CSV 单元格转义 + 防公式注入（= + - @ \t \r 开头或前导空格后接公式前缀均加 ' 保护）。
func csvCell(s string) string {
	if s == "" {
		return ""
	}
	trimmed := strings.TrimLeft(s, " ")
	needsPrefix := false
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		needsPrefix = true
	default:
		if len(trimmed) > 0 {
			switch trimmed[0] {
			case '=', '+', '-', '@', '\t', '\r':
				needsPrefix = true
			}
		}
	}
	if needsPrefix {
		s = "'" + s
	}
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}
