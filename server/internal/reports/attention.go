package reports

// 关注项红色高亮：需要用户立即关注的风险点，三种导出格式（HTML/PDF/Word）
// 统一标红。判定规则为确定性逻辑，与 BuildSuggestions 建议规则同口径——
// 触发建议的数据异常即在对应章节标红，用户一眼可定位关注点。

// attentionColorHex 关注项红色（与 HTML 风险徽章 risk-HIGH 同色）。
const attentionColorHex = "D83931"

// Attention 主报告关注项标记。
type Attention struct {
	HighSeverity  bool // 存在高危及以上事件
	RiskHigh      bool // 综合风险等级 HIGH/CRITICAL
	BlockRateLow  bool // 有事件但阻断率 <50%（建议规则1）
	CCNoBlock     bool // CC 触发阈值但拦截数为 0（建议规则5）
	PublishFailed bool // 发布失败 >0（建议规则8）
}

// NewAttention 由主报告数据计算关注项。
func NewAttention(d *ReportData) *Attention {
	a := &Attention{}
	if d == nil {
		return a
	}
	a.HighSeverity = d.HighSeverity > 0
	a.RiskHigh = d.RiskLevel == "HIGH" || d.RiskLevel == "CRITICAL"
	a.BlockRateLow = d.EventsTotal > 0 && pct(d.EventsBlocked, d.EventsTotal) < 50
	a.CCNoBlock = d.CCExceeded > 0 && d.CCRejected == 0
	a.PublishFailed = d.Publish.Failed > 0
	return a
}

// APIAttention API 域报告关注项标记。
type APIAttention struct {
	ShadowOpen   bool // 未关闭的 Shadow 发现 >0
	Zombie       bool // 僵尸端点 >0
	OpenFindings bool // 未关闭运行时发现 >0
	Overdue      bool // 超期未闭环弱点 >0
	RetestFail   bool // 复测失败 >0
}

// NewAPIAttention 由 API 域报告数据计算关注项。
func NewAPIAttention(d *APIReportData) *APIAttention {
	a := &APIAttention{}
	if d == nil {
		return a
	}
	if r := d.Asset; r != nil {
		a.ShadowOpen = r.ShadowOpen > 0
		a.Zombie = r.Zombie > 0
	}
	if r := d.Risk; r != nil {
		a.OpenFindings = r.OpenFindings > 0
	}
	if r := d.Weakness; r != nil {
		a.Overdue = r.OverdueOpen > 0
		a.RetestFail = r.RetestFail > 0
	}
	return a
}

// severityAttention 严重度行级判定：高危及以上标红。
func severityAttention(sev string) bool {
	return sev == "HIGH" || sev == "CRITICAL"
}

// severityMarks 严重度分布行标记（HIGH/CRITICAL 行标红）。
func severityMarks(kvs []KV) []bool {
	marks := make([]bool, len(kvs))
	for i, kv := range kvs {
		marks[i] = severityAttention(kv.Key)
	}
	return marks
}

// certAttention 证书行级判定：剩余 ≤30 天标红（建议规则6；负数已过期同样命中）。
func certAttention(days int) bool {
	return days <= 30
}

// upstreamAttention 源站行级判定：DOWN/DEGRADED 标红（建议规则7）。
func upstreamAttention(status string) bool {
	return status == "DOWN" || status == "DEGRADED"
}

// componentAttention 组件行级判定：DEGRADED/DOWN 标红（UNKNOWN 为无数据，不标）。
func componentAttention(status string) bool {
	return status == "DOWN" || status == "DEGRADED"
}
