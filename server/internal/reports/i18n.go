package reports

import "fmt"

// 报告展示文案中文化：采集层保持英文枚举词表（与数据库/网关一致），
// 展示层（HTML/PDF/Word 共用）经本文件映射为中文。词表与前端 utils 的
// *_META 标签保持一致，避免同一状态在界面与报告中两种叫法。

// ReportTypeName 报告类型中文名（封面用；API 域类型走 APIReportTypeName）。
func ReportTypeName(t string) string {
	switch t {
	case TypeDaily:
		return "日报"
	case TypeWeekly:
		return "周报"
	case TypeMonthly:
		return "月报"
	case TypeCustom:
		return "自定义"
	}
	if IsAPIReportType(t) {
		return APIReportTypeName(t)
	}
	return t
}

// SeverityName 事件严重度中文名（CRITICAL 严重 / HIGH 高危 / MEDIUM 中危 / LOW 低危 / INFO 提示）。
func SeverityName(sev string) string {
	switch sev {
	case "CRITICAL":
		return "严重"
	case "HIGH":
		return "高危"
	case "MEDIUM":
		return "中危"
	case "LOW":
		return "低危"
	case "INFO":
		return "提示"
	}
	return sev
}

// severityDisplayKVs 严重度分布展示副本（Key 中文化；标红判定仍用原始英文键）。
func severityDisplayKVs(kvs []KV) []KV {
	out := make([]KV, len(kvs))
	for i, kv := range kvs {
		out[i] = KV{Key: SeverityName(kv.Key), Value: kv.Value}
	}
	return out
}

// findingTypeDisplayKVs 发现类型分布展示副本（Key 中文化）。
func findingTypeDisplayKVs(kvs []KV) []KV {
	out := make([]KV, len(kvs))
	for i, kv := range kvs {
		out[i] = KV{Key: FindingTypeName(kv.Key), Value: kv.Value}
	}
	return out
}

// DispositionName 事件处置状态中文名（词表见 security_events.disposition_status）。
func DispositionName(s string) string {
	switch s {
	case "UNPROCESSED":
		return "未处置"
	case "ANALYZING":
		return "分析中"
	case "CONFIRMED_ATTACK":
		return "确认攻击"
	case "CONFIRMED_FALSE_POSITIVE":
		return "确认误报"
	case "IGNORED":
		return "已忽略"
	case "RESOLVED":
		return "已处置"
	}
	return s
}

// UpstreamStatusName 源站/组件健康状态中文名（DISABLED 为报告展示专用：未启用健康检查）。
func UpstreamStatusName(s string) string {
	switch s {
	case "UP":
		return "正常"
	case "DOWN":
		return "故障"
	case "DEGRADED":
		return "降级"
	case "DISABLED":
		return "未启用"
	case "UNKNOWN":
		return "未知"
	}
	return s
}

// ComponentStatusName 系统组件状态中文名（与源站同词表）。
func ComponentStatusName(s string) string {
	return UpstreamStatusName(s)
}

// CertStatusName 证书状态中文名。
func CertStatusName(s string) string {
	switch s {
	case "VALID":
		return "有效"
	case "EXPIRING":
		return "即将到期"
	case "EXPIRED":
		return "已过期"
	case "INVALID":
		return "无效"
	case "KEY_MISMATCH":
		return "密钥不匹配"
	}
	return s
}

// PublishTaskTypeName 发布任务类型中文名。
func PublishTaskTypeName(t string) string {
	switch t {
	case "PUBLISH":
		return "发布"
	case "ROLLBACK":
		return "回滚"
	}
	return t
}

// PublishStatusName 发布任务状态中文名。
func PublishStatusName(s string) string {
	switch s {
	case "PENDING":
		return "待执行"
	case "RUNNING":
		return "进行中"
	case "SUCCESS":
		return "成功"
	case "FAILED":
		return "失败"
	case "CANCELLED":
		return "已取消"
	}
	return s
}

// RiskLevelName 综合风险等级中文名（取值同严重度词表）。
func RiskLevelName(level string) string {
	return SeverityName(level)
}

// ContentScopeName 内容范围中文名。
func ContentScopeName(s string) string {
	switch NormalizeContentScope(s) {
	case ScopeWAF:
		return "Web 应用防护"
	case ScopeAPI:
		return "API 动态防护"
	default:
		return "Web 应用防护 + API 动态防护"
	}
}

// ActionName 事件动作中文名。
func ActionName(a string) string {
	switch a {
	case "BLOCK":
		return "阻断"
	case "OBSERVE":
		return "观察"
	}
	return a
}

// peakHour 攻击高峰时段（返回 "14" 时段与事件数；全 0 返回 "", 0）。
func peakHour(hours []KV) (string, int64) {
	peak := int64(-1)
	name := ""
	for _, kv := range hours {
		if kv.Value > peak {
			peak = kv.Value
			name = kv.Key
		}
	}
	if peak <= 0 {
		return "", 0
	}
	return name, peak
}

// peakHourText 攻击高峰时段展示文案（无事件返回空串）。
func peakHourText(hours []KV) string {
	name, n := peakHour(hours)
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf("攻击高峰时段：%s:00-%s:59（%d 起）。", name, name, n)
}

// FindingTypeName API 运行时发现类型中文名（词表见 api_runtime_findings.finding_type）。
func FindingTypeName(t string) string {
	switch t {
	case "SHADOW":
		return "影子API"
	case "ZOMBIE":
		return "僵尸API"
	case "DEPRECATED":
		return "已下线API"
	case "BOLA":
		return "对象级越权"
	case "BFLA":
		return "功能级越权"
	case "SCHEMA_DEVIATION":
		return "模型偏离"
	case "SENSITIVE_LEAK":
		return "敏感数据泄露"
	case "MASS_ASSIGNMENT":
		return "批量赋值"
	case "BEHAVIOR_ANOMALY":
		return "行为异常"
	}
	return t
}

// countryCodeNames ISO 3166-1 alpha-2 国家码 → 中文名（常见国家/地区；
// 未收录的合法国家码原样展示，空码为「未知地区」）。
var countryCodeNames = map[string]string{
	"CN": "中国", "HK": "中国香港", "TW": "中国台湾", "MO": "中国澳门",
	"US": "美国", "CA": "加拿大", "MX": "墨西哥", "BR": "巴西", "AR": "阿根廷",
	"CL": "智利", "CO": "哥伦比亚", "PE": "秘鲁",
	"GB": "英国", "DE": "德国", "FR": "法国", "NL": "荷兰", "BE": "比利时",
	"ES": "西班牙", "PT": "葡萄牙", "IT": "意大利", "CH": "瑞士", "AT": "奥地利",
	"SE": "瑞典", "NO": "挪威", "DK": "丹麦", "FI": "芬兰", "IE": "爱尔兰",
	"PL": "波兰", "UA": "乌克兰", "TR": "土耳其", "CZ": "捷克", "GR": "希腊",
	"RU": "俄罗斯", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦", "MN": "蒙古",
	"JP": "日本", "KR": "韩国", "KP": "朝鲜",
	"SG": "新加坡", "MY": "马来西亚", "TH": "泰国", "VN": "越南", "ID": "印度尼西亚",
	"PH": "菲律宾", "KH": "柬埔寨", "MM": "缅甸", "LA": "老挝",
	"IN": "印度", "PK": "巴基斯坦", "BD": "孟加拉国", "LK": "斯里兰卡", "NP": "尼泊尔",
	"IR": "伊朗", "IQ": "伊拉克", "SA": "沙特阿拉伯", "AE": "阿联酋", "IL": "以色列",
	"AU": "澳大利亚", "NZ": "新西兰",
	"ZA": "南非", "EG": "埃及", "NG": "尼日利亚", "KE": "肯尼亚",
}

// CountryCodeName 国家码中文名（空码「未知地区」，未收录原样返回码）。
func CountryCodeName(code string) string {
	if code == "" {
		return "未知地区"
	}
	if n, ok := countryCodeNames[code]; ok {
		return n
	}
	return code
}

// crsRuleCategories CRS 规则 ID 段 → 攻击类别中文名（CRS 4.x 规则集结构；
// 段内规则均为同一攻击类别，用于给英文规则名加中文类别前缀）。
var crsRuleCategories = []struct {
	min, max int
	name     string
}{
	{920000, 920999, "协议合规检查"},
	{921000, 921999, "HTTP请求走私"},
	{930000, 930999, "本地文件包含"},
	{931000, 931999, "远程文件包含"},
	{932000, 932999, "远程命令执行"},
	{933000, 933999, "PHP注入"},
	{934000, 934999, "命令注入"},
	{941000, 941999, "XSS跨站脚本"},
	{942000, 942999, "SQL注入"},
	{943000, 943999, "会话固定"},
	{944000, 944999, "Java攻击"},
	{949000, 949999, "异常评分拦截评估"},
}

// RuleDisplayName 规则展示名：自研规则（中文名）原样；CRS 英文规则名加
// 中文类别前缀（保留英文原名便于对照规则文档）；无法归类时原样返回。
func RuleDisplayName(ruleID int, name string) string {
	if name == "" {
		return "-"
	}
	if hasCJK(name) {
		return name
	}
	for _, c := range crsRuleCategories {
		if ruleID >= c.min && ruleID <= c.max {
			return "【" + c.name + "】" + name
		}
	}
	return name
}

// hasCJK 判断字符串是否含 CJK 字符（用于识别已是中文的规则名）。
func hasCJK(s string) bool {
	for _, r := range s {
		if (r >= 0x2E80 && r <= 0x9FFF) || (r >= 0xF900 && r <= 0xFAFF) {
			return true
		}
	}
	return false
}
