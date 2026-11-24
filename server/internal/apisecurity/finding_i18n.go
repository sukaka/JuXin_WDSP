package apisecurity

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/jiuzhang-waf/server/internal/wafrules"
)

// corazaCoreRuleTitles Coraza 核心引擎规则（gateway/rules/coraza.conf 及关联评分汇总规则）
// 未收录在 OWASP CRS / 扩展包词表中的规则中文名兜底。
var corazaCoreRuleTitles = map[int]string{
	200002: "请求体解析失败",
	200003: "Multipart 请求体严格校验失败",
	980170: "异常评分汇总记录",
}

// localizeFindingTitle 在查询读取层把 WAF 规则类风险发现的英文标题转换为中文展示名
// （复用 wafrules 全部 3400+ OWASP CRS / 扩展包 / 爬虫模板词表，与安全事件查询口径一致），
// 不改写数据库落库原文；非 WAF 发现与已是中文的标题原样返回。
func localizeFindingTitle(findingType, title string, detail json.RawMessage) string {
	trimmed := strings.TrimSpace(title)
	if trimmed != "" && wafrules.HasCJK(trimmed) && !strings.Contains(trimmed, "Total Score:") {
		return title
	}
	upperType := strings.ToUpper(strings.TrimSpace(findingType))
	if upperType == "WAF_DOWNSTREAM_INTERCEPT" ||
		strings.EqualFold(trimmed, "request blocked by downstream WAF (coraza interruption)") {
		return "请求已被下游 WAF 引擎阻断"
	}

	ruleID, ok := extractWAFFindingRuleID(upperType, detail)
	if !ok {
		return title
	}
	if zh, found := corazaCoreRuleTitles[ruleID]; found {
		return zh
	}
	raw := trimmed
	if strings.EqualFold(raw, upperType) {
		raw = ""
	}
	if localized := wafrules.LocalizeMatchMessage(ruleID, raw); localized != "" && wafrules.HasCJK(localized) {
		return localized
	}
	return title
}

// extractWAFFindingRuleID 从 finding_type（WAF_<数字规则号>）或 detail JSON（detector=waf + 数字 rule_id）提取 WAF 规则号。
func extractWAFFindingRuleID(upperFindingType string, detail json.RawMessage) (int, bool) {
	if strings.HasPrefix(upperFindingType, "WAF_") {
		if id, err := strconv.Atoi(strings.TrimPrefix(upperFindingType, "WAF_")); err == nil && id > 0 {
			return id, true
		}
	}
	if len(detail) == 0 {
		return 0, false
	}
	var d struct {
		Detector string `json:"detector"`
		RuleID   string `json:"rule_id"`
	}
	if err := json.Unmarshal(detail, &d); err != nil {
		return 0, false
	}
	if !strings.EqualFold(strings.TrimSpace(d.Detector), "waf") {
		return 0, false
	}
	id, err := strconv.Atoi(strings.TrimSpace(d.RuleID))
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}
