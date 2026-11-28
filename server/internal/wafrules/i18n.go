package wafrules

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

//go:embed rule_names_zh.json
var ruleNamesZhJSON []byte

var (
	ruleNamesZh map[int]string

	totalScoreSuffixPattern = regexp.MustCompile(`\(Total Score:\s*(\d+)\)`)
)

// familyNamesZh 规则文件（去 .conf）到中文规则族名的兜底映射。
var familyNamesZh = map[string]string{
	"REQUEST-901-INITIALIZATION":                      "初始化",
	"REQUEST-905-COMMON-EXCEPTIONS":                   "通用例外",
	"REQUEST-911-METHOD-ENFORCEMENT":                  "HTTP 方法强制",
	"REQUEST-913-SCANNER-DETECTION":                   "扫描器检测",
	"REQUEST-920-PROTOCOL-ENFORCEMENT":                "协议合规校验",
	"REQUEST-921-PROTOCOL-ATTACK":                     "协议攻击",
	"REQUEST-922-MULTIPART-ATTACK":                    "Multipart 攻击",
	"REQUEST-930-APPLICATION-ATTACK-LFI":              "本地文件包含（LFI）",
	"REQUEST-931-APPLICATION-ATTACK-RFI":              "远程文件包含（RFI）",
	"REQUEST-932-APPLICATION-ATTACK-RCE":              "远程命令/代码执行（RCE）",
	"REQUEST-933-APPLICATION-ATTACK-PHP":              "PHP 注入攻击",
	"REQUEST-934-APPLICATION-ATTACK-GENERIC":          "通用应用攻击",
	"REQUEST-941-APPLICATION-ATTACK-XSS":              "跨站脚本（XSS）",
	"REQUEST-942-APPLICATION-ATTACK-SQLI":             "SQL 注入",
	"REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION": "会话固定攻击",
	"REQUEST-944-APPLICATION-ATTACK-JAVA":             "Java 攻击",
	"REQUEST-949-BLOCKING-EVALUATION":                 "阻断评估",
	"RESPONSE-950-DATA-LEAKAGES":                      "数据泄露（通用）",
	"RESPONSE-951-DATA-LEAKAGES-SQL":                  "数据泄露（SQL 错误）",
	"RESPONSE-952-DATA-LEAKAGES-JAVA":                 "数据泄露（Java 错误）",
	"RESPONSE-953-DATA-LEAKAGES-PHP":                  "数据泄露（PHP 错误）",
	"RESPONSE-954-DATA-LEAKAGES-IIS":                  "数据泄露（IIS 错误）",
	"RESPONSE-955-WEB-SHELLS":                         "Web Shell 检测",
	"RESPONSE-956-DATA-LEAKAGES-RUBY":                 "数据泄露（Ruby 错误）",
	"RESPONSE-959-BLOCKING-EVALUATION":                "出站阻断评估",
	"RESPONSE-980-CORRELATION":                        "关联评分",
	"auto-decoding-before":                            "自动解码插件",
	"incubator-before":                                "孵化器插件",
	"dokuwiki-rule-exclusions-before":                 "DokuWiki 排除规则",
	"drupal-rule-exclusions-before":                   "Drupal 排除规则",
	"nextcloud-rule-exclusions-before":                "Nextcloud 排除规则",
	"phpmyadmin-rule-exclusions-before":               "phpMyAdmin 排除规则",
	"wordpress-rule-exclusions-before":                "WordPress 排除规则",
	"xenforo-rule-exclusions-before":                  "XenForo 排除规则",
	"ai-crawler-control":                              "AI 爬虫管控",
	"api-abuse":                                       "API 滥用防护",
	"attack-coverage":                                 "攻击覆盖增强",
	"attack-variants-evasion":                         "攻击变种与绕过检测",
	"bot-protocol":                                    "协议与自动化异常检测",
	"cloud-abuse":                                     "云原生与元数据滥用检测",
	"cve-emergency":                                   "高危 CVE 应急防护",
	"cve-recent":                                      "近期 CVE 漏洞防护",
	"deserialization-rce":                             "反序列化与远程代码执行",
	"fake-bot-claims":                                 "搜索引擎爬虫声称检测",
	"injection-variants":                              "注入变种检测",
	"oss-webapps-cve":                                 "常见 Web 应用漏洞防护",
	"scanner-fingerprints":                            "扫描器指纹检测",
	"scanner-fingerprints-ext":                        "扩展爬虫指纹检测",
	"sensitive-exposure":                              "敏感路径暴露检测",
	"ssrf-protocols":                                  "SSRF 协议与地址混淆检测",
	"ssti-injection":                                  "服务端模板注入（SSTI）",
	"unauth-access":                                   "未授权访问与数据外带检测",
	"webshell":                                        "WebShell 检测",
	"webshell-content":                                "WebShell 脚本内容检测",
	"webshell-obfuscation":                            "WebShell 混淆检测",
	"webshell-uploads":                                "WebShell 文件上传检测",
	"xxe-lfi-variants":                                "XXE 与文件包含变种检测",
}

func init() {
	var raw map[string]string
	if err := json.Unmarshal(ruleNamesZhJSON, &raw); err != nil {
		panic(fmt.Sprintf("wafrules: decode rule_names_zh.json: %v", err))
	}
	ruleNamesZh = make(map[int]string, len(raw))
	for k, v := range raw {
		id, err := strconv.Atoi(k)
		if err != nil {
			panic(fmt.Sprintf("wafrules: invalid rule id %q in rule_names_zh.json: %v", k, err))
		}
		ruleNamesZh[id] = v
	}
}

// HasCJK 判断字符串是否包含中文字符。
func HasCJK(s string) bool {
	for _, r := range s {
		if (r >= 0x2E80 && r <= 0x9FFF) || (r >= 0xF900 && r <= 0xFAFF) {
			return true
		}
	}
	return false
}

// translateTemplateMessage 翻译模板化生成的规则消息（如爬虫 UA、AI 爬虫、搜索引擎爬虫声称）。
func translateTemplateMessage(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	const crawlerPrefix = "Scanner fingerprint: crawler UA ("
	if strings.HasPrefix(trimmed, crawlerPrefix) && strings.HasSuffix(trimmed, ")") {
		inner := trimmed[len(crawlerPrefix) : len(trimmed)-1]
		return "扫描器指纹：爬虫 UA（" + inner + "）", true
	}
	const aiPrefix = "AI crawler UA: "
	if strings.HasPrefix(trimmed, aiPrefix) {
		return "AI 爬虫 UA：" + trimmed[len(aiPrefix):], true
	}
	const botClaimPrefix = "Search engine bot UA claim: "
	if strings.HasPrefix(trimmed, botClaimPrefix) {
		return "搜索引擎爬虫 UA 声明：" + trimmed[len(botClaimPrefix):], true
	}
	return "", false
}

// LocalizeRule 将规则名称转换为中文展示名（用于规则库名称、事件匹配 rule_name、统计聚合与报表）。
// 优先级：内置逐条映射 → 模板规则消息翻译 → 已有中文原样保留 → 文件族名兜底 → 原文。
func LocalizeRule(ruleID int, fileName, raw string) string {
	if zh, ok := ruleNamesZh[ruleID]; ok {
		return zh
	}
	if zh, ok := translateTemplateMessage(raw); ok {
		return zh
	}
	if HasCJK(raw) {
		return raw
	}
	if fileName != "" {
		base := strings.TrimSuffix(filepath.Base(fileName), filepath.Ext(fileName))
		if fam, ok := familyNamesZh[base]; ok {
			if strings.Contains(base, "rule-exclusions") {
				return fmt.Sprintf("%s（规则 %d）", fam, ruleID)
			}
			return fam + "检测规则"
		}
	}
	return raw
}

// LocalizeMatchMessage 将事件匹配消息转换为中文，同时保留运行时动态异常总分（如 Total Score: 5）。
func LocalizeMatchMessage(ruleID int, raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed != "" && HasCJK(trimmed) && !strings.Contains(trimmed, "Total Score:") {
		return raw
	}
	base := LocalizeRule(ruleID, "", raw)
	if base == "" {
		return raw
	}
	if m := totalScoreSuffixPattern.FindStringSubmatch(raw); len(m) == 2 {
		score := m[1]
		if strings.HasSuffix(base, "）") {
			return strings.TrimSuffix(base, "）") + "，总分：" + score + "）"
		}
		return base + "（总分：" + score + "）"
	}
	return base
}

// LookupRuleNameZh 仅按 rule_id 查询内置中文名称映射表（测试与工具复用）。
func LookupRuleNameZh(ruleID int) (string, bool) {
	v, ok := ruleNamesZh[ruleID]
	return v, ok
}

// MatchLocalizedRuleIDs 按关键词不区分大小写检索内置中文规则名称映射，返回匹配的 rule_id 列表。
func MatchLocalizedRuleIDs(keyword string) []int {
	kw := strings.ToLower(strings.TrimSpace(keyword))
	if kw == "" {
		return nil
	}
	var ids []int
	for id, name := range ruleNamesZh {
		if strings.Contains(strings.ToLower(name), kw) {
			ids = append(ids, id)
		}
	}
	return ids
}
