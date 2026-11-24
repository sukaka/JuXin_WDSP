package wafrules

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	secRuleHeadPattern = regexp.MustCompile(`^\s*SecRule\s+(\S+)\s+"((?:[^"\\]|\\.)*)"`)
	opTokenPattern     = regexp.MustCompile(`^(!?@[a-zA-Z0-9_]+)(?:\s+(.*))?$`)
	transformPattern   = regexp.MustCompile(`\bt:([a-zA-Z0-9_]+)`)
	skipAfterPattern   = regexp.MustCompile(`\bskipAfter:([^\s,'"]+)`)
	ctlActionPattern   = regexp.MustCompile(`\bctl:([^'",]+)`)
	setvarPattern      = regexp.MustCompile(`\bsetvar:'?([^'",]+)`)
	statusCodePattern  = regexp.MustCompile(`\bstatus:(\d+)`)
	wordBlockPattern   = regexp.MustCompile(`\bblock\b`)
	wordDenyPattern    = regexp.MustCompile(`\bdeny\b`)
	wordPassPattern    = regexp.MustCompile(`\bpass\b`)
	wordNologPattern   = regexp.MustCompile(`\bnolog\b`)
	wordLogPattern     = regexp.MustCompile(`\blog\b`)
	wordChainPattern   = regexp.MustCompile(`\bchain\b`)
	plLtPattern        = regexp.MustCompile(`@lt\s+(\d+)`)
	sourcePrefixRe     = regexp.MustCompile(`^来源[：:]\s*`)
	sevScoreZhRe       = regexp.MustCompile(`\b(CRITICAL|ERROR|WARNING|NOTICE)\s*计分`)
)

// extractRuleSpec 从单条 SecRule 原始文本与紧邻注释块中提取结构化事实与中文说明（方案 A）。
// 同步入库后，任何热投递的新规则包或升级后的 CRS 新规则无需改代码即可生成精准中文详述。
func extractRuleSpec(text, fileName, source, rawMsg string, rule *Rule, tags, commentBlock []string) ruleSpec {
	var targets []string
	var targetRaw, opRaw string
	if m := secRuleHeadPattern.FindStringSubmatch(text); len(m) == 3 {
		targetRaw = m[1]
		opRaw = m[2]
		for _, p := range strings.Split(targetRaw, "|") {
			p = strings.TrimSpace(p)
			if p != "" {
				targets = append(targets, p)
			}
		}
	}

	op, arg := splitParsedOperator(opRaw)

	var transforms []string
	seenTF := map[string]bool{}
	for _, m := range transformPattern.FindAllStringSubmatch(text, -1) {
		tf := m[1]
		if tf == "none" || seenTF[tf] {
			continue
		}
		seenTF[tf] = true
		transforms = append(transforms, tf)
	}

	skipAfter := ""
	if m := skipAfterPattern.FindStringSubmatch(text); len(m) == 2 {
		skipAfter = m[1]
	}

	var ctls []string
	for _, m := range ctlActionPattern.FindAllStringSubmatch(text, -1) {
		ctls = append(ctls, strings.TrimSpace(m[1]))
	}

	var setvars []string
	for _, m := range setvarPattern.FindAllStringSubmatch(text, -1) {
		setvars = append(setvars, strings.TrimSpace(m[1]))
	}

	statusCode := 0
	if m := statusCodePattern.FindStringSubmatch(text); len(m) == 2 {
		statusCode, _ = strconv.Atoi(m[1])
	}

	hasBlock := wordBlockPattern.MatchString(text)
	hasDeny := wordDenyPattern.MatchString(text)
	hasPass := wordPassPattern.MatchString(text)
	hasNolog := wordNologPattern.MatchString(text)
	hasLog := wordLogPattern.MatchString(text)
	hasChain := wordChainPattern.MatchString(text)

	pl := extractPLFromTags(tags)
	act := classifyParsedAction(hasDeny, statusCode, skipAfter, ctls, hasBlock, hasPass, hasNolog, hasLog, rawMsg, setvars)
	kind := classifyParsedKind(rule.RuleID, source, rawMsg, hasPass, hasBlock, hasDeny, ctls, rule.AttackType)
	ctlSummary := summarizeParsedCtlsZh(ctls)

	summary, risk, tuning := extractChineseComments(commentBlock, rule.Name)
	if summary == "" {
		summary = synthesizeParsedSummary(rule, source, fileName, kind, targetRaw, opRaw, op, arg, transforms, skipAfter, ctlSummary, tags)
	}

	return ruleSpec{
		Kind:       kind,
		Targets:    targets,
		Op:         op,
		Arg:        arg,
		Transforms: transforms,
		PL:         pl,
		Action:     act,
		SkipAfter:  skipAfter,
		CtlSummary: ctlSummary,
		Chained:    hasChain,
		Summary:    summary,
		Risk:       risk,
		Tuning:     tuning,
	}
}

func splitParsedOperator(opRaw string) (string, string) {
	if opRaw == "" {
		return "", ""
	}
	m := opTokenPattern.FindStringSubmatch(opRaw)
	if len(m) < 2 {
		return "@rx", ""
	}
	op := m[1]
	arg := ""
	if len(m) >= 3 {
		arg = strings.TrimSpace(m[2])
	}
	switch op {
	case "@pmFromFile", "!@pmFromFile", "@lt", "!@lt", "@ge", "@gt", "@eq", "!@eq",
		"@within", "!@within", "@validateByteRange", "!@validateByteRange", "@ipMatch":
		return op, truncate(arg, 80)
	case "@streq", "!@streq", "@endsWith", "!@endsWith", "@beginsWith", "@contains", "!@contains", "@pm":
		if len([]rune(arg)) <= 64 {
			return op, arg
		}
	}
	return op, ""
}

func classifyParsedAction(hasDeny bool, statusCode int, skipAfter string, ctls []string, hasBlock, hasPass, hasNolog, hasLog bool, rawMsg string, setvars []string) string {
	if hasDeny {
		if statusCode == 500 {
			return "deny_500"
		}
		return "deny_403"
	}
	if skipAfter != "" {
		return "skip"
	}
	if len(ctls) > 0 && !hasBlock {
		return "ctl"
	}
	if hasBlock {
		for _, sv := range setvars {
			if strings.Contains(sv, "outbound_anomaly_score") {
				return "score_out"
			}
			if strings.Contains(sv, "inbound_anomaly_score") {
				return "score_in"
			}
		}
		return "block"
	}
	if hasPass {
		if hasNolog {
			if len(setvars) > 0 {
				return "setvar"
			}
			return "pass_nolog"
		}
		if hasLog || rawMsg != "" {
			return "pass_log"
		}
		return "pass_nolog"
	}
	return "pass_nolog"
}

func classifyParsedKind(ruleID int, source, rawMsg string, hasPass, hasBlock, hasDeny bool, ctls []string, attackType string) string {
	if source == SourceThirdParty || attackType == "EXCLUSION" || ruleID == 905100 || ruleID == 905110 {
		return "exc"
	}
	if source == SourceCRSPlugin {
		return "pre"
	}
	switch ruleID {
	case 949110, 949111, 959100, 959101, 9000102, 9000104:
		return "blk"
	}
	if source == SourceCRS {
		if rawMsg == "" || ruleID == 901340 || ruleID == 901350 || ruleID == 901450 {
			return "int"
		}
		return "det"
	}
	if hasPass && !hasBlock && !hasDeny {
		if len(ctls) > 0 {
			return "exc"
		}
		return "obs"
	}
	return "det"
}

func summarizeParsedCtlsZh(ctls []string) string {
	if len(ctls) == 0 {
		return ""
	}
	var ruleIDs, tags, targets []string
	seenID := map[string]bool{}
	seenTag := map[string]bool{}
	seenTarget := map[string]bool{}
	disableRange := ""
	engineOff := false

	addUniq := func(list *[]string, seen map[string]bool, val string) {
		val = strings.TrimSpace(val)
		if val != "" && !seen[val] {
			seen[val] = true
			*list = append(*list, val)
		}
	}

	for _, c := range ctls {
		c = strings.TrimSpace(c)
		switch {
		case strings.HasPrefix(c, "ruleEngine=Off"):
			engineOff = true
		case strings.HasPrefix(c, "ruleRemoveById="):
			val := strings.TrimPrefix(c, "ruleRemoveById=")
			if strings.Contains(val, "-") {
				disableRange = val
			} else {
				addUniq(&ruleIDs, seenID, val)
			}
		case strings.HasPrefix(c, "ruleRemoveTargetById="):
			parts := strings.SplitN(strings.TrimPrefix(c, "ruleRemoveTargetById="), ";", 2)
			addUniq(&ruleIDs, seenID, parts[0])
			if len(parts) == 2 {
				addUniq(&targets, seenTarget, parts[1])
			}
		case strings.HasPrefix(c, "ruleRemoveTargetByTag="):
			parts := strings.SplitN(strings.TrimPrefix(c, "ruleRemoveTargetByTag="), ";", 2)
			addUniq(&tags, seenTag, parts[0])
			if len(parts) == 2 {
				addUniq(&targets, seenTarget, parts[1])
			}
		case strings.HasPrefix(c, "ruleRemoveByTag="):
			addUniq(&tags, seenTag, strings.TrimPrefix(c, "ruleRemoveByTag="))
		}
	}

	var segs []string
	if engineOff {
		segs = append(segs, "对匹配请求临时关闭规则引擎检测")
	}
	if disableRange != "" {
		segs = append(segs, "停用规则段 "+disableRange)
	}
	if len(targets) > 0 {
		shown := targets
		suffix := ""
		if len(shown) > 6 {
			shown = shown[:6]
			suffix = fmt.Sprintf(" 等 %d 个检测目标", len(targets))
		}
		segs = append(segs, fmt.Sprintf("对变量（%s%s）放行易误报检测", strings.Join(shown, "、"), suffix))
	}
	if len(ruleIDs) > 0 {
		shown := ruleIDs
		suffix := ""
		if len(shown) > 6 {
			shown = shown[:6]
			suffix = fmt.Sprintf(" 等 %d 条规则", len(ruleIDs))
		}
		segs = append(segs, fmt.Sprintf("涉及排除规则 ID：%s%s", strings.Join(shown, "、"), suffix))
	}
	if len(tags) > 0 {
		shown := tags
		if len(shown) > 4 {
			shown = shown[:4]
		}
		segs = append(segs, "涉及排除规则标签："+strings.Join(shown, "、"))
	}
	return strings.Join(segs, "；")
}

// extractChineseComments 从规则正上方注释块中提取显式标注（@desc/@risk/@tuning 或 说明：/风险：/调优：）
// 或常规中文说明注释，使新投递的 .conf 规则直接携带中文详述。
func extractChineseComments(commentBlock []string, ruleName string) (summary, risk, tuning string) {
	if len(commentBlock) == 0 {
		return "", "", ""
	}
	var descLines, riskLines, tuningLines, generalCJK []string

	for _, raw := range commentBlock {
		c := strings.TrimSpace(raw)
		if c == "" || strings.HasPrefix(c, "===") || strings.HasPrefix(c, "-- ") || strings.HasPrefix(c, "-=[") {
			continue
		}
		if strings.HasPrefix(c, "规则 ID") || strings.HasPrefix(c, "规则ID") {
			continue
		}
		if v, ok := trimAnyPrefix(c, "@desc:", "@desc：", "说明：", "说明:"); ok {
			if HasCJK(v) {
				descLines = append(descLines, v)
			}
			continue
		}
		if v, ok := trimAnyPrefix(c, "@risk:", "@risk：", "风险：", "风险:", "危害：", "危害:"); ok {
			if HasCJK(v) {
				riskLines = append(riskLines, v)
			}
			continue
		}
		if v, ok := trimAnyPrefix(c, "@tuning:", "@tuning：", "调优：", "调优:", "建议：", "建议:"); ok {
			if HasCJK(v) {
				tuningLines = append(tuningLines, v)
			}
			continue
		}
		if HasCJK(c) {
			generalCJK = append(generalCJK, c)
		}
	}

	if len(descLines) > 0 {
		summary = cleanCommentProse(strings.Join(descLines, ""))
	} else if len(generalCJK) > 0 {
		cleaned := cleanCommentProse(strings.Join(generalCJK, ""))
		if len([]rune(cleaned)) >= 12 && strings.TrimRight(cleaned, "。") != strings.TrimRight(ruleName, "。") {
			summary = cleaned
		}
	}
	if len(riskLines) > 0 {
		risk = cleanCommentProse(strings.Join(riskLines, ""))
	}
	if len(tuningLines) > 0 {
		tuning = cleanCommentProse(strings.Join(tuningLines, ""))
	}
	return summary, risk, tuning
}

func trimAnyPrefix(s string, prefixes ...string) (string, bool) {
	low := strings.ToLower(s)
	for _, p := range prefixes {
		if strings.HasPrefix(low, strings.ToLower(p)) {
			return strings.TrimSpace(s[len(p):]), true
		}
	}
	return "", false
}

func cleanCommentProse(text string) string {
	text = sourcePrefixRe.ReplaceAllString(strings.TrimSpace(text), "")
	text = sevScoreZhRe.ReplaceAllStringFunc(text, func(m string) string {
		switch {
		case strings.HasPrefix(m, "CRITICAL"):
			return "按严重级别计入异常评分"
		case strings.HasPrefix(m, "ERROR"):
			return "按高危级别计入异常评分"
		case strings.HasPrefix(m, "WARNING"):
			return "按中危级别计入异常评分"
		default:
			return "按低危级别计入异常评分"
		}
	})
	text = strings.TrimSpace(strings.Trim(text, " ，,；;"))
	if text == "" {
		return ""
	}
	if !strings.HasSuffix(text, "。") && !strings.HasSuffix(text, "！") {
		text += "。"
	}
	return truncate(text, 1000)
}

func synthesizeParsedSummary(rule *Rule, source, fileName, kind, targetRaw, opRaw, op, arg string, transforms []string, skipAfter, ctlSummary string, tags []string) string {
	base := strings.TrimSuffix(filepath.Base(fileName), filepath.Ext(fileName))
	fam := familyNamesZh[base]
	if fam == "" {
		fam = attackTypeLabelZh(rule.AttackType)
	}
	srcLabel := ruleSourceLabelZh(source)
	zhName := rule.Name
	if zhName == "" {
		zhName = fmt.Sprintf("规则 %d", rule.RuleID)
	}

	if skipAfter != "" && strings.Contains(targetRaw, "DETECTION_PARANOIA_LEVEL") {
		plGate := "1"
		if m := plLtPattern.FindStringSubmatch(opRaw); len(m) == 2 {
			plGate = m[1]
		}
		return fmt.Sprintf("属于%s「%s」规则族的偏执级别流程控制规则（阶段 %d，PL%s 门槛）。当策略检测偏执级别低于 PL%s 时，自动跳过本规则文件后续阶段 %d 的检测规则；不直接拦截或记录业务告警。", srcLabel, fam, rule.Phase, plGate, plGate, rule.Phase)
	}
	if skipAfter != "" && strings.Contains(targetRaw, "RESPONSE_HEADERS:Content-Encoding") {
		return fmt.Sprintf("属于%s「%s」规则族的压缩响应体跳过规则（阶段 4）。当源站返回压缩编码响应体时自动跳过正文扫描，避免无效计算与误报。", srcLabel, fam)
	}
	if kind == "exc" {
		if ctlSummary != "" {
			return fmt.Sprintf("属于%s「%s」的误报排除规则（%s）。命中条件后动态执行放行（%s），在不关闭整站防护的前提下避免正常业务误拦。", srcLabel, fam, zhName, ctlSummary)
		}
		return fmt.Sprintf("属于%s「%s」的误报排除规则（%s），用于在特定业务场景下放行已知误报。", srcLabel, fam, zhName)
	}
	if kind == "pre" {
		if len(transforms) > 0 {
			tf := transforms[0]
			if zh, ok := transformLabelsZh[tf]; ok {
				tf = zh
			}
			return fmt.Sprintf("属于%s「%s」预处理规则。对目标变量执行「%s」并将结果保存供下游检测规则复用，提升对抗编码绕过能力。", srcLabel, fam, tf)
		}
		return fmt.Sprintf("属于%s「%s」插件控制或预处理规则（%s），负责插件开关控制或数据解码预处理。", srcLabel, fam, zhName)
	}
	if kind == "int" {
		return fmt.Sprintf("属于%s「%s」规则族的内部控制规则（%s），负责策略参数初始化、评分汇总或流程跳转控制，不直接拦截正常请求。", srcLabel, fam, zhName)
	}
	if kind == "obs" {
		return fmt.Sprintf("属于%s「%s」观测告警规则，专门识别「%s」相关的流量特征；命中后仅记录安全日志供运营研判，不直接阻断请求。", srcLabel, fam, zhName)
	}

	atLabel := attackTypeLabelZh(rule.AttackType)
	return fmt.Sprintf("属于%s的「%s」安全检测规则，专门识别并防范「%s」相关的攻击载荷与异常请求特征；命中后按规则风险等级计入异常评分或执行防护处置。", srcLabel, atLabel, zhName)
}

func marshalRuleSpecJSON(spec ruleSpec) json.RawMessage {
	raw, err := json.Marshal(spec)
	if err != nil {
		return json.RawMessage("{}")
	}
	return json.RawMessage(raw)
}

// parseStoredRuleSpec 解析数据库中 waf_rules.parsed_spec 字段；空对象 `{}` 返回 false。
func parseStoredRuleSpec(raw []byte) (ruleSpec, bool) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "{}" || trimmed == "null" {
		return ruleSpec{}, false
	}
	var spec ruleSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return ruleSpec{}, false
	}
	if spec.Kind == "" && spec.Summary == "" && len(spec.Targets) == 0 && spec.Op == "" {
		return ruleSpec{}, false
	}
	return spec, true
}
