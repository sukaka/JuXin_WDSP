package detectors

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// 敏感字段名检测：仅按字段名/路径模式匹配，不触碰任何字段值。
// Evidence 只记录字段路径与数据类型标签。

// SensitivePattern 敏感字段名模式（DataType 为证据中的数据类型标签）。
type SensitivePattern struct {
	DataType string `json:"data_type"`
	Pattern  string `json:"pattern"`
}

// CompiledSensitivePattern 编译后的模式（opaque，由 CompileSensitivePatterns 产出）。
type CompiledSensitivePattern struct {
	dataType string
	re       *regexp.Regexp
}

// defaultSensitivePatterns 内置字段名模式（中英常见命名；编译期正则表）。
// 词根采用分隔符与驼峰边界，避免 hotel/company/panel、mailer/mailinglist/pipermail、
// microphone/automobile 等非敏感词误命中，同时兼容 snake_case/kebab-case/camelCase/全大写命名。
var defaultSensitivePatterns = []SensitivePattern{
	{
		DataType: "phone",
		Pattern: `(?:` +
			`(?:^|[^A-Za-z])(?:[Cc][Ee][Ll][Ll]|[Tt][Ee][Ll][Ee]|[Mm][Oo][Bb][Ii][Ll][Ee])?[Pp][Hh][Oo][Nn][Ee][Ss]?(?:$|[^A-Za-z])` +
			`|(?:^|[^A-Za-z])(?:[Cc]ell|[Tt]ele|[Mm]obile)?[Pp]hone[A-Z]` +
			`|[a-z]Phone[Ss]?(?:$|[^a-z])` +
			`|(?:^|[^A-Za-z])[Mm][Oo][Bb][Ii][Ll][Ee][Ss]?(?:$|[^A-Za-z])` +
			`|(?:^|[^A-Za-z])[Mm]obile[A-Z]` +
			`|[a-z]Mobile[Ss]?(?:$|[^a-z])` +
			`|(?:^|[^A-Za-z])[Tt][Ee][Ll](?:$|[^A-Za-z])` +
			`|(?:^|[^A-Za-z])[Tt]el[A-Z]` +
			`|[a-z]Tel(?:$|[^a-z])` +
			`|(?i:shouji))`,
	},
	{
		DataType: "email",
		Pattern: `(?:` +
			`(?:^|[^A-Za-z])(?:[Ee][-_]?[Mm][Aa][Ii][Ll]|[Mm][Aa][Ii][Ll])[Ss]?(?:$|[^A-Za-z])` +
			`|(?:^|[^A-Za-z])(?:[Ee][-_]?[Mm]ail|[Mm]ail)[A-Z]` +
			`|[a-z](?:Email|Mail)[Ss]?(?:$|[^a-z])` +
			`|(?i:youxiang))`,
	},
	{DataType: "id_card", Pattern: `(?i)(id_?card|idcard|identity|shenfenzheng|(^|[^a-z])sfz([^a-z]|$))`},
	{DataType: "bank_card", Pattern: `(?i)(bank_?card|card_?(number|no)|(^|[^a-z])pan([^a-z]|$)|yinhangka)`},
	{DataType: "credential", Pattern: `(?i)(password|passwd|pwd|secret|token|api_?key|apikey|access_?key|private_?key|mima)`},
}

// maxSensitiveMatches 单请求敏感字段 match 上限（防超大报文撑爆事件）。
const maxSensitiveMatches = 20

// maxSensitiveValueInputLen 值级匹配单值输入长度封顶（字符数；截断后参与匹配，防超长值放大 CPU）。
const maxSensitiveValueInputLen = 4096

// maxSensitiveValueScans 单请求值级匹配扫描次数（值 × 规则的一次求值计一次）上限，
// 与 maxSensitiveMatches 配合防 CPU 放大：命中预算耗尽或扫描次数耗尽即停止值级扫描。
const maxSensitiveValueScans = 512

// maxSensitiveValueRules 值级规则条数上限（发布通道配置防误配）。
const maxSensitiveValueRules = 256

// maxSensitiveValueRegexLen 值级正则长度上限（配合 RE2 线性时间引擎防正则拒绝服务）。
const maxSensitiveValueRegexLen = 512

// SensitiveValueRule 值级敏感检测规则（发布通道下发 api_sensitive_value_rules；
// 对应管理面 api_sensitive_data_types 表 status=ENABLED 且 regex 非空的类型）。
// Locations 词表与管理面一致（query/json/form/xml/header/cookie/path/response_body），
// 请求侧仅消费 query/json/form/header/path，其余位置过滤后忽略。
type SensitiveValueRule struct {
	DataType      string   `json:"data_type"`
	Regex         string   `json:"regex"`
	Locations     []string `json:"locations"`
	Level         string   `json:"level"`                    // 敏感等级（NON_SENSITIVE/GENERAL/SENSITIVE/IMPORTANT/CORE），证据透传
	ExcludeFields []string `json:"exclude_fields,omitempty"` // 排除字段名（小写匹配完整路径或末段名）
}

// CompiledSensitiveValueRule 编译后的值级规则（opaque，由请求侧或响应侧编译入口产出）。
type CompiledSensitiveValueRule struct {
	dataType      string
	level         string
	locations     map[string]bool // 已过滤为对应方向支持的位置
	excludeFields map[string]bool // 排除字段名（小写）
	re            *regexp.Regexp
}

// sensitiveValueRequestLocations 请求侧值级检测支持的位置词表
// （xml 无留存值、cookie 整头脱敏、response_body 属响应侧，均不在请求侧消费）。
var sensitiveValueRequestLocations = map[string]bool{
	"query": true, "json": true, "form": true, "header": true, "path": true, "file": true,
}

// 敏感词表/值级规则编译缓存（热路径预编译修复）：发布通道下发的同一配置逐请求
// 重复传入，首次编译后热路径直接命中；编译错误同为确定性结果一并缓存，校验语义不变。
var (
	sensitivePatternCache   = newCompileCache(16)
	sensitiveValueRuleCache = newCompileCache(16)
)

type sensitiveValueRulesResult struct {
	rules []CompiledSensitiveValueRule
	err   error
}

// CompileSensitiveValueRules 编译值级规则表：非法规则（空 data_type/regex、正则编译失败、
// 条数/长度超限）显式返回错误，拒绝加载不静默；位置过滤为请求侧支持集，
// 过滤后无可用位置的规则跳过（如仅 cookie/response_body 的规则不属请求侧）。
// 结果经并发安全缓存（键为规则内容）：同一配置仅装配期编译一次，热路径零重复编译。
func CompileSensitiveValueRules(in []SensitiveValueRule) ([]CompiledSensitiveValueRule, error) {
	key := sensitiveValueRulesCacheKey(in)
	if v, ok := sensitiveValueRuleCache.load(key); ok {
		r := v.(sensitiveValueRulesResult)
		return r.rules, r.err
	}
	rules, err := compileSensitiveValueRules(in)
	sensitiveValueRuleCache.store(key, sensitiveValueRulesResult{rules, err})
	return rules, err
}

// sensitiveValueRulesCacheKey 缓存内容键：按序 Quote 拼接（消除拼接歧义）。
func sensitiveValueRulesCacheKey(in []SensitiveValueRule) string {
	var b strings.Builder
	for _, r := range in {
		b.WriteString(strconv.Quote(r.DataType))
		b.WriteByte(':')
		b.WriteString(strconv.Quote(r.Regex))
		b.WriteByte(':')
		b.WriteString(strconv.Quote(r.Level))
		for _, loc := range r.Locations {
			b.WriteByte(',')
			b.WriteString(strconv.Quote(loc))
		}
		if len(r.ExcludeFields) > 0 {
			b.WriteByte('|')
			for _, ex := range r.ExcludeFields {
				b.WriteByte(',')
				b.WriteString(strconv.Quote(ex))
			}
		}
		b.WriteByte(';')
	}
	return b.String()
}

func compileSensitiveValueRules(in []SensitiveValueRule) ([]CompiledSensitiveValueRule, error) {
	return compileSensitiveValueRulesForLocations(in, sensitiveValueRequestLocations)
}

func compileSensitiveValueRulesForLocations(in []SensitiveValueRule, supportedLocations map[string]bool) ([]CompiledSensitiveValueRule, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > maxSensitiveValueRules {
		return nil, fmt.Errorf("sensitive value rules: too many rules (%d > %d)", len(in), maxSensitiveValueRules)
	}
	out := make([]CompiledSensitiveValueRule, 0, len(in))
	for i, r := range in {
		if r.DataType == "" || r.Regex == "" {
			return nil, fmt.Errorf("sensitive value rules[%d]: data_type and regex required", i)
		}
		if len(r.Regex) > maxSensitiveValueRegexLen {
			return nil, fmt.Errorf("sensitive value rules[%d] (%s): regex too long", i, r.DataType)
		}
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return nil, fmt.Errorf("sensitive value rules[%d] (%s): bad regex: %w", i, r.DataType, err)
		}
		locs := map[string]bool{}
		for _, loc := range r.Locations {
			if supportedLocations[loc] {
				locs[loc] = true
			}
		}
		if len(locs) == 0 {
			continue // 无当前方向可用位置：跳过该条
		}
		var excludes map[string]bool
		if len(r.ExcludeFields) > 0 {
			excludes = make(map[string]bool, len(r.ExcludeFields))
			for _, ex := range r.ExcludeFields {
				if norm := strings.ToLower(strings.TrimSpace(ex)); norm != "" {
					excludes[norm] = true
				}
			}
		}
		out = append(out, CompiledSensitiveValueRule{
			dataType: r.DataType, level: r.Level, locations: locs, excludeFields: excludes, re: re,
		})
	}
	return out, nil
}

type sensitivePatternsResult struct {
	patterns []CompiledSensitivePattern
	err      error
}

// CompileSensitivePatterns 编译模式表；in 为 nil 时使用内置默认表。
// 结果经并发安全缓存（键为模式内容）：同一配置仅装配期编译一次，热路径零重复编译。
func CompileSensitivePatterns(in []SensitivePattern) ([]CompiledSensitivePattern, error) {
	key := sensitivePatternsCacheKey(in)
	if v, ok := sensitivePatternCache.load(key); ok {
		r := v.(sensitivePatternsResult)
		return r.patterns, r.err
	}
	patterns, err := compileSensitivePatterns(in)
	sensitivePatternCache.store(key, sensitivePatternsResult{patterns, err})
	return patterns, err
}

// sensitivePatternsCacheKey 缓存内容键：nil 入参固定键（内置默认表）；非 nil 按序 Quote 拼接。
func sensitivePatternsCacheKey(in []SensitivePattern) string {
	if in == nil {
		return "\x00default"
	}
	var b strings.Builder
	for _, p := range in {
		b.WriteString(strconv.Quote(p.DataType))
		b.WriteByte(':')
		b.WriteString(strconv.Quote(p.Pattern))
		b.WriteByte(';')
	}
	return b.String()
}

func compileSensitivePatterns(in []SensitivePattern) ([]CompiledSensitivePattern, error) {
	if in == nil {
		in = defaultSensitivePatterns
	}
	out := make([]CompiledSensitivePattern, 0, len(in))
	for _, p := range in {
		if p.DataType == "" || p.Pattern == "" {
			return nil, fmt.Errorf("sensitive pattern: data_type and pattern required")
		}
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, fmt.Errorf("sensitive pattern %q: %w", p.DataType, err)
		}
		out = append(out, CompiledSensitivePattern{dataType: p.DataType, re: re})
	}
	return out, nil
}

// CheckSensitiveData 敏感字段检测：JSON/Form/XML 字段名命中 → SENSITIVE_FIELD（OBSERVE）；
// Query 键名命中（URL 明文外泄）→ SENSITIVE_IN_QUERY（BLOCK 类，PROTECT 下可阻断）。
// valueRules 非空时追加值级检测（QUERY/FORM/JSON_BODY 值 + HEADER/PATH 位置扩展）；
// valueRules 为空时行为与历史版本完全一致（零变化）。
func CheckSensitiveData(ctx *dsctx.RequestContext, p *parser.Parsed, patterns []CompiledSensitivePattern, valueRules []CompiledSensitiveValueRule) {
	if ctx == nil || p == nil || (len(patterns) == 0 && len(valueRules) == 0) {
		return
	}
	n := 0
	// Query 优先（高危，URL 明文）
	for _, k := range sortedKeys(p.Query) {
		if n >= maxSensitiveMatches {
			return
		}
		if typ, ok := matchSensitive(k, patterns); ok && !IsSensitiveFieldExcluded(k, typ, valueRules) {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "sensitive_data",
				RuleID:   "sensitive.in_query",
				Category: "BLOCK",
				Severity: "HIGH",
				Message:  "sensitive field in url query",
				Evidence: map[string]string{
					"field":     k,
					"data_type": typ,
					"location":  "query",
				},
				ScoreDelta: 40,
			})
			n++
		}
	}
	n += scanFieldNames(ctx, p.JSONFields, "json", patterns, valueRules, maxSensitiveMatches-n)
	if n >= maxSensitiveMatches {
		return
	}
	n += scanFieldNames(ctx, p.FormFields, "form", patterns, valueRules, maxSensitiveMatches-n)
	if n >= maxSensitiveMatches {
		return
	}
	n += scanFieldNames(ctx, p.XMLFields, "xml", patterns, valueRules, maxSensitiveMatches-n)
	// 值级检测与 HEADER/PATH 位置扩展：仅随发布通道值级规则开启（无规则下发时零行为变化）
	if len(valueRules) > 0 {
		scanValueLevel(ctx, p, patterns, valueRules, maxSensitiveMatches-n)
	}
}

// scanValueLevel 值级敏感检测：对 QUERY/FORM/JSON_BODY 留存值做 regex 匹配，
// 并扩展 HEADER（仅非脱敏且非标准协议头做字段名/值级匹配；cookie 整头脱敏跳过）与 PATH 原始段的值级匹配。
// URL 路径字面段仅代表路由/资源文件名（如 /mobile.zip、/mailer.zip、/reset-password），不做字段名级敏感匹配，
// 仅在路径段实际携带匹配值级正则的敏感取值（如 /user/13800138000/detail）时产出 sensitive.value。
// 命中产 OBSERVE 明细（QUERY 位置值命中升级 BLOCK 类，与 sensitive.in_query 同一语义）；
// 证据含 data_type/location/字段名/等级及网关内存脱敏后的 masked_sample，绝不落原始明文。budget 为剩余 match 上限。
func scanValueLevel(ctx *dsctx.RequestContext, p *parser.Parsed, patterns []CompiledSensitivePattern, rules []CompiledSensitiveValueRule, budget int) {
	if budget <= 0 {
		return
	}
	scans := 0 // 值×规则求值计数（maxSensitiveValueScans 封顶，防 CPU 放大）
	// QUERY 值命中：URL 明文外泄，BLOCK 类（与键名命中同一升级语义）
	// 键序排序遍历：事件确定性（map 遍历序抖动使事件顺序不可重现，同 authzcheck.go sort 先例）
	for _, k := range sortedKeys(p.Query) {
		v := p.Query[k]
		if budget <= 0 || scans >= maxSensitiveValueScans {
			return
		}
		if r, matched, ok := matchValueRulesWithSample(v, "query", k, rules, &scans); ok {
			addValueMatch(ctx, "sensitive.value_in_query", "BLOCK", "HIGH", 40,
				"sensitive value in url query", k, "query", r, matched)
			budget--
		}
	}
	// JSON_BODY / FORM 值命中：OBSERVE 级（JSONValues/FormValues 仅在留存开关开启时填充）
	for _, k := range sortedKeys(p.JSONValues) {
		v := p.JSONValues[k]
		if budget <= 0 || scans >= maxSensitiveValueScans {
			return
		}
		if r, matched, ok := matchValueRulesWithSample(v, "json", k, rules, &scans); ok {
			addValueMatch(ctx, "sensitive.value", "OBSERVE", "MEDIUM", 15,
				"sensitive value observed", k, "json", r, matched)
			budget--
		}
	}
	for _, k := range sortedKeys(p.FormValues) {
		v := p.FormValues[k]
		if budget <= 0 || scans >= maxSensitiveValueScans {
			return
		}
		if r, matched, ok := matchValueRulesWithSample(v, "form", k, rules, &scans); ok {
			addValueMatch(ctx, "sensitive.value", "OBSERVE", "MEDIUM", 15,
				"sensitive value observed", k, "form", r, matched)
			budget--
		}
	}
	// HEADER 位置扩展（仅非脱敏头做字段名/值级匹配；cookie 整头脱敏、标准协议头跳过字段名匹配）：
	// authorization/cookie/x-api-key 在 parser 层已脱敏为 "[redacted]" 占位，值不可检；
	// 其中 cookie 头为名值混杂整体，连字段名级匹配也跳过，避免占位名误命中；
	// Sec-CH-UA-Mobile 等标准浏览器/HTTP 协议头跳过字段名匹配，避免被 mobile 等词根误判。
	for _, name := range sortedKeys(p.Headers) {
		v := p.Headers[name]
		if budget <= 0 || scans >= maxSensitiveValueScans {
			return
		}
		if name == "cookie" {
			continue // cookie 整头脱敏：不做字段名/值级匹配
		}
		if v == "[redacted]" {
			continue // 脱敏头仅保留存在性，无值可检，字段名匹配由认证检测器覆盖
		}
		if !isStandardProtocolHeader(name) {
			if typ, ok := matchSensitive(name, patterns); ok && !IsSensitiveFieldExcluded(name, typ, rules) {
				ctx.AddMatch(dsctx.DetectorMatch{
					Detector: "sensitive_data",
					RuleID:   "sensitive.field",
					Category: "OBSERVE",
					Severity: "MEDIUM",
					Message:  "sensitive field name observed",
					Evidence: map[string]string{
						"field":     name,
						"data_type": typ,
						"location":  "header",
					},
					ScoreDelta: 10,
				})
				budget--
				if budget <= 0 {
					return
				}
			}
		}
		if r, matched, ok := matchValueRulesWithSample(v, "header", name, rules, &scans); ok {
			addValueMatch(ctx, "sensitive.value", "OBSERVE", "MEDIUM", 15,
				"sensitive value observed", name, "header", r, matched)
			budget--
		}
	}
	// PATH 位置扩展：仅对原始路径段做值级正则匹配，不做字面段字段名匹配（避免 /mobile.zip、
	// /mailer.zip、/remind_password.zip、/reset-password 等路由或扫描文件名误报为敏感数据提交）。
	// 证据字段名取值级安全的标识：占位段用占位名（如 {id}），字面段改用段序号，绝不落原始段值。
	norm := strings.Split(strings.Trim(p.NormalizedPath, "/"), "/")
	raw := strings.Split(strings.Trim(p.RawPath, "/"), "/")
	for i, rawSeg := range raw {
		if budget <= 0 || scans >= maxSensitiveValueScans {
			return
		}
		if rawSeg == "" {
			continue
		}
		// valueField 值级命中的证据字段名（字面段 = 原始值本身，改用段序号防落值）
		valueField := fmt.Sprintf("segment[%d]", i)
		if i < len(norm) && strings.HasPrefix(norm[i], "{") {
			valueField = norm[i]
		}
		if r, matched, ok := matchValueRulesWithSample(rawSeg, "path", valueField, rules, &scans); ok {
			addValueMatch(ctx, "sensitive.value", "OBSERVE", "MEDIUM", 15,
				"sensitive value observed", valueField, "path", r, matched)
			budget--
		}
	}
}

// matchValueRules 值级匹配：输入长度封顶 4096 后逐规则求值（仅当规则声明该位置）；
// 返回首个命中规则。scans 为求值计数（每次 regex 求值 +1），由调用方封顶。
func matchValueRules(value, location string, rules []CompiledSensitiveValueRule, scans *int) (CompiledSensitiveValueRule, bool) {
	r, _, ok := matchValueRulesWithSample(value, location, "", rules, scans)
	return r, ok
}

// matchValueRulesWithSample 值级匹配并返回正则实际命中的片段（供内存脱敏生成 masked_sample）。
// 字段命中规则 exclude_fields 时跳过该规则；原始切片仅用于就地脱敏，绝不直接写入证据。
func matchValueRulesWithSample(value, location, field string, rules []CompiledSensitiveValueRule, scans *int) (CompiledSensitiveValueRule, string, bool) {
	if value == "" {
		return CompiledSensitiveValueRule{}, "", false
	}
	if utf8.RuneCountInString(value) > maxSensitiveValueInputLen {
		value = string([]rune(value)[:maxSensitiveValueInputLen])
	}
	for _, r := range rules {
		if !r.locations[location] {
			continue
		}
		if field != "" && matchesExcludeSet(field, r.excludeFields) {
			continue
		}
		*scans++
		if *scans > maxSensitiveValueScans {
			return CompiledSensitiveValueRule{}, "", false
		}
		if r.re.MatchString(value) {
			return r, r.re.FindString(value), true
		}
	}
	return CompiledSensitiveValueRule{}, "", false
}

// MatchSensitiveValueRule 单值按位置求值已编译值级规则（NG-MCP G1 mcpguard
// 结果检查挂点导出——与请求侧 matchValueRules 同一语义：输入 4096 rune 封顶、
// 位置过滤（结果侧 location=json）、首个命中）。
// 返回命中 data_type/level；scans 为求值计数（调用方封顶，防 CPU 放大）。
func MatchSensitiveValueRule(value, location string, rules []CompiledSensitiveValueRule, scans *int) (dataType, level string, hit bool) {
	r, ok := matchValueRules(value, location, rules, scans)
	if !ok {
		return "", "", false
	}
	return r.dataType, r.level, true
}

// addValueMatch 产出值级命中明细（证据含 data_type/location/字段名/等级与内存脱敏后的
// masked_sample，绝不落原始明文）。
// 置信度显式 1.0：值经正则验证，属确定性判定（区别于字段名词表匹配的 0.8 默认，
// 见 context.go defaultConfidenceByDetector 取值纪律）。
func addValueMatch(ctx *dsctx.RequestContext, ruleID, category, severity string, score int,
	message, field, location string, r CompiledSensitiveValueRule, matchedValue string) {
	evidence := map[string]string{
		"field":     field,
		"data_type": r.dataType,
		"location":  location,
	}
	if r.level != "" {
		evidence["level"] = r.level
	}
	if masked := MaskSensitiveSample(r.dataType, matchedValue); masked != "" {
		evidence["masked_sample"] = masked
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "sensitive_data",
		RuleID:     ruleID,
		Category:   category,
		Severity:   severity,
		Message:    message,
		Evidence:   evidence,
		ScoreDelta: score,
		Confidence: 1.0,
	})
}

// scanFieldNames 扫描一类字段名集合，返回产生的 match 数。
func scanFieldNames(ctx *dsctx.RequestContext, fields map[string]string, location string, patterns []CompiledSensitivePattern, valueRules []CompiledSensitiveValueRule, budget int) int {
	if budget <= 0 {
		return 0
	}
	n := 0
	for _, name := range sortedKeys(fields) {
		if n >= budget {
			break
		}
		if typ, ok := matchSensitive(name, patterns); ok && !IsSensitiveFieldExcluded(name, typ, valueRules) {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "sensitive_data",
				RuleID:   "sensitive.field",
				Category: "OBSERVE",
				Severity: "MEDIUM",
				Message:  "sensitive field name observed",
				Evidence: map[string]string{
					"field":     name,
					"data_type": typ,
					"location":  location,
				},
				ScoreDelta: 10,
			})
			n++
		}
	}
	return n
}

// sortedKeys 返回排序后的键（事件确定性：map 遍历序抖动使事件顺序不可重现，
// 与 authzcheck.go 的 sort 先例同一纪律）。
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// matchSensitive 返回命中的数据类型标签。
func matchSensitive(fieldName string, patterns []CompiledSensitivePattern) (string, bool) {
	for _, p := range patterns {
		if p.re.MatchString(fieldName) {
			return p.dataType, true
		}
	}
	return "", false
}

// MatchSensitiveDataType 导出字段名匹配（响应侧敏感检测复用同一词表；证据不含值）。
func MatchSensitiveDataType(fieldName string, patterns []CompiledSensitivePattern) (string, bool) {
	return matchSensitive(fieldName, patterns)
}
