// Package wafrules 提供WAF规则元数据同步与查询（OWASP CRS + 九章内置 + 自定义）。
package wafrules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultCRSDir 与 server/internal/config 默认 WAF_CRS_DIR 保持一致。
const DefaultCRSDir = "gateway/rules/crs/rules"

// ErrCRSDirEmpty 表示主 CRS 规则目录不存在或不包含任何可用规则文件。
var ErrCRSDirEmpty = errors.New("未找到可用 CRS 规则文件")

// 规则来源
const (
	SourceCRS        = "OWASP_CRS"
	SourceCRSPlugin  = "CRS_PLUGIN"
	SourceThirdParty = "THIRD_PARTY"
	SourceCustomPack = "CUSTOM_PACK"
	SourceJiuzhang   = "JIUZHANG_BUILTIN"
	SourceCustom     = "USER_CUSTOM"
)

// Rule 是WAF规则元数据。
type Rule struct {
	ID           uuid.UUID       `json:"id"`
	RuleID       int             `json:"rule_id"`
	RuleSource   string          `json:"rule_source"`
	FileName     string          `json:"file_name"`
	Name         string          `json:"name"`
	Message      string          `json:"message"`
	Severity     string          `json:"severity"`
	Phase        int             `json:"phase"`
	Tags         json.RawMessage `json:"tags"`
	AttackType   string          `json:"attack_type"`
	DefaultState string          `json:"default_state"`
	CRSVersion   string          `json:"crs_version"`
	ContentHash  string          `json:"content_hash"`
	ParsedSpec   json.RawMessage `json:"parsed_spec,omitempty"`
	RawRule      string          `json:"raw_rule,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// SyncReport 是同步结果报告。
type SyncReport struct {
	TotalParsed int      `json:"total_parsed"`
	TotalInDB   int      `json:"total_in_db"`
	Added       int      `json:"added"`
	Updated     int      `json:"updated"`
	Unchanged   int      `json:"unchanged"`
	Missing     int      `json:"missing"`
	ParseFailed int      `json:"parse_failed"`
	Conflicts   int      `json:"conflicts"`
	FailedRules []string `json:"failed_rules"`
}

// secRulePattern 匹配 SecRule 行首（多行规则用 \ 续行）。
var secRuleStartPattern = regexp.MustCompile(`^\s*SecRule\s+`)

// attrPattern 提取规则动作字符串中的属性（id/msg/severity/phase/tag）。
var idPattern = regexp.MustCompile(`\bid\s*:\s*'?(\d+)'?`)
var phasePattern = regexp.MustCompile(`\bphase\s*:\s*'?(\d+)'?`)
var severityPattern = regexp.MustCompile(`\bseverity\s*:\s*'?([A-Z]+)'?`)
var msgPattern = regexp.MustCompile(`\bmsg\s*:\s*'((?:[^'\\]|\\.)*)'`)
var tagPattern = regexp.MustCompile(`\btag\s*:\s*'((?:[^'\\]|\\.)*)'`)

// attackTypeByTag 标签到攻击类型的映射。
var attackTypeByTag = map[string]string{
	"attack-sqli":                    "SQL_INJECTION",
	"attack-xss":                     "XSS",
	"attack-rce":                     "COMMAND_INJECTION",
	"attack-lfi":                     "LOCAL_FILE_INCLUSION",
	"attack-rfi":                     "REMOTE_FILE_INCLUSION",
	"attack-php":                     "PHP_INJECTION",
	"attack-injection-php":           "PHP_INJECTION",
	"attack-java":                    "JAVA_INJECTION",
	"attack-injection-java":          "JAVA_INJECTION",
	"attack-protocol":                "PROTOCOL_VIOLATION",
	"attack-multipart-header":        "PROTOCOL_VIOLATION",
	"attack-deprecated-header":       "PROTOCOL_VIOLATION",
	"attack-fixation":                "SESSION_FIXATION",
	"attack-scanner":                 "SCANNER_DETECTION",
	"attack-reputation-scanner":      "SCANNER_DETECTION",
	"attack-disclosure":              "INFORMATION_DISCLOSURE",
	"attack-injection-generic":       "REMOTE_CODE_EXECUTION",
	"attack-ssrf":                    "SSRF",
	"attack-xxe":                     "XXE_INJECTION",
	"attack-dos":                     "DOS",
	"attack-mass-assignment":         "MASS_ASSIGNMENT",
	"attack-deserialization":         "DESERIALIZATION",
	"attack-ssti":                    "SSTI",
	"attack-upload":                  "FILE_UPLOAD",
	"OWASP_CRS/METHOD-ENFORCEMENT":   "PROTOCOL_VIOLATION",
	"OWASP_CRS/PROTOCOL-ENFORCEMENT": "PROTOCOL_VIOLATION",
	"OWASP_CRS/PROTOCOL-ATTACK":      "PROTOCOL_VIOLATION",
	"OWASP_CRS/MULTIPART-ATTACK":     "PROTOCOL_VIOLATION",
	"OWASP_CRS/SCANNER-DETECTION":    "SCANNER_DETECTION",
	"OWASP_CRS/WEB-SHELLS":           "WEBSHELL",
}

// ParseCRSFile 解析单个规则文件，提取规则元数据（source 标记入库 rule_source）。
func ParseCRSFile(filePath, source string) ([]*Rule, []string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}
	return ParseCRSRules(string(content), filepath.Base(filePath), source)
}

// ParseCRSRules 解析规则文本，提取规则元数据与失败行（source 标记入库 rule_source）。
func ParseCRSRules(content, fileName, source string) ([]*Rule, []string, error) {
	var rules []*Rule
	var failed []string

	// 按行扫描，拼接续行（以 \ 结尾）；同时记录每条 SecRule 正上方紧邻的
	// 注释块（跳过分隔线与版权/许可证行），供无 msg 的规则兜底命名；
	// 另保留原始多行文本（含链式 chain 子规则），供管理端查看实际 SecRule 源码。
	lines := strings.Split(content, "\n")
	var current strings.Builder
	var rawLines []string
	var currentComments []string
	var pendingComments []string
	var lastRule *Rule
	lastExpectsChain := false
	inRule := false

	flush := func() {
		if !inRule {
			return
		}
		ruleText := current.String()
		rawText := strings.TrimSpace(strings.Join(rawLines, "\n"))
		current.Reset()
		rawLines = nil
		inRule = false
		rule, err := parseOneRule(ruleText, fileName, source, currentComments)
		currentComments = nil
		if err != nil {
			failed = append(failed, truncate(ruleText, 80)+": "+err.Error())
			lastRule = nil
			lastExpectsChain = false
			return
		}
		if rule != nil {
			rule.RawRule = rawText
			rules = append(rules, rule)
			lastRule = rule
			lastExpectsChain = wordChainPattern.MatchString(ruleText)
			return
		}
		// 无 id 的 SecRule 若紧跟在带 chain 动作的主规则之后，归并为同一规则的链式子规则原文
		if lastRule != nil && lastExpectsChain && rawText != "" {
			if lastRule.RawRule != "" {
				lastRule.RawRule += "\n" + rawText
			} else {
				lastRule.RawRule = rawText
			}
			lastExpectsChain = wordChainPattern.MatchString(ruleText)
			return
		}
		lastRule = nil
		lastExpectsChain = false
	}

	for _, line := range lines {
		cleanLine := strings.TrimRight(line, "\r")
		trimmed := strings.TrimRight(cleanLine, " \t")
		isContinuation := strings.HasSuffix(trimmed, "\\")
		if secRuleStartPattern.MatchString(cleanLine) {
			flush()
			inRule = true
			currentComments = pendingComments
			pendingComments = nil
			current.WriteString(strings.TrimSpace(cleanLine))
			rawLines = []string{trimmed}
			if !isContinuation {
				flush()
			}
			continue
		}
		if inRule {
			current.WriteString(" ")
			current.WriteString(strings.TrimSpace(strings.TrimSuffix(trimmed, "\\")))
			rawLines = append(rawLines, trimmed)
			if !isContinuation {
				flush()
			}
			continue
		}
		// 规则之外的行：收集紧邻下一条 SecRule 上方的注释块
		text := strings.TrimSpace(cleanLine)
		if strings.HasPrefix(text, "#") {
			c := strings.TrimSpace(strings.TrimPrefix(text, "#"))
			if c == "" || isNoiseComment(c) {
				continue // 空注释、分隔线、版权/许可证行不计入注释块，也不打断相邻块
			}
			pendingComments = append(pendingComments, c)
		} else {
			pendingComments = nil // 空行或其他指令行打断相邻注释块
			if text != "" {
				lastRule = nil
				lastExpectsChain = false
			}
		}
	}
	flush()
	return rules, failed, nil
}

// isNoiseComment 判断注释行是否为分隔线或版权/许可证信息（不作为规则名称来源）。
func isNoiseComment(c string) bool {
	if strings.HasPrefix(c, "---") {
		return true
	}
	lower := strings.ToLower(c)
	return strings.Contains(lower, "copyright") || strings.Contains(lower, "license")
}

// parseOneRule 解析单条 SecRule 文本；commentBlock 为规则正上方紧邻的注释块。
func parseOneRule(text, fileName, source string, commentBlock []string) (*Rule, error) {
	idMatch := idPattern.FindStringSubmatch(text)
	if idMatch == nil {
		return nil, nil // 非规则行（如 SecAction/SecMarker）
	}
	ruleID, err := strconv.Atoi(idMatch[1])
	if err != nil {
		return nil, fmt.Errorf("invalid rule id %q", idMatch[1])
	}
	// CRS 规则 ID 范围（900xxx-999xxx 及插件段）；来源由调用方指定
	rule := &Rule{
		RuleID:       ruleID,
		RuleSource:   source,
		FileName:     fileName,
		DefaultState: "ENABLED",
		Severity:     "NOTICE",
		Phase:        2,
		AttackType:   "OTHER",
	}
	if m := phasePattern.FindStringSubmatch(text); m != nil {
		rule.Phase, _ = strconv.Atoi(m[1])
	}
	if m := severityPattern.FindStringSubmatch(text); m != nil {
		rule.Severity = normalizeSeverity(m[1])
	}
	rawMsg := ""
	if m := msgPattern.FindStringSubmatch(text); m != nil {
		rawMsg = unescape(m[1])
		rule.Message = rawMsg
		rule.Name = truncate(rule.Message, 200)
	}
	// 名称/消息兜底（msg 优先原则不变）：msg 缺失时取规则正上方注释块，
	// 注释也没有时用「文件名去扩展名 + 规则 ID」，随后统一转为中文展示名
	if rule.Message == "" {
		if len(commentBlock) > 0 {
			rule.Message = truncate(strings.Join(commentBlock, " "), 200)
		} else {
			base := strings.TrimSuffix(fileName, filepath.Ext(fileName))
			rule.Message = fmt.Sprintf("%s 规则 %d", base, ruleID)
		}
	}
	rule.Message = LocalizeRule(ruleID, fileName, rule.Message)
	rule.Name = truncate(rule.Message, 200)
	var tags []string
	for _, m := range tagPattern.FindAllStringSubmatch(text, -1) {
		tags = append(tags, unescape(m[1]))
	}
	if len(tags) > 0 {
		tagJSON, _ := json.Marshal(tags)
		rule.Tags = tagJSON
		// 攻击类型从标签推断（webshell/ 前缀统一归为 WEBSHELL）
		for _, t := range tags {
			if at, ok := attackTypeByTag[t]; ok {
				rule.AttackType = at
				break
			}
			if strings.HasPrefix(t, "webshell/") {
				rule.AttackType = "WEBSHELL"
				break
			}
		}
		// OWASP_CRS/ATTACK-XXX 标签（仅在尚未识别时兜底，避免 ATTACK-GENERIC 等
		// 覆盖前序精确攻击标签如 attack-injection-generic）
		if rule.AttackType == "OTHER" {
			for _, t := range tags {
				if strings.HasPrefix(t, "OWASP_CRS/ATTACK-") {
					at := strings.TrimPrefix(t, "OWASP_CRS/ATTACK-")
					if mapped := mapAttackCategory(at); mapped != "OTHER" {
						rule.AttackType = mapped
						break
					}
				}
			}
		}
	} else {
		rule.Tags = json.RawMessage("[]")
	}
	// 标签无法识别时按规则文件兜底分类（自建包/第三方排除插件）
	if rule.AttackType == "OTHER" {
		rule.AttackType = fallbackAttackTypeByFile(fileName)
	}
	// 提取结构化规则事实与中文注释（方案 A：热投递新规则自动具备中文详述）
	spec := extractRuleSpec(text, fileName, source, rawMsg, rule, tags, commentBlock)
	rule.ParsedSpec = marshalRuleSpecJSON(spec)
	// 内容哈希（用于变更检测）
	h := sha256.Sum256([]byte(text))
	rule.ContentHash = hex.EncodeToString(h[:])
	return rule, nil
}

func mapAttackCategory(cat string) string {
	mapping := map[string]string{
		"SQLI": "SQL_INJECTION", "XSS": "XSS", "RCE": "COMMAND_INJECTION",
		"LFI": "LOCAL_FILE_INCLUSION", "RFI": "REMOTE_FILE_INCLUSION",
		"PHP": "PHP_INJECTION", "JAVA": "JAVA_INJECTION", "SESSION-FIXATION": "SESSION_FIXATION",
	}
	if v, ok := mapping[strings.ToUpper(cat)]; ok {
		return v
	}
	return "OTHER"
}

// attackTypeByFileName 文件级攻击类型兜底映射（标签推断仍为 OTHER 的自建包文件）。
var attackTypeByFileName = map[string]string{
	"ssrf-protocols.conf":       "SSRF",
	"cloud-abuse.conf":          "SSRF",
	"xxe-lfi-variants.conf":     "LOCAL_FILE_INCLUSION",
	"deserialization-rce.conf":  "DESERIALIZATION",
	"ssti-injection.conf":       "SSTI",
	"webshell.conf":             "WEBSHELL",
	"webshell-obfuscation.conf": "WEBSHELL",
	"webshell-uploads.conf":     "WEBSHELL",
	"webshell-content.conf":     "WEBSHELL",
	"unauth-access.conf":        "INFORMATION_DISCLOSURE",
	"sensitive-exposure.conf":   "INFORMATION_DISCLOSURE",
	"scanner-fingerprints.conf": "SCANNER_DETECTION",
	"bot-protocol.conf":         "PROTOCOL_VIOLATION",
}

// fallbackAttackTypeByFile 按文件名兜底攻击类型；rule-exclusions 第三方排除插件
// 统一归为 EXCLUSION，其余（如 CRS 901 初始化/949 阻断评估）保持 OTHER。
func fallbackAttackTypeByFile(fileName string) string {
	if at, ok := attackTypeByFileName[fileName]; ok {
		return at
	}
	if strings.Contains(fileName, "rule-exclusions") {
		return "EXCLUSION"
	}
	return "OTHER"
}

func normalizeSeverity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "CRITICAL", "ERROR", "WARNING", "NOTICE":
		return s
	}
	return "NOTICE"
}

func unescape(s string) string {
	s = strings.ReplaceAll(s, `\'`, `'`)
	s = strings.ReplaceAll(s, `\\`, `\`)
	return s
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		return string(runes[:n])
	}
	return s
}

// hasUsableConfFiles 判断目录下是否存在至少一个可解析的 .conf 规则文件。
func hasUsableConfFiles(dir string) bool {
	if dir == "" {
		return false
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.conf"))
	if err != nil || len(files) == 0 {
		return false
	}
	for _, f := range files {
		base := filepath.Base(f)
		if strings.HasSuffix(base, ".example") || strings.Contains(base, "EXCLUSION") {
			continue
		}
		return true
	}
	return false
}

// ResolveCRSDir 解析实际可用的 CRS 规则目录：
// 优先使用显式配置目录；若配置为默认值或容器标准挂载路径且当前目录缺失/为空，
// 自动回退探测容器内置规则目录与常见相对路径（解决旧编排未挂载卷导致同步全 0）。
func ResolveCRSDir(configured string) string {
	configured = strings.TrimSpace(configured)
	if hasUsableConfFiles(configured) {
		return configured
	}
	if configured != "" && configured != DefaultCRSDir && configured != "/etc/caddy/rules/crs/rules" {
		return configured
	}
	candidates := []string{
		"/etc/caddy/rules/crs/rules",
		"/app/gateway/rules/crs/rules",
		DefaultCRSDir,
		filepath.Join("..", DefaultCRSDir),
	}
	for _, c := range candidates {
		if hasUsableConfFiles(c) {
			return c
		}
	}
	if configured != "" {
		return configured
	}
	return DefaultCRSDir
}

// BuildSyncSources 组装全部同步来源：CRS 主包 + CRS 插件 + 第三方/自建 contrib 包 + 九章内置规则。
func BuildSyncSources(crsDir string) []SourceDir {
	resolved := ResolveCRSDir(crsDir)
	sources := []SourceDir{{Dir: resolved, Source: SourceCRS}}
	crsRoot := filepath.Dir(resolved)
	if pluginDirs, err := filepath.Glob(filepath.Join(crsRoot, "plugins", "*", "plugins")); err == nil {
		sort.Strings(pluginDirs)
		for _, d := range pluginDirs {
			sources = append(sources, SourceDir{Dir: d, Source: SourceCRSPlugin})
		}
	}
	rulesRoot := filepath.Dir(crsRoot)
	contribRoot := filepath.Join(rulesRoot, "contrib")
	for _, sd := range []struct {
		dir, source string
	}{
		{"THIRD_PARTY", SourceThirdParty},
		{"CUSTOM_PACK", SourceCustomPack},
	} {
		if st, err := os.Stat(filepath.Join(contribRoot, sd.dir)); err == nil && st.IsDir() {
			sources = append(sources, SourceDir{Dir: filepath.Join(contribRoot, sd.dir), Source: sd.source})
		}
	}
	jiuzhangDir := filepath.Join(rulesRoot, "jiuzhang")
	if st, err := os.Stat(jiuzhangDir); err == nil && st.IsDir() {
		sources = append(sources, SourceDir{Dir: jiuzhangDir, Source: SourceJiuzhang})
	}
	return sources
}

// LoadRawRuleIndex 扫描全部同步来源目录中的规则文件，建立原始 SecRule 索引。
// 返回：byKey（source|file_name|rule_id -> raw_rule）与 byID（rule_id -> raw_rule，兜底用）。
func LoadRawRuleIndex(sources []SourceDir) (map[string]string, map[int]string) {
	byKey := map[string]string{}
	byID := map[int]string{}
	for _, sd := range sources {
		files, err := filepath.Glob(filepath.Join(sd.Dir, "*.conf"))
		if err != nil {
			continue
		}
		sort.Strings(files)
		for _, f := range files {
			base := filepath.Base(f)
			if strings.HasSuffix(base, ".example") || strings.Contains(base, "EXCLUSION") {
				continue
			}
			rules, _, err := ParseCRSFile(f, sd.Source)
			if err != nil {
				continue
			}
			for _, r := range rules {
				if r.RawRule == "" {
					continue
				}
				key := rawRuleCacheKey(sd.Source, base, r.RuleID)
				byKey[key] = r.RawRule
				if _, exists := byID[r.RuleID]; !exists {
					byID[r.RuleID] = r.RawRule
				}
			}
		}
	}
	return byKey, byID
}

func rawRuleCacheKey(source, fileName string, ruleID int) string {
	return source + "|" + fileName + "|" + strconv.Itoa(ruleID)
}

// SyncService 是 CRS 规则同步服务。
type SyncService struct {
	db *pgxpool.Pool
}

// NewSyncService 创建同步服务。
func NewSyncService(db *pgxpool.Pool) *SyncService {
	return &SyncService{db: db}
}

// SourceDir 一个同步来源：目录 + 入库 rule_source。
type SourceDir struct {
	Dir    string
	Source string
}

// SyncFromDirectory 从 CRS 规则目录同步元数据到数据库（OWASP_CRS 单来源，兼容旧调用）。
func (s *SyncService) SyncFromDirectory(ctx context.Context, crsDir, crsVersion string) (*SyncReport, error) {
	return s.SyncFromSources(ctx, crsVersion, []SourceDir{{Dir: crsDir, Source: SourceCRS}})
}

// SyncFromSources 从多个来源目录同步元数据到数据库（CRS 主包 + 插件 + 第三方/自建包 + 九章内置）。
// 各来源独立去重（rule_id, rule_source, crs_version 唯一）；报告为全部来源合计。
// 主 CRS 来源目录缺失或无任何可用 .conf 文件时返回明确错误，禁止静默返回全 0。
func (s *SyncService) SyncFromSources(ctx context.Context, crsVersion string, sources []SourceDir) (*SyncReport, error) {
	report := &SyncReport{}
	for _, sd := range sources {
		pattern := filepath.Join(sd.Dir, "*.conf")
		files, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		var usable []string
		for _, f := range files {
			base := filepath.Base(f)
			if strings.HasSuffix(base, ".example") || strings.Contains(base, "EXCLUSION") {
				continue
			}
			usable = append(usable, f)
		}
		if len(usable) == 0 {
			if sd.Source == SourceCRS {
				return nil, fmt.Errorf("%w（目录 %q 不存在或为空，请检查 WAF_CRS_DIR 配置与规则目录挂载）", ErrCRSDirEmpty, sd.Dir)
			}
			continue // 可选来源目录（如未启用 contrib/插件包）为空时跳过
		}
		sort.Strings(usable)
		if err := s.syncSourceFiles(ctx, usable, sd.Source, crsVersion, report); err != nil {
			return nil, err
		}
	}
	return report, nil
}

// syncSourceFiles 同步单个来源的文件集合：解析、去重（含同 ID 不同来源隔离）、入库与缺失统计。
func (s *SyncService) syncSourceFiles(ctx context.Context, files []string, source, crsVersion string, report *SyncReport) error {
	// 收集数据库现有规则（该来源 + crs_version）
	existing, err := s.existingRules(ctx, source, crsVersion)
	if err != nil {
		return err
	}
	seen := map[int]bool{}

	for _, file := range files {
		// 跳过 example 与文档文件
		base := filepath.Base(file)
		if strings.HasSuffix(base, ".example") || strings.Contains(base, "EXCLUSION") {
			continue
		}
		rules, failed, err := ParseCRSFile(file, source)
		if err != nil {
			report.ParseFailed++
			report.FailedRules = append(report.FailedRules, base+": "+err.Error())
			continue
		}
		report.ParseFailed += len(failed)
		report.FailedRules = append(report.FailedRules, failed...)

		for _, rule := range rules {
			report.TotalParsed++
			rule.CRSVersion = crsVersion
			seen[rule.RuleID] = true

			existingRule, ok := existing[rule.RuleID]
			if !ok {
				// 新增
				if err := s.insertRule(ctx, rule); err != nil {
					report.Conflicts++
					report.FailedRules = append(report.FailedRules, fmt.Sprintf("rule %d insert: %v", rule.RuleID, err))
					continue
				}
				report.Added++
			} else if existingRule.ContentHash != rule.ContentHash ||
				existingRule.Name != rule.Name || existingRule.Message != rule.Message ||
				existingRule.AttackType != rule.AttackType ||
				existingRule.RawRule != rule.RawRule ||
				!parsedSpecEqual(existingRule.ParsedSpec, rule.ParsedSpec) {
				// 更新（规则原文变化，或解析器升级导致名称/消息/攻击类型/结构化详述/原文补充修正）
				if err := s.updateRule(ctx, rule); err != nil {
					report.Conflicts++
					report.FailedRules = append(report.FailedRules, fmt.Sprintf("rule %d update: %v", rule.RuleID, err))
					continue
				}
				report.Updated++
			} else {
				report.Unchanged++
			}
		}
	}

	// 缺失（数据库有但文件中无）
	for id := range existing {
		if !seen[id] {
			report.Missing++
		}
	}
	total, err := s.countRules(ctx, source, crsVersion)
	if err == nil {
		report.TotalInDB += total
	}
	return nil
}

func parsedSpecEqual(a, b json.RawMessage) bool {
	sa, okA := parseStoredRuleSpec(a)
	sb, okB := parseStoredRuleSpec(b)
	if okA != okB {
		return false
	}
	if !okA {
		return true
	}
	return reflect.DeepEqual(sa, sb)
}

func (s *SyncService) existingRules(ctx context.Context, source, crsVersion string) (map[int]*Rule, error) {
	rows, err := s.db.Query(ctx,
		`SELECT rule_id, content_hash, name, message, attack_type, parsed_spec, COALESCE(raw_rule, '') FROM waf_rules WHERE rule_source = $1 AND crs_version = $2`, source, crsVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]*Rule{}
	for rows.Next() {
		var id int
		var hash, name, message, attackType, rawRule string
		var parsedSpec []byte
		if err := rows.Scan(&id, &hash, &name, &message, &attackType, &parsedSpec, &rawRule); err != nil {
			return nil, err
		}
		out[id] = &Rule{
			RuleID:      id,
			ContentHash: hash,
			Name:        name,
			Message:     message,
			AttackType:  attackType,
			ParsedSpec:  json.RawMessage(parsedSpec),
			RawRule:     rawRule,
		}
	}
	return out, rows.Err()
}

func (s *SyncService) insertRule(ctx context.Context, r *Rule) error {
	spec := r.ParsedSpec
	if len(spec) == 0 {
		spec = json.RawMessage("{}")
	}
	_, err := s.db.Exec(ctx, `
INSERT INTO waf_rules (rule_id, rule_source, file_name, name, message, severity, phase, tags,
  attack_type, default_state, crs_version, content_hash, parsed_spec, raw_rule)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
ON CONFLICT (rule_id, rule_source, crs_version) DO UPDATE SET
  file_name=EXCLUDED.file_name, name=EXCLUDED.name, message=EXCLUDED.message,
  severity=EXCLUDED.severity, phase=EXCLUDED.phase, tags=EXCLUDED.tags,
  attack_type=EXCLUDED.attack_type, content_hash=EXCLUDED.content_hash,
  parsed_spec=EXCLUDED.parsed_spec, raw_rule=EXCLUDED.raw_rule, updated_at=now()`,
		r.RuleID, r.RuleSource, r.FileName, r.Name, r.Message, r.Severity, r.Phase, r.Tags,
		r.AttackType, r.DefaultState, r.CRSVersion, r.ContentHash, spec, r.RawRule)
	return err
}

func (s *SyncService) updateRule(ctx context.Context, r *Rule) error {
	spec := r.ParsedSpec
	if len(spec) == 0 {
		spec = json.RawMessage("{}")
	}
	_, err := s.db.Exec(ctx, `
UPDATE waf_rules SET file_name=$1, name=$2, message=$3, severity=$4, phase=$5, tags=$6,
  attack_type=$7, content_hash=$8, parsed_spec=$9, raw_rule=$10, updated_at=now()
WHERE rule_id=$11 AND rule_source=$12 AND crs_version=$13`,
		r.FileName, r.Name, r.Message, r.Severity, r.Phase, r.Tags, r.AttackType, r.ContentHash, spec, r.RawRule,
		r.RuleID, r.RuleSource, r.CRSVersion)
	return err
}

func (s *SyncService) countRules(ctx context.Context, source, crsVersion string) (int, error) {
	var n int
	err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM waf_rules WHERE rule_source = $1 AND crs_version = $2`, source, crsVersion).Scan(&n)
	return n, err
}

// VerifySync 校验同步结果（规则总数与抽样完整性）。
func (s *SyncService) VerifySync(ctx context.Context, crsVersion string) (int, []int, error) {
	rows, err := s.db.Query(ctx,
		`SELECT rule_id FROM waf_rules WHERE rule_source = $1 AND crs_version = $2 ORDER BY rule_id`, SourceCRS, crsVersion)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return 0, nil, err
		}
		ids = append(ids, id)
	}
	return len(ids), ids, rows.Err()
}
