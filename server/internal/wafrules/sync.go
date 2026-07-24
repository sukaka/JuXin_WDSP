// Package wafrules 提供WAF规则元数据同步与查询（OWASP CRS + 九章内置 + 自定义）。
package wafrules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 规则来源
const (
	SourceCRS       = "OWASP_CRS"
	SourceCRSPlugin = "CRS_PLUGIN"
	SourceThirdParty = "THIRD_PARTY"
	SourceCustomPack = "CUSTOM_PACK"
	SourceJiuzhang  = "JIUZHANG_BUILTIN"
	SourceCustom    = "USER_CUSTOM"
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
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// SyncReport 是同步结果报告。
type SyncReport struct {
	TotalParsed  int      `json:"total_parsed"`
	TotalInDB    int      `json:"total_in_db"`
	Added        int      `json:"added"`
	Updated      int      `json:"updated"`
	Unchanged    int      `json:"unchanged"`
	Missing      int      `json:"missing"`
	ParseFailed  int      `json:"parse_failed"`
	Conflicts    int      `json:"conflicts"`
	FailedRules  []string `json:"failed_rules"`
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
	"attack-sqli":             "SQL_INJECTION",
	"attack-xss":              "XSS",
	"attack-rce":              "COMMAND_INJECTION",
	"attack-lfi":              "LOCAL_FILE_INCLUSION",
	"attack-rfi":              "REMOTE_FILE_INCLUSION",
	"attack-php":              "PHP_INJECTION",
	"attack-java":             "JAVA_INJECTION",
	"attack-protocol":         "PROTOCOL_VIOLATION",
	"attack-fixation":         "SESSION_FIXATION",
	"attack-scanner":          "SCANNER_DETECTION",
	"attack-disclosure":       "INFORMATION_DISCLOSURE",
	"attack-injection-generic": "REMOTE_CODE_EXECUTION",
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

	// 按行扫描，拼接续行（以 \ 结尾）
	lines := strings.Split(content, "\n")
	var current strings.Builder
	inRule := false

	flush := func() {
		if !inRule {
			return
		}
		ruleText := current.String()
		current.Reset()
		inRule = false
		rule, err := parseOneRule(ruleText, fileName, source)
		if err != nil {
			failed = append(failed, truncate(ruleText, 80)+": "+err.Error())
			return
		}
		if rule != nil {
			rules = append(rules, rule)
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimRight(line, " \t\r")
		isContinuation := strings.HasSuffix(trimmed, "\\")
		if secRuleStartPattern.MatchString(line) {
			flush()
			inRule = true
			current.WriteString(strings.TrimSpace(line))
			if !isContinuation {
				flush()
			}
			continue
		}
		if inRule {
			current.WriteString(" ")
			current.WriteString(strings.TrimSpace(strings.TrimSuffix(trimmed, "\\")))
			if !isContinuation {
				flush()
			}
		}
	}
	flush()
	return rules, failed, nil
}

// parseOneRule 解析单条 SecRule 文本。
func parseOneRule(text, fileName, source string) (*Rule, error) {
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
	if m := msgPattern.FindStringSubmatch(text); m != nil {
		rule.Message = unescape(m[1])
		rule.Name = truncate(rule.Message, 200)
	}
	var tags []string
	for _, m := range tagPattern.FindAllStringSubmatch(text, -1) {
		tags = append(tags, unescape(m[1]))
	}
	if len(tags) > 0 {
		tagJSON, _ := json.Marshal(tags)
		rule.Tags = tagJSON
		// 攻击类型从标签推断
		for _, t := range tags {
			if at, ok := attackTypeByTag[t]; ok {
				rule.AttackType = at
				break
			}
		}
		// OWASP_CRS/ATTACK-XXX 标签
		for _, t := range tags {
			if strings.HasPrefix(t, "OWASP_CRS/ATTACK-") {
				at := strings.TrimPrefix(t, "OWASP_CRS/ATTACK-")
				rule.AttackType = mapAttackCategory(at)
				break
			}
		}
	} else {
		rule.Tags = json.RawMessage("[]")
	}
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
	if len(s) > n {
		return s[:n]
	}
	return s
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

// SyncFromSources 从多个来源目录同步元数据到数据库（CRS 主包 + 插件 + 第三方/自建包）。
// 各来源独立去重（rule_id, rule_source, crs_version 唯一）；报告为全部来源合计。
func (s *SyncService) SyncFromSources(ctx context.Context, crsVersion string, sources []SourceDir) (*SyncReport, error) {
	report := &SyncReport{}
	for _, sd := range sources {
		pattern := filepath.Join(sd.Dir, "*.conf")
		files, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			continue // 空来源目录（如未启用 contrib 包）跳过，不视为错误
		}
		sort.Strings(files)
		if err := s.syncSourceFiles(ctx, files, sd.Source, crsVersion, report); err != nil {
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
			} else if existingRule.ContentHash != rule.ContentHash {
				// 更新
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

func (s *SyncService) existingRules(ctx context.Context, source, crsVersion string) (map[int]*Rule, error) {
	rows, err := s.db.Query(ctx,
		`SELECT rule_id, content_hash FROM waf_rules WHERE rule_source = $1 AND crs_version = $2`, source, crsVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]*Rule{}
	for rows.Next() {
		var id int
		var hash string
		if err := rows.Scan(&id, &hash); err != nil {
			return nil, err
		}
		out[id] = &Rule{RuleID: id, ContentHash: hash}
	}
	return out, rows.Err()
}

func (s *SyncService) insertRule(ctx context.Context, r *Rule) error {
	_, err := s.db.Exec(ctx, `
INSERT INTO waf_rules (rule_id, rule_source, file_name, name, message, severity, phase, tags,
  attack_type, default_state, crs_version, content_hash)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT (rule_id, rule_source, crs_version) DO UPDATE SET
  file_name=EXCLUDED.file_name, name=EXCLUDED.name, message=EXCLUDED.message,
  severity=EXCLUDED.severity, phase=EXCLUDED.phase, tags=EXCLUDED.tags,
  attack_type=EXCLUDED.attack_type, content_hash=EXCLUDED.content_hash, updated_at=now()`,
		r.RuleID, r.RuleSource, r.FileName, r.Name, r.Message, r.Severity, r.Phase, r.Tags,
		r.AttackType, r.DefaultState, r.CRSVersion, r.ContentHash)
	return err
}

func (s *SyncService) updateRule(ctx context.Context, r *Rule) error {
	_, err := s.db.Exec(ctx, `
UPDATE waf_rules SET file_name=$1, name=$2, message=$3, severity=$4, phase=$5, tags=$6,
  attack_type=$7, content_hash=$8, updated_at=now()
WHERE rule_id=$9 AND rule_source=$10 AND crs_version=$11`,
		r.FileName, r.Name, r.Message, r.Severity, r.Phase, r.Tags, r.AttackType, r.ContentHash,
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
