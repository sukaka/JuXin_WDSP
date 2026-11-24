package accessrules

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 导入限制
const (
	ImportMaxBytes = 1 << 20 // 文件内容 ≤ 1MB
	ImportMaxLines = 10000   // 行数 ≤ 10000
)

// 导入模式
const (
	ImportModeAllOrNothing = "ALL_OR_NOTHING" // 全部成功才落库（事务）
	ImportModeSkipErrors   = "SKIP_ERRORS"    // 跳过错误行逐条插入
)

// 导入行错误码
const (
	ImportErrInvalid     = "INVALID"
	ImportErrProtected   = "PROTECTED"
	ImportErrAppNotFound = "APP_NOT_FOUND"
	ImportErrConflict    = "CONFLICT"
)

// ImportRowError 是一条行级导入错误。
type ImportRowError struct {
	Line    int    `json:"line"`
	Content string `json:"content"`
	Error   string `json:"error"`
	Code    string `json:"code"`
}

// ImportDefaults 是导入的默认参数（请求体传入，行内未指定时使用）。
type ImportDefaults struct {
	RuleType       string
	ScopeType      string
	ApplicationID  *uuid.UUID
	EffectiveUntil *time.Time
	Reason         string
}

// ParsedImportRow 是一行通过校验的导入数据。
type ParsedImportRow struct {
	Line  int
	Raw   string
	Input CreateInput
}

// AppCodeResolver 按应用编码解析应用 ID（由 Store.ApplicationIDByCode 实现）。
type AppCodeResolver func(ctx context.Context, code string) (uuid.UUID, error)

// csvRecord 是一行原始导入记录（CSV 或纯文本统一成该结构）。
type csvRecord struct {
	line            int
	address         string
	ruleType        string
	scopeType       string
	applicationCode string
	effectiveUntil  string
	reason          string
	raw             string
}

// normalizeImportMode 规范化导入模式，空值默认 ALL_OR_NOTHING（更安全）。
func normalizeImportMode(s string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", ImportModeAllOrNothing:
		return ImportModeAllOrNothing, nil
	case ImportModeSkipErrors:
		return ImportModeSkipErrors, nil
	}
	return "", fmt.Errorf("无效的导入模式: %s（支持 ALL_OR_NOTHING / SKIP_ERRORS）", s)
}

// normalizeImportFormat 规范化导入格式，空值默认 csv。
func normalizeImportFormat(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "csv":
		return "csv", nil
	case "text":
		return "text", nil
	}
	return "", fmt.Errorf("无效的导入格式: %s（支持 csv / text）", s)
}

// parseCSVContent 解析 CSV 导入内容。
// 自动剥离首部 UTF-8 BOM；表头必须包含地址列（address 或 地址）；
// 兼容英文与中文表头别名（大小写不敏感、顺序任意、可选列可缺省）：
// address/地址、rule_type/规则类型、scope_type/生效范围、application_code/应用编码、effective_until/失效时间、reason/原因。
// 结构性错误（缺列/坏引号/超限）整体失败。
func parseCSVContent(content string) ([]csvRecord, error) {
	content = strings.TrimPrefix(content, "\ufeff")
	r := csv.NewReader(strings.NewReader(content))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("CSV 表头解析失败: %v", err)
	}
	colIdx := map[string]int{}
	for i, h := range header {
		key := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(h), "\ufeff")))
		if canon, ok := importHeaderAliases[key]; ok {
			if _, exists := colIdx[canon]; !exists {
				colIdx[canon] = i
			}
		}
	}
	if _, ok := colIdx["address"]; !ok {
		return nil, fmt.Errorf("CSV 表头缺少地址列（address / 地址）（支持列: address/地址, rule_type/规则类型, scope_type/生效范围, application_code/应用编码, effective_until/失效时间, reason/原因）")
	}
	get := func(rec []string, col string) string {
		i, ok := colIdx[col]
		if !ok || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}
	var out []csvRecord
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("CSV 解析失败: %v", err)
		}
		line, _ := r.FieldPos(0)
		if len(rec) == 0 || (len(rec) == 1 && strings.TrimSpace(rec[0]) == "") {
			continue
		}
		out = append(out, csvRecord{
			line:            line,
			address:         get(rec, "address"),
			ruleType:        get(rec, "rule_type"),
			scopeType:       get(rec, "scope_type"),
			applicationCode: get(rec, "application_code"),
			effectiveUntil:  get(rec, "effective_until"),
			reason:          get(rec, "reason"),
			raw:             truncateStr(strings.Join(rec, ","), 200),
		})
		if len(out) > ImportMaxLines {
			return nil, fmt.Errorf("导入行数超过上限 %d", ImportMaxLines)
		}
	}
	return out, nil
}

// importHeaderAliases 导入 CSV 表头中英文别名映射到内部规范列键。
var importHeaderAliases = map[string]string{
	"address":          "address",
	"地址":               "address",
	"rule_type":        "rule_type",
	"规则类型":             "rule_type",
	"scope_type":       "scope_type",
	"生效范围":             "scope_type",
	"application_code": "application_code",
	"应用编码":             "application_code",
	"effective_until":  "effective_until",
	"失效时间":             "effective_until",
	"reason":           "reason",
	"原因":               "reason",
}

// parseTextLines 解析纯文本导入内容：每行一个 IP/CIDR，空行与 # 注释行跳过（自动剥离首部 UTF-8 BOM）。
func parseTextLines(content string) ([]csvRecord, error) {
	content = strings.TrimPrefix(content, "\ufeff")
	var out []csvRecord
	for i, line := range strings.Split(content, "\n") {
		s := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, csvRecord{line: i + 1, address: s, raw: truncateStr(s, 200)})
		if len(out) > ImportMaxLines {
			return nil, fmt.Errorf("导入行数超过上限 %d", ImportMaxLines)
		}
	}
	return out, nil
}

// normalizeImportRuleType 反归一化规则类型：同时兼容英文（ALLOW/DENY）与中文（白名单/黑名单）。
func normalizeImportRuleType(raw string) string {
	s := strings.TrimSpace(raw)
	switch strings.ToUpper(s) {
	case RuleTypeAllow, "白名单":
		return RuleTypeAllow
	case RuleTypeDeny, "黑名单":
		return RuleTypeDeny
	default:
		return strings.ToUpper(s)
	}
}

// normalizeImportScopeType 反归一化生效范围：同时兼容英文（GLOBAL/APPLICATION）与中文（全局/指定应用）。
func normalizeImportScopeType(raw string) string {
	s := strings.TrimSpace(raw)
	switch strings.ToUpper(s) {
	case ScopeGlobal, "全局":
		return ScopeGlobal
	case ScopeApplication, "指定应用":
		return ScopeApplication
	default:
		return strings.ToUpper(s)
	}
}

// buildImportInputs 将原始记录逐行校验并转换为 CreateInput。
// 行级错误（地址/类型/时间/应用编码/保护地址）收集到 errs，不中断后续行。
func buildImportInputs(ctx context.Context, records []csvRecord, def ImportDefaults,
	resolve AppCodeResolver, checker ProtectedChecker, now time.Time) (valid []ParsedImportRow, errs []ImportRowError) {

	for _, rec := range records {
		in := CreateInput{SourceType: SourceImport, Reason: rec.reason}
		fail := func(code, msg string) {
			errs = append(errs, ImportRowError{Line: rec.line, Content: rec.raw, Error: msg, Code: code})
		}

		// 规则类型：行内优先，其次默认参数（同时兼容英文 ALLOW/DENY 与中文 白名单/黑名单）
		in.RuleType = normalizeImportRuleType(firstNonEmpty(rec.ruleType, def.RuleType))
		if in.RuleType != RuleTypeAllow && in.RuleType != RuleTypeDeny {
			fail(ImportErrInvalid, "规则类型必须为 ALLOW/DENY 或 白名单/黑名单")
			continue
		}
		// 生效范围：行内 > 默认参数 > GLOBAL（同时兼容英文 GLOBAL/APPLICATION 与中文 全局/指定应用）
		in.ScopeType = normalizeImportScopeType(firstNonEmpty(rec.scopeType, def.ScopeType, ScopeGlobal))
		switch in.ScopeType {
		case ScopeGlobal:
			if rec.applicationCode != "" {
				fail(ImportErrInvalid, "全局规则不允许指定应用编码")
				continue
			}
		case ScopeApplication:
			switch {
			case rec.applicationCode != "":
				id, err := resolve(ctx, rec.applicationCode)
				if err != nil {
					fail(ImportErrAppNotFound, fmt.Sprintf("应用编码不存在: %s", rec.applicationCode))
					continue
				}
				in.ApplicationID = &id
			case def.ApplicationID != nil:
				in.ApplicationID = def.ApplicationID
			default:
				fail(ImportErrInvalid, "应用级规则缺少应用编码或 application_id 参数")
				continue
			}
		default:
			fail(ImportErrInvalid, "生效范围必须为 GLOBAL/APPLICATION 或 全局/指定应用")
			continue
		}
		// 地址
		norm, _, err := NormalizeAddress(rec.address)
		if err != nil {
			fail(ImportErrInvalid, err.Error())
			continue
		}
		in.Address = norm
		// 失效时间：行内优先
		until := def.EffectiveUntil
		if rec.effectiveUntil != "" {
			t, terr := parseTimeFlex(rec.effectiveUntil)
			if terr != nil {
				fail(ImportErrInvalid, terr.Error())
				continue
			}
			until = &t
		}
		in.EffectiveUntil = until
		if until != nil {
			in.ValidityType = ValidityTemporary
		} else {
			in.ValidityType = ValidityPermanent
		}
		in.Name = norm
		if in.Reason == "" {
			in.Reason = firstNonEmpty(def.Reason, "批量导入")
		}
		if err := ValidateInput(&in, now); err != nil {
			fail(ImportErrInvalid, err.Error())
			continue
		}
		// 保护地址
		if err := CheckProtected(ctx, checker, in.RuleType, in.Address); err != nil {
			if IsProtectedError(err) {
				fail(ImportErrProtected, err.Error())
			} else {
				fail(ImportErrInvalid, err.Error())
			}
			continue
		}
		valid = append(valid, ParsedImportRow{Line: rec.line, Raw: rec.raw, Input: in})
	}
	return valid, errs
}

const csvUTF8BOM = "\xef\xbb\xbf"

// 导出 CSV 中文表头
var exportHeader = []string{
	"规则 ID", "规则名称", "规则类型", "生效范围", "应用编码", "地址", "IP 版本",
	"优先级", "状态", "有效期类型", "生效开始时间", "失效时间",
	"原因", "来源", "命中次数", "最近命中时间", "创建时间",
}

// 导出枚举中文映射（与 web/src/utils/stage5.ts 保持一致）
var (
	exportRuleTypeLabels = map[string]string{
		RuleTypeAllow: "白名单",
		RuleTypeDeny:  "黑名单",
	}
	exportScopeTypeLabels = map[string]string{
		ScopeGlobal:      "全局",
		ScopeApplication: "指定应用",
	}
	exportIPVersionLabels = map[string]string{
		IPVersion4: "IPv4",
		IPVersion6: "IPv6",
	}
	exportStatusLabels = map[string]string{
		StatusDraft:    "草稿",
		StatusActive:   "生效中",
		StatusDisabled: "已停用",
		StatusExpired:  "已过期",
		StatusDeleted:  "已删除",
	}
	exportValidityLabels = map[string]string{
		ValidityPermanent: "永久",
		ValidityTemporary: "临时",
	}
	exportSourceLabels = map[string]string{
		SourceManual:        "手工创建",
		SourceSecurityEvent: "安全事件",
		SourceImport:        "批量导入",
		SourceAutoBlock:     "自动封禁",
		SourceSystem:        "系统内置",
	}
)

func formatRuleEnum(v string, labels map[string]string) string {
	if v == "" {
		return ""
	}
	if label, ok := labels[v]; ok {
		return label
	}
	if label, ok := labels[strings.ToUpper(strings.TrimSpace(v))]; ok {
		return label
	}
	return v
}

// RenderExportCSV 渲染规则导出 CSV（含 UTF-8 BOM、中文表头与中文枚举值）。
// 仅对字符串列做公式注入转义；优先级/命中次数等数值列与 RFC3339 时间戳直接输出，避免误伤负优先级。
func RenderExportCSV(rules []Rule, appCodes map[uuid.UUID]string) string {
	var b strings.Builder
	b.WriteString(csvUTF8BOM)
	b.WriteString(strings.Join(exportHeader, ",") + "\n")
	for _, r := range rules {
		appCode := ""
		if r.ApplicationID != nil {
			appCode = appCodes[*r.ApplicationID]
		}
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%s,%d,%s,%s,%s,%s,%s,%s,%d,%s,%s\n",
			r.ID.String(),
			csvEscape(r.Name),
			csvEscape(formatRuleEnum(r.RuleType, exportRuleTypeLabels)),
			csvEscape(formatRuleEnum(r.ScopeType, exportScopeTypeLabels)),
			csvEscape(appCode),
			csvEscape(r.Address),
			csvEscape(formatRuleEnum(r.IPVersion, exportIPVersionLabels)),
			r.Priority,
			csvEscape(formatRuleEnum(r.Status, exportStatusLabels)),
			csvEscape(formatRuleEnum(r.ValidityType, exportValidityLabels)),
			formatTime(r.EffectiveFrom),
			formatTime(r.EffectiveUntil),
			csvEscape(r.Reason),
			csvEscape(formatRuleEnum(r.SourceType, exportSourceLabels)),
			r.HitCount,
			formatTime(r.LastHitAt),
			r.CreatedAt.UTC().Format(time.RFC3339),
		)
	}
	return b.String()
}

func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// csvEscape CSV 字段转义：=、+、-、@、\t、\r 开头前加 ' 防公式注入；
// 含逗号/引号/换行的字段加双引号并双写内部引号。
func csvEscape(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		s = "'" + s
	}
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
