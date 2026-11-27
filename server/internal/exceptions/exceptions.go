// Package exceptions 提供WAF例外策略：精确例外、临时例外、宽泛例外受控与 SecLang 生成。
//
// WDSP P0-04（docs/tasks/wdsp-p0/S4_DESIGN_BASELINE.md）：
//   - 校验分双层：ValidateInput（保存层格式校验+不支持组合字段级错误）与
//     ValidateForEnable（启用门禁：应用绑定查库、方法/路径/目标规则/时间窗/不支持动作）；
//   - SecLang 编译采用两规则标记法（Coraza 3.7.0 实测：链首匹配即执行 ctl，不等后续链环——
//     链首挂 ctl 会在条件不全匹配时仍摘除规则且无审计，故条件链仅 setvar 打标（末环），
//     ctl 由独立的 TX 标记效果规则携带）；
//   - LOG_ONLY/ADJUST_SCORE 的整请求 DetectionOnly 替代语义已禁用（编译层直接报错）。
package exceptions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/validation"
)

// 例外动作
const (
	ActionRemoveRule         = "REMOVE_RULE"          // 移除指定规则
	ActionRemoveRuleTag      = "REMOVE_RULE_TAG"      // 移除规则标签（启用时展开冻结进 resolved_rule_ids）
	ActionRemoveVarDetection = "REMOVE_VAR_DETECTION" // 移除指定变量检测
	ActionAdjustScore        = "ADJUST_SCORE"         // 调整异常评分（P0-04 起不支持新启用）
	ActionLogOnly            = "LOG_ONLY"             // 仅记录不阻断（P0-04 起不支持新启用）
	ActionObserveRule        = "OBSERVE_RULE"         // API 引擎受限例外：命中保留观察、取消本次执法贡献
)

// 目标引擎
const (
	EngineWAF = "WAF"
	EngineAPI = "API"
)

// 校验状态（迁移 000130）
const (
	ValidationValid       = "VALID"
	ValidationNeedsReview = "NEEDS_REVIEW"
)

// SupportedAPIDetectors 受支持 API detector 注册表（首批，Finding.RuleID 稳定；
// 其余检测器一律拒绝为例外目标——EXC-11）。
var SupportedAPIDetectors = map[string]bool{"api_schema": true, "api_parser": true}

// 允许的标准化 HTTP 方法集合（启用门禁：非空、大写、≤10）
var allowedMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true,
	"PATCH": true, "DELETE": true, "OPTIONS": true,
}

// 错误
var (
	ErrNotFound     = errors.New("exception not found")
	ErrInvalidInput = errors.New("invalid exception input")
	ErrTooBroad     = errors.New("exception too broad")
	ErrRiskRequired = errors.New("broad exception requires risk acknowledgment")
	ErrInvalidTime  = errors.New("invalid effective time range")
)

// FieldError 是字段级校验错误。
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	// Code 可选机器可读码（如 UNSUPPORTED_ACTION：不支持动作/能力拒绝启用）
	Code string `json:"code,omitempty"`
	// infra 标记外部能力（查库）失败导致的错误：ReviewException 据此将审查本身
	// 判定为失败（返回 error），避免把瞬时基础设施故障落库为 NEEDS_REVIEW。
	infra bool
}

// ValidationErrors 是字段级校验错误集合（保存层/启用门禁共用）。
type ValidationErrors struct {
	Fields []FieldError
}

func (e *ValidationErrors) Error() string {
	if e == nil || len(e.Fields) == 0 {
		return "invalid exception input"
	}
	parts := make([]string, 0, len(e.Fields))
	for _, f := range e.Fields {
		parts = append(parts, f.Field+": "+f.Message)
	}
	return "invalid exception input: " + strings.Join(parts, "; ")
}

// OrNil 空集合返回 nil。
func (e *ValidationErrors) OrNil() error {
	if e == nil || len(e.Fields) == 0 {
		return nil
	}
	return e
}

func (e *ValidationErrors) add(field, msg string) {
	e.Fields = append(e.Fields, FieldError{Field: field, Message: msg})
}

func (e *ValidationErrors) addCode(field, code, msg string) {
	e.Fields = append(e.Fields, FieldError{Field: field, Code: code, Message: msg})
}

// addInfra 记录外部能力失败（非用户输入问题）导致的字段错误。
func (e *ValidationErrors) addInfra(field, msg string) {
	e.Fields = append(e.Fields, FieldError{Field: field, Message: msg, infra: true})
}

// HasField 判断是否含指定字段的错误。
func (e *ValidationErrors) HasField(field string) bool {
	return e.FieldErr(field) != nil
}

// FieldErr 返回指定字段的首个错误（无则 nil）。
func (e *ValidationErrors) FieldErr(field string) *FieldError {
	if e == nil {
		return nil
	}
	for i := range e.Fields {
		if e.Fields[i].Field == field {
			return &e.Fields[i]
		}
	}
	return nil
}

// HasUnsupportedAction 判断是否存在不支持动作/能力类错误（响应码 UNSUPPORTED_ACTION）。
func (e *ValidationErrors) HasUnsupportedAction() bool {
	if e == nil {
		return false
	}
	for _, f := range e.Fields {
		if f.Code == "UNSUPPORTED_ACTION" {
			return true
		}
	}
	return false
}

// APIRuleRef 是 API 引擎例外目标规则引用（匹配 Finding 的 detector+rule_id）。
type APIRuleRef struct {
	DetectorID   string `json:"detector_id"`
	RuleID       string `json:"rule_id"`
	ModelVersion string `json:"model_version,omitempty"`
}

// 宽泛例外判定（高风险，需要确认）
// 禁止：全局关闭WAF、关闭全部SQLi/XSS规则、对全部应用移除高风险规则
var broadAttackTypes = map[string]bool{
	"SQL_INJECTION": true, "XSS": true, "COMMAND_INJECTION": true,
}

// Exception 是例外策略。
type Exception struct {
	ID               uuid.UUID  `json:"id"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	ScopeType        string     `json:"scope_type"`
	ApplicationID    *uuid.UUID `json:"application_id"`
	PolicyID         *uuid.UUID `json:"policy_id"`
	Domain           string     `json:"domain"`
	URIExact         string     `json:"uri_exact"`
	URIPrefix        string     `json:"uri_prefix"`
	URIRegex         string     `json:"uri_regex"`
	Methods          []string   `json:"methods"`
	SourceIPs        []string   `json:"source_ips"`
	ParamNames       []string   `json:"param_names"`
	CookieNames      []string   `json:"cookie_names"`
	HeaderNames      []string   `json:"header_names"`
	RuleIDs          []int      `json:"rule_ids"`
	RuleTags         []string   `json:"rule_tags"`
	AttackTypes      []string   `json:"attack_types"`
	ContentTypes     []string   `json:"content_types"`
	ExceptionAction  string     `json:"exception_action"`
	ActionTarget     string     `json:"action_target"`
	IsTemporary      bool       `json:"is_temporary"`
	EffectiveFrom    *time.Time `json:"effective_from"`
	EffectiveUntil   *time.Time `json:"effective_until"`
	Status           string     `json:"status"`
	RiskAcknowledged bool       `json:"risk_acknowledged"`
	Reason           string     `json:"reason"`
	Version          int        `json:"version"`
	// ---------- P0-04 契约扩展列（迁移 000130） ----------
	// TargetEngine 目标引擎：WAF（默认，编译为 before-CRS SecLang）/ API（经 api_exceptions 段下发）
	TargetEngine string `json:"target_engine"`
	// APIRuleRefs API 引擎目标规则引用（detector_id ∈ SupportedAPIDetectors）
	APIRuleRefs []APIRuleRef `json:"api_rule_refs"`
	// ResolvedRuleIDs RuleTags 启用时经规则目录展开并冻结的有界规则 ID 集
	ResolvedRuleIDs []int `json:"resolved_rule_ids"`
	// SourceEventID 从事件创建例外的来源事件（服务端可信绑定）
	SourceEventID *uuid.UUID `json:"source_event_id"`
	// ValidationStatus VALID / NEEDS_REVIEW（保存/更新时重算；NEEDS_REVIEW 禁止启用）
	ValidationStatus string `json:"validation_status"`
	// CompiledFingerprint 编译摘要（sha256 hex；保存/启用/预览时重算，发布前比对防预览后篡改）
	CompiledFingerprint string `json:"compiled_fingerprint"`
	// UnsupportedReasons 不支持字段/动作的可读原因（迁移报告与预览素材）
	UnsupportedReasons []string `json:"unsupported_reasons"`
}

// normalizedEngine 归一目标引擎（空 = WAF，兼容历史行）。
func (e *Exception) normalizedEngine() string {
	if e.TargetEngine == "" {
		return EngineWAF
	}
	return strings.ToUpper(e.TargetEngine)
}

// hasSpecificCondition 判断是否有具体限定条件（限定后不算宽泛）。
func (e *Exception) hasSpecificCondition() bool {
	return e.Domain != "" || e.URIExact != "" || e.URIPrefix != "" ||
		len(e.ParamNames) > 0 || len(e.RuleIDs) > 0 || len(e.SourceIPs) > 0 ||
		len(e.CookieNames) > 0 || len(e.HeaderNames) > 0
}

// IsBroad 判断是否为宽泛例外（高风险）。
// 宽泛定义：对全部SQLi/XSS/CMDi攻击类型且无任何具体限定条件，
// 或全局且无条件，或无应用限定的规则标签例外。
func (e *Exception) IsBroad() bool {
	// 有具体限定条件的例外不算宽泛（精确例外）
	if e.hasSpecificCondition() {
		return false
	}
	// 对全部SQLi/XSS/CMDi攻击类型的无条件例外
	for _, at := range e.AttackTypes {
		if broadAttackTypes[at] {
			return true
		}
	}
	// 全局 + 无具体限定条件
	if e.ScopeType == "GLOBAL" {
		return true
	}
	// 无应用限定的规则标签例外
	if len(e.RuleTags) > 0 && e.ApplicationID == nil {
		for _, t := range e.RuleTags {
			if strings.Contains(strings.ToUpper(t), "SQLI") || strings.Contains(strings.ToUpper(t), "XSS") {
				return true
			}
		}
	}
	return false
}

// ValidateInput 校验例外策略输入（保存层：Create/Update 共用）。
// 口径（P0-04 契约 §4）：字段格式校验保留现状；不支持字段组合返回字段级错误
// （*ValidationErrors），不静默舍弃。Methods 为空的历史数据在此层允许（兼容），
// 由启用门禁（ValidateForEnable）拒绝。
func ValidateInput(e *Exception) error {
	verrs := &ValidationErrors{}
	engine := e.normalizedEngine()
	if e.TargetEngine != "" && engine != EngineWAF && engine != EngineAPI {
		verrs.add("target_engine", "目标引擎仅支持 WAF / API")
	}
	if e.Name == "" || len(e.Name) > 128 {
		verrs.add("name", "例外名称不能为空且不超过128字符")
	}
	// 时间范围
	if e.EffectiveFrom != nil && e.EffectiveUntil != nil {
		if e.EffectiveUntil.Before(*e.EffectiveFrom) {
			verrs.add("effective_until", "失效时间必须晚于生效时间")
		}
	}
	if e.IsTemporary && e.EffectiveUntil == nil {
		verrs.add("effective_until", "临时例外必须设置失效时间")
	}
	// URI 三种匹配方式最多一个（多填不能「组合生效」，必须显式报错而非择一）
	uriForms := 0
	for _, v := range []string{e.URIExact, e.URIPrefix, e.URIRegex} {
		if v != "" {
			uriForms++
		}
	}
	if uriForms > 1 {
		verrs.add("uri_exact", "URI精确匹配/前缀/正则同时最多配置一个")
	}
	// URI 字段控制字符与长度校验（对齐 l7rules/validate.go hasControlChar 纪律）：
	// 三个字段经 escapeArg 进入 before-crs 指令段，换行可注入独立 SecLang 指令行
	for _, f := range []struct {
		field string
		label string
		value string
	}{
		{"uri_exact", "URI精确匹配", e.URIExact},
		{"uri_prefix", "URI前缀", e.URIPrefix},
		{"uri_regex", "URI正则", e.URIRegex},
	} {
		if len(f.value) > MaxURILen {
			verrs.add(f.field, fmt.Sprintf("%s长度不能超过%d字符", f.label, MaxURILen))
		}
		if hasControlChar(f.value) {
			verrs.add(f.field, f.label+"含控制字符")
		}
	}
	// URI 正则校验（RE2 语法，与 Coraza 实际引擎同族）
	if e.URIRegex != "" {
		if _, err := regexp.Compile(e.URIRegex); err != nil {
			verrs.add("uri_regex", fmt.Sprintf("URI正则语法错误: %v", err))
		}
	}
	// 来源 IP 校验
	for _, ip := range e.SourceIPs {
		if _, err := netip.ParseAddr(ip); err != nil {
			if _, err := netip.ParsePrefix(ip); err != nil {
				verrs.add("source_ips", fmt.Sprintf("无效的来源IP或CIDR: %s", ip))
				break
			}
		}
	}
	// 域名校验
	if e.Domain != "" {
		if _, _, err := validation.ValidateHostname(e.Domain); err != nil {
			verrs.add("domain", fmt.Sprintf("域名格式错误: %v", err))
		}
	}
	// 方法：标准化大写校验，数量上限 10（启用门禁另要求非空）
	if len(e.Methods) > 10 {
		verrs.add("methods", "HTTP 方法最多 10 个")
	}
	for _, m := range e.Methods {
		if !allowedMethods[strings.ToUpper(strings.TrimSpace(m))] {
			verrs.add("methods", fmt.Sprintf("非标准 HTTP 方法: %s", m))
			break
		}
	}
	// Content-Type：规范化 MIME type（分离参数，主类型须为 type/subtype 且不含通配）
	for _, ct := range e.ContentTypes {
		if _, err := parseContentTypeMain(ct); err != nil {
			verrs.add("content_types", fmt.Sprintf("非法 Content-Type: %s", ct))
			break
		}
	}
	// 目标变量名字符集（与 escapeVar 白名单一致；; 等字符可拼接第二个 ctl 目标，必须拒绝）
	for _, f := range []struct {
		field string
		names []string
	}{
		{"param_names", e.ParamNames},
		{"cookie_names", e.CookieNames},
		{"header_names", e.HeaderNames},
	} {
		for _, n := range f.names {
			if n == "" || len(n) > 128 || escapeVar(n) != n {
				verrs.add(f.field, fmt.Sprintf("目标名 %q 含非法字符（仅允许字母/数字/_/-/.）", n))
				break
			}
		}
	}
	// 动作 × 引擎矩阵（保存层：不支持组合给字段级错误；LOG_ONLY/ADJUST_SCORE
	// 历史记录仍可保存，由启用门禁拒绝并给出迁移预览）
	switch engine {
	case EngineWAF:
		switch e.ExceptionAction {
		case ActionRemoveRule, ActionRemoveRuleTag, ActionRemoveVarDetection, ActionAdjustScore, ActionLogOnly:
		case ActionObserveRule:
			verrs.add("exception_action", "OBSERVE_RULE 仅适用于 API 引擎")
		default:
			verrs.add("exception_action", "无效的例外动作")
		}
		if len(e.APIRuleRefs) > 0 {
			verrs.add("api_rule_refs", "WAF 引擎不支持 api_rule_refs（请使用 rule_ids/rule_tags）")
		}
	case EngineAPI:
		if e.ExceptionAction != ActionObserveRule {
			verrs.add("exception_action", "API 引擎例外仅支持 OBSERVE_RULE 动作")
		}
		// WAF 专属概念在 API 引擎上不生效：拒绝而非静默舍弃（契约 §4 保存层）
		if len(e.RuleIDs) > 0 {
			verrs.add("rule_ids", "API 引擎不支持 rule_ids（请使用 api_rule_refs）")
		}
		if len(e.RuleTags) > 0 {
			verrs.add("rule_tags", "API 引擎不支持 rule_tags（请使用 api_rule_refs）")
		}
		if len(e.ParamNames)+len(e.CookieNames)+len(e.HeaderNames) > 0 {
			verrs.add("param_names", "API 引擎例外不支持目标变量名排除（OBSERVE_RULE 以规则引用为粒度）")
		}
		if len(e.APIRuleRefs) > 64 {
			verrs.add("api_rule_refs", "api_rule_refs 最多 64 条")
		}
		for _, ref := range e.APIRuleRefs {
			if !SupportedAPIDetectors[ref.DetectorID] {
				verrs.add("api_rule_refs", fmt.Sprintf("detector_id %q 不在受支持注册表（api_schema/api_parser）", ref.DetectorID))
				break
			}
			if ref.RuleID == "" || len(ref.RuleID) > 128 {
				verrs.add("api_rule_refs", "api_rule_refs 的 rule_id 不能为空且不超过128字符")
				break
			}
		}
	}
	// ActionTarget 纪律：禁止自由文本拼 SecLang——仅允许作为 REMOVE_VAR_DETECTION
	// 的目标集合别名（集合名或指向已声明目标名），否则拒绝
	if e.ActionTarget != "" {
		if e.ExceptionAction != ActionRemoveVarDetection {
			verrs.add("action_target", "action_target 仅可作为 REMOVE_VAR_DETECTION 的目标集合别名")
		} else if !e.actionTargetValid() {
			verrs.add("action_target", "action_target 必须是目标集合别名（ARGS/REQUEST_COOKIES/REQUEST_HEADERS）或指向已声明的目标名")
		}
	}
	if len(verrs.Fields) > 0 {
		return verrs
	}
	// 宽泛例外需要风险确认（保存层护栏；启用授权以结构化范围校验为准，见 ValidateForEnable）
	if e.IsBroad() && !e.RiskAcknowledged {
		return fmt.Errorf("%w: 宽泛例外存在高风险，必须确认风险后才能创建", ErrRiskRequired)
	}
	return nil
}

// actionTargetValid 校验 action_target 是否为目标集合别名（ARGS/REQUEST_COOKIES/
// REQUEST_HEADERS）或指向已声明目标名的引用（如 ARGS:comment）。
func (e *Exception) actionTargetValid() bool {
	for _, entry := range strings.Split(e.ActionTarget, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return false
		}
		collection, name, hasName := strings.Cut(entry, ":")
		switch collection {
		case "ARGS", "REQUEST_COOKIES", "REQUEST_HEADERS":
		default:
			return false
		}
		if !hasName {
			continue // 集合别名
		}
		var declared []string
		switch collection {
		case "ARGS":
			declared = e.ParamNames
		case "REQUEST_COOKIES":
			declared = e.CookieNames
		case "REQUEST_HEADERS":
			for _, h := range e.HeaderNames {
				declared = append(declared, strings.ToUpper(h))
			}
		}
		if collection == "REQUEST_HEADERS" {
			name = strings.ToUpper(name)
		}
		found := false
		for _, d := range declared {
			if d == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// parseContentTypeMain 解析 Content-Type 主类型（分离参数；拒绝通配与非法形式）。
func parseContentTypeMain(ct string) (string, error) {
	main, _, err := mime.ParseMediaType(strings.TrimSpace(ct))
	if err != nil {
		return "", err
	}
	if !strings.Contains(main, "/") || strings.Contains(main, "*") {
		return "", fmt.Errorf("非法 MIME 主类型 %q", main)
	}
	return strings.ToLower(main), nil
}

// ---------- 启用门禁（P0-04 契约 §4/§3） ----------

// EnableHooks 启用门禁的外部能力注入（避免包循环）。
type EnableHooks struct {
	// AppExists 应用绑定存在性校验（服务端查库；nil 时门禁报错不静默放行）
	AppExists func(ctx context.Context, id uuid.UUID) (bool, error)
	// ResolveRuleTags 规则目录标签展开（tag → 规则 ID 集；nil = 无规则目录能力，
	// REMOVE_RULE_TAG 拒绝启用并标记 UNSUPPORTED）
	ResolveRuleTags func(ctx context.Context, tags []string) (map[string][]int, error)
}

// EnablePlan 启用门禁通过后的执行计划（启用时落库的派生产物）。
type EnablePlan struct {
	// ResolvedRuleIDs REMOVE_RULE_TAG 展开冻结的规则 ID 集（其余动作复用既有 RuleIDs）
	ResolvedRuleIDs []int
	// CompiledFingerprint 编译摘要（含展开冻结后的内容；发布前重验防预览后篡改）
	CompiledFingerprint string
}

// MaxResolvedRuleIDs 标签展开冻结集上限（有界集合）。
const MaxResolvedRuleIDs = 500

// unsupportedActionMessage 不支持动作的迁移预览文案（契约 §3：返回迁移预览说明）。
func unsupportedActionMessage(action string) string {
	return fmt.Sprintf("动作 %s 为整请求仅观察/调分语义（旧实现编译为 ctl:ruleEngine=DetectionOnly，"+
		"会使该请求整条 WAF 仅观察），P0-04 起不支持新启用；迁移预览：改为 REMOVE_VAR_DETECTION "+
		"并指定目标规则 ID 与目标变量名（精确目标排除），或使用 REMOVE_RULE 限定到具体规则", action)
}

// ValidateForEnable 启用门禁（Enable，及发布前复核）。通过返回执行计划，
// 否则返回字段级错误集合。NEEDS_REVIEW 记录禁止启用（须先修改达标，Update 重算）。
func ValidateForEnable(ctx context.Context, e *Exception, hooks EnableHooks) (*EnablePlan, *ValidationErrors) {
	return validateForEnable(ctx, e, hooks, true)
}

func validateForEnable(ctx context.Context, e *Exception, hooks EnableHooks, checkReviewStatus bool) (*EnablePlan, *ValidationErrors) {
	verrs := &ValidationErrors{}
	engine := e.normalizedEngine()

	if checkReviewStatus && e.ValidationStatus == ValidationNeedsReview {
		verrs.add("validation_status", "该例外标记为 NEEDS_REVIEW（历史危险/不完整配置），须先修改达标后再启用")
	}

	// 动作矩阵门禁（契约 §3）
	switch engine {
	case EngineWAF:
		switch e.ExceptionAction {
		case ActionRemoveRule, ActionRemoveVarDetection, ActionRemoveRuleTag:
		case ActionLogOnly, ActionAdjustScore:
			verrs.addCode("exception_action", "UNSUPPORTED_ACTION", unsupportedActionMessage(e.ExceptionAction))
		default:
			verrs.addCode("exception_action", "UNSUPPORTED_ACTION", fmt.Sprintf("未知例外动作 %q", e.ExceptionAction))
		}
	case EngineAPI:
		if e.ExceptionAction != ActionObserveRule {
			verrs.addCode("exception_action", "UNSUPPORTED_ACTION", "API 引擎例外仅支持 OBSERVE_RULE 动作")
		}
	}

	// 范围门禁：必须绑定具体应用（GLOBAL 禁止新建/启用；应用必须真实存在）
	if e.ScopeType != "APPLICATION" {
		verrs.add("scope_type", "新启用例外必须绑定具体应用（scope_type=APPLICATION）；GLOBAL 历史记录保留可读、禁止启用")
	}
	if e.ApplicationID == nil {
		verrs.add("application_id", "缺少应用绑定")
	} else if hooks.AppExists == nil {
		verrs.add("application_id", "应用存在性校验能力未配置，拒绝启用")
	} else {
		ok, err := hooks.AppExists(ctx, *e.ApplicationID)
		if err != nil {
			verrs.addInfra("application_id", "应用存在性校验失败: "+err.Error())
		} else if !ok {
			verrs.add("application_id", "绑定的应用不存在或已删除")
		}
	}

	// 方法门禁：非空、标准化大写、∈标准集合、≤10（历史空数据保存层兼容，启用拒绝）
	if len(e.Methods) == 0 {
		verrs.add("methods", "启用例外必须限定 HTTP 方法（methods 非空）")
	} else {
		if len(e.Methods) > 10 {
			verrs.add("methods", "HTTP 方法最多 10 个")
		}
		for _, m := range e.Methods {
			if !allowedMethods[strings.ToUpper(strings.TrimSpace(m))] {
				verrs.add("methods", fmt.Sprintf("非标准 HTTP 方法: %s", m))
				break
			}
		}
	}

	// URI 门禁：URIExact XOR URIPrefix（URIRegex 仅历史/高级：需 risk_acknowledged +
	// RE2 可编译 + ≤512，并记录 unsupported_reasons 提示——由 ReviewException 追加）
	uriForms := 0
	for _, v := range []string{e.URIExact, e.URIPrefix, e.URIRegex} {
		if v != "" {
			uriForms++
		}
	}
	if uriForms != 1 {
		verrs.add("uri_exact", "必须且只能配置一种 URI 范围（uri_exact 或 uri_prefix；uri_regex 仅限历史/高级配置）")
	}
	if e.URIPrefix != "" {
		if !strings.HasPrefix(e.URIPrefix, "/") {
			verrs.add("uri_prefix", "URI 前缀必须以 / 开头")
		} else if strings.TrimRight(e.URIPrefix, "/") == "" {
			verrs.add("uri_prefix", "禁止以裸 / 作为唯一范围（全路径例外属另行评审的扩大范围）")
		}
	}
	if e.URIRegex != "" {
		if !e.RiskAcknowledged {
			verrs.add("uri_regex", "URIRegex 属历史/高级配置，启用需显式确认风险（risk_acknowledged）")
		}
		if len(e.URIRegex) > 512 {
			verrs.add("uri_regex", "URIRegex 长度不能超过 512 字符")
		}
		if _, err := regexp.Compile(e.URIRegex); err != nil {
			verrs.add("uri_regex", fmt.Sprintf("URIRegex 语法错误（RE2）: %v", err))
		}
	}

	// 时间门禁：临时例外必须有结束时间；from<until（半开区间，相等非法）
	if e.IsTemporary && e.EffectiveUntil == nil {
		verrs.add("effective_until", "临时例外必须设置失效时间")
	}
	if e.EffectiveFrom != nil && e.EffectiveUntil != nil && !e.EffectiveFrom.Before(*e.EffectiveUntil) {
		verrs.add("effective_until", "生效/失效时间必须满足 from < until（半开区间，相等非法）")
	}

	// 目标规则门禁（WAF：rule_ids 或经规则目录冻结的 resolved_rule_ids；API：api_rule_refs）
	plan := &EnablePlan{}
	switch engine {
	case EngineWAF:
		switch e.ExceptionAction {
		case ActionRemoveRule:
			if len(e.RuleIDs) == 0 {
				verrs.add("rule_ids", "启用例外必须指定目标规则（rule_ids 非空）")
			}
		case ActionRemoveVarDetection:
			if len(e.RuleIDs) == 0 {
				verrs.add("rule_ids", "REMOVE_VAR_DETECTION 必须同时指定目标规则 ID")
			}
			if len(e.compileTargets()) == 0 {
				verrs.add("param_names", "REMOVE_VAR_DETECTION 必须同时指定目标变量名（param_names/cookie_names/header_names）")
			}
		case ActionRemoveRuleTag:
			if len(e.RuleTags) == 0 {
				verrs.add("rule_tags", "REMOVE_RULE_TAG 必须指定规则标签")
			} else if hooks.ResolveRuleTags == nil {
				verrs.addCode("rule_tags", "UNSUPPORTED_ACTION", "无规则目录能力，无法将标签安全展开为有界规则 ID 集，拒绝启用")
			} else {
				resolved, err := hooks.ResolveRuleTags(ctx, e.RuleTags)
				if err != nil {
					verrs.addInfra("rule_tags", "规则目录查询失败: "+err.Error())
				} else {
					var missing []string
					merged := map[int]bool{}
					for _, tag := range e.RuleTags {
						ids := resolved[tag]
						if len(ids) == 0 {
							missing = append(missing, tag)
							continue
						}
						for _, id := range ids {
							merged[id] = true
						}
					}
					if len(missing) > 0 {
						verrs.add("rule_tags", fmt.Sprintf("标签无法在当前规则包中解析为规则: %s", strings.Join(missing, ", ")))
					} else if len(merged) > MaxResolvedRuleIDs {
						verrs.add("rule_tags", fmt.Sprintf("标签展开规则数 %d 超过上限 %d（冻结集必须有界）", len(merged), MaxResolvedRuleIDs))
					} else {
						ids := make([]int, 0, len(merged))
						for id := range merged {
							ids = append(ids, id)
						}
						sort.Ints(ids)
						plan.ResolvedRuleIDs = ids
					}
				}
			}
		}
	case EngineAPI:
		if len(e.APIRuleRefs) == 0 {
			verrs.add("api_rule_refs", "API 引擎例外必须指定目标规则引用（api_rule_refs 非空）")
		} else {
			for _, ref := range e.APIRuleRefs {
				if !SupportedAPIDetectors[ref.DetectorID] {
					verrs.addCode("api_rule_refs", "UNSUPPORTED_ACTION",
						fmt.Sprintf("detector_id %q 不在受支持注册表（api_schema/api_parser），JWT/协议底线/访问控制等不可经例外跳过", ref.DetectorID))
					break
				}
			}
		}
	}

	if len(verrs.Fields) > 0 {
		return nil, verrs
	}

	// 编译摘要（含展开冻结产物；预览后草稿被改 → 指纹变化可被检出）
	fpSrc := *e
	if plan.ResolvedRuleIDs != nil {
		fpSrc.ResolvedRuleIDs = plan.ResolvedRuleIDs
	}
	fp, err := CompiledFingerprint(&fpSrc)
	if err != nil {
		verrs.add("exception_action", "编译失败: "+err.Error())
		return nil, verrs
	}
	plan.CompiledFingerprint = fp
	return plan, nil
}

// ReviewException 重算 validation_status 与 unsupported_reasons（保存/更新后调用）。
// 以启用门禁同一结构化校验为准（不含 NEEDS_REVIEW 自检），任何不达标即 NEEDS_REVIEW
// 并记录可读原因；URIRegex 等高级配置即使达标也追加提示。
// 外部能力（查库）瞬时失败时返回 error——审查结论不可靠，调用方不应落库错误状态。
func ReviewException(ctx context.Context, e *Exception, hooks EnableHooks) (string, []string, error) {
	status, reasons, _, err := review(ctx, e, hooks)
	return status, reasons, err
}

// review 是 ReviewException 的内部形式：额外返回启用计划（REMOVE_RULE_TAG 的
// 展开冻结产物），供保存/更新路径一并落库 resolved_rule_ids。
func review(ctx context.Context, e *Exception, hooks EnableHooks) (string, []string, *EnablePlan, error) {
	plan, verrs := validateForEnable(ctx, e, hooks, false)
	var reasons []string
	if verrs != nil {
		for _, f := range verrs.Fields {
			if f.infra {
				return "", nil, nil, fmt.Errorf("审查例外失败（%s）: %s", f.Field, f.Message)
			}
			reasons = append(reasons, f.Field+": "+f.Message)
		}
	}
	status := ValidationValid
	if len(reasons) > 0 {
		status = ValidationNeedsReview
	}
	// URIRegex 提示为审查留痕（unsupported_reasons/预览素材），不翻转 VALID 判定——
	// 带 risk_acknowledged 的高级配置经启用门禁仍可启用（契约 §4）。
	if e.URIRegex != "" {
		reasons = append(reasons, "uri_regex: URIRegex 为历史/高级配置，建议改用 uri_exact 或 uri_prefix（按段前缀）")
	}
	if status == ValidationValid {
		return status, reasons, plan, nil
	}
	return status, reasons, nil, nil
}

// ---------- SecLang 编译（P0-04 契约 §5：两规则标记法，Coraza 3.7.0 实测锁定） ----------

// GenerateSecLang 生成例外对应的 SecLang 规则（两规则标记法）：
//
//	标记规则（marker=id）：仅条件链，pass,nolog；setvar:tx.jz_exc_<id>=1 写在末环
//	                      （末环仅在前序链环全部匹配后才求值——Coraza 链语义中唯一安全挂点）；
//	效果规则（effect=id+1）：SecRule TX:jz_exc_<id> "@eq 1"，pass,log，携带全部 ctl 与
//	                      tag:'jiuzhang-exception'/tag:'exc:<uuid>'/tag:'excv:<version>'。
//
// 背景：Coraza 3.7.0 对「自身已匹配」的规则立即执行非中断动作（不等后续链环），
// 链首直挂 ctl 会在路径/方法/IP/时间任一不满足时仍摘除规则且无审计——禁止该写法
// （实测证据：gateway/corazasemantics/exception_seclang_test.go）。
// 无任何条件维度的输入拒绝编译（不允许退化为全局放行）。
// markerRuleID 为标记规则 ID（发布侧分配 8000001+2i，效果规则取其 +1）。
func GenerateSecLang(e *Exception, markerRuleID int) (string, error) {
	if e.normalizedEngine() != EngineWAF {
		return "", fmt.Errorf("API 引擎例外不编译为 SecLang（经 guard 配置 api_exceptions 段下发）")
	}
	ctls, err := compileCtlActions(e)
	if err != nil {
		return "", err
	}

	// 条件链环（仅配置了的维度才生成；顺序冻结：Host→URI→方法→IP→Content-Type→时间）
	var conds []string
	if e.Domain != "" {
		domain := escapeRegexArg(regexp.QuoteMeta(validation.NormalizeHostname(e.Domain)))
		conds = append(conds, fmt.Sprintf(`SecRule REQUEST_HEADERS:Host "@rx (?i)^%s(?::\d+)?$"`, domain))
	}
	switch {
	case e.URIExact != "":
		// REQUEST_FILENAME 不含 query（EXC-08）
		conds = append(conds, fmt.Sprintf(`SecRule REQUEST_FILENAME "@streq %s"`, escapeArg(e.URIExact)))
	case e.URIPrefix != "":
		prefix := strings.TrimRight(e.URIPrefix, "/")
		if prefix == "" {
			return "", fmt.Errorf("uri_prefix 为裸 /：拒绝编译（全路径例外不属本 P0 默认范围）")
		}
		conds = append(conds, fmt.Sprintf(`SecRule REQUEST_FILENAME "@rx ^%s(?:/|$)"`, escapeRegexArg(regexp.QuoteMeta(prefix))))
	case e.URIRegex != "":
		conds = append(conds, fmt.Sprintf(`SecRule REQUEST_FILENAME "@rx %s"`, escapeRegexArg(e.URIRegex)))
	}
	if len(e.Methods) > 0 {
		methods := make([]string, 0, len(e.Methods))
		for _, m := range e.Methods {
			methods = append(methods, strings.ToUpper(strings.TrimSpace(m)))
		}
		sort.Strings(methods) // 规范化排序：同一语义集合编译产物（与指纹）逐字节稳定
		conds = append(conds, fmt.Sprintf(`SecRule REQUEST_METHOD "@pm %s"`, strings.Join(methods, " ")))
	}
	if len(e.SourceIPs) > 0 {
		conds = append(conds, fmt.Sprintf(`SecRule REMOTE_ADDR "@ipMatch %s"`, strings.Join(e.SourceIPs, ",")))
	}
	if len(e.ContentTypes) > 0 {
		mains := make([]string, 0, len(e.ContentTypes))
		for _, ct := range e.ContentTypes {
			main, err := parseContentTypeMain(ct)
			if err != nil {
				return "", fmt.Errorf("非法 Content-Type %q: %w", ct, err)
			}
			mains = append(mains, regexp.QuoteMeta(main))
		}
		var pattern string
		if len(mains) == 1 {
			pattern = "^" + mains[0] + "(?:[;]|$)"
		} else {
			pattern = "^(?:" + strings.Join(mains, "|") + ")(?:[;]|$)"
		}
		conds = append(conds, fmt.Sprintf(`SecRule REQUEST_HEADERS:Content-Type "@rx %s"`, pattern))
	}
	// 时间链：TIME_EPOCH UTC 秒半开区间 from≤now<until；到期无需再发布，未来生效照常下发
	if e.EffectiveFrom != nil {
		conds = append(conds, fmt.Sprintf(`SecRule TIME_EPOCH "@ge %d"`, e.EffectiveFrom.UTC().Unix()))
	}
	if e.EffectiveUntil != nil {
		conds = append(conds, fmt.Sprintf(`SecRule TIME_EPOCH "@lt %d"`, e.EffectiveUntil.UTC().Unix()))
	}
	if len(conds) == 0 {
		return "", fmt.Errorf("例外未配置任何条件维度，拒绝编译（不允许退化为全局放行）")
	}

	effectRuleID := markerRuleID + 1
	var b strings.Builder
	for i, c := range conds {
		var actions string
		switch {
		case i == 0 && len(conds) == 1:
			// 单条件：首环即末环，携带 id 与 setvar，无 chain
			actions = fmt.Sprintf("id:%d,phase:1,pass,nolog,setvar:tx.jz_exc_%d=1", markerRuleID, markerRuleID)
		case i == 0:
			actions = fmt.Sprintf("id:%d,phase:1,pass,nolog,chain", markerRuleID)
		case i < len(conds)-1:
			actions = "chain"
		default:
			// 末环：仅在前序链环全部匹配后才求值，setvar 只能写在这里
			actions = fmt.Sprintf("setvar:tx.jz_exc_%d=1", markerRuleID)
		}
		if i > 0 {
			b.WriteString("    ")
		}
		b.WriteString(c)
		b.WriteString(" \"")
		b.WriteString(actions)
		b.WriteString("\"\n")
	}
	// 效果规则：仅当标记被设置才触发；log（非 nolog）——例外命中须可审计（exc:/excv: tag 反查锚点）
	fmt.Fprintf(&b, `SecRule TX:jz_exc_%d "@eq 1" "id:%d,phase:1,pass,log,tag:'jiuzhang-exception',tag:'exc:%s',tag:'excv:%d',%s"`,
		markerRuleID, effectRuleID, e.ID.String(), e.Version, strings.Join(ctls, ","))
	return b.String(), nil
}

// compileTargets 编译目标变量名集合（契约 §3 映射：ParamNames→ARGS:、
// CookieNames→REQUEST_COOKIES:、HeaderNames→REQUEST_HEADERS:（统一大写））。
// 目标名经 escapeVar 白名单兜底（保存层已按同字符集校验）。
func (e *Exception) compileTargets() []string {
	var out []string
	for _, p := range e.ParamNames {
		out = append(out, "ARGS:"+escapeVar(p))
	}
	for _, c := range e.CookieNames {
		out = append(out, "REQUEST_COOKIES:"+escapeVar(c))
	}
	for _, h := range e.HeaderNames {
		out = append(out, "REQUEST_HEADERS:"+strings.ToUpper(escapeVar(h)))
	}
	return out
}

// compileCtlActions 构建 ctl 例外动作（契约 §3 动作编译矩阵）：
// REMOVE_RULE/REMOVE_VAR_DETECTION 允许（后者 rule IDs 与目标名缺一不可）；
// REMOVE_RULE_TAG 使用启用时冻结的 resolved_rule_ids 逐 ID 排除；
// LOG_ONLY/ADJUST_SCORE 禁止再生成 DetectionOnly——编译层直接报错。
func compileCtlActions(e *Exception) ([]string, error) {
	targets := e.compileTargets()
	switch e.ExceptionAction {
	case ActionRemoveRule:
		if len(e.RuleIDs) == 0 {
			return nil, fmt.Errorf("REMOVE_RULE 缺少目标规则 ID")
		}
		var ctls []string
		if len(targets) == 0 {
			for _, rid := range e.RuleIDs {
				ctls = append(ctls, fmt.Sprintf("ctl:ruleRemoveById=%d", rid))
			}
			return ctls, nil
		}
		// 带目标名：每个 规则×目标 精确排除
		for _, rid := range e.RuleIDs {
			for _, tg := range targets {
				ctls = append(ctls, fmt.Sprintf("ctl:ruleRemoveTargetById=%d;%s", rid, tg))
			}
		}
		return ctls, nil
	case ActionRemoveVarDetection:
		if len(e.RuleIDs) == 0 || len(targets) == 0 {
			return nil, fmt.Errorf("REMOVE_VAR_DETECTION 必须同时配置目标规则 ID 与目标变量名")
		}
		var ctls []string
		for _, rid := range e.RuleIDs {
			for _, tg := range targets {
				ctls = append(ctls, fmt.Sprintf("ctl:ruleRemoveTargetById=%d;%s", rid, tg))
			}
		}
		return ctls, nil
	case ActionRemoveRuleTag:
		// 标签已于启用时经规则目录展开冻结（不在运行时按标签摘除——冻结集不随规则包升级自动扩展）
		if len(e.ResolvedRuleIDs) == 0 {
			return nil, fmt.Errorf("REMOVE_RULE_TAG 须在启用时经规则目录展开冻结 resolved_rule_ids")
		}
		ctls := make([]string, 0, len(e.ResolvedRuleIDs))
		for _, rid := range e.ResolvedRuleIDs {
			ctls = append(ctls, fmt.Sprintf("ctl:ruleRemoveById=%d", rid))
		}
		return ctls, nil
	case ActionLogOnly, ActionAdjustScore:
		return nil, errors.New(unsupportedActionMessage(e.ExceptionAction))
	default:
		return nil, fmt.Errorf("未知例外动作 %q", e.ExceptionAction)
	}
}

// CompiledFingerprint 计算编译摘要（sha256 hex）：
// WAF 引擎取规范化 SecLang（规则 ID 归一为 0，随内容/版本变化）；API 引擎取规范化
// 例外 JSON（方法与规则引用排序后序列化，确定性）。不可编译时返回错误。
func CompiledFingerprint(e *Exception) (string, error) {
	var raw []byte
	if e.normalizedEngine() == EngineAPI {
		payload := buildCompiledAPIException(e)
		data, err := json.Marshal(payload)
		if err != nil {
			return "", err
		}
		raw = data
	} else {
		gen, err := GenerateSecLang(e, 0)
		if err != nil {
			return "", err
		}
		raw = []byte(gen)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func buildCompiledAPIException(e *Exception) map[string]interface{} {
	payload := map[string]interface{}{
		"schema_version": 1,
		"exception_id":   e.ID.String(),
		"version":        e.Version,
		"domain":         validation.NormalizeHostname(e.Domain),
		"uri_exact":      e.URIExact,
		"uri_prefix":     e.URIPrefix,
		"methods":        normalizedMethods(e.Methods),
		"source_ips":     e.SourceIPs,
		"rule_refs":      sortedAPIRuleRefs(e.APIRuleRefs),
	}
	if e.EffectiveFrom != nil {
		payload["effective_from"] = e.EffectiveFrom.UTC().Unix()
	}
	if e.EffectiveUntil != nil {
		payload["effective_until"] = e.EffectiveUntil.UTC().Unix()
	}
	return payload
}

// CompilePreviewContent 生成例外策略的实际编译内容供管理端详情与预览展示：
//   - WAF 引擎：调用真实 GenerateSecLang（两规则标记法，示例起点 marker=8000001）；
//     若为 REMOVE_RULE_TAG 且草稿尚未冻结 resolved_rule_ids，使用 resolvedOverride 兜底展开；
//   - API 引擎：返回下发网关 api_exceptions 段的规范 JSON 对象；
//   - 尚不可编译（如缺少条件或不支持动作）时返回明确 compileErr 原因。
func CompilePreviewContent(e *Exception, resolvedOverride []int) (secLang string, apiPayload map[string]interface{}, compileErr string) {
	if e == nil {
		return "", nil, "例外对象为空"
	}
	if e.normalizedEngine() == EngineAPI {
		if len(e.APIRuleRefs) == 0 {
			return "", nil, "API 引擎例外缺少目标 api_rule_refs，尚无法下发"
		}
		return "", buildCompiledAPIException(e), ""
	}
	clone := *e
	if len(clone.ResolvedRuleIDs) == 0 && len(resolvedOverride) > 0 {
		clone.ResolvedRuleIDs = append([]int(nil), resolvedOverride...)
	}
	gen, err := GenerateSecLang(&clone, publishMarkerBase)
	if err != nil {
		return "", nil, err.Error()
	}
	return gen, nil, ""
}

func normalizedMethods(methods []string) []string {
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		out = append(out, strings.ToUpper(strings.TrimSpace(m)))
	}
	sort.Strings(out)
	return out
}

func sortedAPIRuleRefs(refs []APIRuleRef) []APIRuleRef {
	out := make([]APIRuleRef, len(refs))
	copy(out, refs)
	sort.Slice(out, func(i, j int) bool {
		if out[i].DetectorID != out[j].DetectorID {
			return out[i].DetectorID < out[j].DetectorID
		}
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].ModelVersion < out[j].ModelVersion
	})
	return out
}

// MaxURILen 是 URI 条件字段（精确/前缀/正则）长度上限（与 l7rules URI 上限一致）。
const MaxURILen = 2048

// hasControlChar 判断是否含控制字符（含 DEL）。
func hasControlChar(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

func escapeArg(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	// 兜底剥离控制字符（防历史库中修复前写入的数据在发布时注入指令行；
	// 新写入由 ValidateInput 拒绝，与 customrules.escapeSecLangString 同口径）
	var b strings.Builder
	for _, c := range s {
		if c >= 0x20 && c != 0x7f {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func escapeVar(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// escapeRegexArg 转义正则语境参数（@rx）：仅转义 " 并剥离控制字符。
// 与 escapeArg（@streq 纯字符串语境）的关键区别：不重复反斜杠——Coraza 3.7.0
// utils.UnescapeQuotedString 只还原 \"，不折叠 \\；正则中的 \d \. 等转义序列
// 必须单反斜杠原样到达引擎（实测模板见 gateway/corazasemantics/exception_seclang_test.go）。
func escapeRegexArg(s string) string {
	s = strings.ReplaceAll(s, `"`, `\"`)
	var b strings.Builder
	for _, c := range s {
		if c >= 0x20 && c != 0x7f {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// exceptionColumns 是 exception_policies 查询列清单（含迁移 000130 的 P0-04 契约扩展列），
// GetByID/List/Enable 的 SELECT/RETURNING 共用，单一事实源。
const exceptionColumns = `id, name, description, scope_type, application_id, policy_id, domain, uri_exact, uri_prefix,
  uri_regex, methods, source_ips, param_names, cookie_names, header_names, rule_ids, rule_tags,
  attack_types, content_types, exception_action, action_target, is_temporary, effective_from,
  effective_until, status, risk_acknowledged, reason, version,
  target_engine, api_rule_refs, resolved_rule_ids, source_event_id,
  validation_status, compiled_fingerprint, unsupported_reasons`

// Store 是例外策略仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// Create 创建例外。保存时按启用门禁同一结构化校验重算 validation_status /
// unsupported_reasons（及 REMOVE_RULE_TAG 的展开冻结集）并落库；编译摘要依赖自增
// version，插入成功后第二步重算回写（不完整草稿编译失败时留空，由启用门禁重算）。
func (s *Store) Create(ctx context.Context, e *Exception, createdBy uuid.UUID) error {
	if err := ValidateInput(e); err != nil {
		return err
	}
	if err := s.reviewForSave(ctx, e); err != nil {
		return err
	}
	err := s.db.QueryRow(ctx, `
INSERT INTO exception_policies (name, description, scope_type, application_id, policy_id, domain,
  uri_exact, uri_prefix, uri_regex, methods, source_ips, param_names, cookie_names, header_names,
  rule_ids, rule_tags, attack_types, content_types, exception_action, action_target, is_temporary,
  effective_from, effective_until, status, risk_acknowledged, reason, created_by,
  target_engine, api_rule_refs, resolved_rule_ids, source_event_id, validation_status, unsupported_reasons)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,
  $28,$29,$30,$31,$32,$33)
RETURNING id, version`,
		e.Name, e.Description, e.ScopeType, e.ApplicationID, e.PolicyID, e.Domain,
		e.URIExact, e.URIPrefix, e.URIRegex, jsonArray(e.Methods), jsonArray(e.SourceIPs),
		jsonArray(e.ParamNames), jsonArray(e.CookieNames), jsonArray(e.HeaderNames),
		jsonIntArray(e.RuleIDs), jsonArray(e.RuleTags), jsonArray(e.AttackTypes), jsonArray(e.ContentTypes),
		e.ExceptionAction, e.ActionTarget, e.IsTemporary, e.EffectiveFrom, e.EffectiveUntil,
		e.Status, e.RiskAcknowledged, e.Reason, createdBy,
		e.normalizedEngine(), jsonAPIRuleRefs(e.APIRuleRefs), jsonIntArray(e.ResolvedRuleIDs), e.SourceEventID,
		e.ValidationStatus, jsonArray(e.UnsupportedReasons),
	).Scan(&e.ID, &e.Version)
	if err != nil {
		return fmt.Errorf("create exception: %w", err)
	}
	return s.storeFingerprint(ctx, e)
}

// reviewForSave 保存路径重算审查状态与（REMOVE_RULE_TAG 时）标签展开冻结集。
func (s *Store) reviewForSave(ctx context.Context, e *Exception) error {
	status, reasons, plan, err := review(ctx, e, s.enableHooks())
	if err != nil {
		return err
	}
	e.ValidationStatus = status
	e.UnsupportedReasons = reasons
	e.ResolvedRuleIDs = nil
	if plan != nil {
		e.ResolvedRuleIDs = plan.ResolvedRuleIDs
	}
	return nil
}

// storeFingerprint 回写编译摘要：不完整配置编译失败属预期（留空，启用门禁重算），
// 仅数据库写失败向上传递。
func (s *Store) storeFingerprint(ctx context.Context, e *Exception) error {
	fp, err := CompiledFingerprint(e)
	if err != nil {
		return nil
	}
	if _, err := s.db.Exec(ctx, `UPDATE exception_policies SET compiled_fingerprint=$2 WHERE id=$1`, e.ID, fp); err != nil {
		return fmt.Errorf("store exception %s fingerprint: %w", e.ID, err)
	}
	e.CompiledFingerprint = fp
	return nil
}

// GetByID 查询例外。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Exception, error) {
	row := s.db.QueryRow(ctx, `SELECT `+exceptionColumns+`
FROM exception_policies WHERE id = $1 AND deleted_at IS NULL`, id)
	return scanException(row)
}

// List 分页查询。
func (s *Store) List(ctx context.Context, scopeType, status string, page, pageSize int) ([]Exception, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	where := "deleted_at IS NULL"
	args := []interface{}{}
	argIdx := 1
	if scopeType != "" {
		where += fmt.Sprintf(" AND scope_type = $%d", argIdx)
		args = append(args, scopeType)
		argIdx++
	}
	if status != "" {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM exception_policies WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + exceptionColumns + `
FROM exception_policies WHERE ` + where + fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Exception
	for rows.Next() {
		e, err := scanExceptionRows(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *e)
	}
	return out, total, rows.Err()
}

// Delete 删除例外。
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.Exec(ctx,
		`UPDATE exception_policies SET deleted_at=now(), updated_at=now(), version=version+1 WHERE id=$1 AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetStatus 设置例外状态。
func (s *Store) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	res, err := s.db.Exec(ctx, `UPDATE exception_policies SET status=$1, updated_at=now(), version=version+1 WHERE id=$2 AND deleted_at IS NULL`, status, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Update 更新例外策略（乐观锁：version 不匹配则失败）。
// 状态不在此方法修改，须走 SetStatus/Enable。保存时重算审查状态、标签冻结集与编译摘要。
func (s *Store) Update(ctx context.Context, e *Exception, expectedVersion int) error {
	if err := ValidateInput(e); err != nil {
		return err
	}
	if err := s.reviewForSave(ctx, e); err != nil {
		return err
	}
	e.Version = expectedVersion + 1 // 编译摘要随版本变化（预览后草稿被改可检出）
	fp, err := CompiledFingerprint(e)
	if err != nil {
		fp = "" // 不完整配置无编译产物：留空，启用门禁重算
	}
	res, err := s.db.Exec(ctx, `
UPDATE exception_policies SET name=$1, description=$2, scope_type=$3, application_id=$4, policy_id=$5,
  domain=$6, uri_exact=$7, uri_prefix=$8, uri_regex=$9, methods=$10, source_ips=$11, param_names=$12,
  cookie_names=$13, header_names=$14, rule_ids=$15, rule_tags=$16, attack_types=$17, content_types=$18,
  exception_action=$19, action_target=$20, is_temporary=$21, effective_from=$22, effective_until=$23,
  risk_acknowledged=$24, reason=$25, updated_at=now(), version=version+1,
  target_engine=$28, api_rule_refs=$29, resolved_rule_ids=$30, source_event_id=$31,
  validation_status=$32, unsupported_reasons=$33, compiled_fingerprint=$34
WHERE id=$26 AND version=$27 AND deleted_at IS NULL`,
		e.Name, e.Description, e.ScopeType, e.ApplicationID, e.PolicyID,
		e.Domain, e.URIExact, e.URIPrefix, e.URIRegex, jsonArray(e.Methods), jsonArray(e.SourceIPs),
		jsonArray(e.ParamNames), jsonArray(e.CookieNames), jsonArray(e.HeaderNames),
		jsonIntArray(e.RuleIDs), jsonArray(e.RuleTags), jsonArray(e.AttackTypes), jsonArray(e.ContentTypes),
		e.ExceptionAction, e.ActionTarget, e.IsTemporary, e.EffectiveFrom, e.EffectiveUntil,
		e.RiskAcknowledged, e.Reason, e.ID, expectedVersion,
		e.normalizedEngine(), jsonAPIRuleRefs(e.APIRuleRefs), jsonIntArray(e.ResolvedRuleIDs), e.SourceEventID,
		e.ValidationStatus, jsonArray(e.UnsupportedReasons), fp)
	if err != nil {
		return fmt.Errorf("update exception %s: %w", e.ID, err)
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	e.CompiledFingerprint = fp
	return nil
}

// Enable 在启用门禁（ValidateForEnable）通过后落库启用：状态推进、版本 +1，
// 并持久化门禁产物（REMOVE_RULE_TAG 展开冻结集）。编译摘要在版本推进后以新行
// 重算回写（SecLang 内嵌 excv:<version>，指纹必须描述启用后的行版本）。
// 不存在返回 ErrNotFound。
func (s *Store) Enable(ctx context.Context, id uuid.UUID, resolvedRuleIDs []int) (*Exception, error) {
	row := s.db.QueryRow(ctx, `UPDATE exception_policies SET
  status='ENABLED', resolved_rule_ids=$2, updated_at=now(), version=version+1
WHERE id=$1 AND deleted_at IS NULL
RETURNING `+exceptionColumns, id, jsonIntArray(resolvedRuleIDs))
	exc, err := scanException(row)
	if err != nil {
		return nil, fmt.Errorf("enable exception %s: %w", id, err)
	}
	if err := s.storeFingerprint(ctx, exc); err != nil {
		return nil, err
	}
	return exc, nil
}

// ApplicationCode 返回例外绑定应用的编码（预览 required_publish_targets 用；
// 未绑定或应用已删除返回空串）。
func (s *Store) ApplicationCode(ctx context.Context, id uuid.UUID) (string, error) {
	var code string
	err := s.db.QueryRow(ctx, `SELECT a.code FROM exception_policies e
JOIN applications a ON a.id = e.application_id AND a.deleted_at IS NULL
WHERE e.id = $1 AND e.deleted_at IS NULL`, id).Scan(&code)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("query application code for exception %s: %w", id, err)
	}
	return code, nil
}

// enableHooks 返回真实库查询实现的启用门禁能力（应用存在性 + 规则目录标签展开）。
func (s *Store) enableHooks() EnableHooks {
	return EnableHooks{
		AppExists: func(ctx context.Context, id uuid.UUID) (bool, error) {
			var exists bool
			err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM applications WHERE id=$1 AND deleted_at IS NULL)`, id).Scan(&exists)
			if err != nil {
				return false, fmt.Errorf("check application %s: %w", id, err)
			}
			return exists, nil
		},
		ResolveRuleTags: s.resolveRuleTags,
	}
}

// resolveRuleTags 经规则目录（waf_rules.tags JSONB）将标签展开为规则 ID 集（按标签
// 分组；启用门禁合并去重排序后冻结进 resolved_rule_ids，不随规则包升级漂移）。
func (s *Store) resolveRuleTags(ctx context.Context, tags []string) (map[string][]int, error) {
	rows, err := s.db.Query(ctx, `
SELECT t.tag, wr.rule_id
FROM waf_rules wr, LATERAL (SELECT jsonb_array_elements_text(wr.tags) AS tag) t
WHERE t.tag = ANY($1)
ORDER BY t.tag, wr.rule_id`, tags)
	if err != nil {
		return nil, fmt.Errorf("resolve rule tags: %w", err)
	}
	defer rows.Close()
	out := make(map[string][]int)
	for rows.Next() {
		var tag string
		var id int
		if err := rows.Scan(&tag, &id); err != nil {
			return nil, fmt.Errorf("resolve rule tags scan: %w", err)
		}
		out[tag] = append(out[tag], id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("resolve rule tags: %w", err)
	}
	return out, nil
}

// ExpireTemporary 到期临时例外自动失效（定时任务）。
func (s *Store) ExpireTemporary(ctx context.Context) (int, error) {
	res, err := s.db.Exec(ctx, `
UPDATE exception_policies SET status='EXPIRED', updated_at=now()
WHERE is_temporary = TRUE AND status = 'ENABLED' AND effective_until IS NOT NULL AND effective_until < now()`)
	if err != nil {
		return 0, err
	}
	return int(res.RowsAffected()), nil
}

func scanException(row pgx.Row) (*Exception, error) {
	var e Exception
	var methods, ips, params, cookies, headers, ruleIDs, ruleTags, attackTypes, contentTypes []byte
	var apiRefs, resolvedIDs, unsupported []byte
	err := row.Scan(&e.ID, &e.Name, &e.Description, &e.ScopeType, &e.ApplicationID, &e.PolicyID,
		&e.Domain, &e.URIExact, &e.URIPrefix, &e.URIRegex, &methods, &ips, &params, &cookies,
		&headers, &ruleIDs, &ruleTags, &attackTypes, &contentTypes, &e.ExceptionAction, &e.ActionTarget,
		&e.IsTemporary, &e.EffectiveFrom, &e.EffectiveUntil, &e.Status, &e.RiskAcknowledged, &e.Reason, &e.Version,
		&e.TargetEngine, &apiRefs, &resolvedIDs, &e.SourceEventID,
		&e.ValidationStatus, &e.CompiledFingerprint, &unsupported)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	e.Methods = parseStrArray(methods)
	e.SourceIPs = parseStrArray(ips)
	e.ParamNames = parseStrArray(params)
	e.CookieNames = parseStrArray(cookies)
	e.HeaderNames = parseStrArray(headers)
	e.RuleIDs = parseIntArray(ruleIDs)
	e.RuleTags = parseStrArray(ruleTags)
	e.AttackTypes = parseStrArray(attackTypes)
	e.ContentTypes = parseStrArray(contentTypes)
	e.APIRuleRefs = parseAPIRuleRefs(apiRefs)
	e.ResolvedRuleIDs = parseIntArray(resolvedIDs)
	e.UnsupportedReasons = parseStrArray(unsupported)
	return &e, nil
}

func scanExceptionRows(rows pgx.Rows) (*Exception, error) {
	var e Exception
	var methods, ips, params, cookies, headers, ruleIDs, ruleTags, attackTypes, contentTypes []byte
	var apiRefs, resolvedIDs, unsupported []byte
	err := rows.Scan(&e.ID, &e.Name, &e.Description, &e.ScopeType, &e.ApplicationID, &e.PolicyID,
		&e.Domain, &e.URIExact, &e.URIPrefix, &e.URIRegex, &methods, &ips, &params, &cookies,
		&headers, &ruleIDs, &ruleTags, &attackTypes, &contentTypes, &e.ExceptionAction, &e.ActionTarget,
		&e.IsTemporary, &e.EffectiveFrom, &e.EffectiveUntil, &e.Status, &e.RiskAcknowledged, &e.Reason, &e.Version,
		&e.TargetEngine, &apiRefs, &resolvedIDs, &e.SourceEventID,
		&e.ValidationStatus, &e.CompiledFingerprint, &unsupported)
	if err != nil {
		return nil, err
	}
	e.Methods = parseStrArray(methods)
	e.SourceIPs = parseStrArray(ips)
	e.ParamNames = parseStrArray(params)
	e.CookieNames = parseStrArray(cookies)
	e.HeaderNames = parseStrArray(headers)
	e.RuleIDs = parseIntArray(ruleIDs)
	e.RuleTags = parseStrArray(ruleTags)
	e.AttackTypes = parseStrArray(attackTypes)
	e.ContentTypes = parseStrArray(contentTypes)
	e.APIRuleRefs = parseAPIRuleRefs(apiRefs)
	e.ResolvedRuleIDs = parseIntArray(resolvedIDs)
	e.UnsupportedReasons = parseStrArray(unsupported)
	return &e, nil
}

func jsonArray(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	data, err := json.Marshal(v)
	if err != nil {
		// []string 序列化不会失败；兜底返回空数组而非损坏数据
		return "[]"
	}
	return string(data)
}

func jsonIntArray(v []int) string {
	if len(v) == 0 {
		return "[]"
	}
	data, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func jsonAPIRuleRefs(v []APIRuleRef) string {
	if len(v) == 0 {
		return "[]"
	}
	data, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func parseAPIRuleRefs(data []byte) []APIRuleRef {
	if len(data) == 0 || string(data) == "[]" || string(data) == "null" {
		return nil
	}
	var out []APIRuleRef
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return out
}

func parseStrArray(data []byte) []string {
	if len(data) == 0 || string(data) == "[]" || string(data) == "null" {
		return nil
	}
	var out []string
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return out
}

func parseIntArray(data []byte) []int {
	if len(data) == 0 || string(data) == "[]" || string(data) == "null" {
		return nil
	}
	var out []int
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return out
}
