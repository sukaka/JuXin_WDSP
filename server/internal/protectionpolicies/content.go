package protectionpolicies

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/exceptions"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/ruleoverrides"
	"github.com/jiuzhang-waf/server/internal/wafrules"
)

// PolicyContentSummary 是防护策略生效规则统计摘要。
type PolicyContentSummary struct {
	TotalRules            int `json:"total_rules"`
	ActiveRules           int `json:"active_rules"`
	DisabledByOverride    int `json:"disabled_by_override"`
	SkippedByPL           int `json:"skipped_by_pl"`
	ModeOffRules          int `json:"mode_off_rules"`
	CustomRulesCount      int `json:"custom_rules_count"`
	GlobalExceptionsCount int `json:"global_exceptions_count"`
	OverridesCount        int `json:"overrides_count"`
}

// PolicyOverrideItem 是作用于本策略（全局或策略级）的生效规则覆盖条目。
type PolicyOverrideItem struct {
	ID              uuid.UUID `json:"id"`
	RuleID          int       `json:"rule_id"`
	ScopeType       string    `json:"scope_type"`
	Action          string    `json:"action"`
	Reason          string    `json:"reason"`
	EffectiveActive bool      `json:"effective_active"`
}

// PolicyCustomRuleItem 是启用的管理面自定义规则摘要及 SecLang 原文。
type PolicyCustomRuleItem struct {
	RuleID        int    `json:"rule_id"`
	Name          string `json:"name"`
	AttackType    string `json:"attack_type"`
	Severity      string `json:"severity"`
	Phase         int    `json:"phase"`
	Action        string `json:"action"`
	GeneratedRule string `json:"generated_rule"`
}

// PolicyExceptionItem 是作用于全局的已启用 WAF 例外及编译后的 SecLang 原文。
type PolicyExceptionItem struct {
	ExceptionID      string `json:"exception_id"`
	RuleID           int    `json:"rule_id"`
	ScopeType        string `json:"scope_type"`
	ExceptionVersion int    `json:"exception_version"`
	SecLang          string `json:"seclang"`
}

// PolicyEffectiveRuleItem 是规则库中单条规则在当前策略下的生效视图。
type PolicyEffectiveRuleItem struct {
	RuleID          int                  `json:"rule_id"`
	Name            string               `json:"name"`
	Description     string               `json:"description"`
	Detail          *wafrules.RuleDetail `json:"detail,omitempty"`
	AttackType      string               `json:"attack_type"`
	Severity        string               `json:"severity"`
	Phase           int                  `json:"phase"`
	RuleSource      string               `json:"rule_source"`
	FileName        string               `json:"file_name"`
	ParanoiaLevel   int                  `json:"paranoia_level"`
	EffectiveStatus string               `json:"effective_status"`
	RawRule         string               `json:"raw_rule"`
}

// PolicyRuleFileStage 描述网关按顺序加载的规则文件阶段。
type PolicyRuleFileStage struct {
	Order       int    `json:"order"`
	Path        string `json:"path"`
	Description string `json:"description"`
}

// PolicyContentResponse 是 GET /api/v1/protection-policies/{id}/content 返回体。
type PolicyContentResponse struct {
	PolicyID            uuid.UUID                 `json:"policy_id"`
	PolicyCode          string                    `json:"policy_code"`
	PolicyName          string                    `json:"policy_name"`
	ProtectionMode      string                    `json:"protection_mode"`
	SecRuleEngine       string                    `json:"sec_rule_engine"`
	ParanoiaLevel       int                       `json:"paranoia_level"`
	InboundThreshold    int                       `json:"inbound_anomaly_threshold"`
	OutboundThreshold   int                       `json:"outbound_anomaly_threshold"`
	GeneratedDirectives string                    `json:"generated_directives"`
	LoadedRuleFiles     []PolicyRuleFileStage     `json:"loaded_rule_files"`
	Summary             PolicyContentSummary      `json:"summary"`
	Overrides           []PolicyOverrideItem      `json:"overrides"`
	CustomRules         []PolicyCustomRuleItem    `json:"custom_rules"`
	GlobalExceptions    []PolicyExceptionItem     `json:"global_exceptions"`
	Rules               []PolicyEffectiveRuleItem `json:"rules"`
	RulesTotal          int                       `json:"rules_total"`
	Page                int                       `json:"page"`
	PageSize            int                       `json:"page_size"`
}

// Effective status constants for rules under a protection policy.
const (
	RuleStatusActive             = "ACTIVE"
	RuleStatusDisabledByOverride = "DISABLED_BY_OVERRIDE"
	RuleStatusSkippedByPL        = "SKIPPED_BY_PL"
	RuleStatusModeOff            = "MODE_OFF"
)

func secRuleEngineForMode(mode string) string {
	switch mode {
	case ModeOff:
		return "Off"
	case ModeProtect:
		return "On"
	default:
		return "DetectionOnly"
	}
}

func defaultLoadedRuleFiles() []PolicyRuleFileStage {
	return []PolicyRuleFileStage{
		{Order: 1, Path: "/etc/caddy/rules/coraza.conf", Description: "Coraza 引擎基础配置（请求/响应体解析器与审计配置）"},
		{Order: 2, Path: "/etc/caddy/rules/crs/crs-setup.conf", Description: "OWASP CRS 初始化参数与异常评分基础配置"},
		{Order: 3, Path: "/etc/caddy/rules/crs/plugins/*/plugins/*-config.conf", Description: "CRS 官方插件配置段"},
		{Order: 4, Path: "/etc/caddy/rules/crs/plugins/*/plugins/*-before.conf", Description: "CRS 官方插件前置排除与预处理规则"},
		{Order: 5, Path: "/etc/caddy/rules/exclusions/before-crs.conf", Description: "九章内置 CRS 前置排除规则（紧随其后注入全局例外、规则覆盖与自定义规则）"},
		{Order: 6, Path: "/etc/caddy/rules/crs/rules/*.conf", Description: "OWASP CRS 核心攻击检测规则集（SQLi/XSS/RCE/LFI/协议违规等）"},
		{Order: 7, Path: "/etc/caddy/rules/contrib/*/*.conf", Description: "第三方与自建扩展规则包（SSRF/WebShell/SSTI/反序列化等）"},
		{Order: 8, Path: "/etc/caddy/rules/crs/plugins/*/plugins/*-after.conf", Description: "CRS 官方插件后置规则"},
		{Order: 9, Path: "/etc/caddy/rules/exclusions/after-crs.conf", Description: "九章内置 CRS 后置排除规则"},
		{Order: 10, Path: "/etc/caddy/rules/jiuzhang/jiuzhang-custom.conf", Description: "九章内置静态自定义防护规则"},
		{Order: 11, Path: "/etc/caddy/rules/jiuzhang/post-contrib-blocking.conf", Description: "九章二次阻断汇总评估（确保扩展包计分正常触发阻断）"},
	}
}

// EvaluateRuleEffectiveStatus 计算单条规则在指定策略模式/PL/覆盖状态下的实际生效状态。
func EvaluateRuleEffectiveStatus(protectionMode string, policyPL, rulePL int, disabledByOverride bool) string {
	if protectionMode == ModeOff {
		return RuleStatusModeOff
	}
	if disabledByOverride {
		return RuleStatusDisabledByOverride
	}
	if rulePL > 0 && policyPL > 0 && rulePL > policyPL {
		return RuleStatusSkippedByPL
	}
	return RuleStatusActive
}

// ExtractRuleParanoiaLevel 从规则标签与 parsed_spec 中提取生效偏执级别（0 表示不限 PL / 全级别生效）。
func ExtractRuleParanoiaLevel(tags []string, parsedSpec []byte) int {
	for _, t := range tags {
		const prefix = "paranoia-level/"
		if strings.HasPrefix(t, prefix) {
			if n, err := strconv.Atoi(strings.TrimPrefix(t, prefix)); err == nil && n >= 1 && n <= 4 {
				return n
			}
		}
	}
	if len(parsedSpec) > 0 {
		var spec struct {
			PL int `json:"pl"`
		}
		if err := json.Unmarshal(parsedSpec, &spec); err == nil && spec.PL >= 1 && spec.PL <= 4 {
			return spec.PL
		}
	}
	return 0
}

type rawWafRuleRow struct {
	RuleID       int
	RuleSource   string
	FileName     string
	Name         string
	Message      string
	Severity     string
	Phase        int
	Tags         []byte
	AttackType   string
	DefaultState string
	CRSVersion   string
	ParsedSpec   []byte
	RawRule      string
	OvSummary    string
	OvLogic      string
	OvRisk       string
	OvTuning     string
	OvUpdatedBy  string
	OvUpdatedAt  *time.Time
}

func (s *Store) listWafRulesForContent(ctx context.Context) ([]rawWafRuleRow, error) {
	rows, err := s.db.Query(ctx, `
SELECT DISTINCT ON (r.rule_id)
  r.rule_id, r.rule_source, r.file_name, r.name, r.message, r.severity, r.phase,
  r.tags, r.attack_type, r.default_state, r.crs_version, r.parsed_spec, COALESCE(r.raw_rule, ''),
  COALESCE(d.summary, ''), COALESCE(d.detection_logic, ''), COALESCE(d.risk_impact, ''),
  COALESCE(d.tuning_advice, ''), COALESCE(d.updated_by_name, ''), d.updated_at
FROM waf_rules r
LEFT JOIN waf_rule_descriptions d ON d.rule_id = r.rule_id
ORDER BY r.rule_id ASC, r.crs_version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rawWafRuleRow
	for rows.Next() {
		var r rawWafRuleRow
		if err := rows.Scan(
			&r.RuleID, &r.RuleSource, &r.FileName, &r.Name, &r.Message, &r.Severity, &r.Phase,
			&r.Tags, &r.AttackType, &r.DefaultState, &r.CRSVersion, &r.ParsedSpec, &r.RawRule,
			&r.OvSummary, &r.OvLogic, &r.OvRisk, &r.OvTuning, &r.OvUpdatedBy, &r.OvUpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) listEnabledCustomRulesForContent(ctx context.Context) ([]PolicyCustomRuleItem, []string, error) {
	rows, err := s.db.Query(ctx, `
SELECT rule_id, name, attack_type, severity, phase, action, generated_rule
FROM custom_rules
WHERE status = 'ENABLED' AND generated_rule <> ''
ORDER BY rule_id ASC`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	items := []PolicyCustomRuleItem{}
	lines := []string{}
	for rows.Next() {
		var item PolicyCustomRuleItem
		if err := rows.Scan(&item.RuleID, &item.Name, &item.AttackType, &item.Severity, &item.Phase, &item.Action, &item.GeneratedRule); err != nil {
			return nil, nil, err
		}
		item.GeneratedRule = strings.TrimSpace(item.GeneratedRule)
		items = append(items, item)
		if item.GeneratedRule != "" {
			lines = append(lines, item.GeneratedRule)
		}
	}
	return items, lines, rows.Err()
}

// ContentFilter 是策略生效规则清单的查询筛选条件。
type ContentFilter struct {
	Keyword         string
	AttackType      string
	EffectiveStatus string
	Page            int
	PageSize        int
}

// Content GET /api/v1/protection-policies/{id}/content：
// 返回指定防护策略实际生成的 Coraza SecLang 指令、关联规则覆盖/自定义规则/全局例外，
// 以及防护规则库中全部规则在本策略下的生效状态与原始 SecRule 文本（分页）。
func (h *Handler) Content(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的策略ID")
		return
	}
	policy, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "策略不存在")
		return
	}

	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	if pageSize > 100 {
		pageSize = 100
	}
	filter := ContentFilter{
		Keyword:         strings.TrimSpace(r.URL.Query().Get("keyword")),
		AttackType:      strings.TrimSpace(r.URL.Query().Get("attack_type")),
		EffectiveStatus: strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("effective_status"))),
		Page:            page,
		PageSize:        pageSize,
	}

	ctx := r.Context()

	// 1. 规则覆盖（全局 + 本策略）
	var allOverrides []ruleoverrides.Override
	if h.store.db != nil {
		ovList, ovErr := ruleoverrides.NewStore(h.store.db).ListActiveForPublish(ctx)
		if ovErr != nil {
			response.InternalError(w, r, fmt.Errorf("load rule overrides: %w", ovErr))
			return
		}
		allOverrides = ovList
	}
	disabledIDs := ruleoverrides.ResolveDisableRuleIDs(allOverrides, uuid.Nil, &policy.ID)
	disabledSet := make(map[int]bool, len(disabledIDs))
	for _, rid := range disabledIDs {
		disabledSet[rid] = true
	}
	overrideSecLang := ruleoverrides.BuildDisableSecLang(disabledIDs)

	policyOverrides := []PolicyOverrideItem{}
	for _, ov := range allOverrides {
		if ov.ScopeType == ruleoverrides.ScopeGlobal ||
			(ov.ScopeType == ruleoverrides.ScopePolicy && ov.ScopeID != nil && *ov.ScopeID == policy.ID) {
			effectiveActive := ov.Action == ruleoverrides.ActionDisable && disabledSet[ov.RuleID]
			if ov.Action == ruleoverrides.ActionEnable && !disabledSet[ov.RuleID] {
				effectiveActive = true
			}
			policyOverrides = append(policyOverrides, PolicyOverrideItem{
				ID:              ov.ID,
				RuleID:          ov.RuleID,
				ScopeType:       ov.ScopeType,
				Action:          ov.Action,
				Reason:          ov.Reason,
				EffectiveActive: effectiveActive,
			})
		}
	}

	// 2. 启用的自定义规则
	customItems, customLines, err := h.store.listEnabledCustomRulesForContent(ctx)
	if err != nil {
		response.InternalError(w, r, fmt.Errorf("load custom rules: %w", err))
		return
	}

	// 3. 启用的全局 WAF 例外（与 generator.exceptionAppliesToApp 同口径）
	var globalExRules []gatewayconfig.ExceptionRule
	globalExItems := []PolicyExceptionItem{}
	if h.store.db != nil {
		exList, exErr := exceptions.NewStore(h.store.db).ListForPublish(ctx)
		if exErr != nil {
			response.InternalError(w, r, fmt.Errorf("load exceptions: %w", exErr))
			return
		}
		for _, ex := range exList {
			if ex.ScopeType == "" || ex.ScopeType == "GLOBAL" {
				globalExRules = append(globalExRules, ex)
				globalExItems = append(globalExItems, PolicyExceptionItem{
					ExceptionID:      ex.ExceptionID,
					RuleID:           ex.RuleID,
					ScopeType:        ex.ScopeType,
					ExceptionVersion: ex.ExceptionVersion,
					SecLang:          ex.SecLang,
				})
			}
		}
	}

	// 4. 生成与发布管线同源的完整 Coraza SecLang 指令
	directives := gatewayconfig.BuildPolicyDirectives(
		policy.ProtectionMode,
		policy.ParanoiaLevel,
		policy.InboundAnomalyThreshold,
		policy.OutboundAnomalyThreshold,
		globalExRules,
		customLines,
		overrideSecLang,
	)

	// 5. 计算防护规则库在本策略下的生效清单
	rawRows, err := h.store.listWafRulesForContent(ctx)
	if err != nil {
		response.InternalError(w, r, fmt.Errorf("load waf rules: %w", err))
		return
	}

	resp := h.buildPolicyContentResponse(policy, directives, policyOverrides, customItems, globalExItems, disabledSet, rawRows, filter)
	response.JSON(w, r, http.StatusOK, resp)
}

func (h *Handler) buildPolicyContentResponse(
	policy *Policy,
	directives string,
	overrides []PolicyOverrideItem,
	customItems []PolicyCustomRuleItem,
	globalExItems []PolicyExceptionItem,
	disabledSet map[int]bool,
	rawRows []rawWafRuleRow,
	filter ContentFilter,
) PolicyContentResponse {
	summary := PolicyContentSummary{
		TotalRules:            len(rawRows),
		CustomRulesCount:      len(customItems),
		GlobalExceptionsCount: len(globalExItems),
		OverridesCount:        len(overrides),
	}

	type matchedRuleEntry struct {
		item PolicyEffectiveRuleItem
		row  rawWafRuleRow
		tags []string
	}

	kw := strings.ToLower(filter.Keyword)
	matched := make([]matchedRuleEntry, 0, len(rawRows))
	for _, r := range rawRows {
		tags := wafrules.ParseTagsJSON(r.Tags)
		rulePL := ExtractRuleParanoiaLevel(tags, r.ParsedSpec)
		status := EvaluateRuleEffectiveStatus(policy.ProtectionMode, policy.ParanoiaLevel, rulePL, disabledSet[r.RuleID])
		switch status {
		case RuleStatusActive:
			summary.ActiveRules++
		case RuleStatusDisabledByOverride:
			summary.DisabledByOverride++
		case RuleStatusSkippedByPL:
			summary.SkippedByPL++
		case RuleStatusModeOff:
			summary.ModeOffRules++
		}

		name := wafrules.LocalizeRule(r.RuleID, r.FileName, r.Name)
		if filter.AttackType != "" && r.AttackType != filter.AttackType {
			continue
		}
		if filter.EffectiveStatus != "" && status != filter.EffectiveStatus {
			continue
		}
		if kw != "" {
			if !strings.Contains(strconv.Itoa(r.RuleID), kw) &&
				!strings.Contains(strings.ToLower(name), kw) &&
				!strings.Contains(strings.ToLower(r.FileName), kw) &&
				!strings.Contains(strings.ToLower(r.OvSummary), kw) {
				continue
			}
		}
		matched = append(matched, matchedRuleEntry{
			item: PolicyEffectiveRuleItem{
				RuleID:          r.RuleID,
				Name:            name,
				AttackType:      r.AttackType,
				Severity:        r.Severity,
				Phase:           r.Phase,
				RuleSource:      r.RuleSource,
				FileName:        r.FileName,
				ParanoiaLevel:   rulePL,
				EffectiveStatus: status,
				RawRule:         r.RawRule,
			},
			row:  r,
			tags: tags,
		})
	}

	sort.Slice(matched, func(i, j int) bool { return matched[i].item.RuleID < matched[j].item.RuleID })

	total := len(matched)
	start := (filter.Page - 1) * filter.PageSize
	if start > total {
		start = total
	}
	end := start + filter.PageSize
	if end > total {
		end = total
	}
	pageSlice := matched[start:end]
	pageItems := make([]PolicyEffectiveRuleItem, len(pageSlice))

	// 仅对当前分页生成结构化中文说明，并按需回源补齐缺失的 raw_rule
	for i, entry := range pageSlice {
		item := entry.item
		if strings.TrimSpace(item.RawRule) == "" {
			item.RawRule = h.lookupRawRule(item.RuleID, item.RuleSource, item.FileName)
		}
		var customOv *wafrules.RuleDescriptionOverride
		ov := &wafrules.RuleDescriptionOverride{
			Summary:        entry.row.OvSummary,
			DetectionLogic: entry.row.OvLogic,
			RiskImpact:     entry.row.OvRisk,
			TuningAdvice:   entry.row.OvTuning,
			UpdatedByName:  entry.row.OvUpdatedBy,
			UpdatedAt:      entry.row.OvUpdatedAt,
		}
		if ov.HasAnyContent() {
			customOv = ov
		}
		msg := wafrules.LocalizeRule(entry.row.RuleID, entry.row.FileName, entry.row.Message)
		detail := wafrules.DescribeRule(wafrules.RuleDescribeInput{
			RuleID:         entry.row.RuleID,
			RuleSource:     entry.row.RuleSource,
			FileName:       entry.row.FileName,
			Name:           item.Name,
			Message:        msg,
			Severity:       entry.row.Severity,
			Phase:          entry.row.Phase,
			AttackType:     entry.row.AttackType,
			DefaultState:   entry.row.DefaultState,
			CRSVersion:     entry.row.CRSVersion,
			Tags:           entry.tags,
			ParsedSpec:     json.RawMessage(entry.row.ParsedSpec),
			CustomOverride: customOv,
		})
		item.Description = detail.Summary
		item.Detail = &detail
		pageItems[i] = item
	}

	return PolicyContentResponse{
		PolicyID:            policy.ID,
		PolicyCode:          policy.Code,
		PolicyName:          policy.Name,
		ProtectionMode:      policy.ProtectionMode,
		SecRuleEngine:       secRuleEngineForMode(policy.ProtectionMode),
		ParanoiaLevel:       policy.ParanoiaLevel,
		InboundThreshold:    policy.InboundAnomalyThreshold,
		OutboundThreshold:   policy.OutboundAnomalyThreshold,
		GeneratedDirectives: directives,
		LoadedRuleFiles:     defaultLoadedRuleFiles(),
		Summary:             summary,
		Overrides:           overrides,
		CustomRules:         customItems,
		GlobalExceptions:    globalExItems,
		Rules:               pageItems,
		RulesTotal:          total,
		Page:                filter.Page,
		PageSize:            filter.PageSize,
	}
}

func (h *Handler) lookupRawRule(ruleID int, source, fileName string) string {
	h.rawCacheMu.RLock()
	if h.rawCacheLoaded {
		raw := h.rawCacheByKey[source+"|"+fileName+"|"+strconv.Itoa(ruleID)]
		if raw == "" {
			raw = h.rawCacheByID[ruleID]
		}
		h.rawCacheMu.RUnlock()
		return raw
	}
	h.rawCacheMu.RUnlock()

	h.rawCacheMu.Lock()
	defer h.rawCacheMu.Unlock()
	if !h.rawCacheLoaded {
		h.rawCacheByKey, h.rawCacheByID = wafrules.LoadRawRuleIndex(wafrules.BuildSyncSources(h.crsDir))
		h.rawCacheLoaded = true
	}
	raw := h.rawCacheByKey[source+"|"+fileName+"|"+strconv.Itoa(ruleID)]
	if raw == "" {
		raw = h.rawCacheByID[ruleID]
	}
	return raw
}
