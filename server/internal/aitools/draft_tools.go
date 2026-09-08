// draft_tools.go 草稿 Tool：例外/黑名单/CC策略/自定义规则/报告总结。
// 所有草稿：默认 DRAFT/停用状态、标记 AI 生成、记录来源会话/任务/证据，进入既有人工校验发布流程。
// M-23：创建一律走与人机相同的 ValidateInput / Store.Create 路径，created_by 取自调用方 Principal。
package aitools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/customrules"
	"github.com/jiuzhang-waf/server/internal/exceptions"
	"github.com/jiuzhang-waf/server/internal/ratelimitpolicies"
)

// DraftStore 草稿落库仓储。
type DraftStore struct {
	db *pgxpool.Pool
}

// NewDraftStore 创建草稿仓储。
func NewDraftStore(db *pgxpool.Pool) *DraftStore {
	return &DraftStore{db: db}
}

// RecordRecommendation 记录 AI 推荐/草稿（ai_recommendations）。
func (s *DraftStore) RecordRecommendation(ctx context.Context, taskID *uuid.UUID, recType, targetType, targetID, summary, risk, draftRef string, evidence []string) (uuid.UUID, error) {
	id := uuid.New()
	evJSON, _ := json.Marshal(evidence)
	_, err := s.db.Exec(ctx, `
INSERT INTO ai_recommendations (id, task_id, recommendation_type, target_type, target_id,
  summary, evidence_references, risk_level, status, draft_reference, created_by_ai)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'DRAFT',$9,TRUE)`,
		id, taskID, recType, targetType, targetID, summary, evJSON, risk, draftRef)
	return id, err
}

// ---------- 例外草稿 ----------

type draftException struct {
	baseTool
	exStore *exceptions.Store
	draft   *DraftStore
}

// NewDraftTools 注册草稿 Tool 组（复用各业务 Store 的完整校验）。
func NewDraftTools(r *Registry, db *pgxpool.Pool, exStore *exceptions.Store, protected accessrules.ProtectedChecker) {
	d := NewDraftStore(db)
	accessStore := accessrules.NewStore(db)
	rateStore := ratelimitpolicies.NewStore(db)
	customStore := customrules.NewStore(db)
	if exStore == nil {
		exStore = exceptions.NewStore(db)
	}
	r.Register(&draftException{baseTool: baseTool{meta: toolMeta{
		code: "draft.exception.create", name: "例外策略草稿", version: "1.1",
		description: "生成精确范围的例外策略草稿（默认停用，需人工审核发布）",
		risk:        RiskDraftOnly, permission: "ai.draft.exception", timeout: 15, maxResults: 1,
		schema: obj(map[string]interface{}{
			"task_id":        sch("string", "来源任务ID（可选）"),
			"name":           sch("string", "例外名称"),
			"scope_type":     sch("string", "APPLICATION/GLOBAL"),
			"application_id": sch("string", "应用ID（APPLICATION 必填）"),
			"domain":         sch("string", "域名（推荐精确）"),
			"uri_prefix":     sch("string", "URI 前缀（推荐精确）"),
			"uri_exact":      sch("string", "URI 精确（可选）"),
			"rule_ids":       sch("array", "规则ID列表（推荐精确）"),
			"param_names":    sch("array", "参数名列表（可选）"),
			"attack_types":   sch("array", "攻击类型列表"),
			"is_temporary":   sch("boolean", "是否临时"),
			"duration_hours": sch("integer", "有效小时数（临时时必填，≤720）"),
			"reason":         sch("string", "原因"),
			"evidence":       sch("array", "证据引用列表"),
		})}}, exStore: exStore, draft: d})
	r.Register(&draftBlacklist{baseTool: baseTool{meta: toolMeta{
		code: "draft.blacklist.create", name: "黑名单草稿", version: "1.1",
		description: "生成IP黑名单草稿（默认 DRAFT 状态，需人工审核发布）",
		risk:        RiskDraftOnly, permission: "ai.draft.blacklist", timeout: 15, maxResults: 1,
		schema: obj(map[string]interface{}{
			"task_id":        sch("string", "来源任务ID（可选）"),
			"name":           sch("string", "规则名称"),
			"scope_type":     sch("string", "GLOBAL/APPLICATION"),
			"application_id": sch("string", "应用ID（APPLICATION 必填）"),
			"address":        sch("string", "IP 或 CIDR"),
			"duration_hours": sch("integer", "有效小时数（默认 24，≤720）"),
			"reason":         sch("string", "原因"),
			"evidence":       sch("array", "证据引用列表"),
		})}}, access: accessStore, draft: d, protected: protected})
	r.Register(&draftCCPolicy{baseTool: baseTool{meta: toolMeta{
		code: "draft.cc_policy.create", name: "CC策略草稿", version: "1.1",
		description: "生成CC防护策略草稿（默认停用，需人工审核发布）",
		risk:        RiskDraftOnly, permission: "ai.draft.cc_policy", timeout: 15, maxResults: 1,
		schema: obj(map[string]interface{}{
			"task_id":                sch("string", "来源任务ID（可选）"),
			"name":                   sch("string", "策略名称"),
			"scope_type":             sch("string", "GLOBAL/APPLICATION/URI"),
			"application_id":         sch("string", "应用ID（非 GLOBAL 必填）"),
			"uri_match_type":         sch("string", "ALL/EXACT/PREFIX"),
			"uri_pattern":            sch("string", "URI 模式"),
			"dimension":              sch("string", "CLIENT_IP/APPLICATION/CLIENT_IP_AND_URI/CLIENT_IP_AND_APPLICATION"),
			"algorithm":              sch("string", "TOKEN_BUCKET/SLIDING_WINDOW"),
			"requests_limit":         sch("integer", "限次"),
			"window_seconds":         sch("integer", "窗口秒"),
			"burst_capacity":         sch("integer", "突发容量（可选）"),
			"action":                 sch("string", "OBSERVE/REJECT/TEMP_BLOCK"),
			"block_duration_seconds": sch("integer", "封禁秒数（TEMP_BLOCK 必填）"),
			"reason":                 sch("string", "原因"),
			"evidence":               sch("array", "证据引用列表"),
		})}}, rate: rateStore, draft: d})
	r.Register(&draftCustomRule{baseTool: baseTool{meta: toolMeta{
		code: "draft.custom_rule.create", name: "自定义规则草稿", version: "1.1",
		description: "生成自定义WAF规则草稿（默认停用，需人工审核发布）",
		risk:        RiskDraftOnly, permission: "ai.draft.custom_rule", timeout: 15, maxResults: 1,
		schema: obj(map[string]interface{}{
			"task_id":          sch("string", "来源任务ID（可选）"),
			"name":             sch("string", "规则名称"),
			"rule_id":          sch("integer", "规则ID（7100000-7199999）"),
			"attack_type":      sch("string", "攻击类型"),
			"severity":         sch("string", "CRITICAL/ERROR/WARNING/NOTICE"),
			"phase":            sch("integer", "阶段 1/2"),
			"operator":         sch("string", "操作符（白名单）"),
			"operator_value":   sch("string", "匹配内容"),
			"target_variables": sch("array", "检测变量列表"),
			"action":           sch("string", "LOG/OBSERVE/BLOCK"),
			"reason":           sch("string", "原因"),
			"evidence":         sch("array", "证据引用列表"),
		})}}, custom: customStore, draft: d})
	r.Register(&draftReportSummary{baseTool: baseTool{meta: toolMeta{
		code: "draft.report_summary.create", name: "报告总结草稿", version: "1.0",
		description: "登记 AI 报告总结草稿（与固定模板报告分开保存，标记 AI 辅助生成）",
		risk:        RiskDraftOnly, permission: "ai.report_summary.use", timeout: 15, maxResults: 1,
		schema: obj(map[string]interface{}{
			"task_id":  sch("string", "来源任务ID（可选）"),
			"summary":  sch("string", "总结正文"),
			"period":   sch("string", "报告周期说明"),
			"evidence": sch("array", "证据引用列表"),
		})}}, draft: d})
}

func parseTaskID(m map[string]interface{}) *uuid.UUID {
	if s := StrField(m, "task_id", 64); s != "" {
		if id, err := uuid.Parse(s); err == nil {
			return &id
		}
	}
	return nil
}

func evidenceList(m map[string]interface{}) []string {
	out := []string{}
	if raw, ok := m["evidence"].([]interface{}); ok {
		for _, e := range raw {
			if s, ok := e.(string); ok && len(s) <= 200 {
				out = append(out, s)
			}
		}
	}
	return out
}

func (t *draftException) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	name := StrField(m, "name", 200)
	if name == "" {
		return nil, fmt.Errorf("%w: name required", ErrInvalidInput)
	}
	scope := StrField(m, "scope_type", 20)
	if scope == "" {
		scope = "APPLICATION"
	}
	e := &exceptions.Exception{
		Name:      "[AI草稿] " + name,
		ScopeType: scope,
		Status:    "DISABLED", // 草稿默认停用，需人工审核启用
		Reason:    StrField(m, "reason", 500),
	}
	if e.Reason == "" {
		e.Reason = "AI 生成的例外策略草稿，需人工审核"
	}
	if v := StrField(m, "application_id", 64); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid application_id", ErrInvalidInput)
		}
		e.ApplicationID = &id
	}
	if scope == "APPLICATION" && e.ApplicationID == nil {
		return nil, fmt.Errorf("%w: application_id required for APPLICATION scope", ErrInvalidInput)
	}
	e.Domain = StrField(m, "domain", 255)
	e.URIPrefix = StrField(m, "uri_prefix", 255)
	e.URIExact = StrField(m, "uri_exact", 255)
	e.RuleIDs = intList(m, "rule_ids")
	e.ParamNames = strList(m, "param_names")
	e.AttackTypes = strList(m, "attack_types")
	e.ExceptionAction = "REMOVE_RULE"
	if e.IsBroad() {
		return nil, fmt.Errorf("%w: 草稿必须为精确例外（需指定 应用/域名/URI/规则ID/参数 之一）", ErrInvalidInput)
	}
	e.IsTemporary = BoolField(m, "is_temporary")
	if e.IsTemporary {
		h := IntField(m, "duration_hours", 0)
		if h <= 0 || h > 720 {
			return nil, fmt.Errorf("%w: duration_hours must be 1-720 for temporary exception", ErrInvalidInput)
		}
		until := time.Now().Add(time.Duration(h) * time.Hour).UTC()
		e.EffectiveUntil = &until
	}
	// 与人机创建相同：exceptions.ValidateInput + Store.Create
	if err := exceptions.ValidateInput(e); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	if err := t.exStore.Create(ctx, e, CreatorID(ctx)); err != nil {
		return nil, fmt.Errorf("create exception draft: %w", err)
	}
	ev := evidenceList(m)
	draftRef := "exception:" + e.ID.String()
	recID, err := t.draft.RecordRecommendation(ctx, parseTaskID(m), "EXCEPTION", scope, v_or(e.ApplicationID),
		"例外草稿："+name, "MEDIUM", draftRef, ev)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"draft_id": draftRef, "recommendation_id": recID, "status": "DRAFT",
		"message": "例外草稿已生成（默认停用），请在例外策略页面人工审核后启用",
	}, nil
}

func v_or(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func intList(m map[string]interface{}, key string) []int {
	out := []int{}
	if raw, ok := m[key].([]interface{}); ok {
		for _, e := range raw {
			if f, ok := e.(float64); ok && f > 0 && f < 100000000 {
				out = append(out, int(f))
			}
		}
	}
	return out
}

func strList(m map[string]interface{}, key string) []string {
	out := []string{}
	if raw, ok := m[key].([]interface{}); ok {
		for _, e := range raw {
			if s, ok := e.(string); ok && len(s) <= 200 {
				out = append(out, s)
			}
		}
	}
	return out
}

// ---------- 黑名单草稿 ----------

type draftBlacklist struct {
	baseTool
	access    *accessrules.Store
	draft     *DraftStore
	protected accessrules.ProtectedChecker
}

func (t *draftBlacklist) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	name := StrField(m, "name", 200)
	if name == "" {
		return nil, fmt.Errorf("%w: name required", ErrInvalidInput)
	}
	addr := StrField(m, "address", 64)
	hours := IntField(m, "duration_hours", 24)
	if hours <= 0 || hours > 720 {
		return nil, fmt.Errorf("%w: duration_hours must be 1-720", ErrInvalidInput)
	}
	var appID *uuid.UUID
	if v := StrField(m, "application_id", 64); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid application_id", ErrInvalidInput)
		}
		appID = &id
	}
	scope := StrField(m, "scope_type", 20)
	if scope == "" {
		scope = accessrules.ScopeGlobal
	}
	reason := StrField(m, "reason", 500)
	if reason == "" {
		reason = "AI 生成的黑名单草稿，需人工审核"
	}
	until := time.Now().Add(time.Duration(hours) * time.Hour).UTC()
	in := accessrules.CreateInput{
		Name:           "[AI草稿] " + name,
		RuleType:       accessrules.RuleTypeDeny,
		ScopeType:      scope,
		ApplicationID:  appID,
		Address:        addr,
		ValidityType:   accessrules.ValidityTemporary,
		EffectiveUntil: &until,
		Reason:         reason,
		SourceType:     accessrules.SourceManual,
	}
	// 与人机相同：ValidateInput + 保护地址检查
	if err := accessrules.ValidateInput(&in, time.Now()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	norm, _, _ := accessrules.NormalizeAddress(in.Address)
	if t.protected != nil {
		if err := accessrules.CheckProtected(ctx, t.protected, accessrules.RuleTypeDeny, norm); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
		}
	}
	rule, err := t.access.CreateDraft(ctx, in, CreatorID(ctx))
	if err != nil {
		return nil, fmt.Errorf("create blacklist draft: %w", err)
	}
	ev := evidenceList(m)
	draftRef := "access_rule:" + rule.ID.String()
	recID, err := t.draft.RecordRecommendation(ctx, parseTaskID(m), "BLACKLIST", scope, v_or(appID),
		"黑名单草稿："+name+"（"+rule.Address+"，"+fmt.Sprint(hours)+"小时）", "HIGH", draftRef, ev)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"draft_id": draftRef, "recommendation_id": recID, "status": "DRAFT",
		"message": "黑名单草稿已生成（DRAFT 状态），请在 IP黑白名单页面人工审核后启用",
	}, nil
}

// ---------- CC 策略草稿 ----------

type draftCCPolicy struct {
	baseTool
	rate  *ratelimitpolicies.Store
	draft *DraftStore
}

func (t *draftCCPolicy) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	name := StrField(m, "name", 200)
	if name == "" {
		return nil, fmt.Errorf("%w: name required", ErrInvalidInput)
	}
	scope := StrField(m, "scope_type", 15)
	if scope == "" {
		scope = ratelimitpolicies.ScopeApplication
	}
	var appID *uuid.UUID
	if v := StrField(m, "application_id", 64); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid application_id", ErrInvalidInput)
		}
		appID = &id
	}
	dimension := StrField(m, "dimension", 30)
	algo := StrField(m, "algorithm", 20)
	if algo == "" {
		algo = ratelimitpolicies.AlgorithmTokenBucket
	}
	action := StrField(m, "action", 15)
	if action == "" {
		action = ratelimitpolicies.ActionObserve
	}
	uriMatch := StrField(m, "uri_match_type", 10)
	if uriMatch == "" {
		uriMatch = ratelimitpolicies.URIMatchAll
	}
	reason := StrField(m, "reason", 500)
	p := &ratelimitpolicies.Policy{
		Name:                 "[AI草稿] " + name,
		Description:          reason,
		ScopeType:            scope,
		ApplicationID:        appID,
		URIMatchType:         uriMatch,
		URIPattern:           StrField(m, "uri_pattern", 256),
		Dimension:            dimension,
		Algorithm:            algo,
		RequestsLimit:        IntField(m, "requests_limit", 0),
		WindowSeconds:        IntField(m, "window_seconds", 0),
		BurstCapacity:        IntField(m, "burst_capacity", 0),
		Action:               action,
		BlockDurationSeconds: IntField(m, "block_duration_seconds", 0),
		Status:               ratelimitpolicies.StatusDisabled,
		ObserveOnly:          action == ratelimitpolicies.ActionObserve,
		Priority:             100,
	}
	// 与人机相同：ValidateInput + Store.Create
	if errs := ratelimitpolicies.ValidateInput(p); len(errs) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrInvalidInput, errs[0].Message)
	}
	if err := t.rate.Create(ctx, p, CreatorID(ctx)); err != nil {
		return nil, fmt.Errorf("create cc policy draft: %w", err)
	}
	ev := evidenceList(m)
	draftRef := "rate_limit_policy:" + p.ID.String()
	recID, err := t.draft.RecordRecommendation(ctx, parseTaskID(m), "CC_POLICY", scope, v_or(appID),
		fmt.Sprintf("CC策略草稿：%s（%d次/%ds，%s）", name, p.RequestsLimit, p.WindowSeconds, action), "MEDIUM", draftRef, ev)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"draft_id": draftRef, "recommendation_id": recID, "status": "DRAFT",
		"message": "CC策略草稿已生成（默认停用），请在 CC防护页面人工审核后启用",
	}, nil
}

// ---------- 自定义规则草稿 ----------

type draftCustomRule struct {
	baseTool
	custom *customrules.Store
	draft  *DraftStore
}

func (t *draftCustomRule) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	name := StrField(m, "name", 200)
	rid := IntField(m, "rule_id", 0)
	if name == "" || rid < 7100000 || rid > 7199999 {
		return nil, fmt.Errorf("%w: name required and rule_id must be 7100000-7199999", ErrInvalidInput)
	}
	rule := &customrules.CustomRule{
		RuleID:          rid,
		Name:            "[AI草稿] " + name,
		Description:     StrField(m, "reason", 500),
		AttackType:      StrField(m, "attack_type", 40),
		Severity:        StrField(m, "severity", 10),
		Phase:           IntField(m, "phase", 2),
		Operator:        StrField(m, "operator", 30),
		OperatorValue:   StrField(m, "operator_value", 512),
		TargetVariables: strList(m, "target_variables"),
		Action:          StrField(m, "action", 10),
		Status:          "DISABLED",
		ScopeType:       "GLOBAL",
		Tags:            []string{"jiuzhang", "custom", "ai-draft"},
	}
	if rule.AttackType == "" {
		rule.AttackType = "OTHER"
	}
	if rule.Severity == "" {
		rule.Severity = "WARNING"
	}
	if rule.Action == "" {
		rule.Action = "OBSERVE"
	}
	// 与人机相同：ValidateInput + Store.Create（Create 内部再次 ValidateInput）
	if _, err := customrules.ValidateInput(rule); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	if err := t.custom.Create(ctx, rule, CreatorID(ctx)); err != nil {
		return nil, fmt.Errorf("create custom rule draft: %w", err)
	}
	ev := evidenceList(m)
	draftRef := "custom_rule:" + rule.ID.String()
	recID, err := t.draft.RecordRecommendation(ctx, parseTaskID(m), "CUSTOM_RULE", "GLOBAL", "",
		fmt.Sprintf("自定义规则草稿：%s（%d）", name, rid), "HIGH", draftRef, ev)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"draft_id": draftRef, "recommendation_id": recID, "status": "DRAFT",
		"message": "自定义规则草稿已生成（默认停用），请在自定义规则页面人工审核后启用",
	}, nil
}

// ---------- 报告总结草稿 ----------

type draftReportSummary struct {
	baseTool
	draft *DraftStore
}

func (t *draftReportSummary) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	summary := StrField(m, "summary", 8000)
	if len(summary) < 20 {
		return nil, fmt.Errorf("%w: summary too short", ErrInvalidInput)
	}
	period := StrField(m, "period", 100)
	label := summary
	if period != "" {
		label = period + "：" + summary
		if len(label) > 500 {
			label = label[:500]
		}
	}
	recID, err := t.draft.RecordRecommendation(ctx, parseTaskID(m), "REPORT_SUMMARY", "REPORT", "",
		label, "LOW", "ai_summary:"+uuid.NewString(), evidenceList(m))
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"recommendation_id": recID, "status": "DRAFT", "ai_assisted": true,
		"message": "AI 报告总结草稿已登记（AI辅助生成，可人工编辑）",
	}, nil
}
