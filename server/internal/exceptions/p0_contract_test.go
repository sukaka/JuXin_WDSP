// p0_contract_test.go WDSP P0-04 例外契约回归测试（S4_DESIGN_BASELINE.md §3/§4/§5/§9）。
// 覆盖任务书 §2.2 七条缺陷的修复证据：
//  1. 全维度 AND 条件链（Host/路径/方法/IP/Content-Type/时间每维一个链环，不再择一）；
//  2. Methods/SourceIPs/ContentTypes/CookieNames/HeaderNames 全部进入编译产物；
//  3. LOG_ONLY/ADJUST_SCORE 编译层直接报错，绝不生成 ctl:ruleEngine=DetectionOnly；
//  4. 两规则标记法：marker 仅 setvar（末环）+ nolog，effect 携带全部 ctl 与审计 tag；
//  5. 无任何条件维度的输入拒绝编译（旧版退化为 @rx .* 全匹配）；
//  6. 启用门禁双层校验（ValidateForEnable）与保存层字段级错误（ValidateInput）；
//  7. 事件草稿不再用 IsBroad 自动勾选 RiskAcknowledged（见 fromevent 测试）。
package exceptions

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// p0Exception 构造满足启用门禁的合法例外（全维度配置）。
func p0Exception() *Exception {
	from := time.Unix(1700000000, 0).UTC()
	until := time.Unix(1700003600, 0).UTC()
	return &Exception{
		ID:               uuid.MustParse("11111111-2222-3333-4444-555555555555"),
		Name:             "P0契约例外",
		ScopeType:        "APPLICATION",
		ApplicationID:    ptrUUID(uuid.New()),
		Domain:           "example.com",
		URIExact:         "/api/orders",
		Methods:          []string{"POST", "GET"},
		SourceIPs:        []string{"10.0.0.0/8", "192.168.1.7"},
		ContentTypes:     []string{"application/x-www-form-urlencoded"},
		ParamNames:       []string{"comment"},
		RuleIDs:          []int{942100},
		ExceptionAction:  ActionRemoveRule,
		IsTemporary:      true,
		EffectiveFrom:    &from,
		EffectiveUntil:   &until,
		Status:           "DRAFT",
		ValidationStatus: ValidationValid,
		Version:          2,
	}
}

func ptrUUID(id uuid.UUID) *uuid.UUID { return &id }

// ---------- §5 编译模板（两规则标记法） ----------

func TestP0CompileFullChainTwoRuleMarker(t *testing.T) {
	e := p0Exception()
	gen, err := GenerateSecLang(e, 8000001)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	lines := strings.Split(gen, "\n")

	// 标记规则链首：Host 条件 + id/pass/nolog/chain，绝不带 ctl
	if !strings.HasPrefix(lines[0], `SecRule REQUEST_HEADERS:Host "@rx (?i)^example\.com(?::\d+)?$" "id:8000001,phase:1,pass,nolog,chain"`) {
		t.Errorf("marker head wrong: %s", lines[0])
	}
	joined := strings.Join(lines[:len(lines)-1], "\n") // 标记规则整体（末行是效果规则）
	if strings.Contains(joined, "ctl:") {
		t.Errorf("marker rule must not carry ctl actions: %s", joined)
	}
	// 各维度链环齐备（旧实现只取 URI/Domain 之一，忽略 Methods/SourceIPs/ContentTypes）
	for _, want := range []string{
		`SecRule REQUEST_FILENAME "@streq /api/orders" "chain"`,
		`SecRule REQUEST_METHOD "@pm GET POST" "chain"`,
		`SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8,192.168.1.7" "chain"`,
		`SecRule REQUEST_HEADERS:Content-Type "@rx ^application/x-www-form-urlencoded(?:[;]|$)" "chain"`,
		`SecRule TIME_EPOCH "@ge 1700000000" "chain"`,
	} {
		if !strings.Contains(gen, want) {
			t.Errorf("missing chain link %q in:\n%s", want, gen)
		}
	}
	// 末环：时间 lt + setvar 打标（setvar 只能写在末环）
	if !strings.Contains(gen, `SecRule TIME_EPOCH "@lt 1700003600" "setvar:tx.jz_exc_8000001=1"`) {
		t.Errorf("last link must carry setvar marker: %s", gen)
	}
	// 效果规则：effect ID = marker+1，TX 标记单条件，携带全部 ctl 与审计 tag，log 而非 nolog
	last := lines[len(lines)-1]
	wantEffect := `SecRule TX:jz_exc_8000001 "@eq 1" "id:8000002,phase:1,pass,log,` +
		`tag:'jiuzhang-exception',tag:'exc:11111111-2222-3333-4444-555555555555',tag:'excv:2',` +
		`ctl:ruleRemoveTargetById=942100;ARGS:comment"`
	if last != wantEffect {
		t.Errorf("effect rule mismatch:\n got: %s\nwant: %s", last, wantEffect)
	}
}

func TestP0CompileOnlyConfiguredDimensions(t *testing.T) {
	// 仅路径+方法：无 Host/IP/CT/时间链环
	e := p0Exception()
	e.Domain = ""
	e.SourceIPs = nil
	e.ContentTypes = nil
	e.EffectiveFrom = nil
	e.EffectiveUntil = nil
	e.IsTemporary = false
	gen, err := GenerateSecLang(e, 8000003)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if strings.Contains(gen, "REQUEST_HEADERS:Host") || strings.Contains(gen, "REMOTE_ADDR") ||
		strings.Contains(gen, "Content-Type") || strings.Contains(gen, "TIME_EPOCH") {
		t.Errorf("unconfigured dimensions must not emit chain links:\n%s", gen)
	}
	// 首环为 REQUEST_FILENAME（携带 id），末环方法携带 setvar
	if !strings.HasPrefix(gen, `SecRule REQUEST_FILENAME "@streq /api/orders" "id:8000003,phase:1,pass,nolog,chain"`) {
		t.Errorf("first link should carry id when no Host: %s", gen)
	}
	if !strings.Contains(gen, `SecRule REQUEST_METHOD "@pm GET POST" "setvar:tx.jz_exc_8000003=1"`) {
		t.Errorf("last link must carry setvar: %s", gen)
	}
	if !strings.Contains(gen, `"id:8000004,`) {
		t.Errorf("effect rule id = marker+1: %s", gen)
	}
}

func TestP0CompilePrefixSegmentBoundary(t *testing.T) {
	e := p0Exception()
	e.URIExact = ""
	e.URIPrefix = "/api"
	e.Domain = ""
	e.Methods = nil // 编译层容忍（启用门禁拦截），便于隔离观察模板
	e.SourceIPs, e.ContentTypes, e.ParamNames = nil, nil, nil
	e.EffectiveFrom, e.EffectiveUntil, e.IsTemporary = nil, nil, false
	e.ExceptionAction = ActionRemoveRule
	gen, err := GenerateSecLang(e, 8000001)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(gen, `SecRule REQUEST_FILENAME "@rx ^/api(?:/|$)"`) {
		t.Errorf("prefix must be segment-boundary regex: %s", gen)
	}
	if strings.Contains(gen, "beginsWith") {
		t.Errorf("beginsWith has no segment boundary: %s", gen)
	}
}

func TestP0CompileRejectsNoCondition(t *testing.T) {
	// 旧实现全空条件退化为 REQUEST_URI @rx .*（全局摘除规则）；新实现必须拒绝编译
	e := &Exception{
		ID: uuid.New(), Name: "无条件", ExceptionAction: ActionRemoveRule,
		RuleIDs: []int{942100}, Version: 1,
	}
	if _, err := GenerateSecLang(e, 8000001); err == nil {
		t.Fatal("compile without any condition dimension must be rejected")
	}
}

func TestP0CompileUnsupportedActionsNeverDetectionOnly(t *testing.T) {
	for _, action := range []string{ActionLogOnly, ActionAdjustScore} {
		e := p0Exception()
		e.ExceptionAction = action
		gen, err := GenerateSecLang(e, 8000001)
		if err == nil {
			t.Fatalf("%s must fail at compile layer", action)
		}
		if strings.Contains(gen, "DetectionOnly") {
			t.Fatalf("%s must never produce DetectionOnly: %s", action, gen)
		}
	}
}

func TestP0CompileAPIEngineNotSecLang(t *testing.T) {
	e := p0Exception()
	e.TargetEngine = EngineAPI
	e.ExceptionAction = ActionObserveRule
	e.APIRuleRefs = []APIRuleRef{{DetectorID: "api_schema", RuleID: "body.name"}}
	if _, err := GenerateSecLang(e, 8000001); err == nil {
		t.Fatal("API engine exception must not compile to SecLang (distributed via api_exceptions section)")
	}
}

func TestP0CompileTargetNameMapping(t *testing.T) {
	e := p0Exception()
	e.ParamNames = []string{"comment"}
	e.CookieNames = []string{"session_id"}
	e.HeaderNames = []string{"x-custom-header"}
	gen, err := GenerateSecLang(e, 8000001)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, want := range []string{
		"ctl:ruleRemoveTargetById=942100;ARGS:comment",
		"ctl:ruleRemoveTargetById=942100;REQUEST_COOKIES:session_id",
		"ctl:ruleRemoveTargetById=942100;REQUEST_HEADERS:X-CUSTOM-HEADER", // Header 名统一大写
	} {
		if !strings.Contains(gen, want) {
			t.Errorf("missing ctl target %q:\n%s", want, gen)
		}
	}
}

func TestP0CompileRemoveRuleWithoutTargets(t *testing.T) {
	e := p0Exception()
	e.ParamNames = nil
	gen, err := GenerateSecLang(e, 8000001)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(gen, "ctl:ruleRemoveById=942100") {
		t.Errorf("REMOVE_RULE without targets should use ruleRemoveById: %s", gen)
	}
	if strings.Contains(gen, "ruleRemoveTargetById") {
		t.Errorf("no targets configured, must not emit target-level ctl: %s", gen)
	}
}

func TestP0CompileRemoveVarDetectionRequiresBoth(t *testing.T) {
	e := p0Exception()
	e.ExceptionAction = ActionRemoveVarDetection
	// 目标名缺失 → 编译报错
	e.ParamNames = nil
	if _, err := GenerateSecLang(e, 8000001); err == nil {
		t.Fatal("REMOVE_VAR_DETECTION without target names must fail")
	}
	// 规则缺失 → 编译报错
	e = p0Exception()
	e.ExceptionAction = ActionRemoveVarDetection
	e.RuleIDs = nil
	if _, err := GenerateSecLang(e, 8000001); err == nil {
		t.Fatal("REMOVE_VAR_DETECTION without rule ids must fail")
	}
	// 齐备 → 规则×目标排除
	e = p0Exception()
	e.ExceptionAction = ActionRemoveVarDetection
	gen, err := GenerateSecLang(e, 8000001)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(gen, "ctl:ruleRemoveTargetById=942100;ARGS:comment") {
		t.Errorf("REMOVE_VAR_DETECTION should compile to target exclusion: %s", gen)
	}
}

func TestP0CompileRemoveRuleTagUsesFrozenIDs(t *testing.T) {
	e := p0Exception()
	e.ExceptionAction = ActionRemoveRuleTag
	e.RuleTags = []string{"attack-sqli"}
	e.RuleIDs = nil
	// 未冻结（未经过启用门禁展开）→ 拒绝编译
	e.ResolvedRuleIDs = nil
	if _, err := GenerateSecLang(e, 8000001); err == nil {
		t.Fatal("REMOVE_RULE_TAG without frozen resolved_rule_ids must fail")
	}
	// 冻结集逐 ID ruleRemoveById（不再 ruleRemoveByTag——标签在发布侧已展开冻结）
	e.ResolvedRuleIDs = []int{942100, 941160}
	gen, err := GenerateSecLang(e, 8000001)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(gen, "ctl:ruleRemoveById=942100") || !strings.Contains(gen, "ctl:ruleRemoveById=941160") {
		t.Errorf("frozen ids must each compile to ruleRemoveById: %s", gen)
	}
	if strings.Contains(gen, "ruleRemoveByTag") {
		t.Errorf("tag removal must be expanded to frozen ids, not runtime ruleRemoveByTag: %s", gen)
	}
}

// EXC-09：SecLang 注入防护——目标名特殊字符剥离、URI 引号/反斜杠转义、控制字符剥离。
func TestP0CompileInjectionSafety(t *testing.T) {
	e := p0Exception()
	e.URIExact = `/api/x";"ctl:ruleEngine=Off`
	gen, err := GenerateSecLang(e, 8000001)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if strings.Contains(gen, `x";"ctl`) {
		t.Errorf("quote injection must be escaped: %s", gen)
	}
	// 目标名注入：分号可拼接第二个 ctl 目标（ruleRemoveTargetById 的 ; 语义）——
	// escapeVar 剥离 ; 后只剩单个（变形）目标名，不得出现被拼接的第二目标
	e2 := p0Exception()
	e2.ParamNames = []string{"ok;ARGS:injected"}
	gen2, err := GenerateSecLang(e2, 8000001)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if strings.Contains(gen2, ";ARGS:injected") {
		t.Errorf("second ctl target must not be spliced: %s", gen2)
	}
	if !strings.Contains(gen2, "ARGS:ok") {
		t.Errorf("sanitized target name should remain: %s", gen2)
	}
	// 控制字符兜底剥离（历史脏数据）：换行被剥除后注入内容不得形成独立指令行
	e3 := p0Exception()
	e3.URIExact = "/api/ok\nSecAction \"ctl:ruleEngine=Off\""
	gen3, err := GenerateSecLang(e3, 8000001)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if strings.Contains(gen3, "\nSecAction") || strings.Contains(gen3, "ok\n") {
		t.Errorf("control-char line injection must be stripped: %s", gen3)
	}
	for i, line := range strings.Split(gen3, "\n") {
		if strings.HasPrefix(line, "SecAction") {
			t.Errorf("injected directive must not become a standalone line %d: %s", i, gen3)
		}
	}
}

// 单条件（仅路径）时首环即末环：携带 id 且 setvar 写在同一环，无 chain。
func TestP0CompileSingleConditionLink(t *testing.T) {
	e := p0Exception()
	e.Domain, e.Methods, e.SourceIPs, e.ContentTypes = "", nil, nil, nil
	e.EffectiveFrom, e.EffectiveUntil, e.IsTemporary = nil, nil, false
	e.ParamNames = nil
	gen, err := GenerateSecLang(e, 8000001)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(gen, `SecRule REQUEST_FILENAME "@streq /api/orders" "id:8000001,phase:1,pass,nolog,setvar:tx.jz_exc_8000001=1"`) {
		t.Errorf("single link must carry id and setvar, no chain: %s", gen)
	}
}

// ---------- §4 保存层校验 ----------

func p0SaveValid() *Exception {
	e := p0Exception()
	e.ID = uuid.Nil
	return e
}

func TestP0SaveRejectsMultipleURIForms(t *testing.T) {
	e := p0SaveValid()
	e.URIPrefix = "/api"
	err := ValidateInput(e)
	var verrs *ValidationErrors
	if !errors.As(err, &verrs) {
		t.Fatalf("want field errors, got %v", err)
	}
	if !verrs.HasField("uri_exact") {
		t.Errorf("uri_exact/uri_prefix 同时配置应报字段级错误: %v", verrs)
	}
}

func TestP0SaveMethodLimits(t *testing.T) {
	e := p0SaveValid()
	e.Methods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "get", "post", "put", "patch"}
	if err := ValidateInput(e); err == nil {
		t.Error(">10 methods should be rejected")
	}
	e.Methods = []string{"FLY"}
	if err := ValidateInput(e); err == nil {
		t.Error("non-standard method should be rejected")
	}
	e.Methods = []string{"get", "post"} // 大小写归一后合法
	if err := ValidateInput(e); err != nil {
		t.Errorf("lowercase standard methods should pass (normalized): %v", err)
	}
}

func TestP0SaveContentTypeMIME(t *testing.T) {
	e := p0SaveValid()
	e.ContentTypes = []string{"not a mime"}
	if err := ValidateInput(e); err == nil {
		t.Error("invalid MIME should be rejected")
	}
	e.ContentTypes = []string{"application/json; charset=utf-8"} // 参数分离后合法
	if err := ValidateInput(e); err != nil {
		t.Errorf("MIME with params should pass (main type used): %v", err)
	}
}

func TestP0SaveEngineActionMatrix(t *testing.T) {
	// API 引擎用 WAF 动作 → 字段级错误
	e := p0SaveValid()
	e.TargetEngine = EngineAPI
	e.RuleIDs = nil
	e.APIRuleRefs = []APIRuleRef{{DetectorID: "api_schema", RuleID: "body.name"}}
	if err := ValidateInput(e); err == nil {
		t.Error("API engine with WAF action REMOVE_RULE should be rejected")
	}
	// API 引擎 + OBSERVE_RULE → 合法
	e.ExceptionAction = ActionObserveRule
	e.ParamNames = nil
	if err := ValidateInput(e); err != nil {
		t.Errorf("API OBSERVE_RULE should pass: %v", err)
	}
	// WAF 引擎 + OBSERVE_RULE → 拒绝
	e2 := p0SaveValid()
	e2.ExceptionAction = ActionObserveRule
	if err := ValidateInput(e2); err == nil {
		t.Error("WAF engine with OBSERVE_RULE should be rejected")
	}
	// API 引擎 + 未注册 detector → 拒绝
	e3 := p0SaveValid()
	e3.TargetEngine = EngineAPI
	e3.ExceptionAction = ActionObserveRule
	e3.RuleIDs = nil
	e3.APIRuleRefs = []APIRuleRef{{DetectorID: "jwt_verify", RuleID: "x"}}
	if err := ValidateInput(e3); err == nil {
		t.Error("unregistered detector must be rejected (EXC-11)")
	}
	// API 引擎 + 空 rule_id → 拒绝
	e4 := p0SaveValid()
	e4.TargetEngine = EngineAPI
	e4.ExceptionAction = ActionObserveRule
	e4.RuleIDs = nil
	e4.ParamNames = nil
	e4.APIRuleRefs = []APIRuleRef{{DetectorID: "api_parser", RuleID: ""}}
	if err := ValidateInput(e4); err == nil {
		t.Error("API rule ref with empty rule_id should be rejected")
	}
}

func TestP0SaveAPIEngineRejectsWAFFields(t *testing.T) {
	e := p0SaveValid()
	e.TargetEngine = EngineAPI
	e.ExceptionAction = ActionObserveRule
	e.APIRuleRefs = []APIRuleRef{{DetectorID: "api_schema", RuleID: "body.name"}}
	// RuleIDs 残留（WAF 概念）→ 字段级错误，不得静默忽略
	if err := ValidateInput(e); err == nil {
		t.Error("API engine with rule_ids should be rejected")
	}
	e.RuleIDs = nil
	e.ParamNames = nil
	if err := ValidateInput(e); err != nil {
		t.Errorf("clean API exception should pass: %v", err)
	}
}

func TestP0SaveActionTargetDiscipline(t *testing.T) {
	// ActionTarget 仅允许作为 REMOVE_VAR_DETECTION 的目标集合别名，否则拒绝
	e := p0SaveValid()
	e.ActionTarget = "ARGS"
	if err := ValidateInput(e); err == nil {
		t.Error("action_target on REMOVE_RULE should be rejected")
	}
	e.ExceptionAction = ActionRemoveVarDetection
	e.ActionTarget = "ARGS:comment"
	if err := ValidateInput(e); err != nil {
		t.Errorf("action_target naming a declared target should pass: %v", err)
	}
	e.ActionTarget = "ARGS:undeclared"
	if err := ValidateInput(e); err == nil {
		t.Error("action_target referencing undeclared target should be rejected")
	}
	// 自由文本（自由拼接 SecLang 的通道）必须拒绝
	e.ActionTarget = `x" "ctl:ruleEngine=Off`
	if err := ValidateInput(e); err == nil {
		t.Error("free-text action_target must be rejected")
	}
}

func TestP0SaveTargetNameCharset(t *testing.T) {
	e := p0SaveValid()
	e.ParamNames = []string{"bad;name"}
	if err := ValidateInput(e); err == nil {
		t.Error("param name with ctl separator should be rejected at save layer")
	}
	e.ParamNames = []string{"content"}
	e.HeaderNames = []string{"X-Custom_1.5"}
	if err := ValidateInput(e); err != nil {
		t.Errorf("charset-clean names should pass: %v", err)
	}
}

// ---------- §4 启用门禁 ----------

func p0Hooks() EnableHooks {
	return EnableHooks{
		AppExists: func(context.Context, uuid.UUID) (bool, error) { return true, nil },
		ResolveRuleTags: func(_ context.Context, tags []string) (map[string][]int, error) {
			out := map[string][]int{}
			for _, tg := range tags {
				if tg == "attack-sqli" {
					out[tg] = []int{942100, 941160}
				}
			}
			return out, nil
		},
	}
}

func TestP0EnableGateHappyPath(t *testing.T) {
	plan, verrs := ValidateForEnable(context.Background(), p0Exception(), p0Hooks())
	if verrs != nil {
		t.Fatalf("valid exception blocked: %v", verrs)
	}
	if plan == nil || plan.CompiledFingerprint == "" {
		t.Fatal("plan must carry compiled fingerprint")
	}
}

func TestP0EnableGateNeedsReviewBlocked(t *testing.T) {
	e := p0Exception()
	e.ValidationStatus = ValidationNeedsReview
	if _, verrs := ValidateForEnable(context.Background(), e, p0Hooks()); verrs == nil {
		t.Fatal("NEEDS_REVIEW must be blocked from enabling")
	}
}

func TestP0EnableGateScopeAndApp(t *testing.T) {
	// GLOBAL 禁止启用
	e := p0Exception()
	e.ScopeType = "GLOBAL"
	if _, verrs := ValidateForEnable(context.Background(), e, p0Hooks()); verrs == nil {
		t.Error("GLOBAL scope must be blocked")
	}
	// 缺应用绑定
	e = p0Exception()
	e.ApplicationID = nil
	if _, verrs := ValidateForEnable(context.Background(), e, p0Hooks()); verrs == nil {
		t.Error("missing application_id must be blocked")
	}
	// 应用不存在
	hooks := p0Hooks()
	hooks.AppExists = func(context.Context, uuid.UUID) (bool, error) { return false, nil }
	if _, verrs := ValidateForEnable(context.Background(), p0Exception(), hooks); verrs == nil {
		t.Error("nonexistent application must be blocked")
	}
	// 查库失败 → 阻止启用（不静默放行）
	hooks.AppExists = func(context.Context, uuid.UUID) (bool, error) { return false, errors.New("db down") }
	if _, verrs := ValidateForEnable(context.Background(), p0Exception(), hooks); verrs == nil {
		t.Error("app existence check failure must block enabling")
	}
}

func TestP0EnableGateMethodsRequired(t *testing.T) {
	// 历史数据 Methods 为空：保存层兼容，启用层拒绝
	e := p0Exception()
	e.Methods = nil
	_, verrs := ValidateForEnable(context.Background(), e, p0Hooks())
	if verrs == nil || !verrs.HasField("methods") {
		t.Errorf("empty methods must be blocked at enable gate: %v", verrs)
	}
}

func TestP0EnableGateURIRules(t *testing.T) {
	// 三选一缺省 → 拒绝
	e := p0Exception()
	e.URIExact = ""
	_, verrs := ValidateForEnable(context.Background(), e, p0Hooks())
	if verrs == nil || !verrs.HasField("uri_exact") {
		t.Errorf("no URI condition must be blocked: %v", verrs)
	}
	// 裸 / 前缀 → 拒绝（任务书 §5.2 默认值）
	e = p0Exception()
	e.URIExact = ""
	e.URIPrefix = "/"
	if _, verrs := ValidateForEnable(context.Background(), e, p0Hooks()); verrs == nil {
		t.Error("bare / prefix must be blocked")
	}
	// 前缀不以 / 开头 → 拒绝
	e.URIPrefix = "api"
	if _, verrs := ValidateForEnable(context.Background(), e, p0Hooks()); verrs == nil {
		t.Error("prefix not starting with / must be blocked")
	}
	// URIRegex：需 risk_acknowledged + 可编译 + ≤512
	e = p0Exception()
	e.URIExact = ""
	e.URIRegex = "^/api/orders$"
	if _, verrs := ValidateForEnable(context.Background(), e, p0Hooks()); verrs == nil {
		t.Error("URIRegex without risk_acknowledged must be blocked")
	}
	e.RiskAcknowledged = true
	if _, verrs := ValidateForEnable(context.Background(), e, p0Hooks()); verrs != nil {
		t.Errorf("URIRegex with ack should pass gate: %v", verrs)
	}
	e.URIRegex = "^/api/(" + strings.Repeat("a", 512) + ")$"
	if _, verrs := ValidateForEnable(context.Background(), e, p0Hooks()); verrs == nil {
		t.Error("URIRegex >512 must be blocked")
	}
}

func TestP0EnableGateTargetRules(t *testing.T) {
	// WAF 无目标规则 → 拒绝
	e := p0Exception()
	e.RuleIDs = nil
	if _, verrs := ValidateForEnable(context.Background(), e, p0Hooks()); verrs == nil {
		t.Error("empty rule_ids must be blocked")
	}
	// REMOVE_VAR_DETECTION 缺一 → 拒绝
	e = p0Exception()
	e.ExceptionAction = ActionRemoveVarDetection
	e.ParamNames = nil
	if _, verrs := ValidateForEnable(context.Background(), e, p0Hooks()); verrs == nil {
		t.Error("REMOVE_VAR_DETECTION without targets must be blocked")
	}
	// API 引擎缺 api_rule_refs → 拒绝
	e = p0Exception()
	e.TargetEngine = EngineAPI
	e.ExceptionAction = ActionObserveRule
	e.RuleIDs = nil
	e.ParamNames = nil
	e.APIRuleRefs = nil
	if _, verrs := ValidateForEnable(context.Background(), e, p0Hooks()); verrs == nil {
		t.Error("API exception without api_rule_refs must be blocked")
	}
}

func TestP0EnableGateTimeRange(t *testing.T) {
	// 相等起止非法
	e := p0Exception()
	same := time.Unix(1700000000, 0).UTC()
	e.EffectiveFrom = &same
	e.EffectiveUntil = &same
	if _, verrs := ValidateForEnable(context.Background(), e, p0Hooks()); verrs == nil {
		t.Error("equal from/until must be blocked")
	}
	// 临时例外无 until → 拒绝
	e = p0Exception()
	e.EffectiveUntil = nil
	if _, verrs := ValidateForEnable(context.Background(), e, p0Hooks()); verrs == nil {
		t.Error("temporary without until must be blocked")
	}
}

// EXC-04：LOG_ONLY/ADJUST_SCORE 启用被门禁拒绝并携带 UNSUPPORTED_ACTION 与迁移预览文案。
func TestP0EnableGateUnsupportedAction(t *testing.T) {
	for _, action := range []string{ActionLogOnly, ActionAdjustScore} {
		e := p0Exception()
		e.ExceptionAction = action
		_, verrs := ValidateForEnable(context.Background(), e, p0Hooks())
		if verrs == nil {
			t.Fatalf("%s must be blocked at enable gate", action)
		}
		fe := verrs.FieldErr("exception_action")
		if fe == nil {
			t.Fatalf("%s must produce exception_action field error: %v", action, verrs)
		}
		if fe.Code != "UNSUPPORTED_ACTION" {
			t.Errorf("field error code = %q, want UNSUPPORTED_ACTION", fe.Code)
		}
		if !strings.Contains(fe.Message, "REMOVE_VAR_DETECTION") {
			t.Errorf("migration preview must point to precise target exclusion: %q", fe.Message)
		}
	}
}

// REMOVE_RULE_TAG 启用时经规则目录展开冻结（EXC 契约 §3）；解析不出 → 拒绝启用。
func TestP0EnableGateTagExpansion(t *testing.T) {
	e := p0Exception()
	e.ExceptionAction = ActionRemoveRuleTag
	e.RuleIDs = nil
	e.ParamNames = nil
	e.RuleTags = []string{"attack-sqli"}
	plan, verrs := ValidateForEnable(context.Background(), e, p0Hooks())
	if verrs != nil {
		t.Fatalf("tag expansion should pass: %v", verrs)
	}
	if len(plan.ResolvedRuleIDs) != 2 || plan.ResolvedRuleIDs[0] != 941160 || plan.ResolvedRuleIDs[1] != 942100 {
		t.Errorf("resolved ids must be sorted frozen set, got %v", plan.ResolvedRuleIDs)
	}
	// 未知标签 → 解析为空 → 拒绝
	e.RuleTags = []string{"attack-unknown"}
	if _, verrs := ValidateForEnable(context.Background(), e, p0Hooks()); verrs == nil {
		t.Error("unresolvable tag must be blocked")
	}
	// 无规则目录能力 → UNSUPPORTED 拒绝
	hooks := p0Hooks()
	hooks.ResolveRuleTags = nil
	e.RuleTags = []string{"attack-sqli"}
	_, verrs = ValidateForEnable(context.Background(), e, hooks)
	if verrs == nil {
		t.Fatal("missing rule directory must block REMOVE_RULE_TAG")
	}
	if fe := verrs.FieldErr("rule_tags"); fe == nil || fe.Code != "UNSUPPORTED_ACTION" {
		t.Errorf("missing directory should report UNSUPPORTED on rule_tags: %v", verrs)
	}
}

// ---------- 编译摘要 ----------

func TestP0FingerprintDeterministic(t *testing.T) {
	e := p0Exception()
	fp1, err := CompiledFingerprint(e)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if len(fp1) != 64 {
		t.Errorf("fingerprint should be sha256 hex, got %q", fp1)
	}
	if fp2, _ := CompiledFingerprint(e); fp2 != fp1 {
		t.Error("fingerprint must be deterministic")
	}
	// 内容变化 → 指纹变化
	e2 := p0Exception()
	e2.ParamNames = []string{"other"}
	if fp2, _ := CompiledFingerprint(e2); fp2 == fp1 {
		t.Error("content change must change fingerprint")
	}
	// 版本变化 → 指纹变化（预览后草稿被改可被检出）
	e3 := p0Exception()
	e3.Version = 3
	if fp3, _ := CompiledFingerprint(e3); fp3 == fp1 {
		t.Error("version change must change fingerprint")
	}
}

// API 引擎指纹：规范化 JSON 的 sha256（不依赖 SecLang）。
func TestP0FingerprintAPIEngine(t *testing.T) {
	e := p0Exception()
	e.TargetEngine = EngineAPI
	e.ExceptionAction = ActionObserveRule
	e.RuleIDs = nil
	e.ParamNames = nil
	e.APIRuleRefs = []APIRuleRef{{DetectorID: "api_schema", RuleID: "body.name"}}
	fp, err := CompiledFingerprint(e)
	if err != nil {
		t.Fatalf("api fingerprint: %v", err)
	}
	if len(fp) != 64 {
		t.Errorf("api fingerprint should be sha256 hex, got %q", fp)
	}
}

// ---------- ReviewException（保存/更新后重算 validation_status） ----------

func TestP0ReviewException(t *testing.T) {
	// 达标 → VALID 无原因
	status, reasons, err := ReviewException(context.Background(), p0Exception(), p0Hooks())
	if err != nil {
		t.Fatalf("review: %v", err)
	}
	if status != ValidationValid || len(reasons) != 0 {
		t.Errorf("valid exception reviewed as %s %v", status, reasons)
	}
	// 缺应用/方法 → NEEDS_REVIEW 且原因列明缺失项
	e := p0Exception()
	e.ApplicationID = nil
	e.Methods = nil
	status, reasons, err = ReviewException(context.Background(), e, p0Hooks())
	if err != nil {
		t.Fatalf("review: %v", err)
	}
	if status != ValidationNeedsReview {
		t.Errorf("incomplete draft should be NEEDS_REVIEW, got %s", status)
	}
	joined := strings.Join(reasons, "|")
	if !strings.Contains(joined, "应用") || !strings.Contains(joined, "方法") {
		t.Errorf("reasons must name missing items, got %v", reasons)
	}
	// 不支持动作 → NEEDS_REVIEW 且原因含迁移指引
	e = p0Exception()
	e.ExceptionAction = ActionLogOnly
	status, reasons, err = ReviewException(context.Background(), e, p0Hooks())
	if err != nil {
		t.Fatalf("review: %v", err)
	}
	if status != ValidationNeedsReview || !strings.Contains(strings.Join(reasons, "|"), "REMOVE_VAR_DETECTION") {
		t.Errorf("LOG_ONLY should be NEEDS_REVIEW with migration hint, got %s %v", status, reasons)
	}
}
