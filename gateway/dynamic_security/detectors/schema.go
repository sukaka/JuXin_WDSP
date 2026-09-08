// Package detectors 运行时检测器：只写 Matches，不设置 FinalAction。
package detectors

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// CheckSchemaDeviation 对比观测字段与冻结正式模型；偏离只产生 match，不修改 formal。
func CheckSchemaDeviation(ctx *dsctx.RequestContext, observed map[string]string, formal map[string]string) {
	if ctx == nil || formal == nil || len(formal) == 0 {
		return
	}
	for name, gotType := range observed {
		want, ok := formal[name]
		if !ok {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector:   "api_schema",
				RuleID:     "schema.undefined_field",
				Category:   "OBSERVE",
				Severity:   "MEDIUM",
				Message:    "undefined field vs formal model",
				Evidence:   map[string]string{"field": name, "type": gotType},
				ScoreDelta: 15,
			})
			continue
		}
		if want != "" && gotType != "" && want != gotType {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector:   "api_schema",
				RuleID:     "schema.type_mismatch",
				Category:   "BLOCK",
				Severity:   "HIGH",
				Message:    fmt.Sprintf("type mismatch for %s", name),
				Evidence:   map[string]string{"field": name, "want": want, "got": gotType},
				ScoreDelta: 40,
			})
		}
	}
	// missing required: formal keys with empty observed
	// 键序排序遍历：事件确定性（map 遍历序抖动使事件顺序不可重现，同 authzcheck.go sort 先例）
	formalNames := make([]string, 0, len(formal))
	for name := range formal {
		formalNames = append(formalNames, name)
	}
	sort.Strings(formalNames)
	for _, name := range formalNames {
		if _, ok := observed[name]; !ok {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector:   "api_schema",
				RuleID:     "schema.missing_field",
				Category:   "OBSERVE",
				Severity:   "LOW",
				Message:    "missing formal field",
				Evidence:   map[string]string{"field": name},
				ScoreDelta: 5,
			})
		}
	}
}

// CheckIdentitySignals 身份/凭据存在性指纹（不存明文）。
func CheckIdentitySignals(ctx *dsctx.RequestContext, p *parser.Parsed) {
	if ctx == nil || p == nil {
		return
	}
	if v, ok := p.Headers["authorization"]; ok && v == "[redacted]" {
		ctx.AuthenticationType = "bearer_or_basic"
		ctx.TokenFingerprint = "present"
		// 信息性记录：不得抬高 FinalAction（决策引擎忽略 INFO）
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "identity",
			RuleID:   "identity.token_present",
			Category: "INFO",
			Severity: "INFO",
			Message:  "credential header present (redacted)",
			Evidence: map[string]string{"header": "authorization"},
		})
	}
	if v, ok := p.Headers["x-api-key"]; ok && v == "[redacted]" {
		ctx.APIKeyFingerprint = "present"
		ctx.AuthenticationType = "api_key"
	}
	if v, ok := p.Headers["cookie"]; ok && v == "[redacted]" {
		ctx.SessionFingerprint = "present"
		// 信息性记录：不得抬高 FinalAction（决策引擎忽略 INFO）
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "identity",
			RuleID:   "identity.cookie_present",
			Category: "INFO",
			Severity: "INFO",
			Message:  "cookie header present (redacted)",
			Evidence: map[string]string{"header": "cookie"},
		})
		// cookie_session 优先级最低：仅在无 token/api_key 时设置
		if ctx.AuthenticationType == "" {
			ctx.AuthenticationType = "cookie_session"
		}
	}
}

// ---------- 参数级确认约束检测（P0-2，发布通道下发） ----------

// ParamConstraint 发布通道下发的单参数确认约束（server apimodels.ParamConstraint 镜像）。
type ParamConstraint struct {
	Location     string         `json:"location"`      // QUERY / HEADER / BODY / PATH / COOKIE
	Name         string         `json:"name"`          // 参数名（QUERY/HEADER 键名；BODY 末段名）
	Path         string         `json:"path"`          // 结构化路径（BODY 点路径；PATH 可为段序号）
	BaseType     string         `json:"base_type"`     // string|number|bool|object|array|null
	Required     bool           `json:"required"`      // 必填（缺失产生 OBSERVE 级明细）
	SemanticType string         `json:"semantic_type"` // 语义类型（id/uuid/email 等；供对象标识联动）
	Constraints  map[string]any `json:"constraints"`   // 确认约束（词汇见 Constraint* 常量）
}

// 参数约束词汇（钉死 snake_case；读取侧宽容——未知键忽略）。
const (
	ConstraintMinLength = "min_length" // 字符串最小长度（字符数）
	ConstraintMaxLength = "max_length" // 字符串最大长度（字符数）
	ConstraintMinimum   = "minimum"    // 数值下界
	ConstraintMaximum   = "maximum"    // 数值上界
	ConstraintEnum      = "enum"       // 枚举（字符串数组）
	ConstraintRegex     = "regex"      // 字符串正则（RE2；编译失败/超长保守 OBSERVE，见 CompileConstraintRegex）
	// ConstraintNullable null 是否允许（仅 BODY JSON 有 null 语义；缺省不判定，显式 false 才违例）
	ConstraintNullable = "nullable"
	// ConstraintEmptyAllowed 空值是否允许（空串：各位置；空数组：仅 BODY；空 object 不在本期词汇内；
	// 缺省不判定，显式 false 才违例）
	ConstraintEmptyAllowed = "empty_allowed"
)

// maxConstraintRegexLen 约束正则长度上限（字符数）。
// Go regexp 为 RE2 语义（线性匹配，无回溯灾难）；上限防超长 pattern 编译自动机占内存。
const maxConstraintRegexLen = 512

// 约束正则编译缓存（热路径预编译修复）：端点约束集经发布通道下发，同一 pattern
// 逐请求逐约束重复传入，首次编译后热路径直接命中；错误同为确定性结果一并缓存，校验语义不变。
var constraintRegexCache = newCompileCache(256)

type constraintRegexResult struct {
	re  *regexp.Regexp
	err error
}

// CompileConstraintRegex 编译约束正则（RE2）：超上限或语法错误返回 error。
// 运行期调用方对失败保守 OBSERVE（不升级为阻断）；装配层（jiuzhang_guard Provision）用于配置预检 Warn。
// 结果经并发安全缓存（键即 pattern）：同一约束仅装配期编译一次，热路径零重复编译。
func CompileConstraintRegex(pattern string) (*regexp.Regexp, error) {
	if v, ok := constraintRegexCache.load(pattern); ok {
		r := v.(constraintRegexResult)
		return r.re, r.err
	}
	re, err := compileConstraintRegex(pattern)
	constraintRegexCache.store(pattern, constraintRegexResult{re, err})
	return re, err
}

func compileConstraintRegex(pattern string) (*regexp.Regexp, error) {
	if utf8.RuneCountInString(pattern) > maxConstraintRegexLen {
		return nil, fmt.Errorf("regex constraint exceeds %d chars", maxConstraintRegexLen)
	}
	return regexp.Compile(pattern)
}

// CheckParamConstraints 按下发确认约束检测请求参数（QUERY/HEADER/BODY/PATH/COOKIE）。
// 证据只写字段/约束/位置，永不写原始值；约束解析失败跳过该条（不致命）。
// mode 为已解析的防护模式：required 违例在 PROTECT 升级为 BLOCK 类（可定案阻断），
// OBSERVE/OFF 维持 OBSERVE 级观察（与 schema.type_mismatch 的类别语义一致——类别描述违例等级，模式决定是否执行）。
func CheckParamConstraints(ctx *dsctx.RequestContext, p *parser.Parsed, params []ParamConstraint, mode decision.Mode) {
	if ctx == nil || p == nil || len(params) == 0 {
		return
	}
	for i := range params {
		pc := params[i]
		var present bool
		var value string
		var hasValue bool
		var bodyPath string // BODY 结构化路径（nullable/empty_allowed 结构判定用；非 BODY 为空）
		field := pc.Name
		switch strings.ToUpper(pc.Location) {
		case "QUERY":
			v, ok := p.Query[pc.Name]
			present, value, hasValue = ok, v, ok
		case "HEADER":
			v, ok := p.Headers[strings.ToLower(pc.Name)]
			present, value, hasValue = ok, v, ok
			// 脱敏头（authorization/cookie/x-api-key）仅保留存在性，占位值不可用于取值约束
			if ok && v == "[redacted]" {
				hasValue = false
			}
		case "BODY":
			path := pc.Path
			if path == "" {
				path = pc.Name
			}
			field = path
			bodyPath = path
			_, present = p.JSONFields[path]
			v, ok := p.JSONValues[path]
			value, hasValue = v, ok // 非标量（object/array/null）无留存值：存在但无可检值
		case "PATH":
			// PATH：按归一化段占位名（{id}/{uuid}/{hex}）或段序号匹配原始路径段
			v, ok := pathSegmentValue(p, pc.Name, pc.Path)
			present, value, hasValue = ok, v, ok
			if ok {
				field = pc.Name
			}
		case "COOKIE":
			// Cookie 整头脱敏：仅能做 required 存在性（SessionFingerprint / cookie 头存在）
			if p.Headers["cookie"] == "[redacted]" {
				present = true
				hasValue = false
			}
		default:
			continue
		}
		if !present {
			if pc.Required {
				if mode == decision.ModeProtect {
					// PROTECT：required 违例升级 BLOCK 类（决策引擎可定案阻断）
					addParamViolation(ctx, pc.Location, field, "required", "schema.param_required")
				} else {
					// OBSERVE/OFF：维持 OBSERVE 级观察（原有语义不破）
					ctx.AddMatch(dsctx.DetectorMatch{
						Detector:   "api_schema",
						RuleID:     "schema.param_required",
						Category:   "OBSERVE",
						Severity:   "LOW",
						Message:    "required parameter missing",
						Evidence:   map[string]string{"field": field, "constraint": "required", "location": pc.Location},
						ScoreDelta: 5,
					})
				}
			}
			continue
		}
		// BODY 结构性观测（null/空数组无留存标量值，进不了取值约束）：nullable/empty_allowed 在此判定
		if bodyPath != "" {
			switch p.JSONFields[bodyPath] {
			case "null":
				// null 观测：nullable=false → 违例；null 无标量值，其余取值约束不适用
				if allow, ok := constraintBool(pc.Constraints[ConstraintNullable]); ok && !allow {
					addParamViolation(ctx, pc.Location, field, ConstraintNullable, "schema.param_nullable")
				}
				continue
			case "array":
				if _, hasElem := p.JSONFields[bodyPath+"[]"]; !hasElem {
					// 空数组观测：empty_allowed=false → 违例
					if allow, ok := constraintBool(pc.Constraints[ConstraintEmptyAllowed]); ok && !allow {
						addParamViolation(ctx, pc.Location, field, ConstraintEmptyAllowed, "schema.param_empty")
					}
					continue
				}
			}
		}
		if !hasValue {
			continue
		}
		checkParamValueConstraints(ctx, pc.Location, field, value, pc.Constraints)
	}
}

// checkParamValueConstraints 对字符串形态观测值执行约束（值不入证据；未知键忽略）。
func checkParamValueConstraints(ctx *dsctx.RequestContext, location, field, value string, constraints map[string]any) {
	// 数值区间：先解析观测值一次；非数值只报一条 param_type（避免 min+max 双发）
	var rangeMin, rangeMax float64
	var hasMin, hasMax bool
	if raw, ok := constraints[ConstraintMinimum]; ok {
		if bound, ok := constraintNumber(raw); ok {
			rangeMin, hasMin = bound, true
		}
	}
	if raw, ok := constraints[ConstraintMaximum]; ok {
		if bound, ok := constraintNumber(raw); ok {
			rangeMax, hasMax = bound, true
		}
	}
	if hasMin || hasMax {
		num, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil {
			// QUERY/HEADER 等不经 schema.type_mismatch；非数值对数值约束按类型违规处理
			addParamViolation(ctx, location, field, "type", "schema.param_type")
		} else {
			if hasMin && num < rangeMin {
				addParamViolation(ctx, location, field, ConstraintMinimum, "schema.param_range")
			}
			if hasMax && num > rangeMax {
				addParamViolation(ctx, location, field, ConstraintMaximum, "schema.param_range")
			}
		}
	}
	for key, raw := range constraints {
		switch key {
		case ConstraintMinLength, ConstraintMaxLength:
			bound, ok := constraintNumber(raw)
			if !ok {
				continue // 约束解析失败：跳过该条（不致命）
			}
			n := float64(utf8.RuneCountInString(value))
			if (key == ConstraintMinLength && n < bound) || (key == ConstraintMaxLength && n > bound) {
				addParamViolation(ctx, location, field, key, "schema.param_length")
			}
		case ConstraintMinimum, ConstraintMaximum:
			// 已在上方统一处理
		case ConstraintEnum:
			allowed, ok := constraintStringSet(raw)
			if !ok {
				continue
			}
			if !allowed[value] {
				addParamViolation(ctx, location, field, key, "schema.param_enum")
			}
		case ConstraintRegex:
			pattern, ok := raw.(string)
			if !ok || pattern == "" {
				continue // 非字符串/空 pattern：与未知键同等宽容跳过
			}
			re, err := CompileConstraintRegex(pattern)
			if err != nil {
				// 编译失败/超长：保守 OBSERVE（配置问题在事件流可见，不升级阻断、不静默）
				addParamConstraintInvalid(ctx, location, field, key)
				continue
			}
			if !re.MatchString(value) {
				addParamViolation(ctx, location, field, key, "schema.param_regex")
			}
		case ConstraintEmptyAllowed:
			allow, ok := constraintBool(raw)
			if !ok {
				continue
			}
			if !allow && value == "" {
				addParamViolation(ctx, location, field, key, "schema.param_empty")
			}
		case ConstraintNullable:
			// null 语义仅存在于 BODY JSON 结构层，已在 CheckParamConstraints 结构分支判定；标量值层面无动作
		default:
			// 未知约束键忽略（读取侧宽容）
		}
	}
}

// addParamViolation 参数约束违规明细（BLOCK/HIGH；证据只写字段/约束/位置，不写值）。
func addParamViolation(ctx *dsctx.RequestContext, location, field, constraint, ruleID string) {
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "api_schema",
		RuleID:     ruleID,
		Category:   "BLOCK",
		Severity:   "HIGH",
		Message:    "parameter constraint violated",
		Evidence:   map[string]string{"field": field, "constraint": constraint, "location": location},
		ScoreDelta: 40,
	})
}

// addParamConstraintInvalid 约束自身不可执行（如 regex 编译失败/超长）的保守 OBSERVE 明细：
// 配置问题在事件流可见（不静默吞错），但不计分不升级阻断（坏配置不得放大为误阻断）。
func addParamConstraintInvalid(ctx *dsctx.RequestContext, location, field, constraint string) {
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "api_schema",
		RuleID:   "schema.param_constraint_invalid",
		Category: "OBSERVE",
		Severity: "LOW",
		Message:  "parameter constraint cannot be executed (observed only)",
		Evidence: map[string]string{"field": field, "constraint": constraint, "location": location},
	})
}

// constraintBool 解析布尔型约束（nullable/empty_allowed；JSON 布尔为主，
// 兼容字符串形态；其余视为未配置——缺省不判定，读取侧宽容）。
func constraintBool(raw any) (bool, bool) {
	switch v := raw.(type) {
	case bool:
		return v, true
	case string:
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			return b, true
		}
	}
	return false, false
}

// constraintNumber 解析数值型约束界（JSONB/JSON 数值经 Unmarshal 多为 float64；
// 兼容 int/int64/float32 与字符串形态；其余视为解析失败）。
func constraintNumber(raw any) (float64, bool) {
	switch v := raw.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case int32:
		return float64(v), true
	case json.Number:
		n, err := v.Float64()
		return n, err == nil
	case string:
		if n, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return n, true
		}
	}
	return 0, false
}

// constraintStringSet 解析枚举约束（字符串数组；含非字符串元素或为空数组视为解析失败，
// 空枚举若按「全部违规」处理会把配置笔误放大成全量误阻断）。
// 兼容 []any（json.Unmarshal 默认）与 []string（手工构造/部分序列化路径）。
func constraintStringSet(raw any) (map[string]bool, bool) {
	switch arr := raw.(type) {
	case []any:
		if len(arr) == 0 {
			return nil, false
		}
		set := make(map[string]bool, len(arr))
		for _, item := range arr {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			set[s] = true
		}
		return set, true
	case []string:
		if len(arr) == 0 {
			return nil, false
		}
		set := make(map[string]bool, len(arr))
		for _, s := range arr {
			set[s] = true
		}
		return set, true
	default:
		return nil, false
	}
}

// pathSegmentValue 按 PATH 约束匹配原始路径段值。
// name 可为占位名 {id}/{uuid}/{hex}；path 可为段序号字符串。
func pathSegmentValue(p *parser.Parsed, name, pathIdx string) (string, bool) {
	if p == nil {
		return "", false
	}
	norm := strings.Split(strings.Trim(p.NormalizedPath, "/"), "/")
	raw := strings.Split(strings.Trim(p.RawPath, "/"), "/")
	// 优先按段序号
	if pathIdx != "" {
		if i, err := strconv.Atoi(pathIdx); err == nil && i >= 0 && i < len(raw) && i < len(norm) {
			return raw[i], true
		}
	}
	// 按占位名匹配首个同名段
	want := name
	if want == "" {
		return "", false
	}
	for i, s := range norm {
		if s == want && i < len(raw) {
			return raw[i], true
		}
	}
	return "", false
}
