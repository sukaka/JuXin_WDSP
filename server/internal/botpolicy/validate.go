// validate.go Bot 策略输入校验（PUT 保存草稿与 store.SaveDraft 共用同一校验；
// 与 jwttrust/riskpolicy 同一模式：字段级错误列表，handler 转 400 details）。
// 结构校验为纯函数（无网络 IO、无 DB）；路由保留冲突预检见 handler.Preflight。
package botpolicy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// FieldError 字段级校验错误。
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError 校验错误集合（handler 转 400 响应 details）。
type ValidationError struct {
	Errors []FieldError
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("bot policy validation failed: %d field(s)", len(e.Errors))
}

// 规则 ID 词形（稳定标识：小写字母开头，小写字母/数字/下划线）。
var ruleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// key_ref 引用名词形（仅引用名——不是密钥材料；防路径拼接与注入）。
var keyRefPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// UA 分类词表（与网关 identitybehavior 身份分类一致；可伪造弱信号）。
var validUAClasses = map[string]bool{
	"BOT": true, "APPLICATION": true, "SERVICE": true, "AGENT": true, "UNKNOWN": true,
}

// method_ratio 参数方法白名单（与 l7rules 方法集合一致）。
var validParamMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true,
	"HEAD": true, "OPTIONS": true, "TRACE": true, "CONNECT": true,
}

// 阈值语义（按指标冻结，不接受请求侧覆盖方向）。
const (
	thresholdRatioGTE = "ratio_gte" // 占比类：≥ 阈值触发，阈值 ∈ (0,1]
	thresholdRatioLTE = "ratio_lte" // known_uri_ratio：≤ 阈值触发，阈值 ∈ [0,1)
	thresholdCountGTE = "count_gte" // 计数类：≥ 阈值触发，阈值 ∈ [1,100]
	thresholdNone     = "none"      // 声明匹配类：命中即触发，threshold 恒 0
)

// metricSpec 指标规格（B0 冻结：组归属、参数键白名单、阈值语义）。
type metricSpec struct {
	group     string
	paramKeys []string // 允许的参数键（全部必填；多/少/未知键一律拒绝）
	threshold string
}

// metricSpecs 指标白名单（未知指标拒绝）。
var metricSpecs = map[string]metricSpec{
	MetricStatusFamilyRatio:     {group: GroupRequestBehavior, paramKeys: []string{"family"}, threshold: thresholdRatioGTE},
	MetricMethodRatio:           {group: GroupRequestBehavior, paramKeys: []string{"method"}, threshold: thresholdRatioGTE},
	MetricURIConcentration:      {group: GroupRequestBehavior, paramKeys: nil, threshold: thresholdRatioGTE},
	MetricKnownURIRatio:         {group: GroupAccessSequence, paramKeys: nil, threshold: thresholdRatioLTE},
	MetricMethodEnumerationSize: {group: GroupAccessSequence, paramKeys: nil, threshold: thresholdCountGTE},
	MetricUAClassMatch:          {group: GroupClientClaim, paramKeys: []string{"class"}, threshold: thresholdNone},
	MetricTLSClientHint:         {group: GroupClientClaim, paramKeys: []string{"equals", "field"}, threshold: thresholdNone},
}

// IsBehaviorGroup 行为组判定（B0：提出挑战必须至少 1 个行为组；
// client_claim 为可伪造弱信号声明组，不算行为观测）。
func IsBehaviorGroup(group string) bool {
	return group == GroupRequestBehavior || group == GroupAccessSequence
}

// Normalize 归一化输入（校验与落库前调用）：规则 ID 去空白；params 值去空白、
// method 大写、family/class/field 统一大小写形式。challenge 缺省值由 handler 在
// 反序列化层应用（指针区分「未提供」与显式 0）。
func Normalize(p *Policy) {
	for i := range p.SignalRules.Rules {
		r := &p.SignalRules.Rules[i]
		r.ID = strings.TrimSpace(r.ID)
		for k, v := range r.Params {
			v = strings.TrimSpace(v)
			switch k {
			case "method", "class":
				v = strings.ToUpper(v)
			case "family", "field":
				v = strings.ToLower(v)
			}
			r.Params[k] = v
		}
	}
	p.Challenge.KeyRef = strings.TrimSpace(p.Challenge.KeyRef)
	p.RouteReservation.Namespace = strings.TrimSpace(p.RouteReservation.Namespace)
}

// ValidateStructure 校验策略全字段（纯结构），返回字段级错误列表（空=通过）。
// 契约（B0 冻结）：未知 mode 拒绝；非 OFF 必须至少一条 selector 与一条信号规则；
// selectors 仅 GET（方法不出现在契约中）+ 路径精确/规范化前缀二选一，禁止正则、
// 百分号编码、全站通配与保留命名空间；信号规则按组指标白名单校验且同源计数派生
// 指标（同 group+metric+params）不重复计权；PROTECT 要求已配置信号组数达到
// min_independent_groups 且至少含 1 个行为组（否则策略永远无法提出挑战，属配置错误）；
// PROTECT 要求 route_reservation.state=ENABLED（挑战路由必须注册）。
func ValidateStructure(p *Policy) []FieldError {
	errs := []FieldError{}
	add := func(field, msg string) {
		errs = append(errs, FieldError{Field: field, Message: msg})
	}

	if p.Mode != ModeOff && p.Mode != ModeObserve && p.Mode != ModeProtect {
		add("mode", "仅支持 OFF / OBSERVE / PROTECT")
	}

	validateSelectors(p, add)
	validateSignalRules(p, add)
	validateChallenge(p, add)
	validateRouteReservation(p, add)
	return errs
}

// validateSelectors 选择器校验（仅 GET + 精确/前缀；禁止正则与全站通配）。
func validateSelectors(p *Policy, add func(field, msg string)) {
	if len(p.Selectors) > MaxSelectors {
		add("selectors", fmt.Sprintf("选择器数量不能超过 %d", MaxSelectors))
	}
	if p.Mode != ModeOff && len(p.Selectors) == 0 {
		add("selectors", "非 OFF 模式必须配置至少一条选择器")
	}
	for i, s := range p.Selectors {
		prefix := fmt.Sprintf("selectors[%d]", i)
		hasExact := s.PathExact != ""
		hasPrefix := s.PathPrefix != ""
		if hasExact == hasPrefix {
			add(prefix, "path_exact 与 path_prefix 必须且仅须提供一个")
			continue
		}
		path := s.PathExact
		field := prefix + ".path_exact"
		if hasPrefix {
			path = s.PathPrefix
			field = prefix + ".path_prefix"
		}
		if !strings.HasPrefix(path, "/") {
			add(field, "路径必须以 / 开头")
			continue
		}
		if len(path) > MaxSelectorPathLen {
			add(field, fmt.Sprintf("路径长度不能超过 %d", MaxSelectorPathLen))
		}
		if strings.ContainsAny(path, "?#") {
			add(field, "路径不得包含 query 或 fragment")
		}
		if hasControlChars(path) {
			add(field, "路径不得包含控制字符")
		}
		if strings.Contains(path, "%") {
			add(field, "路径按解码后形式配置，不得包含百分号编码（避免双重编码歧义）")
		}
		for _, seg := range strings.Split(path, "/") {
			if seg == "." || seg == ".." {
				add(field, "路径不得包含 . 或 .. 段（避免规范化歧义）")
				break
			}
		}
		if hasPrefix {
			if path == "/" {
				add(field, "path_prefix 不允许全站通配（/）；须给出具体前缀")
			} else if strings.HasSuffix(path, "/") {
				add(field, "path_prefix 须按完整路径段给出，不应以 / 结尾")
			}
			// 前缀不得覆盖保留命名空间（/doc 形式的前缀按完整段匹配：
			// p 匹配 verify 路径当且仅当 p==verifyPath 或 verifyPath 以 p+"/" 开头）
			if ReservedVerifyPath == path || strings.HasPrefix(ReservedVerifyPath, path+"/") {
				add(field, "path_prefix 不得覆盖 Bot 保留命名空间 "+ReservedNamespace)
			}
		} else if path == ReservedVerifyPath || strings.HasPrefix(path, ReservedNamespace) {
			add(field, "path_exact 不得落入 Bot 保留命名空间 "+ReservedNamespace)
		}
	}
}

// validateSignalRules 信号规则校验（组/指标白名单、窗口/权重/阈值上下界、
// 同源计数派生指标不重复计权、PROTECT 组覆盖充分性）。
func validateSignalRules(p *Policy, add func(field, msg string)) {
	sr := p.SignalRules
	if sr.MinIndependentGroups < MinGroups || sr.MinIndependentGroups > MaxGroups {
		add("signal_rules.min_independent_groups",
			fmt.Sprintf("必须在 %d~%d 之间（B0：提出挑战需至少 %d 个独立信号组）", MinGroups, MaxGroups, MinGroups))
	}
	if !sr.RequireBehaviorGroup {
		add("signal_rules.require_behavior_group", "必须为 true（B0：至少 1 个行为观测组；声明组为可伪造弱信号，不能单独构成挑战依据）")
	}
	if len(sr.Rules) > MaxSignalRules {
		add("signal_rules.rules", fmt.Sprintf("信号规则数量不能超过 %d", MaxSignalRules))
	}
	if p.Mode != ModeOff && len(sr.Rules) == 0 {
		add("signal_rules.rules", "非 OFF 模式必须配置至少一条信号规则")
	}

	seenID := map[string]bool{}
	seenSource := map[string]string{} // 同源计数指纹（group|metric|canonical params）→ 规则 ID
	groups := map[string]bool{}
	for i, r := range sr.Rules {
		prefix := fmt.Sprintf("signal_rules.rules[%d]", i)
		if !ruleIDPattern.MatchString(r.ID) {
			add(prefix+".id", "规则 ID 须为小写字母开头的小写字母/数字/下划线（1~64 字符）")
		} else if seenID[r.ID] {
			add(prefix+".id", "规则 ID 在策略内必须唯一: "+r.ID)
		}
		seenID[r.ID] = true

		spec, ok := metricSpecs[r.Metric]
		if !ok {
			add(prefix+".metric", "未知信号指标: "+r.Metric)
			continue
		}
		if r.Group != spec.group {
			add(prefix+".group", fmt.Sprintf("指标 %s 属于信号组 %s，实际: %s", r.Metric, spec.group, r.Group))
		}
		groups[spec.group] = true

		validateRuleParams(r, spec, prefix, add)

		if r.WindowSeconds < MinWindowSeconds || r.WindowSeconds > MaxWindowSeconds {
			add(prefix+".window_seconds", fmt.Sprintf("必须在 %d~%d 秒之间", MinWindowSeconds, MaxWindowSeconds))
		}
		if r.Weight <= 0 || r.Weight > MaxRuleWeight {
			add(prefix+".weight", fmt.Sprintf("必须在 (0,%d] 之间（组满足 = 组内已触发权重和 ≥1）", MaxRuleWeight))
		}
		switch spec.threshold {
		case thresholdRatioGTE:
			if r.Threshold <= 0 || r.Threshold > 1 {
				add(prefix+".threshold", "占比类指标阈值必须在 (0,1] 之间（≥ 阈值触发）")
			}
		case thresholdRatioLTE:
			if r.Threshold < 0 || r.Threshold >= 1 {
				add(prefix+".threshold", "known_uri_ratio 阈值必须在 [0,1) 之间（≤ 阈值触发）")
			}
		case thresholdCountGTE:
			if r.Threshold < 1 || r.Threshold > 100 {
				add(prefix+".threshold", "计数类指标阈值必须在 1~100 之间（≥ 阈值触发）")
			}
		case thresholdNone:
			if r.Threshold != 0 {
				add(prefix+".threshold", "声明匹配类指标命中即触发，threshold 必须为 0")
			}
		}

		// 同源计数派生指标不重复计权（同 group+metric+规范化 params 视为同一计数源）
		fp := r.Group + "|" + r.Metric + "|" + canonicalParams(r.Params)
		if dup, ok := seenSource[fp]; ok {
			add(prefix, fmt.Sprintf("与规则 %s 同源（同组同指标同参数），派生指标不重复计权", dup))
		} else {
			seenSource[fp] = r.ID
		}
	}

	// PROTECT 组覆盖充分性：配置的信号组数达不到 min_independent_groups 或缺少行为组时，
	// 策略按 B0 判定口径永远无法提出挑战——属于配置错误，保存期拒绝（不比发布后发现好）
	if p.Mode == ModeProtect {
		if len(groups) < sr.MinIndependentGroups {
			add("signal_rules.rules",
				fmt.Sprintf("PROTECT 要求已配置信号覆盖至少 %d 个独立信号组，当前 %d 个", sr.MinIndependentGroups, len(groups)))
		}
		hasBehavior := false
		for g := range groups {
			if IsBehaviorGroup(g) {
				hasBehavior = true
				break
			}
		}
		if !hasBehavior {
			add("signal_rules.rules", "PROTECT 要求至少配置 1 个行为组（request_behavior / access_sequence）规则")
		}
	}
}

// validateRuleParams 指标参数校验（允许键白名单 + 取值约束；未知/缺失键拒绝）。
func validateRuleParams(r SignalRule, spec metricSpec, prefix string, add func(field, msg string)) {
	if len(spec.paramKeys) == 0 && len(r.Params) > 0 {
		add(prefix+".params", "该指标不接受参数")
		return
	}
	for k := range r.Params {
		found := false
		for _, want := range spec.paramKeys {
			if k == want {
				found = true
				break
			}
		}
		if !found {
			add(prefix+".params", "未知参数键: "+k)
		}
	}
	for _, k := range spec.paramKeys {
		v, ok := r.Params[k]
		if !ok || v == "" {
			add(prefix+".params."+k, "缺少必需参数: "+k)
			continue
		}
		switch k {
		case "family":
			if v != "2xx" && v != "3xx" && v != "4xx" && v != "5xx" {
				add(prefix+".params.family", "状态码族仅支持 2xx/3xx/4xx/5xx")
			}
		case "method":
			if !validParamMethods[v] {
				add(prefix+".params.method", "非法 HTTP 方法: "+v)
			}
		case "class":
			if !validUAClasses[v] {
				add(prefix+".params.class", "UA 分类仅支持 BOT/APPLICATION/SERVICE/AGENT/UNKNOWN（可伪造弱信号）")
			}
		case "field":
			if v != "version" && v != "cipher_suite" {
				add(prefix+".params.field", "TLS 轻量特征字段仅支持 version/cipher_suite")
			}
		case "equals":
			if len(v) > 128 || hasControlChars(v) {
				add(prefix+".params.equals", "比对值须为长度 1~128 的无控制字符字符串")
			}
		}
	}
}

// validateChallenge 挑战参数校验（仅 JS 类型；B0 冻结上下界；
// key_ref 仅为引用名——任何密钥材料不得出现在策略中）。
func validateChallenge(p *Policy, add func(field, msg string)) {
	c := p.Challenge
	if c.Type != "JS" {
		add("challenge.type", "仅支持 JS（第一方 JavaScript 挑战，无外部服务依赖）")
	}
	if c.NonceTTLSeconds < MinNonceTTL || c.NonceTTLSeconds > MaxNonceTTL {
		add("challenge.nonce_ttl_seconds", fmt.Sprintf("必须在 %d~%d 秒之间（默认 %d）", MinNonceTTL, MaxNonceTTL, DefaultNonceTTL))
	}
	if c.ClearanceTTLSeconds < MinClearanceTTL || c.ClearanceTTLSeconds > MaxClearanceTTL {
		add("challenge.clearance_ttl_seconds", fmt.Sprintf("必须在 %d~%d 秒之间（默认 %d）", MinClearanceTTL, MaxClearanceTTL, DefaultClearanceTTL))
	}
	if c.Difficulty < MinDifficulty || c.Difficulty > MaxDifficulty {
		add("challenge.difficulty", fmt.Sprintf("必须在 %d~%d bit 之间（默认 %d）", MinDifficulty, MaxDifficulty, DefaultDifficulty))
	}
	if c.MaxAttempts < MinMaxAttempts || c.MaxAttempts > MaxMaxAttempts {
		add("challenge.max_attempts", fmt.Sprintf("必须在 %d~%d 次之间（默认 %d）", MinMaxAttempts, MaxMaxAttempts, DefaultMaxAttempts))
	}
	if c.KeyRef != "" && !keyRefPattern.MatchString(c.KeyRef) {
		add("challenge.key_ref", "非法密钥引用名（小写字母/数字/._-，小写字母或数字开头，1~64 字符；仅引用名，不接受密钥材料）")
	}
}

// validateRouteReservation 路由保留状态校验（状态机 + 命名空间冻结 +
// PROTECT 一致性：挑战路由必须注册）。
func validateRouteReservation(p *Policy, add func(field, msg string)) {
	rr := p.RouteReservation
	switch rr.State {
	case ReservationEnabled, ReservationTombstone, ReservationReleased:
	default:
		add("route_reservation.state", "仅支持 ENABLED / RESERVED_TOMBSTONE / RELEASED")
	}
	if rr.Namespace != ReservedNamespace {
		add("route_reservation.namespace", "保留命名空间固定为 "+ReservedNamespace+"（更换需升 schema 版本）")
	}
	if p.Mode == ModeProtect && rr.State != ReservationEnabled {
		add("route_reservation.state", "PROTECT 要求 ENABLED（挑战/verify 路由必须注册；从已启用状态关闭请使用 RESERVED_TOMBSTONE 保留墓碑）")
	}
}

// canonicalParams 参数规范化指纹（键序稳定拼接，供同源计权去重）。
func canonicalParams(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(params[k])
		b.WriteByte(';')
	}
	return b.String()
}

// hasControlChars 控制字符检测（防注入）。
func hasControlChars(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}
