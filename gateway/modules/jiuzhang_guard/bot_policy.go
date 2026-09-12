// Bot 挑战策略（WDSP P1-02，任务书 docs/tasks/wdsp-p1/P1-02_BOT_CHALLENGE.md）：
// bot_policy 段的配置解析、校验与装配。
//
// 纪律：
//   - 与 jwt_trust 同一 fail-closed 口径（严格解码——未知字段、不支持的
//     schema_version、非法结构一律拒绝加载），**不采用** riskengine Compile 的
//     逐项消毒 fail-open：risk_policy 的消毒仅适用于「非法也不实断」的评分策略，
//     而 bot_policy 携带 PROTECT 强制语义（挑战路由保留与强制挑战），静默消毒/
//     降级等于把「应当挑战」变成「直接放行」；server 侧 botpolicy.SchemaVersion
//     注释已冻结「旧节点不识别即拒绝加载，与 jwt_trust 同一纪律」。
//   - 请求链接入（B3）：解析产物总是保留在 g.botPolicy（OFF + RESERVED_TOMBSTONE
//     需段内容维持 verify 命名空间本地墓碑）；非 OFF 装配 botchallenge.Service
//     （g.botSvc）供 bot_step.go 的 Bot 步骤消费；PROTECT 依赖缺失 fail-closed 拒载，
//     OBSERVE 依赖缺失降级为仅装配持有（观测不阻断请求链）。
//   - 配置内容为跨分片契约（json tag 与 server/internal/gatewayconfig.GuardBotPolicy
//     同形，不得改动）；校验边界与 server/internal/botpolicy/validate.go 的 B0 冻结
//     口径逐条对应（网关独立复检，不信任发布侧已校验）。
package jiuzhang_guard

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/botchallenge"
)

// botPolicySchemaVersion 本网关支持的 bot_policy 配置结构版本
// （与 server/internal/botpolicy.SchemaVersion 对应；不一致即拒绝加载）。
const botPolicySchemaVersion = 1

// Bot 模式枚举（默认 OFF：不观测、不挑战、不改变既有流量）。
const (
	botModeOff     = "OFF"
	botModeObserve = "OBSERVE"
	botModeProtect = "PROTECT"
)

// 保留端点命名空间（B0 冻结；与 server/internal/botpolicy 一致——
// 命名空间更换需升 schema 版本并经冲突预检重新评估）。
const (
	botReservedNamespace  = "/_wdsp/bot/v1/"
	botReservedVerifyPath = "/_wdsp/bot/v1/verify"
)

// 路由保留状态机（route_reservation.state，版本化配置）。
const (
	botReservationEnabled   = "ENABLED"
	botReservationTombstone = "RESERVED_TOMBSTONE"
	botReservationReleased  = "RELEASED"
)

// 校验边界（B0 冻结默认值与上下界；与 server/internal/botpolicy 逐条对应）。
const (
	botMaxSelectors       = 64
	botMaxSelectorPathLen = 512
	botMaxSignalRules     = 32
	botMinGroups          = 2
	botMaxGroups          = 3
	botMinWindowSeconds   = 30
	botMaxWindowSeconds   = 3600
	// 挑战参数（0 = 未显式下发，按默认值兜底后复检边界；任务书 §5.2 建议初值）
	botDefaultNonceTTL     = 90
	botMinNonceTTL         = 30
	botMaxNonceTTL         = 300
	botDefaultClearanceTTL = 900
	botMinClearanceTTL     = 60
	botMaxClearanceTTL     = 3600
	botDefaultDifficulty   = 14
	botMinDifficulty       = 10
	botMaxDifficulty       = 18
	botDefaultMaxAttempts  = 3
	botMinMaxAttempts      = 1
	botMaxMaxAttempts      = 5
	botMaxRuleWeight       = 10
)

// 规则 ID / key_ref 词形（与 server 侧同一正则）。
var (
	botRuleIDPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	botKeyRefPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	botValidUAClasses = map[string]bool{
		"BOT": true, "APPLICATION": true, "SERVICE": true, "AGENT": true, "UNKNOWN": true,
	}
	botValidParamMethods = map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true,
		"HEAD": true, "OPTIONS": true, "TRACE": true, "CONNECT": true,
	}
)

// botMetricSpec 指标规格（B0 冻结：组归属、参数键白名单、阈值语义；未知指标拒绝）。
type botMetricSpec struct {
	group     string
	paramKeys []string
	threshold string // ratio_gte | ratio_lte | count_gte | none
}

// botMetricSpecs 指标白名单（与 server/internal/botpolicy.metricSpecs 同表）。
var botMetricSpecs = map[string]botMetricSpec{
	"status_family_ratio":     {group: "request_behavior", paramKeys: []string{"family"}, threshold: "ratio_gte"},
	"method_ratio":            {group: "request_behavior", paramKeys: []string{"method"}, threshold: "ratio_gte"},
	"uri_concentration":       {group: "request_behavior", paramKeys: nil, threshold: "ratio_gte"},
	"known_uri_ratio":         {group: "access_sequence", paramKeys: nil, threshold: "ratio_lte"},
	"method_enumeration_size": {group: "access_sequence", paramKeys: nil, threshold: "count_gte"},
	"ua_class_match":          {group: "client_claim", paramKeys: []string{"class"}, threshold: "none"},
	"tls_client_hint":         {group: "client_claim", paramKeys: []string{"equals", "field"}, threshold: "none"},
}

// botPolicyJSON 发布通道下发 bot_policy 处理器段（json tag 为跨分片契约，不得改动；
// 与 server/internal/gatewayconfig.GuardBotPolicy 同形）。
type botPolicyJSON struct {
	SchemaVersion    int                     `json:"schema_version"`
	ApplicationID    string                  `json:"application_id"`
	Mode             string                  `json:"mode"` // OFF | OBSERVE | PROTECT
	Version          int                     `json:"version"`
	Selectors        []botSelectorJSON       `json:"selectors"`
	SignalRules      botSignalRulesJSON      `json:"signal_rules"`
	Challenge        botChallengeJSON        `json:"challenge"`
	RouteReservation botRouteReservationJSON `json:"route_reservation"`
	// SigningKeys Bot 挑战签名密钥（B3 预备：key_ref → 密钥材料 hex，由发布通道
	// 密钥注入并入段内；策略本体不含秘密材料）。密钥材料绝不落日志/事件；
	// 装配期经 assembleBotKeyring 构造 botchallenge.Keyring（current=challenge.key_ref，
	// 其余为轮换窗口 previous），OBSERVE 缺密钥不强制（不签名），PROTECT 缺密钥
	// fail-closed 拒绝加载（与发布侧就绪门禁同一口径，任务书 §5.4 末段）。
	SigningKeys map[string]string `json:"signing_keys,omitempty"`

	// keyring 装配产物（非配置字段，不参与 JSON 序列化；nil = OFF/未下发密钥/
	// OBSERVE 无 key_ref；B3 由 assembleBotService 消费构造挑战服务）。
	keyring *botchallenge.Keyring
}

type botSelectorJSON struct {
	PathExact  string `json:"path_exact,omitempty"`
	PathPrefix string `json:"path_prefix,omitempty"`
}

type botSignalRuleJSON struct {
	ID            string            `json:"id"`
	Group         string            `json:"group"`
	Metric        string            `json:"metric"`
	Params        map[string]string `json:"params,omitempty"`
	WindowSeconds int               `json:"window_seconds"`
	Weight        float64           `json:"weight"`
	Threshold     float64           `json:"threshold"`
}

type botSignalRulesJSON struct {
	MinIndependentGroups int                 `json:"min_independent_groups"`
	RequireBehaviorGroup bool                `json:"require_behavior_group"`
	Rules                []botSignalRuleJSON `json:"rules"`
}

type botChallengeJSON struct {
	Type                string `json:"type"` // 仅 JS
	NonceTTLSeconds     int    `json:"nonce_ttl_seconds"`
	ClearanceTTLSeconds int    `json:"clearance_ttl_seconds"`
	Difficulty          int    `json:"difficulty"`
	MaxAttempts         int    `json:"max_attempts"`
	KeyRef              string `json:"key_ref,omitempty"`
}

type botRouteReservationJSON struct {
	State     string `json:"state"`
	Namespace string `json:"namespace"`
}

// parseBotPolicySection 严格解码 bot_policy 段并校验结构版本与强制语义。
// 任何不理解的内容都拒绝加载（fail-closed），绝不静默忽略——与 jwt_trust 同一纪律。
func parseBotPolicySection(raw json.RawMessage) (*botPolicyJSON, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// 显式例外：guard 其他段容忍未知字段（前向兼容），bot_policy 不行——
	// 未知字段可能携带本网关不理解的强制语义
	dec.DisallowUnknownFields()
	var sec botPolicyJSON
	if err := dec.Decode(&sec); err != nil {
		return nil, fmt.Errorf("bot_policy: 配置结构解析失败（拒绝加载）: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("bot_policy: 配置含多余内容（拒绝加载）")
	}
	if sec.SchemaVersion != botPolicySchemaVersion {
		return nil, fmt.Errorf("bot_policy: 不支持的 schema_version %d（本网关支持 %d；拒绝加载而非忽略强制语义）",
			sec.SchemaVersion, botPolicySchemaVersion)
	}
	switch sec.Mode {
	case botModeOff, botModeObserve, botModeProtect:
	default:
		return nil, fmt.Errorf("bot_policy: 未知强制语义 mode=%q（拒绝加载）", sec.Mode)
	}
	return &sec, nil
}

// applyBotChallengeDefaults 挑战参数默认值兜底（0 = 未显式下发；发布侧恒下发显式值，
// 0 兜底仅为容错最小发布面；默认值应用后再做边界复检）。
func applyBotChallengeDefaults(c *botChallengeJSON) {
	if c.Type == "" {
		c.Type = "JS"
	}
	if c.NonceTTLSeconds == 0 {
		c.NonceTTLSeconds = botDefaultNonceTTL
	}
	if c.ClearanceTTLSeconds == 0 {
		c.ClearanceTTLSeconds = botDefaultClearanceTTL
	}
	if c.Difficulty == 0 {
		c.Difficulty = botDefaultDifficulty
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = botDefaultMaxAttempts
	}
}

// validateBotPolicy 完整结构校验（B0 冻结口径，与 server 侧 validate.go 逐条对应；
// 即使 mode=OFF 也全量校验——配置面与管理面同口径，避免「保存合法、网关拒载」分叉）。
// 返回全部字段错误（errors.Join 聚合），空切片 = 通过。
func validateBotPolicy(sec *botPolicyJSON) []error {
	errs := []error{}
	add := func(format string, args ...interface{}) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	validateBotSelectors(sec, add)
	validateBotSignalRules(sec, add)
	validateBotChallenge(sec, add)
	validateBotRouteReservation(sec, add)
	validateBotSigningKeys(sec, add)
	return errs
}

// validateBotSigningKeys 签名密钥结构校验（B3 预备：key_id 词形 + hex 解码 +
// 密钥材料 ≥32 字节，与 botchallenge.NewKeyring 同一口径；错误信息只含 key_id
// 与长度，绝不含密钥材料）。缺省（未下发 signing_keys）不在此报错——
// PROTECT 缺密钥的强制语义由 assembleBotKeyring fail-closed 判定。
func validateBotSigningKeys(sec *botPolicyJSON, add func(string, ...interface{})) {
	for id, hexKey := range sec.SigningKeys {
		if !botKeyRefPattern.MatchString(id) {
			add("signing_keys: 非法 key_id %q（仅 [a-z0-9._-] 引用名，禁止路径/URL 形态）", id)
			continue
		}
		key, err := hex.DecodeString(strings.TrimSpace(hexKey))
		if err != nil {
			add("signing_keys[%q]: 密钥材料非合法 hex", id)
			continue
		}
		if len(key) < 32 {
			add("signing_keys[%q]: 密钥材料过短（%d < 32 字节）", id, len(key))
		}
	}
}

// assembleBotKeyring 由 signing_keys 构造签名密钥环（B3 预备）：
//   - current = challenge.key_ref 引用的密钥；其余按 key_id 升序作为轮换窗口 previous
//     （旧通行在 clearance_ttl 内仍可验签，紧急撤销经 policy_epoch 正交生效）；
//   - PROTECT：key_ref 为空或未在已下发密钥集合中就绪 → fail-closed 拒绝加载
//     （与 server 侧发布就绪门禁同一口径——宁可拒载也不发布必然全站 503 的配置）；
//   - OBSERVE：不签发挑战，缺密钥/空 key_ref/引用未就绪均不构建密钥环（返回 nil, nil），
//     不阻断观测。
func assembleBotKeyring(sec *botPolicyJSON) (*botchallenge.Keyring, error) {
	if len(sec.SigningKeys) == 0 {
		if sec.Mode == botModeProtect {
			return nil, fmt.Errorf("bot_policy: PROTECT 要求已下发签名密钥（signing_keys 为空；拒绝加载——无密钥时挑战/通行只能 fail-closed 503）")
		}
		return nil, nil
	}
	keys := make(map[string][]byte, len(sec.SigningKeys))
	for id, hexKey := range sec.SigningKeys {
		key, err := hex.DecodeString(strings.TrimSpace(hexKey))
		if err != nil || len(key) < 32 {
			// 结构校验已先行拦截；此处防御（不得携带密钥材料进错误信息）
			return nil, fmt.Errorf("bot_policy: signing_keys[%q] 密钥材料非法", id)
		}
		keys[id] = key
	}
	currentID := sec.Challenge.KeyRef
	if currentID == "" {
		if sec.Mode == botModeProtect {
			return nil, fmt.Errorf("bot_policy: PROTECT 要求 challenge.key_ref 引用已下发签名密钥（当前为空；拒绝加载）")
		}
		return nil, nil
	}
	cur, ok := keys[currentID]
	if !ok {
		if sec.Mode == botModeProtect {
			return nil, fmt.Errorf("bot_policy: PROTECT 的 challenge.key_ref %q 未在已下发签名密钥集合中就绪（拒绝加载——防新 key 未安装导致全站挑战故障）", currentID)
		}
		return nil, nil
	}
	prevIDs := make([]string, 0, len(keys)-1)
	for id := range keys {
		if id != currentID {
			prevIDs = append(prevIDs, id)
		}
	}
	sort.Strings(prevIDs)
	previous := make([]botchallenge.Key, 0, len(prevIDs))
	for _, id := range prevIDs {
		previous = append(previous, botchallenge.Key{ID: id, Secret: keys[id]})
	}
	kr, err := botchallenge.NewKeyring(botchallenge.Key{ID: currentID, Secret: cur}, previous...)
	if err != nil {
		return nil, fmt.Errorf("bot_policy: 签名密钥环构造失败（拒绝加载）: %w", err)
	}
	return kr, nil
}

// validateBotSelectors 选择器校验（仅 GET 浏览器文档导航——方法不出现在契约中；
// 路径精确/规范化前缀二选一；禁止正则、百分号编码、全站通配与保留命名空间）。
func validateBotSelectors(sec *botPolicyJSON, add func(string, ...interface{})) {
	if len(sec.Selectors) > botMaxSelectors {
		add("selectors: 数量不能超过 %d", botMaxSelectors)
	}
	if sec.Mode != botModeOff && len(sec.Selectors) == 0 {
		add("selectors: 非 OFF 模式必须配置至少一条选择器")
	}
	for i, s := range sec.Selectors {
		hasExact := s.PathExact != ""
		hasPrefix := s.PathPrefix != ""
		if hasExact == hasPrefix {
			add("selectors[%d]: path_exact 与 path_prefix 必须且仅须提供一个", i)
			continue
		}
		path := s.PathExact
		if hasPrefix {
			path = s.PathPrefix
		}
		if !strings.HasPrefix(path, "/") {
			add("selectors[%d]: 路径必须以 / 开头", i)
			continue
		}
		if len(path) > botMaxSelectorPathLen {
			add("selectors[%d]: 路径长度不能超过 %d", i, botMaxSelectorPathLen)
		}
		if strings.ContainsAny(path, "?#") {
			add("selectors[%d]: 路径不得包含 query 或 fragment", i)
		}
		if botHasControlChars(path) {
			add("selectors[%d]: 路径不得包含控制字符", i)
		}
		if strings.Contains(path, "%") {
			add("selectors[%d]: 路径按解码后形式配置，不得包含百分号编码（避免双重编码歧义）", i)
		}
		for _, seg := range strings.Split(path, "/") {
			if seg == "." || seg == ".." {
				add("selectors[%d]: 路径不得包含 . 或 .. 段（避免规范化歧义）", i)
				break
			}
		}
		if hasPrefix {
			if path == "/" {
				add("selectors[%d]: path_prefix 不允许全站通配（/）；须给出具体前缀", i)
			} else if strings.HasSuffix(path, "/") {
				add("selectors[%d]: path_prefix 须按完整路径段给出，不应以 / 结尾", i)
			}
			// 前缀不得覆盖保留命名空间（按完整路径段匹配：p 覆盖 verify 当且仅当
			// p==verifyPath 或 verifyPath 以 p+"/" 开头）
			if botReservedVerifyPath == path || strings.HasPrefix(botReservedVerifyPath, path+"/") {
				add("selectors[%d]: path_prefix 不得覆盖 Bot 保留命名空间 %s", i, botReservedNamespace)
			}
		} else if path == botReservedVerifyPath || strings.HasPrefix(path, botReservedNamespace) {
			add("selectors[%d]: path_exact 不得落入 Bot 保留命名空间 %s", i, botReservedNamespace)
		}
	}
}

// validateBotSignalRules 信号规则校验（组/指标白名单、窗口/权重/阈值上下界、
// 同源计数派生指标不重复计权、PROTECT 组覆盖充分性——配置的信号组数达不到
// min_independent_groups 或缺少行为组时策略永远无法提出挑战，属配置错误）。
func validateBotSignalRules(sec *botPolicyJSON, add func(string, ...interface{})) {
	sr := sec.SignalRules
	if sr.MinIndependentGroups < botMinGroups || sr.MinIndependentGroups > botMaxGroups {
		add("signal_rules.min_independent_groups: 必须在 %d~%d 之间（B0：提出挑战需至少 %d 个独立信号组）",
			botMinGroups, botMaxGroups, botMinGroups)
	}
	if !sr.RequireBehaviorGroup {
		add("signal_rules.require_behavior_group: 必须为 true（B0：至少 1 个行为观测组；声明组为可伪造弱信号，不能单独构成挑战依据）")
	}
	if len(sr.Rules) > botMaxSignalRules {
		add("signal_rules.rules: 信号规则数量不能超过 %d", botMaxSignalRules)
	}
	if sec.Mode != botModeOff && len(sr.Rules) == 0 {
		add("signal_rules.rules: 非 OFF 模式必须配置至少一条信号规则")
	}

	seenID := map[string]bool{}
	seenSource := map[string]string{} // 同源计数指纹（group|metric|canonical params）→ 规则 ID
	groups := map[string]bool{}
	for i, r := range sr.Rules {
		if !botRuleIDPattern.MatchString(r.ID) {
			add("signal_rules.rules[%d].id: 规则 ID 须为小写字母开头的小写字母/数字/下划线（1~64 字符）", i)
		} else if seenID[r.ID] {
			add("signal_rules.rules[%d].id: 规则 ID 在策略内必须唯一: %s", i, r.ID)
		}
		seenID[r.ID] = true

		spec, ok := botMetricSpecs[r.Metric]
		if !ok {
			add("signal_rules.rules[%d].metric: 未知信号指标: %s", i, r.Metric)
			continue
		}
		if r.Group != spec.group {
			add("signal_rules.rules[%d].group: 指标 %s 属于信号组 %s，实际: %s", i, r.Metric, spec.group, r.Group)
		}
		groups[spec.group] = true

		validateBotRuleParams(r, spec, i, add)

		if r.WindowSeconds < botMinWindowSeconds || r.WindowSeconds > botMaxWindowSeconds {
			add("signal_rules.rules[%d].window_seconds: 必须在 %d~%d 秒之间", i, botMinWindowSeconds, botMaxWindowSeconds)
		}
		if r.Weight <= 0 || r.Weight > botMaxRuleWeight {
			add("signal_rules.rules[%d].weight: 必须在 (0,%d] 之间（组满足 = 组内已触发权重和 ≥1）", i, botMaxRuleWeight)
		}
		switch spec.threshold {
		case "ratio_gte":
			if r.Threshold <= 0 || r.Threshold > 1 {
				add("signal_rules.rules[%d].threshold: 占比类指标阈值必须在 (0,1] 之间（≥ 阈值触发）", i)
			}
		case "ratio_lte":
			if r.Threshold < 0 || r.Threshold >= 1 {
				add("signal_rules.rules[%d].threshold: known_uri_ratio 阈值必须在 [0,1) 之间（≤ 阈值触发）", i)
			}
		case "count_gte":
			if r.Threshold < 1 || r.Threshold > 100 {
				add("signal_rules.rules[%d].threshold: 计数类指标阈值必须在 1~100 之间（≥ 阈值触发）", i)
			}
		case "none":
			if r.Threshold != 0 {
				add("signal_rules.rules[%d].threshold: 声明匹配类指标命中即触发，threshold 必须为 0", i)
			}
		}

		// 同源计数派生指标不重复计权（同 group+metric+规范化 params 视为同一计数源）
		fp := r.Group + "|" + r.Metric + "|" + botCanonicalParams(r.Params)
		if dup, ok := seenSource[fp]; ok {
			add("signal_rules.rules[%d]: 与规则 %s 同源（同组同指标同参数），派生指标不重复计权", i, dup)
		} else {
			seenSource[fp] = r.ID
		}
	}

	if sec.Mode == botModeProtect {
		if len(groups) < sr.MinIndependentGroups {
			add("signal_rules.rules: PROTECT 要求已配置信号覆盖至少 %d 个独立信号组，当前 %d 个",
				sr.MinIndependentGroups, len(groups))
		}
		hasBehavior := groups["request_behavior"] || groups["access_sequence"]
		if !hasBehavior {
			add("signal_rules.rules: PROTECT 要求至少配置 1 个行为组（request_behavior / access_sequence）规则")
		}
	}
}

// validateBotRuleParams 指标参数校验（允许键白名单 + 取值约束；未知/缺失键拒绝）。
func validateBotRuleParams(r botSignalRuleJSON, spec botMetricSpec, idx int, add func(string, ...interface{})) {
	if len(spec.paramKeys) == 0 && len(r.Params) > 0 {
		add("signal_rules.rules[%d].params: 该指标不接受参数", idx)
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
			add("signal_rules.rules[%d].params: 未知参数键: %s", idx, k)
		}
	}
	for _, k := range spec.paramKeys {
		v, ok := r.Params[k]
		if !ok || v == "" {
			add("signal_rules.rules[%d].params.%s: 缺少必需参数: %s", idx, k, k)
			continue
		}
		switch k {
		case "family":
			if v != "2xx" && v != "3xx" && v != "4xx" && v != "5xx" {
				add("signal_rules.rules[%d].params.family: 状态码族仅支持 2xx/3xx/4xx/5xx", idx)
			}
		case "method":
			if !botValidParamMethods[v] {
				add("signal_rules.rules[%d].params.method: 非法 HTTP 方法: %s", idx, v)
			}
		case "class":
			if !botValidUAClasses[v] {
				add("signal_rules.rules[%d].params.class: UA 分类仅支持 BOT/APPLICATION/SERVICE/AGENT/UNKNOWN（可伪造弱信号）", idx)
			}
		case "field":
			if v != "version" && v != "cipher_suite" {
				add("signal_rules.rules[%d].params.field: TLS 轻量特征字段仅支持 version/cipher_suite", idx)
			}
		case "equals":
			if len(v) > 128 || botHasControlChars(v) {
				add("signal_rules.rules[%d].params.equals: 比对值须为长度 1~128 的无控制字符字符串", idx)
			}
		}
	}
}

// validateBotChallenge 挑战参数校验（仅 JS 类型；B0 冻结上下界；
// key_ref 仅为引用名——任何密钥材料不得出现在配置中）。
func validateBotChallenge(sec *botPolicyJSON, add func(string, ...interface{})) {
	c := sec.Challenge
	if c.Type != "JS" {
		add("challenge.type: 仅支持 JS（第一方 JavaScript 挑战，无外部服务依赖）")
	}
	if c.NonceTTLSeconds < botMinNonceTTL || c.NonceTTLSeconds > botMaxNonceTTL {
		add("challenge.nonce_ttl_seconds: 必须在 %d~%d 秒之间（默认 %d）", botMinNonceTTL, botMaxNonceTTL, botDefaultNonceTTL)
	}
	if c.ClearanceTTLSeconds < botMinClearanceTTL || c.ClearanceTTLSeconds > botMaxClearanceTTL {
		add("challenge.clearance_ttl_seconds: 必须在 %d~%d 秒之间（默认 %d）", botMinClearanceTTL, botMaxClearanceTTL, botDefaultClearanceTTL)
	}
	if c.Difficulty < botMinDifficulty || c.Difficulty > botMaxDifficulty {
		add("challenge.difficulty: 必须在 %d~%d bit 之间（默认 %d）", botMinDifficulty, botMaxDifficulty, botDefaultDifficulty)
	}
	if c.MaxAttempts < botMinMaxAttempts || c.MaxAttempts > botMaxMaxAttempts {
		add("challenge.max_attempts: 必须在 %d~%d 次之间（默认 %d）", botMinMaxAttempts, botMaxMaxAttempts, botDefaultMaxAttempts)
	}
	if c.KeyRef != "" && !botKeyRefPattern.MatchString(c.KeyRef) {
		add("challenge.key_ref: 非法密钥引用名（小写字母/数字/._-，小写字母或数字开头，1~64 字符；仅引用名，不接受密钥材料）")
	}
}

// validateBotRouteReservation 路由保留状态校验（状态机 + 命名空间冻结 +
// PROTECT 一致性：挑战路由必须注册）。
func validateBotRouteReservation(sec *botPolicyJSON, add func(string, ...interface{})) {
	rr := sec.RouteReservation
	switch rr.State {
	case botReservationEnabled, botReservationTombstone, botReservationReleased:
	default:
		add("route_reservation.state: 仅支持 ENABLED / RESERVED_TOMBSTONE / RELEASED")
	}
	if rr.Namespace != botReservedNamespace {
		add("route_reservation.namespace: 保留命名空间固定为 %s（更换需升 schema 版本）", botReservedNamespace)
	}
	if sec.Mode == botModeProtect && rr.State != botReservationEnabled {
		add("route_reservation.state: PROTECT 要求 ENABLED（挑战/verify 路由必须注册；从已启用状态关闭请使用 RESERVED_TOMBSTONE 保留墓碑）")
	}
}

// botCanonicalParams 参数规范化指纹（键序稳定拼接，供同源计权去重；
// 与 server 侧 canonicalParams 同口径）。
func botCanonicalParams(params map[string]string) string {
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

// botHasControlChars 控制字符检测（防注入）。
func botHasControlChars(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// parseAndValidateBotPolicy 解析 + 默认值兜底 + 全量校验 + 签名密钥环装配
// （Provision 与 Validate 共用；任一失败即拒绝整体配置加载——fail-closed；
// 密钥环装配含 PROTECT 密钥就绪判定，Validate 路径同口径拒载）。
func parseAndValidateBotPolicy(raw json.RawMessage) (*botPolicyJSON, error) {
	sec, err := parseBotPolicySection(raw)
	if err != nil {
		return nil, err
	}
	applyBotChallengeDefaults(&sec.Challenge)
	if errs := validateBotPolicy(sec); len(errs) > 0 {
		return nil, fmt.Errorf("bot_policy: 配置校验未通过（拒绝加载）: %w", errors.Join(errs...))
	}
	kr, err := assembleBotKeyring(sec)
	if err != nil {
		return nil, err
	}
	sec.keyring = kr
	return sec, nil
}

// assembleBotPolicy 装配 Bot 挑战策略（Provision 调用）：解析/校验失败拒绝整体配置
// 加载（fail-closed，已存在 PROTECT 策略不得被静默删除/降级）；段缺失 = 零行为变化
// （发布通道对 OFF 也下发以覆盖旧配置残留）。
//
// 解析产物（含签名密钥环 sec.keyring）总是保留在 g.botPolicy——OFF + RESERVED_TOMBSTONE
// 需要段内容维持 verify 命名空间本地墓碑（防旧挑战提交落入业务源站）；OFF 不构造挑战
// 服务（不初始化签名/状态依赖），非 OFF 经 assembleBotService 装配请求链服务（B3）。
func (g *Guard) assembleBotPolicy() error {
	if len(g.BotPolicy) == 0 {
		return nil
	}
	sec, err := parseAndValidateBotPolicy(g.BotPolicy)
	if err != nil {
		return err
	}
	g.botPolicy = sec
	if g.logger != nil {
		fields := []zap.Field{
			zap.String("app_id", sec.ApplicationID),
			zap.String("mode", sec.Mode),
			zap.Int("policy_version", sec.Version),
			zap.Int("selectors", len(sec.Selectors)),
			zap.Int("signal_rules", len(sec.SignalRules.Rules)),
			zap.String("route_reservation", sec.RouteReservation.State),
		}
		if sec.keyring != nil {
			// 仅引用名与数量（密钥材料绝不落日志）
			fields = append(fields,
				zap.String("signing_key_id", sec.keyring.Current().ID),
				zap.Int("signing_keys", len(sec.keyring.KeyIDs())))
		}
		g.logger.Info("bot policy loaded", fields...)
	}
	if sec.Mode == botModeOff {
		// OFF：不初始化挑战依赖（墓碑由请求链按保留段内容本地处理）
		return nil
	}
	return g.assembleBotService(sec)
}

// assembleBotService 装配 Bot 挑战请求链服务（B3；非 OFF 模式）：
//   - 状态存储/限速器复用共享引擎（engine.valkey / engine.limiter）；Valkey 客户端
//     缺失（如 counter_backend=memory）时：PROTECT fail-closed 拒绝整体配置加载
//     （挑战/验通行必然 503 的配置宁可拒载，与发布门禁同口径），OBSERVE 降级为
//     仅装配持有 + Warn（观测不阻断请求链，verify 命名空间按依赖缺失墓碑处理）；
//   - 签名密钥环缺失时同理（PROTECT 在 assembleBotKeyring 已 fail-closed，此处防御；
//     OBSERVE 不签名不强制）。
func (g *Guard) assembleBotService(sec *botPolicyJSON) error {
	degrade := func(reason string) error {
		if sec.Mode == botModeProtect {
			return fmt.Errorf("bot_policy: PROTECT 挑战服务依赖缺失（%s；拒绝加载——宁可拒载也不发布必然 fail-closed 503 的配置）", reason)
		}
		if g.logger != nil {
			g.logger.Warn("bot policy OBSERVE degraded: challenge service unavailable（仅装配持有，请求链零行为变化）",
				zap.String("app_id", sec.ApplicationID),
				zap.String("reason", reason))
		}
		return nil
	}
	if g.engine == nil || g.engine.valkey == nil {
		return degrade("valkey client unavailable")
	}
	if sec.keyring == nil {
		return degrade("signing keyring unavailable")
	}
	svc, err := botchallenge.NewService(botchallenge.Config{
		AppID:         sec.ApplicationID,
		AppCode:       g.AppCode,
		Mode:          sec.Mode,
		PolicyVersion: sec.Version,
		NonceTTL:      time.Duration(sec.Challenge.NonceTTLSeconds) * time.Second,
		ClearanceTTL:  time.Duration(sec.Challenge.ClearanceTTLSeconds) * time.Second,
		Difficulty:    sec.Challenge.Difficulty,
		MaxAttempts:   sec.Challenge.MaxAttempts,
		KeyRef:        sec.Challenge.KeyRef,
		Keyring:       sec.keyring,
		Store:         botchallenge.NewStore(g.engine.valkey, ""),
		Limiter:       g.engine.limiter,
		Sink:          g.events,
		Node:          g.GatewayNode,
		Logger:        g.logger,
	})
	if err != nil {
		return fmt.Errorf("bot_policy: 挑战服务构造失败（拒绝加载）: %w", err)
	}
	g.botSvc = svc
	return nil
}
