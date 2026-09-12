// stage.go 攻击阶段推断（WDSP AI 自动化渗透防护增强 阶段4；设计 #16.2）。
// 纯函数有序规则表：第一阶段只允许基于规则简单推断，不做 AI 攻击链推理。
// 会话 attack_stage 取成员事件阶段最高值，秩序：
//
//	UNKNOWN(0) < RECON(1) < DISCOVERY(2) < AUTH_PROBE(3) < AUTHORIZATION_PROBE(4)
//	< EXPLOIT(5) < DATA_ACCESS(6) < PERSISTENCE(7，仅枚举占位，本期无规则产生)
package attacksessions

import (
	"encoding/json"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// parseDetectorMatches 解析 api_runtime_events.details_json（[]DetectorMatch；
// 坏 JSON 按无明细处理——采集侧契约外的脏数据不阻断聚合，阶段 UNKNOWN 兜底）。
func parseDetectorMatches(raw []byte) []dsctx.DetectorMatch {
	if len(raw) == 0 {
		return nil
	}
	var matches []dsctx.DetectorMatch
	if err := json.Unmarshal(raw, &matches); err != nil {
		return nil
	}
	return matches
}

// 攻击阶段枚举（迁移 000103 CHECK 八值）。
const (
	StageUnknown            = "UNKNOWN"
	StageRecon              = "RECON"
	StageDiscovery          = "DISCOVERY"
	StageAuthProbe          = "AUTH_PROBE"
	StageAuthorizationProbe = "AUTHORIZATION_PROBE"
	StageExploit            = "EXPLOIT"
	StageDataAccess         = "DATA_ACCESS"
	// StagePersistence 仅占位：设计 #16.2 枚举要求，本期无任何推断规则产生。
	StagePersistence = "PERSISTENCE"
)

// validStages 会话/事件阶段合法值（查询筛选校验用）。
var validStages = map[string]bool{
	StageRecon: true, StageDiscovery: true, StageAuthProbe: true,
	StageAuthorizationProbe: true, StageExploit: true, StageDataAccess: true,
	StagePersistence: true, StageUnknown: true,
}

// stageRank 阶段秩（会话阶段取成员事件最高值；未知值按 UNKNOWN 处理）。
func stageRank(s string) int {
	switch s {
	case StagePersistence:
		return 7
	case StageDataAccess:
		return 6
	case StageExploit:
		return 5
	case StageAuthorizationProbe:
		return 4
	case StageAuthProbe:
		return 3
	case StageDiscovery:
		return 2
	case StageRecon:
		return 1
	default:
		return 0
	}
}

// MaxStage 返回两阶段中秩高者（会话增量维护用；秩相同偏好后者无副作用）。
func MaxStage(a, b string) string {
	if stageRank(b) > stageRank(a) {
		return b
	}
	return a
}

// behaviorRuleStageRules identity_behavior_events.rule_code → 阶段（有序，先中先得）。
// 侦察六规则（RECON-URI-001/RECON-404-001/RECON-PATH-001/RECON-METHOD-001/
// RECON-PARAM-001/RECON-LOWSLOW-001，网关 identitybehavior/recon.go 契约）统一
// RECON- 前缀命中；AUTH-FAIL-001 为认证失败探测。
// BIZ-* 为本期 Business 滥用检测产出（businesssec.go；设计 #12.2/#13）：
// 登录滥用归 AUTH_PROBE（同身份多账号认证失败探测语义）、导出滥用归 DATA_ACCESS
// （批量数据导出语义）、对象枚举归 AUTHORIZATION_PROBE（#13 OBJECT_ENUMERATION
// 即 BOLA 自动化探测行为）。
var behaviorRuleStageRules = []struct {
	prefix string
	stage  string
}{
	{"RECON-", StageRecon},
	{"AUTH-FAIL-", StageAuthProbe},
	{"BIZ-LOGIN-", StageAuthProbe},
	{"BIZ-EXPORT-", StageDataAccess},
	{"BIZ-OBJENUM-", StageAuthorizationProbe},
}

// StageForBehaviorRule 行为事件规则码 → 阶段（未知规则 UNKNOWN 兜底）。
func StageForBehaviorRule(ruleCode string) string {
	for _, r := range behaviorRuleStageRules {
		if strings.HasPrefix(ruleCode, r.prefix) {
			return r.stage
		}
	}
	return StageUnknown
}

// runtimeStageRule api_runtime_events.details_json 单条命中明细 → 阶段（有序，先中先得；
// 按从高到低阶段排布，保证同一命中取最强解释）。规则依据：
//   - DISCOVERY：findings SHADOW/DEPRECATED（lifecycle.new_endpoint /
//     lifecycle.deprecated_api_call，apiruntime findings.go 语义覆盖表同口径）；
//   - AUTH_PROBE：auth.* 系（detector=authentication，网关 detectors/authentication.go 实名）；
//   - AUTHORIZATION_PROBE：BOLA_UNAUTHENTICATED_OBJECT_ACCESS
//     （detector=resource_access + resource.unauthenticated_object_access）；
//   - EXPLOIT：SCHEMA_*（detector=api_schema）、api_parser 系、waf 明细；
//   - DATA_ACCESS：请求中携带真实敏感取值（detector=sensitive_data 且
//     rule_id=sensitive.value，正则命中身份证/手机号等实值——携带他人敏感实值探测
//     语义接近数据获取）；sensitive.field/sensitive.in_query 仅字段名命中（正常
//     登录携带 password 字段即触发），不构成杀伤链阶段证据，不抬升阶段。
var runtimeStageRules = []struct {
	detector string // 空 = 不限定检测器
	ruleID   string // 空 = 不限定规则
	stage    string
}{
	{"sensitive_data", "sensitive.value", StageDataAccess},
	{"api_schema", "", StageExploit},
	{"api_parser", "", StageExploit},
	{"waf", "", StageExploit},
	{"resource_access", "resource.unauthenticated_object_access", StageAuthorizationProbe},
	{"authentication", "", StageAuthProbe},
	{"lifecycle", "lifecycle.new_endpoint", StageDiscovery},
	{"lifecycle", "lifecycle.deprecated_api_call", StageDiscovery},
}

// StageForRuntimeDetails api_runtime_events.details_json → 阶段：
// 逐条命中按有序规则表取阶段，全明细取最高秩（无任何可解释明细 UNKNOWN 兜底）。
func StageForRuntimeDetails(details []dsctx.DetectorMatch) string {
	stage := StageUnknown
	for _, m := range details {
		for _, r := range runtimeStageRules {
			if r.detector != "" && m.Detector != r.detector {
				continue
			}
			if r.ruleID != "" && m.RuleID != r.ruleID {
				continue
			}
			stage = MaxStage(stage, r.stage)
			break
		}
	}
	return stage
}

// StageForSecurityEvent security_events 行 → 阶段：攻击检测命中即利用阶段
// （attack_type 仅作分类，不降级；空类型按 UNKNOWN 兜底）。
func StageForSecurityEvent(attackType string) string {
	if strings.TrimSpace(attackType) == "" {
		return StageUnknown
	}
	return StageExploit
}
