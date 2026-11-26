package accesscontrolevents

import (
	"fmt"
	"strings"
	"time"
)

const csvUTF8BOM = "\xef\xbb\xbf"

const acEventsExportHeader = "发生时间,请求 ID,应用编码,客户端 IP,连接 IP,域名,请求方法,请求路径,事件类型,动作,策略 ID,规则 ID,当前计数,阈值,统计窗口（秒）,响应状态码,网关节点,消息"

// acEventTypeLabels 访问控制事件类型中文映射（与 web/src/utils/stage5.ts AC_EVENT_TYPE_META 完整对齐，覆盖全部 36 项）。
var acEventTypeLabels = map[string]string{
	EventTypeIPAllowMatch:         "命中 IP 白名单",
	EventTypeURLAllowMatch:        "命中 URL 白名单",
	EventTypeIPDenyMatch:          "命中 IP 黑名单",
	EventTypeCCThresholdExceeded:  "频率超阈值",
	EventTypeCCRequestRejected:    "频率请求被拒绝",
	EventTypeCCTempBlockCreated:   "频率临时封禁创建",
	EventTypeCCTempBlockExpired:   "频率临时封禁到期",
	EventTypeCCTempBlockReleased:  "频率临时封禁解除",
	EventTypeCCTempBlockDowngraded: "频率临时封禁降级",
	"TRUSTED_PROXY_INVALID":       "可信代理无效",
	"FORWARDED_HEADER_INVALID":    "转发头无效",
	"FORWARDED_CHAIN_TOO_LONG":    "转发链过长",
	"RATE_LIMIT_ENGINE_ERROR":     "限速引擎错误",
	EventTypeL7RuleAllow:          "L7规则放行",
	EventTypeL7RuleBlock:          "L7规则阻断",
	EventTypeL7RuleRedirect:       "L7规则重定向",
	EventTypeL7RuleCustom:         "L7自定义页面",
	"IDENTITY_MANUAL_BLOCK":       "身份手工封禁",
	EventTypeRiskPolicyBlock:      "风险策略阻断",
	EventTypeRiskPolicyRateLimit:  "风险策略限速",
	EventTypeRiskPolicyChallenge:  "风险策略挑战",
	EventTypeJWTObserved:          "JWT 校验观察",
	EventTypeJWTAuthFailed:        "JWT 认证失败",
	EventTypeJWTUnavailable:       "JWT 服务不可用",
	EventTypeBotChallengeOffered:  "Bot 挑战下发",
	EventTypeBotVerifySuccess:     "Bot 挑战验证通过",
	EventTypeBotVerifyRejected:    "Bot 挑战验证拒绝",
	EventTypeBotChallengeExpired:  "Bot 挑战已过期",
	EventTypeBotStateUnavailable:  "Bot 状态存储不可用",
	EventTypeBotClearanceAccepted: "Bot 通行凭据有效",
	"MID_VERIFIED":                "机器身份验签通过",
	"MID_OBSERVED":                "机器身份观察",
	"MID_AUTH_FAILED":             "机器身份认证失败",
	"MID_UNAVAILABLE":             "机器身份服务不可用",
	"MID_SCOPE_DENIED":                      "机器身份越权拒绝",
	"MID_BOT_EXEMPT":                        "机器身份豁免 Bot 挑战",
	EventTypeClientSideScriptObserved:       "客户端脚本观测",
	EventTypeClientSideUnauthorizedScript:   "客户端未授权脚本",
	EventTypeClientSideScriptTampered:       "客户端脚本篡改",
	EventTypeClientSideCSPViolation:         "客户端 CSP 违规",
	EventTypeClientSideProbeAlert:           "客户端探针告警",
	EventTypeA2AAgentCardDiscovered:         "A2A Agent 发现",
	EventTypeA2AObserved:                    "A2A 安全观测",
	EventTypeA2ABlocked:                     "A2A 安全阻断",
	EventTypeA2ALoopKilled:                  "A2A 递归循环熔断",
	EventTypeA2ALethalTrifecta:              "A2A 致命三要素拦截",
	EventTypeSemanticObserved:               "语义安全观测",
	EventTypeSemanticBlocked:                "语义安全阻断",
	EventTypeSemanticUnavailable:            "语义服务不可用",
	EventTypeWasmPluginObserved:             "Wasm 插件观测",
	EventTypeWasmPluginBlock:                "Wasm 插件阻断",
	EventTypeWasmPluginRateLimit:            "Wasm 插件限速",
	EventTypeWasmPluginError:                "Wasm 插件执行异常",
}

// acEventActionLabels 访问控制事件动作中文映射（与 web/src/utils/stage5.ts AC_EVENT_ACTION_META 对齐，
// 并补齐网关实际发出的 DENY / CONNECTION_FALLBACK / IGNORED / ENGINE_ERROR）。
var acEventActionLabels = map[string]string{
	"ALLOW":               "放行",
	"BLOCK":               "阻断",
	"DENY":                "拒绝",
	ActionLog:             "仅记录",
	ActionObserve:         "观察",
	"REDIRECT":            "重定向",
	"CUSTOM_PAGE":         "自定义页面",
	ActionReject:          "拒绝",
	ActionChallenge:       "挑战",
	ActionTempBlock:       "临时封禁",
	"PASS":                "放行",
	"CONNECTION_FALLBACK": "回退连接 IP",
	"IGNORED":             "已忽略",
	"ENGINE_ERROR":        "引擎异常",
	"RATE_LIMIT":          "限速",
	"blocked":             "已阻断",
	"would_block":         "拟阻断（观察）",
	"challenged":          "已挑战",
	"would_challenge":     "拟挑战（观察）",
	"rate_limited":        "已限速",
	"would_rate_limit":    "拟限速（观察）",
}

func formatACEventType(v string) string {
	if v == "" {
		return ""
	}
	if label, ok := acEventTypeLabels[v]; ok {
		return label
	}
	if label, ok := acEventTypeLabels[strings.ToUpper(strings.TrimSpace(v))]; ok {
		return label
	}
	return v
}

func formatACEventAction(v string) string {
	if v == "" {
		return ""
	}
	if label, ok := acEventActionLabels[v]; ok {
		return label
	}
	trimmed := strings.TrimSpace(v)
	if label, ok := acEventActionLabels[trimmed]; ok {
		return label
	}
	if label, ok := acEventActionLabels[strings.ToUpper(trimmed)]; ok {
		return label
	}
	if label, ok := acEventActionLabels[strings.ToLower(trimmed)]; ok {
		return label
	}
	return v
}

func renderExportCSV(list []Event) string {
	var b strings.Builder
	b.WriteString(csvUTF8BOM)
	b.WriteString(acEventsExportHeader + "\n")
	for _, e := range list {
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			e.OccurredAt.UTC().Format(time.RFC3339),
			csvCell(e.RequestID), csvCell(e.ApplicationCode), csvCell(e.ClientIP), csvCell(e.ConnectionIP),
			csvCell(e.Domain), csvCell(e.RequestMethod), csvCell(e.RequestPath),
			csvCell(formatACEventType(e.EventType)), csvCell(formatACEventAction(e.Action)),
			csvCell(e.PolicyID), csvCell(e.AccessRuleID),
			int64PtrStr(e.CurrentCount), int64PtrStr(e.LimitValue), intPtrStr(e.WindowSeconds),
			intPtrStr(e.ResponseStatus), csvCell(e.GatewayNodeID), csvCell(e.Message))
	}
	return b.String()
}
