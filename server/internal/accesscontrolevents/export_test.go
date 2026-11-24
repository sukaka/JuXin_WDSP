package accesscontrolevents

import (
	"strings"
	"testing"
	"time"
)

func TestRenderExportCSVChineseHeadersAndValues(t *testing.T) {
	ts := time.Date(2026, 11, 24, 16, 0, 0, 0, time.UTC)

	// 覆盖全部 36 项事件类型（与 web/src/utils/stage5.ts AC_EVENT_TYPE_META 对齐）
	eventTypeCases := []struct {
		code string
		want string
	}{
		{EventTypeIPAllowMatch, "命中 IP 白名单"},
		{EventTypeURLAllowMatch, "命中 URL 白名单"},
		{EventTypeIPDenyMatch, "命中 IP 黑名单"},
		{EventTypeCCThresholdExceeded, "频率超阈值"},
		{EventTypeCCRequestRejected, "频率请求被拒绝"},
		{EventTypeCCTempBlockCreated, "频率临时封禁创建"},
		{EventTypeCCTempBlockExpired, "频率临时封禁到期"},
		{EventTypeCCTempBlockReleased, "频率临时封禁解除"},
		{EventTypeCCTempBlockDowngraded, "频率临时封禁降级"},
		{"TRUSTED_PROXY_INVALID", "可信代理无效"},
		{"FORWARDED_HEADER_INVALID", "转发头无效"},
		{"FORWARDED_CHAIN_TOO_LONG", "转发链过长"},
		{"RATE_LIMIT_ENGINE_ERROR", "限速引擎错误"},
		{EventTypeL7RuleAllow, "L7规则放行"},
		{EventTypeL7RuleBlock, "L7规则阻断"},
		{EventTypeL7RuleRedirect, "L7规则重定向"},
		{EventTypeL7RuleCustom, "L7自定义页面"},
		{"IDENTITY_MANUAL_BLOCK", "身份手工封禁"},
		{EventTypeRiskPolicyBlock, "风险策略阻断"},
		{EventTypeRiskPolicyRateLimit, "风险策略限速"},
		{EventTypeRiskPolicyChallenge, "风险策略挑战"},
		{EventTypeJWTObserved, "JWT 校验观察"},
		{EventTypeJWTAuthFailed, "JWT 认证失败"},
		{EventTypeJWTUnavailable, "JWT 服务不可用"},
		{EventTypeBotChallengeOffered, "Bot 挑战下发"},
		{EventTypeBotVerifySuccess, "Bot 挑战验证通过"},
		{EventTypeBotVerifyRejected, "Bot 挑战验证拒绝"},
		{EventTypeBotChallengeExpired, "Bot 挑战已过期"},
		{EventTypeBotStateUnavailable, "Bot 状态存储不可用"},
		{EventTypeBotClearanceAccepted, "Bot 通行凭据有效"},
		{"MID_VERIFIED", "机器身份验签通过"},
		{"MID_OBSERVED", "机器身份观察"},
		{"MID_AUTH_FAILED", "机器身份认证失败"},
		{"MID_UNAVAILABLE", "机器身份服务不可用"},
		{"MID_SCOPE_DENIED", "机器身份越权拒绝"},
		{"MID_BOT_EXEMPT", "机器身份豁免 Bot 挑战"},
		{"UNKNOWN_EVENT_TYPE", "UNKNOWN_EVENT_TYPE"},
		{"", ""},
	}
	for _, tc := range eventTypeCases {
		if got := formatACEventType(tc.code); got != tc.want {
			t.Errorf("event_type %q = %q, want %q", tc.code, got, tc.want)
		}
	}

	// 覆盖全部动作值（含 stage5.ts 大小写变体及网关扩展动作）
	actionCases := []struct {
		code string
		want string
	}{
		{"ALLOW", "放行"},
		{"BLOCK", "阻断"},
		{"DENY", "拒绝"},
		{ActionLog, "仅记录"},
		{ActionObserve, "观察"},
		{"REDIRECT", "重定向"},
		{"CUSTOM_PAGE", "自定义页面"},
		{ActionReject, "拒绝"},
		{ActionChallenge, "挑战"},
		{ActionTempBlock, "临时封禁"},
		{"PASS", "放行"},
		{"CONNECTION_FALLBACK", "回退连接 IP"},
		{"IGNORED", "已忽略"},
		{"ENGINE_ERROR", "引擎异常"},
		{"blocked", "已阻断"},
		{"would_block", "拟阻断（观察）"},
		{"challenged", "已挑战"},
		{"would_challenge", "拟挑战（观察）"},
		{"rate_limited", "已限速"},
		{"would_rate_limit", "拟限速（观察）"},
		{"UNKNOWN_ACT", "UNKNOWN_ACT"},
		{"", ""},
	}
	for _, tc := range actionCases {
		if got := formatACEventAction(tc.code); got != tc.want {
			t.Errorf("action %q = %q, want %q", tc.code, got, tc.want)
		}
	}

	cnt := int64(120)
	limit := int64(100)
	win := 60
	status := 429
	out := renderExportCSV([]Event{
		{
			OccurredAt:      ts,
			RequestID:       "req-ac-1",
			ApplicationCode: "shop",
			ClientIP:        "203.0.113.5",
			ConnectionIP:    "10.0.0.1",
			Domain:          "shop.example.com",
			RequestMethod:   "POST",
			RequestPath:     "/api/login",
			EventType:       EventTypeCCRequestRejected,
			Action:          ActionReject,
			PolicyID:        "pol-1",
			AccessRuleID:    "rule-1",
			CurrentCount:    &cnt,
			LimitValue:      &limit,
			WindowSeconds:   &win,
			ResponseStatus:  &status,
			GatewayNodeID:   "gw-1",
			Message:         "触发限速,请稍后",
		},
		{
			OccurredAt:    ts,
			RequestID:     "req-ac-2",
			ClientIP:      "203.0.113.6",
			Domain:        "=evil.com",
			RequestMethod: "GET",
			RequestPath:   "\t/admin",
			EventType:     EventTypeRiskPolicyBlock,
			Action:        "would_block",
			Message:       "\r-inject",
		},
		{
			OccurredAt:    ts,
			RequestID:     "req-ac-3",
			ClientIP:      "203.0.113.7",
			RequestMethod: "GET",
			RequestPath:   "/x",
			EventType:     "FUTURE_TYPE",
			Action:        "=RAW_ACT",
		},
	})

	if !strings.HasPrefix(out, csvUTF8BOM) {
		t.Fatalf("missing UTF-8 BOM")
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("lines = %d, want 4", len(lines))
	}
	wantHeader := csvUTF8BOM + "发生时间,请求 ID,应用编码,客户端 IP,连接 IP,域名,请求方法,请求路径,事件类型,动作,策略 ID,规则 ID,当前计数,阈值,统计窗口（秒）,响应状态码,网关节点,消息"
	if lines[0] != wantHeader {
		t.Fatalf("header = %q, want %q", lines[0], wantHeader)
	}
	if lines[1] != `2026-11-24T16:00:00Z,req-ac-1,shop,203.0.113.5,10.0.0.1,shop.example.com,POST,/api/login,频率请求被拒绝,拒绝,pol-1,rule-1,120,100,60,429,gw-1,"触发限速,请稍后"` {
		t.Fatalf("row 1 mismatch: %q", lines[1])
	}
	if !strings.Contains(lines[2], "'=evil.com,GET,'\t/admin,风险策略阻断,拟阻断（观察）") || !strings.Contains(lines[2], "\"'\r-inject\"") {
		t.Fatalf("row 2 mismatch: %q", lines[2])
	}
	if !strings.Contains(lines[3], ",FUTURE_TYPE,'=RAW_ACT,") {
		t.Fatalf("row 3 fallback/escape mismatch: %q", lines[3])
	}
}

func TestCSVCellTabAndCREscape(t *testing.T) {
	if got := csvCell("\t=1"); got != "'\t=1" {
		t.Fatalf("csvCell(tab) = %q, want '\\t=1", got)
	}
	if got := csvCell("\r=1"); got != "\"'\r=1\"" {
		t.Fatalf("csvCell(cr) = %q, want quoted '\\r=1", got)
	}
}
