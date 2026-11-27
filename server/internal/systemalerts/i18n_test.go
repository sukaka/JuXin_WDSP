package systemalerts

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestFindingTypeLabelAndSpikeMessageLocalization(t *testing.T) {
	cases := map[string]string{
		"IDENTITY_COOKIE_PRESENT":            "携带 Cookie 会话头",
		"CREDENTIAL_COOKIE_SENSITIVE":        "Cookie 携带敏感凭据",
		"AUTH_CREDENTIAL_CONCURRENCY":        "凭据异常并发使用",
		"SCHEMA_DEVIATION":                   "模型偏离",
		"BOLA_UNAUTHENTICATED_OBJECT_ACCESS": "未认证对象越权访问",
		"WAF_942100":                         "WAF SQL 注入（942100）",
		"AUTHZ_FUTURE_CODE":                  "授权安全异常",
	}
	for raw, want := range cases {
		if got := findingTypeLabel(raw); got != want {
			t.Errorf("findingTypeLabel(%q) = %q, want %q", raw, got, want)
		}
	}

	msg := spikeMessage(60*time.Minute, 20, []FindingTypeCount{
		{FindingType: "IDENTITY_COOKIE_PRESENT", Count: 219},
		{FindingType: "CREDENTIAL_COOKIE_SENSITIVE", Count: 219},
		{FindingType: "AUTH_CREDENTIAL_CONCURRENCY", Count: 129},
		{FindingType: "SCHEMA_DEVIATION", Count: 50},
	})
	want := "最近 60 分钟同类型风险发现超过阈值 20：携带 Cookie 会话头 219 条；Cookie 携带敏感凭据 219 条；凭据异常并发使用 129 条 等 4 类"
	if msg != want {
		t.Fatalf("spikeMessage =\n  %s\nwant:\n  %s", msg, want)
	}
}

func TestLocalizeAlertMessageLegacyRowsAndCSVExport(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "存量 API 风险发现激增英文码",
			in:   "最近 60 分钟同类型风险发现超过阈值 20：IDENTITY_COOKIE_PRESENT 219 条；CREDENTIAL_COOKIE_SENSITIVE 219 条；AUTH_CREDENTIAL_CONCURRENCY 129 条 等 4 类",
			want: "最近 60 分钟同类型风险发现超过阈值 20：携带 Cookie 会话头 219 条；Cookie 携带敏感凭据 219 条；凭据异常并发使用 129 条 等 4 类",
		},
		{
			name: "存量安全事件激增英文级别",
			in:   "最近 1 分钟 HIGH/CRITICAL 级安全事件 12 条（阈值 10）",
			want: "最近 1 分钟高危/严重级安全事件 12 条（阈值 10）",
		},
		{
			name: "存量响应脱敏失败英文动作码",
			in:   "最近 10 分钟新增 3 条响应脱敏（MASK_RESPONSE）失败记录，存在未脱敏数据外发风险",
			want: "最近 10 分钟新增 3 条响应脱敏失败记录，存在未脱敏数据外发风险",
		},
		{
			name: "存量严重发现与短代码及括号简称幂等",
			in:   "最近 10 分钟新增 2 条 CRITICAL 级风险发现：BOLA 30 条；AUTHZ_BOLA_001（AUTHZ_BOLA_001）",
			want: "最近 10 分钟新增 2 条严重级风险发现：对象级越权 30 条；对象级越权（BOLA）",
		},
		{
			name: "漏洞情报保留 CVE 与链接并翻译级别",
			in:   "最高级别：CRITICAL；CVE 列表：CVE-2026-0001；参考链接：https://example.com/AUTH_TEST/CVE-2026-0001",
			want: "最高级别：严重；CVE 列表：CVE-2026-0001；参考链接：https://example.com/AUTH_TEST/CVE-2026-0001",
		},
		{
			name: "事件采集 checkpoint 滞后",
			in:   "事件采集 checkpoint 滞后",
			want: "事件采集位点滞后",
		},
	}
	for _, tc := range cases {
		got := localizeAlertMessage(tc.in)
		if got != tc.want {
			t.Errorf("%s:\n got: %q\nwant: %q", tc.name, got, tc.want)
		}
		if again := localizeAlertMessage(got); again != got {
			t.Errorf("%s 二次调用不幂等:\n once: %q\ntwice: %q", tc.name, got, again)
		}
	}

	now := time.Date(2026, 11, 27, 11, 0, 0, 0, time.UTC)
	csvOut := renderExportCSV([]Alert{{
		ID:              uuid.MustParse("44444444-4444-4444-4444-444444444444"),
		AlertType:       TypeAPIFindingSpike,
		Severity:        SeverityHigh,
		Component:       ComponentAPISecurity,
		Title:           "API风险发现激增",
		Message:         "最近 60 分钟同类型风险发现超过阈值 20：IDENTITY_COOKIE_PRESENT 219 条",
		Status:          StatusAcknowledged,
		OccurrenceCount: 568,
		FirstSeenAt:     now,
		LastSeenAt:      now,
	}})
	if !strings.Contains(csvOut, "携带 Cookie 会话头 219 条") || strings.Contains(csvOut, "IDENTITY_COOKIE_PRESENT") {
		t.Fatalf("CSV 导出应中文化历史告警详情: %s", csvOut)
	}
}
