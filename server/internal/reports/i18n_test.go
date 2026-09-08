package reports

import "testing"

func TestI18NMappings(t *testing.T) {
	cases := []struct {
		fn   func(string) string
		in   string
		want string
	}{
		{ReportTypeName, TypeDaily, "日报"},
		{ReportTypeName, TypeWeekly, "周报"},
		{ReportTypeName, TypeMonthly, "月报"},
		{ReportTypeName, TypeCustom, "自定义"},
		{ReportTypeName, TypeAPIAsset, "API资产周报"},
		{SeverityName, "CRITICAL", "严重"},
		{SeverityName, "HIGH", "高危"},
		{SeverityName, "MEDIUM", "中危"},
		{SeverityName, "LOW", "低危"},
		{DispositionName, "UNPROCESSED", "未处置"},
		{DispositionName, "CONFIRMED_FALSE_POSITIVE", "确认误报"},
		{DispositionName, "RESOLVED", "已处置"},
		{UpstreamStatusName, "UP", "正常"},
		{UpstreamStatusName, "DOWN", "故障"},
		{UpstreamStatusName, "DEGRADED", "降级"},
		{UpstreamStatusName, "DISABLED", "未启用"},
		{UpstreamStatusName, "UNKNOWN", "未知"},
		{CertStatusName, "VALID", "有效"},
		{CertStatusName, "EXPIRING", "即将到期"},
		{CertStatusName, "EXPIRED", "已过期"},
		{PublishTaskTypeName, "PUBLISH", "发布"},
		{PublishTaskTypeName, "ROLLBACK", "回滚"},
		{PublishStatusName, "SUCCESS", "成功"},
		{PublishStatusName, "FAILED", "失败"},
		{PublishStatusName, "RUNNING", "进行中"},
		{FindingTypeName, "SHADOW", "影子API"},
		{FindingTypeName, "ZOMBIE", "僵尸API"},
		{FindingTypeName, "BOLA", "对象级越权"},
		// 未知值原样返回
		{SeverityName, "WHATEVER", "WHATEVER"},
		{DispositionName, "X_Y", "X_Y"},
	}
	for i, tc := range cases {
		if got := tc.fn(tc.in); got != tc.want {
			t.Fatalf("case %d: got %q want %q", i, got, tc.want)
		}
	}
}

func TestRuleDisplayName(t *testing.T) {
	// CRS 规则：加中文类别前缀，保留英文原名
	got := RuleDisplayName(942100, "SQL Injection Attack Detected via libinjection")
	want := "【SQL注入】SQL Injection Attack Detected via libinjection"
	if got != want {
		t.Fatalf("crs rule: got %q want %q", got, want)
	}
	got = RuleDisplayName(941160, "NoScript XSS InjectionChecker: HTML Injection")
	if got != "【XSS跨站脚本】NoScript XSS InjectionChecker: HTML Injection" {
		t.Fatalf("xss rule: got %q", got)
	}
	got = RuleDisplayName(949110, "Inbound Anomaly Score Exceeded (Total Score: 9)")
	if got != "【异常评分拦截评估】Inbound Anomaly Score Exceeded (Total Score: 9)" {
		t.Fatalf("eval rule: got %q", got)
	}
	// 中文规则名（自研）原样
	got = RuleDisplayName(1001101, "检测到SQL注入攻击")
	if got != "检测到SQL注入攻击" {
		t.Fatalf("chinese rule should pass through: got %q", got)
	}
	// 无法归类的英文名原样
	got = RuleDisplayName(123456, "Some Custom Rule")
	if got != "Some Custom Rule" {
		t.Fatalf("unknown rule should pass through: got %q", got)
	}
	// 空名兜底
	if got := RuleDisplayName(942100, ""); got != "-" {
		t.Fatalf("empty name: got %q", got)
	}
}

func TestSeverityDisplayKVs(t *testing.T) {
	kvs := []KV{{Key: "HIGH", Value: 3}, {Key: "LOW", Value: 5}}
	out := severityDisplayKVs(kvs)
	if out[0].Key != "高危" || out[1].Key != "低危" || out[0].Value != 3 {
		t.Fatalf("severity display kvs wrong: %+v", out)
	}
	// 原始数据不被修改（标红判定依赖英文键）
	if kvs[0].Key != "HIGH" {
		t.Fatal("original kvs should not be mutated")
	}
}
