package notify

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestSeverityOrdering 级别序与最低级别过滤。
func TestSeverityOrdering(t *testing.T) {
	if !SeverityGte(SeverityLow, SeverityLow) || !SeverityGte(SeverityCritical, SeverityLow) {
		t.Error("同级/高级应通过")
	}
	if SeverityGte(SeverityMedium, SeverityHigh) {
		t.Error("MEDIUM 不应达到 HIGH 门槛")
	}
	if SeverityGte(SeverityInfo, SeverityLow) {
		t.Error("INFO 不应达到 LOW 门槛")
	}
	if SeverityGte("UNKNOWN", SeverityLow) {
		t.Error("未知级别不应通过")
	}
	if !IsValidMinSeverity("CRITICAL") || IsValidMinSeverity("INFO") {
		t.Error("min_severity 词表校验错误")
	}
	sevs := Severities()
	if len(sevs) != 4 || sevs[0] != "LOW" || sevs[3] != "CRITICAL" {
		t.Errorf("severities 契约错误: %v", sevs)
	}
}

// TestCategoriesContract notification-meta 固定 10 类契约（VULN_INTEL MVP 起新增漏洞情报类）。
func TestCategoriesContract(t *testing.T) {
	cats := Categories()
	if len(cats) != 10 {
		t.Fatalf("categories 应为 10 类, got %d", len(cats))
	}
	wantCodes := []string{"infrastructure", "storage", "certificate", "collection", "config_publish", "api_security", "ops", "security_events", "apm", "threat_intel"}
	total := 0
	for i, c := range cats {
		if c.Code != wantCodes[i] {
			t.Errorf("categories[%d].code = %s, want %s", i, c.Code, wantCodes[i])
		}
		if c.Name == "" || len(c.AlertTypes) == 0 {
			t.Errorf("categories[%d] 缺名称或类型: %+v", i, c)
		}
		total += len(c.AlertTypes)
	}
	if total != 40 {
		t.Errorf("告警类型总数应为 40, got %d", total)
	}
	if got := CategoryOf("RULEPACK_APPLY_FAILED"); got != "ops" {
		t.Errorf("CategoryOf(RULEPACK_APPLY_FAILED) = %s, want ops", got)
	}
	if got := AlertTypeName("RULEPACK_NODE_DRIFT"); got != "HA规则包版本漂移" {
		t.Errorf("AlertTypeName(RULEPACK_NODE_DRIFT) = %s, want HA规则包版本漂移", got)
	}
	if got := CategoryOf("HA_SPLIT_BRAIN"); got != "infrastructure" {
		t.Errorf("CategoryOf(HA_SPLIT_BRAIN) = %s, want infrastructure", got)
	}
	if got := AlertTypeName("HA_SPLIT_BRAIN"); got != "主备双主脑裂" {
		t.Errorf("AlertTypeName(HA_SPLIT_BRAIN) = %s, want 主备双主脑裂", got)
	}
	// CategoryOf 映射
	if got := CategoryOf("GATEWAY_DOWN"); got != "infrastructure" {
		t.Errorf("CategoryOf(GATEWAY_DOWN) = %s", got)
	}
	if got := CategoryOf("API_MASK_FAILURE"); got != "api_security" {
		t.Errorf("CategoryOf(API_MASK_FAILURE) = %s", got)
	}
	if got := CategoryOf("AUDIT_INTEGRITY_FAILED"); got != "ops" {
		t.Errorf("CategoryOf(AUDIT_INTEGRITY_FAILED) = %s", got)
	}
	if got := CategoryOf("APM_SLO_BREACH"); got != "apm" {
		t.Errorf("CategoryOf(APM_SLO_BREACH) = %s", got)
	}
	if got := CategoryOf("APM_INGEST_LAG"); got != "collection" {
		t.Errorf("CategoryOf(APM_INGEST_LAG) = %s", got)
	}
	if got := CategoryOf("UPGRADE_ROLLBACK_FAILED"); got != "ops" {
		t.Errorf("CategoryOf(UPGRADE_ROLLBACK_FAILED) = %s", got)
	}
	for _, typ := range []string{"SECURITY_EVENT_SPIKE", "LOGIN_BRUTE_FORCE", "CC_BAN_SPIKE"} {
		if got := CategoryOf(typ); got != "security_events" {
			t.Errorf("CategoryOf(%s) = %s, want security_events", typ, got)
		}
	}
	if got := CategoryOf("VULN_INTEL_NEW"); got != "threat_intel" {
		t.Errorf("CategoryOf(VULN_INTEL_NEW) = %s, want threat_intel", got)
	}
	if got := CategoryOf("NO_SUCH_TYPE"); got != "" {
		t.Errorf("未知类型应返回空串, got %q", got)
	}
	// 副本语义：修改返回值不影响词表
	cats[0].Code = "hacked"
	if Categories()[0].Code != "infrastructure" {
		t.Error("Categories 应返回副本")
	}
}

// TestRenderMessage 触发/恢复/摘要三类文案渲染。
func TestRenderMessage(t *testing.T) {
	msg := renderMessage(testEvent())
	if msg.Subject != "【九章WAF告警】防护网关不可用" {
		t.Errorf("Subject = %q", msg.Subject)
	}
	for _, want := range []string{"级别：CRITICAL", "类型：网关离线（GATEWAY_DOWN）", "组件：GATEWAY",
		"标题：防护网关不可用", "状态：新触发", "详情：网关 Admin Socket 不可达", "2026-08-18 15:00:00（Asia/Shanghai）"} {
		if !strings.Contains(msg.Text, want) {
			t.Errorf("Text 缺少 %q\n%s", want, msg.Text)
		}
	}

	resolved := testEvent()
	resolved.Status = StatusResolved
	rmsg := renderMessage(resolved)
	if rmsg.Subject != "【九章WAF恢复】防护网关不可用" {
		t.Errorf("恢复 Subject = %q", rmsg.Subject)
	}
	if !strings.Contains(rmsg.Text, "状态：已恢复") {
		t.Errorf("恢复 Text 缺状态行: %s", rmsg.Text)
	}

	summary := Event{Summary: true, Title: "过去 1 分钟共 3 条告警",
		Message: "过去 1 分钟共 3 条告警：网关离线×3（因速率限制合并发送）",
		Status:  StatusOpen, Severity: SeverityHigh, OccurredAt: testEvent().OccurredAt}
	smsg := renderMessage(summary)
	if !strings.HasPrefix(smsg.Subject, "【九章WAF告警摘要】") {
		t.Errorf("摘要 Subject = %q", smsg.Subject)
	}
	if !strings.Contains(smsg.Text, "网关离线×3") {
		t.Errorf("摘要 Text 缺计数: %s", smsg.Text)
	}
}

// TestSubscribes 渠道订阅判定（启用/级别/类别）。
func TestSubscribes(t *testing.T) {
	open := wecomChannel(uuid.New(), "https://x", SeverityMedium, []string{"storage"})
	if !open.subscribes(ev("DISK_SPACE_LOW", "D", SeverityHigh)) {
		t.Error("storage 类别 HIGH 应订阅（min MEDIUM）")
	}
	if open.subscribes(ev("DISK_SPACE_LOW", "D", SeverityLow)) {
		t.Error("LOW 不应达到 MEDIUM 门槛")
	}
	if open.subscribes(ev("GATEWAY_DOWN", "G", SeverityCritical)) {
		t.Error("infrastructure 不在订阅类别内")
	}
	open.Categories = []string{}
	if !open.subscribes(ev("GATEWAY_DOWN", "G", SeverityCritical)) {
		t.Error("空类别 = 订阅全部")
	}
	open.Enabled = false
	if open.subscribes(ev("DISK_SPACE_LOW", "D", SeverityCritical)) {
		t.Error("停用渠道不应订阅")
	}
}
