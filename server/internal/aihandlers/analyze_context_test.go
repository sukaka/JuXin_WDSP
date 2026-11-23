// analyze_context_test.go 结构化分析扩展单测：入参逐一校验、时间范围解析、
// 上下文组装与 What-If 离线估算（纯函数，不依赖数据库）。
package aihandlers

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/aiorchestrator"
)

func TestParseAnalyzeTimeRange(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	start, end, label, err := parseAnalyzeTimeRange("7d", "24h", now)
	if err != nil {
		t.Fatalf("7d should parse: %v", err)
	}
	if !end.Equal(now) || !start.Equal(now.Add(-7*24*time.Hour)) || label != "近 7 天" {
		t.Fatalf("unexpected range: %v %v %q", start, end, label)
	}
	// 空串回退默认预设
	start, _, label, err = parseAnalyzeTimeRange("", "24h", now)
	if err != nil || !start.Equal(now.Add(-24*time.Hour)) || label != "近 24 小时" {
		t.Fatalf("default preset failed: %v %q %v", start, label, err)
	}
	if _, _, _, err = parseAnalyzeTimeRange("3d", "24h", now); err == nil {
		t.Fatal("3d should be rejected (not in whitelist)")
	}
}

func TestValidateAnalyzeStructured(t *testing.T) {
	cases := []struct {
		name string
		req  analyzeRequest
		want string // 空串表示通过；否则为错误消息子串
	}{
		{"empty ok", analyzeRequest{}, ""},
		{"event ok", analyzeRequest{EventID: "11111111-1111-1111-1111-111111111111"}, ""},
		{"event bad", analyzeRequest{EventID: "not-a-uuid"}, "无效的事件ID"},
		{"ip ok", analyzeRequest{IP: "203.0.113.10"}, ""},
		{"ip bad", analyzeRequest{IP: "999.1.1.1"}, "无效的IP地址"},
		{"uri ok", analyzeRequest{URI: "/api/users"}, ""},
		{"uri no slash", analyzeRequest{URI: "api/users"}, "无效的URI"},
		{"uri too short", analyzeRequest{URI: "/"}, "无效的URI"},
		{"uri control char", analyzeRequest{URI: "/a\nb"}, "无效的URI"},
		{"app ok", analyzeRequest{ApplicationID: "22222222-2222-2222-2222-222222222222"}, ""},
		{"app bad", analyzeRequest{ApplicationID: "app-1"}, "无效的应用ID"},
		{"rule negative", analyzeRequest{RuleID: -1}, "无效的规则ID"},
		{"request id ok", analyzeRequest{RequestID: "req-abc_123.45:6"}, ""},
		{"request id bad", analyzeRequest{RequestID: "req id with space"}, "无效的Request ID"},
		{"time range ok", analyzeRequest{TimeRange: "30d"}, ""},
		{"time range bad", analyzeRequest{TimeRange: "1y"}, "无效的时间范围"},
		{"scenario ok", analyzeRequest{Scenario: "cc_threshold"}, ""},
		{"scenario bad", analyzeRequest{Scenario: "drop_table"}, "无效的模拟场景"},
		{"cc threshold ok", analyzeRequest{CCThreshold: 100}, ""},
		{"cc threshold negative", analyzeRequest{CCThreshold: -5}, "无效的 CC 阈值"},
		{"cc threshold too big", analyzeRequest{CCThreshold: 1000001}, "无效的 CC 阈值"},
		{"block duration ok", analyzeRequest{BlockDurationSeconds: 3600}, ""},
		{"block duration too big", analyzeRequest{BlockDurationSeconds: 2592001}, "无效的封禁时长"},
	}
	for _, c := range cases {
		got := validateAnalyzeStructured(&c.req)
		if c.want == "" && got != "" {
			t.Errorf("%s: want pass, got %q", c.name, got)
		}
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s: want %q, got %q", c.name, c.want, got)
		}
	}
}

func TestHasEventFilter(t *testing.T) {
	if hasEventFilter(&analyzeRequest{Question: "q"}) {
		t.Fatal("question alone is not a filter")
	}
	for _, req := range []analyzeRequest{
		{IP: "1.2.3.4"}, {URI: "/a"}, {RuleID: 942100},
		{RequestID: "r1"}, {ApplicationID: "app"},
	} {
		if !hasEventFilter(&req) {
			t.Fatalf("expected filter: %+v", req)
		}
	}
}

func TestEventFilterWhere(t *testing.T) {
	start := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	where, args := eventFilterWhere(&analyzeRequest{
		ApplicationID: "app-1", IP: "1.2.3.4", URI: "/login", RuleID: 942100, RequestID: "r1",
	}, start, end)
	for _, clause := range []string{"application_id", "client_ip", "request_path", "request_id", "security_event_matches"} {
		if !strings.Contains(where, clause) {
			t.Errorf("where missing %s: %s", clause, where)
		}
	}
	if len(args) != 7 {
		t.Fatalf("want 7 args, got %d", len(args))
	}
	// 无维度时仅时间范围
	where, args = eventFilterWhere(&analyzeRequest{}, start, end)
	if strings.Contains(where, "application_id") || len(args) != 2 {
		t.Fatalf("bare range should have no extra clause: %s (%d args)", where, len(args))
	}
}

func TestBuildEventFilterContext(t *testing.T) {
	req := &analyzeRequest{IP: "203.0.113.10", URI: "/login"}
	// 缺数据：如实返回数据不足口径
	empty := buildEventFilterContext(req, "近 24 小时", &eventFilterSummary{})
	if !strings.Contains(empty, "数据不足") || !strings.Contains(empty, "不得推测") {
		t.Fatalf("empty summary must state insufficient data: %s", empty)
	}
	full := buildEventFilterContext(&analyzeRequest{IP: "203.0.113.10", Question: "是否有误伤"}, "近 24 小时", &eventFilterSummary{
		Total: 12, Blocked: 9, FirstAt: time.Date(2026, 9, 10, 1, 0, 0, 0, time.UTC), LastAt: time.Date(2026, 9, 10, 2, 0, 0, 0, time.UTC),
		AttackTypes:  []countKV{{"SQL_INJECTION", 8}, {"XSS", 4}},
		SourceIPs:    []countKV{{"203.0.113.10", 12}},
		Paths:        []countKV{{"/login", 12}},
		AccessEvents: 3,
	})
	for _, want := range []string{"安全事件 12 条", "阻断 9 条", "SQL_INJECTION(8)", "访问控制事件", "是否有误伤"} {
		if !strings.Contains(full, want) {
			t.Errorf("context missing %q: %s", want, full)
		}
	}
}

func TestBuildURIProfileContext(t *testing.T) {
	empty := buildURIProfileContext("近 7 天", &uriProfileSummary{URI: "/api/pay"})
	if !strings.Contains(empty, "数据不足") || !strings.Contains(empty, "/api/pay") {
		t.Fatalf("empty uri profile must state insufficient data: %s", empty)
	}
	full := buildURIProfileContext("近 7 天", &uriProfileSummary{
		URI: "/api/pay", Total: 5, Blocked: 5,
		FirstAt: time.Now(), LastAt: time.Now(),
		AttackTypes: []countKV{{"SQL_INJECTION", 5}},
		SourceIPs:   []countKV{{"198.51.100.7", 5}},
		Rules:       []countKV{{"942100", 5}},
	})
	for _, want := range []string{"安全事件 5 条", "942100(5)", "198.51.100.7(5)"} {
		if !strings.Contains(full, want) {
			t.Errorf("uri profile missing %q: %s", want, full)
		}
	}
}

func TestBuildAppProfileContext(t *testing.T) {
	empty := buildAppProfileContext("近 7 天", &appProfileSummary{AppID: "app-1"})
	if !strings.Contains(empty, "数据不足") || !strings.Contains(empty, "app-1") {
		t.Fatalf("empty app profile must state insufficient data: %s", empty)
	}
	full := buildAppProfileContext("近 7 天", &appProfileSummary{
		AppID: "app-1", AppName: "商城", Mode: "PROTECT", Status: "ENABLED",
		Total: 30, Blocked: 20, FirstAt: time.Now(), LastAt: time.Now(),
		AttackTypes: []countKV{{"XSS", 18}},
		SourceIPs:   []countKV{{"192.0.2.9", 11}},
		URIs:        []countKV{{"/order", 15}},
	})
	for _, want := range []string{"商城", "PROTECT", "安全事件 30 条", "/order(15)"} {
		if !strings.Contains(full, want) {
			t.Errorf("app profile missing %q: %s", want, full)
		}
	}
}

func TestEstimateCCThreshold(t *testing.T) {
	samples := []ccTriggerSample{
		{ClientIP: "1.1.1.1", CurrentCount: 120, LimitValue: 100, WindowSeconds: 60},
		{ClientIP: "1.1.1.1", CurrentCount: 150, LimitValue: 100, WindowSeconds: 60},
		{ClientIP: "2.2.2.2", CurrentCount: 300, LimitValue: 100, WindowSeconds: 60},
		{ClientIP: "3.3.3.3", CurrentCount: 101, LimitValue: 100, WindowSeconds: 60},
	}
	est := estimateCCThreshold(samples, 200)
	if est.SampleTotal != 4 || est.AvoidedTotal != 3 || est.AffectedIPs != 2 {
		t.Fatalf("unexpected estimate: %+v", est)
	}
	if est.CurrentLimit != 100 || est.WindowSeconds != 60 || est.EstimatedRatio != 75 {
		t.Fatalf("unexpected reference fields: %+v", est)
	}
	// 空样本
	if e := estimateCCThreshold(nil, 50); e.SampleTotal != 0 || e.EstimatedRatio != 0 {
		t.Fatalf("empty samples: %+v", e)
	}
}

func TestEstimateBlockDuration(t *testing.T) {
	base := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	mk := func(ip string, startMin int, durMin int) blockSample {
		return blockSample{ClientIP: ip,
			StartedAt: base.Add(time.Duration(startMin) * time.Minute),
			ExpiresAt: base.Add(time.Duration(startMin+durMin) * time.Minute)}
	}
	// 调用方保证按 IP+时刻排序
	samples := []blockSample{
		mk("1.1.1.1", 0, 10),
		mk("1.1.1.1", 20, 10), // 距前次 20 分钟
		mk("1.1.1.1", 90, 10), // 距前次 70 分钟
		mk("2.2.2.2", 5, 30),
	}
	// 新时长 30 分钟：第二次（间隔 20 分钟）被吞并，第三次不吞并
	est := estimateBlockDuration(samples, 30*time.Minute)
	if est.SampleTotal != 4 || est.DistinctIPs != 2 || est.SubsumedBlocks != 1 {
		t.Fatalf("unexpected estimate: %+v", est)
	}
	// 当前平均封禁时长：(10+10+10+30)/4 = 15 分钟 = 900 秒
	if est.AvgCurrentSecond != 900 {
		t.Fatalf("avg duration: %d", est.AvgCurrentSecond)
	}
	// 新时长很短：无吞并
	if e := estimateBlockDuration(samples, time.Minute); e.SubsumedBlocks != 0 {
		t.Fatalf("short duration should subsume none: %+v", e)
	}
}

func TestBuildWhatIfContexts(t *testing.T) {
	cc := buildCCThresholdContext("近 7 天", 200, ccThresholdEstimate{
		SampleTotal: 10, AvoidedTotal: 4, AffectedIPs: 3, CurrentLimit: 100, WindowSeconds: 60, EstimatedRatio: 40})
	for _, want := range []string{"每窗口 200 次", "10 条", "4 条历史触发不会发生", "统计估算"} {
		if !strings.Contains(cc, want) {
			t.Errorf("cc context missing %q: %s", want, cc)
		}
	}
	if got := buildCCThresholdContext("近 7 天", 200, ccThresholdEstimate{}); !strings.Contains(got, "数据不足") {
		t.Fatalf("empty cc estimate must state insufficient data: %s", got)
	}
	bd := buildBlockDurationContext("近 7 天", time.Hour, blockDurationEstimate{
		SampleTotal: 8, DistinctIPs: 5, SubsumedBlocks: 2, AvgCurrentSecond: 600})
	for _, want := range []string{"3600 秒", "8 条", "2 次历史重复封禁不会发生", "非逐请求回放"} {
		if !strings.Contains(bd, want) {
			t.Errorf("block duration context missing %q: %s", want, bd)
		}
	}
	if got := buildBlockDurationContext("近 7 天", time.Hour, blockDurationEstimate{}); !strings.Contains(got, "数据不足") {
		t.Fatalf("empty block estimate must state insufficient data: %s", got)
	}
}

func TestDescribeEventFilterDims(t *testing.T) {
	got := describeEventFilterDims(&analyzeRequest{IP: "1.2.3.4", RuleID: 942100, URI: "/a"})
	if !strings.Contains(got, "IP 1.2.3.4") || !strings.Contains(got, "规则 942100") || !strings.Contains(got, "URI /a") {
		t.Fatalf("dims description: %s", got)
	}
	if describeEventFilterDims(&analyzeRequest{}) != "" {
		t.Fatal("no dims should be empty")
	}
}

// ---------- §19 What-If 新增五场景单测 ----------

func TestValidateAnalyzeStructuredNewScenarios(t *testing.T) {
	cases := []struct {
		name string
		req  analyzeRequest
		want string
	}{
		{"enable rule ok", analyzeRequest{Scenario: "enable_rule", RuleID: 942100}, ""},
		{"anomaly threshold ok", analyzeRequest{Scenario: "anomaly_threshold", AnomalyThreshold: 5}, ""},
		{"anomaly threshold negative", analyzeRequest{AnomalyThreshold: -1}, "无效的异常阈值"},
		{"anomaly threshold too big", analyzeRequest{AnomalyThreshold: 10001}, "无效的异常阈值"},
		{"pl switch ok", analyzeRequest{Scenario: "pl_switch", ParanoiaLevel: 2}, ""},
		{"pl switch too big", analyzeRequest{ParanoiaLevel: 5}, "无效的执行等级"},
		{"add exception ok", analyzeRequest{Scenario: "add_exception", RuleID: 942100, URI: "/api/pay"}, ""},
		{"remove exception ok", analyzeRequest{Scenario: "remove_exception", ExceptionID: "33333333-3333-3333-3333-333333333333"}, ""},
		{"remove exception bad id", analyzeRequest{Scenario: "remove_exception", ExceptionID: "not-a-uuid"}, "无效的例外ID"},
		{"scenario still bad", analyzeRequest{Scenario: "drop_table"}, "无效的模拟场景"},
	}
	for _, c := range cases {
		got := validateAnalyzeStructured(&c.req)
		if c.want == "" && got != "" {
			t.Errorf("%s: want pass, got %q", c.name, got)
		}
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s: want %q, got %q", c.name, c.want, got)
		}
	}
}

func TestEstimateRuleEnable(t *testing.T) {
	if r := estimateRuleEnable(&ruleEnableSummary{}); r != "UNKNOWN" {
		t.Fatalf("missing rule: %s", r)
	}
	// 无历史命中且同类型仅观察事件存在：启用可能新增处置，MEDIUM
	if r := estimateRuleEnable(&ruleEnableSummary{RuleExists: true, SameTypeObserve: 12}); r != "MEDIUM" {
		t.Fatalf("observe backlog: %s", r)
	}
	// 有历史命中（规则曾正常工作）：LOW
	if r := estimateRuleEnable(&ruleEnableSummary{RuleExists: true, HistHits: 5, SameTypeObserve: 12}); r != "LOW" {
		t.Fatalf("with hits: %s", r)
	}
}

func TestBuildEnableRuleContext(t *testing.T) {
	if got := buildEnableRuleContext("近 30 天", &ruleEnableSummary{RuleID: 999999}); !strings.Contains(got, "无法确认") {
		t.Fatalf("unknown rule must state cannot confirm: %s", got)
	}
	full := buildEnableRuleContext("近 30 天", &ruleEnableSummary{
		RuleID: 942100, RuleExists: true, RuleName: "SQL Injection", Severity: "CRITICAL",
		AttackType: "SQL_INJECTION", DefaultState: "ENABLED", DisableOverrides: 1,
		HistHits: 8, HistBlocks: 6, HistFPs: 1, SameTypeTotal: 40, SameTypeObserve: 12,
	})
	for _, want := range []string{"启用规则 942100", "SQL Injection", "停用覆盖 1 条", "历史命中 8 条", "仅观察 12 条", "上界参考", "非逐请求回放"} {
		if !strings.Contains(full, want) {
			t.Errorf("enable context missing %q: %s", want, full)
		}
	}
}

func TestEstimateAnomalyThreshold(t *testing.T) {
	samples := []anomalySample{
		{Action: "BLOCK", Score: 10},
		{Action: "BLOCK", Score: 3},
		{Action: "OBSERVE", Score: 8},
		{Action: "OBSERVE", Score: 2},
		{Action: "BLOCK", Score: 20},
	}
	// 新阈值 7：BLOCK(3) 解除；OBSERVE(8) 新增；估算阻断数 3-1+1=3，占 60%
	est := estimateAnomalyThreshold(samples, 7)
	if est.SampleTotal != 5 || est.CurrentlyBlocked != 3 || est.NoLongerBlocked != 1 || est.NewlyBlocked != 1 || est.NewBlockedRatio != 60 {
		t.Fatalf("unexpected estimate: %+v", est)
	}
	// 空样本
	if e := estimateAnomalyThreshold(nil, 5); e.SampleTotal != 0 || e.NewBlockedRatio != 0 {
		t.Fatalf("empty samples: %+v", e)
	}
}

func TestBuildAnomalyThresholdContext(t *testing.T) {
	if got := buildAnomalyThresholdContext("近 7 天", 8, 5, 5, anomalyThresholdEstimate{}); !strings.Contains(got, "数据不足") {
		t.Fatalf("empty estimate must state insufficient data: %s", got)
	}
	full := buildAnomalyThresholdContext("近 7 天", 8, 5, 10, anomalyThresholdEstimate{
		SampleTotal: 100, CurrentlyBlocked: 30, NoLongerBlocked: 4, NewlyBlocked: 12, NewBlockedRatio: 38})
	for _, want := range []string{"异常阈值调整为 8", "100 条", "参考区间 5-10", "4 条历史阻断不再触发", "12 条历史未阻断事件将新增阻断", "统计估算"} {
		if !strings.Contains(full, want) {
			t.Errorf("anomaly context missing %q: %s", want, full)
		}
	}
}

func TestEstimatePLSwitch(t *testing.T) {
	events := []plSeverityCount{
		{Severity: "CRITICAL", Total: 5, Blocked: 5},
		{Severity: "WARNING", Total: 20, Blocked: 4},
		{Severity: "NOTICE", Total: 30, Blocked: 2},
	}
	low, lowBlocked := estimatePLSwitch(events)
	if low != 50 || lowBlocked != 6 {
		t.Fatalf("low band: %d/%d", low, lowBlocked)
	}
}

func TestBuildPLSwitchContext(t *testing.T) {
	if got := buildPLSwitchContext("近 30 天", 2, &plSwitchSummary{}); !strings.Contains(got, "数据不足") {
		t.Fatalf("empty summary must state insufficient data: %s", got)
	}
	full := buildPLSwitchContext("近 30 天", 2, &plSwitchSummary{
		Events:   []plSeverityCount{{Severity: "CRITICAL", Total: 5, Blocked: 5}, {Severity: "NOTICE", Total: 30, Blocked: 2}},
		RuleLib:  []countKV{{Key: "CRITICAL", Count: 100}},
		EventSum: 35, RuleSum: 100,
	})
	for _, want := range []string{"PL2", "CRITICAL 5 条", "NOTICE 30 条", "规则库共 100 条", "新增命中", "跳规则"} {
		if !strings.Contains(full, want) {
			t.Errorf("pl context missing %q: %s", want, full)
		}
	}
	// PL 降低方向措辞
	down := buildPLSwitchContext("近 30 天", 1, &plSwitchSummary{
		Events: []plSeverityCount{{Severity: "NOTICE", Total: 30}}, EventSum: 30})
	if !strings.Contains(down, "可能减少命中") {
		t.Fatalf("lower direction wording: %s", down)
	}
}

func TestExceptionScopeWhere(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	where, args := exceptionScopeWhere(&exceptionScope{
		Found: true, AppID: "app-1", URIPrefix: "/api", RuleIDs: []int{942100, 941100},
	}, start, end)
	for _, clause := range []string{"application_id", "request_path LIKE", "security_event_matches", "ANY("} {
		if !strings.Contains(where, clause) {
			t.Errorf("where missing %s: %s", clause, where)
		}
	}
	if len(args) != 5 {
		t.Fatalf("want 5 args, got %d", len(args))
	}
	// LIKE 通配符转义
	if args[3] != `/api%` {
		t.Fatalf("prefix arg: %v", args[3])
	}
	_, argsEsc := exceptionScopeWhere(&exceptionScope{Found: true, URIPrefix: "/a%b_c"}, start, end)
	if argsEsc[2] != `/a\%b\_c%` {
		t.Fatalf("like escape: %v", argsEsc[2])
	}
	// 精确 URI 优先于前缀
	whereEx, _ := exceptionScopeWhere(&exceptionScope{Found: true, URIExact: "/login", URIPrefix: "/api"}, start, end)
	if !strings.Contains(whereEx, "request_path = $3") || strings.Contains(whereEx, "LIKE") {
		t.Fatalf("exact uri should win: %s", whereEx)
	}
	// 无条件：仅时间范围
	whereBare, argsBare := exceptionScopeWhere(&exceptionScope{Found: true}, start, end)
	if strings.Contains(whereBare, "application_id") || len(argsBare) != 2 {
		t.Fatalf("bare scope: %s (%d args)", whereBare, len(argsBare))
	}
}

func TestExceptionImpactRisk(t *testing.T) {
	if r := estimateAddExceptionRisk(&exceptionImpactSummary{}); r != "UNKNOWN" {
		t.Fatalf("empty: %s", r)
	}
	if r := estimateAddExceptionRisk(&exceptionImpactSummary{Total: 10, Blocked: 4}); r != "HIGH" {
		t.Fatalf("blocked without fp should be HIGH: %s", r)
	}
	if r := estimateAddExceptionRisk(&exceptionImpactSummary{Total: 10, Blocked: 4, FPs: 2}); r != "MEDIUM" {
		t.Fatalf("blocked with fp: %s", r)
	}
	if r := estimateAddExceptionRisk(&exceptionImpactSummary{Total: 10}); r != "LOW" {
		t.Fatalf("observe only: %s", r)
	}
	if r := estimateRemoveExceptionRisk(&exceptionImpactSummary{Total: 10, FPs: 3}); r != "MEDIUM" {
		t.Fatalf("remove with fp: %s", r)
	}
	if r := estimateRemoveExceptionRisk(&exceptionImpactSummary{Total: 10}); r != "LOW" {
		t.Fatalf("remove without fp: %s", r)
	}
}

func TestBuildExceptionContexts(t *testing.T) {
	// 新增例外：缺数据与完整数据
	if got := buildAddExceptionContext("近 30 天", "规则 942100", &exceptionImpactSummary{}); !strings.Contains(got, "数据不足") {
		t.Fatalf("empty add exception must state insufficient data: %s", got)
	}
	add := buildAddExceptionContext("近 30 天", "规则 942100，URI /api/pay", &exceptionImpactSummary{
		Total: 12, Blocked: 5, FPs: 3,
		URIs: []countKV{{Key: "/api/pay", Count: 12}}, Apps: []countKV{{Key: "商城", Count: 12}},
	})
	for _, want := range []string{"新增例外", "历史事件 12 条", "阻断 5 条", "误报标记 3 条", "/api/pay(12)", "MEDIUM", "不再发生", "人工审核"} {
		if !strings.Contains(add, want) {
			t.Errorf("add exception context missing %q: %s", want, add)
		}
	}
	// 删除例外：缺数据与完整数据
	exc := &exceptionScope{Found: true, Name: "支付接口误报例外", URIExact: "/api/pay", RuleIDs: []int{942100}, Action: "REMOVE_RULE", Status: "ENABLED"}
	if got := buildRemoveExceptionContext("近 30 天", exc, &exceptionImpactSummary{}); !strings.Contains(got, "数据不足") {
		t.Fatalf("empty remove exception must state insufficient data: %s", got)
	}
	rm := buildRemoveExceptionContext("近 30 天", exc, &exceptionImpactSummary{
		Total: 20, Blocked: 1, FPs: 6, Apps: []countKV{{Key: "商城", Count: 20}},
	})
	for _, want := range []string{"支付接口误报例外", "URI 精确 /api/pay", "规则 942100", "历史事件 20 条", "误报标记 6 条", "重新按规则评估", "低估"} {
		if !strings.Contains(rm, want) {
			t.Errorf("remove exception context missing %q: %s", want, rm)
		}
	}
}

func TestDescribeExceptionScope(t *testing.T) {
	got := describeExceptionScope(&exceptionScope{AppID: "app-1", URIPrefix: "/api", RuleIDs: []int{942100, 941100}})
	for _, want := range []string{"应用ID app-1", "URI 前缀 /api", "规则 942100/941100"} {
		if !strings.Contains(got, want) {
			t.Errorf("scope desc missing %q: %s", want, got)
		}
	}
	if !strings.Contains(describeExceptionScope(&exceptionScope{}), "无显式范围条件") {
		t.Fatal("empty scope should say so")
	}
}

func TestBuildReportSummaryMessage(t *testing.T) {
	def := buildReportSummaryMessage(&analyzeRequest{})
	if !strings.Contains(def, "近7天") || strings.Contains(def, "补充说明") {
		t.Fatalf("default report summary msg unexpected: %s", def)
	}
	withQ := buildReportSummaryMessage(&analyzeRequest{Period: "近30天", Question: "重点关注 ERP 应用"})
	for _, want := range []string{"近30天", "补充说明：重点关注 ERP 应用"} {
		if !strings.Contains(withQ, want) {
			t.Errorf("report summary msg missing %q: %s", want, withQ)
		}
	}
}

func TestBuildIPProfileMessage(t *testing.T) {
	plain := buildIPProfileMessage(&analyzeRequest{IP: "203.0.113.10"})
	if !strings.Contains(plain, "203.0.113.10") || strings.Contains(plain, "分析侧重点") {
		t.Fatalf("plain ip profile msg unexpected: %s", plain)
	}
	withQ := buildIPProfileMessage(&analyzeRequest{IP: "203.0.113.10", Question: "重点关注针对 198.51.100.2 的撞库手法"})
	idxTarget := strings.Index(withQ, "203.0.113.10")
	idxFocus := strings.Index(withQ, "分析侧重点：重点关注针对 198.51.100.2 的撞库手法")
	if idxTarget < 0 || idxFocus < 0 || idxTarget >= idxFocus {
		t.Fatalf("target IP must precede Question so ExtractIDs picks target IP first: %s", withQ)
	}
}

func TestBuildEventIDAnalyzeMessage(t *testing.T) {
	eid := "11111111-2222-3333-4444-555555555555"
	plain := buildEventIDAnalyzeMessage(&analyzeRequest{EventID: eid})
	if !strings.Contains(plain, eid) || strings.Contains(plain, "分析侧重点") {
		t.Fatalf("plain event id msg unexpected: %s", plain)
	}
	withQ := buildEventIDAnalyzeMessage(&analyzeRequest{
		EventID:  eid,
		Question: "检查是否与 99999999-8888-7777-6666-555555555555 误报相关",
	})
	idxEvent := strings.Index(withQ, eid)
	idxFocus := strings.Index(withQ, "分析侧重点：检查是否与 99999999-8888-7777-6666-555555555555 误报相关")
	if idxEvent < 0 || idxFocus < 0 || idxEvent >= idxFocus {
		t.Fatalf("target EventID must precede Question so ExtractIDs picks target EventID first: %s", withQ)
	}
}

func TestAnalyzeEndpointsEmptyBodyValidation(t *testing.T) {
	d := NewDeps(Deps{})
	h := noiseMux(d, noisePrincipal("ai.event_analysis.use", "ai.attack_profile.use"))
	for _, path := range []string{"/api/v1/ai/analyze/event", "/api/v1/ai/analyze/attack-profile"} {
		rec := doRequest(t, h, http.MethodPost, path, `{}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s empty body status=%d want 400 body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestBuildEventFilterContextEventIDPrecedesQuestion(t *testing.T) {
	eid := "11111111-2222-3333-4444-555555555555"
	qUUID := "99999999-8888-7777-6666-555555555555"
	req := &analyzeRequest{
		ApplicationID: "22222222-2222-2222-2222-222222222222",
		EventID:       eid,
		Question:      "是否与 " + qUUID + " 误报相关",
	}
	emptyCtx := buildEventFilterContext(req, "近 24 小时", &eventFilterSummary{})
	if iE, iQ := strings.Index(emptyCtx, eid), strings.Index(emptyCtx, qUUID); iE < 0 || iQ < 0 || iE >= iQ {
		t.Fatalf("Total=0: EventID must precede Question: %s", emptyCtx)
	}
	fullCtx := buildEventFilterContext(req, "近 24 小时", &eventFilterSummary{
		Total: 3, Blocked: 2, FirstAt: time.Now(), LastAt: time.Now(),
	})
	if iE, iQ := strings.Index(fullCtx, eid), strings.Index(fullCtx, qUUID); iE < 0 || iQ < 0 || iE >= iQ {
		t.Fatalf("Total>0: EventID must precede Question: %s", fullCtx)
	}
}

func TestBuildReportSummaryMessageNoFalsePositiveKeyword(t *testing.T) {
	msg := buildReportSummaryMessage(&analyzeRequest{})
	if strings.Contains(msg, "误报") {
		t.Fatalf("buildReportSummaryMessage must not contain 误报: %s", msg)
	}
	if !strings.Contains(msg, "例外与处置建议") {
		t.Fatalf("buildReportSummaryMessage missing 例外与处置建议: %s", msg)
	}
	if plan := aiorchestrator.Classify(msg); plan.TaskType != aiorchestrator.TaskReportSummary {
		t.Fatalf("Classify(report summary) = %s, want %s", plan.TaskType, aiorchestrator.TaskReportSummary)
	}
}

func TestAnalyzeRunInputBuildersAllEndpoints(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	appUUID := "22222222-2222-2222-2222-222222222222"
	evtUUID := "11111111-2222-3333-4444-555555555555"
	qUUID := "99999999-8888-7777-6666-555555555555"

	// 1. AnalyzeEvent (filter + AppID + EventID + Question="昨天 是否误报")
	evFilterIn := buildEventFilterRunInput(&analyzeRequest{
		ApplicationID: appUUID, EventID: evtUUID, RuleID: 900110, IP: "2001:db8::1",
		URI: "/login", TimeRange: "24h", Question: "昨天 是否误报 " + qUUID,
	}, "近 24 小时", &eventFilterSummary{Total: 1, FirstAt: now, LastAt: now}, now)
	plan := aiorchestrator.ResolveRunPlan(evFilterIn, evFilterIn.Message)
	evIDs, rIDs, ips := aiorchestrator.ResolveRunIDs(evFilterIn, evFilterIn.Message)
	tr := aiorchestrator.ResolveRunTimeRange(evFilterIn, evFilterIn.Message, now)
	if plan.TaskType != aiorchestrator.TaskEventAnalysis {
		t.Fatalf("event filter plan = %+v", plan)
	}
	if len(evIDs) != 1 || evIDs[0] != evtUUID || len(rIDs) != 1 || rIDs[0] != 900110 || len(ips) != 1 || ips[0] != "2001:db8::1" {
		t.Fatalf("event filter IDs = %v %v %v", evIDs, rIDs, ips)
	}
	if evFilterIn.URI != "/login" || evFilterIn.ApplicationID != appUUID || tr.Label != "近 24 小时" {
		t.Fatalf("event filter meta mismatch: uri=%q app=%q tr=%+v", evFilterIn.URI, evFilterIn.ApplicationID, tr)
	}

	// 1b. AnalyzeEvent (filter without EventID: AppID must NOT leak into EventIDs)
	evNoEvtIn := buildEventFilterRunInput(&analyzeRequest{ApplicationID: appUUID, TimeRange: "24h"}, "近 24 小时", &eventFilterSummary{}, now)
	if evNoEvt, _, _ := aiorchestrator.ResolveRunIDs(evNoEvtIn, evNoEvtIn.Message); len(evNoEvt) != 0 {
		t.Fatalf("ApplicationID leaked into EventIDs: %v", evNoEvt)
	}

	// 1c. AnalyzeEvent (question only allows ExtractIDs)
	evQIn := buildEventQuestionRunInput(&analyzeRequest{Question: "分析 " + evtUUID + " 根因"})
	if qPlan := aiorchestrator.ResolveRunPlan(evQIn, evQIn.Message); qPlan.TaskType != aiorchestrator.TaskEventAnalysis {
		t.Fatalf("event question plan = %+v", qPlan)
	}
	if qEvs, _, _ := aiorchestrator.ResolveRunIDs(evQIn, evQIn.Message); len(qEvs) != 1 || qEvs[0] != evtUUID {
		t.Fatalf("event question ExtractIDs = %v", qEvs)
	}

	// 2. AnalyzeFalsePositive with non-91x..96x rule_id=900110
	fpIn := buildFalsePositiveRunInput(&analyzeRequest{RuleID: 900110}, nil)
	if fpPlan := aiorchestrator.ResolveRunPlan(fpIn, fpIn.Message); fpPlan.TaskType != aiorchestrator.TaskFalsePositive {
		t.Fatalf("fp plan = %+v", fpPlan)
	}
	if _, fpRules, _ := aiorchestrator.ResolveRunIDs(fpIn, fpIn.Message); len(fpRules) != 1 || fpRules[0] != 900110 {
		t.Fatalf("fp rules = %v, want [900110]", fpRules)
	}

	// 3. AnalyzeAttackProfile: IPv6 + URI + AppID + Question
	ipProfIn := buildIPProfileRunInput(&analyzeRequest{IP: "2001:db8::1", TimeRange: "7d", Question: "昨天 是否误报 compare with 10.0.0.1"}, now)
	if p := aiorchestrator.ResolveRunPlan(ipProfIn, ipProfIn.Message); p.TaskType != aiorchestrator.TaskAttackProfile {
		t.Fatalf("ip profile plan = %+v", p)
	}
	if _, _, profIPs := aiorchestrator.ResolveRunIDs(ipProfIn, ipProfIn.Message); len(profIPs) != 1 || profIPs[0] != "2001:db8::1" {
		t.Fatalf("ip profile IPs = %v", profIPs)
	}
	if profTR := aiorchestrator.ResolveRunTimeRange(ipProfIn, ipProfIn.Message, now); profTR.Label != "近 7 天" {
		t.Fatalf("ip profile TimeRange = %+v", profTR)
	}

	uriProfIn := buildURIProfileRunInput(&analyzeRequest{URI: "/api/pay/", Question: "排查根因"}, "近 7 天", &uriProfileSummary{
		URI: "/api/pay/", Total: 5, FirstAt: now, LastAt: now, SourceIPs: []countKV{{"198.51.100.7", 5}},
	}, now)
	if _, _, uriIPs := aiorchestrator.ResolveRunIDs(uriProfIn, uriProfIn.Message); len(uriIPs) != 0 || uriProfIn.URI != "/api/pay/" {
		t.Fatalf("uri profile leaked TOP IP or lost URI: ips=%v uri=%q", uriIPs, uriProfIn.URI)
	}

	appProfIn := buildAppProfileRunInput(&analyzeRequest{ApplicationID: appUUID, Question: "是否误报"}, "近 7 天", &appProfileSummary{
		AppID: appUUID, Total: 10, FirstAt: now, LastAt: now, URIs: []countKV{{"/order", 10}}, SourceIPs: []countKV{{"192.0.2.9", 5}},
	}, now)
	if aEv, _, aIP := aiorchestrator.ResolveRunIDs(appProfIn, appProfIn.Message); len(aEv) != 0 || len(aIP) != 0 || appProfIn.ApplicationID != appUUID {
		t.Fatalf("app profile leaked IDs/IPs: ev=%v ip=%v app=%q", aEv, aIP, appProfIn.ApplicationID)
	}

	// 4. AnalyzeAttackChain with IPv6
	acIn := buildAttackChainRunInput(&analyzeRequest{IP: "2001:db8::1"})
	if p := aiorchestrator.ResolveRunPlan(acIn, acIn.Message); p.TaskType != aiorchestrator.TaskAttackChain {
		t.Fatalf("attack chain plan = %+v", p)
	}
	if _, _, acIPs := aiorchestrator.ResolveRunIDs(acIn, acIn.Message); len(acIPs) != 1 || acIPs[0] != "2001:db8::1" {
		t.Fatalf("attack chain IPv6 = %v", acIPs)
	}

	// 5. AnalyzePolicyRecommendation
	prIn := buildPolicyRecommendationRunInput(&analyzeRequest{Question: "排查误报"})
	if p := aiorchestrator.ResolveRunPlan(prIn, prIn.Message); p.TaskType != aiorchestrator.TaskPolicyRec {
		t.Fatalf("policy rec plan = %+v", p)
	}

	// 6. AnalyzeWhatIf (including "误报" in prompt & exception UUID)
	wiIn := buildWhatIfRunInput(&analyzeRequest{RuleID: 900110, ApplicationID: appUUID, URI: "/api/pay", TimeRange: "30d"},
		"如果关闭规则 900110 会有什么影响？估算误报减少 "+qUUID, "30d", now)
	if p := aiorchestrator.ResolveRunPlan(wiIn, wiIn.Message); p.TaskType != aiorchestrator.TaskWhatIf {
		t.Fatalf("what-if plan = %+v", p)
	}
	if wiEv, wiRules, _ := aiorchestrator.ResolveRunIDs(wiIn, wiIn.Message); len(wiEv) != 0 || len(wiRules) != 1 || wiRules[0] != 900110 {
		t.Fatalf("what-if IDs = ev:%v rules:%v", wiEv, wiRules)
	}

	// 7. AnalyzeRootCause with "误报" in question
	rcIn := buildRootCauseRunInput(&analyzeRequest{Question: "为什么误报率升高"})
	if p := aiorchestrator.ResolveRunPlan(rcIn, rcIn.Message); p.TaskType != aiorchestrator.TaskRootCause {
		t.Fatalf("root cause plan = %+v", p)
	}

	// 8. AnalyzeReportSummary with adversarial question
	rsIn := buildReportSummaryRunInput(&analyzeRequest{Period: "近7天", Question: "是否误报"})
	if p := aiorchestrator.ResolveRunPlan(rsIn, rsIn.Message); p.TaskType != aiorchestrator.TaskReportSummary {
		t.Fatalf("report summary plan = %+v", p)
	}
}
