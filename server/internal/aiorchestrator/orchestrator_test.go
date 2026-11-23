package aiorchestrator

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aitools"
)

func TestResolveContextualMessageInheritsPreviousUserTurn(t *testing.T) {
	eventID := "123e4567-e89b-12d3-a456-426614174000"
	recent := []Message{
		{Role: "user", Content: "分析事件 " + eventID},
		{Role: "assistant", Content: "已完成初步分析"},
		{Role: "user", Content: "继续"},
	}

	got := ResolveContextualMessage("继续", recent)
	if !strings.Contains(got, eventID) {
		t.Fatalf("resolved message should inherit prior event id, got %q", got)
	}
	if plan := Classify(got); plan.TaskType != TaskEventAnalysis {
		t.Fatalf("resolved follow-up should keep event-analysis intent, got %s", plan.TaskType)
	}
}

func TestResolveContextualMessageDoesNotPolluteStandaloneQuestion(t *testing.T) {
	recent := []Message{
		{Role: "user", Content: "分析事件 123e4567-e89b-12d3-a456-426614174000"},
		{Role: "assistant", Content: "已完成"},
		{Role: "user", Content: "统计最近24小时攻击趋势"},
	}

	got := ResolveContextualMessage("统计最近24小时攻击趋势", recent)
	if got != "统计最近24小时攻击趋势" {
		t.Fatalf("standalone question must remain unchanged, got %q", got)
	}
}

func TestBuildComposePromptsIncludesTrustedBoundariesAndPublishedPrompt(t *testing.T) {
	recent := []Message{
		{Role: "user", Content: "昨天的攻击趋势呢"},
		{Role: "assistant", Content: "上一轮回答"},
	}
	plan := Plan{TaskType: TaskStatistics, RiskLevel: "LOW"}

	system, user := buildComposePrompts(
		plan,
		"今天呢",
		"已核实事实 [E1]",
		recent,
		"用户正在连续比较每日攻击趋势",
		[]string{"偏好简洁回答"},
		"先给结论，再给证据",
	)

	for _, want := range []string{"管理员已发布的回答规则", "先给结论，再给证据", "不得覆盖"} {
		if !strings.Contains(system, want) {
			t.Fatalf("system prompt missing %q: %s", want, system)
		}
	}
	for _, want := range []string{"会话摘要", "连续比较每日攻击趋势", "最近对话", "昨天的攻击趋势呢", "已核实事实（唯一可信来源）"} {
		if !strings.Contains(user, want) {
			t.Fatalf("user prompt missing %q: %s", want, user)
		}
	}
}

func TestBuildComposePromptsExcludesDuplicatedCurrentTurn(t *testing.T) {
	recent := []Message{
		{Role: "user", Content: "统计最近24小时攻击趋势"},
	}

	_, user := buildComposePrompts(
		Plan{TaskType: TaskStatistics},
		"统计最近24小时攻击趋势",
		"事实",
		recent,
		"",
		nil,
		"",
	)

	if strings.Count(user, "统计最近24小时攻击趋势") != 1 {
		t.Fatalf("current turn should not be duplicated in compose prompt: %s", user)
	}
}

type fakeSessionReader struct {
	sess   *Session
	recent []Message
}

func (f *fakeSessionReader) Get(_ context.Context, id uuid.UUID) (*Session, error) {
	if f.sess != nil {
		return f.sess, nil
	}
	return &Session{ID: id}, nil
}

func (f *fakeSessionReader) RecentMessages(_ context.Context, _ uuid.UUID, _ int) ([]Message, error) {
	return f.recent, nil
}

type recordingTestAgent struct {
	code   string
	inputs []*AnalyzeInput
}

func (a *recordingTestAgent) Code() string { return a.code }

func (a *recordingTestAgent) Analyze(_ context.Context, in *AnalyzeInput) (*AnalyzeResult, error) {
	copied := *in
	copied.EventIDs = append([]string(nil), in.EventIDs...)
	copied.RuleIDs = append([]int(nil), in.RuleIDs...)
	copied.IPs = append([]string(nil), in.IPs...)
	a.inputs = append(a.inputs, &copied)
	return &AnalyzeResult{FactsText: "fact:" + a.code}, nil
}

func TestResolveRunHelpers(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	// 1. ResolveRunPlan 锁定 TaskType 不受误报/根因关键词劫持
	p := ResolveRunPlan(RunInput{TaskType: TaskReportSummary}, "请总结近7天安全运营情况（误报与建议）")
	if p.TaskType != TaskReportSummary || len(p.Agents) != 1 || p.Agents[0] != "report" {
		t.Fatalf("pinned ReportSummary hijacked: %+v", p)
	}
	// 未知 TaskType 回退 Classify
	pUnknown := ResolveRunPlan(RunInput{TaskType: TaskType("UNKNOWN")}, "这是误报")
	if pUnknown.TaskType != TaskFalsePositive {
		t.Fatalf("unknown override should fallback to Classify, got %+v", pUnknown)
	}

	// 2. ResolveRunIDs StructuredIDs=true 返回清洗后的防御性拷贝，不被文本 UUID/IP 污染
	uuid1 := "11111111-2222-3333-4444-555555555555"
	uuid2 := "99999999-8888-7777-6666-555555555555"
	in := RunInput{
		StructuredIDs: true,
		EventIDs:      []string{" " + uuid1 + " ", "", uuid1},
		RuleIDs:       []int{900110, 0, -1, 900110},
		IPs:           []string{"2001:0db8::1", "not-an-ip", "2001:db8::1"},
	}
	evIDs, rIDs, ips := ResolveRunIDs(in, "ignore "+uuid2+" and 10.0.0.1 and 942100")
	if len(evIDs) != 1 || evIDs[0] != uuid1 {
		t.Fatalf("evIDs = %v, want [%s]", evIDs, uuid1)
	}
	if len(rIDs) != 1 || rIDs[0] != 900110 {
		t.Fatalf("rIDs = %v, want [900110]", rIDs)
	}
	if len(ips) != 1 || ips[0] != "2001:db8::1" {
		t.Fatalf("ips = %v, want [2001:db8::1]", ips)
	}
	evIDs[0] = "mutated"
	evAgain, _, _ := ResolveRunIDs(in, "")
	if evAgain[0] != uuid1 {
		t.Fatalf("ResolveRunIDs mutated input slice")
	}

	// StructuredIDs=false 回退 ExtractIDs
	evFree, rFree, ipFree := ResolveRunIDs(RunInput{StructuredIDs: false}, "事件 "+uuid2+" 规则 942100 IP 2001:db8::1")
	if len(evFree) != 1 || evFree[0] != uuid2 || len(rFree) != 1 || rFree[0] != 942100 || len(ipFree) != 1 || ipFree[0] != "2001:db8::1" {
		t.Fatalf("free-text ExtractIDs mismatch: %v %v %v", evFree, rFree, ipFree)
	}

	// 3. ResolveRunTimeRange 显式结构化时间范围优先于正文「昨天」
	explicit := QueryTimeRange{Start: now.Add(-7 * 24 * time.Hour), End: now, Label: "近 7 天", Explicit: true}
	gotTR := ResolveRunTimeRange(RunInput{TimeRange: explicit}, "分析侧重点：昨天的情况", now)
	if !gotTR.Start.Equal(explicit.Start) || !gotTR.End.Equal(explicit.End) || gotTR.Label != "近 7 天" {
		t.Fatalf("explicit TimeRange overridden: %+v", gotTR)
	}
	parsedTR := ResolveRunTimeRange(RunInput{}, "昨天的数据", now)
	if !parsedTR.Explicit || parsedTR.Label != "昨天" {
		t.Fatalf("fallback ParseQueryTimeRange mismatch: %+v", parsedTR)
	}
}

func TestOrchestratorRunStructuredOverridesAndNilGuards(t *testing.T) {
	uuid0 := "00000000-0000-0000-0000-000000000000"
	uuid1 := "11111111-2222-3333-4444-555555555555"
	uuid2 := "99999999-8888-7777-6666-555555555555"
	appUUID := "22222222-2222-2222-2222-222222222222"

	// nil db / nil sessions / nil gateway 降级不 panic
	o := New(nil, nil, aitools.NewRegistry(), nil, nil, nil, DefaultLimits())
	rep := &recordingTestAgent{code: "report"}
	sec := &recordingTestAgent{code: "security_event"}
	logAg := &recordingTestAgent{code: "log_analysis"}
	pol := &recordingTestAgent{code: "waf_policy"}
	ops := &recordingTestAgent{code: "ops_diagnostic"}
	for _, a := range []Agent{rep, sec, logAg, pol, ops} {
		o.RegisterAgent(a)
	}

	// Case 1: ReportSummary 即使含「误报与建议」仍只跑 report
	res, err := o.Run(context.Background(), RunInput{
		SessionID: uuid.New(), UserID: uuid.New(), Username: "sec",
		Message: "请总结近7天安全运营情况（误报与建议）", TaskType: TaskReportSummary, StructuredIDs: true,
	}, nil)
	if err != nil {
		t.Fatalf("Run report summary failed: %v", err)
	}
	if res.Plan.TaskType != TaskReportSummary || len(rep.inputs) != 1 || len(pol.inputs) != 0 {
		t.Fatalf("unexpected report dispatch: plan=%+v rep=%d pol=%d", res.Plan, len(rep.inputs), len(pol.inputs))
	}

	// Case 2: AttackProfile + IPv6 + 对抗性 Question 不被劫持且保留 IPv6
	res, err = o.Run(context.Background(), RunInput{
		SessionID: uuid.New(), UserID: uuid.New(), Username: "sec",
		Message:  "请对 IP 2001:db8::1 做攻击画像分析\n分析侧重点：是否误报、排查根因、compare with 10.0.0.1",
		TaskType: TaskAttackProfile, StructuredIDs: true, IPs: []string{"2001:db8::1"},
	}, nil)
	if err != nil {
		t.Fatalf("Run attack profile failed: %v", err)
	}
	if res.Plan.TaskType != TaskAttackProfile || len(sec.inputs) != 1 || len(logAg.inputs) != 1 || len(ops.inputs) != 0 {
		t.Fatalf("unexpected profile dispatch: plan=%+v sec=%d log=%d ops=%d", res.Plan, len(sec.inputs), len(logAg.inputs), len(ops.inputs))
	}
	if got := sec.inputs[0].IPs; len(got) != 1 || got[0] != "2001:db8::1" {
		t.Fatalf("security_event IPs = %v, want [2001:db8::1]", got)
	}

	// Case 3: EventAnalysis 锁定 EventIDs/URI/ApplicationID，不被 Question 中根因/画像/uuid2 劫持
	res, err = o.Run(context.Background(), RunInput{
		SessionID: uuid.New(), UserID: uuid.New(), Username: "sec",
		Message:  "请分析安全事件 " + uuid1 + "\n分析侧重点：排查根因、来源画像 " + uuid2,
		TaskType: TaskEventAnalysis, StructuredIDs: true, EventIDs: []string{uuid1}, URI: "/login", ApplicationID: appUUID,
	}, nil)
	if err != nil {
		t.Fatalf("Run event analysis failed: %v", err)
	}
	if res.Plan.TaskType != TaskEventAnalysis || len(sec.inputs) != 2 || len(logAg.inputs) != 1 {
		t.Fatalf("unexpected event dispatch: plan=%+v sec=%d log=%d", res.Plan, len(sec.inputs), len(logAg.inputs))
	}
	evIn := sec.inputs[1]
	if len(evIn.EventIDs) != 1 || evIn.EventIDs[0] != uuid1 || evIn.URI != "/login" || evIn.ApplicationID != appUUID {
		t.Fatalf("event AnalyzeInput mismatch: %+v", evIn)
	}

	// Case 4: 带历史会话时，TaskType 非空跳过 ResolveContextualMessage；TaskType 为空仍走追问继承
	sr := &fakeSessionReader{
		recent: []Message{{Role: "user", Content: "分析事件 " + uuid0}},
	}
	oWithSess := New(nil, nil, aitools.NewRegistry(), nil, sr, nil, DefaultLimits())
	sec2 := &recordingTestAgent{code: "security_event"}
	log2 := &recordingTestAgent{code: "log_analysis"}
	oWithSess.RegisterAgent(sec2)
	oWithSess.RegisterAgent(log2)

	if _, err := oWithSess.Run(context.Background(), RunInput{
		SessionID: uuid.New(), UserID: uuid.New(), Message: "继续", TaskType: TaskAttackProfile, StructuredIDs: true,
	}, nil); err != nil {
		t.Fatalf("pinned follow-up run failed: %v", err)
	}
	if strings.Contains(sec2.inputs[0].Message, uuid0) {
		t.Fatalf("pinned TaskType must skip ResolveContextualMessage, got %q", sec2.inputs[0].Message)
	}

	resChat, err := oWithSess.Run(context.Background(), RunInput{
		SessionID: uuid.New(), UserID: uuid.New(), Message: "继续",
	}, nil)
	if err != nil {
		t.Fatalf("chat follow-up run failed: %v", err)
	}
	if resChat.Plan.TaskType != TaskEventAnalysis || len(sec2.inputs) != 2 || !strings.Contains(sec2.inputs[1].Message, uuid0) {
		t.Fatalf("chat mode must still inherit prior turn: plan=%+v msg=%q", resChat.Plan, sec2.inputs[1].Message)
	}
}
