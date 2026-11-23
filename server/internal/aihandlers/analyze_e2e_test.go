// analyze_e2e_test.go 离线 HTTP → Handler → Orchestrator.Run → Agent 端到端契约测试：
// 无需 PostgreSQL/Ollama，通过内存 SessionStore、CostService 与打桩 Agent 实证 B2-4/B2-5/B2-6
// 等结构化分析端点的意图锁定、IPv6/ID 隔离及一次性会话无泄漏清理。
package aihandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aicost"
	"github.com/jiuzhang-waf/server/internal/aimodel"
	"github.com/jiuzhang-waf/server/internal/aiorchestrator"
	"github.com/jiuzhang-waf/server/internal/aitools"
)

type memSessionStore struct {
	mu       sync.Mutex
	sessions map[uuid.UUID]*aiorchestrator.Session
}

func newMemSessionStore() *memSessionStore {
	return &memSessionStore{sessions: map[uuid.UUID]*aiorchestrator.Session{}}
}

func (m *memSessionStore) Create(_ context.Context, userID uuid.UUID, title string) (*aiorchestrator.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := &aiorchestrator.Session{ID: uuid.New(), UserID: userID, Title: title, Status: "ACTIVE"}
	m.sessions[s.ID] = s
	return s, nil
}

func (m *memSessionStore) Get(_ context.Context, id uuid.UUID) (*aiorchestrator.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, aiorchestrator.ErrSessionNotFound
	}
	cp := *s
	return &cp, nil
}

func (m *memSessionStore) List(_ context.Context, _ uuid.UUID, _ bool, _, _ int) ([]aiorchestrator.Session, int64, error) {
	return nil, 0, nil
}
func (m *memSessionStore) Rename(_ context.Context, _ uuid.UUID, _ string) error { return nil }
func (m *memSessionStore) Archive(_ context.Context, _ uuid.UUID) error        { return nil }

func (m *memSessionStore) Delete(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}

func (m *memSessionStore) AppendMessage(_ context.Context, _ uuid.UUID, _, _ string, _, _ *uuid.UUID, _, _ int, _ string) (uuid.UUID, error) {
	return uuid.New(), nil
}

func (m *memSessionStore) RecentMessages(_ context.Context, _ uuid.UUID, _ int) ([]aiorchestrator.Message, error) {
	return nil, nil
}

func (m *memSessionStore) MaybeCompress(_ context.Context, _ uuid.UUID, _ int) (bool, error) {
	return false, nil
}

func (m *memSessionStore) AddFeedback(_ context.Context, _, _, _ uuid.UUID, _ int, _, _ string) error {
	return nil
}

func (m *memSessionStore) GetMessage(_ context.Context, _ uuid.UUID) (*aiorchestrator.Message, *uuid.UUID, error) {
	return nil, nil, aiorchestrator.ErrSessionNotFound
}

func (m *memSessionStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

type stubCostService struct {
	usageCalls int
}

func (s *stubCostService) RecordUsage(_ context.Context, _ uuid.UUID, _, _ *uuid.UUID, _ *uuid.UUID, _, _, _ int, _ float64) error {
	s.usageCalls++
	return nil
}

func (s *stubCostService) CheckQuota(_ context.Context, _ uuid.UUID, _ string, _ int) error {
	return nil
}
func (s *stubCostService) Overview(_ context.Context) (*aicost.Usage, error) {
	return &aicost.Usage{}, nil
}
func (s *stubCostService) ByUser(_ context.Context) ([]map[string]interface{}, error)  { return nil, nil }
func (s *stubCostService) ByAgent(_ context.Context) ([]map[string]interface{}, error) { return nil, nil }
func (s *stubCostService) ByTask(_ context.Context) ([]map[string]interface{}, error)  { return nil, nil }

type recordedAgentCall struct {
	agentCode string
	input     aiorchestrator.AnalyzeInput
}

type recordingAgent struct {
	code  string
	calls *[]recordedAgentCall
	mu    *sync.Mutex
}

func (a *recordingAgent) Code() string { return a.code }

func (a *recordingAgent) Analyze(_ context.Context, in *aiorchestrator.AnalyzeInput) (*aiorchestrator.AnalyzeResult, error) {
	cp := *in
	cp.EventIDs = append([]string(nil), in.EventIDs...)
	cp.RuleIDs = append([]int(nil), in.RuleIDs...)
	cp.IPs = append([]string(nil), in.IPs...)
	a.mu.Lock()
	*a.calls = append(*a.calls, recordedAgentCall{agentCode: a.code, input: cp})
	a.mu.Unlock()
	return &aiorchestrator.AnalyzeResult{FactsText: "stub fact from " + a.code}, nil
}

func TestAnalyzeHTTPToAgentE2ENoHijack(t *testing.T) {
	memSess := newMemSessionStore()
	costSvc := &stubCostService{}
	orch := aiorchestrator.New(nil, aimodel.NewGateway(nil), aitools.NewRegistry(), nil, memSess, nil, aiorchestrator.DefaultLimits())

	var mu sync.Mutex
	var calls []recordedAgentCall
	for _, code := range []string{"report", "security_event", "log_analysis", "waf_policy", "ops_diagnostic"} {
		orch.RegisterAgent(&recordingAgent{code: code, calls: &calls, mu: &mu})
	}

	d := NewDeps(Deps{Orch: orch, Sessions: memSess, Cost: costSvc})
	h := noiseMux(d, noisePrincipal(
		"ai.event_analysis.use",
		"ai.false_positive_analysis.use",
		"ai.attack_profile.use",
		"ai.attack_chain.use",
		"ai.policy_recommendation.use",
		"ai.what_if.use",
		"ai.root_cause.use",
		"ai.report_summary.use",
	))

	evt1 := "11111111-2222-3333-4444-555555555555"
	evt2 := "99999999-8888-7777-6666-555555555555"

	cases := []struct {
		name       string
		path       string
		body       string
		wantTask   aiorchestrator.TaskType
		wantAgents []string
		wantIPs    []string
		wantEvents []string
		wantRules  []int
	}{
		{
			name:       "report-summary empty body",
			path:       "/api/v1/ai/analyze/report-summary",
			body:       `{}`,
			wantTask:   aiorchestrator.TaskReportSummary,
			wantAgents: []string{"report"},
		},
		{
			name:       "report-summary adversarial false positive question",
			path:       "/api/v1/ai/analyze/report-summary",
			body:       `{"period":"近7天","question":"是否误报"}`,
			wantTask:   aiorchestrator.TaskReportSummary,
			wantAgents: []string{"report"},
		},
		{
			name:       "attack-profile ipv4 with false-positive question",
			path:       "/api/v1/ai/analyze/attack-profile",
			body:       `{"ip":"203.0.113.10","question":"是否误报"}`,
			wantTask:   aiorchestrator.TaskAttackProfile,
			wantAgents: []string{"security_event", "log_analysis"},
			wantIPs:    []string{"203.0.113.10"},
		},
		{
			name:       "attack-profile ipv4 with root-cause question",
			path:       "/api/v1/ai/analyze/attack-profile",
			body:       `{"ip":"203.0.113.10","question":"排查根因"}`,
			wantTask:   aiorchestrator.TaskAttackProfile,
			wantAgents: []string{"security_event", "log_analysis"},
			wantIPs:    []string{"203.0.113.10"},
		},
		{
			name:       "attack-profile ipv6 with ipv4 in question",
			path:       "/api/v1/ai/analyze/attack-profile",
			body:       `{"ip":"2001:db8::1","question":"compare with 10.0.0.1"}`,
			wantTask:   aiorchestrator.TaskAttackProfile,
			wantAgents: []string{"security_event", "log_analysis"},
			wantIPs:    []string{"2001:db8::1"},
		},
		{
			name:       "event with root-cause question",
			path:       "/api/v1/ai/analyze/event",
			body:       `{"event_id":"` + evt1 + `","question":"排查根因"}`,
			wantTask:   aiorchestrator.TaskEventAnalysis,
			wantAgents: []string{"security_event"},
			wantEvents: []string{evt1},
		},
		{
			name:       "event with attack-profile question",
			path:       "/api/v1/ai/analyze/event",
			body:       `{"event_id":"` + evt1 + `","question":"查看来源画像"}`,
			wantTask:   aiorchestrator.TaskEventAnalysis,
			wantAgents: []string{"security_event"},
			wantEvents: []string{evt1},
		},
		{
			name:       "event with competing uuid and false-positive question",
			path:       "/api/v1/ai/analyze/event",
			body:       `{"event_id":"` + evt1 + `","question":"检查是否与 ` + evt2 + ` 误报相关"}`,
			wantTask:   aiorchestrator.TaskEventAnalysis,
			wantAgents: []string{"security_event"},
			wantEvents: []string{evt1},
		},
		{
			name:       "false-positive non-crs rule id",
			path:       "/api/v1/ai/analyze/false-positive",
			body:       `{"rule_id":900110}`,
			wantTask:   aiorchestrator.TaskFalsePositive,
			wantAgents: []string{"waf_policy", "security_event"},
			wantRules:  []int{900110},
		},
		{
			name:       "attack-chain ipv6",
			path:       "/api/v1/ai/analyze/attack-chain",
			body:       `{"ip":"2001:db8::1"}`,
			wantTask:   aiorchestrator.TaskAttackChain,
			wantAgents: []string{"security_event", "log_analysis"},
			wantIPs:    []string{"2001:db8::1"},
		},
		{
			name:       "policy-recommendation empty body",
			path:       "/api/v1/ai/analyze/policy-recommendation",
			body:       `{}`,
			wantTask:   aiorchestrator.TaskPolicyRec,
			wantAgents: []string{"waf_policy"},
		},
		{
			name:       "what-if disable_rule 900110",
			path:       "/api/v1/ai/analyze/what-if",
			body:       `{"rule_id":900110,"scenario":"disable_rule"}`,
			wantTask:   aiorchestrator.TaskWhatIf,
			wantAgents: []string{"waf_policy"},
			wantRules:  []int{900110},
		},
		{
			name:       "root-cause with false-positive keyword",
			path:       "/api/v1/ai/analyze/root-cause",
			body:       `{"question":"为什么误报率升高"}`,
			wantTask:   aiorchestrator.TaskRootCause,
			wantAgents: []string{"ops_diagnostic", "log_analysis"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			calls = nil
			mu.Unlock()

			rec := doRequest(t, h, http.MethodPost, tc.path, tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d want 200 body=%s", rec.Code, rec.Body.String())
			}

			var resp struct {
				Data struct {
					Plan aiorchestrator.Plan `json:"plan"`
				} `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response failed: %v body=%s", err, rec.Body.String())
			}
			if resp.Data.Plan.TaskType != tc.wantTask {
				t.Fatalf("plan.task_type = %s, want %s", resp.Data.Plan.TaskType, tc.wantTask)
			}
			if !reflect.DeepEqual(resp.Data.Plan.Agents, tc.wantAgents) {
				t.Fatalf("plan.agents = %v, want %v", resp.Data.Plan.Agents, tc.wantAgents)
			}

			mu.Lock()
			gotCalls := append([]recordedAgentCall(nil), calls...)
			mu.Unlock()

			var gotAgents []string
			for _, c := range gotCalls {
				gotAgents = append(gotAgents, c.agentCode)
				if c.input.TaskType != tc.wantTask {
					t.Errorf("agent %s received TaskType=%s, want %s", c.agentCode, c.input.TaskType, tc.wantTask)
				}
				if tc.wantIPs != nil && !reflect.DeepEqual(c.input.IPs, tc.wantIPs) {
					t.Errorf("agent %s IPs=%v, want %v", c.agentCode, c.input.IPs, tc.wantIPs)
				}
				if tc.wantEvents != nil && !reflect.DeepEqual(c.input.EventIDs, tc.wantEvents) {
					t.Errorf("agent %s EventIDs=%v, want %v", c.agentCode, c.input.EventIDs, tc.wantEvents)
				}
				if tc.wantRules != nil && !reflect.DeepEqual(c.input.RuleIDs, tc.wantRules) {
					t.Errorf("agent %s RuleIDs=%v, want %v", c.agentCode, c.input.RuleIDs, tc.wantRules)
				}
			}
			if !reflect.DeepEqual(gotAgents, tc.wantAgents) {
				t.Fatalf("invoked agents = %v, want %v", gotAgents, tc.wantAgents)
			}
		})
	}

	if got := memSess.count(); got != 0 {
		t.Fatalf("ephemeral sessions leaked: count=%d, want 0", got)
	}
	if costSvc.usageCalls != len(cases) {
		t.Fatalf("usageCalls=%d, want %d", costSvc.usageCalls, len(cases))
	}
}
