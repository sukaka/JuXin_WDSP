package apia2a

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jiuzhang-waf/server/internal/accesscontrolevents"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func TestValidatePolicyAndBounds(t *testing.T) {
	appID := uuid.New()
	p := DefaultPolicy(appID)
	p.Mode = "protect"
	p.A2APathPrefixes = []string{" /a2a ", "/a2a", "/.well-known/agent.json"}
	p.AllowedCallerAgents = []string{" planner-agent ", "billing-agent", "planner-agent"}
	p.MaxDelegationDepth = 5
	p.LoopWindowSeconds = 120
	p.MaxCallsPerTaskWindow = 100
	p.ConfidentialReadPatterns = []string{"/api/v1/secrets", "read_secret"}
	p.ExternalEgressPatterns = []string{"send_email", "webhook"}

	NormalizePolicy(p)
	if p.Mode != ModeProtect {
		t.Fatalf("normalize mode = %q, want PROTECT", p.Mode)
	}
	if len(p.A2APathPrefixes) != 2 || len(p.AllowedCallerAgents) != 2 {
		t.Fatalf("dedup failed: prefixes=%v callers=%v", p.A2APathPrefixes, p.AllowedCallerAgents)
	}
	if errs := ValidatePolicy(p); len(errs) > 0 {
		t.Fatalf("valid policy rejected: %+v", errs)
	}

	fieldSet := func(errs []FieldError) map[string]bool {
		m := map[string]bool{}
		for _, e := range errs {
			m[e.Field] = true
		}
		return m
	}

	tooManyPrefixes := make([]string, MaxPathPrefixes+1)
	for i := range tooManyPrefixes {
		tooManyPrefixes[i] = "/a2a-" + string(rune('a'+i%26))
	}
	tooManyCallers := make([]string, MaxAllowedAgents+1)
	for i := range tooManyCallers {
		tooManyCallers[i] = "agent-" + string(rune('a'+i%26))
	}
	tooManyPatterns := make([]string, MaxPatterns+1)
	for i := range tooManyPatterns {
		tooManyPatterns[i] = "pat-" + string(rune('a'+i%26))
	}

	cases := []struct {
		name   string
		mutate func(*Policy)
		field  string
	}{
		{"invalid mode", func(x *Policy) { x.Mode = "BLOCK" }, "mode"},
		{"prefix missing slash", func(x *Policy) { x.A2APathPrefixes = []string{"a2a"} }, "a2a_path_prefixes[0]"},
		{"prefix has query", func(x *Policy) { x.A2APathPrefixes = []string{"/a2a?x=1"} }, "a2a_path_prefixes[0]"},
		{"prefix has fragment", func(x *Policy) { x.A2APathPrefixes = []string{"/a2a#top"} }, "a2a_path_prefixes[0]"},
		{"prefix too long", func(x *Policy) { x.A2APathPrefixes = []string{"/" + strings.Repeat("a", MaxPathLen)} }, "a2a_path_prefixes[0]"},
		{"too many prefixes", func(x *Policy) { x.A2APathPrefixes = tooManyPrefixes }, "a2a_path_prefixes"},
		{"too many callers", func(x *Policy) { x.AllowedCallerAgents = tooManyCallers }, "allowed_caller_agents"},
		{"caller too long", func(x *Policy) { x.AllowedCallerAgents = []string{strings.Repeat("a", MaxAllowedAgentNameLen+1)} }, "allowed_caller_agents[0]"},
		{"delegation depth below min", func(x *Policy) { x.MaxDelegationDepth = 0 }, "max_delegation_depth"},
		{"delegation depth above max", func(x *Policy) { x.MaxDelegationDepth = 11 }, "max_delegation_depth"},
		{"loop window below min", func(x *Policy) { x.LoopWindowSeconds = 4 }, "loop_window_seconds"},
		{"loop window above max", func(x *Policy) { x.LoopWindowSeconds = 3601 }, "loop_window_seconds"},
		{"max calls below min", func(x *Policy) { x.MaxCallsPerTaskWindow = 0 }, "max_calls_per_task_window"},
		{"max calls above max", func(x *Policy) { x.MaxCallsPerTaskWindow = 10001 }, "max_calls_per_task_window"},
		{"too many confidential patterns", func(x *Policy) { x.ConfidentialReadPatterns = tooManyPatterns }, "confidential_read_patterns"},
		{"confidential pattern too long", func(x *Policy) { x.ConfidentialReadPatterns = []string{strings.Repeat("x", MaxPatternLen+1)} }, "confidential_read_patterns[0]"},
		{"too many egress patterns", func(x *Policy) { x.ExternalEgressPatterns = tooManyPatterns }, "external_egress_patterns"},
		{"egress pattern control char", func(x *Policy) { x.ExternalEgressPatterns = []string{"bad\npat"} }, "external_egress_patterns[0]"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := *p
			cp.A2APathPrefixes = cloneStrings(p.A2APathPrefixes)
			cp.AllowedCallerAgents = cloneStrings(p.AllowedCallerAgents)
			cp.ConfidentialReadPatterns = cloneStrings(p.ConfidentialReadPatterns)
			cp.ExternalEgressPatterns = cloneStrings(p.ExternalEgressPatterns)
			tc.mutate(&cp)
			errs := ValidatePolicy(&cp)
			if !fieldSet(errs)[tc.field] {
				t.Fatalf("expected error on %q, got %+v", tc.field, errs)
			}
		})
	}
}

func TestValidateAgent(t *testing.T) {
	ag := Agent{
		ApplicationID: uuid.New(),
		AgentName:     "billing-agent",
		AgentURL:      "https://agents.example.com/billing",
		AgentVersion:  "1.0.0",
		Status:        "approved",
		Description:   "处理账单查询",
		Skills:        []string{"invoice.read", "invoice.refund"},
		AllowedSkills: []string{"invoice.read"},
		AuthSchemes:   []string{"oauth2"},
	}
	NormalizeAgent(&ag)
	if errs := ValidateCreateAgent(&ag); len(errs) > 0 {
		t.Fatalf("valid agent rejected: %+v", errs)
	}

	// Empty agent_name
	bad := ag
	bad.AgentName = ""
	if errs := ValidateCreateAgent(&bad); len(errs) == 0 || errs[0].Field != "agent_name" {
		t.Fatalf("empty agent_name must fail: %+v", errs)
	}
	// Valid single-slash relative path
	rel := ag
	rel.AgentURL = "/a2a/billing"
	if errs := ValidateCreateAgent(&rel); len(errs) > 0 {
		t.Fatalf("valid relative agent_url rejected: %+v", errs)
	}
	// Protocol-relative //evil.com must be rejected (matches gateway a2aguard/card.go)
	bad = ag
	bad.AgentURL = "//evil.com/billing"
	if errs := ValidateCreateAgent(&bad); len(errs) == 0 || errs[0].Field != "agent_url" {
		t.Fatalf("protocol-relative agent_url must fail: %+v", errs)
	}
	bad = ag
	bad.AgentURL = "//"
	if errs := ValidateCreateAgent(&bad); len(errs) == 0 || errs[0].Field != "agent_url" {
		t.Fatalf("bare // agent_url must fail: %+v", errs)
	}
	// Bad URL with embedded credentials
	bad = ag
	bad.AgentURL = "https://user:pass@agents.example.com/billing"
	if errs := ValidateCreateAgent(&bad); len(errs) == 0 || errs[0].Field != "agent_url" {
		t.Fatalf("agent_url with userinfo must fail: %+v", errs)
	}
	// Invalid status on update
	if errs := ValidateUpdateAgent("UNKNOWN", "", nil); len(errs) == 0 || errs[0].Field != "status" {
		t.Fatalf("invalid status must fail: %+v", errs)
	}
}

func TestToGuardPolicyFrozenContract(t *testing.T) {
	appID := uuid.MustParse("8b1a2c3d-0000-4000-8000-000000000099")
	p := DefaultPolicy(appID)
	p.Mode = ModeProtect
	p.Version = 4
	p.AllowedCallerAgents = []string{"planner-agent"}

	gp := toGuardPolicy(p)
	raw, err := json.Marshal(gp)
	if err != nil {
		t.Fatalf("marshal guard policy: %v", err)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal guard policy: %v", err)
	}
	wantKeys := []string{
		"schema_version", "application_id", "mode", "version",
		"card_discovery_enabled", "a2a_path_prefixes", "allowed_caller_agents",
		"max_delegation_depth", "enforce_scope_attenuation",
		"loop_window_seconds", "max_calls_per_task_window",
		"lethal_trifecta_enabled", "confidential_read_patterns", "external_egress_patterns",
	}
	if len(obj) != len(wantKeys) {
		t.Fatalf("frozen contract expects exactly %d keys, got %d: %s", len(wantKeys), len(obj), raw)
	}
	for _, k := range wantKeys {
		if _, ok := obj[k]; !ok {
			t.Errorf("frozen guard JSON missing key %q: %s", k, raw)
		}
	}
}

type execCall struct {
	sql  string
	args []any
}

type fakeExecer struct {
	calls []execCall
}

func (f *fakeExecer) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.calls = append(f.calls, execCall{sql: sql, args: args})
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func TestIngestEventSQLAndNeverOverwritesApprovedOrBlocked(t *testing.T) {
	// 静态断言：upsertDiscoveredAgentSQL 的 ON CONFLICT DO UPDATE 绝不覆盖 status / description / allowed_skills
	conflictPart := upsertDiscoveredAgentSQL[strings.Index(upsertDiscoveredAgentSQL, "DO UPDATE SET"):]
	for _, forbidden := range []string{"status", "description", "allowed_skills"} {
		if strings.Contains(conflictPart, "\t"+forbidden+" ") ||
			strings.Contains(conflictPart, " "+forbidden+"=") ||
			strings.Contains(conflictPart, " "+forbidden+" =") {
			t.Fatalf("upsertDiscoveredAgentSQL must NEVER overwrite %q on conflict:\n%s", forbidden, conflictPart)
		}
	}

	appID := uuid.New()
	ts := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)

	// 1. A2A_AGENT_CARD_DISCOVERED -> UPSERT api_a2a_agents
	fe := &fakeExecer{}
	store := &Store{exec: fe}
	err := store.IngestEvent(context.Background(), &accesscontrolevents.Event{
		OccurredAt:    ts,
		ApplicationID: &appID,
		EventType:     accesscontrolevents.EventTypeA2AAgentCardDiscovered,
		Details: map[string]interface{}{
			"a2a": map[string]interface{}{
				"agent_name":    "planner-agent",
				"agent_url":     "https://agents.example.com/planner",
				"agent_version": "2.1.0",
				"skills":        []interface{}{"plan.create", "plan.read"},
				"auth_schemes":  []string{"oauth2"},
			},
		},
	})
	if err != nil {
		t.Fatalf("IngestEvent discovered: %v", err)
	}
	if len(fe.calls) != 1 || !strings.Contains(fe.calls[0].sql, "INSERT INTO api_a2a_agents") {
		t.Fatalf("expected 1 agent upsert, got %d calls", len(fe.calls))
	}
	if fe.calls[0].args[1] != "planner-agent" || fe.calls[0].args[2] != "https://agents.example.com/planner" {
		t.Fatalf("unexpected upsert args: %+v", fe.calls[0].args)
	}

	// 2. A2A_OBSERVED / A2A_BLOCKED / A2A_LOOP_KILLED / A2A_LETHAL_TRIFECTA -> INSERT api_a2a_events
	for _, evType := range []string{
		accesscontrolevents.EventTypeA2AObserved,
		accesscontrolevents.EventTypeA2ABlocked,
		accesscontrolevents.EventTypeA2ALoopKilled,
		accesscontrolevents.EventTypeA2ALethalTrifecta,
	} {
		fe2 := &fakeExecer{}
		s2 := &Store{exec: fe2}
		if err := s2.IngestEvent(context.Background(), &accesscontrolevents.Event{
			RequestID:     "req-1",
			OccurredAt:    ts,
			ApplicationID: &appID,
			ClientIP:      "203.0.113.10",
			EventType:     evType,
			Action:        "REJECT",
			Details: map[string]interface{}{
				"a2a": map[string]interface{}{
					"method":           "tasks/send",
					"agent_name":       "planner-agent",
					"delegation_depth": float64(4),
					"rule_id":          "a2a.delegation_depth_exceeded",
					"action_taken":     "BLOCKED",
					"reason":           "depth exceeded",
				},
			},
		}); err != nil {
			t.Fatalf("IngestEvent %s: %v", evType, err)
		}
		if len(fe2.calls) != 1 || !strings.Contains(fe2.calls[0].sql, "INSERT INTO api_a2a_events") {
			t.Fatalf("%s expected 1 event insert, got %d", evType, len(fe2.calls))
		}
		if fe2.calls[0].args[6] != 4 || fe2.calls[0].args[7] != "a2a.delegation_depth_exceeded" {
			t.Fatalf("%s unexpected event args: %+v", evType, fe2.calls[0].args)
		}
	}
}

// ---------- Handler HTTP tests ----------

type fakeApps struct {
	apps map[uuid.UUID]*applications.Application
}

func (f *fakeApps) GetByID(_ context.Context, id uuid.UUID) (*applications.Application, error) {
	if a, ok := f.apps[id]; ok {
		return a, nil
	}
	return nil, applications.ErrNotFound
}

type fakeRepo struct {
	policies  map[uuid.UUID]*Policy
	published map[string]int
	agents    map[uuid.UUID]*Agent
	events    []Event
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		policies:  map[uuid.UUID]*Policy{},
		published: map[string]int{},
		agents:    map[uuid.UUID]*Agent{},
	}
}

func (f *fakeRepo) GetPolicyByApp(_ context.Context, appID uuid.UUID) (*Policy, error) {
	p, ok := f.policies[appID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *p
	return &cp, nil
}

func (f *fakeRepo) SavePolicyDraft(_ context.Context, p *Policy, expectedVersion int, reason, updatedBy string) error {
	if errs := ValidatePolicy(p); len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	cur, exists := f.policies[p.ApplicationID]
	if !exists {
		if expectedVersion != 0 {
			return ErrConflict
		}
		cp := *p
		cp.ID = uuid.New()
		cp.Version = 1
		cp.UpdatedBy = updatedBy
		f.policies[p.ApplicationID] = &cp
		p.ID = cp.ID
		p.Version = 1
		return nil
	}
	if cur.Version != expectedVersion {
		return ErrConflict
	}
	cp := *p
	cp.ID = cur.ID
	cp.Version = cur.Version + 1
	cp.UpdatedBy = updatedBy
	f.policies[p.ApplicationID] = &cp
	p.ID = cp.ID
	p.Version = cp.Version
	return nil
}

func (f *fakeRepo) PublishedVersion(_ context.Context, appCode string) (int, error) {
	return f.published[appCode], nil
}

func (f *fakeRepo) ListAgents(_ context.Context, filter AgentFilter) ([]Agent, int64, error) {
	out := []Agent{}
	for _, a := range f.agents {
		if filter.ApplicationID != nil && a.ApplicationID != *filter.ApplicationID {
			continue
		}
		if filter.Status != "" && a.Status != filter.Status {
			continue
		}
		if filter.Keyword != "" && !strings.Contains(strings.ToLower(a.AgentName), strings.ToLower(filter.Keyword)) {
			continue
		}
		out = append(out, *a)
	}
	return out, int64(len(out)), nil
}

func (f *fakeRepo) GetAgent(_ context.Context, id uuid.UUID) (*Agent, error) {
	a, ok := f.agents[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *a
	return &cp, nil
}

func (f *fakeRepo) CreateAgent(_ context.Context, a *Agent) error {
	for _, cur := range f.agents {
		if cur.ApplicationID == a.ApplicationID && cur.AgentName == a.AgentName && cur.AgentURL == a.AgentURL {
			return ErrConflict
		}
	}
	a.ID = uuid.New()
	now := time.Now().UTC()
	a.FirstSeenAt = now
	a.LastSeenAt = now
	a.CreatedAt = now
	a.UpdatedAt = now
	cp := *a
	f.agents[a.ID] = &cp
	return nil
}

func (f *fakeRepo) UpdateAgent(_ context.Context, id uuid.UUID, status, description string, allowedSkills []string) (*Agent, error) {
	a, ok := f.agents[id]
	if !ok {
		return nil, ErrNotFound
	}
	a.Status = status
	a.Description = description
	a.AllowedSkills = cloneStrings(allowedSkills)
	a.UpdatedAt = time.Now().UTC()
	cp := *a
	return &cp, nil
}

func (f *fakeRepo) DeleteAgent(_ context.Context, id uuid.UUID) error {
	if _, ok := f.agents[id]; !ok {
		return ErrNotFound
	}
	delete(f.agents, id)
	return nil
}

func (f *fakeRepo) ListEvents(_ context.Context, filter EventFilter) ([]Event, int64, error) {
	out := []Event{}
	for _, e := range f.events {
		if filter.ApplicationID != nil && e.ApplicationID != *filter.ApplicationID {
			continue
		}
		if filter.EventType != "" && e.EventType != filter.EventType {
			continue
		}
		if filter.RuleID != "" && e.RuleID != filter.RuleID {
			continue
		}
		out = append(out, e)
	}
	return out, int64(len(out)), nil
}

type spyAudit struct {
	entries []audits.RecordInput
}

func (s *spyAudit) Record(_ context.Context, in audits.RecordInput) error {
	s.entries = append(s.entries, in)
	return nil
}

func withPrincipal(r *http.Request) *http.Request {
	p := &authz.Principal{UserID: uuid.New(), Username: "secadmin"}
	return r.WithContext(authz.WithPrincipal(r.Context(), p))
}

func TestHandlerPolicyAgentsAndEventsHTTP(t *testing.T) {
	appID := uuid.New()
	apps := &fakeApps{apps: map[uuid.UUID]*applications.Application{
		appID: {ID: appID, Code: "agent-app", Name: "Agent App"},
	}}
	repo := newFakeRepo()
	repo.events = []Event{
		{
			ID: uuid.New(), ApplicationID: appID, RequestID: "r1",
			OccurredAt: time.Now().UTC(), EventType: accesscontrolevents.EventTypeA2ALoopKilled,
			Method: "tasks/send", AgentName: "planner-agent", DelegationDepth: 2,
			RuleID: "a2a.recursive_loop_detected", ActionTaken: "BLOCKED", Reason: "loop detected", ClientIP: "10.0.0.1",
		},
	}
	spy := &spyAudit{}
	h := NewHandler(repo, apps, nil)
	h.audits = spy

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/applications/{id}/a2a-policy", h.GetPolicy)
	mux.HandleFunc("PUT /api/v1/applications/{id}/a2a-policy", h.PutPolicy)
	mux.HandleFunc("GET /api/v1/api-security/a2a/agents", h.ListAgents)
	mux.HandleFunc("POST /api/v1/api-security/a2a/agents", h.CreateAgent)
	mux.HandleFunc("PUT /api/v1/api-security/a2a/agents/{id}", h.UpdateAgent)
	mux.HandleFunc("DELETE /api/v1/api-security/a2a/agents/{id}", h.DeleteAgent)
	mux.HandleFunc("GET /api/v1/api-security/a2a/events", h.ListEvents)

	do := func(method, target, body string) *httptest.ResponseRecorder {
		req := withPrincipal(httptest.NewRequest(method, target, bytes.NewBufferString(body)))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}

	// 1. GET default policy
	rr := do(http.MethodGet, "/api/v1/applications/"+appID.String()+"/a2a-policy", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"NOT_CONFIGURED"`) {
		t.Fatalf("GET default policy: %d %s", rr.Code, rr.Body.String())
	}

	// 2. PUT policy -> 200 (v1), then conflict with expected_version=0 -> 409
	putBody := `{
		"mode":"PROTECT",
		"expected_version":0,
		"card_discovery_enabled":true,
		"a2a_path_prefixes":["/a2a","/.well-known/agent.json"],
		"allowed_caller_agents":["planner-agent"],
		"max_delegation_depth":3,
		"enforce_scope_attenuation":true,
		"loop_window_seconds":60,
		"max_calls_per_task_window":20,
		"lethal_trifecta_enabled":true,
		"confidential_read_patterns":["/api/v1/secrets"],
		"external_egress_patterns":["send_email"],
		"reason":"enable A2A protection"
	}`
	rr = do(http.MethodPut, "/api/v1/applications/"+appID.String()+"/a2a-policy", putBody)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"version":1`) {
		t.Fatalf("PUT policy v1: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(http.MethodPut, "/api/v1/applications/"+appID.String()+"/a2a-policy", putBody); rr.Code != http.StatusConflict {
		t.Fatalf("duplicate v0 should return 409, got %d", rr.Code)
	}
	// Missing reason -> 400
	if rr := do(http.MethodPut, "/api/v1/applications/"+appID.String()+"/a2a-policy", `{"mode":"OBSERVE","expected_version":1}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("missing reason should return 400, got %d", rr.Code)
	}

	// 3. POST /api/v1/api-security/a2a/agents -> 201, duplicate -> 409
	agentBody := `{
		"application_id":"` + appID.String() + `",
		"agent_name":"planner-agent",
		"agent_url":"https://agents.example.com/planner",
		"agent_version":"1.0.0",
		"status":"APPROVED",
		"description":"Planner",
		"skills":["plan.create"],
		"allowed_skills":["plan.create"],
		"auth_schemes":["oauth2"]
	}`
	rr = do(http.MethodPost, "/api/v1/api-security/a2a/agents", agentBody)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST agent: %d %s", rr.Code, rr.Body.String())
	}
	var createEnv struct {
		Data struct {
			Agent Agent `json:"agent"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &createEnv); err != nil {
		t.Fatal(err)
	}
	agentID := createEnv.Data.Agent.ID.String()
	if rr := do(http.MethodPost, "/api/v1/api-security/a2a/agents", agentBody); rr.Code != http.StatusConflict {
		t.Fatalf("duplicate agent should return 409, got %d", rr.Code)
	}

	// 4. GET /api/v1/api-security/a2a/agents
	rr = do(http.MethodGet, "/api/v1/api-security/a2a/agents?application_id="+appID.String()+"&status=APPROVED&keyword=planner", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "planner-agent") {
		t.Fatalf("GET agents: %d %s", rr.Code, rr.Body.String())
	}

	// 5. PUT /api/v1/api-security/a2a/agents/{id}
	rr = do(http.MethodPut, "/api/v1/api-security/a2a/agents/"+agentID, `{"status":"BLOCKED","description":"revoked","allowed_skills":[]}`)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"BLOCKED"`) {
		t.Fatalf("PUT agent: %d %s", rr.Code, rr.Body.String())
	}

	// 6. DELETE /api/v1/api-security/a2a/agents/{id}
	rr = do(http.MethodDelete, "/api/v1/api-security/a2a/agents/"+agentID, "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"deleted":true`) {
		t.Fatalf("DELETE agent: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(http.MethodDelete, "/api/v1/api-security/a2a/agents/"+agentID, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("repeat DELETE should return 404, got %d", rr.Code)
	}

	// 7. GET /api/v1/api-security/a2a/events
	rr = do(http.MethodGet, "/api/v1/api-security/a2a/events?application_id="+appID.String()+"&event_type=A2A_LOOP_KILLED&rule_id=a2a.recursive_loop_detected", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "a2a.recursive_loop_detected") {
		t.Fatalf("GET events: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(http.MethodGet, "/api/v1/api-security/a2a/events?event_type=BOGUS", ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid event_type should return 400, got %d", rr.Code)
	}

	// 4 write operations audited (PutPolicy + CreateAgent + UpdateAgent + DeleteAgent)
	if len(spy.entries) != 4 {
		t.Fatalf("expected 4 audit records, got %d", len(spy.entries))
	}
}
