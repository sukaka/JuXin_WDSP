// policy_versions_test.go Phase 2 单测：策略版本快照（创建/PUT 联动）、版本列表端点、
// 回滚端点（新版本 version+1 / config_version 联动 / 不存在版本 404 / HIGH 审计）、
// 心跳时钟偏移记录、列表与详情健康评分字段输出。
package agents

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
)

// TestPolicyVersionSnapshot 创建与每次 PUT 均在仓储留下版本快照（fake 与 SQL 同口径）。
func TestPolicyVersionSnapshot(t *testing.T) {
	store := newFakeAdminStore()
	h := NewHandler(store).SetAudits(&spyAudits{})
	mux := newAdminMux(h, injectPerms(PermAgentsManage))

	rr := doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/policies", policyBody("snap"))
	if rr.Code != http.StatusCreated {
		t.Fatalf("创建 status = %d", rr.Code)
	}
	var created Policy
	decodeEnvelope(t, rr, &created)
	if len(store.versions[created.ID]) != 1 || store.versions[created.ID][0].Version != 1 {
		t.Fatalf("创建未快照 v1: %+v", store.versions[created.ID])
	}
	if store.versions[created.ID][0].CreatedBy != "admin-it" {
		t.Errorf("快照 created_by = %q", store.versions[created.ID][0].CreatedBy)
	}

	rr = doAdmin(t, mux, http.MethodPut, "/api/v1/traffic/policies/"+created.ID.String(), policyBody("snap"))
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT status = %d", rr.Code)
	}
	if len(store.versions[created.ID]) != 2 || store.versions[created.ID][1].Version != 2 {
		t.Fatalf("PUT 未快照 v2: %+v", store.versions[created.ID])
	}
}

// TestListPolicyVersions 版本列表：version 倒序、current 标记、策略不存在 404、view 权限放行。
func TestListPolicyVersions(t *testing.T) {
	setup := func(t *testing.T) (*fakeAdminStore, *http.ServeMux, Policy) {
		t.Helper()
		store := newFakeAdminStore()
		h := NewHandler(store).SetAudits(&spyAudits{})
		mux := newAdminMux(h, injectPerms(PermAgentsView, PermAgentsManage))
		rr := doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/policies", policyBody("hist"))
		var created Policy
		decodeEnvelope(t, rr, &created)
		doAdmin(t, mux, http.MethodPut, "/api/v1/traffic/policies/"+created.ID.String(), policyBody("hist"))
		doAdmin(t, mux, http.MethodPut, "/api/v1/traffic/policies/"+created.ID.String(), policyBody("hist"))
		return store, mux, created
	}

	t.Run("倒序 + current 标记", func(t *testing.T) {
		_, mux, created := setup(t)
		rr := doAdmin(t, mux, http.MethodGet, "/api/v1/traffic/policies/"+created.ID.String()+"/versions", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d (body=%s)", rr.Code, rr.Body.String())
		}
		var resp struct {
			Items []struct {
				Version   int    `json:"version"`
				CreatedBy string `json:"created_by"`
				Current   bool   `json:"current"`
			} `json:"items"`
			Total int `json:"total"`
		}
		decodeEnvelope(t, rr, &resp)
		if resp.Total != 3 || len(resp.Items) != 3 {
			t.Fatalf("items = %+v", resp.Items)
		}
		for i, want := range []int{3, 2, 1} {
			if resp.Items[i].Version != want {
				t.Fatalf("items[%d].version = %d, want %d（倒序）", i, resp.Items[i].Version, want)
			}
			if resp.Items[i].Current != (want == 3) {
				t.Errorf("items[%d].current = %v, want %v", i, resp.Items[i].Current, want == 3)
			}
			if resp.Items[i].CreatedBy != "admin-it" {
				t.Errorf("items[%d].created_by = %q", i, resp.Items[i].CreatedBy)
			}
		}
	})
	t.Run("策略不存在 404", func(t *testing.T) {
		_, mux, _ := setup(t)
		rr := doAdmin(t, mux, http.MethodGet, "/api/v1/traffic/policies/"+uuid.NewString()+"/versions", "")
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})
	t.Run("view 权限可读", func(t *testing.T) {
		_, _, created := setup(t)
		store2 := newFakeAdminStore()
		h2 := NewHandler(store2)
		mux2 := newAdminMux(h2, injectPerms(PermAgentsView))
		rr := doAdmin(t, mux2, http.MethodGet, "/api/v1/traffic/policies/"+created.ID.String()+"/versions", "")
		if rr.Code != http.StatusNotFound { // fake 无此策略 → 404 而非 403，证明权限链放行
			t.Fatalf("status = %d, want 404（view 权限应过权限链）", rr.Code)
		}
	})
}

// TestRollbackPolicy 回滚：以历史版本 config 生成新版本（version+1）、联动 config_version、
// 不存在版本 404、策略不存在 404、HIGH 审计含 from_version/to_version、view 权限 403。
func TestRollbackPolicy(t *testing.T) {
	setup := func(t *testing.T) (*fakeAdminStore, *spyAudits, *http.ServeMux, Policy) {
		t.Helper()
		store := newFakeAdminStore()
		spy := &spyAudits{}
		h := NewHandler(store).SetAudits(spy)
		mux := newAdminMux(h, injectPerms(PermAgentsManage))
		rr := doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/policies", policyBody("rb"))
		var created Policy
		decodeEnvelope(t, rr, &created)
		// PUT 一次使 v2 与 v1 config 不同（v1 为原始 config）
		body2 := strings.Replace(policyBody("rb"), `"mode":"FLOW"`, `"mode":"RAW"`, 1)
		doAdmin(t, mux, http.MethodPut, "/api/v1/traffic/policies/"+created.ID.String(), body2)
		return store, spy, mux, created
	}

	t.Run("回滚生成新版本 + 审计", func(t *testing.T) {
		store, spy, mux, created := setup(t)
		beforeBumps := store.cfgBumped
		rr := doAdmin(t, mux, http.MethodPost,
			"/api/v1/traffic/policies/"+created.ID.String()+"/rollback", `{"version":1}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d (body=%s)", rr.Code, rr.Body.String())
		}
		var updated Policy
		decodeEnvelope(t, rr, &updated)
		if updated.Version != 3 {
			t.Errorf("version = %d, want 3（回滚生成新版本 version+1）", updated.Version)
		}
		// 新当前 config 应为 v1 的 config（含 FLOW），不再是 v2 的 RAW
		if !strings.Contains(string(updated.Config), `"mode":"FLOW"`) ||
			strings.Contains(string(updated.Config), `"mode":"RAW"`) {
			t.Errorf("回滚后 config 未取历史版本: %s", updated.Config)
		}
		// 新版本同样快照
		vs := store.versions[created.ID]
		if len(vs) != 3 || vs[2].Version != 3 {
			t.Errorf("回滚未快照新版本: %+v", vs)
		}
		// 绑定 Agent config_version 联动
		if store.cfgBumped != beforeBumps+1 {
			t.Errorf("cfgBumped 增量 = %d, want 1", store.cfgBumped-beforeBumps)
		}
		// HIGH 审计：action=rollback，before 含 from_version、after 含 to_version
		last := spy.entries[len(spy.entries)-1]
		if last.Action != "rollback" || last.Module != auditModule || last.RiskLevel != audits.RiskHigh ||
			last.ObjectType != "agent_policy" {
			t.Errorf("audit = %+v", last)
		}
		var beforeSum, afterSum map[string]int
		if err := json.Unmarshal([]byte(last.BeforeSummary), &beforeSum); err != nil {
			t.Fatalf("before 非合法 JSON: %q", last.BeforeSummary)
		}
		if err := json.Unmarshal([]byte(last.AfterSummary), &afterSum); err != nil {
			t.Fatalf("after 非合法 JSON: %q", last.AfterSummary)
		}
		if beforeSum["from_version"] != 2 || afterSum["to_version"] != 3 || afterSum["rolled_back_from"] != 1 {
			t.Errorf("before/after = %q -> %q", last.BeforeSummary, last.AfterSummary)
		}
	})
	t.Run("历史版本不存在 404", func(t *testing.T) {
		_, _, mux, created := setup(t)
		rr := doAdmin(t, mux, http.MethodPost,
			"/api/v1/traffic/policies/"+created.ID.String()+"/rollback", `{"version":99}`)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body=%s)", rr.Code, rr.Body.String())
		}
	})
	t.Run("策略不存在 404", func(t *testing.T) {
		_, _, mux, _ := setup(t)
		rr := doAdmin(t, mux, http.MethodPost,
			"/api/v1/traffic/policies/"+uuid.NewString()+"/rollback", `{"version":1}`)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})
	t.Run("version 非法 400", func(t *testing.T) {
		_, _, mux, created := setup(t)
		rr := doAdmin(t, mux, http.MethodPost,
			"/api/v1/traffic/policies/"+created.ID.String()+"/rollback", `{"version":0}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})
	t.Run("view 权限 403", func(t *testing.T) {
		store := newFakeAdminStore()
		h := NewHandler(store)
		mux := newAdminMux(h, injectPerms(PermAgentsView))
		rr := doAdmin(t, mux, http.MethodPost,
			"/api/v1/traffic/policies/"+uuid.NewString()+"/rollback", `{"version":1}`)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rr.Code)
		}
	})
}

// TestHeartbeatClockOffset 心跳时钟偏移记录：偏移 = 服务端收包时间 − Agent timestamp（毫秒）；
// timestamp ≤0 时不透传（仓储保留原值）。
func TestHeartbeatClockOffset(t *testing.T) {
	fixedNow := time.Unix(1788256900, 400*int64(time.Millisecond)).UTC()

	t.Run("记录偏移", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mh := NewMachineHandler(store)
		mh.now = func() time.Time { return fixedNow }
		rr := doMachine(t, newMachineMux(mh), http.MethodPost,
			"/api/v1/agents/"+agentID.String()+"/heartbeat",
			`{"timestamp":1788256897,"status":"ONLINE"}`, cred)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d (body=%s)", rr.Code, rr.Body.String())
		}
		// 1788256900.400 − 1788256897.000 = 3400ms
		if store.hbClockOffsetMS == nil || *store.hbClockOffsetMS != 3400 {
			t.Fatalf("clock_offset = %v, want 3400ms", store.hbClockOffsetMS)
		}
	})
	t.Run("Agent 时钟偏快为负偏移", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mh := NewMachineHandler(store)
		mh.now = func() time.Time { return fixedNow }
		rr := doMachine(t, newMachineMux(mh), http.MethodPost,
			"/api/v1/agents/"+agentID.String()+"/heartbeat",
			`{"timestamp":1788256910,"status":"ONLINE"}`, cred)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d", rr.Code)
		}
		if store.hbClockOffsetMS == nil || *store.hbClockOffsetMS != -9600 {
			t.Fatalf("clock_offset = %v, want -9600ms", store.hbClockOffsetMS)
		}
	})
	t.Run("timestamp 缺失不覆盖", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mh := NewMachineHandler(store)
		mh.now = func() time.Time { return fixedNow }
		rr := doMachine(t, newMachineMux(mh), http.MethodPost,
			"/api/v1/agents/"+agentID.String()+"/heartbeat", `{"status":"ONLINE"}`, cred)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d", rr.Code)
		}
		if store.hbClockOffsetMS != nil {
			t.Fatalf("timestamp 缺失时 offset 应为 nil，got %v", *store.hbClockOffsetMS)
		}
	})
}

// TestListAgentsHealthFields 列表/详情输出 health_score / health_reasons / clock_offset_ms
// （查询时计算，不落库评分；summary 端点不变）。
func TestListAgentsHealthFields(t *testing.T) {
	offset := int64(6000)
	store := newFakeAdminStore()
	agentID := uuid.New()
	store.agents = []Agent{{
		AgentID: agentID, Hostname: "web-prod-01", Status: StatusOnline,
		LastMetrics:          []byte(`{"cpu_percent":95}`),
		ConfigVersion:        2,
		AppliedConfigVersion: 2,
		ClockOffsetMS:        &offset,
	}}
	store.agents[0].cpuLimitPercent = 20

	h := NewHandler(store)
	rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsView)), http.MethodGet,
		"/api/v1/traffic/agents", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Items []struct {
			HealthScore   int      `json:"health_score"`
			HealthReasons []string `json:"health_reasons"`
			ClockOffsetMS *int64   `json:"clock_offset_ms"`
		} `json:"items"`
	}
	decodeEnvelope(t, rr, &resp)
	if len(resp.Items) != 1 {
		t.Fatalf("items = %+v", resp.Items)
	}
	it := resp.Items[0]
	// cpu_over_limit(−25) + clock_drift(−15) = 60
	if it.HealthScore != 60 {
		t.Errorf("health_score = %d, want 60", it.HealthScore)
	}
	if len(it.HealthReasons) != 2 {
		t.Errorf("health_reasons = %v", it.HealthReasons)
	}
	if it.ClockOffsetMS == nil || *it.ClockOffsetMS != 6000 {
		t.Errorf("clock_offset_ms = %v, want 6000", it.ClockOffsetMS)
	}

	// 详情同样输出健康字段
	store2 := newFakeAdminStore()
	detail := &AgentDetail{Agent: Agent{
		AgentID: agentID, Hostname: "web-prod-01", Disabled: true,
	}}
	store2.details[agentID] = detail
	h2 := NewHandler(store2)
	rr = doAdmin(t, newAdminMux(h2, injectPerms(PermAgentsView)), http.MethodGet,
		"/api/v1/traffic/agents/"+agentID.String(), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("detail status = %d", rr.Code)
	}
	var d struct {
		Status        string   `json:"status"`
		HealthScore   int      `json:"health_score"`
		HealthReasons []string `json:"health_reasons"`
	}
	decodeEnvelope(t, rr, &d)
	if d.Status != StatusDisabled || d.HealthScore != 0 || len(d.HealthReasons) != 1 ||
		d.HealthReasons[0] != "agent_disabled" {
		t.Errorf("detail = %+v", d)
	}
}
