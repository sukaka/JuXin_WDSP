// overrides_test.go Phase 4 定向采集规则单测（契约 §2，fake 模式）：
// match 校验矩阵、ttl 边界、config_version 联动、审计（override_create/override_delete
// HIGH，before/after 含 match 与 level）、config 响应 overrides（恒在/过期剔除/
// 无绑定策略照常返回）、sweeper 顺带清理（expires_at 早于 30 天）。
package agents

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
)

// seedOverrideAgent 在 fake 中放入一个 Agent 并返回 ID。
func seedOverrideAgent(f *fakeAdminStore) uuid.UUID {
	id := uuid.New()
	seedAgentDetail(f, id, false)
	return id
}

func doOverridePost(t *testing.T, h *Handler, agentID uuid.UUID, body string) int {
	t.Helper()
	rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsView, PermAgentsManage)), http.MethodPost,
		"/api/v1/traffic/agents/"+agentID.String()+"/overrides", body)
	return rr.Code
}

// TestOverrideMatchValidation match 校验矩阵（契约 §2.2：至少一字段、dst_ip 合法
// IP/CIDR、dst_port 范围、uri_prefix 以 / 开头且 ≤512、host 非空 ≤255、未知字段拒绝）。
func TestOverrideMatchValidation(t *testing.T) {
	valid := `{"match":{"dst_ip":"10.10.20.30"},"capture_level":"L2","ttl_minutes":30}`

	t.Run("四字段全空 400", func(t *testing.T) {
		for _, body := range []string{
			`{"match":{},"capture_level":"L2"}`,
			`{"match":{"dst_ip":"","host":"","uri_prefix":""},"capture_level":"L2"}`,
			`{"match":{"host":"   "},"capture_level":"L2"}`,
		} {
			store := newFakeAdminStore()
			id := seedOverrideAgent(store)
			if code := doOverridePost(t, NewHandler(store), id, body); code != http.StatusBadRequest {
				t.Errorf("body=%s status = %d, want 400", body, code)
			}
		}
	})
	t.Run("match 缺失 400", func(t *testing.T) {
		store := newFakeAdminStore()
		id := seedOverrideAgent(store)
		if code := doOverridePost(t, NewHandler(store), id, `{"capture_level":"L2"}`); code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", code)
		}
	})
	t.Run("match 未知字段拒绝（fail-closed）", func(t *testing.T) {
		store := newFakeAdminStore()
		id := seedOverrideAgent(store)
		body := `{"match":{"dst_ip":"10.0.0.1","src_ip":"1.2.3.4"},"capture_level":"L2"}`
		if code := doOverridePost(t, NewHandler(store), id, body); code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", code)
		}
	})
	t.Run("dst_ip 非法 400", func(t *testing.T) {
		for _, ip := range []string{"999.1.1.1", "10.0.0.0/33", "not-an-ip", "2001:db8::/129"} {
			store := newFakeAdminStore()
			id := seedOverrideAgent(store)
			body := `{"match":{"dst_ip":"` + ip + `"},"capture_level":"L2"}`
			if code := doOverridePost(t, NewHandler(store), id, body); code != http.StatusBadRequest {
				t.Errorf("dst_ip=%s status = %d, want 400", ip, code)
			}
		}
	})
	t.Run("dst_ip 合法 IP 与 CIDR（v4/v6）放行", func(t *testing.T) {
		for _, ip := range []string{"10.10.20.30", "10.10.20.0/24", "2001:db8::1", "2001:db8::/32"} {
			store := newFakeAdminStore()
			id := seedOverrideAgent(store)
			body := `{"match":{"dst_ip":"` + ip + `"},"capture_level":"L2"}`
			if code := doOverridePost(t, NewHandler(store), id, body); code != http.StatusCreated {
				t.Errorf("dst_ip=%s status = %d, want 201", ip, code)
			}
		}
	})
	t.Run("dst_port 范围", func(t *testing.T) {
		for _, tc := range []struct {
			port int
			want int
		}{{0, 400}, {-1, 400}, {65536, 400}, {1, 201}, {65535, 201}, {8443, 201}} {
			store := newFakeAdminStore()
			id := seedOverrideAgent(store)
			body := `{"match":{"dst_port":` + jsonNumber(tc.port) + `},"capture_level":"L2"}`
			if code := doOverridePost(t, NewHandler(store), id, body); code != tc.want {
				t.Errorf("dst_port=%d status = %d, want %d", tc.port, code, tc.want)
			}
		}
	})
	t.Run("uri_prefix 规则", func(t *testing.T) {
		for _, tc := range []struct {
			prefix string
			want   int
		}{
			{"api/payment", 400},                  // 不以 / 开头
			{"/", 201},                            // 根前缀合法
			{"/api/payment", 201},                 // 常规前缀
			{"/" + strings.Repeat("a", 511), 201}, // 恰好 512 字节
			{"/" + strings.Repeat("a", 512), 400}, // 513 字节超限
		} {
			store := newFakeAdminStore()
			id := seedOverrideAgent(store)
			raw, _ := json.Marshal(map[string]interface{}{
				"match": map[string]interface{}{"uri_prefix": tc.prefix}, "capture_level": "L2",
			})
			if code := doOverridePost(t, NewHandler(store), id, string(raw)); code != tc.want {
				t.Errorf("uri_prefix(len=%d) status = %d, want %d", len(tc.prefix), code, tc.want)
			}
		}
	})
	t.Run("host 上限", func(t *testing.T) {
		for _, tc := range []struct {
			host string
			want int
		}{
			{"api.example.com", 201},
			{strings.Repeat("h", 255), 201},
			{strings.Repeat("h", 256), 400},
		} {
			store := newFakeAdminStore()
			id := seedOverrideAgent(store)
			raw, _ := json.Marshal(map[string]interface{}{
				"match": map[string]interface{}{"host": tc.host}, "capture_level": "L2",
			})
			if code := doOverridePost(t, NewHandler(store), id, string(raw)); code != tc.want {
				t.Errorf("host(len=%d) status = %d, want %d", len(tc.host), code, tc.want)
			}
		}
	})
	t.Run("多字段 AND 组合合法", func(t *testing.T) {
		store := newFakeAdminStore()
		id := seedOverrideAgent(store)
		body := `{"match":{"dst_ip":"10.10.20.30","dst_port":8443,"host":"api.example.com","uri_prefix":"/api/payment"},"capture_level":"L2","ttl_minutes":30,"note":"排障"}`
		if code := doOverridePost(t, NewHandler(store), id, body); code != http.StatusCreated {
			t.Errorf("status = %d, want 201", code)
		}
		// 归一落库：契约 §2.2 示例形状
		got := store.overrides[id][0]
		var m map[string]interface{}
		if err := json.Unmarshal(got.Match, &m); err != nil {
			t.Fatalf("落库 match 非合法 JSON: %v", err)
		}
		if m["dst_ip"] != "10.10.20.30" || m["host"] != "api.example.com" || m["uri_prefix"] != "/api/payment" {
			t.Errorf("落库 match = %v", m)
		}
		if port, ok := m["dst_port"].(float64); !ok || int(port) != 8443 {
			t.Errorf("落库 dst_port = %v", m["dst_port"])
		}
	})
	t.Run("capture_level 非法 400", func(t *testing.T) {
		store := newFakeAdminStore()
		id := seedOverrideAgent(store)
		body := `{"match":{"dst_ip":"10.0.0.1"},"capture_level":"L4"}`
		if code := doOverridePost(t, NewHandler(store), id, body); code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", code)
		}
	})
	_ = valid
}

// TestOverrideTTL ttl_minutes 边界（契约 §2.3：1-1440，缺省 30）。
func TestOverrideTTL(t *testing.T) {
	t.Run("缺省（0）取 30 分钟", func(t *testing.T) {
		store := newFakeAdminStore()
		id := seedOverrideAgent(store)
		before := time.Now()
		if code := doOverridePost(t, NewHandler(store), id,
			`{"match":{"dst_ip":"10.0.0.1"},"capture_level":"L2"}`); code != http.StatusCreated {
			t.Fatalf("status = %d, want 201", code)
		}
		exp := store.overrides[id][0].ExpiresAt
		if exp.Before(before.Add(29*time.Minute)) || exp.After(time.Now().Add(31*time.Minute)) {
			t.Errorf("expires_at = %v, want ≈ now+30m", exp)
		}
	})
	t.Run("边界 1 与 1440 放行", func(t *testing.T) {
		for _, ttl := range []int{1, 1440} {
			store := newFakeAdminStore()
			id := seedOverrideAgent(store)
			body := `{"match":{"dst_ip":"10.0.0.1"},"capture_level":"L1","ttl_minutes":` + jsonNumber(ttl) + `}`
			if code := doOverridePost(t, NewHandler(store), id, body); code != http.StatusCreated {
				t.Errorf("ttl=%d status = %d, want 201", ttl, code)
			}
		}
	})
	t.Run("越界 400", func(t *testing.T) {
		for _, ttl := range []int{-1, 1441, 100000} {
			store := newFakeAdminStore()
			id := seedOverrideAgent(store)
			body := `{"match":{"dst_ip":"10.0.0.1"},"capture_level":"L1","ttl_minutes":` + jsonNumber(ttl) + `}`
			if code := doOverridePost(t, NewHandler(store), id, body); code != http.StatusBadRequest {
				t.Errorf("ttl=%d status = %d, want 400", ttl, code)
			}
		}
	})
}

// TestOverrideConfigVersionBump 创建/删除联动 config_version+1（契约 §2.3；fake 以 cfgBumped 计数）。
func TestOverrideConfigVersionBump(t *testing.T) {
	store := newFakeAdminStore()
	spy := &spyAudits{}
	h := NewHandler(store).SetAudits(spy)
	id := seedOverrideAgent(store)
	mux := newAdminMux(h, injectPerms(PermAgentsView, PermAgentsManage))

	rr := doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/agents/"+id.String()+"/overrides",
		`{"match":{"host":"api.example.com"},"capture_level":"L3","ttl_minutes":60,"note":"排障"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status = %d (body=%s)", rr.Code, rr.Body.String())
	}
	if store.cfgBumped != 1 {
		t.Fatalf("创建后 config_version bump = %d, want 1", store.cfgBumped)
	}
	overrideID := store.overrides[id][0].ID

	// 审计 override_create：HIGH、after 含 match 与 level
	if len(spy.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(spy.entries))
	}
	e := spy.entries[0]
	if e.Module != auditModule || e.Action != "override_create" || e.RiskLevel != audits.RiskHigh ||
		e.ObjectType != "agent_capture_override" {
		t.Errorf("create audit = %+v", e)
	}
	var after map[string]interface{}
	if err := json.Unmarshal([]byte(e.AfterSummary), &after); err != nil {
		t.Fatalf("after 非合法 JSON: %v", err)
	}
	if after["capture_level"] != "L3" {
		t.Errorf("after.capture_level = %v", after["capture_level"])
	}
	if m, ok := after["match"].(map[string]interface{}); !ok || m["host"] != "api.example.com" {
		t.Errorf("after.match = %v", after["match"])
	}

	rr = doAdmin(t, mux, http.MethodDelete,
		"/api/v1/traffic/agents/"+id.String()+"/overrides/"+overrideID.String(), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d (body=%s)", rr.Code, rr.Body.String())
	}
	if store.cfgBumped != 2 {
		t.Fatalf("删除后 config_version bump = %d, want 2", store.cfgBumped)
	}
	if len(store.overrides[id]) != 0 {
		t.Fatal("规则未被删除")
	}
	// 审计 override_delete：before 含 match 与 level
	if len(spy.entries) != 2 {
		t.Fatalf("audit entries = %d, want 2", len(spy.entries))
	}
	de := spy.entries[1]
	if de.Action != "override_delete" || de.RiskLevel != audits.RiskHigh {
		t.Errorf("delete audit = %+v", de)
	}
	var before map[string]interface{}
	if err := json.Unmarshal([]byte(de.BeforeSummary), &before); err != nil {
		t.Fatalf("before 非合法 JSON: %v", err)
	}
	if before["capture_level"] != "L3" {
		t.Errorf("before.capture_level = %v", before["capture_level"])
	}
	if m, ok := before["match"].(map[string]interface{}); !ok || m["host"] != "api.example.com" {
		t.Errorf("before.match = %v", before["match"])
	}

	// 删除不存在规则 → 404
	rr = doAdmin(t, mux, http.MethodDelete,
		"/api/v1/traffic/agents/"+id.String()+"/overrides/"+uuid.NewString(), "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("删除不存在 status = %d, want 404", rr.Code)
	}
}

// TestOverrideListAndPerms 列表（派生 active）与权限（view 读 / manage 写）。
func TestOverrideListAndPerms(t *testing.T) {
	t.Run("列表含派生 active（过期规则 inactive 仍在列表）", func(t *testing.T) {
		store := newFakeAdminStore()
		id := seedOverrideAgent(store)
		now := time.Now().UTC()
		store.overrides[id] = []CaptureOverride{
			{ID: uuid.New(), AgentID: id, Match: json.RawMessage(`{"host":"a.example.com"}`),
				CaptureLevel: "L2", ExpiresAt: now.Add(10 * time.Minute)},
			{ID: uuid.New(), AgentID: id, Match: json.RawMessage(`{"host":"b.example.com"}`),
				CaptureLevel: "L1", ExpiresAt: now.Add(-time.Minute)},
		}
		h := NewHandler(store)
		rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsView)), http.MethodGet,
			"/api/v1/traffic/agents/"+id.String()+"/overrides", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d (body=%s)", rr.Code, rr.Body.String())
		}
		var resp struct {
			Items []struct {
				Match   json.RawMessage `json:"match"`
				Active  bool            `json:"active"`
				Level   string          `json:"capture_level"`
				Expires string          `json:"expires_at"`
			} `json:"items"`
			Total int `json:"total"`
		}
		decodeEnvelope(t, rr, &resp)
		if resp.Total != 2 || len(resp.Items) != 2 {
			t.Fatalf("total = %d, want 2", resp.Total)
		}
		actives := map[bool]int{}
		for _, it := range resp.Items {
			actives[it.Active]++
		}
		if actives[true] != 1 || actives[false] != 1 {
			t.Errorf("active 分布 = %v, want 1 active + 1 inactive", actives)
		}
	})
	t.Run("view 不能创建/删除（403）", func(t *testing.T) {
		store := newFakeAdminStore()
		id := seedOverrideAgent(store)
		mux := newAdminMux(NewHandler(store), injectPerms(PermAgentsView))
		rr := doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/agents/"+id.String()+"/overrides",
			`{"match":{"host":"a.example.com"},"capture_level":"L2"}`)
		if rr.Code != http.StatusForbidden {
			t.Errorf("POST view-only status = %d, want 403", rr.Code)
		}
		rr = doAdmin(t, mux, http.MethodDelete,
			"/api/v1/traffic/agents/"+id.String()+"/overrides/"+uuid.NewString(), "")
		if rr.Code != http.StatusForbidden {
			t.Errorf("DELETE view-only status = %d, want 403", rr.Code)
		}
	})
	t.Run("Agent 不存在 404", func(t *testing.T) {
		store := newFakeAdminStore()
		h := NewHandler(store)
		mux := newAdminMux(h, injectPerms(PermAgentsView, PermAgentsManage))
		rr := doAdmin(t, mux, http.MethodGet, "/api/v1/traffic/agents/"+uuid.NewString()+"/overrides", "")
		if rr.Code != http.StatusNotFound {
			t.Errorf("GET status = %d, want 404", rr.Code)
		}
		rr = doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/agents/"+uuid.NewString()+"/overrides",
			`{"match":{"host":"a.example.com"},"capture_level":"L2"}`)
		if rr.Code != http.StatusNotFound {
			t.Errorf("POST status = %d, want 404", rr.Code)
		}
	})
}

// TestMachineConfigOverrides 机器端 config 响应 overrides（契约 §2.4/§5：
// 字段恒在；无规则为空数组；过期剔除；无绑定策略时照常返回）。
func TestMachineConfigOverrides(t *testing.T) {
	t.Run("无规则时 overrides 为空数组且字段恒在", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodGet, "/api/v1/agents/"+agentID.String()+"/config", "", cred)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d", rr.Code)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
			t.Fatalf("decode: %v", err)
		}
		ov, ok := raw["overrides"]
		if !ok {
			t.Fatal("overrides 字段缺失（契约要求恒在）")
		}
		if string(ov) != "[]" {
			t.Errorf("overrides = %s, want []", ov)
		}
	})
	t.Run("未过期规则全量下发、过期剔除、字段形状", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		now := time.Now().UTC()
		activeID := uuid.New()
		store.overrides = []CaptureOverride{
			{ID: activeID, AgentID: agentID, Match: json.RawMessage(`{"dst_ip":"10.10.20.30","uri_prefix":"/api/payment"}`),
				CaptureLevel: "L2", Note: "排障", CreatedBy: "admin", ExpiresAt: now.Add(20 * time.Minute)},
			{ID: uuid.New(), AgentID: agentID, Match: json.RawMessage(`{"host":"old.example.com"}`),
				CaptureLevel: "L3", ExpiresAt: now.Add(-time.Minute)}, // 已过期 → 剔除
		}
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodGet, "/api/v1/agents/"+agentID.String()+"/config", "", cred)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d", rr.Code)
		}
		var resp struct {
			Version   int64            `json:"version"`
			Policy    *json.RawMessage `json:"policy"`
			Overrides []struct {
				ID           string          `json:"id"`
				Match        json.RawMessage `json:"match"`
				CaptureLevel string          `json:"capture_level"`
				ExpiresAt    string          `json:"expires_at"`
			} `json:"overrides"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Overrides) != 1 {
			t.Fatalf("overrides = %d 条, want 1（过期剔除）", len(resp.Overrides))
		}
		o := resp.Overrides[0]
		if o.ID != activeID.String() || o.CaptureLevel != "L2" {
			t.Errorf("override = %+v", o)
		}
		if _, err := time.Parse(time.RFC3339, o.ExpiresAt); err != nil {
			t.Errorf("expires_at 非 RFC3339: %q", o.ExpiresAt)
		}
		var m map[string]interface{}
		if err := json.Unmarshal(o.Match, &m); err != nil || m["dst_ip"] != "10.10.20.30" {
			t.Errorf("match = %s", o.Match)
		}
		// 无绑定策略时 policy=null 且 overrides 照常返回
		if resp.Policy != nil {
			t.Error("无绑定时 policy 应为 null")
		}
	})
}

// TestOverrideSweeperCleanup sweeper 顺带清理：删除 expires_at 早于 30 天的规则
// （契约 §2.3，挂入既有 HTTPEventSweeper 同周期）。
func TestOverrideSweeperCleanup(t *testing.T) {
	fixed := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	t.Run("override cutoff 为 30 天前且与 HTTP 事件同轮清理", func(t *testing.T) {
		cl := &fakeHTTPCleaner{n: 7, overrideN: 3}
		s := NewHTTPEventSweeper(cl).SetClock(func() time.Time { return fixed })
		n, err := s.SweepOnce(context.Background())
		if err != nil {
			t.Fatalf("SweepOnce: %v", err)
		}
		if n != 10 {
			t.Errorf("删除合计 = %d, want 10（7 HTTP 事件 + 3 规则）", n)
		}
		want := fixed.Add(-CaptureOverrideRetention)
		if !cl.overrideBefore.Equal(want) {
			t.Errorf("override cutoff = %v, want %v", cl.overrideBefore, want)
		}
		if CaptureOverrideRetention != 30*24*time.Hour {
			t.Errorf("retention = %v, want 30d（契约 §2.3）", CaptureOverrideRetention)
		}
	})
	t.Run("override 删除失败如实返回", func(t *testing.T) {
		cl := &fakeHTTPCleaner{overrideErr: errTest}
		s := NewHTTPEventSweeper(cl).SetClock(func() time.Time { return fixed })
		if _, err := s.SweepOnce(context.Background()); err == nil {
			t.Error("错误不得静默吞掉")
		}
	})
}

var errTest = errTestSentinel{}

type errTestSentinel struct{}

func (errTestSentinel) Error() string { return "test error" }
