// machine_handler_test.go 机器端点单测：注册（令牌消费/凭据摘要）/ Bearer 认证矩阵 /
// disabled 处置（心跳放行、其余 403）/ flows 批量上限 / RAW 帧校验与计数 / 配置拉取与 ACK。
// 仓储为内存 fake（MachineRepository 接口隔离，不触 DB——仓库无 DB 测试基建先例，
// DB 层以接口隔离，参照 apinodes sweeper_test.go fakeNodeStore 模式）。
package agents

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeMachineStore MachineRepository 内存实现。
type fakeMachineStore struct {
	agentsByHash map[string]*Agent
	enrollErr    error
	enrollIn     *EnrollInput

	hbStatus        string
	hbMetrics       []byte
	hbClockOffsetMS *int64
	cfgVer          int64

	metricsBody []byte
	policy      *Policy
	configVer   int64

	ackedVersion int64
	ackedApplied bool

	insertedEvents []FlowEvent
	insertErr      error
	rawFrames      int64
	rawBytes       int64

	// Phase 3：HTTP 事件批量 fake 状态
	insertedHTTP  []HTTPRecord
	httpInsertErr error

	// v2：HTTP 事件 schema v2 幂等入库与来源关系 fake 状态
	insertedHTTPV2   []HTTPRecordV2
	httpV2SeenIDs    map[string]bool
	httpV2InsertErr  error
	assetSources     []HTTPAssetSourceInput
	assetSourceErr   error
	heartbeatSchemas []int16

	// Phase 2-B：PoP 认证与证书轮换 fake 状态
	agentsByID map[uuid.UUID]*Agent
	graceFP    map[string]time.Time // 宽限中指纹 → grace_until（模拟 revocations 宽限行）
	revokedFP  map[string]bool      // 立即撤销指纹（模拟 revocations grace_until=NULL / disable 清空当前指纹后状态）
	rotateIn   *RotateCertInput
	rotateErr  error

	// Phase 4：定向采集规则 fake 状态（config 下发）
	overrides []CaptureOverride
}

func newFakeMachineStore() *fakeMachineStore {
	return &fakeMachineStore{
		agentsByHash:  map[string]*Agent{},
		agentsByID:    map[uuid.UUID]*Agent{},
		graceFP:       map[string]time.Time{},
		revokedFP:     map[string]bool{},
		httpV2SeenIDs: map[string]bool{},
	}
}

func (f *fakeMachineStore) Enroll(_ context.Context, in EnrollInput) (*Agent, error) {
	if f.enrollErr != nil {
		return nil, f.enrollErr
	}
	cp := in
	f.enrollIn = &cp
	return &Agent{AgentID: in.AgentID, Hostname: in.Hostname, IP: in.IP, LastMetrics: []byte(`{}`)}, nil
}

func (f *fakeMachineStore) AgentByCredentialHash(_ context.Context, hash string) (*Agent, error) {
	if a, ok := f.agentsByHash[hash]; ok {
		return a, nil
	}
	return nil, ErrAgentNotFound
}

func (f *fakeMachineStore) RecordHeartbeat(_ context.Context, _ uuid.UUID, status string, metrics []byte, clockOffsetMS *int64, schemas []int16, _ time.Time) (int64, error) {
	f.hbStatus = status
	f.hbMetrics = metrics
	f.hbClockOffsetMS = clockOffsetMS
	f.heartbeatSchemas = schemas
	return f.cfgVer, nil
}

func (f *fakeMachineStore) RecordMetrics(_ context.Context, _ uuid.UUID, metrics []byte, _ time.Time) error {
	f.metricsBody = metrics
	return nil
}

func (f *fakeMachineStore) AgentConfig(_ context.Context, _ uuid.UUID) (int64, *Policy, error) {
	return f.configVer, f.policy, nil
}

func (f *fakeMachineStore) AckConfig(_ context.Context, _ uuid.UUID, version int64, applied bool) error {
	f.ackedVersion = version
	f.ackedApplied = applied
	return nil
}

func (f *fakeMachineStore) InsertFlowEvents(_ context.Context, _ uuid.UUID, events []FlowEvent) error {
	if f.insertErr != nil {
		return f.insertErr
	}
	f.insertedEvents = append(f.insertedEvents, events...)
	return nil
}

func (f *fakeMachineStore) InsertHTTPEvents(_ context.Context, _ uuid.UUID, records []HTTPRecord) error {
	if f.httpInsertErr != nil {
		return f.httpInsertErr
	}
	f.insertedHTTP = append(f.insertedHTTP, records...)
	return nil
}

// InsertHTTPEventsV2 v2 幂等入库 fake（按 event_id 去重——与库部分唯一索引同口径；
// 返回新入库下标与重复条数）。
func (f *fakeMachineStore) InsertHTTPEventsV2(_ context.Context, _ uuid.UUID, records []HTTPRecordV2, _ time.Time) ([]int, int, error) {
	if f.httpV2InsertErr != nil {
		return nil, 0, f.httpV2InsertErr
	}
	accepted := []int{}
	dups := 0
	for i := range records {
		if f.httpV2SeenIDs[records[i].EventID] {
			dups++
			continue
		}
		f.httpV2SeenIDs[records[i].EventID] = true
		f.insertedHTTPV2 = append(f.insertedHTTPV2, records[i])
		accepted = append(accepted, i)
	}
	return accepted, dups, nil
}

// UpsertHTTPAssetSource 来源关系持久化 fake（逐条追加，断言用）。
func (f *fakeMachineStore) UpsertHTTPAssetSource(_ context.Context, in HTTPAssetSourceInput) error {
	if f.assetSourceErr != nil {
		return f.assetSourceErr
	}
	f.assetSources = append(f.assetSources, in)
	return nil
}

func (f *fakeMachineStore) AddRawCounters(_ context.Context, _ uuid.UUID, frames, bytes int64) error {
	f.rawFrames += frames
	f.rawBytes += bytes
	return nil
}

// ActiveCaptureOverrides 未过期规则全量（按 now 过滤，与 SQL expires_at > now 同口径）。
func (f *fakeMachineStore) ActiveCaptureOverrides(_ context.Context, _ uuid.UUID, now time.Time) ([]CaptureOverride, error) {
	out := []CaptureOverride{}
	for _, o := range f.overrides {
		if o.ExpiresAt.After(now) {
			out = append(out, o)
		}
	}
	return out, nil
}

// registerAgent 在 fake 中登记 Agent，返回明文凭据。
func registerAgent(f *fakeMachineStore, agentID uuid.UUID, disabled bool) string {
	cred := "wda_" + strings.Repeat("ef", 32)
	a := &Agent{AgentID: agentID, Disabled: disabled}
	f.agentsByHash[HashSecret(cred)] = a
	f.agentsByID[agentID] = a
	return cred
}

func newMachineMux(mh *MachineHandler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterMachineRoutes(mux, mh)
	return mux
}

func doMachine(t *testing.T, mux http.Handler, method, path, body, cred string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// decodeErrEnvelope 解析契约 §2 错误信封。
func decodeErrEnvelope(t *testing.T, rr *httptest.ResponseRecorder) (code, msg string) {
	t.Helper()
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("错误信封解析失败: %v (body=%s)", err, rr.Body.String())
	}
	return env.Error.Code, env.Error.Message
}

// ---------- 注册 ----------

// TestEnrollSuccess 注册成功：201 + credential 明文仅此一次下发；服务端只收摘要。
func TestEnrollSuccess(t *testing.T) {
	store := newFakeMachineStore()
	mux := newMachineMux(NewMachineHandler(store))
	token := "wdt_" + strings.Repeat("cd", 32)
	body := `{
	  "enrollment_token": "` + token + `",
	  "hostname": "web-prod-01", "ip": "10.0.1.10", "os": "Rocky Linux 9",
	  "kernel": "5.14.0", "arch": "x86_64", "version": "1.0.0",
	  "interfaces": [{"name":"eth0","mac":"aa:bb:cc:dd:ee:ff","ipv4":"10.0.1.10","ipv6":"","mtu":1500,"speed_mbps":1000}]
	}`
	rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/enroll", body, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		AgentID                 string `json:"agent_id"`
		Credential              string `json:"credential"`
		HeartbeatIntervalSecond int    `json:"heartbeat_interval_seconds"`
		ConfigVersion           int64  `json:"config_version"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, err := uuid.Parse(resp.AgentID); err != nil {
		t.Errorf("agent_id 非 UUID: %q", resp.AgentID)
	}
	if !credentialPattern.MatchString(resp.Credential) {
		t.Errorf("credential 格式非法: %q", resp.Credential)
	}
	if resp.HeartbeatIntervalSecond != HeartbeatIntervalSeconds || resp.ConfigVersion != 0 {
		t.Errorf("响应字段异常: %+v", resp)
	}
	// 落库只应是摘要：token/credential 明文不得出现在存储输入
	if store.enrollIn == nil {
		t.Fatal("store.Enroll 未被调用")
	}
	if store.enrollIn.TokenHash != HashSecret(token) {
		t.Error("token 未按 SHA-256 摘要落库")
	}
	if store.enrollIn.CredentialHash != HashSecret(resp.Credential) {
		t.Error("credential 未按 SHA-256 摘要落库")
	}
	if strings.Contains(store.enrollIn.TokenHash, token) || strings.Contains(store.enrollIn.CredentialHash, resp.Credential) {
		t.Error("摘要中不得包含明文")
	}
}

// TestEnrollInvalidToken 令牌无效/过期/已用/已撤销 → 401（契约 §3.1）。
func TestEnrollInvalidToken(t *testing.T) {
	store := newFakeMachineStore()
	store.enrollErr = ErrTokenInvalid
	mux := newMachineMux(NewMachineHandler(store))
	body := `{"enrollment_token":"wdt_` + strings.Repeat("cd", 32) + `","hostname":"h","ip":"10.0.0.1"}`
	rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/enroll", body, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rr.Code, rr.Body.String())
	}
	code, _ := decodeErrEnvelope(t, rr)
	if code != mcUnauthenticated {
		t.Errorf("error.code = %q, want %q", code, mcUnauthenticated)
	}
}

// TestEnrollBadRequest 参数非法 → 400（且不触库——格式问题不烧令牌）。
func TestEnrollBadRequest(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"令牌格式非法", `{"enrollment_token":"bad","hostname":"h","ip":"10.0.0.1"}`},
		{"ip 非法", `{"enrollment_token":"wdt_` + strings.Repeat("cd", 32) + `","hostname":"h","ip":"x"}`},
		{"hostname 缺失", `{"enrollment_token":"wdt_` + strings.Repeat("cd", 32) + `","ip":"10.0.0.1"}`},
		{"未知字段", `{"enrollment_token":"wdt_` + strings.Repeat("cd", 32) + `","hostname":"h","ip":"10.0.0.1","evil":1}`},
		{"非 JSON", `not-json`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := newFakeMachineStore()
			mux := newMachineMux(NewMachineHandler(store))
			rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/enroll", c.body, "")
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", rr.Code, rr.Body.String())
			}
			if store.enrollIn != nil {
				t.Error("校验失败不应触库（令牌不得被烧毁）")
			}
		})
	}
}

// ---------- 认证矩阵 ----------

// TestMachineAuthMatrix Bearer 认证：缺头/格式非法/未登记 → 401；路径 agent_id 不匹配 → 403。
func TestMachineAuthMatrix(t *testing.T) {
	agentID := uuid.New()
	newMux := func() (*http.ServeMux, string) {
		store := newFakeMachineStore()
		cred := registerAgent(store, agentID, false)
		return newMachineMux(NewMachineHandler(store)), cred
	}
	hb := `{"timestamp":1788256800,"status":"ONLINE"}`
	path := "/api/v1/agents/" + agentID.String() + "/heartbeat"

	t.Run("缺 Authorization 401", func(t *testing.T) {
		mux, _ := newMux()
		rr := doMachine(t, mux, http.MethodPost, path, hb, "")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
	})
	t.Run("credential 格式非法 401", func(t *testing.T) {
		mux, _ := newMux()
		rr := doMachine(t, mux, http.MethodPost, path, hb, "short")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
	})
	t.Run("credential 未登记 401", func(t *testing.T) {
		mux, _ := newMux()
		rr := doMachine(t, mux, http.MethodPost, path, hb, "wda_"+strings.Repeat("00", 32))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
	})
	t.Run("路径 agent_id 不匹配 403", func(t *testing.T) {
		mux, cred := newMux()
		rr := doMachine(t, mux, http.MethodPost,
			"/api/v1/agents/"+uuid.NewString()+"/heartbeat", hb, cred)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rr.Code)
		}
	})
	t.Run("路径 agent_id 非法 400", func(t *testing.T) {
		mux, cred := newMux()
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/not-uuid/heartbeat", hb, cred)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})
}

// ---------- 心跳 / 指标 ----------

// TestHeartbeat 心跳：正常 200（desired_state/config_version/心跳间隔）；disabled 放行且 desired_state=DISABLED。
func TestHeartbeat(t *testing.T) {
	t.Run("正常心跳", func(t *testing.T) {
		store := newFakeMachineStore()
		store.cfgVer = 12
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/heartbeat",
			`{"timestamp":1788256800,"status":"DEGRADED","metrics":{"cpu_percent":3.2,"memory_mb":128.5}}`, cred)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}
		var resp struct {
			ServerTime         int64  `json:"server_time"`
			ConfigVersion      int64  `json:"config_version"`
			DesiredState       string `json:"desired_state"`
			HeartbeatIntervalS int    `json:"heartbeat_interval_seconds"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.ConfigVersion != 12 || resp.DesiredState != DesiredEnabled ||
			resp.HeartbeatIntervalS != HeartbeatIntervalSeconds || resp.ServerTime <= 0 {
			t.Errorf("响应异常: %+v", resp)
		}
		if store.hbStatus != "DEGRADED" || !strings.Contains(string(store.hbMetrics), "cpu_percent") {
			t.Errorf("落库内容异常: status=%q metrics=%s", store.hbStatus, store.hbMetrics)
		}
	})
	t.Run("disabled 心跳放行且 desired_state=DISABLED", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, true)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/heartbeat",
			`{"timestamp":1788256800,"status":"ONLINE"}`, cred)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"desired_state":"DISABLED"`) {
			t.Errorf("desired_state 应为 DISABLED: %s", rr.Body.String())
		}
	})
	t.Run("status 非法 400", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/heartbeat",
			`{"timestamp":1788256800,"status":"SLEEPING"}`, cred)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})
}

// TestMetricsEndpoint 指标端点：204；disabled 403（契约：除心跳外全部 403）。
func TestMetricsEndpoint(t *testing.T) {
	t.Run("正常 204", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/metrics",
			`{"cpu_percent":3.2,"memory_mb":128.5}`, cred)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204 (body=%s)", rr.Code, rr.Body.String())
		}
		if !strings.Contains(string(store.metricsBody), "cpu_percent") {
			t.Errorf("metrics 未落库: %s", store.metricsBody)
		}
	})
	t.Run("disabled 403", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, true)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/metrics",
			`{"cpu_percent":3.2}`, cred)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rr.Code)
		}
	})
	t.Run("非 JSON 对象 400", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/metrics", `[1,2]`, cred)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})
}

// ---------- 配置拉取与 ACK ----------

// TestGetConfig 配置拉取：无绑定 policy=null；有绑定原样下发策略 JSON。
func TestGetConfig(t *testing.T) {
	t.Run("无绑定 policy=null", func(t *testing.T) {
		store := newFakeMachineStore()
		store.configVer = 7
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodGet, "/api/v1/agents/"+agentID.String()+"/config", "", cred)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
		var resp struct {
			Version int64            `json:"version"`
			Policy  *json.RawMessage `json:"policy"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Version != 7 || resp.Policy != nil {
			t.Errorf("resp = %+v, want version=7 policy=null", resp)
		}
	})
	t.Run("有绑定原样下发", func(t *testing.T) {
		store := newFakeMachineStore()
		store.configVer = 12
		store.policy = &Policy{ID: uuid.New(), Name: "production-web", Config: validPolicyJSON(), Version: 3}
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodGet, "/api/v1/agents/"+agentID.String()+"/config", "", cred)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
		var resp struct {
			Version int64           `json:"version"`
			Policy  json.RawMessage `json:"policy"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Version != 12 {
			t.Errorf("version = %d, want 12", resp.Version)
		}
		var cfg PolicyConfig
		if err := json.Unmarshal(resp.Policy, &cfg); err != nil {
			t.Fatalf("policy decode: %v", err)
		}
		if cfg.Name != "production-web" || cfg.Output.Mode != "FLOW" || cfg.Capture.Direction != "both" {
			t.Errorf("policy 内容异常: %+v", cfg)
		}
	})
}

// TestConfigAck ACK：APPLIED 推进 applied 版本；FAILED 不回填。
func TestConfigAck(t *testing.T) {
	t.Run("APPLIED 204", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/config/ack",
			`{"version":12,"status":"APPLIED","error":""}`, cred)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204 (body=%s)", rr.Code, rr.Body.String())
		}
		if !store.ackedApplied || store.ackedVersion != 12 {
			t.Errorf("ack = (%d, %v), want (12, true)", store.ackedVersion, store.ackedApplied)
		}
	})
	t.Run("FAILED 不回填", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/config/ack",
			`{"version":12,"status":"FAILED","error":"bpf load failed"}`, cred)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rr.Code)
		}
		if store.ackedApplied {
			t.Error("FAILED 不应回填 applied_config_version")
		}
	})
	t.Run("FAILED 缺 error 400", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/config/ack",
			`{"version":12,"status":"FAILED"}`, cred)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})
}

// ---------- flows ----------

// TestFlows 流量事件上报：202 accepted；超 500 拒绝；入库失败整体 500。
func TestFlows(t *testing.T) {
	eventJSON := func() string {
		raw, _ := json.Marshal(validFlowEvent())
		return string(raw)
	}
	t.Run("正常 202", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/flows",
			`{"events":[`+eventJSON()+`,`+eventJSON()+`]}`, cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"accepted":2`) {
			t.Errorf("accepted 应为 2: %s", rr.Body.String())
		}
		if len(store.insertedEvents) != 2 {
			t.Errorf("入库事件数 = %d, want 2", len(store.insertedEvents))
		}
	})
	t.Run("超 500 条 400", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		var sb strings.Builder
		sb.WriteString(`{"events":[`)
		for i := 0; i < MaxFlowEventsPerBatch+1; i++ {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(eventJSON())
		}
		sb.WriteString(`]}`)
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/flows", sb.String(), cred)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
		if len(store.insertedEvents) != 0 {
			t.Error("超限批量不得入库")
		}
	})
	t.Run("入库失败整体 500", func(t *testing.T) {
		store := newFakeMachineStore()
		store.insertErr = errors.New("db down")
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/flows",
			`{"events":[`+eventJSON()+`]}`, cred)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rr.Code)
		}
	})
	t.Run("disabled 403", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, true)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/flows",
			`{"events":[`+eventJSON()+`]}`, cred)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rr.Code)
		}
	})
	t.Run("事件非法 400", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		bad := validFlowEvent()
		bad.EventType = "response"
		raw, _ := json.Marshal(bad)
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/flows",
			`{"events":[`+string(raw)+`]}`, cred)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})
}

// ---------- packets ----------

// doPackets 发送 RAW 批量（二进制 Content-Type）。
func doPackets(t *testing.T, mux http.Handler, path, cred string, body []byte, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Authorization", "Bearer "+cred)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestPackets RAW 包上报：WDP1 校验/计数/丢弃；magic/Content-Type/disabled 拒绝。
func TestPackets(t *testing.T) {
	t.Run("合法批量 202 并计数", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		body := buildBatch([]byte("frame-one"), []byte("frame-two!!"))
		rr := doPackets(t, mux, "/api/v1/agents/"+agentID.String()+"/packets", cred, body, packetBatchContentType)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"accepted_frames":2`) {
			t.Errorf("accepted_frames 应为 2: %s", rr.Body.String())
		}
		wantBytes := int64(len("frame-one") + len("frame-two!!"))
		if store.rawFrames != 2 || store.rawBytes != wantBytes {
			t.Errorf("计数 = (%d, %d), want (2, %d)", store.rawFrames, store.rawBytes, wantBytes)
		}
	})
	t.Run("magic 非法 400", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		body := buildBatch([]byte("x"))
		copy(body[:4], "XXXX")
		rr := doPackets(t, mux, "/api/v1/agents/"+agentID.String()+"/packets", cred, body, packetBatchContentType)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
		if store.rawFrames != 0 {
			t.Error("非法批量不得计数")
		}
	})
	t.Run("Content-Type 缺失 400", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doPackets(t, mux, "/api/v1/agents/"+agentID.String()+"/packets", cred, buildBatch(), "")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})
	t.Run("disabled 403", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, true)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doPackets(t, mux, "/api/v1/agents/"+agentID.String()+"/packets", cred, buildBatch(), packetBatchContentType)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rr.Code)
		}
	})
	t.Run("未认证 401", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		mux := newMachineMux(NewMachineHandler(store))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/"+agentID.String()+"/packets",
			strings.NewReader(string(buildBatch())))
		req.Header.Set("Content-Type", packetBatchContentType)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
	})
}
