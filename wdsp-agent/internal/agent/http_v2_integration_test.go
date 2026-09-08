// HTTP 事件 v2 双侧联调集成测试（P1-03 G1；契约
// docs/agents/WDSP_AGENT_HTTP_EVENT_V2_CONTRACT.md §1/§3/§4）：
// httptest 模拟 server v2 端点按契约响应 + 真实序列化批次，覆盖：
// v2 协商→发送→计数分账、invalid_records 索引隔离（不再二分）、
// 旧 server（无协商回执）降级 v1、v2 无索引 400 降级重发、重试 event_id 不变。
package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/buffer"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

// v2IntegRecords 三条可区分测试记录（flow_id/request_ts 不同 → event_id 互异）。
func v2IntegRecords() []events.HTTPRecord {
	out := make([]events.HTTPRecord, 0, 3)
	for i := 0; i < 3; i++ {
		ts := 1788256800.123 + float64(i)*0.001
		respTS := ts + 0.1
		lat := int64(100)
		out = append(out, events.HTTPRecord{
			FlowID: "a1-1.1.1.1-80-2.2.2.2-8080-" + string(rune('1'+i)), RequestTS: ts,
			ResponseTS: &respTS, LatencyMs: &lat,
			SrcIP: "1.1.1.1", SrcPort: 80, DstIP: "2.2.2.2", DstPort: 8080,
			Direction: "ingress", TLSVisibility: "PLAINTEXT",
			Request:  &events.HTTPMessage{Method: "GET", Scheme: "http", Host: "h", URI: "/a", Headers: map[string]string{"x-a": "1"}},
			Response: &events.HTTPMessage{Status: 200, Headers: map[string]string{"x-b": "2"}},
		})
	}
	return out
}

// v2Envelope 服务端视角的 v2 批次包络（解码校验用）。
type v2Envelope struct {
	SchemaVersion int                      `json:"schema_version"`
	Records       []map[string]interface{} `json:"records"`
}

// assertV2Wire 校验记录线格式关键字段（契约 §2 [G1] 项）。
func assertV2Wire(t *testing.T, rec map[string]interface{}) {
	t.Helper()
	if rec["event_id"] == "" {
		t.Error("event_id 缺失")
	}
	if rec["source_type"] != events.SourcePassiveHTTP1 || rec["source_instance"] == "" {
		t.Errorf("来源字段错误: %v/%v", rec["source_type"], rec["source_instance"])
	}
	if rec["observed_http_version"] != events.HTTPVersion11 {
		t.Errorf("observed_http_version: %v", rec["observed_http_version"])
	}
	if rec["association_state"] != events.AssocComplete || rec["association_reason"] != "" {
		t.Errorf("association: %v/%v", rec["association_state"], rec["association_reason"])
	}
	if rec["collection_ts"] == nil {
		t.Error("collection_ts 缺失")
	}
	req, _ := rec["request"].(map[string]interface{})
	hdrs, _ := req["headers"].(map[string]interface{})
	if arr, _ := hdrs["x-a"].([]interface{}); len(arr) != 1 {
		t.Errorf("request.headers 应为数组形态: %v", hdrs)
	}
	if _, ok := req["body_quality"].(map[string]interface{}); !ok {
		t.Errorf("request.body_quality 缺失: %v", req)
	}
}

// TestHTTPV2NegotiateSendAccounting v2 协商→发送→计数分账：
// 真实心跳回执生效集 [1,2] → 发送 v2 批次 → accepted/duplicate 分账；
// 同批重放 → 全部 duplicate（服务端按 event_id 幂等），event_id 不变。
func TestHTTPV2NegotiateSendAccounting(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	var batches []v2Envelope
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agents/a1/heartbeat":
			var req transport.HeartbeatRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("心跳解析: %v", err)
			}
			if req.Capabilities == nil || !req.Capabilities.HasSchemaVersion(2) {
				t.Errorf("心跳应声明 [1,2]: %+v", req.Capabilities)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"server_time": 1, "config_version": 0, "desired_state": "ENABLED",
				"heartbeat_interval_seconds": 15,
				"capabilities":               map[string]interface{}{"http_event_schema_versions": []int{1, 2}},
			})
		case "/api/v1/agents/a1/http":
			var env v2Envelope
			if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
				t.Errorf("批次解析: %v", err)
			}
			if env.SchemaVersion != 2 {
				t.Errorf("schema_version 应为 2: %d", env.SchemaVersion)
			}
			mu.Lock()
			batches = append(batches, env)
			accepted, duplicate := 0, 0
			for _, rec := range env.Records {
				assertV2Wire(t, rec)
				id, _ := rec["event_id"].(string)
				if seen[id] {
					duplicate++
				} else {
					seen[id] = true
					accepted++
				}
			}
			mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(events.HTTPV2Response{AcceptedCount: accepted, DuplicateCount: duplicate})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	a := newTestAgent(t, srv.URL)
	a.applyPolicy(a.cfg.EffectivePolicy())

	// ① 协商：真实心跳往返 → 生效集含 2
	hb, err := a.client.Heartbeat(context.Background(), "a1", transport.HeartbeatRequest{
		Timestamp: time.Now().Unix(), Status: "ONLINE", Capabilities: transport.DeclaredCapabilities(),
	})
	if err != nil {
		t.Fatal(err)
	}
	a.applyCapabilities(hb.Capabilities)
	if !a.httpV2.Load() {
		t.Fatal("生效集含 v2 应启用 v2 发送路径")
	}

	// ② 发送：accepted 分账
	recs := v2IntegRecords()
	a.sendHTTPBatch(recs)
	if got := a.metrics.Accepted.Load(); got != 3 {
		t.Fatalf("accepted 应为 3: %d", got)
	}
	if got := a.metrics.Duplicate.Load(); got != 0 {
		t.Fatalf("首发不应有 duplicate: %d", got)
	}

	// ③ 重放同批：duplicate 分账且 event_id 不变
	a.sendHTTPBatch(recs)
	if got := a.metrics.Duplicate.Load(); got != 3 {
		t.Fatalf("重放应全部 duplicate: %d", got)
	}
	if got := a.metrics.Accepted.Load(); got != 3 {
		t.Fatalf("重放不应增加 accepted: %d", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(batches) != 2 {
		t.Fatalf("应发送 2 批: %d", len(batches))
	}
	for i := range batches[0].Records {
		if batches[0].Records[i]["event_id"] != batches[1].Records[i]["event_id"] {
			t.Fatal("重放 event_id 必须稳定不变（幂等键）")
		}
	}
}

// TestHTTPV2InvalidRecordsIndexIsolation invalid_records 按索引隔离（不再二分）：
// 3 条中 records[1] 非法 → 仅该条丢弃计数，剩余 2 条原序重建批次重发成功。
func TestHTTPV2InvalidRecordsIndexIsolation(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	var resent v2Envelope
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env v2Envelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			t.Errorf("批次解析: %v", err)
		}
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]string{"code": "INVALID_ARGUMENT", "message": "批次含非法记录"},
				"invalid_records": []events.InvalidRecord{
					{Index: 1, Reason: "records[1]: event_id 非法"},
				},
			})
			return
		}
		mu.Lock()
		resent = env
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(events.HTTPV2Response{AcceptedCount: len(env.Records)})
	}))
	defer srv.Close()

	a := newTestAgent(t, srv.URL)
	a.applyCapabilities(&transport.Capabilities{HTTPEventSchemaVersions: []int{1, 2}})

	recs := v2IntegRecords()
	wantEventIDs := []string{
		events.StableEventID("a1", recs[0]), events.StableEventID("a1", recs[2]),
	}
	a.sendHTTPBatch(recs)

	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("应为 首次400 + 重建重发 共 2 次: %d", calls)
	}
	if len(resent.Records) != 2 {
		t.Fatalf("重建批次应为 2 条: %d", len(resent.Records))
	}
	for i, rec := range resent.Records {
		if rec["event_id"] != wantEventIDs[i] {
			t.Fatalf("重建批次第 %d 条 event_id 错误（索引隔离须保序保留合法记录）: %v", i, rec["event_id"])
		}
	}
	if got := a.metrics.Accepted.Load(); got != 2 {
		t.Fatalf("accepted 应为 2: %d", got)
	}
	if got := a.metrics.dropReasonsSnapshot()[DropReasonPermanentInvalid]; got != 1 {
		t.Fatalf("permanent_invalid 应为 1: %d", got)
	}
}

// TestHTTPLegacyServerFallbackV1 旧服务端无协商回执 → 完全走旧 v1 路径
// （v1 包络无 schema_version、headers 为单值 map 形态；202 {"accepted": n}）。
func TestHTTPLegacyServerFallbackV1(t *testing.T) {
	var gotV1 bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agents/a1/heartbeat":
			// 旧服务端：无 capabilities 回执字段
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"server_time": 1, "config_version": 0, "desired_state": "ENABLED",
				"heartbeat_interval_seconds": 15,
			})
		case "/api/v1/agents/a1/http":
			var env map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
				t.Errorf("批次解析: %v", err)
			}
			if _, ok := env["schema_version"]; ok {
				t.Errorf("v1 包络不应携带 schema_version: %v", env["schema_version"])
			}
			recs, _ := env["records"].([]interface{})
			rec, _ := recs[0].(map[string]interface{})
			if _, ok := rec["event_id"]; ok {
				t.Error("v1 记录不应携带 event_id")
			}
			req, _ := rec["request"].(map[string]interface{})
			hdrs, _ := req["headers"].(map[string]interface{})
			if v, ok := hdrs["x-a"].(string); !ok || v != "1" {
				t.Errorf("v1 headers 应为单值 map: %v", hdrs)
			}
			gotV1 = true
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(events.HTTPAcceptedResponse{Accepted: len(recs)})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	a := newTestAgent(t, srv.URL)
	a.applyPolicy(a.cfg.EffectivePolicy())

	hb, err := a.client.Heartbeat(context.Background(), "a1", transport.HeartbeatRequest{
		Timestamp: time.Now().Unix(), Status: "ONLINE", Capabilities: transport.DeclaredCapabilities(),
	})
	if err != nil {
		t.Fatal(err)
	}
	a.applyCapabilities(hb.Capabilities) // nil 回执 → 仅 v1
	if a.httpV2.Load() {
		t.Fatal("旧服务端无回执字段，不得启用 v2 发送路径")
	}

	a.sendHTTPBatch(v2IntegRecords()[:1])
	if !gotV1 {
		t.Fatal("应走 v1 线格式发送")
	}
	if got := a.metrics.Accepted.Load(); got != 1 {
		t.Fatalf("accepted 应为 1: %d", got)
	}
}

// TestHTTPV2NotNegotiatedDowngradesToV1 v2 批次 400 且无 invalid_records
// （未协商场景，契约 §1）→ 降级 v1 采集模式重发，不无限重试 v2。
func TestHTTPV2NotNegotiatedDowngradesToV1(t *testing.T) {
	var mu sync.Mutex
	var calls []int // 记录每批 schema_version
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			t.Errorf("批次解析: %v", err)
		}
		sv := 0
		if v, ok := env["schema_version"].(float64); ok {
			sv = int(v)
		}
		mu.Lock()
		calls = append(calls, sv)
		n := len(calls)
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]string{"code": "INVALID_ARGUMENT", "message": "该 Agent 未协商 HTTP 事件 schema v2"},
			})
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(events.HTTPAcceptedResponse{Accepted: 1})
	}))
	defer srv.Close()

	a := newTestAgent(t, srv.URL)
	a.applyCapabilities(&transport.Capabilities{HTTPEventSchemaVersions: []int{1, 2}})

	a.sendHTTPBatch(v2IntegRecords()[:1])

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 || calls[0] != 2 || calls[1] != 0 {
		t.Fatalf("应为 v2 400 → v1 重发各一次: %v", calls)
	}
	if a.httpV2.Load() {
		t.Fatal("降级后应关闭 v2 发送路径")
	}
	if got := a.metrics.Accepted.Load(); got != 1 {
		t.Fatalf("v1 重发应被接受: %d", got)
	}
}

// TestHTTPV2RetryEventIDStable 重试/补传 event_id 不变：首发 500 转磁盘缓存，
// 恢复后 replayBuffer 真实补传，两次请求同一 event_id（服务端据此幂等去重）。
func TestHTTPV2RetryEventIDStable(t *testing.T) {
	var mu sync.Mutex
	var eventIDs []string
	fail := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env v2Envelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			t.Errorf("批次解析: %v", err)
		}
		if env.SchemaVersion != 2 || len(env.Records) != 1 {
			t.Errorf("应为 v2 单条批次: sv=%d n=%d", env.SchemaVersion, len(env.Records))
		}
		mu.Lock()
		eventIDs = append(eventIDs, env.Records[0]["event_id"].(string))
		shouldFail := fail
		mu.Unlock()
		if shouldFail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(events.HTTPV2Response{AcceptedCount: 1, DuplicateCount: 0})
	}))
	defer srv.Close()

	a := newTestAgent(t, srv.URL)
	// 启用磁盘缓存（补传真实往返）
	buf, err := buffer.Open(t.TempDir(), 0, 1<<20, time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	a.buf = buf
	a.applyCapabilities(&transport.Capabilities{HTTPEventSchemaVersions: []int{1, 2}})

	recs := v2IntegRecords()[:1]
	a.sendHTTPBatch(recs) // 500 → 转缓存
	if a.buf.Bytes() == 0 {
		t.Fatal("500 后记录应转磁盘缓存")
	}

	mu.Lock()
	fail = false
	mu.Unlock()
	a.replayBuffer() // 补传（缓存记录为 v1，发送时按协商重构造 v2）
	if a.buf.Bytes() != 0 {
		t.Fatalf("补传成功后缓存应清空: %d", a.buf.Bytes())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(eventIDs) != 2 {
		t.Fatalf("应为 首发 + 补传 共 2 次请求: %d", len(eventIDs))
	}
	if eventIDs[0] != eventIDs[1] {
		t.Fatalf("重试/补传 event_id 必须稳定不变: %q vs %q", eventIDs[0], eventIDs[1])
	}
	if got := a.metrics.Accepted.Load(); got != 1 {
		t.Fatalf("补传 accepted 应为 1: %d", got)
	}
}
