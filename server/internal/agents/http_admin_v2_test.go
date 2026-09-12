// http_admin_v2_test.go HTTP 事件管理端点 v2 展示单测（任务书 P1-03 §4.3，G4a；
// v2 契约 §6 存储映射）：
//   - 列表/详情扩展返回 v2 字段（来源三元组/协议观测/关联状态/绑定/时间戳）；
//   - 详情还原 v2 headers/trailers 数组形态（保序保留重复值——修复 v2 行 headers
//     返回空对象的限制），body_quality/grpc 子对象如实输出；
//   - v1 行 headers 维持 string map 形态，v2 专有子对象为 null（不伪造）；
//   - Agent 详情暴露 http_event_schemas 能力集（「需升级」判定依据字段）。
package agents

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

// nestedHTTPEventV2 测试侧 v2 嵌套记录解码结构（headers/trailers 双形态 RawMessage）。
type nestedHTTPEventV2 struct {
	ID                        int64           `json:"id"`
	FlowID                    string          `json:"flow_id"`
	SchemaVersion             int             `json:"schema_version"`
	EventID                   *string         `json:"event_id"`
	SourceType                string          `json:"source_type"`
	SourceInstance            string          `json:"source_instance"`
	SourceEpoch               int64           `json:"source_epoch"`
	SourceCapabilitiesVersion string          `json:"source_capabilities_version"`
	ObservedHTTPVersion       string          `json:"observed_http_version"`
	OriginalHTTPVersion       *string         `json:"original_http_version"`
	AssociationState          *string         `json:"association_state"`
	AssociationReason         string          `json:"association_reason"`
	CaptureStreamID           *string         `json:"capture_stream_id"`
	ApplicationBindingID      *string         `json:"application_binding_id"`
	BindingVersion            *int64          `json:"binding_version"`
	GRPC                      json.RawMessage `json:"grpc"`
	CollectionTS              *float64        `json:"collection_ts"`
	IngestionTS               *float64        `json:"ingestion_ts"`
	Request                   struct {
		Method      string          `json:"method"`
		Host        string          `json:"host"`
		URI         string          `json:"uri"`
		Headers     json.RawMessage `json:"headers"`
		Trailers    json.RawMessage `json:"trailers"`
		Body        string          `json:"body"`
		BodyQuality json.RawMessage `json:"body_quality"`
	} `json:"request"`
	Response *struct {
		Status      int             `json:"status"`
		Headers     json.RawMessage `json:"headers"`
		Trailers    json.RawMessage `json:"trailers"`
		Body        string          `json:"body"`
		BodyQuality json.RawMessage `json:"body_quality"`
	} `json:"response"`
}

// v2HTTPRow 构造 v2 事件行（含全部 v2 列与 JSONB 子对象）。
func v2HTTPRow(agentID uuid.UUID) HTTPEventRow {
	status := 200
	latency := 12
	eventID := "agent1-mirror-nginx-a-1788256800123-7"
	origVer := HTTPVersion11
	assocState := AssocStateRequestOnly
	streamID := "conn-9/stream-3"
	bindingID := uuid.New()
	bindingVer := int64(4)
	reqBody := `{"q":"1"}`
	collectionTS := time.Unix(1788256800, 100000000).UTC()
	ingestionTS := time.Unix(1788256845, 200000000).UTC() // 延迟 45.1s——缓存补传可辨
	return HTTPEventRow{
		ID: 9, AgentID: agentID, FlowID: "f-v2", Method: "POST", Scheme: "https",
		Host: "api.example.com", URI: "/pkg.UserService/GetUser",
		Direction: "ingress", TLSVisibility: TLSDecrypted,
		SrcIP: "127.0.0.1", SrcPort: 0, DstIP: "127.0.0.1", DstPort: 9000,
		Status: &status, LatencyMS: &latency,
		RequestHeaders:  json.RawMessage(`{"content-type":["application/grpc"],"set-cookie":["a=1","b=2"]}`),
		ResponseHeaders: json.RawMessage(`{"content-type":["application/grpc"]}`),
		RequestBody:     &reqBody,
		ReqTruncated:    true, ReqOriginalSize: 4096,
		Ts: time.Unix(1788256800, 123000000).UTC(),
		// ---- v2 列 ----
		SchemaVersion: HTTPEventSchemaV2, EventID: &eventID,
		SourceType: SourceTypeNginxMirror, SourceInstance: "nginx-a", SourceEpoch: 3,
		SourceCapabilitiesVersion: "nginx-mirror/1",
		ObservedHTTPVersion:       HTTPVersion2, OriginalHTTPVersion: &origVer,
		AssociationState: &assocState, AssociationReason: AssocReasonSourceRequestOnly,
		CaptureStreamID:      &streamID,
		ApplicationBindingID: &bindingID, BindingVersion: &bindingVer,
		GRPC:             json.RawMessage(`{"service":"pkg.UserService","method":"GetUser","grpc_status":null,"stream_state":"OPEN"}`),
		RequestTrailers:  json.RawMessage(`{"x-trace":["t1"]}`),
		ResponseTrailers: json.RawMessage(`{"grpc-status":["0"]}`),
		ReqBodyQuality:   json.RawMessage(`{"captured_bytes":128,"original_total_size":4096,"truncated":true,"skipped_reason":""}`),
		RespBodyQuality:  json.RawMessage(`{"captured_bytes":0,"original_total_size":null,"truncated":false,"skipped_reason":""}`),
		CollectionTS:     &collectionTS, IngestionTS: &ingestionTS,
	}
}

// TestListHTTPEventsV2 列表：v2 标量字段（来源/协议/关联/绑定/时间戳）逐行带出；
// headers 仍为空对象（列表轻量纪律不变）。
func TestListHTTPEventsV2(t *testing.T) {
	agentID := uuid.New()
	store := newFakeAdminStore()
	store.details[agentID] = &AgentDetail{Agent: Agent{AgentID: agentID}}
	store.httpEvents = []HTTPEventRow{v2HTTPRow(agentID)}
	h := NewHandler(store).SetAudits(&spyAudits{})
	mux := newAdminMux(h, injectPerms(PermAgentsView))

	rr := doAdmin(t, mux, http.MethodGet,
		"/api/v1/traffic/agents/"+agentID.String()+"/http-events", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var payload struct {
		Items []nestedHTTPEventV2 `json:"items"`
		Total int64               `json:"total"`
	}
	decodeEnvelope(t, rr, &payload)
	if payload.Total != 1 || len(payload.Items) != 1 {
		t.Fatalf("分页载荷异常: %+v", payload)
	}
	it := payload.Items[0]
	if it.SchemaVersion != 2 || it.EventID == nil || *it.EventID == "" {
		t.Errorf("schema_version/event_id 异常: %+v", it)
	}
	if it.SourceType != SourceTypeNginxMirror || it.SourceInstance != "nginx-a" || it.SourceEpoch != 3 {
		t.Errorf("来源三元组异常: %+v", it)
	}
	if it.SourceCapabilitiesVersion != "nginx-mirror/1" {
		t.Errorf("source_capabilities_version 异常: %q", it.SourceCapabilitiesVersion)
	}
	if it.ObservedHTTPVersion != HTTPVersion2 || it.OriginalHTTPVersion == nil || *it.OriginalHTTPVersion != HTTPVersion11 {
		t.Errorf("协议观测异常: observed=%q original=%v", it.ObservedHTTPVersion, it.OriginalHTTPVersion)
	}
	if it.AssociationState == nil || *it.AssociationState != AssocStateRequestOnly ||
		it.AssociationReason != AssocReasonSourceRequestOnly {
		t.Errorf("关联状态异常: %+v", it)
	}
	if it.CaptureStreamID == nil || *it.CaptureStreamID != "conn-9/stream-3" {
		t.Errorf("capture_stream_id 异常: %v", it.CaptureStreamID)
	}
	if it.ApplicationBindingID == nil || it.BindingVersion == nil || *it.BindingVersion != 4 {
		t.Errorf("来源绑定异常: %+v", it)
	}
	if it.CollectionTS == nil || !floatEq(*it.CollectionTS, 1788256800.1) {
		t.Errorf("collection_ts 异常: %v", it.CollectionTS)
	}
	if it.IngestionTS == nil || !floatEq(*it.IngestionTS, 1788256845.2) {
		t.Errorf("ingestion_ts 异常: %v", it.IngestionTS)
	}
	// 列表轻量：headers 空对象，grpc/body_quality 不带出（null）
	if string(it.Request.Headers) != `{}` {
		t.Errorf("列表 request.headers 应为空对象: %s", it.Request.Headers)
	}
	if string(it.GRPC) != `null` {
		t.Errorf("列表 grpc 应为 null: %s", it.GRPC)
	}
}

// TestGetHTTPEventV2 详情：v2 headers/trailers 数组形态还原（重复 set-cookie 保留）、
// body_quality/grpc 子对象、null 语义（grpc_status 未结束不伪造 0）。
func TestGetHTTPEventV2(t *testing.T) {
	agentID := uuid.New()
	store := newFakeAdminStore()
	store.details[agentID] = &AgentDetail{Agent: Agent{AgentID: agentID}}
	row := v2HTTPRow(agentID)
	store.httpDetail = &row
	mux := newAdminMux(NewHandler(store), injectPerms(PermAgentsView))

	rr := doAdmin(t, mux, http.MethodGet,
		"/api/v1/traffic/agents/"+agentID.String()+"/http-events/9", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var ev nestedHTTPEventV2
	decodeEnvelope(t, rr, &ev)

	// headers 数组形态还原（v2 行不再返回空对象；重复值保序保留）
	var reqHeaders map[string][]string
	if err := json.Unmarshal(ev.Request.Headers, &reqHeaders); err != nil {
		t.Fatalf("request.headers 不是数组形态: %s (%v)", ev.Request.Headers, err)
	}
	cookies := reqHeaders["set-cookie"]
	if len(cookies) != 2 || cookies[0] != "a=1" || cookies[1] != "b=2" {
		t.Errorf("重复 set-cookie 未保序保留: %v", cookies)
	}
	if got := reqHeaders["content-type"]; len(got) != 1 || got[0] != "application/grpc" {
		t.Errorf("content-type 异常: %v", got)
	}
	// trailers 还原
	var reqTrailers map[string][]string
	if err := json.Unmarshal(ev.Request.Trailers, &reqTrailers); err != nil || reqTrailers["x-trace"][0] != "t1" {
		t.Errorf("request.trailers 还原异常: %s (%v)", ev.Request.Trailers, err)
	}
	// body_quality 完整对象（captured_bytes 与截断语义仅此保留）
	var bq HTTPBodyQuality
	if err := json.Unmarshal(ev.Request.BodyQuality, &bq); err != nil {
		t.Fatalf("request.body_quality 解析失败: %v", err)
	}
	if bq.CapturedBytes != 128 || !bq.Truncated || bq.OriginalTotalSize == nil || *bq.OriginalTotalSize != 4096 {
		t.Errorf("body_quality 异常: %+v", bq)
	}
	// 未知长度如实为 null（不得填 0）
	var respBQ map[string]interface{}
	if err := json.Unmarshal(ev.Response.BodyQuality, &respBQ); err != nil {
		t.Fatalf("response.body_quality 解析失败: %v", err)
	}
	if v, ok := respBQ["original_total_size"]; !ok || v != nil {
		t.Errorf("未知 original_total_size 应为 null: %v", respBQ)
	}
	// grpc 子对象原样（grpc_status null=流未结束，不伪造 0）
	var grpc map[string]interface{}
	if err := json.Unmarshal(ev.GRPC, &grpc); err != nil {
		t.Fatalf("grpc 解析失败: %v", err)
	}
	if grpc["service"] != "pkg.UserService" || grpc["stream_state"] != "OPEN" {
		t.Errorf("grpc 异常: %v", grpc)
	}
	if v, ok := grpc["grpc_status"]; !ok || v != nil {
		t.Errorf("grpc_status 应为 null（流未结束不伪造 0）: %v", grpc)
	}
}

// TestGetHTTPEventV1Compat v1 行详情：headers 维持 string map；v2 子对象全 null；
// 零值 v2 列归一为库默认口径（schema_version=1 / PASSIVE_HTTP1 / UNKNOWN）。
func TestGetHTTPEventV1Compat(t *testing.T) {
	agentID := uuid.New()
	body := `{"token":"********"}`
	status := 200
	latency := 33
	store := newFakeAdminStore()
	store.details[agentID] = &AgentDetail{Agent: Agent{AgentID: agentID}}
	store.httpDetail = &HTTPEventRow{
		ID: 7, AgentID: agentID, FlowID: "f1", Method: "POST", Scheme: "http",
		Host: "api.example.com", URI: "/api/login",
		Direction: "ingress", TLSVisibility: "PLAINTEXT",
		SrcIP: "10.1.1.10", SrcPort: 51234, DstIP: "10.1.2.20", DstPort: 8080,
		Status: &status, LatencyMS: &latency,
		RequestHeaders: json.RawMessage(`{"authorization":"********"}`),
		ResponseBody:   &body,
		Ts:             time.Unix(1788256800, 123000000).UTC(),
	}
	mux := newAdminMux(NewHandler(store), injectPerms(PermAgentsView))

	rr := doAdmin(t, mux, http.MethodGet,
		"/api/v1/traffic/agents/"+agentID.String()+"/http-events/7", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var ev nestedHTTPEventV2
	decodeEnvelope(t, rr, &ev)
	if ev.SchemaVersion != 1 || ev.EventID != nil {
		t.Errorf("v1 行 schema_version/event_id 异常: %+v", ev)
	}
	if ev.SourceType != SourceTypePassiveHTTP1 || ev.SourceInstance != "" || ev.SourceEpoch != 0 {
		t.Errorf("v1 行来源默认口径异常: %+v", ev)
	}
	if ev.ObservedHTTPVersion != HTTPVersionUnknown || ev.OriginalHTTPVersion != nil {
		t.Errorf("v1 行协议观测默认口径异常: %+v", ev)
	}
	if ev.AssociationState != nil || ev.AssociationReason != "" {
		t.Errorf("v1 行关联状态应为 null/空: %+v", ev)
	}
	// headers 维持 string map 形态
	var headers map[string]string
	if err := json.Unmarshal(ev.Request.Headers, &headers); err != nil || headers["authorization"] != "********" {
		t.Errorf("v1 headers 应为 string map: %s (%v)", ev.Request.Headers, err)
	}
	// v2 专有子对象为 null（不伪造）
	if string(ev.Request.Trailers) != `null` || string(ev.Request.BodyQuality) != `null` || string(ev.GRPC) != `null` {
		t.Errorf("v1 行 trailers/body_quality/grpc 应为 null: %s %s %s",
			ev.Request.Trailers, ev.Request.BodyQuality, ev.GRPC)
	}
	if ev.CollectionTS != nil || ev.IngestionTS != nil {
		t.Errorf("v1 行 collection/ingestion_ts 应为 null: %+v", ev)
	}
}

// TestHeaderValuesFromJSON v2 headers 还原单元矩阵：数组形态保序保留；nil/空 → {}；
// v1 string map 形态（损坏/越版本数据）→ {} 回落（不原样透传、不输出 null）。
func TestHeaderValuesFromJSON(t *testing.T) {
	t.Run("数组形态原样还原", func(t *testing.T) {
		raw := json.RawMessage(`{"set-cookie":["a=1","b=2"],"x":["v"]}`)
		got := headerValuesFromJSON(raw)
		var m map[string][]string
		if err := json.Unmarshal(got, &m); err != nil {
			t.Fatalf("还原结果不是数组形态: %s", got)
		}
		if len(m["set-cookie"]) != 2 || m["set-cookie"][1] != "b=2" {
			t.Errorf("重复值未保留: %v", m)
		}
	})
	t.Run("nil/空 → {}", func(t *testing.T) {
		if got := headerValuesFromJSON(nil); string(got) != `{}` {
			t.Errorf("nil 应回落 {}: %s", got)
		}
	})
	t.Run("v1 string map 形态 → {}", func(t *testing.T) {
		if got := headerValuesFromJSON(json.RawMessage(`{"a":"b"}`)); string(got) != `{}` {
			t.Errorf("string map 形态应回落 {}: %s", got)
		}
	})
	t.Run("非法 JSON → {}", func(t *testing.T) {
		if got := headerValuesFromJSON(json.RawMessage(`{broken`)); string(got) != `{}` {
			t.Errorf("非法 JSON 应回落 {}: %s", got)
		}
	})
	t.Run("headersAdminJSON 列表恒轻量", func(t *testing.T) {
		raw := json.RawMessage(`{"a":["b"]}`)
		if got := headersAdminJSON(HTTPEventSchemaV2, raw, false); string(got) != `{}` {
			t.Errorf("列表 headers 应为 {}: %s", got)
		}
	})
	t.Run("headersAdminJSON v1 详情 string map", func(t *testing.T) {
		got := headersAdminJSON(1, json.RawMessage(`{"a":"b"}`), true)
		var m map[string]string
		if err := json.Unmarshal(got, &m); err != nil || m["a"] != "b" {
			t.Errorf("v1 详情 headers 异常: %s (%v)", got, err)
		}
	})
}

// TestGetAgentHTTPEventSchemas Agent 详情暴露 http_event_schemas 能力集（v2 契约 §3；
// 任务书 §4.3 旧 Agent「需升级」判定依据字段）。
func TestGetAgentHTTPEventSchemas(t *testing.T) {
	agentID := uuid.New()
	store := newFakeAdminStore()
	store.details[agentID] = &AgentDetail{
		Agent:            Agent{AgentID: agentID, Hostname: "web-prod-01"},
		HTTPEventSchemas: []int{1, HTTPEventSchemaV2},
	}
	mux := newAdminMux(NewHandler(store), injectPerms(PermAgentsView))

	rr := doAdmin(t, mux, http.MethodGet, "/api/v1/traffic/agents/"+agentID.String(), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var detail struct {
		HTTPEventSchemas []int `json:"http_event_schemas"`
	}
	decodeEnvelope(t, rr, &detail)
	if len(detail.HTTPEventSchemas) != 2 || detail.HTTPEventSchemas[0] != 1 || detail.HTTPEventSchemas[1] != 2 {
		t.Errorf("http_event_schemas 异常: %v", detail.HTTPEventSchemas)
	}
}
