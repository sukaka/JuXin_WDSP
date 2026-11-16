// machine_http_v2_test.go HTTP 事件 schema v2 机器端点单测（契约
// docs/agents/WDSP_AGENT_HTTP_EVENT_V2_CONTRACT.md；任务书 P1-03 §4.1/§4.2，G0+G1）：
// 能力协商（注册/心跳）/ v2 批次幂等重放 / 混合重复计数 / 非法记录索引+原因整批拒绝 /
// 未协商 v2 准入拒绝 / v1 旧 schema 兼容 / 资产来源关系（含 Host 去重、GRPC 协议、
// UNASSIGNED/QUOTA_REJECTED/FAILED 状态）/ 管理端来源关系查询。
package agents

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

// validHTTPRecordV2 合法 v2 记录（含响应，COMPLETE）。
func validHTTPRecordV2() HTTPRecordV2 {
	respTS := 1788256800.156
	latency := int64(33)
	total := int64(42)
	return HTTPRecordV2{
		EventID:      "01J0EXAMPLE0000000000000000A",
		FlowID:       "a1-10.1.1.10-51234-10.1.2.20-8080-1788256800",
		RequestTS:    1788256800.123,
		ResponseTS:   &respTS,
		LatencyMS:    &latency,
		CollectionTS: 1788256800.130,
		SrcIP:        "10.1.1.10", SrcPort: 51234, DstIP: "10.1.2.20", DstPort: 8080,
		Direction:     "ingress",
		TLSVisibility: TLSPlaintext,

		SourceType:                SourceTypePassiveHTTP1,
		SourceInstance:            "sensor-eth0-a",
		SourceEpoch:               3,
		SourceCapabilitiesVersion: "caps-1",
		ObservedHTTPVersion:       HTTPVersion11,
		AssociationState:          AssocStateComplete,

		Request: HTTPRequestPartV2{
			Method: "POST", Scheme: "http", Host: "api.example.com", URI: "/api/login",
			Headers: HTTPHeaderValues{
				"content-type": {"application/json"},
				"set-cookie":   {"a=1", "b=2"}, // 重复值保序保留
			},
			Body: `{"user":"alice","password":"********"}`,
			BodyQuality: HTTPBodyQuality{
				CapturedBytes:     42,
				OriginalTotalSize: &total,
			},
		},
		Response: &HTTPResponsePartV2{
			Status:  200,
			Headers: HTTPHeaderValues{"content-type": {"application/json"}},
			Body:    `{"token":"********"}`,
			BodyQuality: HTTPBodyQuality{
				CapturedBytes:     31,
				OriginalTotalSize: &total,
			},
		},
	}
}

// httpRecordsV2JSON 序列化 v2 批量上报体。
func httpRecordsV2JSON(t *testing.T, recs ...HTTPRecordV2) string {
	t.Helper()
	raw, err := json.Marshal(HTTPRecordsRequestV2{SchemaVersion: HTTPEventSchemaV2, Records: recs})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// registerAgentV2 登记声明 v2 能力的 Agent，返回明文凭据。
func registerAgentV2(store *fakeMachineStore, agentID uuid.UUID) string {
	cred := registerAgent(store, agentID, false)
	store.agentsByHash[HashSecret(cred)].HTTPEventSchemas = []int{1, HTTPEventSchemaV2}
	return cred
}

type httpV2Accepted struct {
	AcceptedCount  int `json:"accepted_count"`
	DuplicateCount int `json:"duplicate_count"`
}

// ---------- 能力协商（契约 §3） ----------

// TestEnrollCapabilities 注册能力协商：声明 [1,2] 回执并入参落库；未声明回落 {1}；非法取值 400。
func TestEnrollCapabilities(t *testing.T) {
	token := "wdt_" + strings.Repeat("cd", 32)
	base := `{"enrollment_token":"` + token + `","hostname":"h","ip":"10.0.0.1"`

	t.Run("声明 v1+v2 回执生效集", func(t *testing.T) {
		store := newFakeMachineStore()
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/enroll",
			base+`,"capabilities":{"http_event_schema_versions":[1,2]}}`, "")
		if rr.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body=%s)", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"http_event_schema_versions":[1,2]`) {
			t.Errorf("回执缺少生效能力集: %s", rr.Body.String())
		}
		if store.enrollIn == nil || len(store.enrollIn.HTTPEventSchemas) != 2 {
			t.Errorf("生效集未落库: %+v", store.enrollIn)
		}
	})
	t.Run("未声明回落 {1}", func(t *testing.T) {
		store := newFakeMachineStore()
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/enroll", base+`}`, "")
		if rr.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body=%s)", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"http_event_schema_versions":[1]`) {
			t.Errorf("未声明应回执 {1}: %s", rr.Body.String())
		}
	})
	t.Run("非法取值 400 且不触库", func(t *testing.T) {
		store := newFakeMachineStore()
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/enroll",
			base+`,"capabilities":{"http_event_schema_versions":[1,7]}}`, "")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body=%s)", rr.Code, rr.Body.String())
		}
		if store.enrollIn != nil {
			t.Error("能力声明非法不应触库")
		}
	})
}

// TestHeartbeatCapabilities 心跳能力协商：携带时更新生效集并回执；未携带回执当前生效集。
func TestHeartbeatCapabilities(t *testing.T) {
	t.Run("携带声明更新并回执", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/heartbeat",
			`{"timestamp":1788256800,"status":"ONLINE","capabilities":{"http_event_schema_versions":[2]}}`, cred)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"http_event_schema_versions":[2]`) {
			t.Errorf("回执异常: %s", rr.Body.String())
		}
		if len(store.heartbeatSchemas) != 1 || store.heartbeatSchemas[0] != 2 {
			t.Errorf("生效集未透传仓储: %v", store.heartbeatSchemas)
		}
	})
	t.Run("未携带保持既有生效集", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgentV2(store, agentID)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/heartbeat",
			`{"timestamp":1788256800,"status":"ONLINE"}`, cred)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), `"http_event_schema_versions":[1,2]`) {
			t.Errorf("应回执既有生效集: %s", rr.Body.String())
		}
		if store.heartbeatSchemas != nil {
			t.Errorf("未声明 capabilities 不应更新能力集: %v", store.heartbeatSchemas)
		}
	})
	t.Run("声明非法 400", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/heartbeat",
			`{"timestamp":1788256800,"status":"ONLINE","capabilities":{"http_event_schema_versions":[9]}}`, cred)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body=%s)", rr.Code, rr.Body.String())
		}
	})
}

// ---------- v2 批次语义（契约 §4） ----------

// TestHTTPEventsV2Batch v2 批次：202 accepted_count/duplicate_count；幂等重放；混合重复计数。
func TestHTTPEventsV2Batch(t *testing.T) {
	path := func(id uuid.UUID) string { return "/api/v1/agents/" + id.String() + "/http" }

	t.Run("正常 202 全量接受", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgentV2(store, agentID)
		mux := newMachineMux(NewMachineHandler(store))
		rec2 := validHTTPRecordV2()
		rec2.EventID = "01J0EXAMPLE0000000000000000B"
		rr := doMachine(t, mux, http.MethodPost, path(agentID), httpRecordsV2JSON(t, validHTTPRecordV2(), rec2), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
		}
		var resp httpV2Accepted
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.AcceptedCount != 2 || resp.DuplicateCount != 0 {
			t.Errorf("计数 = %+v, want accepted=2 duplicate=0", resp)
		}
		if len(store.insertedHTTPV2) != 2 {
			t.Fatalf("入库记录数 = %d, want 2", len(store.insertedHTTPV2))
		}
	})

	t.Run("幂等重放：event_id 不变全部计重复", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgentV2(store, agentID)
		mux := newMachineMux(NewMachineHandler(store))
		body := httpRecordsV2JSON(t, validHTTPRecordV2())
		for round, want := range []httpV2Accepted{{AcceptedCount: 1}, {AcceptedCount: 0, DuplicateCount: 1}} {
			rr := doMachine(t, mux, http.MethodPost, path(agentID), body, cred)
			if rr.Code != http.StatusAccepted {
				t.Fatalf("round %d status = %d, want 202 (body=%s)", round, rr.Code, rr.Body.String())
			}
			var resp httpV2Accepted
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp != want {
				t.Errorf("round %d 计数 = %+v, want %+v", round, resp, want)
			}
		}
		if len(store.insertedHTTPV2) != 1 {
			t.Errorf("重复事件重复入库: %d 条", len(store.insertedHTTPV2))
		}
	})

	t.Run("混合重复批次计数（批内重复 + 历史重复）", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgentV2(store, agentID)
		mux := newMachineMux(NewMachineHandler(store))
		new1 := validHTTPRecordV2() // 历史已有（event_id A）
		new2 := validHTTPRecordV2()
		new2.EventID = "01J0EXAMPLE0000000000000000C"
		dupInBatch := validHTTPRecordV2()
		dupInBatch.EventID = new2.EventID // 批内重复
		if _, _, err := store.InsertHTTPEventsV2(t.Context(), agentID, []HTTPRecordV2{new1}, mustNow()); err != nil {
			t.Fatal(err)
		}
		rr := doMachine(t, mux, http.MethodPost, path(agentID),
			httpRecordsV2JSON(t, new1, new2, dupInBatch), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
		}
		var resp httpV2Accepted
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.AcceptedCount != 1 || resp.DuplicateCount != 2 {
			t.Errorf("计数 = %+v, want accepted=1 duplicate=2", resp)
		}
		if resp.AcceptedCount+resp.DuplicateCount != 3 {
			t.Errorf("计数与输入条数不符: %+v", resp)
		}
	})

	t.Run("非法记录返回索引+原因且整批不入库", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgentV2(store, agentID)
		mux := newMachineMux(NewMachineHandler(store))
		bad := validHTTPRecordV2()
		bad.EventID = "bad id with spaces!!"
		rr := doMachine(t, mux, http.MethodPost, path(agentID),
			httpRecordsV2JSON(t, validHTTPRecordV2(), bad), cred)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body=%s)", rr.Code, rr.Body.String())
		}
		var resp struct {
			InvalidRecords []InvalidRecord `json:"invalid_records"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v (body=%s)", err, rr.Body.String())
		}
		if len(resp.InvalidRecords) != 1 || resp.InvalidRecords[0].Index != 1 ||
			!strings.Contains(resp.InvalidRecords[0].Reason, "event_id") {
			t.Errorf("invalid_records 异常: %+v", resp.InvalidRecords)
		}
		if len(store.insertedHTTPV2) != 0 {
			t.Error("含非法记录的批次不得部分提交")
		}
	})

	t.Run("多条非法记录全部返回", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgentV2(store, agentID)
		mux := newMachineMux(NewMachineHandler(store))
		bad1 := validHTTPRecordV2()
		bad1.EventID = ""
		bad2 := validHTTPRecordV2()
		bad2.AssociationState = AssocStateRequestOnly
		bad2.AssociationReason = "" // 非 COMPLETE 必须给原因
		rr := doMachine(t, mux, http.MethodPost, path(agentID),
			httpRecordsV2JSON(t, bad1, validHTTPRecordV2(), bad2), cred)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
		var resp struct {
			InvalidRecords []InvalidRecord `json:"invalid_records"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.InvalidRecords) != 2 || resp.InvalidRecords[0].Index != 0 || resp.InvalidRecords[1].Index != 2 {
			t.Errorf("应返回全部非法记录索引: %+v", resp.InvalidRecords)
		}
	})

	t.Run("未协商 v2 的 Agent 发送 v2 批次 400（永久失败）", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false) // 仅 v1
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, path(agentID), httpRecordsV2JSON(t, validHTTPRecordV2()), cred)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body=%s)", rr.Code, rr.Body.String())
		}
		if len(store.insertedHTTPV2) != 0 {
			t.Error("未协商 v2 的批次不得入库")
		}
	})

	t.Run("不支持 schema_version 400", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, path(agentID), `{"schema_version":3,"records":[]}`, cred)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body=%s)", rr.Code, rr.Body.String())
		}
	})

	t.Run("v1 显式 schema_version=1 旧行为不变", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		body := `{"schema_version":1,"records":[` + mustV1JSON(t) + `]}`
		rr := doMachine(t, mux, http.MethodPost, path(agentID), body, cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"accepted":1`) {
			t.Errorf("v1 响应形状不变: %s", rr.Body.String())
		}
	})

	t.Run("v2 入库失败整体 500", func(t *testing.T) {
		store := newFakeMachineStore()
		store.httpV2InsertErr = errors.New("db down")
		agentID := uuid.New()
		cred := registerAgentV2(store, agentID)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, path(agentID), httpRecordsV2JSON(t, validHTTPRecordV2()), cred)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 (body=%s)", rr.Code, rr.Body.String())
		}
	})
}

// mustV1JSON 序列化单条 v1 记录。
func mustV1JSON(t *testing.T) string {
	t.Helper()
	raw, err := json.Marshal(validHTTPRecord())
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func mustNow() time.Time { return time.Unix(1788256800, 0).UTC() }

// ---------- 资产来源关系（契约 §5） ----------

// TestHTTPEventsV2AssetSources 来源关系：绑定记录 LINKED 且 gRPC 不写死 REST；
// 未绑定 UNASSIGNED 不 upsert 端点；配额/失败状态落行；去重键含 Host；重复事件不联动。
func TestHTTPEventsV2AssetSources(t *testing.T) {
	path := func(id uuid.UUID) string { return "/api/v1/agents/" + id.String() + "/http" }
	bindingID := uuid.New().String()
	bindingVer := int64(7)

	withBinding := func(rec HTTPRecordV2) HTTPRecordV2 {
		rec.ApplicationBindingID = &bindingID
		rec.BindingVersion = &bindingVer
		return rec
	}

	t.Run("绑定记录 LINKED 且来源字段落行", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgentV2(store, agentID)
		upserter := &fakeDiscoveryUpserter{}
		mux := newMachineMux(NewMachineHandler(store).SetDiscoveryUpserter(upserter))
		rr := doMachine(t, mux, http.MethodPost, path(agentID), httpRecordsV2JSON(t, withBinding(validHTTPRecordV2())), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
		}
		if len(store.assetSources) != 1 {
			t.Fatalf("来源关系行数 = %d, want 1", len(store.assetSources))
		}
		src := store.assetSources[0]
		if src.State != AssetLinkLinked || src.EndpointID == nil {
			t.Errorf("来源关系状态异常: %+v", src)
		}
		if src.SourceType != SourceTypePassiveHTTP1 || src.SourceInstance != "sensor-eth0-a" || src.SourceEpoch != 3 {
			t.Errorf("来源三元组未落行: %+v", src)
		}
		if src.ApplicationBindingID == nil || src.BindingVersion == nil || *src.BindingVersion != 7 {
			t.Errorf("绑定字段未落行: %+v", src)
		}
		if len(upserter.inputs) != 1 || upserter.inputs[0].ProtocolType != "REST" {
			t.Errorf("端点 upsert 异常: %+v", upserter.inputs)
		}
	})

	t.Run("gRPC 记录协议类型 GRPC（不写死 REST）", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgentV2(store, agentID)
		upserter := &fakeDiscoveryUpserter{}
		mux := newMachineMux(NewMachineHandler(store).SetDiscoveryUpserter(upserter))
		rec := withBinding(validHTTPRecordV2())
		grpcStatus := 0
		rec.GRPC = &GRPCMeta{Service: "pkg.UserService", Method: "GetUser", GRPCStatus: &grpcStatus, StreamState: GRPCStreamClosed}
		rec.Request.URI = "/pkg.UserService/GetUser"
		rec.ObservedHTTPVersion = HTTPVersion2
		rr := doMachine(t, mux, http.MethodPost, path(agentID), httpRecordsV2JSON(t, rec), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
		}
		if len(upserter.inputs) != 1 || upserter.inputs[0].ProtocolType != "GRPC" {
			t.Errorf("gRPC 端点协议类型应为 GRPC: %+v", upserter.inputs)
		}
	})

	t.Run("未绑定 v2 记录 UNASSIGNED 且不 upsert 端点", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgentV2(store, agentID)
		upserter := &fakeDiscoveryUpserter{}
		mux := newMachineMux(NewMachineHandler(store).SetDiscoveryUpserter(upserter))
		rr := doMachine(t, mux, http.MethodPost, path(agentID), httpRecordsV2JSON(t, validHTTPRecordV2()), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202", rr.Code)
		}
		if len(upserter.inputs) != 0 {
			t.Errorf("未绑定记录不得 upsert 端点: %+v", upserter.inputs)
		}
		if len(store.assetSources) != 1 || store.assetSources[0].State != AssetLinkUnassigned ||
			store.assetSources[0].EndpointID != nil {
			t.Errorf("应落 UNASSIGNED 行: %+v", store.assetSources)
		}
	})

	t.Run("配额拒绝落 QUOTA_REJECTED 行（不阻断 202）", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgentV2(store, agentID)
		upserter := &fakeDiscoveryUpserter{err: apiassets.ErrLicenseQuotaExceeded}
		mux := newMachineMux(NewMachineHandler(store).SetDiscoveryUpserter(upserter))
		rr := doMachine(t, mux, http.MethodPost, path(agentID), httpRecordsV2JSON(t, withBinding(validHTTPRecordV2())), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202", rr.Code)
		}
		if len(store.assetSources) != 1 || store.assetSources[0].State != AssetLinkQuotaRejected {
			t.Errorf("应落 QUOTA_REJECTED 行: %+v", store.assetSources)
		}
	})

	t.Run("关联失败落 FAILED 行", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgentV2(store, agentID)
		upserter := &fakeDiscoveryUpserter{err: errors.New("asset store down")}
		mux := newMachineMux(NewMachineHandler(store).SetDiscoveryUpserter(upserter))
		rr := doMachine(t, mux, http.MethodPost, path(agentID), httpRecordsV2JSON(t, withBinding(validHTTPRecordV2())), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202", rr.Code)
		}
		if len(store.assetSources) != 1 || store.assetSources[0].State != AssetLinkFailed ||
			store.assetSources[0].LastError == "" {
			t.Errorf("应落 FAILED 行: %+v", store.assetSources)
		}
	})

	t.Run("去重键含 Host：同 method+path 不同 Host 各自 upsert", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgentV2(store, agentID)
		upserter := &fakeDiscoveryUpserter{}
		mux := newMachineMux(NewMachineHandler(store).SetDiscoveryUpserter(upserter))
		recA := withBinding(validHTTPRecordV2())
		recB := withBinding(validHTTPRecordV2())
		recB.EventID = "01J0EXAMPLE0000000000000000D"
		recB.Request.Host = "other.example.com"
		rr := doMachine(t, mux, http.MethodPost, path(agentID), httpRecordsV2JSON(t, recA, recB), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
		}
		if len(upserter.inputs) != 2 {
			t.Errorf("不同 Host 不得合并: upsert %d 次, want 2", len(upserter.inputs))
		}
		if len(upserter.inputs) == 2 &&
			(upserter.inputs[0].Host != "api.example.com" || upserter.inputs[1].Host != "other.example.com") {
			t.Errorf("Host 作用域未传入资产 upsert: %+v", upserter.inputs)
		}
		if len(store.assetSources) != 2 {
			t.Errorf("来源关系应两行: %+v", store.assetSources)
		}
	})

	t.Run("去重键含协议：同 Host/method/path 的 REST 与 GRPC 各自 upsert", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgentV2(store, agentID)
		upserter := &fakeDiscoveryUpserter{}
		mux := newMachineMux(NewMachineHandler(store).SetDiscoveryUpserter(upserter))
		rest := withBinding(validHTTPRecordV2())
		grpc := withBinding(validHTTPRecordV2())
		grpc.EventID = "01J0EXAMPLE0000000000000000E"
		grpc.GRPC = &GRPCMeta{Service: "pkg.UserService", Method: "GetUser", StreamState: GRPCStreamClosed}
		grpc.ObservedHTTPVersion = HTTPVersion2
		rr := doMachine(t, mux, http.MethodPost, path(agentID), httpRecordsV2JSON(t, rest, grpc), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
		}
		if len(upserter.inputs) != 2 || upserter.inputs[0].ProtocolType != "REST" || upserter.inputs[1].ProtocolType != "GRPC" {
			t.Errorf("REST 与 GRPC 不得合并: %+v", upserter.inputs)
		}
	})

	t.Run("去重键含绑定作用域：同 Host/method/path 的不同绑定各自 upsert", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgentV2(store, agentID)
		upserter := &fakeDiscoveryUpserter{}
		mux := newMachineMux(NewMachineHandler(store).SetDiscoveryUpserter(upserter))
		bindingA, bindingB := uuid.New().String(), uuid.New().String()
		versionA, versionB := int64(1), int64(2)
		recA := validHTTPRecordV2()
		recA.ApplicationBindingID, recA.BindingVersion = &bindingA, &versionA
		recB := validHTTPRecordV2()
		recB.EventID = "01J0EXAMPLE0000000000000000F"
		recB.ApplicationBindingID, recB.BindingVersion = &bindingB, &versionB
		rr := doMachine(t, mux, http.MethodPost, path(agentID), httpRecordsV2JSON(t, recA, recB), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
		}
		if len(upserter.inputs) != 2 {
			t.Fatalf("不同绑定不得合并: upsert %d 次, want 2", len(upserter.inputs))
		}
		if upserter.inputs[0].ApplicationBindingID == nil || upserter.inputs[1].ApplicationBindingID == nil ||
			*upserter.inputs[0].ApplicationBindingID == *upserter.inputs[1].ApplicationBindingID {
			t.Errorf("绑定作用域未参与端点键: %+v", upserter.inputs)
		}
	})

	t.Run("重复事件不触发资产联动（不扩大资产计数）", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgentV2(store, agentID)
		upserter := &fakeDiscoveryUpserter{}
		mux := newMachineMux(NewMachineHandler(store).SetDiscoveryUpserter(upserter))
		body := httpRecordsV2JSON(t, withBinding(validHTTPRecordV2()))
		for i := 0; i < 2; i++ {
			rr := doMachine(t, mux, http.MethodPost, path(agentID), body, cred)
			if rr.Code != http.StatusAccepted {
				t.Fatalf("round %d status = %d", i, rr.Code)
			}
		}
		if len(upserter.inputs) != 1 {
			t.Errorf("重复重放不应重复 upsert: %d 次", len(upserter.inputs))
		}
		if len(store.assetSources) != 1 {
			t.Errorf("重复重放不应重复落来源行: %d 行", len(store.assetSources))
		}
	})
}

// TestHTTPEventsV2AssetClassification v2 资产联动按请求/响应可见证据分类，
// 不再对已绑定事件统一写死 true/0.8；v1 兼容口径由 machine_http_test.go 覆盖。
func TestHTTPEventsV2AssetClassification(t *testing.T) {
	path := func(id uuid.UUID) string { return "/api/v1/agents/" + id.String() + "/http" }
	bindingID := uuid.New().String()
	bindingVer := int64(7)

	run := func(t *testing.T, rec HTTPRecordV2) apiassets.DiscoveryInput {
		t.Helper()
		rec.ApplicationBindingID = &bindingID
		rec.BindingVersion = &bindingVer
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgentV2(store, agentID)
		upserter := &fakeDiscoveryUpserter{}
		mux := newMachineMux(NewMachineHandler(store).SetDiscoveryUpserter(upserter))
		rr := doMachine(t, mux, http.MethodPost, path(agentID), httpRecordsV2JSON(t, rec), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
		}
		if len(upserter.inputs) != 1 {
			t.Fatalf("端点 upsert 次数 = %d, want 1: %+v", len(upserter.inputs), upserter.inputs)
		}
		return upserter.inputs[0]
	}

	t.Run("JSON 请求与响应按证据分类", func(t *testing.T) {
		got := run(t, validHTTPRecordV2())
		if !got.IsAPI || got.Confidence <= 0.50 || got.Confidence >= 1 {
			t.Fatalf("JSON API 分类异常: %+v", got)
		}
	})

	t.Run("普通 HTML 页面不再固定登记为高置信 API", func(t *testing.T) {
		rec := validHTTPRecordV2()
		rec.Request.Method = "GET"
		rec.Request.URI = "/docs"
		rec.Request.Headers = HTTPHeaderValues{"content-type": {"text/html"}}
		rec.Request.Body = ""
		rec.Request.BodyQuality = HTTPBodyQuality{}
		rec.Response.Headers = HTTPHeaderValues{"content-type": {"text/html"}}
		rec.Response.Body = ""
		rec.Response.BodyQuality = HTTPBodyQuality{}
		got := run(t, rec)
		if got.IsAPI || got.Confidence != 0 {
			t.Fatalf("HTML 页面被误登记为 API: %+v", got)
		}
	})

	t.Run("单向 Nginx 源缺响应不作负向推断", func(t *testing.T) {
		rec := validHTTPRecordV2()
		rec.EventID = "01J0EXAMPLE0000000000000000B"
		rec.SourceType = SourceTypeNginxMirror
		rec.TLSVisibility = TLSDecrypted
		rec.Request.Method = "GET"
		rec.Request.URI = "/v1/ping"
		rec.Request.Headers = HTTPHeaderValues{"content-type": {"application/json"}}
		rec.Request.Body = ""
		rec.Request.BodyQuality = HTTPBodyQuality{}
		rec.Response = nil
		rec.ResponseTS = nil
		rec.LatencyMS = nil
		rec.AssociationState = AssocStateRequestOnly
		rec.AssociationReason = AssocReasonSourceRequestOnly
		got := run(t, rec)
		if !got.IsAPI || got.Confidence != 0.55 {
			t.Fatalf("请求侧 JSON 证据被响应缺失压低: %+v", got)
		}
	})

	t.Run("Envoy 响应 JSON 相比单向源提高置信度", func(t *testing.T) {
		rec := validHTTPRecordV2()
		rec.EventID = "01J0EXAMPLE0000000000000000C"
		rec.SourceType = SourceTypeEnvoyTap
		rec.Request.Method = "GET"
		rec.Request.URI = "/v1/ping"
		rec.Request.Headers = HTTPHeaderValues{"content-type": {"application/json"}}
		rec.Request.Body = ""
		rec.Request.BodyQuality = HTTPBodyQuality{}
		rec.Response.Body = ""
		rec.Response.BodyQuality = HTTPBodyQuality{}
		got := run(t, rec)
		if !got.IsAPI || got.Confidence <= 0.35 {
			t.Fatalf("响应 JSON 未提高置信度: %+v", got)
		}
	})

	t.Run("gRPC 可信元数据为强 API 证据", func(t *testing.T) {
		rec := validHTTPRecordV2()
		rec.EventID = "01J0EXAMPLE0000000000000000D"
		rec.SourceType = SourceTypeEnvoyTap
		rec.ObservedHTTPVersion = HTTPVersion2
		rec.Request.Method = "POST"
		rec.Request.URI = "/pkg.UserService/GetUser"
		rec.Request.Headers = HTTPHeaderValues{"content-type": {"application/grpc"}}
		rec.Request.Body = ""
		rec.Request.BodyQuality = HTTPBodyQuality{}
		rec.Response.Headers = HTTPHeaderValues{"content-type": {"application/grpc"}}
		rec.Response.Body = ""
		rec.Response.BodyQuality = HTTPBodyQuality{}
		grpcStatus := 0
		rec.GRPC = &GRPCMeta{Service: "pkg.UserService", Method: "GetUser", GRPCStatus: &grpcStatus, StreamState: GRPCStreamClosed}
		got := run(t, rec)
		if got.ProtocolType != "GRPC" || !got.IsAPI || got.Confidence < 0.90 {
			t.Fatalf("gRPC 分类异常: %+v", got)
		}
	})
}

// TestHTTPEventsV2AssetClassificationPersisted v2 分类证据随来源关系持久化，
// 供单个 API 详细导出解释识别依据；历史行不回填。
func TestHTTPEventsV2AssetClassificationPersisted(t *testing.T) {
	store := newFakeMachineStore()
	agentID := uuid.New()
	cred := registerAgentV2(store, agentID)
	upserter := &fakeDiscoveryUpserter{}
	mux := newMachineMux(NewMachineHandler(store).SetDiscoveryUpserter(upserter))
	rec := validHTTPRecordV2()
	bindingID := uuid.New().String()
	bindingVer := int64(7)
	rec.ApplicationBindingID = &bindingID
	rec.BindingVersion = &bindingVer
	rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/http",
		httpRecordsV2JSON(t, rec), cred)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
	}
	if len(store.assetSources) != 1 {
		t.Fatalf("来源关系行数 = %d, want 1", len(store.assetSources))
	}
	classification := store.assetSources[0].Classification
	if classification == nil {
		t.Fatal("v2 来源关系缺少分类证据")
	}
	if !classification.IsAPI || classification.Confidence <= 0.50 || classification.Level != "CONFIRMED_API" {
		t.Fatalf("v2 分类证据异常: %+v", classification)
	}
	if len(classification.Signals) == 0 || classification.ClassifiedAt.IsZero() {
		t.Fatalf("v2 分类信号/时间未持久化: %+v", classification)
	}
}

// ---------- v2 校验矩阵（契约 §2） ----------

// TestHTTPRecordV2Validate v2 字段校验矩阵。
func TestHTTPRecordV2Validate(t *testing.T) {
	ok := func(rec HTTPRecordV2) bool {
		return len((&HTTPRecordsRequestV2{SchemaVersion: HTTPEventSchemaV2, Records: []HTTPRecordV2{rec}}).Validate()) == 0
	}
	t.Run("基线合法", func(t *testing.T) {
		if !ok(validHTTPRecordV2()) {
			t.Fatal("基线记录应合法")
		}
	})
	cases := []struct {
		name   string
		mutate func(*HTTPRecordV2)
	}{
		{"event_id 空", func(r *HTTPRecordV2) { r.EventID = "" }},
		{"event_id 非法字符", func(r *HTTPRecordV2) { r.EventID = "has space" }},
		{"event_id 超长", func(r *HTTPRecordV2) { r.EventID = "a" + strings.Repeat("b", 128) }},
		{"source_type 非法", func(r *HTTPRecordV2) { r.SourceType = "PCAP" }},
		{"source_instance 空", func(r *HTTPRecordV2) { r.SourceInstance = " " }},
		{"source_epoch 负", func(r *HTTPRecordV2) { r.SourceEpoch = -1 }},
		{"observed 非法", func(r *HTTPRecordV2) { r.ObservedHTTPVersion = "2.0" }},
		{"original 非法", func(r *HTTPRecordV2) { v := "9"; r.OriginalHTTPVersion = &v }},
		{"tls_visibility v1 枚举 ENCRYPTED 拒绝", func(r *HTTPRecordV2) { r.TLSVisibility = "ENCRYPTED" }},
		{"association_state 非法", func(r *HTTPRecordV2) { r.AssociationState = "GUESSED" }},
		{"COMPLETE 携带原因", func(r *HTTPRecordV2) { r.AssociationReason = AssocReasonTimeout }},
		{"REQUEST_ONLY 缺原因", func(r *HTTPRecordV2) {
			r.AssociationState = AssocStateRequestOnly
			r.AssociationReason = ""
			r.Response = nil
			r.ResponseTS = nil
			r.LatencyMS = nil
		}},
		{"response null 自称 COMPLETE", func(r *HTTPRecordV2) {
			r.Response = nil
			r.ResponseTS = nil
			r.LatencyMS = nil
		}},
		{"绑定字段不成对", func(r *HTTPRecordV2) { v := int64(1); r.BindingVersion = &v }},
		{"binding_id 非 UUID", func(r *HTTPRecordV2) {
			id := "not-uuid"
			v := int64(1)
			r.ApplicationBindingID = &id
			r.BindingVersion = &v
		}},
		{"collection_ts 非法", func(r *HTTPRecordV2) { r.CollectionTS = 0 }},
		{"headers 空值数组", func(r *HTTPRecordV2) { r.Request.Headers["x-empty"] = []string{} }},
		{"truncated 且 original_total_size 小于 captured", func(r *HTTPRecordV2) {
			orig := int64(1)
			r.Request.BodyQuality.Truncated = true
			r.Request.BodyQuality.CapturedBytes = 4
			r.Request.BodyQuality.OriginalTotalSize = &orig
		}},
		{"skipped 但 captured 非零", func(r *HTTPRecordV2) {
			r.Request.BodyQuality.SkippedReason = SkipReasonContentType
		}},
		{"grpc_status 越界", func(r *HTTPRecordV2) { s := 17; r.GRPC = &GRPCMeta{GRPCStatus: &s, StreamState: GRPCStreamClosed} }},
		{"grpc stream_state 非法", func(r *HTTPRecordV2) { r.GRPC = &GRPCMeta{StreamState: "HALF"} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := validHTTPRecordV2()
			c.mutate(&rec)
			if ok(rec) {
				t.Errorf("%s 应被拒绝", c.name)
			}
		})
	}
	t.Run("DECRYPTED/UNKNOWN 与合法变体接受", func(t *testing.T) {
		rec := validHTTPRecordV2()
		rec.TLSVisibility = TLSDecrypted
		if !ok(rec) {
			t.Error("DECRYPTED 应被接受（v2）")
		}
		rec2 := validHTTPRecordV2()
		rec2.Response = nil
		rec2.ResponseTS = nil
		rec2.LatencyMS = nil
		rec2.AssociationState = AssocStateRequestOnly
		rec2.AssociationReason = AssocReasonSourceRequestOnly
		if !ok(rec2) {
			t.Error("REQUEST_ONLY + SOURCE_REQUEST_ONLY 应被接受")
		}
	})
	t.Run("truncated 且 original_total_size=null 接受（V1.1：原始总大小未知）", func(t *testing.T) {
		rec := validHTTPRecordV2()
		rec.Request.BodyQuality.Truncated = true
		rec.Request.BodyQuality.OriginalTotalSize = nil
		if !ok(rec) {
			t.Error("truncated=true + original_total_size=null（未知）应被接受（契约 V1.1）")
		}
	})
}

// ---------- 管理端来源关系查询（契约 §5.4） ----------

// TestListHTTPAssetSources 管理端：state 过滤透传/非法 state 400/信封 {items,total}。
func TestListHTTPAssetSources(t *testing.T) {
	agentID := uuid.New()
	base := "/api/v1/traffic/agents/" + agentID.String() + "/http-asset-sources"
	newMux := func(store *fakeAdminStore) *http.ServeMux {
		store.details[agentID] = &AgentDetail{Agent: Agent{AgentID: agentID}}
		return newAdminMux(NewHandler(store).SetAudits(&spyAudits{}), injectPerms(PermAgentsView))
	}

	t.Run("正常 200 信封", func(t *testing.T) {
		store := newFakeAdminStore()
		store.assetSources = []HTTPAssetSourceRow{{ID: 1, AgentID: agentID, AssociationState: AssetLinkLinked}}
		mux := newMux(store)
		rr := doAdmin(t, mux, http.MethodGet, base+"?state=LINKED", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}
		if store.assetSourceFilter.State != AssetLinkLinked {
			t.Errorf("state 过滤未透传: %+v", store.assetSourceFilter)
		}
		if !strings.Contains(rr.Body.String(), `"total":1`) {
			t.Errorf("信封异常: %s", rr.Body.String())
		}
	})
	t.Run("非法 state 400", func(t *testing.T) {
		store := newFakeAdminStore()
		mux := newMux(store)
		rr := doAdmin(t, mux, http.MethodGet, base+"?state=GUESSED", "")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})
}
