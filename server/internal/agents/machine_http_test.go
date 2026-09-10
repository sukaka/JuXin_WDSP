// machine_http_test.go HTTP 事件机器端点单测（Phase 3 契约 §3/§6）：
// 认证矩阵 / 校验 / 批量上限 / disabled 403 / 入库失败整体 500 / API 资产联动
// （fake DiscoveryUpserter 断言 method/模板化 URI 与去重；联动失败不阻断 202）。
package agents

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

// fakeDiscoveryUpserter API 资产联动入口 fake。
type fakeDiscoveryUpserter struct {
	inputs []apiassets.DiscoveryInput
	err    error
}

func (f *fakeDiscoveryUpserter) UpsertDiscovery(_ context.Context, in apiassets.DiscoveryInput) (*apiassets.Endpoint, error) {
	f.inputs = append(f.inputs, in)
	if f.err != nil {
		return nil, f.err
	}
	return &apiassets.Endpoint{}, nil
}

// httpRecordsJSON 序列化批量上报体。
func httpRecordsJSON(t *testing.T, recs ...HTTPRecord) string {
	t.Helper()
	raw, err := json.Marshal(HTTPRecordsRequest{Records: recs})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestHTTPEventsEndpoint 端点矩阵。
func TestHTTPEventsEndpoint(t *testing.T) {
	path := func(id uuid.UUID) string { return "/api/v1/agents/" + id.String() + "/http" }

	t.Run("正常 202 并触发资产联动", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		upserter := &fakeDiscoveryUpserter{}
		mux := newMachineMux(NewMachineHandler(store).SetDiscoveryUpserter(upserter))
		rec1 := validHTTPRecord()
		rec2 := validHTTPRecord() // 与 rec1 同端点 → 联动去重
		rec3 := validHTTPRecord()
		rec3.Request.URI = "/api/users/42" // 数字段 → 模板化
		rr := doMachine(t, mux, http.MethodPost, path(agentID),
			httpRecordsJSON(t, rec1, rec2, rec3), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"accepted":3`) {
			t.Errorf("accepted 应为 3: %s", rr.Body.String())
		}
		if len(store.insertedHTTP) != 3 {
			t.Fatalf("入库记录数 = %d, want 3", len(store.insertedHTTP))
		}
		// 资产联动：3 条记录 2 个去重端点
		if len(upserter.inputs) != 2 {
			t.Fatalf("联动调用数 = %d, want 2（去重）: %+v", len(upserter.inputs), upserter.inputs)
		}
		if upserter.inputs[0].Method != "POST" || upserter.inputs[0].PathTemplate != "/api/login" {
			t.Errorf("端点 1 异常: %+v", upserter.inputs[0])
		}
		if upserter.inputs[1].PathTemplate != "/api/users/{id}" {
			t.Errorf("URI 模板化异常（数字段应归一化为 {id}）: %+v", upserter.inputs[1])
		}
		for _, in := range upserter.inputs {
			if !in.IsAPI || in.Confidence != agentDiscoveryConfidence || in.Host != "api.example.com" {
				t.Errorf("联动输入异常: %+v", in)
			}
		}
	})

	t.Run("body_skipped_reason 合法枚举 202 并透传", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rec := validHTTPRecord()
		rec.Request.Body = ""
		rec.Request.BodySkippedReason = "content_type"
		rec.Response.Body = ""
		rec.Response.BodySkippedReason = "encoding"
		rr := doMachine(t, mux, http.MethodPost, path(agentID), httpRecordsJSON(t, rec), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
		}
		got := store.insertedHTTP[0]
		if got.Request.BodySkippedReason != "content_type" || got.Response.BodySkippedReason != "encoding" {
			t.Errorf("skipped_reason 未透传: %+v", got)
		}
	})

	t.Run("response null 记录 202", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rec := validHTTPRecord()
		rec.Response = nil
		rec.ResponseTS = nil
		rec.LatencyMS = nil
		rr := doMachine(t, mux, http.MethodPost, path(agentID), httpRecordsJSON(t, rec), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
		}
		if len(store.insertedHTTP) != 1 || store.insertedHTTP[0].Response != nil {
			t.Errorf("response null 记录未按原样入库: %+v", store.insertedHTTP)
		}
	})

	t.Run("联动失败不阻断 202（仅 Warn）", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		upserter := &fakeDiscoveryUpserter{err: errors.New("asset store down")}
		mux := newMachineMux(NewMachineHandler(store).SetDiscoveryUpserter(upserter))
		rr := doMachine(t, mux, http.MethodPost, path(agentID),
			httpRecordsJSON(t, validHTTPRecord()), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202（联动失败不得阻断入库响应）", rr.Code)
		}
		if len(store.insertedHTTP) != 1 {
			t.Error("联动失败不得影响入库")
		}
	})

	t.Run("联动配额超限不阻断 202", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		upserter := &fakeDiscoveryUpserter{err: apiassets.ErrLicenseQuotaExceeded}
		mux := newMachineMux(NewMachineHandler(store).SetDiscoveryUpserter(upserter))
		rr := doMachine(t, mux, http.MethodPost, path(agentID),
			httpRecordsJSON(t, validHTTPRecord()), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202", rr.Code)
		}
	})

	t.Run("未认证 401", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, path(agentID),
			httpRecordsJSON(t, validHTTPRecord()), "")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
	})

	t.Run("disabled 403（与 flows 一致）", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, true)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, path(agentID),
			httpRecordsJSON(t, validHTTPRecord()), cred)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rr.Code)
		}
		if len(store.insertedHTTP) != 0 {
			t.Error("disabled 批量不得入库")
		}
	})

	t.Run("超 100 条 400", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		recs := make([]HTTPRecord, MaxHTTPRecordsPerBatch+1)
		for i := range recs {
			recs[i] = validHTTPRecord()
		}
		rr := doMachine(t, mux, http.MethodPost, path(agentID), httpRecordsJSON(t, recs...), cred)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
		if len(store.insertedHTTP) != 0 {
			t.Error("超限批量不得入库")
		}
	})

	t.Run("记录非法 400（tls_visibility 密文）", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rec := validHTTPRecord()
		rec.TLSVisibility = "ENCRYPTED"
		rr := doMachine(t, mux, http.MethodPost, path(agentID), httpRecordsJSON(t, rec), cred)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("入库失败整体 500", func(t *testing.T) {
		store := newFakeMachineStore()
		store.httpInsertErr = errors.New("db down")
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		upserter := &fakeDiscoveryUpserter{}
		mux := newMachineMux(NewMachineHandler(store).SetDiscoveryUpserter(upserter))
		rr := doMachine(t, mux, http.MethodPost, path(agentID),
			httpRecordsJSON(t, validHTTPRecord()), cred)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rr.Code)
		}
		if len(upserter.inputs) != 0 {
			t.Error("入库失败不得触发资产联动")
		}
	})

	t.Run("空 records 400", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rr := doMachine(t, mux, http.MethodPost, path(agentID), `{"records":[]}`, cred)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("未知字段 400（fail-closed）", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		mux := newMachineMux(NewMachineHandler(store))
		rec := validHTTPRecord()
		body := strings.TrimSuffix(httpRecordsJSON(t, rec), `]}`) + `],"evil":1}`
		rr := doMachine(t, mux, http.MethodPost, path(agentID), body, cred)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})
}
