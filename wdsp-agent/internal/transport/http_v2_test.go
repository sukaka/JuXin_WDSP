// PostHTTPV2 端点语义测试（v2 契约 §1/§3/§4：包络 schema_version=2、
// 202 accepted_count/duplicate_count 分账、400 invalid_records 索引定位、
// 计数一致性校验、注册/心跳 capabilities 声明与回执解析）。
package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
)

func testV2Records(n int) []events.HTTPRecordV2 {
	batch := events.NewHTTPBatchV2("a1", testRecords(n), events.SourceRef{Type: events.SourcePassiveHTTP1, Epoch: 1788250000})
	return batch.Records
}

// 202 分账：accepted_count/duplicate_count 解析；请求包络 schema_version=2；
// 记录线格式为契约 §2（event_id、headers 数组形态、body_quality 内嵌）。
func TestPostHTTPV2AcceptedDuplicate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/a1/http" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var env map[string]any
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			t.Errorf("请求体解析: %v", err)
		}
		if env["schema_version"] != float64(2) {
			t.Errorf("schema_version 应为 2: %v", env["schema_version"])
		}
		recs, _ := env["records"].([]any)
		if len(recs) != 3 {
			t.Errorf("records=%d", len(recs))
		}
		rec, _ := recs[0].(map[string]any)
		if rec["event_id"] == "" || rec["source_type"] != events.SourcePassiveHTTP1 {
			t.Errorf("v2 记录来源字段错误: %v", rec)
		}
		if rec["observed_http_version"] != events.HTTPVersion11 {
			t.Errorf("observed_http_version: %v", rec["observed_http_version"])
		}
		req, _ := rec["request"].(map[string]any)
		if _, ok := req["body_quality"].(map[string]any); !ok {
			t.Errorf("request.body_quality 缺失: %v", req)
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(events.HTTPV2Response{AcceptedCount: 2, DuplicateCount: 1})
	}))
	defer srv.Close()

	c := newClient(t, srv)
	c.SetCredential("cred")
	acc, dup, invalid, err := c.PostHTTPV2(context.Background(), "a1", testV2Records(3))
	if err != nil {
		t.Fatal(err)
	}
	if acc != 2 || dup != 1 {
		t.Fatalf("accepted/duplicate=%d/%d", acc, dup)
	}
	if invalid != nil {
		t.Fatalf("成功响应不应有 invalid_records: %+v", invalid)
	}
}

// 400 + invalid_records：索引与原因解析；错误仍可被 IsPermanent 判定。
func TestPostHTTPV2InvalidRecords(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{"code": "INVALID_ARGUMENT", "message": "批次含非法记录"},
			"invalid_records": []events.InvalidRecord{
				{Index: 1, Reason: "records[1]: event_id 非法"},
				{Index: 2, Reason: "records[2]: source_instance 缺失"},
			},
		})
	}))
	defer srv.Close()

	c := newClient(t, srv)
	c.SetCredential("cred")
	_, _, invalid, err := c.PostHTTPV2(context.Background(), "a1", testV2Records(3))
	if err == nil || !IsPermanent(err) {
		t.Fatalf("400 应为永久非法: %v", err)
	}
	if len(invalid) != 2 || invalid[0].Index != 1 || invalid[1].Index != 2 {
		t.Fatalf("invalid_records 解析错误: %+v", invalid)
	}
	if invalid[0].Reason == "" {
		t.Fatal("invalid_records 应携带原因")
	}
}

// 400 无 invalid_records（未协商/包络级拒绝）：invalid 为空，由调用方降级 v1。
func TestPostHTTPV2PermanentWithoutInvalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{"code": "INVALID_ARGUMENT", "message": "该 Agent 未协商 HTTP 事件 schema v2"},
		})
	}))
	defer srv.Close()

	c := newClient(t, srv)
	c.SetCredential("cred")
	_, _, invalid, err := c.PostHTTPV2(context.Background(), "a1", testV2Records(1))
	if err == nil || !IsPermanent(err) {
		t.Fatalf("400 应为永久非法: %v", err)
	}
	if len(invalid) != 0 {
		t.Fatalf("无 invalid_records 时应为空: %+v", invalid)
	}
}

// 计数一致性（契约 §4.3）：accepted+duplicate != len(records) 视为服务端协议错误。
func TestPostHTTPV2CountMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(events.HTTPV2Response{AcceptedCount: 1, DuplicateCount: 0})
	}))
	defer srv.Close()

	c := newClient(t, srv)
	c.SetCredential("cred")
	_, _, _, err := c.PostHTTPV2(context.Background(), "a1", testV2Records(3))
	if err == nil {
		t.Fatal("计数不符应报错")
	}
	if IsPermanent(err) {
		t.Fatal("计数不符为服务端协议错误，不应按永久非法（不重试原批）之外的语义丢弃")
	}
}

// 能力协商线格式（v2 契约 §3）：注册/心跳请求携带声明集，响应解析生效集；
// 旧服务端无 capabilities 响应字段 → nil（调用方按仅 v1 处理）。
func TestCapabilitiesNegotiationWireFormat(t *testing.T) {
	t.Run("heartbeat", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req HeartbeatRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("心跳请求解析: %v", err)
			}
			if req.Capabilities == nil ||
				len(req.Capabilities.HTTPEventSchemaVersions) != 2 ||
				req.Capabilities.HTTPEventSchemaVersions[0] != 1 ||
				req.Capabilities.HTTPEventSchemaVersions[1] != 2 {
				t.Errorf("心跳应声明 [1,2]: %+v", req.Capabilities)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"server_time": 1, "config_version": 1, "desired_state": "ENABLED",
				"heartbeat_interval_seconds": 15,
				"capabilities":               map[string]any{"http_event_schema_versions": []int{1, 2}},
			})
		}))
		defer srv.Close()

		c := newClient(t, srv)
		c.SetCredential("cred")
		resp, err := c.Heartbeat(context.Background(), "a1", HeartbeatRequest{
			Timestamp: 1, Status: "ONLINE", Capabilities: DeclaredCapabilities(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if !resp.Capabilities.HasSchemaVersion(2) || !resp.Capabilities.HasSchemaVersion(1) {
			t.Fatalf("生效集应含 v1+v2: %+v", resp.Capabilities)
		}
	})

	t.Run("enroll", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req EnrollRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("注册请求解析: %v", err)
			}
			if req.Capabilities == nil || !req.Capabilities.HasSchemaVersion(2) {
				t.Errorf("注册应声明 v2: %+v", req.Capabilities)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id": "a1", "credential": "cred", "heartbeat_interval_seconds": 15,
				"config_version": 1,
				"capabilities":   map[string]any{"http_event_schema_versions": []int{1}},
			})
		}))
		defer srv.Close()

		c := newClient(t, srv)
		resp, err := c.Enroll(context.Background(), EnrollRequest{
			EnrollmentToken: "wdt_x", Hostname: "h", Version: "test",
			Capabilities: DeclaredCapabilities(),
		})
		if err != nil {
			t.Fatal(err)
		}
		// 服务端仅支持 v1 时生效集为交集 {1}
		if resp.Capabilities.HasSchemaVersion(2) || !resp.Capabilities.HasSchemaVersion(1) {
			t.Fatalf("生效集应为交集 {{1}}: %+v", resp.Capabilities)
		}
	})

	t.Run("legacy server no capabilities field", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"server_time": 1, "config_version": 1, "desired_state": "ENABLED",
				"heartbeat_interval_seconds": 15,
			})
		}))
		defer srv.Close()

		c := newClient(t, srv)
		c.SetCredential("cred")
		resp, err := c.Heartbeat(context.Background(), "a1", HeartbeatRequest{
			Timestamp: 1, Status: "ONLINE", Capabilities: DeclaredCapabilities(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Capabilities != nil {
			t.Fatalf("旧服务端无回执字段应为 nil: %+v", resp.Capabilities)
		}
		if resp.Capabilities.HasSchemaVersion(2) {
			t.Fatal("nil 生效集不得判定为支持 v2")
		}
	})
}
