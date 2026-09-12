// http_admin_test.go HTTP 事件管理端点单测（Phase 3 契约 §6）：
// 分页 + host/method 过滤透传 / 单条全量 / 404 / 统一信封 / view 权限。
// 响应记录为契约 §3 嵌套结构（+顶层 id/agent_id）；列表项 headers 空对象、
// body 空串、截断标志保留；详情全量。
package agents

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

// floatEq Unix 秒浮点近似比较（response_ts 派生值可能有 1 ulp 尾差）。
func floatEq(a, b float64) bool {
	const eps = 1e-6
	d := a - b
	return d > -eps && d < eps
}

// nestedHTTPEvent 测试侧嵌套记录解码结构（与契约 §3 对齐）。
type nestedHTTPEvent struct {
	ID            int64    `json:"id"`
	AgentID       string   `json:"agent_id"`
	FlowID        string   `json:"flow_id"`
	RequestTS     float64  `json:"request_ts"`
	ResponseTS    *float64 `json:"response_ts"`
	LatencyMS     *int64   `json:"latency_ms"`
	SrcIP         string   `json:"src_ip"`
	SrcPort       int      `json:"src_port"`
	DstIP         string   `json:"dst_ip"`
	DstPort       int      `json:"dst_port"`
	Direction     string   `json:"direction"`
	TLSVisibility string   `json:"tls_visibility"`
	Request       struct {
		Method            string            `json:"method"`
		Scheme            string            `json:"scheme"`
		Host              string            `json:"host"`
		URI               string            `json:"uri"`
		Headers           map[string]string `json:"headers"`
		Body              string            `json:"body"`
		BodyTruncated     bool              `json:"body_truncated"`
		OriginalBodySize  int64             `json:"original_body_size"`
		BodySkippedReason string            `json:"body_skipped_reason"`
	} `json:"request"`
	Response *struct {
		Status            int               `json:"status"`
		Headers           map[string]string `json:"headers"`
		Body              string            `json:"body"`
		BodyTruncated     bool              `json:"body_truncated"`
		OriginalBodySize  int64             `json:"original_body_size"`
		BodySkippedReason string            `json:"body_skipped_reason"`
	} `json:"response"`
}

// TestListHTTPEvents 列表：200 信封 {items,total}，嵌套结构轻量项；过滤透传仓储。
func TestListHTTPEvents(t *testing.T) {
	agentID := uuid.New()
	newMux := func(store *fakeAdminStore) *http.ServeMux {
		store.details[agentID] = &AgentDetail{Agent: Agent{AgentID: agentID}}
		h := NewHandler(store).SetAudits(&spyAudits{})
		return newAdminMux(h, injectPerms(PermAgentsView))
	}
	base := "/api/v1/traffic/agents/" + agentID.String() + "/http-events"

	t.Run("默认分页 200（嵌套轻量项）", func(t *testing.T) {
		store := newFakeAdminStore()
		status := 200
		latency := 33
		store.httpEvents = []HTTPEventRow{
			{ID: 2, AgentID: agentID, Method: "POST", Scheme: "http", Host: "api.example.com", URI: "/api/login",
				FlowID: "f1", Direction: "ingress", TLSVisibility: "PLAINTEXT",
				SrcIP: "10.1.1.10", SrcPort: 51234, DstIP: "10.1.2.20", DstPort: 8080,
				Status: &status, LatencyMS: &latency,
				ReqTruncated: true, ReqOriginalSize: 300000, ReqSkippedReason: "content_type",
				Ts: time.Unix(1788256800, 123000000).UTC()},
			{ID: 1, AgentID: agentID, Method: "GET", Scheme: "https", Host: "api.example.com", URI: "/api/users",
				Direction: "egress", TLSVisibility: "PLAINTEXT",
				Ts: time.Unix(1788256800, 0).UTC()}, // response 未捕获（Status nil）
		}
		rr := doAdmin(t, newMux(store), http.MethodGet, base, "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}
		var payload struct {
			Items []nestedHTTPEvent `json:"items"`
			Total int64             `json:"total"`
		}
		decodeEnvelope(t, rr, &payload)
		if payload.Total != 2 || len(payload.Items) != 2 {
			t.Fatalf("分页载荷异常: %+v", payload)
		}
		it := payload.Items[0]
		if it.ID != 2 || it.AgentID != agentID.String() || it.FlowID != "f1" {
			t.Errorf("顶层字段异常: %+v", it)
		}
		if it.Request.Method != "POST" || it.Request.Scheme != "http" ||
			it.Request.Host != "api.example.com" || it.Request.URI != "/api/login" {
			t.Errorf("嵌套 request 异常: %+v", it.Request)
		}
		// 列表轻量：headers 空对象（非 null）、body 空串；截断标志如实保留
		if it.Request.Headers == nil || len(it.Request.Headers) != 0 {
			t.Errorf("列表 request.headers 应为空对象: %+v", it.Request.Headers)
		}
		if it.Request.Body != "" {
			t.Errorf("列表 request.body 应为空串: %q", it.Request.Body)
		}
		if !it.Request.BodyTruncated || it.Request.OriginalBodySize != 300000 {
			t.Errorf("列表截断标志未保留: %+v", it.Request)
		}
		if it.Request.BodySkippedReason != "content_type" {
			t.Errorf("列表 skipped_reason 未保留: %+v", it.Request)
		}
		// request_ts 毫秒精度
		if it.RequestTS != 1788256800.123 {
			t.Errorf("request_ts = %v, want 1788256800.123", it.RequestTS)
		}
		// response 嵌套轻量项 + latency/response_ts 派生
		if it.Response == nil || it.Response.Status != 200 {
			t.Fatalf("response 嵌套异常: %+v", it.Response)
		}
		if it.Response.Headers == nil || len(it.Response.Headers) != 0 || it.Response.Body != "" {
			t.Errorf("列表 response headers/body 应置空: %+v", it.Response)
		}
		if it.LatencyMS == nil || *it.LatencyMS != 33 {
			t.Errorf("latency_ms 异常: %+v", it.LatencyMS)
		}
		if it.ResponseTS == nil || !floatEq(*it.ResponseTS, 1788256800.156) {
			t.Errorf("response_ts = %v, want ≈1788256800.156", it.ResponseTS)
		}
		// response 未捕获：response null 且 response_ts/latency_ms 为 null
		it2 := payload.Items[1]
		if it2.Response != nil || it2.ResponseTS != nil || it2.LatencyMS != nil {
			t.Errorf("response 未捕获应整体为 null: %+v", it2)
		}
		if store.httpFilter.Page.Page != 1 || store.httpFilter.Page.PageSize != 20 {
			t.Errorf("默认分页异常: %+v", store.httpFilter.Page)
		}
	})

	t.Run("host/method/page 过滤透传", func(t *testing.T) {
		store := newFakeAdminStore()
		rr := doAdmin(t, newMux(store), http.MethodGet,
			base+"?page=3&page_size=50&host=API.example.com&method=post", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
		f := store.httpFilter
		if f.Host != "API.example.com" || f.Method != "post" || f.Page.Page != 3 || f.Page.PageSize != 50 {
			t.Errorf("过滤参数未透传: %+v", f)
		}
	})

	t.Run("Agent 不存在 404", func(t *testing.T) {
		store := newFakeAdminStore()
		rr := doAdmin(t, newAdminMux(NewHandler(store), injectPerms(PermAgentsView)),
			http.MethodGet, "/api/v1/traffic/agents/"+uuid.NewString()+"/http-events", "")
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})

	t.Run("无 view 权限 403", func(t *testing.T) {
		store := newFakeAdminStore()
		rr := doAdmin(t, newAdminMux(NewHandler(store), injectPerms(PermAgentsManage)),
			http.MethodGet, base, "")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rr.Code)
		}
	})
}

// TestGetHTTPEvent 详情：嵌套全量（含 headers/body）；404；id 非法 400。
func TestGetHTTPEvent(t *testing.T) {
	agentID := uuid.New()
	body := `{"token":"********"}`
	reqBody := `{"user":"alice","password":"********"}`
	status := 200
	latency := 33
	newMux := func(store *fakeAdminStore) *http.ServeMux {
		store.details[agentID] = &AgentDetail{Agent: Agent{AgentID: agentID}}
		store.httpDetail = &HTTPEventRow{
			ID: 7, AgentID: agentID, FlowID: "f1", Method: "POST", Scheme: "http",
			Host: "api.example.com", URI: "/api/login",
			Direction: "ingress", TLSVisibility: "PLAINTEXT",
			SrcIP: "10.1.1.10", SrcPort: 51234, DstIP: "10.1.2.20", DstPort: 8080,
			Status: &status, LatencyMS: &latency,
			RequestHeaders:  json.RawMessage(`{"authorization":"********"}`),
			ResponseHeaders: json.RawMessage(`{"set-cookie":"********"}`),
			RequestBody:     &reqBody, ReqSkippedReason: "content_type",
			ResponseBody: &body, RespTruncated: true, RespOriginalSize: 300000,
			RespSkippedReason: "encoding",
			Ts:                time.Unix(1788256800, 123000000).UTC(),
		}
		return newAdminMux(NewHandler(store), injectPerms(PermAgentsView))
	}
	base := "/api/v1/traffic/agents/" + agentID.String() + "/http-events"

	t.Run("单条全量 200（嵌套）", func(t *testing.T) {
		rr := doAdmin(t, newMux(newFakeAdminStore()), http.MethodGet, base+"/7", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}
		var ev nestedHTTPEvent
		decodeEnvelope(t, rr, &ev)
		if ev.ID != 7 || ev.FlowID != "f1" || ev.RequestTS != 1788256800.123 {
			t.Errorf("顶层字段异常: %+v", ev)
		}
		if ev.Request.Method != "POST" || ev.Request.Body != reqBody {
			t.Errorf("request 全量异常: %+v", ev.Request)
		}
		if ev.Request.Headers["authorization"] != "********" {
			t.Errorf("request.headers 异常: %+v", ev.Request.Headers)
		}
		if ev.Response == nil || ev.Response.Status != 200 || ev.Response.Body != body {
			t.Fatalf("response 全量异常: %+v", ev.Response)
		}
		if ev.Response.Headers["set-cookie"] != "********" {
			t.Errorf("response.headers 异常: %+v", ev.Response.Headers)
		}
		if !ev.Response.BodyTruncated || ev.Response.OriginalBodySize != 300000 {
			t.Errorf("截断标记异常: %+v", ev.Response)
		}
		if ev.Request.BodySkippedReason != "content_type" || ev.Response.BodySkippedReason != "encoding" {
			t.Errorf("skipped_reason 异常: req=%q resp=%q", ev.Request.BodySkippedReason, ev.Response.BodySkippedReason)
		}
		if ev.LatencyMS == nil || *ev.LatencyMS != 33 || ev.ResponseTS == nil || !floatEq(*ev.ResponseTS, 1788256800.156) {
			t.Errorf("latency/response_ts 异常: %+v", ev)
		}
	})

	t.Run("不存在 404", func(t *testing.T) {
		rr := doAdmin(t, newMux(newFakeAdminStore()), http.MethodGet, base+"/99", "")
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})

	t.Run("id 非法 400", func(t *testing.T) {
		rr := doAdmin(t, newMux(newFakeAdminStore()), http.MethodGet, base+"/abc", "")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})
}
