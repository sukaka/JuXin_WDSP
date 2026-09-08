// 心跳能力协商测试（v2 契约 §3：心跳请求携带声明集 [1,2]，
// 服务端回执生效集经 OnCapabilitiesFn 回调下发；旧服务端无回执 → nil 回调）。
package control

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

// runOneHeartbeat 跑一轮心跳（回调触发后取消）并返回服务端收到的声明集与回调收到的生效集。
func runOneHeartbeat(t *testing.T, respCaps any) (declared *transport.Capabilities, effective *transport.Capabilities) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req transport.HeartbeatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("心跳请求解析: %v", err)
		}
		declared = req.Capabilities
		resp := map[string]any{
			"server_time": 1, "config_version": 0, "desired_state": "ENABLED",
			"heartbeat_interval_seconds": 3600,
		}
		if respCaps != nil {
			resp["capabilities"] = respCaps
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)

	client, err := transport.New(srv.URL, false, "test")
	if err != nil {
		t.Fatal(err)
	}
	l := New(Deps{
		Client:  client,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AgentID: "a1",
		StatusFn: func() string {
			return "ONLINE"
		},
		MetricsFn:        func() transport.Metrics { return transport.Metrics{} },
		AppliedVersionFn: func() int64 { return 0 },
		OnCapabilitiesFn: func(c *transport.Capabilities) {
			effective = c
			cancel()
		},
	})
	l.Run(ctx)
	return declared, effective
}

func TestHeartbeatDeclaresCapabilitiesV2(t *testing.T) {
	declared, effective := runOneHeartbeat(t, map[string]any{"http_event_schema_versions": []int{1, 2}})
	if declared == nil || len(declared.HTTPEventSchemaVersions) != 2 ||
		declared.HTTPEventSchemaVersions[0] != 1 || declared.HTTPEventSchemaVersions[1] != 2 {
		t.Fatalf("心跳应声明 [1,2]: %+v", declared)
	}
	if effective == nil || !effective.HasSchemaVersion(2) {
		t.Fatalf("回调应收到生效集 [1,2]: %+v", effective)
	}
}

func TestHeartbeatLegacyServerNilCapabilities(t *testing.T) {
	declared, effective := runOneHeartbeat(t, nil)
	if declared == nil {
		t.Fatal("旧服务端也应收到声明（双向忽略即降级）")
	}
	if effective != nil {
		t.Fatalf("旧服务端无回执字段，回调应收到 nil: %+v", effective)
	}
}
