// apigrpc_test.go gRPC v1 端到端（W14-GW / P2-05）：
// 畸形帧 PROTECT 阻断、健康流量观测、压缩策略、protocol/proto 事件字段、
// 端点键与路径模板全保留、不挂 IsAPI 分类门槛、帧上限配置校验。
package jiuzhang_guard

import (
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// grpcE2EFrame 构造单条 gRPC 帧。
func grpcE2EFrame(compressed bool, msg []byte) []byte {
	f := make([]byte, 5+len(msg))
	if compressed {
		f[0] = 1
	}
	binary.BigEndian.PutUint32(f[1:5], uint32(len(msg)))
	copy(f[5:], msg)
	return f
}

// grpcE2ERequest 构造 gRPC 请求（HTTP/2 协议版本标注；无 JSON 信号，验证不挂 IsAPI 门槛）。
func grpcE2ERequest(id string, body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://api.example.com/pkg.orders.v1.OrderService/CreateOrder",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/grpc+proto")
	req.Header.Set("X-Request-Id", id)
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	return req
}

// 畸形帧 PROTECT：403 阻断、事件 protocol=GRPC + proto=HTTP/2.0 + grpc.malformed_frame 明细、
// 端点键服务/方法名全保留；不挂 IsAPI 门槛（gRPC 二进制体分类低分仍定案）。
func TestServeNext_GRPCMalformedFrameBlocks(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)

	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	f := grpcE2EFrame(true, []byte{1, 2, 3})
	binary.BigEndian.PutUint32(f[1:5], 100) // 声明 100 实际 3 → 畸形；压缩位置位
	err := g.serveNext(httptest.NewRecorder(), grpcE2ERequest("req-grpc-e2e-1", f), next)
	if err == nil {
		t.Fatal("expect block error")
	}
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 HandlerError, got %v", err)
	}
	if called {
		t.Fatal("next handler must not run when blocked")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	rec := recs[0]
	if rec.FinalAction != "BLOCK" || rec.ResponseStatus != http.StatusForbidden {
		t.Fatalf("bad action/status: %s/%d", rec.FinalAction, rec.ResponseStatus)
	}
	if rec.Protocol != "GRPC" {
		t.Fatalf("protocol = %q, want GRPC", rec.Protocol)
	}
	if rec.Proto != "HTTP/2.0" {
		t.Fatalf("proto = %q, want HTTP/2.0", rec.Proto)
	}
	if rec.EndpointKey != "POST /pkg.orders.v1.OrderService/CreateOrder" {
		t.Fatalf("endpoint key must preserve grpc path verbatim: %q", rec.EndpointKey)
	}
	if rec.PathTemplate != "/pkg.orders.v1.OrderService/CreateOrder" {
		t.Fatalf("path template must be preserved: %q", rec.PathTemplate)
	}
	if rec.IsAPI {
		t.Fatal("grpc binary body must not score as API (checks must not depend on it)")
	}
	var malformed, compressed, observed bool
	for _, d := range rec.Details {
		switch d.RuleID {
		case "grpc.malformed_frame":
			malformed = true
			if d.Evidence["kind"] != "length_exceeds_remaining" {
				t.Fatalf("malformed evidence = %+v", d.Evidence)
			}
		case "grpc.unexpected_compression":
			compressed = true
		case "grpc.observed":
			observed = true
		}
	}
	if !malformed || !compressed || !observed {
		t.Fatalf("details malformed/compressed/observed = %v/%v/%v: %+v", malformed, compressed, observed, rec.Details)
	}
}

// 健康 gRPC 流量（OBSERVE 模式 + 允许压缩）：放行、体完整交付下游、
// 事件带帧观测（计数/体量不落内容）与 protocol/proto 标注。
func TestServeNext_GRPCHealthyPassthrough(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)
	g.APIGRPCAllowCompression = true

	body := append(grpcE2EFrame(false, []byte{0x0a, 0x01}), grpcE2EFrame(true, []byte{1})...)
	var gotBody []byte
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		gotBody = make([]byte, len(body))
		n, _ := r.Body.Read(gotBody)
		gotBody = gotBody[:n]
		w.WriteHeader(http.StatusOK)
		return nil
	})
	req := grpcE2ERequest("req-grpc-e2e-2", body)
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if len(gotBody) != len(body) {
		t.Fatalf("downstream body corrupted: %d != %d", len(gotBody), len(body))
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	rec := recs[0]
	if rec.Protocol != "GRPC" || rec.Proto != "HTTP/2.0" {
		t.Fatalf("protocol/proto = %q/%q", rec.Protocol, rec.Proto)
	}
	if rec.FinalAction != "ALLOW" {
		t.Fatalf("healthy grpc must allow, got %s", rec.FinalAction)
	}
	for _, d := range rec.Details {
		if d.RuleID == "grpc.observed" {
			if d.Evidence["message_count"] != "2" || d.Evidence["declared_bytes"] != "3" {
				t.Fatalf("observation evidence = %+v", d.Evidence)
			}
			return
		}
	}
	t.Fatalf("grpc.observed missing: %+v", rec.Details)
}

// 压缩策略：默认（未配置允许）压缩标志位置位产 grpc.unexpected_compression OBSERVE。
func TestServeNext_GRPCCompressionObserve(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	body := grpcE2EFrame(true, []byte{1, 2, 3, 4})
	if err := g.serveNext(httptest.NewRecorder(), grpcE2ERequest("req-grpc-e2e-3", body), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	for _, d := range recs[0].Details {
		if d.RuleID == "grpc.unexpected_compression" {
			if d.Category != "OBSERVE" || d.Severity != "MEDIUM" {
				t.Fatalf("compression discipline broken: %s/%s", d.Category, d.Severity)
			}
			return
		}
	}
	t.Fatalf("grpc.unexpected_compression missing: %+v", recs[0].Details)
}

// 非 gRPC 事件：protocol 字段省略、proto 字段存在（HTTP/1.1）。
func TestServeNext_NonGRPCProtoVisibility(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", map[string]map[string]string{"POST /v1/orders": {"id": "number"}})

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-grpc-e2e-4")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	if recs[0].Protocol != "" {
		t.Fatalf("non-grpc event must omit protocol, got %q", recs[0].Protocol)
	}
	if recs[0].Proto != "HTTP/1.1" {
		t.Fatalf("proto = %q, want HTTP/1.1", recs[0].Proto)
	}
	for _, d := range recs[0].Details {
		if d.Detector == "grpc" {
			t.Fatalf("non-grpc traffic must not carry grpc details: %+v", d)
		}
	}
}

// 帧上限配置校验：负值与超 64MiB 硬上限拒绝加载。
func TestGuardValidateGRPCMaxFrameBytes(t *testing.T) {
	g := &Guard{APIDynamicProtection: true, EventsLog: "/tmp/x.log"}
	g.APIGRPCMaxFrameBytes = -1
	if err := g.Validate(); err == nil {
		t.Fatal("negative api_grpc_max_frame_bytes must be rejected")
	}
	g.APIGRPCMaxFrameBytes = maxAPIGRPCMaxFrameBytes + 1
	if err := g.Validate(); err == nil {
		t.Fatal("oversized api_grpc_max_frame_bytes must be rejected")
	}
	g.APIGRPCMaxFrameBytes = 8 << 20
	if err := g.Validate(); err != nil {
		t.Fatalf("valid frame limit must pass: %v", err)
	}
}
