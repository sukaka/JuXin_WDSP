// pipeline_grpc_test.go gRPC 管线集成测试（W14-GW / P2-05）：
// 识别打标、端点键路径全保留、帧校验正反、单帧上限配置、不挂 IsAPI 分类门槛。
package pipeline

import (
	"encoding/binary"
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
)

// grpcPipeFrame 构造单条 gRPC 帧。
func grpcPipeFrame(compressed bool, msg []byte) []byte {
	f := make([]byte, 5+len(msg))
	if compressed {
		f[0] = 1
	}
	binary.BigEndian.PutUint32(f[1:5], uint32(len(msg)))
	copy(f[5:], msg)
	return f
}

// grpcPipeRequest 构造 gRPC 请求（无 JSON 信号：API 分类天然低分，验证不挂 IsAPI 门槛）。
func grpcPipeRequest(body []byte) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "http://h/pkg.orders.v1.OrderService/CreateOrder", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/grpc+proto")
	r.Header.Set("X-Request-Id", "pipe-grpc-1")
	return r
}

// 识别与端点键：protocol=GRPC 打标、服务/方法名全保留（不归一化）、帧观测入明细；
// 健康流量不阻断（仅 INFO 观测）。
func TestProcessGRPCHealthy(t *testing.T) {
	body := append(grpcPipeFrame(false, []byte{0x0a, 0x01}), grpcPipeFrame(true, []byte{1})...)
	res, err := Process(grpcPipeRequest(body), Config{Enabled: true, Mode: decision.ModeProtect, GRPCAllowCompression: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.API.IsAPI {
		t.Fatal("grpc binary body must not score as API (no JSON signals)")
	}
	if res.EndpointKey != "POST /pkg.orders.v1.OrderService/CreateOrder" {
		t.Fatalf("endpoint key must preserve grpc path verbatim: %q", res.EndpointKey)
	}
	if v, ok := res.Context.GetExtension("api.protocol"); !ok || v != "GRPC" {
		t.Fatalf("api.protocol extension = %v/%v", v, ok)
	}
	if res.FinalAction != dsctx.ActionAllow {
		t.Fatalf("healthy grpc must allow, got %s", res.FinalAction)
	}
	var observed bool
	for _, m := range res.Context.CopyMatches() {
		if m.RuleID == "grpc.observed" {
			observed = true
			if m.Evidence["message_count"] != "2" || m.Evidence["declared_bytes"] != "3" {
				t.Fatalf("observation evidence = %+v", m.Evidence)
			}
		}
	}
	if !observed {
		t.Fatalf("grpc.observed missing: %+v", res.Context.CopyMatches())
	}
}

// 畸形帧 PROTECT 阻断（不挂 IsAPI 门槛：非 API 分类同样定案）；
// OBSERVE 模式仅记录；压缩策略不允许时产 OBSERVE 明细。
func TestProcessGRPCMalformedBlocks(t *testing.T) {
	f := grpcPipeFrame(true, []byte{1, 2, 3})
	binary.BigEndian.PutUint32(f[1:5], 100) // 声明 100 实际 3 → 畸形；且压缩位置位
	res, err := Process(grpcPipeRequest(f), Config{Enabled: true, Mode: decision.ModeProtect}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.FinalAction != dsctx.ActionBlock {
		t.Fatalf("malformed frame must block in PROTECT, got %s", res.FinalAction)
	}
	var malformed, compressed bool
	for _, m := range res.Context.CopyMatches() {
		if m.RuleID == "grpc.malformed_frame" && m.Evidence["kind"] == "length_exceeds_remaining" {
			malformed = true
		}
		if m.RuleID == "grpc.unexpected_compression" {
			compressed = true
		}
	}
	if !malformed || !compressed {
		t.Fatalf("malformed/compressed details = %v/%v: %+v", malformed, compressed, res.Context.CopyMatches())
	}
	// OBSERVE 模式：畸形帧降级记录，不阻断
	res2, err := Process(grpcPipeRequest(f), Config{Enabled: true, Mode: decision.ModeObserve}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res2.FinalAction != dsctx.ActionObserve {
		t.Fatalf("OBSERVE mode must only record, got %s", res2.FinalAction)
	}
	// 允许压缩：不产压缩明细
	res3, err := Process(grpcPipeRequest(f), Config{Enabled: true, Mode: decision.ModeObserve, GRPCAllowCompression: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range res3.Context.CopyMatches() {
		if m.RuleID == "grpc.unexpected_compression" {
			t.Fatalf("compression allowed must not flag: %+v", m)
		}
	}
}

// 单帧上限配置：GRPCMaxFrameBytes 下发覆盖生效；缺省 4MiB 兜底不误伤正常帧。
func TestProcessGRPCMaxFrameBytesConfig(t *testing.T) {
	f := grpcPipeFrame(false, make([]byte, 128))
	// 上限 64：声明 128 超上限 → 阻断
	res, err := Process(grpcPipeRequest(f), Config{Enabled: true, Mode: decision.ModeProtect, GRPCMaxFrameBytes: 64}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.FinalAction != dsctx.ActionBlock {
		t.Fatalf("oversized frame must block with configured limit, got %s", res.FinalAction)
	}
	var kind string
	for _, m := range res.Context.CopyMatches() {
		if m.RuleID == "grpc.malformed_frame" {
			kind = m.Evidence["kind"]
		}
	}
	if kind != "frame_exceeds_limit" {
		t.Fatalf("kind = %q, want frame_exceeds_limit", kind)
	}
	// 缺省（4MiB 兜底）：128 字节帧正常放行
	res2, err := Process(grpcPipeRequest(f), Config{Enabled: true, Mode: decision.ModeProtect}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res2.FinalAction != dsctx.ActionAllow {
		t.Fatalf("normal frame under default limit must allow, got %s", res2.FinalAction)
	}
}

// 非 gRPC 流量：不打标、端点键维持归一化、零 gRPC 明细。
func TestProcessNonGRPCUntouched(t *testing.T) {
	r, _ := http.NewRequest(http.MethodPost, "http://h/v1/orders/9", strings.NewReader(`{"id":1}`))
	r.Header.Set("Content-Type", "application/json")
	res, err := Process(r, Config{Enabled: true, Mode: decision.ModeProtect}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.Context.GetExtension("api.protocol"); ok {
		t.Fatal("non-grpc traffic must not carry api.protocol")
	}
	if res.EndpointKey != "POST /v1/orders/{id}" {
		t.Fatalf("endpoint key must stay normalized: %q", res.EndpointKey)
	}
	for _, m := range res.Context.CopyMatches() {
		if m.Detector == "grpc" {
			t.Fatalf("non-grpc traffic must not carry grpc details: %+v", m)
		}
	}
}
