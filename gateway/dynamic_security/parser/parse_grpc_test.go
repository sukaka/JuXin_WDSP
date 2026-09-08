// parse_grpc_test.go gRPC 帧结构观测测试（W14-GW / P2-05）：
// 逐帧校验正反、三种畸形形态、截断样本不可判纪律、上限配置、ParseRequest 集成。
package parser

import (
	"encoding/binary"
	"net/http/httptest"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// grpcTestFrame 构造单条 gRPC 帧（5 字节前缀 + 消息体）。
func grpcTestFrame(compressed bool, msg []byte) []byte {
	f := make([]byte, 5+len(msg))
	if compressed {
		f[0] = 1
	}
	binary.BigEndian.PutUint32(f[1:5], uint32(len(msg)))
	copy(f[5:], msg)
	return f
}

// 正常帧序列：多帧计数与声明长度合计、压缩标志观测、无畸形结论。
func TestParseGRPCFramesValid(t *testing.T) {
	body := append(grpcTestFrame(false, []byte{0x0a, 0x03}), grpcTestFrame(true, []byte{1, 2, 3, 4})...)
	info := parseGRPCFrames(body, 1024, true)
	if info.Malformed {
		t.Fatalf("valid frames must not be malformed: %+v", info)
	}
	if info.MessageCount != 2 || info.DeclaredBytes != 6 {
		t.Fatalf("count/bytes = %d/%d, want 2/6", info.MessageCount, info.DeclaredBytes)
	}
	if !info.CompressedSeen {
		t.Fatal("compressed flag must be observed")
	}
	// 首帧未压缩且完整：FirstMessage 留存首帧消息字节（供描述符解码，瞬时不落盘）
	if len(info.FirstMessage) != 2 || info.FirstMessage[0] != 0x0a {
		t.Fatalf("first message must retain frame[0] payload: %x", info.FirstMessage)
	}
	// 空消息帧（声明长度 0）合法
	info = parseGRPCFrames(grpcTestFrame(false, nil), 1024, true)
	if info.Malformed || info.MessageCount != 1 || info.DeclaredBytes != 0 {
		t.Fatalf("empty message frame must be valid: %+v", info)
	}
	if info.FirstMessage == nil {
		t.Fatal("empty first message must be retained as non-nil empty slice")
	}
	// 空体：零帧零结论
	info = parseGRPCFrames(nil, 1024, true)
	if info.Malformed || info.MessageCount != 0 || info.CompressedSeen {
		t.Fatalf("empty body must be clean: %+v", info)
	}
	if info.FirstMessage != nil {
		t.Fatalf("no frame must not retain first message: %x", info.FirstMessage)
	}
}

// FirstMessage 留存纪律（W14-DESC / P2-05 深化）：
// 首帧压缩不存（内容不解）；首帧不完整（截断样本/畸形）不存；首帧之后的帧不影响留存。
func TestParseGRPCFramesFirstMessageRetention(t *testing.T) {
	// 首帧压缩：FirstMessage 为 nil（CompressedSeen 照记）
	body := grpcTestFrame(true, []byte{1, 2, 3})
	info := parseGRPCFrames(body, 1024, true)
	if info.FirstMessage != nil || !info.CompressedSeen {
		t.Fatalf("compressed first frame must not be retained: %+v", info)
	}
	// 首帧不完整（截断样本声明长度超剩余）：不存不判
	f := grpcTestFrame(false, []byte{1, 2, 3})
	binary.BigEndian.PutUint32(f[1:5], 100)
	info = parseGRPCFrames(f, 1024, false)
	if info.FirstMessage != nil || info.Malformed {
		t.Fatalf("incomplete first frame must not be retained: %+v", info)
	}
	// 单帧超上限（畸形）：不存
	big := grpcTestFrame(false, make([]byte, 32))
	info = parseGRPCFrames(big, 16, true)
	if info.FirstMessage != nil || !info.Malformed {
		t.Fatalf("oversized frame must not be retained: %+v", info)
	}
}

// 畸形：声明长度超出体剩余（完整体判定）。
func TestParseGRPCFramesLengthExceedsRemaining(t *testing.T) {
	f := grpcTestFrame(false, []byte{1, 2, 3})
	binary.BigEndian.PutUint32(f[1:5], 100) // 声明 100 字节，实际只有 3
	info := parseGRPCFrames(f, 1024, true)
	if !info.Malformed || info.MalformedKind != "length_exceeds_remaining" {
		t.Fatalf("want length_exceeds_remaining: %+v", info)
	}
	if info.MessageCount != 0 {
		t.Fatalf("malformed frame must not count: %+v", info)
	}
}

// 畸形：单帧声明长度超上限（声明本身即证据，截断样本同样可判）。
func TestParseGRPCFramesFrameExceedsLimit(t *testing.T) {
	f := grpcTestFrame(false, make([]byte, 64))
	info := parseGRPCFrames(f, 16, true)
	if !info.Malformed || info.MalformedKind != "frame_exceeds_limit" {
		t.Fatalf("want frame_exceeds_limit: %+v", info)
	}
	// 截断样本（complete=false）：单帧超上限仍可判
	info = parseGRPCFrames(f, 16, false)
	if !info.Malformed || info.MalformedKind != "frame_exceeds_limit" {
		t.Fatalf("sampled body must still flag oversized frame: %+v", info)
	}
	// 上限缺省（≤0）按引擎默认 4MiB 兜底：4MiB+1 声明即超
	big := grpcTestFrame(false, nil)
	binary.BigEndian.PutUint32(big[1:5], dsctx.DefaultGRPCMaxFrameBytes+1)
	info = parseGRPCFrames(big, 0, true)
	if !info.Malformed || info.MalformedKind != "frame_exceeds_limit" {
		t.Fatalf("default limit must apply: %+v", info)
	}
}

// 畸形：残留不足一个帧头（完整体）；截断样本边界不判。
func TestParseGRPCFramesTruncatedPrefix(t *testing.T) {
	body := append(grpcTestFrame(false, []byte{9}), 0x00, 0x01, 0x02) // 尾部残留 3 字节
	info := parseGRPCFrames(body, 1024, true)
	if !info.Malformed || info.MalformedKind != "truncated_frame_prefix" {
		t.Fatalf("want truncated_frame_prefix: %+v", info)
	}
	if info.MessageCount != 1 {
		t.Fatalf("leading valid frame must count: %+v", info)
	}
	// 截断样本：样本边界残留不判（样本边界非体边界）
	info = parseGRPCFrames(body, 1024, false)
	if info.Malformed {
		t.Fatalf("sampled body boundary must not be judged: %+v", info)
	}
	// 截断样本：声明长度超样本剩余同样不判
	f := grpcTestFrame(false, []byte{1, 2, 3})
	binary.BigEndian.PutUint32(f[1:5], 100)
	info = parseGRPCFrames(f, 1024, false)
	if info.Malformed {
		t.Fatalf("declared>sample-remaining must not be judged on sampled body: %+v", info)
	}
}

// Content-Type 主类型判定：application/grpc(+proto) 命中，grpc-web/JSON 不命中。
func TestIsGRPCMediaType(t *testing.T) {
	for mt, want := range map[string]bool{
		"application/grpc":           true,
		"application/grpc+proto":     true,
		"application/grpc+json":      true,
		"application/grpc-web":       false,
		"application/grpc-web+proto": false,
		"application/json":           false,
		"application/octet-stream":   false,
		"":                           false,
	} {
		if got := IsGRPCMediaType(mt); got != want {
			t.Fatalf("IsGRPCMediaType(%q) = %v, want %v", mt, got, want)
		}
	}
}

// ParseRequest 集成：application/grpc 体产帧观测；截断体样本校验（complete=false 不判边界）。
func TestParseRequestGRPC(t *testing.T) {
	body := append(grpcTestFrame(false, []byte{0x0a}), grpcTestFrame(true, []byte{1, 2})...)
	req := httptest.NewRequest("POST", "http://api.example.com/pkg.Svc/Call", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/grpc+proto")
	ctx := dsctx.New("req-grpc-parse-1", dsctx.DefaultParseLimits())
	p, err := ParseRequest(req, ctx)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.GRPC == nil {
		t.Fatal("GRPC observation missing")
	}
	if p.GRPC.MessageCount != 2 || p.GRPC.DeclaredBytes != 3 || !p.GRPC.CompressedSeen || p.GRPC.Malformed {
		t.Fatalf("bad grpc observation: %+v", p.GRPC)
	}
	// 非 gRPC 流量：观测为 nil（零产出）
	req2 := httptest.NewRequest("POST", "http://api.example.com/v1/orders", strings.NewReader(`{"a":1}`))
	req2.Header.Set("Content-Type", "application/json")
	p2, err := ParseRequest(req2, dsctx.New("req-grpc-parse-2", dsctx.DefaultParseLimits()))
	if err != nil {
		t.Fatalf("parse json: %v", err)
	}
	if p2.GRPC != nil {
		t.Fatalf("non-grpc traffic must not carry grpc observation: %+v", p2.GRPC)
	}
	// 截断体：超 MaxBodyParseBytes 只留样本，样本内声明超剩余不判畸形
	limits := dsctx.DefaultParseLimits()
	limits.MaxBodyParseBytes = 32
	limits.MaxBodySampleBytes = 16
	big := grpcTestFrame(false, make([]byte, 1024)) // 声明 1024 超样本剩余但不超帧上限
	req3 := httptest.NewRequest("POST", "http://api.example.com/pkg.Svc/Call", strings.NewReader(string(big)))
	req3.Header.Set("Content-Type", "application/grpc")
	p3, err := ParseRequest(req3, dsctx.New("req-grpc-parse-3", limits))
	if err != nil {
		t.Fatalf("parse truncated: %v", err)
	}
	if !p3.BodyTruncated {
		t.Fatal("body must be truncated")
	}
	if p3.GRPC == nil || p3.GRPC.Malformed {
		t.Fatalf("sampled body must not be judged malformed: %+v", p3.GRPC)
	}
}
