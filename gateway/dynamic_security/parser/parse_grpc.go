// parse_grpc.go gRPC 帧结构观测（W14-GW / P2-05 首批 + W14-DESC / P2-05 深化）。
//
// Caddy 已终结 HTTP/2 传输层，到达引擎的请求体即 gRPC 消息帧序列：
// 逐帧 5 字节前缀（1 字节压缩标志 + 4 字节大端声明长度）+ protobuf 消息。
// v1 做帧结构校验与计数观测；深化版追加首帧消息瞬时留存（仅未压缩完整首帧，
// raw 子切片零拷贝，值只在请求内存活，供描述符解码，绝不写入事件/日志）。
//
// 校验口径（三种畸形形态，均只记结构事实）：
//   - 残留不足一个帧头（1~4 字节）：完整体判定为截断帧头（truncated_frame_prefix）；
//   - 单帧声明长度超上限（MaxGRPCFrameBytes，默认 4 MiB）：frame_exceeds_limit；
//   - 声明长度超出体剩余：length_exceeds_remaining。
//
// 截断体纪律：超 MaxBodyParseBytes 的体只留样本（BodyTruncated=true），样本边界不是
// 体边界——样本内「声明长度>剩余」不可判定（剩余体未读完），仅「单帧超上限」仍可判
// （声明长度本身即证据）；complete=false 时遇不可判定形态停止走帧，不产畸形结论。
package parser

import (
	"encoding/binary"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// GRPCInfo gRPC 帧结构观测（结构事实与计数 + 首帧消息瞬时留存，不落事件/日志）。
type GRPCInfo struct {
	MessageCount   int    // 完整校验通过的消息帧数
	DeclaredBytes  int64  // 已校验帧的声明长度合计（体量观测，不含内容）
	CompressedSeen bool   // 存在压缩标志位（bit0）置位的帧
	Malformed      bool   // 帧结构与体边界不符（完整体判定，或单帧超上限）
	MalformedKind  string // 畸形形态：truncated_frame_prefix / frame_exceeds_limit / length_exceeds_remaining
	// FirstMessage 首帧消息字节（raw 子切片；仅未压缩且完整落入解析体的首帧，
	// 首帧压缩/不完整/畸形时为 nil）。值只在请求内存活，供描述符驱动字段级解析
	// （W14-DESC / P2-05 深化）解码使用，与 JSONValues 同一纪律：绝不写入事件/日志；
	// 长度已被帧上限约束（≤ MaxGRPCFrameBytes，默认 4MiB，与单消息解码上限一致）。
	FirstMessage []byte
}

// IsGRPCMediaType gRPC Content-Type 主类型判定：application/grpc 与
// application/grpc+<suffix>（+proto/+json 等编码变体）。
// 不含 application/grpc-web（Web 走 HTTP/1.1 兼容封装，帧封装不同，v1 不覆盖）。
func IsGRPCMediaType(mt string) bool {
	return mt == "application/grpc" || strings.HasPrefix(mt, "application/grpc+")
}

// parseGRPCFrames 逐帧校验 gRPC 帧序列并计数（不落消息内容）。
// maxFrameBytes 单帧声明长度上限（≤0 用 dsctx.DefaultGRPCMaxFrameBytes 兜底）；
// complete 表示 raw 为完整请求体（false = 截断样本，样本边界不判 length_exceeds_remaining）。
func parseGRPCFrames(raw []byte, maxFrameBytes int, complete bool) *GRPCInfo {
	if maxFrameBytes <= 0 {
		maxFrameBytes = dsctx.DefaultGRPCMaxFrameBytes
	}
	info := &GRPCInfo{}
	offset := 0
	for {
		rem := len(raw) - offset
		if rem == 0 {
			break // 帧序列干净结束
		}
		if rem < 5 {
			// 残留不足一个帧头：完整体即截断帧头；截断样本的样本边界不判
			if complete {
				info.Malformed = true
				info.MalformedKind = "truncated_frame_prefix"
			}
			break
		}
		compressed := raw[offset]&0x01 != 0
		if compressed {
			info.CompressedSeen = true
		}
		declared := binary.BigEndian.Uint32(raw[offset+1 : offset+5])
		if declared > uint32(maxFrameBytes) {
			// 单帧声明长度超上限：声明本身即证据，与体完整性无关
			info.Malformed = true
			info.MalformedKind = "frame_exceeds_limit"
			break
		}
		if uint64(declared) > uint64(rem-5) {
			// 声明长度超出体剩余：完整体即畸形；截断样本不可判定，停止不判
			if complete {
				info.Malformed = true
				info.MalformedKind = "length_exceeds_remaining"
			}
			break
		}
		info.MessageCount++
		info.DeclaredBytes += int64(declared)
		if info.MessageCount == 1 && !compressed {
			// 首帧消息瞬时留存（raw 子切片零拷贝）：供描述符解码；压缩帧内容不解不存
			info.FirstMessage = raw[offset+5 : offset+5+int(declared)]
		}
		offset += 5 + int(declared)
	}
	return info
}
