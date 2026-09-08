// W3C Trace Context 入口处理（APM 阶段1，ADR D5/D6）：
//   - traceparent 严格校验：version-traceid-spanid-flags 四段小写 hex；version 非 ff；
//     trace_id 32 hex 非全零；span_id 16 hex 非全零；整头 ≤128 字符。
//     任一不满足即视为无外部上下文（调用方新建内部 trace）；
//   - trace_id 16 字节 crypto/rand → hex，span_id 8 字节同理；
//   - tracestate 一律不读取、不转发、不返回（跨信任域清理）；
//   - 阶段1 不向客户端返回 trace_id、不向上游注入 traceparent；
//   - 不盲从外部 sampled 标志（采样语义留待阶段2）。
package context

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// TraceContext W3C trace 上下文（仅作网关内部关联键：不回传客户端、不注入上游）。
type TraceContext struct {
	TraceID string // 32 字符小写 hex
	SpanID  string // 16 字符小写 hex
}

// MaxTraceparentLen traceparent 整头长度上限（D5 约束，与 W3C 建议一致）。
const MaxTraceparentLen = 128

// ParseTraceparent 严格校验 W3C traceparent 并提取 trace_id；
// 任一约束不满足返回 ok=false（视为无外部上下文）。
func ParseTraceparent(h string) (traceID string, ok bool) {
	if h == "" || len(h) > MaxTraceparentLen {
		return "", false
	}
	parts := strings.Split(h, "-")
	if len(parts) != 4 {
		return "", false
	}
	version, tid, sid, flags := parts[0], parts[1], parts[2], parts[3]
	if len(version) != 2 || version == "ff" || !isLowerHex(version) {
		return "", false
	}
	if len(tid) != 32 || !isLowerHex(tid) || isAllZero(tid) {
		return "", false
	}
	if len(sid) != 16 || !isLowerHex(sid) || isAllZero(sid) {
		return "", false
	}
	if len(flags) != 2 || !isLowerHex(flags) {
		return "", false
	}
	return tid, true
}

// NewTraceContext 生成全新 trace 上下文（trace_id 16 字节、span_id 8 字节，crypto/rand）。
func NewTraceContext() (TraceContext, error) {
	tid, err := randomHex(16)
	if err != nil {
		return TraceContext{}, err
	}
	sid, err := randomHex(8)
	if err != nil {
		return TraceContext{}, err
	}
	return TraceContext{TraceID: tid, SpanID: sid}, nil
}

// ContinueTrace 以校验通过的外部 trace_id 续接（重新生成 span_id，不信任外部 span）。
// traceID 须已过 ParseTraceparent 校验，调用方保证。
func ContinueTrace(traceID string) (TraceContext, error) {
	sid, err := randomHex(8)
	if err != nil {
		return TraceContext{}, err
	}
	return TraceContext{TraceID: traceID, SpanID: sid}, nil
}

// randomHex 生成 n 字节随机数的小写 hex（2n 字符）；crypto/rand 故障如实返回错误，不降级弱随机源。
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// isLowerHex 全串小写 hex 判定（大写/非 hex 字符一律拒绝——W3C 要求小写）。
func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// isAllZero 全零判定（W3C 规定全零 trace_id/span_id 非法）。
func isAllZero(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return false
		}
	}
	return true
}
