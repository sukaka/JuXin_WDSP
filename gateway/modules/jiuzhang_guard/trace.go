// APM 阶段1（ADR D5/D6）：W3C trace 上下文入口处理与请求上下文桥接。
//
// 口径：
//   - 默认总是新建 trace_id（不信任外部 traceparent）；trace_trust_external=true 且外部
//     traceparent 严格校验通过时续接其 trace_id（span_id 仍重新生成，不信任外部 span）；
//   - 不读取/返回 tracestate；不向客户端返回 trace_id；trace_inject_upstream=true 时才
//     向上游注入 traceparent（覆盖入站值并清除 tracestate），默认关闭零行为变化；
//   - trace 上下文在任何拦截分支之前写入请求上下文，前置拦截分支同样可关联。
package jiuzhang_guard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"go.uber.org/zap"
)

// traceContextKey 请求上下文中的 W3C trace 上下文键（ServeHTTP 入口写入）。
type traceContextKey struct{}

// clientIPResultKey 请求上下文中的真实 IP 识别结果键（ServeHTTP 真实IP识别后写入，
// 供统一 RequestContext 桥接复用，避免重复解析代理头）。
type clientIPResultKey struct{}

// traceFallbackCounter crypto/rand 故障派生兜底的去重输入（保证并发不撞）。
var traceFallbackCounter atomic.Uint64

// resolveTraceContext 入口 trace 处理（D5）：默认新建；信任开关开启且外部 traceparent
// 校验通过时续接 trace_id。生成失败如实告警并派生兜底（不静默、不阻断请求）。
func (g *Guard) resolveTraceContext(r *http.Request) dsctx.TraceContext {
	if g.TraceTrustExternal {
		if tid, ok := dsctx.ParseTraceparent(r.Header.Get("traceparent")); ok {
			tc, err := dsctx.ContinueTrace(tid)
			if err == nil {
				return tc
			}
			g.logger.Warn("trace span id generation failed, deriving fallback", zap.Error(err))
			return deriveTraceContext(r)
		}
	}
	tc, err := dsctx.NewTraceContext()
	if err != nil {
		g.logger.Warn("trace id generation failed, deriving fallback", zap.Error(err))
		return deriveTraceContext(r)
	}
	return tc
}

// injectTraceparent 向上游注入 W3C traceparent（trace_inject_upstream=true 时由
// serveNext 放行链路调用）：version 00 + 内部 trace_id/span_id + flags=01。
// sampled=01 表示「本系统保留该 trace」（阶段1 无 Agent 模式日志全量不采样，
// 最终采样决策由中央 tail sampling 决定，ADR D5-4/D6）。
// Header.Set 一律覆盖入站外部值——注入的始终是内部上下文（trace_trust_external
// 续接场景 span_id 也已重新生成，不透传外部 span）；同时清除 tracestate
// （跨信任域不续传，ADR D5-3）。
// tc 为零值时跳过：仅测试直接调 serveNext 绕过 ServeHTTP 入口埋点才会出现，
// 生产路径入口必写入非空上下文（含派生兜底），此处不编造 trace 关联键。
func injectTraceparent(tc dsctx.TraceContext, r *http.Request) {
	if tc.TraceID == "" || tc.SpanID == "" {
		return
	}
	r.Header.Set("traceparent", "00-"+tc.TraceID+"-"+tc.SpanID+"-01")
	r.Header.Del("tracestate")
}

// deriveTraceContext crypto/rand 故障兜底：sha256(requestID | 纳秒时间 | 原子计数) 取 hex，
// 保证关联键非空且唯一。仅作关联用途，不构成安全边界（trace 关联键本就不作信任决策）。
func deriveTraceContext(r *http.Request) dsctx.TraceContext {
	sum := sha256.Sum256([]byte(r.Header.Get("X-Request-Id") + "|" +
		strconv.FormatInt(time.Now().UnixNano(), 10) + "|" +
		strconv.FormatUint(traceFallbackCounter.Add(1), 10)))
	h := hex.EncodeToString(sum[:])
	return dsctx.TraceContext{TraceID: h[:32], SpanID: h[32:48]}
}

// traceContextFrom 取请求 trace 上下文（ServeHTTP 入口必写入；测试直接调 serveNext 等
// 绕过入口的路径无此值，返回零值——字段如实留空，不编造）。
func traceContextFrom(ctx context.Context) dsctx.TraceContext {
	v, _ := ctx.Value(traceContextKey{}).(dsctx.TraceContext)
	return v
}

// clientIPResultFrom 取真实 IP 识别结果（ServeHTTP 写入；未写入返回 ok=false）。
func clientIPResultFrom(ctx context.Context) (clientip.Result, bool) {
	v, ok := ctx.Value(clientIPResultKey{}).(clientip.Result)
	return v, ok
}
