// apimcpsse.go MCP SSE（text/event-stream）逐逻辑消息结果检查捕获
// （NG-MCP G1 §1.7/D7）：绑定 MCP 端点专属捕获模式——现状 text/event-stream
// 直通不缓冲（apiresponse.go 先例）之上，对请求相位已确认 tools/call 的
// 响应启用逐事件检查。
//
// 纪律（§1.7 冻结边界）：
//   - 按 SSE 事件边界（空行分隔，行尾三形态）缓冲**单条**事件 → mcprpc.SSEReader
//     解析为一条事件 → 检查通过即放行该条（**不整流缓冲**——背压与流式语义
//     保留，已放行字节即外发不撤回）；
//   - 注释行/keepalive（mcprpc 零值事件）原样透传；非 JSON-RPC 形态事件
//     观测不检查单条放行（UNKNOWN 不阻断，§1.7）；
//   - PROTECT 双闸命中违规 → **该条不外发**：中止上游读取（Write 返回错误即
//     反代中止）、关闭下游连接（已外发字节不冒充撤回）、产
//     `mcp.result_blocked_midstream` 事件（disclosed_bytes/messages_forwarded
//     逐量如实披露——§10.3 共用神门禁「首条正常第二条违规不得报告整个调用
//     通过」的 MCP 承接）；
//   - 预算（§1.10 SSE 行：单事件 1MiB/事件数 4096/流合计 16MiB）触顶 → 覆盖
//     PARTIAL(COV_INPUT_TRUNCATED) 如实，余量直通不再逐检（不冒充已检）；
//   - 解析全在请求 goroutine 内（无后台任务）；仅确认 text/event-stream 才
//     逐事件处理，其余响应逐字节透传零行为变化。
package jiuzhang_guard

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/mcpguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser/mcprpc"
	"go.uber.org/zap"
)

// SSE 流式预算（§1.10 表冻结）。
const (
	mcpSSEMaxEventBytes  = 1 << 20  // 单事件 ≤1MiB
	mcpSSEMaxEvents      = 4096     // 事件数 ≤4096/流
	mcpSSEMaxStreamBytes = 16 << 20 // 流合计 ≤16MiB
)

// errMCPResultBlocked SSE 中途阻断哨兵（Write 返回即反代中止上游读取；
// 下游连接随处理器错误关闭——已外发字节不冒充撤回）。
//
// 反代恐慌转换（批次 C 联调修正）：Caddy reverse_proxy 对中途写错误
// panic(http.ErrAbortHandler)（reverseproxy.go:1283——stdlib 先例）；
// 不经转换时恐慌越过 serveAPIProtected 的 finishAPIResponse（事件丢失）
// 且未 flush 的已放行字节被丢弃（客户端零字节）。proxyWithMCPSSEGuard
// 在本哨兵触发的 ErrAbortHandler 处恢复并折算为普通错误返回（finishAPIResponse
// 照常收束——mcp.result_blocked_midstream 事件随请求事件持久化）；
// 非本哨兵的 ErrAbortHandler 与其他恐慌原样再抛（存量语义不变）。
var errMCPResultBlocked = errors.New("mcp result blocked midstream")

// proxyWithMCPSSEGuard 反代调用包装：仅在 sfMCP 已阻断（本模块哨兵所致写错误）
// 时把反代的 ErrAbortHandler 恐慌折算为 errMCPResultBlocked 返回；其余情况透传/再抛。
func proxyWithMCPSSEGuard(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, sfMCP *mcpSSEWriter) (err error) {
	defer func() {
		rec := recover()
		if rec == nil {
			return
		}
		if sfMCP != nil && sfMCP.blocked && rec == http.ErrAbortHandler {
			err = errMCPResultBlocked
			return
		}
		panic(rec)
	}()
	return proxyAndCount(w, r, next)
}

// mcpSSEWriter SSE 逐消息检查 writer（单请求单 goroutine 顺序写；
// 激活前/非 SSE 逐字节透传零开销）。
type mcpSSEWriter struct {
	base          http.ResponseWriter
	rc            *dsctx.RequestContext
	call          *mcpguard.CallContext
	vrs           []detectors.CompiledSensitiveValueRule
	engineProtect bool
	logger        *zap.Logger

	decided     bool // Content-Type 已判定
	active      bool // 确认为 text/event-stream（逐事件模式）
	status      int
	pending     []byte // 当前未完结事件块缓冲（≤mcpSSEMaxEventBytes）
	degraded    bool   // 预算触顶已降级直通（PARTIAL 已如实披露一次）
	blocked     bool   // 已阻断（后续写一律拒绝）
	forwarded   int    // 已放行事件数（messages_forwarded 读数）
	disclosed   int64  // 已外发字节数（disclosed_bytes 读数）
	streamBytes int64  // 流入合计（流预算读数）
}

// wrapMCPSSEResponse MCP SSE 捕获包装（tools/call 调用上下文存在时包装；
// 否则原 writer 直返零行为 NG-T-C01）。返回（使用的 writer, 记录器或 nil）。
func (g *Guard) wrapMCPSSEResponse(w http.ResponseWriter, rc *dsctx.RequestContext) (http.ResponseWriter, *mcpSSEWriter) {
	if g.apiMCPGuard == nil || rc == nil {
		return w, nil
	}
	call := mcpguard.CallFromContext(rc)
	if call == nil || call.Tool == nil || call.Catalog == nil {
		return w, nil // 无完整调用上下文（非 tools/call/白名单前短路）——零行为
	}
	var vrs []detectors.CompiledSensitiveValueRule
	if len(g.APISensitiveValueRules) > 0 {
		if rules, err := detectors.CompileSensitiveValueRules(g.APISensitiveValueRules); err == nil {
			vrs = rules
		}
	}
	rec := &mcpSSEWriter{
		base: w, rc: rc, call: call, vrs: vrs,
		engineProtect: apiDecisionMode(g.APIProtectionMode) == decision.ModeProtect,
		logger:        g.logger,
	}
	return rec, rec
}

// Header 透传底层头表。
func (m *mcpSSEWriter) Header() http.Header { return m.base.Header() }

// WriteHeader 透传状态行（1xx 同 apiResponseCapture 口径；首个非 1xx 判定
// Content-Type——text/event-stream 激活逐事件模式）。
func (m *mcpSSEWriter) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		if m.status == 0 {
			m.base.WriteHeader(code)
		}
		return
	}
	if m.status != 0 {
		return
	}
	m.status = code
	if mcpguard.IsSSEContentType(m.base.Header().Get("Content-Type")) {
		m.active = true
	}
	m.decided = true
	m.base.WriteHeader(code)
}

// Write 直通/逐事件分派（激活后：事件边界单条缓冲即检即放，不整流缓冲）。
func (m *mcpSSEWriter) Write(p []byte) (int, error) {
	if m.status == 0 {
		m.WriteHeader(http.StatusOK)
	}
	if m.blocked {
		return 0, errMCPResultBlocked
	}
	if !m.active {
		return m.base.Write(p) // 非 SSE 逐字节透传零行为
	}
	m.streamBytes += int64(len(p))
	m.pending = append(m.pending, p...)
	// 流合计预算（§1.10：≤16MiB）与事件数预算（≤4096）——触顶降级直通
	if m.streamBytes > mcpSSEMaxStreamBytes || m.forwarded >= mcpSSEMaxEvents {
		m.degradePassthrough("stream_budget")
		return m.flushPending()
	}
	// 单事件预算（§1.10：≤1MiB）——未完结块超限即降级直通（不无限缓冲）
	if len(m.pending) > mcpSSEMaxEventBytes && !bytes.Contains(m.pending, []byte("\n\n")) {
		m.degradePassthrough("event_bytes")
		return m.flushPending()
	}
	for {
		block, rest := splitMCPSSEEvent(m.pending)
		if block == nil {
			return len(p), nil // 无完结块：累积待下一片（背压天然）
		}
		m.pending = rest
		if err := m.processEvent(block); err != nil {
			return 0, err
		}
	}
}

// flushPending 余量直通（降级路径）。
func (m *mcpSSEWriter) flushPending() (int, error) {
	if len(m.pending) == 0 {
		return 0, nil
	}
	n, err := m.base.Write(m.pending)
	m.disclosed += int64(n)
	m.pending = nil
	if err != nil {
		return n, err
	}
	return n, nil
}

// degradePassthrough 预算触顶降级（覆盖 PARTIAL(COV_INPUT_TRUNCATED) 如实——
// 余量直通不再逐检，不冒充已检；每流只披露一次）。
func (m *mcpSSEWriter) degradePassthrough(rule string) {
	if m.degraded {
		return
	}
	m.degraded = true
	m.rc.AddMatch(dsctx.DetectorMatch{
		Detector: "mcpguard",
		RuleID:   "mcp.coverage_v1",
		Category: "INFO",
		Severity: "INFO",
		Message:  "mcp sse result check degraded to passthrough (budget)",
		Evidence: map[string]string{
			"direction": "response", "completion": "partial",
			"skip_reason": "stream_budget", "rule": rule,
		},
	})
	if e := coverageEmitter(); e != nil {
		e.Emit(coverage.Observation{
			RequestID:  m.rc.RequestID,
			Detector:   "mcpguard",
			Phase:      coverage.PhaseResponse,
			Status:     coverage.StatusPartial,
			ReasonCode: coverage.ReasonInputTruncated,
			Truncated:  true,
		})
	}
	m.active = false
}

// processEvent 单条事件检查与转发（检查通过即放行该条字节）。
func (m *mcpSSEWriter) processEvent(block []byte) error {
	ev, err := mcprpc.NewSSEReader(bytes.NewReader(block), mcpSSEMaxEventBytes).Next()
	if err != nil {
		// 事件形态不可解析（含单事件超预算——splitter 已按块界切分，此处为
		// 解析层预算/形态问题）：UNKNOWN 不阻断，单条原样放行（§1.7）
		return m.forward(block)
	}
	// keepalive/注释-only（零值事件）与非 data 事件：原样透传
	if len(ev.Data) == 0 {
		return m.forward(block)
	}
	// JSON-RPC result 成员提取：非 JSON-RPC 形态事件观测不检查单条放行
	result, ok := mcpguard.ExtractResultMemberRaw(ev.Data)
	if !ok {
		return m.forward(block)
	}
	// 结果检查（output_schema + 值级敏感规则；双闸定案）
	if mcpguard.EvaluateResult(m.rc, m.call.Message, result, m.call.Config, m.vrs, m.engineProtect) {
		// 该条不外发：中止上游读取、关闭下游连接、事件逐量如实披露
		m.rc.AddMatch(dsctx.DetectorMatch{
			Detector:   "mcpguard",
			RuleID:     "mcp.result_blocked_midstream",
			Category:   "BLOCK",
			Severity:   "HIGH",
			Message:    "mcp tool result blocked midstream (event withheld, connection closed, forwarded bytes disclosed honestly)",
			Confidence: 1.0,
			Evidence: map[string]string{
				"disclosed_bytes":    formatInt64(m.disclosed),
				"messages_forwarded": fmt.Sprintf("%d", m.forwarded),
				"direction":          "response",
			},
		})
		m.blocked = true
		if m.logger != nil {
			m.logger.Warn("mcp tool result blocked midstream",
				zap.Int64("disclosed_bytes", m.disclosed), zap.Int("messages_forwarded", m.forwarded))
		}
		return errMCPResultBlocked
	}
	return m.forward(block)
}

// forward 放行单条事件字节（已放行即外发不撤回——写后立刻 flush：
// 批次 C 联调实证 Caddy 下游写缓冲在未 flush 的中止路径会丢弃已 Write 字节
// （客户端零字节、disclosed_bytes 失真）；flush 后「已外发」即为真实到达）。
func (m *mcpSSEWriter) forward(block []byte) error {
	n, err := m.base.Write(block)
	m.disclosed += int64(n)
	m.forwarded++
	if err == nil {
		_ = http.NewResponseController(m.base).Flush()
	}
	return err
}

// Finish 流尾收束（挂点侧在下游返回后调用）：未完结块原样外发
// （半截事件为源站字节——代理透传语义，非消费侧丢弃；UNKNOWN 不冒充判定）。
func (m *mcpSSEWriter) Finish() {
	if m.blocked || !m.decided {
		return
	}
	if len(m.pending) > 0 && m.active {
		n, _ := m.base.Write(m.pending)
		m.disclosed += int64(n)
		m.pending = nil
		_ = http.NewResponseController(m.base).Flush()
	}
}

// Flush 透传底层 Flusher。
func (m *mcpSSEWriter) Flush() {
	if m.status == 0 {
		m.WriteHeader(http.StatusOK)
	}
	if f, ok := m.base.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap 返回底层 writer（http.ResponseController 依赖）。
func (m *mcpSSEWriter) Unwrap() http.ResponseWriter { return m.base }

// Hijack 透传连接劫持（升级后脱离逐事件检查——如实直通）。
func (m *mcpSSEWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	m.active = false
	h, ok := m.base.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying writer does not support hijacking")
	}
	return h.Hijack()
}

// splitMCPSSEEvent 事件边界切分（空行分隔；行尾 \n / \r\n / 孤 \r 三形态）。
// 返回（首个完整块含边界, 余量）；无完整块返回 (nil, 原缓冲)。
func splitMCPSSEEvent(buf []byte) (block, rest []byte) {
	lineStart := 0
	i := 0
	for i < len(buf) {
		switch buf[i] {
		case '\n':
			if i == lineStart { // 空行（\n 结尾）
				return buf[:i+1], buf[i+1:]
			}
			i++
			lineStart = i
		case '\r':
			if i == lineStart { // 空行（\r 或 \r\n 结尾）
				end := i + 1
				if end < len(buf) && buf[end] == '\n' {
					end++
				}
				return buf[:end], buf[end:]
			}
			i++
			if i < len(buf) && buf[i] == '\n' {
				i++
			}
			lineStart = i
		default:
			i++
		}
	}
	return nil, buf
}

func formatInt64(v int64) string {
	return strings.TrimSpace(fmt.Sprintf("%d", v))
}
