// Package apievents API 动态防护运行时事件输出（JSON Lines，由管理平台采集入库）。
// 与 events 包（访问控制/CC 事件）并列，承载统一引擎产出的主事件与端点发现信息。
package apievents

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
)

// Record 统一运行时主事件 + 端点发现信息（采集端据此写 api_runtime_events 并 upsert 端点资产）。
type Record struct {
	ID            string    `json:"id,omitempty"`
	RequestID     string    `json:"request_id"`
	OccurredAt    time.Time `json:"occurred_at"`
	ApplicationID string    `json:"application_id,omitempty"`
	AppCode       string    `json:"app_code,omitempty"`
	// TraceID W3C trace 关联键（APM 阶段1 D6：guard 入口生成，32 字符小写 hex；
	// 空 = 不可得省略，如心跳记录）。实现「安全事件 ↔ 访问记录」双向检索。
	TraceID      string `json:"trace_id,omitempty"`
	Domain       string `json:"domain,omitempty"`
	EndpointKey  string `json:"endpoint_key"`
	Method       string `json:"method,omitempty"`
	PathTemplate string `json:"path_template,omitempty"`
	// RawPath 归一化前的请求路径（不含 query，Emit 时封顶 512 字符）。
	RawPath string `json:"raw_path,omitempty"`
	// Proto HTTP 协议版本（W14-GW：r.Proto 原样 HTTP/1.1 / HTTP/2.0 / HTTP/3；
	// 空 = 不可得省略，采集端容忍缺失）。
	Proto string `json:"proto,omitempty"`
	// Protocol 应用层协议族（W14-GW / P2-05：gRPC 识别命中 = GRPC；其余省略，
	// 采集端按缺省 REST 口径消费 api_endpoints.protocol_type）。
	Protocol string `json:"protocol,omitempty"`
	// ClientIP guard 识别的真实客户端 IP（入口已改写 RemoteAddr；空 = 不可得）。
	ClientIP      string                `json:"client_ip,omitempty"`
	IsAPI         bool                  `json:"is_api"`
	APIConfidence float64               `json:"api_confidence,omitempty"`
	RiskScore     int                   `json:"risk_score"`
	RiskLevel     string                `json:"risk_level"`
	FinalAction   string                `json:"final_action"`
	Details       []dsctx.DetectorMatch `json:"details"`
	// ResponseStatus 响应状态码：API 流量事件在响应完成后输出，为真实状态码；
	// 阻断类动作按决策映射 403/429；非 API 命中事件仍在响应前输出，置 0（未采集）。
	ResponseStatus int `json:"response_status"`
	// LatencyMS 请求处理耗时（毫秒；API 流量为入口到下游响应完成，阻断类为到阻断点）。
	LatencyMS int64 `json:"latency_ms,omitempty"`
	// ModelVersion 当前命中的 FORMAL 模型版本号（发布通道经 api_formal_model_versions 下发；无则省略）。
	ModelVersion string `json:"model_version,omitempty"`
	// PolicyVersion 策略版本戳（发布通道经 api_policy_version 下发，原样透传）。
	PolicyVersion string `json:"policy_version,omitempty"`
	// SourceFingerprint 客户端来源指纹（HMAC-SHA256 截断 16 字节 hex，真实客户端 IP 不可逆脱敏；空 = 不可得）。
	SourceFingerprint string `json:"source_fingerprint,omitempty"`
	// IdentityFingerprint 身份指纹（auth:/key:/sess: 前缀 + 统一加盐指纹；仅凭据派生，空 = 匿名）。
	// IP 属环境维度，不得冒充身份（docs/API_MICRO_MODELS.md §2.2）。
	IdentityFingerprint string `json:"identity_fingerprint,omitempty"`
	// AuthType 认证方式（bearer_or_basic / api_key / cookie_session；空 = 匿名或未识别）。
	AuthType    string `json:"auth_type,omitempty"`
	GatewayNode string `json:"gateway_node_id"`
	// ParamObservations 参数值脱敏观测（length/hash/num；无明文），供管理面回填 statistics。
	ParamObservations []detectors.ParamObservation `json:"param_observations,omitempty"`
	// ResponseObservations 响应结构观测（P0-06：一级字段路径→类型 + status/content_type/
	// body_size；不落值），供管理面按 端点×状态码 合并学习 api_response_schemas；
	// 仅 API 流量且捕获到合法 JSON 时携带，无观测时键省略（事件零变化）。
	ResponseObservations []dsctx.ResponseObservation `json:"response_observations,omitempty"`
	// FileObservations 文件传输观测（P1-04：multipart 上传 part 元数据 + 响应侧
	// Content-Disposition 下载观测；仅元数据不落文件内容），供管理面 upsert
	// api_file_assets；仅 API 流量且有文件传输时携带，无观测时键省略（事件零变化）。
	FileObservations []dsctx.FileObservation `json:"file_observations,omitempty"`
	// LLMObservation LLM API 观测（P2-04：识别为 LLM 端点的流量携带；model/prompt
	// 存在性/体量桶/token 用量/流式标记，数据最小化不落 Prompt/Response 原文），
	// 供管理面落 api_llm_observations；非 LLM 流量为 nil，事件零变化。
	LLMObservation *dsctx.LLMObservation `json:"llm_observation,omitempty"`
	// JWTVerification JWT 信任链验证摘要（WDSP P0-03：请求经 jwt_trust 范围内
	// 评估时携带——含 VERIFIED 与 OBSERVE 记录的失败；OFF/范围外为 nil，事件
	// 零变化。不落原始 Token/payload/明文 sub/tenant，tenant 为加盐指纹），
	// 供管理面落 api_runtime_events.jwt_verification（迁移 000127）。
	JWTVerification *dsevents.JWTVerification `json:"jwt_verification,omitempty"`
	// AuthzDecision request-level BOLA/BFLA decision group. ObjectRef values
	// are HMAC references produced by the gateway detector.
	AuthzDecision *dsevents.AuthorizationDecisionGroup `json:"authz_decision,omitempty"`
	// FinalDecision 请求最终处置上下文（WDSP P0-04，final_decision JSON
	// schema_version=1）：仅处置事实已确定（终止/源站完成/错误）时由 emitAPIEvent
	// 挂载（Settled 门禁），采集端落 api_runtime_events.final_decision（迁移 000131）；
	// 响应前输出的事件不携带（请求在途，提前 Finalize 会锁死后续记录）。
	FinalDecision json.RawMessage `json:"final_decision,omitempty"`
	// Heartbeat 合成心跳标记（W17-HB：节点活性/策略版本周期上报，无业务语义）。
	// 采集端识别后跳过端点发现/学习样本/findings 等全部业务物化，仅透传给节点活性聚合。
	Heartbeat bool `json:"heartbeat,omitempty"`
	// UptimeSeconds guard 本次装配至今的运行秒数（仅心跳记录携带；omitempty 保证业务事件零变化）。
	UptimeSeconds int64 `json:"uptime_seconds,omitempty"`
	// GuardStartTime guard 本次装配启动时间（仅心跳记录携带；指针保证业务事件键省略）。
	GuardStartTime *time.Time `json:"guard_start_time,omitempty"`
	// FormalModelVersions FORMAL 模型版本摘要数（api_formal_model_versions 下发条目数；
	// 仅心跳记录携带——逐端点版本号由业务事件 model_version 按命中上报，心跳不落明细）。
	FormalModelVersions int `json:"formal_model_versions,omitempty"`
}

// 字段长度上限（防超大输入撑爆日志）。
const (
	maxEndpointKeyLen    = 560
	maxPathLen           = 512
	maxDomainLen         = 255
	maxClientIPLen       = 64
	maxVersionLen        = 128
	maxLLMModelLen       = 128
	maxProtoLen          = 32
	maxTraceIDLen        = 32
	authzObjectRefHexLen = 64
)

// 有界积压队列与异步异常上报节流参数（code-review MED-6）。
const (
	// eventQueueSize 有界内存队列深度（条）：仅在写进行期间（磁盘卡顿/高并发）累积；
	// 满则丢弃新事件并节流上报（经 Emit 返回值由调用方 Warn），在飞请求不再阻塞。
	eventQueueSize = 4096
	// asyncReportInterval 队列丢弃/后台落盘失败的上报节流窗口：窗口内重复发生不重复
	// 返回错误（计数与错误保留至下一窗口汇总），可见性与防洪泛兼得。
	asyncReportInterval = 10 * time.Second
)

// Logger JSON Lines 事件记录器（并发安全）。
//
// 写入模型（code-review MED-6：消除请求路径内全局互斥锁下的同步磁盘写头阻塞）：
//   - 快路径：无在途写且无积压时同步落盘——Emit 返回即耐久（与历史语义一致，调用方与
//     既有测试可直接读盘断言）；写错误同步返回；
//   - 有在途写（磁盘可能卡顿）时新事件入有界队列，后台 goroutine 持写令牌逐条补写
//     （补写只在持令牌后从队列取条，快路径持令牌时确认队列空，二者互斥保证落盘顺序）；
//     磁盘卡顿期间在飞请求至多一次 O(1) 入队，队列满则丢新事件——不再全部排队等同一把锁；
//   - 丢弃与后台落盘失败按 asyncReportInterval 节流汇总，经 Emit 返回值/Close 上报，不静默；
//   - mu 只护生命周期与异步异常账本，任何磁盘 IO 均不持 mu。
type Logger struct {
	node string
	f    *os.File

	writeTok  chan struct{}  // 容量 1 写令牌：持令牌者独占文件写（快路径与后台补写互斥）
	queue     chan []byte    // 有界积压队列（已序列化含换行记录）
	notify    chan struct{}  // 容量 1 唤醒信号（入队后触发后台补写）
	done      chan struct{}  // Close 关闭信号（唤醒后台排空后退出）
	closeDone chan struct{}  // 首次 Close 完成信号（后续 Close 等待并复用结果）
	drainWg   sync.WaitGroup // 后台落盘 goroutine 生命周期
	inflight  sync.WaitGroup // 在途 Emit（Close 等其完成后再封队列）

	mu         sync.Mutex // 生命周期与异步异常账本（绝不持锁做磁盘 IO）
	closed     bool
	closeErr   error
	dropped    int64     // 队列满累计丢弃数（上报后清零）
	writeErr   error     // 后台落盘最近未上报错误（上报后清零）
	lastReport time.Time // 上次异步异常上报时刻
}

// NewLogger 打开事件日志文件（追加写入），并启动后台落盘 goroutine（随 Close 退出）。
func NewLogger(path, gatewayNode string) (*Logger, error) {
	if path == "" {
		return nil, fmt.Errorf("api events log path required")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open api events log: %w", err)
	}
	l := &Logger{
		f:         f,
		node:      gatewayNode,
		writeTok:  make(chan struct{}, 1),
		queue:     make(chan []byte, eventQueueSize),
		notify:    make(chan struct{}, 1),
		done:      make(chan struct{}),
		closeDone: make(chan struct{}),
	}
	l.writeTok <- struct{}{}
	l.drainWg.Add(1)
	go l.writer()
	return l, nil
}

// sanitize 截断超长字段、剥离控制字符（防日志注入；JSON 转义为第二道防线）。
func sanitize(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}

// Emit 输出一条记录（出错返回，不静默丢弃）。
// 无在途写时同步落盘（返回即耐久）；有在途写时入有界队列由后台补写——队列满丢弃
// 新事件并随节流窗口汇总返回错误（窗口内重复丢弃返回 nil，计数不丢，下一窗口汇总上报）。
func (l *Logger) Emit(e Record) error {
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	e.GatewayNode = l.node
	e.TraceID = sanitize(e.TraceID, maxTraceIDLen)
	e.EndpointKey = sanitize(e.EndpointKey, maxEndpointKeyLen)
	e.PathTemplate = sanitize(e.PathTemplate, maxPathLen)
	e.RawPath = sanitize(e.RawPath, maxPathLen)
	e.ClientIP = sanitize(e.ClientIP, maxClientIPLen)
	e.ModelVersion = sanitize(e.ModelVersion, maxVersionLen)
	e.PolicyVersion = sanitize(e.PolicyVersion, maxVersionLen)
	e.Domain = sanitize(e.Domain, maxDomainLen)
	e.Proto = sanitize(e.Proto, maxProtoLen)
	e.Protocol = sanitize(e.Protocol, maxProtoLen)
	if e.LLMObservation != nil {
		e.LLMObservation.Model = sanitize(e.LLMObservation.Model, maxLLMModelLen)
	}
	if e.JWTVerification != nil {
		e.JWTVerification.Status = sanitize(e.JWTVerification.Status, maxProtoLen)
		e.JWTVerification.ReasonCode = sanitize(e.JWTVerification.ReasonCode, maxProtoLen)
		e.JWTVerification.PolicyVersion = sanitize(e.JWTVerification.PolicyVersion, maxVersionLen)
		e.JWTVerification.IssuerConfigID = sanitize(e.JWTVerification.IssuerConfigID, maxVersionLen)
		e.JWTVerification.KeysetVersion = sanitize(e.JWTVerification.KeysetVersion, maxVersionLen)
		e.JWTVerification.VerifiedPrincipalID = sanitize(e.JWTVerification.VerifiedPrincipalID, maxVersionLen)
		e.JWTVerification.VerifiedTenantID = sanitize(e.JWTVerification.VerifiedTenantID, maxVersionLen)
		e.JWTVerification.VerifiedIdentityType = sanitize(e.JWTVerification.VerifiedIdentityType, maxProtoLen)
		e.JWTVerification.EvaluatedAt = sanitize(e.JWTVerification.EvaluatedAt, 64)
	}
	if e.AuthzDecision != nil {
		sanitizeAuthzDecision(e.AuthzDecision)
	}
	if e.Details == nil {
		e.Details = []dsctx.DetectorMatch{}
	}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal api event: %w", err)
	}
	data = append(data, '\n')

	// 注册在途（closed 判定与 Add 同锁，保证 Close 的 Wait 不会漏等已受理的 Emit）
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return fmt.Errorf("api events logger closed")
	}
	l.inflight.Add(1)
	l.mu.Unlock()
	defer l.inflight.Done()

	// 快路径：持令牌且队列空（后台补写只在持令牌后取条，故此判定无隐藏积压）→
	// 同步落盘，保持返回即耐久语义与写错误同步返回
	select {
	case <-l.writeTok:
		if len(l.queue) == 0 {
			_, werr := l.f.Write(data)
			l.writeTok <- struct{}{}
			if werr != nil {
				return fmt.Errorf("write api event: %w", werr)
			}
			return nil
		}
		l.writeTok <- struct{}{} // 有积压：放回令牌，走入队保序
	default:
	}

	dropped := false
	select {
	case l.queue <- data:
		// 唤醒后台补写（容量 1，多次入队合并为一次唤醒；补写循环会排空整个队列）
		select {
		case l.notify <- struct{}{}:
		default:
		}
	default:
		dropped = true // 队列满：丢新事件，计数随节流窗口汇总上报
	}
	return l.asyncReport(dropped)
}

func sanitizeAuthzDecision(g *dsevents.AuthorizationDecisionGroup) {
	g.DecisionID = sanitize(g.DecisionID, maxVersionLen)
	g.PolicyVersion = sanitize(g.PolicyVersion, maxVersionLen)
	if len(g.Checks) > 32 {
		g.Checks = g.Checks[:32]
	}
	for i := range g.Checks {
		c := &g.Checks[i]
		c.Type = sanitize(c.Type, maxProtoLen)
		c.Decision = dsevents.AuthorizationDecision(sanitize(string(c.Decision), maxProtoLen))
		c.ReasonCode = sanitize(c.ReasonCode, maxProtoLen)
		c.RelationState = sanitize(c.RelationState, maxProtoLen)
		c.ObjectType = sanitize(c.ObjectType, maxVersionLen)
		c.ObjectRef = sanitizeObjectRef(c.ObjectRef)
		// Role claim values are never part of the event contract, even when a
		// Record is assembled by a caller outside the detector package.
		c.Role = ""
		c.RoleSource = sanitize(c.RoleSource, maxProtoLen)
		c.TenantState = sanitize(c.TenantState, maxProtoLen)
		c.PolicyVersion = sanitize(c.PolicyVersion, maxVersionLen)
		c.ModelVersion = sanitize(c.ModelVersion, maxVersionLen)
	}
}

// sanitizeObjectRef keeps the event contract closed over gateway-generated
// HMAC references. A caller cannot accidentally turn an object ID into an
// event field by constructing a Record directly.
func sanitizeObjectRef(ref string) string {
	ref = sanitize(ref, maxVersionLen)
	if len(ref) != len("objref:")+authzObjectRefHexLen || !strings.HasPrefix(ref, "objref:") {
		return ""
	}
	if _, err := hex.DecodeString(ref[len("objref:"):]); err != nil {
		return ""
	}
	return ref
}

// asyncReport 异步异常账本（队列满丢弃 / 后台落盘失败）节流上报：超窗口返回聚合错误
// 供调用方 Warn；窗口内返回 nil（计数与错误保留至下一窗口，不静默丢账）。
func (l *Logger) asyncReport(dropped bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if dropped {
		l.dropped++
	}
	if l.dropped == 0 && l.writeErr == nil {
		return nil
	}
	now := time.Now()
	if now.Sub(l.lastReport) < asyncReportInterval {
		return nil
	}
	l.lastReport = now
	var b strings.Builder
	if l.dropped > 0 {
		fmt.Fprintf(&b, "api events queue full: dropped %d new event(s) since last report (disk stalled or saturated)", l.dropped)
		l.dropped = 0
	}
	if l.writeErr != nil {
		if b.Len() > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "background write failed: %v", l.writeErr)
		l.writeErr = nil
	}
	return errors.New(b.String())
}

// writer 后台落盘 goroutine：唤醒后持写令牌逐条排空队列（持令牌才取条——与快路径
// 「持令牌见队列空才直写」互斥，保证落盘顺序）；Close 发起且队列排空后退出。
// 写失败记账（sticky，经 Emit 节流上报 / Close 返回）并继续消费：磁盘恢复后
// 后续事件仍可落盘，事件丢失仅限队列满丢弃。
func (l *Logger) writer() {
	defer l.drainWg.Done()
	for {
		for {
			<-l.writeTok
			select {
			case data := <-l.queue:
				_, err := l.f.Write(data)
				l.writeTok <- struct{}{}
				if err != nil {
					l.mu.Lock()
					l.writeErr = err
					l.mu.Unlock()
				}
			default:
				l.writeTok <- struct{}{}
				if l.isClosed() {
					return // Close 已发起且队列排空
				}
				goto drained
			}
		}
	drained:
		select {
		case <-l.notify:
		case <-l.done:
		}
	}
}

// isClosed 供后台 goroutine 查询关闭标记（mu 临界区无 IO）。
func (l *Logger) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// Close 关闭：停止接收新事件（此后 Emit 返回错误），等在途 Emit 完成后由后台
// goroutine 排空队列落盘，再关闭文件。幂等；返回关闭前未上报的落盘错误/丢弃账。
func (l *Logger) Close() error {
	l.mu.Lock()
	if l.closed {
		closeDone := l.closeDone
		l.mu.Unlock()
		<-closeDone
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.closeErr
	}
	l.closed = true
	l.mu.Unlock()
	l.inflight.Wait() // 在途 Emit 完成（其入队均在此前），此后无人再发送
	close(l.done)     // 唤醒后台 goroutine 排空并退出
	l.drainWg.Wait()
	l.mu.Lock()
	werr := l.writeErr
	l.writeErr = nil
	dropped := l.dropped
	l.dropped = 0
	l.mu.Unlock()
	var closeErr error
	if err := l.f.Close(); err != nil {
		closeErr = fmt.Errorf("close api events log: %w", err)
	}
	var reportErr error
	switch {
	case werr != nil:
		reportErr = fmt.Errorf("api events background write: %w", werr)
	case dropped > 0:
		reportErr = fmt.Errorf("api events queue full: dropped %d event(s) before close", dropped)
	}
	err := errors.Join(closeErr, reportErr)
	l.mu.Lock()
	l.closeErr = err
	close(l.closeDone)
	l.mu.Unlock()
	return err
}
