// Package tapsrc Envoy tap 管理流适配器（P1-03 §3.3，G3）。
//
// S0 锁定结论（详见 deployment/envoy-tap/README.md）：
//   - 锁定 Envoy v1.35.3（镜像 tag+digest 双锁）；
//   - tap 输出走本机受控管理流（POST {admin}/tap + streaming_admin sink），
//     不写原始 tap 文件、不把 Admin 暴露到非回环地址——无需 ADR；
//   - 输出格式锁定 JSON_BODY_AS_BYTES：Envoy v1.35.3 上 streaming_admin +
//     PROTO_BINARY_LENGTH_DELIMITED 会使 Envoy 进程崩溃（absl null check，
//     实测可复现，SIGTRAP），二进制路径禁用；
//   - JSON 流为「美化 JSON 消息以换行相接」的自相似流：读取器按括号深度
//     分帧，正确处理分片/半消息；TCP 字节流本身保序，不重排消息；流中断
//     后有界退避重连并重新提交 tap 配置（tap 配置不持久，Envoy 重启即失效）。
//
// 边界红线：
//   - 纯观测：适配器是 tap 管理流的客户端，只出向连接回环 Admin 读取数据，
//     不监听任何采集端口、不反向代理、不接触业务流量转发路径；适配器故障
//     不影响 Envoy 转发（tap 会话随连接断开被 Envoy 取消）；
//   - 配对：HTTP/2 多路复用的请求/响应配对由 Envoy 按流缓冲完成——每条
//     HttpBufferedTrace 消息就是一个完整的流（请求+响应），适配器不做
//     跨消息配对，绝不用五元组/时间接近合并流。缓冲输出不含连接/流 ID
//     与地址/时间戳：capture_stream_id=null（不可获得，不造假），五元组
//     以 127.0.0.1:0 占位，时间戳为 tap 消息接收时间（latency 恒 0，
//     不表达业务延迟——口径见契约附录 B）；
//   - gRPC：仅元数据（service/method 由 :path 可信解析，grpc-status 取自
//     响应 trailers；HTTP 200 ≠ RPC 成功）；取消/未完成如实 UNKNOWN，
//     不伪造 grpc-status=0；默认不采集 gRPC 消息正文（content_type 跳过），
//     不解析 Protobuf 正文；
//   - WebSocket：只交付握手视图（Upgrade 请求 + 可获得的握手响应）；
//     帧/消息正文不驻留、不解析；
//   - 脱敏：请求/响应消息经 httpsensor.MaskedRequestMessage /
//     MaskedResponseMessage 构造——与被动 HTTP/1 传感器同一脱敏/Body 后
//     处理出口；多值 Header/Trailer 经 MaskedHeaderValues 逐值脱敏保序
//     保留重复值；x-wdsp-* 控制命名空间剥离；
//   - 资源有界：channel 数、单消息字节、Header 存储量、正文捕获、退避
//     上限全部有界；单条消息异常只丢弃该条并计数。
package tapsrc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/httpsensor"
)

// CapabilitiesVersion 采集源能力版本（与 policy_version / Agent build 分开记录）。
const CapabilitiesVersion = "envoy-tap/1"

// 默认值与硬上限（P1-03 §5.1：全部有界）。
const (
	DefaultAdminAddr      = "127.0.0.1:9901"
	defaultMaxBodyBytes   = 4 << 10 // tap 正文缓冲上限（同时下发为 Envoy max_buffered_*_bytes）
	defaultMaxMessage     = 1 << 20 // 单条 TraceWrapper JSON 上限
	maxMessageHard        = 8 << 20
	defaultReconnectMin   = 1 * time.Second
	defaultReconnectMax   = 30 * time.Second
	defaultConnectTimeout = 10 * time.Second
	maxHeaderStoreBytes   = 16 << 10 // Header/Trailer 存储总量钳（与 mirrorsrc 同口径）
)

// Config tap 适配器配置（本地 agent.json tap 段；默认关闭，显式启用）。
type Config struct {
	// AdminAddr Envoy Admin 地址（仅允许回环 host:port；Admin 不暴露到非回环）。
	AdminAddr string
	// SourceInstance 受控采集实例标识（必填；≤255 字符；非 Agent 身份）。
	SourceInstance string
	// ConfigID tap filter admin_config 的 config_id（必填）。Envoy Admin 同时
	// 只允许一条已挂接 tap 流（"An attached /tap admin stream already exists"），
	// 故本适配器为单会话：多个 listener 的 tap filter 共享同一 config_id。
	ConfigID string
	// ObservedHTTPVersion 部署断言：本 tap 会话覆盖的全部 listener 的观测协议
	// （"1.0"/"1.1"/"2"/"3"；空/"UNKNOWN"=无法确认——tap 缓冲输出不含协议版本，
	// HTTP/1 与 HTTP/2 在 tap 中呈现同一伪头形态，禁止据内容猜测；混合协议
	// listener 时必须 UNKNOWN）。
	ObservedHTTPVersion string
	// TLSTerminated 部署断言：本 tap 会话覆盖的全部 listener 均为可信 TLS 终止点
	// （→ tls_visibility=DECRYPTED）；混合终止点时必须 false（保守如实）。
	// 不由外部 Header 决定。
	TLSTerminated bool
	// BodyEnabled 正文采集总开关（默认 false=仅元数据；gRPC 正文恒不采集）。
	BodyEnabled bool
	// MaxBodyBytes 正文捕获上限（≤0 取默认 4KB；硬上限 config.HardMaxBodySize；
	// 同时作为 tap 输出 max_buffered_rx/tx_bytes 下发，Envoy 侧超限即截断）。
	MaxBodyBytes int
	// MaxMessageBytes 单条 TraceWrapper JSON 上限（≤0 取默认 1MB；硬上限 8MB；
	// 超限丢弃该条并计数，状态机继续同步后续消息）。
	MaxMessageBytes int64
	// 重连退避（≤0 取默认 1s/30s）。
	ReconnectMin time.Duration
	ReconnectMax time.Duration
	// ConnectTimeout 连接与响应头超时（≤0 取默认 10s）。
	ConnectTimeout time.Duration
}

// Stats 适配器计数（agent 聚合观测；全部原子操作）。
type Stats struct {
	Received       atomic.Uint64 // 完整接收的 TraceWrapper 消息数
	Emitted        atomic.Uint64 // 产出的 v2 记录数
	Disconnects    atomic.Uint64 // tap 管理流中断次数（source_disconnect 指标）
	Reconnects     atomic.Uint64 // 重新提交 tap 配置次数
	AdminRejects   atomic.Uint64 // POST /tap 非 200（配置被拒/Admin 异常）
	ParseErrors    atomic.Uint64 // 完整帧 JSON 解析失败
	OversizeDrops  atomic.Uint64 // 单消息超 MaxMessageBytes 丢弃
	NonHTTPIgnored atomic.Uint64 // 非 HTTP trace（socket trace 等）忽略
	HeaderClamped  atomic.Uint64 // Header/Trailer 总量超钳次数

	sensorStats httpsensor.Stats // 脱敏字段计数（masked 指标）
}

// Source tap 适配器（单 tap 管理流读取协程；全部 Fail-Open）。
type Source struct {
	cfg      Config
	agentID  string
	epoch    int64 // 适配器进程启动代次（Unix 秒，单调递增）
	log      *slog.Logger
	onRecord func(events.HTTPRecordV2)

	policy atomic.Pointer[httpsensor.Policy]
	Stats  Stats

	seq     atomic.Uint64 // flow_id 序号
	mu      sync.Mutex
	cancel  context.CancelFunc
	stopped bool
	wg      sync.WaitGroup
}

// New 创建适配器（校验配置；onRecord 必须非阻塞快速返回）。
func New(agentID string, cfg Config, onRecord func(events.HTTPRecordV2), log *slog.Logger) (*Source, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.SourceInstance == "" || len(cfg.SourceInstance) > 255 {
		return nil, errors.New("tapsrc: source_instance 必填且 ≤255 字符")
	}
	if cfg.AdminAddr == "" {
		cfg.AdminAddr = DefaultAdminAddr
	}
	if err := validateLoopbackAdmin(cfg.AdminAddr); err != nil {
		return nil, err
	}
	if cfg.ConfigID == "" || len(cfg.ConfigID) > 128 {
		return nil, errors.New("tapsrc: config_id 必填且 ≤128 字符")
	}
	switch cfg.ObservedHTTPVersion {
	case "", events.HTTPVersionUnknown:
		cfg.ObservedHTTPVersion = events.HTTPVersionUnknown
	case events.HTTPVersion10, events.HTTPVersion11, events.HTTPVersion2, events.HTTPVersion3:
	default:
		return nil, fmt.Errorf("tapsrc: observed_http_version 非法（仅 1.0/1.1/2/3/UNKNOWN）: %q", cfg.ObservedHTTPVersion)
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = defaultMaxBodyBytes
	}
	if cfg.MaxBodyBytes > config.HardMaxBodySize {
		cfg.MaxBodyBytes = config.HardMaxBodySize
	}
	if cfg.MaxMessageBytes <= 0 {
		cfg.MaxMessageBytes = defaultMaxMessage
	}
	if cfg.MaxMessageBytes > maxMessageHard {
		cfg.MaxMessageBytes = maxMessageHard
	}
	if cfg.ReconnectMin <= 0 {
		cfg.ReconnectMin = defaultReconnectMin
	}
	if cfg.ReconnectMax <= 0 {
		cfg.ReconnectMax = defaultReconnectMax
	}
	if cfg.ReconnectMax < cfg.ReconnectMin {
		cfg.ReconnectMax = cfg.ReconnectMin
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = defaultConnectTimeout
	}
	s := &Source{
		cfg:      cfg,
		agentID:  agentID,
		epoch:    time.Now().Unix(),
		log:      log,
		onRecord: onRecord,
	}
	// 默认仅元数据（L1）+ 契约默认脱敏，待策略热更
	s.policy.Store(&httpsensor.Policy{
		Level:       config.LevelL1,
		MaxBodySize: config.DefaultMaxBodySize,
		Masking:     config.DefaultMasking(),
	})
	return s, nil
}

// validateLoopbackAdmin 校验 Admin 地址为回环（Admin 不暴露到非回环地址——
// 适配器只出向连接本机 Envoy Admin；开放远程采集不属于默认部署）。
func validateLoopbackAdmin(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("tapsrc: admin_addr 非法: %w", err)
	}
	if host == "" {
		return errors.New("tapsrc: admin_addr 禁止 wildcard（仅允许回环地址）")
	}
	if p, err := strconv.Atoi(port); err != nil || p <= 0 || p > 65535 {
		return errors.New("tapsrc: admin_addr 端口非法")
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("tapsrc: admin_addr 仅允许回环地址（拒绝 %q）", host)
	}
	return nil
}

// UpdatePolicy 热更采集策略（与被动传感器同口径整表替换）。tap 会话的
// Envoy 侧正文缓冲上限在下次 tap 重连时随新策略下发。
func (s *Source) UpdatePolicy(level string, maxBodySize int, masking config.Masking) {
	if maxBodySize <= 0 {
		maxBodySize = config.DefaultMaxBodySize
	}
	if maxBodySize > config.HardMaxBodySize {
		maxBodySize = config.HardMaxBodySize
	}
	s.policy.Store(&httpsensor.Policy{Level: level, MaxBodySize: maxBodySize, Masking: masking})
}

// Run 启动 tap 管理流读取协程并阻塞至 ctx 取消（优雅停机有界）。
func (s *Source) Run(ctx context.Context) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		s.runSession(runCtx)
	}()
	s.log.Info("tapsrc Envoy tap 适配器已启动",
		"admin", s.cfg.AdminAddr, "source_instance", s.cfg.SourceInstance,
		"config_id", s.cfg.ConfigID, "observed", s.cfg.ObservedHTTPVersion,
		"tls_terminated", s.cfg.TLSTerminated, "body_enabled", s.cfg.BodyEnabled,
		"max_body_bytes", s.cfg.MaxBodyBytes, "max_message_bytes", s.cfg.MaxMessageBytes)
	s.wg.Wait()
}

// Shutdown 停止全部 channel（有界等待；与 Run 并发调用安全）。
func (s *Source) Shutdown(ctx context.Context) {
	s.mu.Lock()
	s.stopped = true
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// MaskedFieldCount 脱敏字段累计数（masked 指标，P1-03 §5.7）。
func (s *Source) MaskedFieldCount() uint64 { return s.Stats.sensorStats.MaskedFields.Load() }

// runSession tap 管理流循环：连接 → 读流 → 中断后有界退避重连。
// tap 配置不持久（Envoy 重启即失效），每次（重）连都重新提交。
func (s *Source) runSession(ctx context.Context) {
	backoff := s.cfg.ReconnectMin
	first := true
	for {
		err := s.tapSession(ctx)
		if ctx.Err() != nil {
			return
		}
		if !first {
			s.Stats.Reconnects.Add(1)
		}
		first = false
		if err != nil {
			s.Stats.Disconnects.Add(1)
			s.log.Warn("tapsrc 管理流中断，退避后重连",
				"config_id", s.cfg.ConfigID, "backoff", backoff, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > s.cfg.ReconnectMax {
			backoff = s.cfg.ReconnectMax
		}
	}
}
