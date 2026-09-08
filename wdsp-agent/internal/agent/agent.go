// Package agent WDSP 边缘 Agent 编排层：抓包→过滤→流跟踪→事件→限速→外发/缓存，
// 以及控制通道、自我保护、磁盘缓存补传的组装（TASK-001~009/012 集成点）。
//
// 红线（设计 §72 / 契约 §6）：
//   - 纯旁路只读：不存在任何向网卡写报文的代码路径；
//   - Fail-Open：所有 goroutine recover 保护，任何内部错误只降级不退出进程；
//   - 所有 Queue/Buffer 有硬上限（内存队列 10000 事件或 64MB，磁盘缓存 512MB）。
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/buffer"
	"github.com/jiuzhang-waf/wdsp-agent/internal/capture"
	"github.com/jiuzhang-waf/wdsp-agent/internal/cert"
	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/control"
	// ebpfcapture init 向 capture 注册 eBPF 后端工厂（Linux；其他平台为编译占位）。
	"github.com/jiuzhang-waf/wdsp-agent/internal/backpressure"
	_ "github.com/jiuzhang-waf/wdsp-agent/internal/ebpfcapture"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/filter"
	"github.com/jiuzhang-waf/wdsp-agent/internal/flow"
	"github.com/jiuzhang-waf/wdsp-agent/internal/httpparse"
	"github.com/jiuzhang-waf/wdsp-agent/internal/httpsensor"
	"github.com/jiuzhang-waf/wdsp-agent/internal/k8smeta"
	"github.com/jiuzhang-waf/wdsp-agent/internal/mirrorsrc"
	"github.com/jiuzhang-waf/wdsp-agent/internal/netif"
	"github.com/jiuzhang-waf/wdsp-agent/internal/override"
	"github.com/jiuzhang-waf/wdsp-agent/internal/ratelimit"
	"github.com/jiuzhang-waf/wdsp-agent/internal/selfmon"
	"github.com/jiuzhang-waf/wdsp-agent/internal/tapsrc"
	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

// 硬上限（契约 §6 / 设计 §68：不允许无限 Queue）。
const (
	flowQueueCap     = 10000            // 内存事件队列硬上限（条）
	httpQueueCap     = 2048             // HTTP 记录队列硬上限（条）
	rawQueueCap      = 10000            // RAW 帧队列硬上限（帧）
	queueMaxBytes    = 64 << 20         // 内存队列字节硬上限（先到为准）
	rawFlushInterval = time.Second      // RAW 批/事件批冲刷周期
	flowSweepSec     = 2 * time.Second  // 流表扫描周期（FIN 宽限 3s 能及时生效；90s 空闲驱逐亦由此驱动）
	kernelStatsSec   = 15 * time.Second // 内核丢包采集周期
	bufferEnforceSec = 60 * time.Second
)

// 磁盘缓存记录类型标签（单字节前缀；无标签的旧缓存按 flow 事件解析）。
const (
	bufTagFlow   byte = 'F'
	bufTagHTTP   byte = 'H'
	bufTagMirror byte = 'M' // 镜像来源 v2 记录（完整 v2 JSON，G2）
)

// 补传限速等待参数（契约 §6 限速约束；测试可缩短）。
var (
	replayWaitAttempts = 50
	replayWaitInterval = 100 * time.Millisecond
)

// errReplayThrottled 补传批次在限速等待窗口内未获令牌：整批保留在缓存，下轮重试。
var errReplayThrottled = errors.New("限速桶持续饱和，暂停本轮补传")

// errReplayBackoff 429 Retry-After 退避窗口内：整批保留在缓存，窗口过后重试。
var errReplayBackoff = errors.New("429 Retry-After 退避中，暂停本轮补传")

// dropped_by_reason 指标词表（agent 侧管线，P1-03 冻结；缓存侧段级原因见
// buffer.ReasonXxx，快照时以 spool_segments_<reason> 键并入）。
const (
	DropReasonRateLimited        = "rate_limited"          // 出站限速桶满（RAW 直接丢弃）
	DropReasonQueueFull          = "queue_full"            // 内存队列/字节硬上限满（RAW 直接丢弃）
	DropReasonSpoolWriteFailed   = "spool_write_failed"    // 磁盘缓存满/关闭/写失败
	DropReasonPermanentInvalid   = "permanent_invalid"     // 服务端 400/413/422 判定永久非法
	DropReasonHTTPEndpointGone   = "http_endpoint_gone"    // 旧服务端无 /http 端点，降级丢弃
	DropReasonFrameOversize      = "frame_oversize"        // RAW 帧超 65535 上限
	DropReasonReassemblyConnFull = "reassembly_table_full" // HTTP 重组连接表满拒绝
	DropReasonFlowTableFull      = "flow_table_full"       // 流表满驱逐
)

// httpQItem HTTP 记录队列项（带字节估算，用于 64MB 队列硬上限记账）。
// v2rec 非空时为镜像来源 v2 记录（G2；走独立 v2 发送/缓存路径，rec 字段无效）。
type httpQItem struct {
	rec   events.HTTPRecord
	est   int64
	v2rec *events.HTTPRecordV2
}

// Agent 边缘采集 Agent。
type Agent struct {
	cfg     *config.Config
	cfgPath string
	cfgMu   sync.Mutex // 保护 cfg 变更与 Save
	log     *slog.Logger

	client       *transport.Client
	bucket       *ratelimit.Bucket
	replayBucket *ratelimit.Bucket // 补传公平预算桶（P1-03 §5.5：份额=出站带宽×replay_share_percent）
	buf          *buffer.Buffer
	filt         *filter.Filter
	tracker      *flow.Tracker
	sensor       *httpsensor.Sensor
	mirror       *mirrorsrc.Receiver // Nginx mirror 接收器（G2；nil=未启用）
	tap          *tapsrc.Source      // Envoy tap 适配器（G3；nil=未启用）
	monitor      *selfmon.Monitor
	sampler      selfmon.Sampler
	k8sResolver  *k8smeta.Resolver
	k8sClient    *k8smeta.Client

	metrics  Metrics
	capStats capture.Stats

	// Phase 4 智能采集：背压降级帽状态机、定向规则集、基础等级与策略采样缓存
	// （applyPolicy 热更；热路径 atomic 读，见 phase4.go 决策链注释）。
	bp               *backpressure.Monitor
	overrides        *override.Set
	baseLevel        atomic.Int64 // config.LevelRank（含 /http 404 降级）
	policySampleRate atomic.Int64 // float64 bits；0=不采样，(0,1)=策略采样率

	flowQ      chan events.FlowEvent
	httpQ      chan httpQItem
	httpQBytes atomic.Int64
	rawQ       chan events.PacketFrame
	rawQBytes  atomic.Int64

	// httpGone Phase 3 契约 §10：服务端无 /http 端点（404）→ 降级 L0，
	// 不再重试该端点（不进入缓存补传死循环）。
	httpGone atomic.Bool

	// httpRetryUntil 429 Retry-After 退避截止（unixnano；P1-03 §4.2.4：
	// 窗口内 HTTP 实时批次直接转缓存、补传暂停，不再向服务端施压）。
	httpRetryUntil atomic.Int64

	// httpV2 HTTP 事件 schema v2 协商生效（v2 契约 §3：注册/心跳回执生效集含 2
	// 时才走 v2 线格式；旧服务端无回执字段 → 恒 false 走 v1，双向忽略即降级）。
	httpV2 atomic.Bool

	// startEpoch 来源进程重启代次（v2 source_epoch，进程启动 Unix 秒，单调递增）。
	startEpoch int64

	capMu              sync.Mutex
	backend            capture.Backend // 当前抓包后端（AF_PACKET 或 eBPF，单实例覆盖全部接口）
	backendName        string          // 生效后端名（afpacket|ebpf）
	fallbackReason     string          // eBPF→AF_PACKET 回退原因（无回退为空）
	capIfaces          []string        // 当前抓包接口集合（升序，用于热更判定）
	localBackend       string          // agent.json capture_backend（本地显式后端选择）
	localSnaplen       int             // agent.json capture_snaplen（eBPF 截取上限）
	disabledByServer   atomic.Bool
	degraded           atomic.Bool
	hbFailed           atomic.Bool
	online             atomic.Bool
	captureUnsupported atomic.Bool

	lastCPU atomic.Int64 // float64 bits
	lastMem atomic.Int64

	// 机器身份证书（Phase 2-B 契约 §7-§9）；certMgr=nil 表示 Bearer 模式。
	// 轮换状态仅由控制循环单 goroutine 访问，无需加锁。
	certMgr       *cert.Manager
	rotateBackoff *transport.Backoff
	rotateNext    time.Time // 下次允许尝试轮换的时刻（失败退避）

	wg sync.WaitGroup
}

// New 组装 Agent（cfg 必须已含 server/agent_id/credential；stateDir 存 agent.key/agent.crt/ca.crt）。
func New(cfg *config.Config, cfgPath, stateDir string, log *slog.Logger) (*Agent, error) {
	if cfg.AgentID == "" || cfg.Credential == "" || cfg.Server == "" {
		return nil, errors.New("配置缺少 server/agent_id/credential，请先执行 wdsp-agent enroll")
	}
	client, err := transport.New(cfg.Server, cfg.InsecureSkipVerify, Version)
	if err != nil {
		return nil, err
	}
	client.SetCredential(cfg.Credential)

	policy := cfg.EffectivePolicy()
	a := &Agent{
		cfg:          cfg,
		cfgPath:      cfgPath,
		log:          log,
		client:       client,
		localBackend: cfg.CaptureBackend,
		localSnaplen: cfg.CaptureSnaplen,
		startEpoch:   time.Now().Unix(),
	}

	// 机器身份（契约 §8/§12）：agent.key+agent.crt 均存在且匹配 → PoP 模式；
	// 缺失或损坏仅降级为 Bearer（Phase 1 老 Agent 无证书，需管理员重新注册方可升级）。
	mgr := cert.NewManager(
		filepath.Join(stateDir, cert.KeyFileName),
		filepath.Join(stateDir, cert.CertFileName),
		filepath.Join(stateDir, cert.CAFileName),
		nil,
	)
	switch id, err := mgr.Load(); {
	case err != nil:
		log.Warn("机器身份证书加载失败，按 Bearer 模式运行", "err", err)
	case id != nil:
		a.certMgr = mgr
		a.rotateBackoff = transport.NewBackoff(0, 0)
		client.SetIdentity(mgr.TransportIdentity())
		log.Info("机器身份证书已加载，启用 PoP 认证", "not_after", id.Cert.NotAfter)
	default:
		log.Info("无机器身份证书，按 Bearer 模式运行（老 Agent 不自动补证书；如需 PoP 模式请由管理员触发重新注册）")
	}
	a.filt = filter.New(portsToUint16(policy.Capture.Ports), policy.Capture.Direction)
	a.bucket = ratelimit.New(policy.Limits.OutboundMbps)
	a.replayBucket = ratelimit.New(a.replayShareMbps(policy))
	a.monitor = selfmon.NewMonitor(policy.Limits.CPUPercent, policy.Limits.MemoryMB)
	a.sampler = selfmon.NewProcSampler()

	bufCfg := policy.Buffer
	if !cfg.Buffer.Enabled {
		bufCfg.Enabled = false
	}
	a.buf, err = buffer.Open(config.DefaultBufferDir, buffer.DefaultSegmentBytes,
		int64(bufCfg.MaxSizeMB)<<20, time.Duration(bufCfg.MaxAgeMinutes)*time.Minute, bufCfg.Enabled)
	if err != nil {
		// 缓存不可用不致命：降级为无缓存运行（Fail-Open）
		log.Error("磁盘缓存初始化失败，降级为无缓存运行", "err", err)
		a.buf, _ = buffer.Open(config.DefaultBufferDir, buffer.DefaultSegmentBytes, 1, time.Minute, false)
	}

	a.flowQ = make(chan events.FlowEvent, flowQueueCap)
	a.httpQ = make(chan httpQItem, httpQueueCap)
	a.rawQ = make(chan events.PacketFrame, rawQueueCap)
	a.tracker = flow.NewTracker(cfg.AgentID, 0, 0, a.onFlowEvent, func() {
		a.metrics.Dropped.Add(1) // 流表满驱逐计数
		a.metrics.DropReason(DropReasonFlowTableFull, 1)
	})
	a.sensor = httpsensor.New(cfg.AgentID, a.filt.HasPort, a.onHTTPRecord, log)
	if cfg.K8s.Mode() != "off" {
		client, kerr := k8smeta.NewInCluster(os.Getenv("NODE_NAME"), os.Getenv("K8S_CLUSTER_NAME"), log)
		if kerr == nil {
			a.k8sResolver, a.k8sClient = k8smeta.NewResolver(), client
		} else if cfg.K8s.Mode() == "on" {
			log.Warn("Kubernetes 元数据已开启但集群凭据不可用，继续无元数据运行", "err", kerr)
		}
	}
	a.initPhase4()                   // Phase 4：背压帽/定向规则/生效等级/采样 接线
	a.mirror = a.newMirrorReceiver() // G2：Nginx mirror 接收器（默认关闭）
	a.tap = a.newTapSource()         // G3：Envoy tap 适配器（默认关闭）
	return a, nil
}

// Version 由 main 注入（避免循环依赖）。
var Version = "dev"

// Run 阻塞运行：控制循环 + 数据通道 + 自我保护，直到 ctx 取消。
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("wdsp-agent 启动",
		"version", Version, "agent_id", a.cfg.AgentID, "server", a.cfg.Server)

	// 初始应用策略（含抓包启动）
	a.applyPolicy(a.cfg.EffectivePolicy())
	a.startMirror() // G2：镜像接收器（默认关闭；启动失败 Fail-Open）
	a.startTap()    // G3：Envoy tap 适配器（默认关闭；Fail-Open）

	ctrl := control.New(control.Deps{
		Client:           a.client,
		Log:              a.log,
		AgentID:          a.cfg.AgentID,
		InitialInterval:  a.cfg.HeartbeatIntervalSeconds,
		StatusFn:         a.status,
		MetricsFn:        a.metricsSnapshot,
		AppliedVersionFn: a.appliedVersion,
		ApplyConfigFn:    a.applyServerConfig,
		SetEnabledFn:     a.setEnabled,
		OnConnectionFn:   a.onConnection,
		CheckRotateFn:    a.checkCertRotation,
		OnCapabilitiesFn: a.applyCapabilities,
	})

	workers := 5
	if a.k8sClient != nil {
		workers++
	}
	a.wg.Add(workers)
	go func() { defer a.wg.Done(); defer a.recover("control"); ctrl.Run(ctx) }()
	go func() { defer a.wg.Done(); defer a.recover("sender"); a.senderLoop(ctx) }()
	go func() { defer a.wg.Done(); defer a.recover("replay"); a.replayLoop(ctx) }()
	go func() { defer a.wg.Done(); defer a.recover("selfmon"); a.selfmonLoop(ctx) }()
	go func() { defer a.wg.Done(); defer a.recover("housekeep"); a.housekeepLoop(ctx) }()
	if a.k8sClient != nil {
		go func() { defer a.wg.Done(); defer a.recover("k8smeta"); a.k8sClient.Run(ctx, a.k8sResolver) }()
	}

	<-ctx.Done()
	a.log.Info("收到退出信号，优雅停机")
	a.shutdown()
	a.wg.Wait()
	return nil
}

// recover goroutine panic 护栏（Fail-Open：记录并退出该 goroutine，不拖垮进程）。
func (a *Agent) recover(name string) {
	if r := recover(); r != nil {
		a.log.Error("goroutine panic 已捕获（Fail-Open）", "goroutine", name, "panic", r)
	}
}

// shutdown 停抓并冲刷流表与缓存句柄。
func (a *Agent) shutdown() {
	a.stopMirror() // 先停镜像接收器（不再收新镜像请求）
	a.stopTap()    // 停止 tap 适配器（取消全部 tap 管理流）
	a.stopCaptures()
	a.sensor.Close() // 收尾 HTTP 会话（补发 response=null 记录）后再冲刷流表
	a.tracker.Close(time.Now())
	// 尝试把内存队列中残留事件落盘
	a.drainQueueToBuffer()
	_ = a.buf.Close()
}

// ── 抓包管理 ──────────────────────────────────────────────

// applyServerConfig 服务端配置应用入口（control 回调）：解析校验 + 持久化 + 生效。
// overrides 为 Phase 4 定向采集规则（契约 §2.4），随策略一并持久化快照。
func (a *Agent) applyServerConfig(policy *config.Policy, overrides []config.Override, version int64) error {
	a.cfgMu.Lock()
	a.cfg.Policy = policy
	a.cfg.Overrides = overrides
	a.cfg.AppliedConfigVersion = version
	err := a.cfg.Save(a.cfgPath)
	a.cfgMu.Unlock()
	if err != nil {
		return fmt.Errorf("配置持久化失败: %w", err)
	}
	a.applyPolicy(policy)
	return nil
}

// appliedVersion 本地已应用配置版本。
func (a *Agent) appliedVersion() int64 {
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	return a.cfg.AppliedConfigVersion
}

// replayShareMbps 补传公平预算折算的带宽份额（P1-03 §5.5）：
// 服务端策略下发优先，本地 agent.json buffer.replay_share_percent 显式配置覆盖
// （沿用 buffer.enabled 本地优先的既有口径）。
func (a *Agent) replayShareMbps(policy *config.Policy) float64 {
	share := policy.Buffer.EffectiveReplaySharePercent()
	if a.cfg.Buffer.ReplaySharePercent > 0 {
		share = a.cfg.Buffer.EffectiveReplaySharePercent()
	}
	return policy.Limits.OutboundMbps * float64(share) / 100
}

// applyPolicy 应用策略到各运行组件（重建或热更 capture）。
func (a *Agent) applyPolicy(policy *config.Policy) {
	if policy == nil {
		policy = config.DefaultPolicy()
	}
	// 采集等级（Phase 3 契约 §2 冻结语义）：L0 仅 flow 事件；L1/L2 启用 HTTP
	// 传感器；L3=L2+RAW 通道（outputMode 内附加）。服务端 /http 端点 404
	// 降级后按 L0 运行（契约 §10）。
	level := policy.EffectiveCaptureLevel()
	if a.httpGone.Load() {
		level = config.LevelL0
	}
	a.sensor.UpdatePolicy(level, policy.Limits.EffectiveMaxBodySize(), policy.Masking.Effective())
	if a.mirror != nil {
		// G2：镜像适配器与被动传感器同口径应用策略（等级门控/脱敏/正文上限），
		// 不绕过原采集策略（P1-03 §3.1）
		a.mirror.UpdatePolicy(level, policy.Limits.EffectiveMaxBodySize(), policy.Masking.Effective())
	}
	if a.tap != nil {
		// G3：tap 适配器同口径应用策略（不绕过原采集策略）
		a.tap.UpdatePolicy(level, policy.Limits.EffectiveMaxBodySize(), policy.Masking.Effective())
	}
	// Phase 4：基础等级缓存（生效等级=max(基础,规则) 后按背压帽 min 压制，
	// request 事件抑制由 flow 包按流生效等级驱动：≥L1 停发旧 request 事件）
	a.baseLevel.Store(int64(config.LevelRank(level)))
	// 策略采样（Phase 4 契约 §4）：enabled 且 rate∈(0,1) 才生效；
	// rate=1 等价关闭，rate≤0 或 >1 按关闭处理（管理端 400，Agent 侧防御）
	sampleRate := 0.0
	if policy.Sampling.Enabled && policy.Sampling.Rate > 0 && policy.Sampling.Rate < 1 {
		sampleRate = policy.Sampling.Rate
	}
	a.policySampleRate.Store(int64(math.Float64bits(sampleRate)))
	// 定向规则热更（整表替换，不重启抓包；非法规则跳过不阻断采集）
	a.cfgMu.Lock()
	ovs := append([]config.Override(nil), a.cfg.Overrides...)
	a.cfgMu.Unlock()
	a.overrides.Replace(ovs)
	a.bucket.SetRate(policy.Limits.OutboundMbps)
	if a.replayBucket != nil {
		a.replayBucket.SetRate(a.replayShareMbps(policy))
	}
	a.monitor.SetLimits(policy.Limits.CPUPercent, policy.Limits.MemoryMB)
	a.buf.UpdateLimits(int64(policy.Buffer.MaxSizeMB)<<20,
		time.Duration(policy.Buffer.MaxAgeMinutes)*time.Minute, policy.Buffer.Enabled)

	ports := portsToUint16(policy.Capture.Ports)
	if len(ports) == 0 {
		ports = portsToUint16(config.DefaultPorts)
	}
	a.filt.SetPorts(ports)
	a.filt.SetDirection(policy.Capture.Direction)

	ifaceSet := a.desiredInterfaces(policy)
	a.capMu.Lock()
	defer a.capMu.Unlock()
	if !a.captureAllowedLocked() {
		a.stopCapturesLocked()
		return
	}
	a.reconcileCapturesLocked(ifaceSet, capture.ResolveBackend(a.localBackend, policy.Capture.Backend), ports)
}

// reconcileCapturesLocked 后端名+接口集合一致 → 热更端口过滤；否则重建抓包后端。
func (a *Agent) reconcileCapturesLocked(ifaces []string, backendName string, ports []uint16) {
	if a.backend != nil && a.backendName == backendName && equalStrings(a.capIfaces, ifaces) {
		// 接口与后端未变：filter 已热更；eBPF 后端还需同步端口 map
		a.backend.SetPorts(ports)
		return
	}
	a.stopCapturesLocked()
	a.capIfaces = append([]string(nil), ifaces...)
	if len(ifaces) == 0 {
		a.log.Warn("无可用抓包接口，仅控制通道运行")
		return
	}
	sel, err := capture.StartBackend(backendName, capture.BackendConfig{
		Ifaces:   ifaces,
		Filter:   a.filt,
		Consumer: a.onPacket,
		Stats:    &a.capStats,
		Log:      a.log,
		Snaplen:  a.localSnaplen,
	})
	if err != nil {
		if errors.Is(err, capture.ErrUnsupported) {
			if !a.captureUnsupported.Swap(true) {
				a.log.Warn("该平台不支持抓包，仅控制通道运行", "backend", backendName)
			}
			return
		}
		a.log.Error("启动抓包后端失败（Fail-Open，仅控制通道运行）", "backend", backendName, "err", err)
		return
	}
	a.backend = sel.Backend
	a.backendName = sel.Name
	a.fallbackReason = sel.Reason
	if sel.Fallback {
		a.log.Warn("抓包后端回退", "requested", backendName, "effective", sel.Name, "reason", sel.Reason)
	}
	a.log.Info("抓包已启动", "ifaces", ifaces, "backend", sel.Name)
}

// stopCaptures 停抓包后端。
func (a *Agent) stopCaptures() {
	a.capMu.Lock()
	defer a.capMu.Unlock()
	a.stopCapturesLocked()
}

func (a *Agent) stopCapturesLocked() {
	if a.backend != nil {
		_ = a.backend.Close()
		a.backend = nil
	}
	a.backendName = ""
	a.fallbackReason = ""
	a.capIfaces = nil
}

// desiredInterfaces 目标接口集合（升序）；空配置=全部非 loopback 已发现接口。
func (a *Agent) desiredInterfaces(policy *config.Policy) []string {
	if len(policy.Capture.Interfaces) > 0 {
		out := append([]string(nil), policy.Capture.Interfaces...)
		sort.Strings(out)
		return out
	}
	ifaces, err := netif.Discover()
	if err != nil || len(ifaces) == 0 {
		if err != nil {
			a.log.Warn("网卡发现失败", "err", err)
		}
		return nil
	}
	out := make([]string, 0, len(ifaces))
	for _, i := range ifaces {
		out = append(out, i.Name)
	}
	sort.Strings(out)
	return out
}

// captureAllowedLocked 是否允许抓包（未被禁用且未降级）。
func (a *Agent) captureAllowedLocked() bool {
	return !a.disabledByServer.Load() && !a.degraded.Load()
}

// setEnabled desired_state 处置（DISABLED 停抓保心跳）。
func (a *Agent) setEnabled(enabled bool) {
	if a.disabledByServer.Swap(!enabled) == !enabled {
		return
	}
	if enabled {
		a.log.Info("服务端启用 Agent，恢复抓包")
	} else {
		a.log.Warn("服务端禁用 Agent，停止抓包（心跳继续）")
	}
	a.applyPolicy(a.currentPolicy())
}

// currentPolicy 当前策略快照。
func (a *Agent) currentPolicy() *config.Policy {
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	return a.cfg.EffectivePolicy()
}

// ── 数据通道 ──────────────────────────────────────────────

// onPacket 抓包消费回调（capture 层已解码过滤；注意 NoCopy 语义，RAW 入队需拷贝）。
//
// 采集决策统一走 flow.Track 返回的生效等级（Phase 4 决策链：基础等级 →
// overrides 提升 → 降级帽压制 → 采样过滤，见 phase4.go）。
func (a *Agent) onPacket(p capture.Packet) {
	a.metrics.Processed.Add(1)
	a.metrics.CaptureBytes.Add(uint64(p.OrigLen))
	if p.Truncated {
		a.metrics.TruncatedFrames.Add(1) // D-06：捕获不完整帧计数
	}

	mode := a.outputMode()
	if mode == "RAW" {
		// 纯 RAW 模式无 flow 概念（既有语义保持），不进入采集调制
		a.enqueueRaw(p)
		return
	}
	st := a.tracker.Track(flow.Packet{
		Ts: p.Ts, SrcIP: p.SrcIP, DstIP: p.DstIP,
		SrcPort: p.SrcPort, DstPort: p.DstPort,
		Ingress: p.Ingress, BothHit: p.BothHit, Length: p.OrigLen, Payload: p.Payload,
		FIN: p.FIN, RST: p.RST,
	})
	// HTTP 传感器按流生效等级调制：L1+ 且采样选中才重组（L0 流被规则提升
	// 后从当前包起建链，已过的不补）；帽压回落时终止既有连接（补发
	// response=null，已采集数据不丢）
	switch {
	case st.Visibility == httpparse.Encrypted:
		// TLS 加密流不进重组器：parseRequest 必失败，两个半流 goroutine 会
		// io.Copy(Discard) 钉到连接 EOF（长连接每条泄漏 2 个 goroutine）。
		// 若嗅探未决期间的首批包已建链，以 L0 终止释放。
		if st.SensorWanted {
			a.sensor.AssembleLevel(p, config.LevelL0)
		}
	case st.Sampled && st.Level >= 1:
		a.sensor.AssembleLevel(p, config.LevelName(st.Level))
	case st.SensorWanted:
		a.sensor.AssembleLevel(p, config.LevelL0)
	}
	// RAW 通道：显式 FLOW_RAW 或生效等级 L3（契约 §2：L3=L2+RAW 自动附加）；
	// 采样外 flow 不产生（仅 flow_end 计数，契约 §4）
	if st.Sampled && (mode == "FLOW_RAW" || st.Level >= 3) {
		a.enqueueRaw(p)
	}
}

// outputMode 当前输出模式（FLOW | RAW | FLOW_RAW）。
// Phase 3 契约 §2：capture_level=L3 且 output.mode 未含 RAW 时自动附加 RAW 通道；
// Phase 4 起自动附加改由流生效等级（st.Level>=3）在 onPacket 内判定，
// 本函数仅归一化 policy.output.mode 的显式配置。
func (a *Agent) outputMode() string {
	policy := a.currentPolicy()
	switch policy.Output.Mode {
	case "RAW", "FLOW_RAW":
		return policy.Output.Mode
	default:
		return "FLOW"
	}
}

// reserveQBytes 原子预留内存队列字节额度（check-then-act 合一：CAS 循环，
// 并发生产者无法突破 queueMaxBytes 硬上限）；失败返回 false。
func reserveQBytes(q *atomic.Int64, n, limit int64) bool {
	for {
		cur := q.Load()
		if cur+n > limit {
			return false
		}
		if q.CompareAndSwap(cur, cur+n) {
			return true
		}
	}
}

// enqueueRaw RAW 帧入队：限速桶满直接丢弃计数（契约 §6）；队列满丢弃计数。
func (a *Agent) enqueueRaw(p capture.Packet) {
	frameBytes := len(p.Frame) + 20
	if !a.bucket.Allow(frameBytes) {
		a.metrics.RawDropped.Add(1)
		a.metrics.Dropped.Add(1)
		a.metrics.DropReason(DropReasonRateLimited, 1)
		return
	}
	if !reserveQBytes(&a.rawQBytes, int64(frameBytes), queueMaxBytes) {
		a.metrics.RawDropped.Add(1)
		a.metrics.Dropped.Add(1)
		a.metrics.DropReason(DropReasonQueueFull, 1)
		return
	}
	frame := make([]byte, len(p.Frame))
	copy(frame, p.Frame) // NoCopy 语义：跨 goroutine 必须拷贝
	f := events.PacketFrame{Ts: p.Ts, OrigLen: uint32(p.OrigLen), Data: frame}
	select {
	case a.rawQ <- f:
	default:
		a.rawQBytes.Add(-int64(frameBytes)) // 入队失败回滚预留额度
		a.metrics.RawDropped.Add(1)
		a.metrics.Dropped.Add(1)
		a.metrics.DropReason(DropReasonQueueFull, 1)
	}
}

// onFlowEvent 流事件出口（tracker 回调）：入内存队列；满则尝试磁盘缓存。
func (a *Agent) onFlowEvent(ev events.FlowEvent) {
	if a.k8sResolver != nil {
		ev.K8s = a.k8sResolver.Resolve(ev.SrcIP, ev.DstIP)
	}
	select {
	case a.flowQ <- ev:
	default:
		a.bufferEvents([]events.FlowEvent{ev})
	}
}

// onHTTPRecord HTTP 记录出口（httpsensor 回调）：入内存队列；满则尝试磁盘缓存。
// 记录已在 httpsensor 内完成脱敏（离主机前唯一构造出口）。
func (a *Agent) onHTTPRecord(rec events.HTTPRecord) {
	if a.k8sResolver != nil {
		rec.K8s = a.k8sResolver.Resolve(rec.SrcIP, rec.DstIP)
	}
	est := estRecordBytes(rec)
	if !reserveQBytes(&a.httpQBytes, est, queueMaxBytes) {
		a.bufferHTTP([]events.HTTPRecord{rec})
		return
	}
	select {
	case a.httpQ <- httpQItem{rec: rec, est: est}:
	default:
		a.httpQBytes.Add(-est) // 入队失败回滚预留额度
		a.bufferHTTP([]events.HTTPRecord{rec})
	}
}

// estRecordBytes HTTP 记录序列化字节估算（队列 64MB 硬上限记账用）。
func estRecordBytes(rec events.HTTPRecord) int64 {
	n := int64(384 + len(rec.FlowID))
	for _, m := range []*events.HTTPMessage{rec.Request, rec.Response} {
		if m == nil {
			continue
		}
		n += int64(len(m.Method) + len(m.Host) + len(m.URI) + len(m.Body))
		for k, v := range m.Headers {
			n += int64(len(k) + len(v) + 8)
		}
	}
	return n
}

// bufferEvents FLOW 事件写磁盘缓存（桶满/断线/队列满路径）；缓存不可用则丢弃计数。
func (a *Agent) bufferEvents(evs []events.FlowEvent) {
	for _, ev := range evs {
		data, err := json.Marshal(ev)
		if err != nil {
			a.metrics.Dropped.Add(1)
			a.metrics.DropReason(events.DropUnserializable, 1)
			continue
		}
		if err := a.buf.Write(append([]byte{bufTagFlow}, data...)); err != nil {
			a.metrics.BufferFailed.Add(1)
			a.metrics.Dropped.Add(1)
			a.metrics.DropReason(DropReasonSpoolWriteFailed, 1)
			continue
		}
		a.metrics.FlowBuffered.Add(1)
	}
}

// bufferHTTP HTTP 记录写磁盘缓存（同 FLOW 管道；404 降级的记录不进缓存——
// 契约 §10 不进入补传死循环）。
func (a *Agent) bufferHTTP(recs []events.HTTPRecord) {
	for _, rec := range recs {
		data, err := json.Marshal(rec)
		if err != nil {
			a.metrics.Dropped.Add(1)
			a.metrics.DropReason(events.DropUnserializable, 1)
			continue
		}
		if err := a.buf.Write(append([]byte{bufTagHTTP}, data...)); err != nil {
			a.metrics.BufferFailed.Add(1)
			a.metrics.Dropped.Add(1)
			a.metrics.DropReason(DropReasonSpoolWriteFailed, 1)
			continue
		}
		a.metrics.HTTPBuffered.Add(1)
	}
}

// senderLoop 数据外发主循环（实时流量）。补传由独立 replayLoop 按公平预算
// 驱动（P1-03 §5.5：长期离线积压不饿死实时采集，补传不再阻塞本循环）。
// 取队列优先级（契约 §8）：flow 事件 > HTTP 记录 > RAW。
func (a *Agent) senderLoop(ctx context.Context) {
	flush := time.NewTicker(rawFlushInterval)
	defer flush.Stop()
	batch := make([]events.FlowEvent, 0, events.MaxEventsPerBatch)
	httpBatcher := events.NewHTTPBatcher(func(reason string) {
		a.metrics.DropReason(reason, 1)
		a.metrics.Dropped.Add(1)
	})
	batcher := events.NewPacketBatcher(0, func(n int) {
		a.metrics.RawDropped.Add(uint64(n))
		a.metrics.Dropped.Add(uint64(n))
		a.metrics.DropReason(DropReasonFrameOversize, uint64(n))
	})
	var mirrorBatch []events.HTTPRecordV2 // 镜像 v2 批（独立线格式，≤100 条冲刷）
	for {
		// 非阻塞优先取 flow，其次 http（桶满/发送压力时自然让 RAW 饥饿）
		select {
		case ev := <-a.flowQ:
			batch = append(batch, ev)
			if len(batch) >= events.MaxEventsPerBatch {
				a.sendFlowBatch(batch)
				batch = batch[:0]
			}
			continue
		default:
		}
		select {
		case item := <-a.httpQ:
			a.httpQBytes.Add(-item.est)
			if item.v2rec != nil {
				mirrorBatch = append(mirrorBatch, *item.v2rec)
				if len(mirrorBatch) >= events.MaxHTTPRecordsPerBatch {
					a.sendMirrorBatch(mirrorBatch)
					mirrorBatch = nil
				}
				continue
			}
			if !httpBatcher.Add(item.rec) {
				a.sendHTTPBatch(httpBatcher.Flush())
				httpBatcher.Add(item.rec) //nolint:errcheck // 新批次首条必成功（超限记录已在 Add 内缩减/丢弃）
			}
			continue
		default:
		}
		select {
		case <-ctx.Done():
			return
		case ev := <-a.flowQ:
			batch = append(batch, ev)
			if len(batch) >= events.MaxEventsPerBatch {
				a.sendFlowBatch(batch)
				batch = batch[:0]
			}
		case item := <-a.httpQ:
			a.httpQBytes.Add(-item.est)
			if item.v2rec != nil {
				mirrorBatch = append(mirrorBatch, *item.v2rec)
				if len(mirrorBatch) >= events.MaxHTTPRecordsPerBatch {
					a.sendMirrorBatch(mirrorBatch)
					mirrorBatch = nil
				}
				continue
			}
			if !httpBatcher.Add(item.rec) {
				a.sendHTTPBatch(httpBatcher.Flush())
				httpBatcher.Add(item.rec) //nolint:errcheck // 同上
			}
		case f := <-a.rawQ:
			a.rawQBytes.Add(-int64(len(f.Data) + 20))
			if !batcher.Add(f) {
				a.sendPacketBatch(batcher)
				batcher.Add(f) //nolint:errcheck // 新批次首帧必成功（帧长 ≤65535）
			}
		case <-flush.C:
			if len(batch) > 0 {
				a.sendFlowBatch(batch)
				batch = batch[:0]
			}
			a.sendHTTPBatch(httpBatcher.Flush())
			a.sendMirrorBatch(mirrorBatch)
			mirrorBatch = nil
			a.sendPacketBatch(batcher)
		}
	}
}

// replayLoop 磁盘缓存补传循环（P1-03 §5.5）：独立 goroutine + 独立公平预算
// 令牌桶（出站带宽 × replay_share_percent），与实时流量互不阻塞、互不饿死。
func (a *Agent) replayLoop(ctx context.Context) {
	t := time.NewTicker(rawFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !a.online.Load() || a.buf.Bytes() == 0 {
			continue
		}
		if a.httpRetryWait() > 0 {
			continue // 429 Retry-After 退避窗口内暂停补传
		}
		a.replayBuffer()
	}
}

// sendFlowBatch 限速 → 外发；桶满转缓存，失败转缓存（契约 §6）。
func (a *Agent) sendFlowBatch(batch []events.FlowEvent) {
	data, err := json.Marshal(events.FlowsRequest{Events: batch})
	if err != nil {
		a.log.Error("事件批序列化失败", "err", err)
		a.metrics.Dropped.Add(uint64(len(batch)))
		a.metrics.DropReason(events.DropUnserializable, uint64(len(batch)))
		return
	}
	if !a.bucket.Allow(len(data)) {
		a.bufferEvents(batch) // 桶满：FLOW 转磁盘缓存
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	accepted, err := a.client.PostFlows(ctx, a.cfg.AgentID, batch)
	cancel()
	if err != nil {
		a.log.Warn("flows 上报失败，转磁盘缓存", "events", len(batch), "err", err)
		a.bufferEvents(batch)
		return
	}
	a.metrics.Forwarded.Add(uint64(len(batch)))
	a.metrics.Accepted.Add(uint64(accepted))
	a.metrics.ForwardBytes.Add(uint64(len(data)))
}

// httpRetryWait 当前 429 Retry-After 退避剩余时长（无退避为 0）。
func (a *Agent) httpRetryWait() time.Duration {
	until := a.httpRetryUntil.Load()
	if until == 0 {
		return 0
	}
	d := time.Until(time.Unix(0, until))
	if d < 0 {
		return 0
	}
	return d
}

// setHTTPRetryAfter 记录 429 退避窗口（无 Retry-After 头时保守取 5s 默认）。
func (a *Agent) setHTTPRetryAfter(d time.Duration) {
	if d <= 0 {
		d = 5 * time.Second
	}
	a.httpRetryUntil.Store(time.Now().Add(d).UnixNano())
}

// sendHTTPBatch HTTP 记录批外发（契约 §3/§10 + P1-03 §4.2.4 错误分类 + v2 契约 §1/§4）：
//   - 协商生效集含 v2 → 按 v2 线格式发送（schema_version=2、稳定 event_id、
//     来源/协议/关联字段如实填充）；未协商 → 完全走旧 v1 路径；
//   - 429 Retry-After 窗口内：直接转缓存等待（不向服务端施压）；
//   - 限速桶满 / 5xx / 网络错误（可恢复）→ 转磁盘缓存（at-least-once）；
//   - 429 → 尊重 Retry-After 设置退避窗口后转缓存；
//   - 400/413/422（永久非法）：v2 响应携带 invalid_records → 按索引隔离丢弃
//     （permanent_invalid 计数）并重建剩余批次重发；v2 无索引定位 → 降级 v1
//     采集模式重发一次（未协商场景，契约 §1）；v1 无索引定位 → 二分隔离；
//     整批不再转缓存重放，杜绝「超限记录 → 400 → 转缓存 → 无限重放」死循环；
//   - 404（旧服务端无端点）→ 降级 L0、WARN、丢弃本批且不缓存。
func (a *Agent) sendHTTPBatch(recs []events.HTTPRecord) {
	if len(recs) == 0 {
		return
	}
	if a.httpGone.Load() {
		a.metrics.Dropped.Add(uint64(len(recs)))
		a.metrics.DropReason(DropReasonHTTPEndpointGone, uint64(len(recs)))
		return
	}
	if a.httpRetryWait() > 0 {
		a.bufferHTTP(recs) // 429 退避窗口内：转缓存等待
		return
	}
	v2 := a.httpV2.Load()
	var data []byte
	var err error
	if v2 {
		data, err = json.Marshal(events.NewHTTPBatchV2(a.cfg.AgentID, recs, a.sourceRef()))
	} else {
		data, err = json.Marshal(events.HTTPRequest{Records: recs})
	}
	if err != nil {
		a.log.Error("HTTP 记录批序列化失败", "err", err)
		a.metrics.Dropped.Add(uint64(len(recs)))
		a.metrics.DropReason(events.DropUnserializable, uint64(len(recs)))
		return
	}
	if !a.bucket.Allow(len(data)) {
		a.bufferHTTP(recs) // 桶满：转磁盘缓存
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	accepted, duplicate, invalid, err := a.postHTTP(ctx, recs, v2)
	cancel()
	if err != nil {
		a.handleHTTPSendError(recs, invalid, err)
		return
	}
	a.metrics.Forwarded.Add(uint64(len(recs)))
	a.metrics.Accepted.Add(uint64(accepted))
	if duplicate > 0 {
		a.metrics.Duplicate.Add(uint64(duplicate))
	}
	a.metrics.ForwardBytes.Add(uint64(len(data)))
}

// applyCapabilities 应用服务端回执的 HTTP 事件 schema 生效集（v2 契约 §3）；
// nil 回执 = 旧服务端无该字段 → 仅 v1（降级协商，双向忽略）。
func (a *Agent) applyCapabilities(caps *transport.Capabilities) {
	v2 := caps.HasSchemaVersion(events.HTTPRecordSchemaVersion)
	if a.httpV2.Swap(v2) == v2 {
		return
	}
	if v2 {
		a.log.Info("HTTP 事件 schema v2 协商生效，切换 v2 线格式上报",
			"effective", caps.HTTPEventSchemaVersions)
	} else {
		a.log.Info("HTTP 事件 schema 生效集不含 v2，按 v1 线格式上报")
	}
}

// sourceRef 本进程采集来源身份（G1 唯一适配器：被动 HTTP/1；source_epoch 取进程
// 启动时间，单调递增；实例标识缺省 default——受控配置项随 G2/G3 来源管理落地）。
func (a *Agent) sourceRef() events.SourceRef {
	return events.SourceRef{Type: events.SourcePassiveHTTP1, Epoch: a.startEpoch}
}

// postHTTP 按协商生效集选择 v2/v1 线格式发送（v1 路径无 invalid_records 概念）。
func (a *Agent) postHTTP(ctx context.Context, recs []events.HTTPRecord, v2 bool) (accepted, duplicate int, invalid []events.InvalidRecord, err error) {
	if v2 {
		batch := events.NewHTTPBatchV2(a.cfg.AgentID, recs, a.sourceRef())
		return a.client.PostHTTPV2(ctx, a.cfg.AgentID, batch.Records)
	}
	accepted, duplicate, err = a.client.PostHTTP(ctx, a.cfg.AgentID, recs)
	return accepted, duplicate, nil, err
}

// handleHTTPSendError 发送失败分类处置（sendHTTPBatch/replay 共用语义；
// v2 按 invalid_records 索引隔离，v1 保留二分隔离）。
func (a *Agent) handleHTTPSendError(recs []events.HTTPRecord, invalid []events.InvalidRecord, err error) {
	switch {
	case transport.IsNotFound(err):
		// 契约 §10：旧服务端无 /http 端点 → 降级为 L0 行为并 WARN，不再重试该端点
		a.httpGone.Store(true)
		a.log.Warn("服务端无 /http 端点（旧版本），HTTP 采集降级为 L0 行为，不再重试该端点", "records", len(recs))
		a.metrics.Dropped.Add(uint64(len(recs)))
		a.metrics.DropReason(DropReasonHTTPEndpointGone, uint64(len(recs)))
		a.applyPolicy(a.currentPolicy())
	case transport.IsPermanent(err) && len(invalid) > 0:
		a.isolateHTTPBatchByIndex(recs, invalid)
	case transport.IsPermanent(err) && a.httpV2.Swap(false):
		// v2 批次 400 但无非法记录定位：未协商/包络级拒绝（契约 §1）→ 降级 v1
		// 采集模式重发一次；v1 重发仍永久失败则落入下方二分隔离，不无限重试。
		a.log.Warn("v2 批次被服务端永久拒绝且无非法记录定位（可能未协商），降级 v1 采集模式重发",
			"records", len(recs), "err", err)
		a.sendHTTPBatch(recs)
	case transport.IsPermanent(err):
		a.isolateHTTPBatch(recs, err)
	case transport.IsTooManyRequests(err):
		d := transport.RetryAfterOf(err)
		a.setHTTPRetryAfter(d)
		a.log.Warn("http 上报被限速（429），尊重 Retry-After 退避", "records", len(recs), "retry_after", d)
		a.bufferHTTP(recs)
	default:
		a.log.Warn("http 上报失败，转磁盘缓存", "records", len(recs), "err", err)
		a.bufferHTTP(recs)
	}
}

// isolateHTTPBatchByIndex v2 永久非法批次按索引隔离（v2 契约 §4.4）：服务端返回
// 全部非法记录的可定位索引与原因——按索引丢弃计数（permanent_invalid），剩余记录
// 重建批次重发；批次级错误（index=-1）或越界索引无法定位时回退二分隔离。
func (a *Agent) isolateHTTPBatchByIndex(recs []events.HTTPRecord, invalid []events.InvalidRecord) {
	bad := make(map[int]string, len(invalid))
	for _, iv := range invalid {
		if iv.Index < 0 || iv.Index >= len(recs) {
			a.log.Warn("http v2 非法记录索引不可定位，回退二分隔离", "index", iv.Index, "reason", iv.Reason)
			a.isolateHTTPBatch(recs, errors.New(iv.Reason))
			return
		}
		bad[iv.Index] = iv.Reason
	}
	keep := make([]events.HTTPRecord, 0, len(recs)-len(bad))
	for i, rec := range recs {
		if reason, drop := bad[i]; drop {
			a.log.Warn("http 记录被服务端判定永久非法，按索引隔离丢弃",
				"flow_id", rec.FlowID, "reason", reason)
			a.metrics.Dropped.Add(1)
			a.metrics.DropReason(DropReasonPermanentInvalid, 1)
			continue
		}
		keep = append(keep, rec)
	}
	if len(keep) > 0 {
		a.sendHTTPBatch(keep) // 隔离后重建剩余批次重发（契约 §4.4）
	}
}

// isolateHTTPBatch 永久非法批次隔离（P1-03 §4.2.3）：二分拆分重建子批重发；
// 单条仍被判定永久非法 → 丢弃计数（dropped_by_reason=permanent_invalid），
// 不转缓存、不重放。递归深度 ≤ log2(100)≈7，子批遇可恢复错误转缓存后停止拆分。
func (a *Agent) isolateHTTPBatch(recs []events.HTTPRecord, cause error) {
	if len(recs) == 1 {
		a.log.Warn("http 记录被服务端判定永久非法，隔离丢弃",
			"flow_id", recs[0].FlowID, "err", cause)
		a.metrics.Dropped.Add(1)
		a.metrics.DropReason(DropReasonPermanentInvalid, 1)
		return
	}
	a.log.Warn("http 批次含永久非法记录，二分隔离重建", "records", len(recs), "err", cause)
	mid := len(recs) / 2
	a.sendHTTPBatch(recs[:mid])
	a.sendHTTPBatch(recs[mid:])
}

// sendPacketBatch RAW 批外发；失败直接丢弃计数（RAW 不缓存，设计 §17）。
func (a *Agent) sendPacketBatch(b *events.PacketBatcher) {
	frames := b.Len()
	body := b.Flush(time.Now())
	if body == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	_, err := a.client.PostPackets(ctx, a.cfg.AgentID, body)
	cancel()
	if err != nil {
		a.log.Warn("packets 上报失败，RAW 丢弃计数", "frames", frames, "err", err)
		a.metrics.RawDropped.Add(uint64(frames))
		a.metrics.Dropped.Add(uint64(frames))
		a.metrics.DropReason(DropReasonRateLimited, uint64(frames))
		return
	}
	a.metrics.Forwarded.Add(uint64(frames))
	a.metrics.ForwardBytes.Add(uint64(len(body)))
}

// replayBuffer 补传磁盘缓存（at-least-once；独立公平预算限速下逐批外发）。
// 缓存记录带类型标签（Phase 3 起）：F=flow 事件，H=HTTP 记录；无标签的旧版
// 缓存按 flow 事件解析。HTTP 记录按契约 §3 上限（≤100 条/≤8MB）重新分批；
// 补传中遇 /http 404 → 降级 L0 并丢弃该批 HTTP 记录（不进入补传死循环）；
// 遇 400/413/422 永久非法 → 二分隔离丢弃非法记录（其余照常补传）；
// 遇 429 → 尊重 Retry-After 暂停本轮。
func (a *Agent) replayBuffer() {
	// 公平预算桶（P1-03 §5.5）；nil 兜底兼容手工装配的测试 Agent
	bucket := a.replayBucket
	if bucket == nil {
		bucket = a.bucket
	}
	_, err := a.buf.Replay(events.MaxEventsPerBatch, func(recs [][]byte) error {
		evs := make([]events.FlowEvent, 0, len(recs))
		var https []events.HTTPRecord
		var mirrors []events.HTTPRecordV2
		size := 0
		for _, r := range recs {
			size += len(r)
			switch {
			case len(r) > 1 && r[0] == bufTagMirror:
				var rec events.HTTPRecordV2
				if err := json.Unmarshal(r[1:], &rec); err == nil {
					mirrors = append(mirrors, rec)
				}
			case len(r) > 1 && r[0] == bufTagHTTP:
				var rec events.HTTPRecord
				if err := json.Unmarshal(r[1:], &rec); err == nil {
					https = append(https, rec)
				}
			case len(r) > 1 && r[0] == bufTagFlow:
				var ev events.FlowEvent
				if err := json.Unmarshal(r[1:], &ev); err == nil {
					evs = append(evs, ev)
				}
			default: // 旧版无标签缓存（Phase 1/2）
				var ev events.FlowEvent
				if err := json.Unmarshal(r, &ev); err == nil {
					evs = append(evs, ev)
				}
			}
		}
		if len(evs) == 0 && len(https) == 0 && len(mirrors) == 0 {
			return nil
		}
		// 公平预算限速等待：最多等 ~5s；循环结束后必须复查——否则 50 次
		// Allow 全部失败后会落入正常发送（不限速照发）。仍不满足则返回错误
		// 暂停补传（本批保留在缓存，下轮继续）。补传消耗独立份额桶，
		// 不占用实时流量预算（§5.5 公平预算）。
		allowed := false
		for i := 0; i < replayWaitAttempts; i++ {
			if bucket.Allow(size) {
				allowed = true
				break
			}
			time.Sleep(replayWaitInterval)
		}
		if !allowed {
			return errReplayThrottled
		}
		if len(evs) > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			accepted, err := a.client.PostFlows(ctx, a.cfg.AgentID, evs)
			cancel()
			if err != nil {
				return err
			}
			a.metrics.Forwarded.Add(uint64(len(evs)))
			a.metrics.Accepted.Add(uint64(accepted))
		}
		// HTTP 记录按契约上限重新分批
		batcher := events.NewHTTPBatcher(func(reason string) {
			a.metrics.DropReason(reason, 1)
			a.metrics.Dropped.Add(1)
		})
		for _, rec := range https {
			if !batcher.Add(rec) {
				if err := a.replayHTTPBatch(batcher.Flush()); err != nil {
					return err
				}
				batcher.Add(rec) //nolint:errcheck // 新批次首条必成功（超限已在 Add 内缩减/丢弃）
			}
		}
		if err := a.replayHTTPBatch(batcher.Flush()); err != nil {
			return err
		}
		// 镜像 v2 记录按 ≤100 条重新分批补传（不降级 v1，避免来源误标）
		for len(mirrors) > 0 {
			n := len(mirrors)
			if n > events.MaxHTTPRecordsPerBatch {
				n = events.MaxHTTPRecordsPerBatch
			}
			if err := a.replayMirrorBatch(mirrors[:n]); err != nil {
				return err
			}
			mirrors = mirrors[n:]
		}
		a.metrics.ForwardBytes.Add(uint64(size))
		return nil
	})
	if err != nil {
		a.log.Warn("缓存补传中断", "err", err)
	}
}

// replayHTTPBatch 补传一批 HTTP 记录。返回 nil 表示本批已了结（全部接受，
// 或永久非法记录已隔离丢弃）可删段；返回错误保留该段下轮重试。
// 404 → 降级并丢弃（返回 nil）；429 → 设置 Retry-After 退避并暂停本轮；
// 400/413/422 → v2 按 invalid_records 索引隔离丢弃（其余照常补传），v1 二分隔离；
// v2 无索引定位的 400 → 降级 v1 重发本批（event_id 由记录内容派生，重放不变）。
func (a *Agent) replayHTTPBatch(recs []events.HTTPRecord) error {
	if len(recs) == 0 {
		return nil
	}
	if a.httpGone.Load() {
		a.metrics.Dropped.Add(uint64(len(recs)))
		a.metrics.DropReason(DropReasonHTTPEndpointGone, uint64(len(recs)))
		return nil
	}
	if a.httpRetryWait() > 0 {
		return errReplayBackoff // 429 退避窗口内暂停补传（本批保留）
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	accepted, duplicate, invalid, err := a.postHTTP(ctx, recs, a.httpV2.Load())
	cancel()
	if err != nil {
		switch {
		case transport.IsNotFound(err):
			a.httpGone.Store(true)
			a.log.Warn("补传遇 /http 404：服务端为旧版本，HTTP 采集降级为 L0 行为", "records", len(recs))
			a.metrics.Dropped.Add(uint64(len(recs)))
			a.metrics.DropReason(DropReasonHTTPEndpointGone, uint64(len(recs)))
			a.applyPolicy(a.currentPolicy())
			return nil
		case transport.IsPermanent(err) && len(invalid) > 0:
			return a.replayIsolateByIndex(recs, invalid)
		case transport.IsPermanent(err) && a.httpV2.Swap(false):
			// v2 补传 400 无索引定位（未协商/包络级拒绝）→ 降级 v1 重发本批一次
			a.log.Warn("v2 补传被服务端永久拒绝且无非法记录定位，降级 v1 重发", "records", len(recs), "err", err)
			return a.replayHTTPBatch(recs)
		case transport.IsPermanent(err):
			if len(recs) == 1 {
				a.log.Warn("补传记录被服务端判定永久非法，隔离丢弃",
					"flow_id", recs[0].FlowID, "err", err)
				a.metrics.Dropped.Add(1)
				a.metrics.DropReason(DropReasonPermanentInvalid, 1)
				return nil
			}
			mid := len(recs) / 2
			if err := a.replayHTTPBatch(recs[:mid]); err != nil {
				return err
			}
			return a.replayHTTPBatch(recs[mid:])
		case transport.IsTooManyRequests(err):
			d := transport.RetryAfterOf(err)
			a.setHTTPRetryAfter(d)
			a.log.Warn("补传被限速（429），尊重 Retry-After 暂停本轮", "records", len(recs), "retry_after", d)
			return errReplayBackoff
		default:
			return err
		}
	}
	a.metrics.Forwarded.Add(uint64(len(recs)))
	a.metrics.Accepted.Add(uint64(accepted))
	if duplicate > 0 {
		a.metrics.Duplicate.Add(uint64(duplicate))
	}
	return nil
}

// replayIsolateByIndex 补传批次按 v2 invalid_records 索引隔离（v2 契约 §4.4）：
// 非法记录丢弃计数后剩余继续补传；索引不可定位（批次级/越界）时回退二分隔离。
func (a *Agent) replayIsolateByIndex(recs []events.HTTPRecord, invalid []events.InvalidRecord) error {
	bad := make(map[int]string, len(invalid))
	for _, iv := range invalid {
		if iv.Index < 0 || iv.Index >= len(recs) {
			a.log.Warn("补传 v2 非法记录索引不可定位，回退二分隔离", "index", iv.Index, "reason", iv.Reason)
			if len(recs) == 1 {
				a.metrics.Dropped.Add(1)
				a.metrics.DropReason(DropReasonPermanentInvalid, 1)
				return nil
			}
			mid := len(recs) / 2
			if err := a.replayHTTPBatch(recs[:mid]); err != nil {
				return err
			}
			return a.replayHTTPBatch(recs[mid:])
		}
		bad[iv.Index] = iv.Reason
	}
	keep := make([]events.HTTPRecord, 0, len(recs)-len(bad))
	for i, rec := range recs {
		if reason, drop := bad[i]; drop {
			a.log.Warn("补传记录被服务端判定永久非法，按索引隔离丢弃",
				"flow_id", rec.FlowID, "reason", reason)
			a.metrics.Dropped.Add(1)
			a.metrics.DropReason(DropReasonPermanentInvalid, 1)
			continue
		}
		keep = append(keep, rec)
	}
	return a.replayHTTPBatch(keep)
}

// drainQueueToBuffer 停机时尽量把队列残留落盘。
func (a *Agent) drainQueueToBuffer() {
	for {
		select {
		case ev := <-a.flowQ:
			a.bufferEvents([]events.FlowEvent{ev})
		case item := <-a.httpQ:
			if item.v2rec != nil {
				a.bufferMirror([]events.HTTPRecordV2{*item.v2rec})
			} else {
				a.bufferHTTP([]events.HTTPRecord{item.rec})
			}
		default:
			return
		}
	}
}

// ── 自我保护 ──────────────────────────────────────────────

// selfmonLoop 每 10s 采样 CPU/RSS → 阈值状态机 → 降级/恢复。
func (a *Agent) selfmonLoop(ctx context.Context) {
	t := time.NewTicker(selfmon.DefaultInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s, err := a.sampler.Sample()
		if err != nil {
			continue // 采样失败（非 Linux /proc）跳过本次
		}
		a.lastCPU.Store(int64(float64bits(s.CPUPercent)))
		a.lastMem.Store(int64(float64bits(s.MemoryMB)))
		degraded, changed, reason := a.monitor.Check(s)
		if changed {
			a.degraded.Store(degraded)
			if degraded {
				a.log.Error("资源超阈值，停止抓包进入 DEGRADED（心跳继续）", "reason", reason)
			} else {
				a.log.Info("资源回落，恢复抓包", "reason", reason)
			}
			a.applyPolicy(a.currentPolicy())
		}
	}
}

// housekeepLoop 周期维护：流表扫描（空闲驱逐 + FIN 半关闭宽限）、内核丢包采集、缓存清理。
func (a *Agent) housekeepLoop(ctx context.Context) {
	sweep := time.NewTicker(flowSweepSec)
	kernel := time.NewTicker(kernelStatsSec)
	enforce := time.NewTicker(bufferEnforceSec)
	defer sweep.Stop()
	defer kernel.Stop()
	defer enforce.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sweep.C:
			a.tracker.Expire(time.Now())
			a.sensor.Sweep(time.Now(), flow.DefaultIdleTimeout)
			// Phase 4：背压水位采样驱动降级帽状态机；定向规则惰性清理
			a.checkBackpressure()
			a.overrides.Prune(time.Now())
		case <-kernel.C:
			a.pollKernelDrops()
		case <-enforce.C:
			a.buf.Enforce()
		}
	}
}

// pollKernelDrops 采集内核丢包。Backend.KernelStats 统一为「自上次调用起的
// 差值」语义（AF_PACKET PACKET_STATISTICS 读后即清零，pcapgo 同样按差值累加；
// eBPF 后端内部对累计计数差分），此处直接累加每次读数，不做二次差分。
func (a *Agent) pollKernelDrops() {
	a.capMu.Lock()
	defer a.capMu.Unlock()
	if a.backend == nil {
		return
	}
	_, drops, err := a.backend.KernelStats()
	if err != nil {
		return
	}
	a.capStats.KernelDrops.Add(uint64(drops))
}

// onConnection 控制通道连通状态回调。
func (a *Agent) onConnection(connected bool) {
	a.online.Store(connected)
	a.hbFailed.Store(!connected)
	if connected {
		a.log.Info("数据通道恢复，将优先补传磁盘缓存", "buffer_bytes", a.buf.Bytes())
	} else {
		a.metrics.SourceDisconnects.Add(1) // source_disconnect 指标（P1-03 §5.7）
	}
}

// checkCertRotation 证书轮换（契约 §9）：存活期过半后由控制循环每个心跳周期检查一次。
// 成功 → 原子替换 agent.key/agent.crt 并更新 agent.json 与 transport PoP 身份；
// 失败 → 指数退避重试，旧证书到期前持续可用。仅控制循环单 goroutine 调用。
func (a *Agent) checkCertRotation(ctx context.Context) {
	if a.certMgr == nil {
		return
	}
	now := time.Now()
	if now.Before(a.rotateNext) {
		return
	}
	if !a.certMgr.Due() {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	err := a.certMgr.Rotate(rctx, a.client, a.cfg.AgentID)
	cancel()
	if err != nil {
		d := a.rotateBackoff.Next()
		a.rotateNext = now.Add(d)
		if errors.Is(err, cert.ErrRollbackFailed) {
			// 回滚失败：磁盘可能处于钥/证不匹配死状态，Error 级显式上报
			a.log.Error("证书轮换回滚失败，磁盘钥证可能不匹配，需管理员触发重新注册", "retry_in", d, "err", err)
			return
		}
		a.log.Warn("证书轮换失败，退避重试（旧证书继续有效）", "retry_in", d, "err", err)
		return
	}
	a.rotateBackoff.Reset()
	a.rotateNext = time.Time{}
	id := a.certMgr.Identity()
	a.client.SetIdentity(a.certMgr.TransportIdentity())
	a.cfgMu.Lock()
	a.cfg.CertExpiresAt = id.Cert.NotAfter.UTC().Format(time.RFC3339)
	saveErr := a.cfg.Save(a.cfgPath)
	a.cfgMu.Unlock()
	if saveErr != nil {
		a.log.Error("轮换后配置持久化失败（新证书已生效，重启后仍将加载新证书文件）", "err", saveErr)
	}
	a.log.Info("机器身份证书已轮换", "not_after", id.Cert.NotAfter)
}

// status 心跳上报状态（契约 §3.2：ONLINE | DEGRADED | ERROR）。
// Phase 4 契约 §3.1：背压降级帽 < L3 时同为 DEGRADED（恢复 L3 后回 ONLINE）。
func (a *Agent) status() string {
	if a.degraded.Load() || (a.bp != nil && a.bp.Degraded()) {
		return "DEGRADED"
	}
	if a.hbFailed.Load() {
		return "ERROR"
	}
	return "ONLINE"
}

// metricsSnapshot 心跳 metrics 快照。
func (a *Agent) metricsSnapshot() transport.Metrics {
	a.capMu.Lock()
	backendName, fallbackReason := a.backendName, a.fallbackReason
	a.capMu.Unlock()
	m := a.metrics.snapshot(
		a.capStats.Received.Load(),
		a.capStats.KernelDrops.Load(),
		float64frombits(a.lastCPU.Load()),
		float64frombits(a.lastMem.Load()),
		len(a.flowQ)+len(a.httpQ)+len(a.rawQ),
		a.buf.Bytes(),
		backendName,
		fallbackReason,
	)
	// Phase 4 契约 §3.1：帽 < L3 上报 backpressure_cap；累计降级次数 >0 上报
	if a.bp != nil {
		if a.bp.Degraded() {
			m.BackpressureCap = a.bp.Cap()
		}
		if ev := a.bp.Events(); ev > 0 {
			m.BackpressureEvents = ev
		}
	}
	// P1-03 §5.7 统一指标：received=PacketsReceived、queued=QueueDepth 沿用既有
	// 字段；dropped_by_reason 合并管线分账与缓存段级淘汰/损坏计数（后者键名
	// spool_segments_<reason> / spool_bytes_corrupt，单位为段/字节）。
	m.Normalized = a.sensor.Stats.RecordsEmitted.Load()
	m.Masked = a.sensor.Stats.MaskedFields.Load()
	if a.mirror != nil {
		// G2：镜像来源计数并入统一指标（normalized/masked 含镜像记录）
		m.Normalized += a.mirror.Stats.Emitted.Load()
		m.Masked += a.mirror.MaskedFieldCount()
	}
	if a.tap != nil {
		// G3：tap 来源计数并入统一指标；tap 管理流断连计入 source_disconnect
		m.Normalized += a.tap.Stats.Emitted.Load()
		m.Masked += a.tap.MaskedFieldCount()
		m.SourceDisconnects += a.tap.Stats.Disconnects.Load()
	}
	m.Accepted = a.metrics.Accepted.Load()
	m.Duplicate = a.metrics.Duplicate.Load()
	m.SourceDisconnects = a.metrics.SourceDisconnects.Load()
	m.AssociationPending = a.sensor.Conns()
	m.SpoolBytes = m.BufferBytes
	m.OldestAgeSec = a.buf.OldestAge(time.Now()).Seconds()
	merged := a.metrics.dropReasonsSnapshot()
	bs := a.buf.Stats()
	for reason, n := range bs.DroppedSegments {
		if n <= 0 {
			continue
		}
		if merged == nil {
			merged = make(map[string]uint64)
		}
		merged["spool_segments_"+reason] += uint64(n)
	}
	if bs.CorruptSegments > 0 {
		if merged == nil {
			merged = make(map[string]uint64)
		}
		merged["spool_segments_"+buffer.ReasonCorrupt] += uint64(bs.CorruptSegments)
	}
	if n := bs.DroppedBytes[buffer.ReasonCorrupt]; n > 0 {
		if merged == nil {
			merged = make(map[string]uint64)
		}
		merged["spool_bytes_"+buffer.ReasonCorrupt] += uint64(n)
	}
	if rj := a.sensor.Stats.ConnsRejected.Load(); rj > 0 {
		if merged == nil {
			merged = make(map[string]uint64)
		}
		merged[DropReasonReassemblyConnFull] += rj
	}
	m.DroppedByReason = merged
	// G4b：k8smeta 健康接入心跳 metrics（server 端 jsonb 透传，管理端 Agent 详情可见）。
	// 元数据失效不影响采集本身，故不改动 status 的 ONLINE/DEGRADED/ERROR 判定，
	// 由 k8smeta_state 显式表达 STALE/UNAVAILABLE。
	if a.k8sResolver != nil {
		h := a.k8sResolver.Health()
		m.K8sMetaState = string(h.State)
		m.K8sMetaEntries = h.Entries
		m.K8sMetaInferredOwners = h.InferredOwners
		m.K8sMetaSyncFailures = h.SyncFailures
		if h.State != k8smeta.StateOK {
			m.K8sMetaStaleSeconds = h.StaleFor.Seconds()
		}
	} else {
		a.cfgMu.Lock()
		k8sForced := a.cfg.K8s.Mode() == "on"
		a.cfgMu.Unlock()
		if k8sForced {
			// 显式开启但集群凭据不可用：显式 UNAVAILABLE，不静默缺省
			m.K8sMetaState = string(k8smeta.StateUnavailable)
		}
	}
	return m
}

func portsToUint16(ports []int) []uint16 {
	out := make([]uint16, 0, len(ports))
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			out = append(out, uint16(p))
		}
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// float64bits/frombits 供 atomic.Int64 存取浮点。
func float64bits(f float64) uint64 { return math.Float64bits(f) }
func float64frombits(b int64) float64 {
	return math.Float64frombits(uint64(b))
}
