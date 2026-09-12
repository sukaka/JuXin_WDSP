// Package mirrorsrc Nginx TLS 终止后 mirror 子请求接收适配器（P1-03 §3.2，G2）。
//
// 边界红线：
//   - 纯接收器：不反向代理任何请求，不向任何地方转发业务流量；镜像接收器
//     的响应与 Nginx 业务响应完全无关（Nginx mirror 忽略子请求响应），
//     记录中 response/response_ts/latency_ms 恒为 null，缺失原因
//     SOURCE_REQUEST_ONLY（单向源）；
//   - 默认仅本机接入：Unix Socket（默认，0600，可配置属组）或 loopback TCP
//     （显式校验回环地址，拒绝 wildcard/非回环绑定）；开放远程监听不属于
//     默认部署；
//   - 伪造防护：写入方必须携带与本地配置一致的固定采集实例标识头
//     （X-WDSP-Mirror-Instance，由 Nginx 侧 proxy_set_header 覆盖注入，
//     常量时间比较）；所有 x-wdsp-* 控制命名空间头部在采集前剥离，绝不入
//     记录；X-Forwarded-For/X-Real-IP 等外部头仅作为普通数据头采集，绝不
//     用于记录五元组或身份判定（五元组取镜像连接的真实对端）；
//   - 脱敏：请求消息经 httpsensor.MaskedRequestMessage 构造——与被动
//     HTTP/1 传感器同一脱敏/Body 后处理出口，无第二条脱敏路径；
//   - 资源有界：连接数、Header 存储量、正文捕获、读写时限全部有上限；
//     任何单请求异常只丢弃该条记录并计数，不影响其他请求与进程。
package mirrorsrc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/httpsensor"
)

// HeaderInstance 固定采集实例标识头（Nginx 配置以 proxy_set_header 覆盖注入；
// 客户端同名头在 mirror 子请求中被覆盖，直连伪造者不持有令牌即被拒）。
const HeaderInstance = "X-WDSP-Mirror-Instance"

// HeaderOriginalBodySize 原始正文大小控制头（可信内部通道）：元数据镜像路径
// 下 Nginx 清空子请求 Content-Length（防止接收端等待不存在的正文），原始正文
// 大小由 Nginx 经本头传递。仅在令牌校验通过后、且子请求自身无正文长度时采用；
// 与全部 x-wdsp-* 控制头一样在采集前剥离，绝不入记录。
const HeaderOriginalBodySize = "X-WDSP-Original-Body-Size"

// headerControlPrefix 控制命名空间前缀：采集前整体剥离，永不入记录。
const headerControlPrefix = "x-wdsp-"

// CapabilitiesVersion 采集源能力版本（与 policy_version / Agent build 分开记录）。
const CapabilitiesVersion = "nginx-mirror/1"

// 默认值与硬上限（P1-03 §5.1：连接数/正文/时限有界）。
const (
	DefaultSocketPath       = "/var/run/wdsp-agent/nginx-mirror.sock"
	defaultMaxBodyBytes     = 64 << 10 // 镜像正文默认上限（仅显式开启正文时生效）
	DefaultMaxConns         = 64
	maxHeaderStoreBytes     = 16 << 10 // Header 存储总量钳（与 httpsensor 契约 §4 同口径）
	maxConnsHard            = 1024
	defaultReadHeaderTimout = 5 * time.Second
	defaultReadTimeout      = 60 * time.Second
	defaultWriteTimeout     = 5 * time.Second
	defaultIdleTimeout      = 30 * time.Second
	shutdownTimeout         = 5 * time.Second
)

// Config 镜像接收器配置（本地 agent.json mirror 段；默认关闭，显式启用）。
type Config struct {
	// SocketPath Unix Socket 路径（首选接入方式；非空时忽略 ListenAddr）。
	SocketPath string
	// ListenAddr TCP 监听地址（仅允许回环地址，如 127.0.0.1:9080；其他一律拒绝）。
	ListenAddr string
	// SocketMode Unix Socket 权限（默认 0600）。
	SocketMode os.FileMode
	// SocketGroup 可选属组（如 "nginx"：Nginx worker 需写 socket 时配合 0660）。
	SocketGroup string
	// SourceInstance 受控采集实例标识（必填；≤255 字符；非 Agent 身份，不可用于认证）。
	SourceInstance string
	// InstanceToken 固定采集实例标识令牌（必填；X-WDSP-Mirror-Instance 期望取值，
	// 本地共享秘密，用于拒绝伪造写入方）。
	InstanceToken string
	// TLSTerminated 部署断言：本接收器仅接可信 TLS 终止点（模板锁定拓扑）后镜像
	// → tls_visibility=DECRYPTED；缺省 false=PLAINTEXT。不得由外部 Header 决定。
	TLSTerminated bool
	// BodyEnabled 正文采集总开关（默认 false=仅元数据；正文另受策略等级 L2 与
	// MaxBodySize 钳制，与被动采集同口径）。
	BodyEnabled bool
	// MaxBodyBytes 正文捕获上限（≤0 取默认 64KB；硬上限 config.HardMaxBodySize）。
	MaxBodyBytes int
	// MaxConns 并发连接硬上限（≤0 取默认 64；硬上限 1024）。
	MaxConns int
	// 时限（≤0 取默认值）。
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

// Stats 接收器计数（agent 聚合观测；全部原子操作）。
type Stats struct {
	Received      atomic.Uint64 // 收到的镜像请求数（含被拒绝）
	Emitted       atomic.Uint64 // 产出的 v2 记录数
	Forbidden     atomic.Uint64 // 实例标识校验失败拒绝数（伪造/直连防御）
	HeaderClamped atomic.Uint64 // Header 总量超钳次数
	ConnsRejected atomic.Uint64 // 连接数超限拒绝数

	sensorStats httpsensor.Stats // 脱敏字段计数（masked 指标，复用 httpsensor 出口）
}

// Receiver 镜像接收器。
type Receiver struct {
	cfg      Config
	agentID  string
	epoch    int64 // 来源重启代次（进程启动 Unix 秒，单调递增）
	log      *slog.Logger
	onRecord func(events.HTTPRecordV2)

	policy atomic.Pointer[httpsensor.Policy]
	Stats  Stats

	srv     *http.Server
	ln      net.Listener
	sem     chan struct{} // 连接数信号量（有界）
	seq     atomic.Uint64 // flow_id 序号（同 agent+instance+ts 下唯一）
	started atomic.Bool
}

// New 创建接收器（校验配置；onRecord 必须非阻塞快速返回）。
func New(agentID string, cfg Config, onRecord func(events.HTTPRecordV2), log *slog.Logger) (*Receiver, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.SourceInstance == "" || len(cfg.SourceInstance) > 255 {
		return nil, errors.New("mirrorsrc: source_instance 必填且 ≤255 字符")
	}
	if cfg.InstanceToken == "" {
		return nil, errors.New("mirrorsrc: instance_token 必填（伪造写入方防护）")
	}
	if cfg.SocketPath == "" && cfg.ListenAddr == "" {
		cfg.SocketPath = DefaultSocketPath
	}
	if cfg.SocketPath != "" && cfg.ListenAddr != "" {
		return nil, errors.New("mirrorsrc: socket_path 与 listen_addr 只能配置其一")
	}
	if cfg.ListenAddr != "" {
		if err := validateLoopback(cfg.ListenAddr); err != nil {
			return nil, err
		}
	}
	if cfg.SocketMode == 0 {
		cfg.SocketMode = 0o600
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = defaultMaxBodyBytes
	}
	if cfg.MaxBodyBytes > config.HardMaxBodySize {
		cfg.MaxBodyBytes = config.HardMaxBodySize
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.MaxConns > maxConnsHard {
		cfg.MaxConns = maxConnsHard
	}
	if cfg.ReadHeaderTimeout <= 0 {
		cfg.ReadHeaderTimeout = defaultReadHeaderTimout
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = defaultReadTimeout
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = defaultWriteTimeout
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	r := &Receiver{
		cfg:      cfg,
		agentID:  agentID,
		epoch:    time.Now().Unix(),
		log:      log,
		onRecord: onRecord,
		sem:      make(chan struct{}, cfg.MaxConns),
	}
	// 默认仅元数据（L1）+ 契约默认脱敏，待策略热更
	r.policy.Store(&httpsensor.Policy{
		Level:       config.LevelL1,
		MaxBodySize: config.DefaultMaxBodySize,
		Masking:     config.DefaultMasking(),
	})
	return r, nil
}

// validateLoopback 校验监听地址为回环（拒绝 wildcard 与非回环绑定——
// 开放远程采集监听不属于默认部署，需另行 ADR）。
func validateLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("mirrorsrc: listen_addr 非法: %w", err)
	}
	if host == "" {
		return errors.New("mirrorsrc: listen_addr 禁止 wildcard 绑定（仅允许回环地址）")
	}
	if p, err := strconv.Atoi(port); err != nil || p < 0 || p > 65535 {
		return errors.New("mirrorsrc: listen_addr 端口非法")
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("mirrorsrc: listen_addr 仅允许回环地址（拒绝 %q）", host)
	}
	return nil
}

// UpdatePolicy 热更采集策略（与被动传感器同口径整表替换；等级门控 Body、
// MaxBodySize 与脱敏规则即时生效）。mirror 适配器不得绕过原采集策略。
func (r *Receiver) UpdatePolicy(level string, maxBodySize int, masking config.Masking) {
	if maxBodySize <= 0 {
		maxBodySize = config.DefaultMaxBodySize
	}
	if maxBodySize > config.HardMaxBodySize {
		maxBodySize = config.HardMaxBodySize
	}
	r.policy.Store(&httpsensor.Policy{Level: level, MaxBodySize: maxBodySize, Masking: masking})
}

// Start 启动监听（Unix Socket 或回环 TCP）。幂等；失败返回错误（调用方 Fail-Open 降级）。
func (r *Receiver) Start() error {
	if !r.started.CompareAndSwap(false, true) {
		return errors.New("mirrorsrc: 接收器已启动")
	}
	ln, err := r.listen()
	if err != nil {
		r.started.Store(false)
		return err
	}
	r.ln = ln
	r.srv = &http.Server{
		Handler:           r,
		MaxHeaderBytes:    64 << 10, // 线上头部块硬上限（超出由 http.Server 拒绝）
		ReadHeaderTimeout: r.cfg.ReadHeaderTimeout,
		ReadTimeout:       r.cfg.ReadTimeout,
		WriteTimeout:      r.cfg.WriteTimeout,
		IdleTimeout:       r.cfg.IdleTimeout,
	}
	go func() {
		if err := r.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			r.log.Error("mirrorsrc 监听异常退出（Fail-Open，不影响其他采集）", "err", err)
		}
	}()
	r.log.Info("mirrorsrc 镜像接收器已启动",
		"addr", ln.Addr().String(), "source_instance", r.cfg.SourceInstance,
		"tls_terminated", r.cfg.TLSTerminated, "body_enabled", r.cfg.BodyEnabled,
		"max_conns", r.cfg.MaxConns, "max_body_bytes", r.cfg.MaxBodyBytes)
	return nil
}

// listen 建立监听（Unix Socket：清理陈旧 socket 文件、设置权限与可选属组）。
func (r *Receiver) listen() (net.Listener, error) {
	if r.cfg.ListenAddr != "" {
		ln, err := net.Listen("tcp", r.cfg.ListenAddr)
		if err != nil {
			return nil, fmt.Errorf("mirrorsrc: 监听 %s 失败: %w", r.cfg.ListenAddr, err)
		}
		// 防御性复核实际绑定地址（防解析差异）
		if ta, ok := ln.Addr().(*net.TCPAddr); !ok || !ta.IP.IsLoopback() {
			_ = ln.Close()
			return nil, errors.New("mirrorsrc: 实际绑定地址非回环，拒绝启动")
		}
		return ln, nil
	}
	path := r.cfg.SocketPath
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("mirrorsrc: %s 已存在且非 socket，拒绝覆盖", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("mirrorsrc: 清理陈旧 socket 失败: %w", err)
		}
	}
	if dir := filepath.Dir(path); dir != "" {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("mirrorsrc: socket 目录 %s 不存在（请由部署侧以 0700 预建）", dir)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("mirrorsrc: 监听 unix %s 失败: %w", path, err)
	}
	if err := os.Chmod(path, r.cfg.SocketMode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("mirrorsrc: 设置 socket 权限失败: %w", err)
	}
	if r.cfg.SocketGroup != "" {
		g, err := user.LookupGroup(r.cfg.SocketGroup)
		if err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("mirrorsrc: 属组 %q 不存在: %w", r.cfg.SocketGroup, err)
		}
		gid, err := strconv.Atoi(g.Gid)
		if err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("mirrorsrc: 属组 %q GID 非法: %w", r.cfg.SocketGroup, err)
		}
		if err := os.Chown(path, -1, gid); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("mirrorsrc: 设置 socket 属组失败: %w", err)
		}
	}
	return ln, nil
}

// Shutdown 优雅停机（有关闭时限）；Unix Socket 路径仅删除本接收器创建的文件。
func (r *Receiver) Shutdown(ctx context.Context) {
	if !r.started.Load() {
		return
	}
	if r.srv != nil {
		cctx, cancel := context.WithTimeout(ctx, shutdownTimeout)
		_ = r.srv.Shutdown(cctx)
		cancel()
	}
	if r.cfg.SocketPath != "" && r.ln != nil {
		if fi, err := os.Lstat(r.cfg.SocketPath); err == nil && fi.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(r.cfg.SocketPath)
		}
	}
	r.started.Store(false)
}

// MaskedFieldCount 脱敏字段累计数（masked 指标，P1-03 §5.7）。
func (r *Receiver) MaskedFieldCount() uint64 { return r.Stats.sensorStats.MaskedFields.Load() }

// ── 请求处理 ──────────────────────────────────────────────

// ServeHTTP 接收 Nginx mirror 子请求副本。任何请求一律 204（镜像接收器响应
// 与业务无关且被 Nginx 忽略）；标识校验失败 403。绝不反向代理。
func (r *Receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			r.log.Error("mirrorsrc 处理 panic 已捕获（Fail-Open）", "panic", rec)
		}
	}()
	r.Stats.Received.Add(1)

	// 连接数有界（信号量在 ConnState 之外的兜底：handler 维度限流）
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	default:
		r.Stats.ConnsRejected.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	// 伪造写入方防护：固定采集实例标识必须恰好一个且与本地配置一致
	// （常量时间比较；Nginx 侧 proxy_set_header 覆盖客户端同名头）。
	tokens := req.Header.Values(HeaderInstance)
	if len(tokens) != 1 ||
		subtle.ConstantTimeCompare([]byte(tokens[0]), []byte(r.cfg.InstanceToken)) != 1 {
		r.Stats.Forbidden.Add(1)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	rec := r.normalize(req)
	if r.onRecord != nil {
		r.Stats.Emitted.Add(1)
		r.onRecord(rec)
	}
	w.WriteHeader(http.StatusNoContent)
}

// normalize 规范化镜像请求为 v2 记录（脱敏经 httpsensor 同一出口；
// response/response_ts/latency_ms 恒 null，association_reason=SOURCE_REQUEST_ONLY）。
func (r *Receiver) normalize(req *http.Request) events.HTTPRecordV2 {
	now := time.Now()
	pol := r.policy.Load()

	headers := captureHeaders(req, &r.Stats)
	host := req.Host
	if h := headers["host"]; h != "" && !strings.EqualFold(h, host) {
		// Host 与头块冲突不静默覆盖（契约 §4.1）：以请求行 Host 为准，头块值移除
		delete(headers, "host")
	}

	raw, wireSize, knownTotal, truncated := r.captureBody(req, pol)
	if req.ContentLength <= 0 {
		// 元数据镜像：子请求无正文长度（Content-Length 被 Nginx 清空），
		// 原始正文大小取可信控制头（令牌校验已过；客户端伪造值已被 Nginx 覆盖）
		if v, err := strconv.ParseInt(strings.TrimSpace(req.Header.Get(HeaderOriginalBodySize)), 10, 64); err == nil && v >= 0 {
			wireSize = v
			knownTotal = true
		}
	}

	// 五元组取镜像连接真实对端（外部头不得用于身份/拓扑判定）
	srcIP, srcPort, dstIP, dstPort := peerTuple(req, r.ln)

	visibility := events.VisibilityPlaintext
	if r.cfg.TLSTerminated {
		// DECRYPTED 依据：本地配置断言的可信终止点拓扑（模板锁定同机 socket/
		// 回环接入），非外部 Header
		visibility = "DECRYPTED"
	}

	msg := httpsensor.MaskedRequestMessage(httpsensor.MaskedRequestInput{
		Method:    req.Method,
		Host:      host,
		URI:       req.URL.RequestURI(),
		Headers:   headers,
		RawBody:   raw,
		WireSize:  wireSize,
		Truncated: truncated,
	}, pol, &r.Stats.sensorStats)

	v1 := events.HTTPRecord{
		FlowID: fmt.Sprintf("%s-mirror-%s-%d-%d",
			r.agentID, r.cfg.SourceInstance, now.UnixMilli(), r.seq.Add(1)),
		RequestTS:     float64(now.UnixMilli()) / 1000,
		SrcIP:         srcIP,
		SrcPort:       srcPort,
		DstIP:         dstIP,
		DstPort:       dstPort,
		Direction:     "ingress",
		TLSVisibility: visibility,
		Request:       msg,
		// Response/ResponseTS/LatencyMs 恒 null：单向源不观测业务响应，
		// 镜像接收器状态码与业务延迟不得回填
	}
	out := events.NewHTTPRecordV2(r.agentID, v1, events.SourceRef{
		Type:                events.SourceNginxMirror,
		Instance:            r.cfg.SourceInstance,
		Epoch:               r.epoch,
		CapabilitiesVersion: CapabilitiesVersion,
		ObservedHTTPVersion: observedProto(req),
		RequestOnly:         true,
	})
	// 原始 Body 总大小不可确认（chunked 且未读尽/读取中断）时
	// body_quality.original_total_size 保持 null（不得填 0）；契约 V1.1 起
	// truncated 如实保留（truncated=true + null 表达「截断但总大小未知」），
	// 已捕获字节数 captured_bytes 如实保留。
	if !knownTotal {
		out.Request.BodyQuality.OriginalTotalSize = nil
	}
	return out
}

// captureHeaders 采集头块：小写规范化、同名多值 ", " 连接（与 httpsensor 契约 §3
// map 形态一致）、剥离全部 x-wdsp-* 控制命名空间头、存储总量钳 16KB。
// X-Forwarded-For 等外部头仅作普通数据采集（脱敏规则照常适用）。
func captureHeaders(req *http.Request, stats *Stats) map[string]string {
	out := make(map[string]string, len(req.Header))
	stored := 0
	clamped := false
	// 遍历顺序确定性非必须（map 形态输出）；同名多值保留全部值
	names := make([]string, 0, len(req.Header))
	for name := range req.Header {
		names = append(names, name)
	}
	for _, name := range names {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, headerControlPrefix) {
			continue // 控制命名空间剥离，含 X-WDSP-Mirror-Instance 本身
		}
		value := strings.Join(req.Header.Values(name), ", ")
		need := len(lower) + len(value) + 4
		if stored+need > maxHeaderStoreBytes {
			clamped = true
			continue
		}
		stored += need
		out[lower] = value
	}
	if clamped && stats != nil {
		stats.HeaderClamped.Add(1)
	}
	return out
}

// captureBody 读取镜像请求正文（有界）：仅在本地总开关与策略等级（L2+）同时
// 允许时驻留字节；超限截断；读取中断（客户端取消/子请求中止）保留已读部分
// 并标记截断。返回：捕获字节、线上原始总大小、总大小是否可确认、是否截断。
func (r *Receiver) captureBody(req *http.Request, pol *httpsensor.Policy) (raw []byte, wireSize int64, knownTotal, truncated bool) {
	knownTotal = req.ContentLength >= 0
	if knownTotal {
		wireSize = req.ContentLength
	}
	if req.Body == nil || req.ContentLength == 0 {
		return nil, wireSize, knownTotal, false
	}
	if !r.cfg.BodyEnabled || config.LevelRank(pol.Level) < 2 {
		// 仅元数据：不驻留正文（排空由 http.Server 连接收尾处理；限时至多有界）
		return nil, wireSize, knownTotal, false
	}
	limit := int64(r.cfg.MaxBodyBytes)
	if int64(pol.MaxBodySize) < limit {
		limit = int64(pol.MaxBodySize)
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, limit+1))
	if int64(len(data)) > limit {
		truncated = true
		data = data[:limit]
	}
	if err != nil {
		// 子请求中止/连接断开：已读部分仍上报（partial），总大小除非 CL 已知否则不可确认
		truncated = true
	}
	if !knownTotal && !truncated {
		wireSize = int64(len(data)) // chunked 完整读尽：总大小=实际读取量
		knownTotal = true
	}
	return data, wireSize, knownTotal, truncated
}

// peerTuple 镜像连接真实五元组（Unix Socket 无地址语义，以回环占位并记端口 0）。
func peerTuple(req *http.Request, ln net.Listener) (string, uint16, string, uint16) {
	dstIP, dstPort := "127.0.0.1", uint16(0)
	if ln != nil {
		if ta, ok := ln.Addr().(*net.TCPAddr); ok {
			dstIP, dstPort = ta.IP.String(), uint16(ta.Port)
		}
	}
	srcIP, srcPort := "127.0.0.1", uint16(0)
	if host, port, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			srcIP = ip.String()
		}
		if p, err := strconv.Atoi(port); err == nil && p >= 0 && p <= 65535 {
			srcPort = uint16(p)
		}
	}
	return srcIP, srcPort, dstIP, dstPort
}

// observedProto 观测协议（Nginx→接收器的子请求协议，v2 契约枚举 1.0/1.1/2/3/UNKNOWN）。
// 原客户端协议不在此推断（original_http_version 保持 null）。
func observedProto(req *http.Request) string {
	switch {
	case req.ProtoMajor == 1 && req.ProtoMinor == 0:
		return "1.0"
	case req.ProtoMajor == 1 && req.ProtoMinor == 1:
		return "1.1"
	case req.ProtoMajor == 2:
		return "2"
	case req.ProtoMajor == 3:
		return "3"
	default:
		return events.HTTPVersionUnknown
	}
}
