// Package config Agent 本地配置（/etc/wdsp-agent/agent.json）与策略模型。
//
// 对应契约 §3.1 注册响应、§3.3 配置拉取、§6 本地行为约定：
//   - agent.json 存 server/agent_id/credential/心跳间隔/已应用配置版本，0600 落盘；
//   - 无绑定策略时使用内置默认采集集（端口 80,443,8000,8001,8080,8081,8443,8888,9000,9443，
//     direction=both，output=FLOW，outbound_mbps=100）。
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// 默认路径（契约 §6）。
const (
	DefaultConfigPath = "/etc/wdsp-agent/agent.json"
	DefaultStateDir   = "/var/lib/wdsp-agent"
	DefaultBufferDir  = DefaultStateDir + "/buffer"
)

// DefaultPorts 内置默认采集端口（契约 §6）。
var DefaultPorts = []int{80, 443, 8000, 8001, 8080, 8081, 8443, 8888, 9000, 9443}

// 默认值（契约 §6）。
const (
	DefaultHeartbeatInterval = 15
	DefaultOutboundMbps      = 100.0
	DefaultCPUPercent        = 20.0
	DefaultMemoryMB          = 512.0
	DefaultBufferMaxSizeMB   = 512
	DefaultBufferMaxAgeMin   = 30
)

// Config agent.json 持久化结构。
type Config struct {
	Server                   string `json:"server"`
	AgentID                  string `json:"agent_id"`
	Credential               string `json:"credential"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
	InsecureSkipVerify       bool   `json:"insecure_skip_verify,omitempty"`
	AppliedConfigVersion     int64  `json:"applied_config_version"`
	// PendingConfigAckVersion 是已持久化且已生效、但控制面尚未确认的配置版本。
	// 进程在 APPLIED ACK 返回前退出时，重启后必须优先重试该 ACK。
	PendingConfigAckVersion int64   `json:"pending_config_ack_version,omitempty"`
	Limits                  Limits  `json:"limits"`
	Buffer                  Buffer  `json:"buffer"`
	Policy                  *Policy `json:"policy,omitempty"` // 最近应用的策略快照（重启后沿用，直到服务端下发新版本）

	// Phase 2 抓包后端（本地运维意志，优先于策略下发；见 capture.ResolveBackend）：
	// afpacket | ebpf | auto（空=auto：先试 eBPF，失败回退 AF_PACKET，Fail-Open）。
	CaptureBackend string `json:"capture_backend,omitempty"`
	// CaptureSnaplen eBPF 单事件截取字节上限（0=默认 2048，硬上限 4096）。
	CaptureSnaplen int `json:"capture_snaplen,omitempty"`

	// CertExpiresAt 机器身份证书到期时间（RFC3339，Phase 2-B 契约 §7；
	// 空=无证书 Bearer 模式。证书本体存状态目录 agent.crt，私钥 agent.key）。
	CertExpiresAt string `json:"cert_expires_at,omitempty"`

	// Overrides 最近应用的定向采集规则快照（Phase 4 契约 §2.4，随策略一并
	// 持久化，重启后沿用直到服务端下发新版本；过期规则求值时即时忽略）。
	Overrides []Override `json:"overrides,omitempty"`

	// K8s controls optional in-cluster metadata enrichment: auto(default)|on|off.
	K8s K8sConfig `json:"k8s,omitempty"`

	// Mirror Nginx TLS 终止后 mirror 子请求接收（P1-03 §3.2，G2；本地运维意志，
	// 默认关闭）。记录为 v2 单向源（source_type=NGINX_MIRROR，response 恒 null），
	// 仅在服务端协商支持 v2 时上行；未协商时丢弃计数（不降级为 v1 以免来源误标）。
	Mirror MirrorConfig `json:"mirror,omitempty"`

	APIObservation APIObservationConfig `json:"api_observation,omitempty"`

	// Tap Envoy tap 管理流适配（P1-03 §3.3，G3；本地运维意志，默认关闭）。
	// 记录为 v2 来源（source_type=ENVOY_TAP）；适配器只出向连接本机回环
	// Envoy Admin 读取 tap 流，不监听采集端口、不代理业务流量。
	Tap TapConfig `json:"tap,omitempty"`
}

type APIObservationConfig struct {
	Enabled      bool   `json:"enabled,omitempty"`
	SocketPath   string `json:"socket_path,omitempty"`
	SocketMode   int    `json:"socket_mode,omitempty"`
	HMACKeyID    string `json:"hmac_key_id,omitempty"`
	HMACKeyEnv   string `json:"hmac_key_env,omitempty"`
	MaxBodyBytes int    `json:"max_body_bytes,omitempty"`
}

func (c APIObservationConfig) EffectiveSocketPath() string {
	if c.SocketPath == "" {
		return "/run/wdsp-agent/api.sock"
	}
	return c.SocketPath
}

func (c APIObservationConfig) EffectiveSocketMode() os.FileMode {
	if c.SocketMode == 0 {
		return 0o600
	}
	return os.FileMode(c.SocketMode)
}

func (c APIObservationConfig) EffectiveHMACKeyEnv() string {
	if c.HMACKeyEnv == "" {
		return "WDSP_API_OBSERVATION_HMAC_KEY"
	}
	return c.HMACKeyEnv
}

// TapConfig tap 适配器本地配置（装配见 internal/tapsrc 包注释；
// 转换在 internal/agent/tap.go，config 包不反向依赖）。
// 单会话约束：Envoy Admin 同时只允许一条已挂接 tap 流，多个 listener 的
// tap filter 共享同一 config_id；协议/TLS 断言覆盖全部 tapped listener，
// 混合场景必须保守（UNKNOWN / false）。
type TapConfig struct {
	Enabled        bool   `json:"enabled,omitempty"`
	AdminAddr      string `json:"admin_addr,omitempty"` // 仅回环 host:port（默认 127.0.0.1:9901）
	SourceInstance string `json:"source_instance,omitempty"`
	ConfigID       string `json:"config_id,omitempty"` // tap filter admin_config config_id
	// ObservedHTTPVersion 部署断言：全部 tapped listener 的观测协议
	//（1.0/1.1/2/3；缺省/混合 UNKNOWN；不从数据内容猜测）
	ObservedHTTPVersion string `json:"observed_http_version,omitempty"`
	// TLSTerminated 部署断言：全部 tapped listener 均为可信 TLS 终止点 → DECRYPTED
	TLSTerminated   bool  `json:"tls_terminated_upstream,omitempty"`
	BodyEnabled     bool  `json:"body_enabled,omitempty"`      // 默认仅元数据；gRPC 正文恒不采集
	MaxBodyBytes    int   `json:"max_body_bytes,omitempty"`    // 默认 4KB；同时下发 Envoy max_buffered_*_bytes
	MaxMessageBytes int64 `json:"max_message_bytes,omitempty"` // 单条 TraceWrapper JSON 上限（默认 1MB）
	ReconnectMinMs  int   `json:"reconnect_min_ms,omitempty"`  // 默认 1000
	ReconnectMaxMs  int   `json:"reconnect_max_ms,omitempty"`  // 默认 30000
}

// MirrorConfig mirror 接收器本地配置（装配见 internal/mirrorsrc 包注释；
// 转换在 internal/agent/mirror.go，config 包不反向依赖）。
type MirrorConfig struct {
	Enabled        bool   `json:"enabled,omitempty"`
	SocketPath     string `json:"socket_path,omitempty"`  // Unix Socket（首选；与 listen_addr 互斥）
	ListenAddr     string `json:"listen_addr,omitempty"`  // 仅回环地址（如 127.0.0.1:9080）
	SocketMode     int    `json:"socket_mode,omitempty"`  // 默认 0600（八进制解释）
	SocketGroup    string `json:"socket_group,omitempty"` // 可选属组（如 nginx，配合 0660）
	SourceInstance string `json:"source_instance,omitempty"`
	InstanceToken  string `json:"instance_token,omitempty"`
	// TLSTerminated 部署断言：本接收器仅接可信 TLS 终止点后镜像（→ DECRYPTED）；
	// 缺省 false=PLAINTEXT。不得由外部 Header 决定。
	TLSTerminated bool `json:"tls_terminated_upstream,omitempty"`
	BodyEnabled   bool `json:"body_enabled,omitempty"`   // 默认仅元数据
	MaxBodyBytes  int  `json:"max_body_bytes,omitempty"` // 默认 64KB，硬上限 10MB
	MaxConns      int  `json:"max_conns,omitempty"`      // 默认 64，硬上限 1024
}

type K8sConfig struct {
	Enabled string `json:"enabled,omitempty"`
}

func (k K8sConfig) Mode() string {
	switch k.Enabled {
	case "on", "off":
		return k.Enabled
	default:
		return "auto"
	}
}

// Override 定向采集规则（Phase 4 契约 §2.1/§2.4 config 响应 overrides 数组元素）。
type Override struct {
	ID           string        `json:"id"`
	Match        OverrideMatch `json:"match"`
	CaptureLevel string        `json:"capture_level"` // L0|L1|L2|L3
	Note         string        `json:"note,omitempty"`
	ExpiresAt    string        `json:"expires_at"` // RFC3339
}

// OverrideMatch 匹配条件（契约 §2.2：全部可选，多字段 AND；四字段全空非法）。
type OverrideMatch struct {
	DstIP     string `json:"dst_ip,omitempty"`     // 单个 IP 或 CIDR（v4/v6）
	DstPort   int    `json:"dst_port,omitempty"`   // 1-65535
	Host      string `json:"host,omitempty"`       // 精确匹配（大小写不敏感）
	URIPrefix string `json:"uri_prefix,omitempty"` // URI 前缀（≤512 字节，以 / 开头）
}

// Limits 资源上限（契约 §3.3 policy.limits）。
type Limits struct {
	MaxBodySize  int     `json:"max_body_size"` // 单方向 Body 采集上限（Phase 3 契约 §4）
	OutboundMbps float64 `json:"outbound_mbps"`
	CPUPercent   float64 `json:"cpu_percent"`
	MemoryMB     float64 `json:"memory_mb"`
}

// Body 采集上限（Phase 3 契约 §4：默认 256KB，硬上限 10MB）。
const (
	DefaultMaxBodySize = 256 << 10
	HardMaxBodySize    = 10 << 20
)

// EffectiveMaxBodySize max_body_size 生效值：<=0 取默认，超硬上限按硬上限截。
func (l Limits) EffectiveMaxBodySize() int {
	if l.MaxBodySize <= 0 {
		return DefaultMaxBodySize
	}
	if l.MaxBodySize > HardMaxBodySize {
		return HardMaxBodySize
	}
	return l.MaxBodySize
}

// 脱敏模式（Phase 3 契约 §5）。
const (
	MaskModeNone = "NONE"
	MaskModeMask = "MASK"
	MaskModeHash = "HASH"
	MaskModeDrop = "DROP"
)

// MaskRule 一组脱敏规则（headers 或 params）。
type MaskRule struct {
	Mode  string   `json:"mode"`
	Names []string `json:"names"`
}

// Masking 策略脱敏段（Phase 3 契约 §5，可整体缺省）。
type Masking struct {
	Headers MaskRule `json:"headers"`
	Params  MaskRule `json:"params"`
}

// 缺省脱敏规则（契约 §5 默认值，逐字）。
var (
	defaultMaskHeaderNames = []string{"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}
	defaultMaskParamNames  = []string{"password", "passwd", "pwd", "token", "access_token", "refresh_token", "secret", "api_key", "apikey"}
)

// DefaultMasking 契约 §5 缺省脱敏段。
func DefaultMasking() Masking {
	return Masking{
		Headers: MaskRule{Mode: MaskModeMask, Names: append([]string(nil), defaultMaskHeaderNames...)},
		Params:  MaskRule{Mode: MaskModeMask, Names: append([]string(nil), defaultMaskParamNames...)},
	}
}

// normalizeMaskRule 归一化单条规则：mode 非法回落 MASK（管理端 PUT 已校验，
// Agent 侧防御性兜底）；names 非数组（nil）时保留空集语义——仅在整段缺省时用默认。
func normalizeMaskRule(r MaskRule, def MaskRule) MaskRule {
	switch r.Mode {
	case MaskModeNone, MaskModeMask, MaskModeHash, MaskModeDrop:
	default:
		r.Mode = def.Mode
	}
	if r.Names == nil {
		r.Names = def.Names
	}
	return r
}

// EffectiveMasking 生效脱敏段：masking 整体缺省 → 契约默认值；
// 部分缺省的子段（mode 非法/names 为 null）以默认子段补齐。
func (m *Masking) Effective() Masking {
	if m == nil {
		return DefaultMasking()
	}
	def := DefaultMasking()
	return Masking{
		Headers: normalizeMaskRule(m.Headers, def.Headers),
		Params:  normalizeMaskRule(m.Params, def.Params),
	}
}

// Buffer 磁盘缓存配置（契约 §3.3 policy.buffer）。
type Buffer struct {
	Enabled       bool `json:"enabled"`
	MaxSizeMB     int  `json:"max_size_mb"`
	MaxAgeMinutes int  `json:"max_age_minutes"`
	// ReplaySharePercent 补传公平预算（P1-03 §5.5）：补传占用出站带宽的
	// 百分比上限（相对 limits.outbound_mbps），实时采集保底其余份额——
	// 长期离线积压不会饿死实时流量。0=默认 30；>100 按 100（不限份额）。
	ReplaySharePercent int `json:"replay_share_percent,omitempty"`
}

// DefaultReplaySharePercent 补传公平预算默认值（%）。
const DefaultReplaySharePercent = 30

// EffectiveReplaySharePercent 生效补传份额（%）：<=0 取默认，>100 按 100。
func (b Buffer) EffectiveReplaySharePercent() int {
	if b.ReplaySharePercent <= 0 {
		return DefaultReplaySharePercent
	}
	if b.ReplaySharePercent > 100 {
		return 100
	}
	return b.ReplaySharePercent
}

// Policy 服务端下发策略（契约 §3.3 policy）。
type Policy struct {
	Name         string   `json:"name"`
	Capture      Capture  `json:"capture"`
	CaptureLevel string   `json:"capture_level"`
	Output       Output   `json:"output"`
	Limits       Limits   `json:"limits"`
	Sampling     Sampling `json:"sampling"`
	Buffer       Buffer   `json:"buffer"`
	// Masking 脱敏段（Phase 3 契约 §5，可整体缺省=契约默认值；服务端不补齐缺省段）。
	Masking *Masking `json:"masking,omitempty"`
}

// 采集等级（Phase 3 契约 §2 冻结语义）。
const (
	LevelL0 = "L0" // 仅 flow 元数据事件
	LevelL1 = "L1" // + 请求/响应 Header（脱敏后）
	LevelL2 = "L2" // + Body
	LevelL3 = "L3" // L2 + RAW 包通道
)

// EffectiveCaptureLevel 归一化采集等级：空/非法值按 L0（保守，少采集）。
func (p *Policy) EffectiveCaptureLevel() string {
	switch p.CaptureLevel {
	case LevelL1, LevelL2, LevelL3:
		return p.CaptureLevel
	default:
		return LevelL0
	}
}

// LevelRank 采集等级序数（L0=0 … L3=3；空/非法按 L0，与 EffectiveCaptureLevel 同保守口径）。
func LevelRank(level string) int {
	switch level {
	case LevelL1:
		return 1
	case LevelL2:
		return 2
	case LevelL3:
		return 3
	default:
		return 0
	}
}

// LevelName 序数回等级字符串（越界钳制到 [L0,L3]）。
func LevelName(rank int) string {
	switch {
	case rank >= 3:
		return LevelL3
	case rank == 2:
		return LevelL2
	case rank == 1:
		return LevelL1
	default:
		return LevelL0
	}
}

// Capture 采集范围。
type Capture struct {
	Interfaces []string `json:"interfaces"`
	Direction  string   `json:"direction"` // ingress | egress | both
	Protocols  []string `json:"protocols"` // Phase 1 仅 tcp
	Ports      []int    `json:"ports"`
	// Backend 策略下发期望的抓包后端（afpacket|ebpf|auto，空=不指定；
	// Phase 2 追加字段，本地 agent.json capture_backend 显式值优先）。
	Backend string `json:"backend,omitempty"`
}

// Output 输出模式。
type Output struct {
	Mode string `json:"mode"` // FLOW | RAW | FLOW_RAW
}

// Sampling 采样（Phase 4 契约 §4 起生效：enabled 且 rate∈(0,1) 时按
// SHA-256(flow_id) 前 8 字节确定性采样，同流一致；rate=1 等价关闭）。
type Sampling struct {
	Enabled bool    `json:"enabled"`
	Rate    float64 `json:"rate"`
}

// Default 返回带内置默认值的配置。
func Default() *Config {
	return &Config{
		HeartbeatIntervalSeconds: DefaultHeartbeatInterval,
		Limits: Limits{
			OutboundMbps: DefaultOutboundMbps,
			CPUPercent:   DefaultCPUPercent,
			MemoryMB:     DefaultMemoryMB,
		},
		Buffer: Buffer{
			Enabled:       true,
			MaxSizeMB:     DefaultBufferMaxSizeMB,
			MaxAgeMinutes: DefaultBufferMaxAgeMin,
		},
		K8s: K8sConfig{Enabled: "auto"},
	}
}

// DefaultPolicy 无绑定策略时的内置默认采集集（契约 §6）。
func DefaultPolicy() *Policy {
	return &Policy{
		Name: "builtin-default",
		Capture: Capture{
			Direction: "both",
			Protocols: []string{"tcp"},
			Ports:     append([]int(nil), DefaultPorts...),
		},
		CaptureLevel: "L1",
		Output:       Output{Mode: "FLOW"},
		Limits: Limits{
			OutboundMbps: DefaultOutboundMbps,
			CPUPercent:   DefaultCPUPercent,
			MemoryMB:     DefaultMemoryMB,
		},
		Sampling: Sampling{Rate: 1.0},
		Buffer: Buffer{
			Enabled:       true,
			MaxSizeMB:     DefaultBufferMaxSizeMB,
			MaxAgeMinutes: DefaultBufferMaxAgeMin,
		},
	}
}

// EffectivePolicy 当前生效策略（无策略快照时用内置默认）。
func (c *Config) EffectivePolicy() *Policy {
	if c.Policy != nil {
		return c.Policy
	}
	return DefaultPolicy()
}

// Load 读取 agent.json；文件不存在返回 Default() 与 os.ErrNotExist 包装错误。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Default(), fmt.Errorf("读取配置 %s: %w", path, err)
	}
	cfg := Default()
	if err := json.Unmarshal(data, cfg); err != nil {
		return Default(), fmt.Errorf("解析配置 %s: %w", path, err)
	}
	cfg.applyDefaults()
	return cfg, nil
}

// applyDefaults 补齐缺省字段（旧版本配置文件兼容）。
func (c *Config) applyDefaults() {
	c.K8s.Enabled = c.K8s.Mode()
	if c.HeartbeatIntervalSeconds <= 0 {
		c.HeartbeatIntervalSeconds = DefaultHeartbeatInterval
	}
	if c.Limits.OutboundMbps <= 0 {
		c.Limits.OutboundMbps = DefaultOutboundMbps
	}
	if c.Limits.CPUPercent <= 0 {
		c.Limits.CPUPercent = DefaultCPUPercent
	}
	if c.Limits.MemoryMB <= 0 {
		c.Limits.MemoryMB = DefaultMemoryMB
	}
	if c.Buffer.MaxSizeMB <= 0 {
		c.Buffer.MaxSizeMB = DefaultBufferMaxSizeMB
	}
	if c.Buffer.MaxAgeMinutes <= 0 {
		c.Buffer.MaxAgeMinutes = DefaultBufferMaxAgeMin
	}
}

// Save 原子写入 agent.json（tmp+rename），文件权限 0600，目录 0700。
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("创建配置目录: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("写临时配置: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("替换配置: %w", err)
	}
	// 显式修正权限（rename 保留 tmp 权限，防御 umask 异常场景）
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("修正配置权限: %w", err)
	}
	return nil
}
