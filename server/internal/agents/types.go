// Package agents WDSP 分布式流量采集 Agent 服务端（Phase 1 + Phase 2/2-B）。
//
// 冻结契约：docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md（§3 机器端点 / §4 管理端点 /
// §5 状态派生 / §7 数据库）+ docs/agents/WDSP_AGENT_PHASE2_CONTRACT.md（§7-§12
// 机器身份证书与 PoP 认证）。机器端点默认走 Bearer credential（wda_ 明文 SHA-256
// 摘要比对），已持证书 Agent 走请求级证书 PoP（三头齐全 → 严格校验，失败绝不降级；
// 三头全缺 → 回退 Bearer，过渡期兼容），管理端点走会话 + RBAC
// （traffic.agents.view / traffic.agents.manage）。
// 本包端点的响应体按契约 §2 裸 JSON + {"error":{"code","message"}} 信封输出
// （不经全局 response.Body 包装——契约冻结了线格式，wdsp-agent 与前端均按契约解析）。
package agents

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ---------- 常量（契约冻结值） ----------

const (
	// HeartbeatIntervalSeconds 注册/心跳响应携带的建议心跳间隔（契约 §6 默认 15s）。
	HeartbeatIntervalSeconds = 15
	// OfflineAfterSeconds 状态派生离线阈值（契约 §5：last_seen 距今 > 60 秒 → OFFLINE）。
	OfflineAfterSeconds = 60
	// MaxFlowEventsPerBatch flows 批量上限（契约 §3.4：每批 events 上限 500 条）。
	MaxFlowEventsPerBatch = 500
	// MaxPacketBatchBytes RAW 批量 body 上限（契约 §3.5：单批 8 MB）。
	MaxPacketBatchBytes = 8 << 20
	// MaxFrameCapLen 单帧 cap_len 上限（契约 §3.5：65535）。
	MaxFrameCapLen = 65535
	// maxFrameCount 单批帧数上限（frame_count 为 BE uint16 的理论上限）。
	maxFrameCount = 65535
	// packetBatchMagic RAW 批量魔数（契约 §3.5）。
	packetBatchMagic = "WDP1"
	// packetBatchHeaderLen magic(4) + batch_ts(8) + frame_count(2)。
	packetBatchHeaderLen = 14
	// packetFrameHeaderLen ts_sec(8) + ts_usec(4) + orig_len(4) + cap_len(4)。
	packetFrameHeaderLen = 20
)

// 心跳/派生状态枚举（契约 §3.2/§5）。
const (
	StatusOnline   = "ONLINE"
	StatusDegraded = "DEGRADED"
	StatusError    = "ERROR"
	StatusOffline  = "OFFLINE"
	StatusDisabled = "DISABLED"
)

// 期望状态（契约 §3.2 desired_state）。
const (
	DesiredEnabled  = "ENABLED"
	DesiredDisabled = "DISABLED"
)

// ---------- 状态派生 ----------

// DeriveStatus 查询时派生 Agent 状态（契约 §5，不落库）：
//  1. disabled → DISABLED；
//  2. last_seen 为空（从未心跳）或距今 > 60 秒 → OFFLINE；
//  3. 否则取最近心跳自报状态（ONLINE/DEGRADED/ERROR），空/非法值兜底 ONLINE
//     （心跳在窗口内成功到达即视为存活）。
//
// 说明：契约 §5 的「从未心跳且创建未超 60 秒」分支在本函数签名下不可区分，
// 统一按 OFFLINE 处理——注册后首个心跳（≤15s）即恢复，偏差有界且如实。
func DeriveStatus(disabled bool, lastSeen *time.Time, lastReported string, now time.Time) string {
	if disabled {
		return StatusDisabled
	}
	if lastSeen == nil || now.Sub(*lastSeen) > OfflineAfterSeconds*time.Second {
		return StatusOffline
	}
	switch lastReported {
	case StatusOnline, StatusDegraded, StatusError:
		return lastReported
	}
	return StatusOnline
}

// ---------- 令牌 / 凭据 ----------

var (
	enrollmentTokenPattern = regexp.MustCompile(`^wdt_[0-9a-f]{64}$`)
	credentialPattern      = regexp.MustCompile(`^wda_[0-9a-f]{64}$`)
)

// GenerateEnrollmentToken 生成注册令牌明文（wdt_ + 32 字节随机 hex；契约 §2）。
func GenerateEnrollmentToken() (string, error) { return generateSecret("wdt_") }

// GenerateCredential 生成 Agent 凭据明文（wda_ + 32 字节随机 hex；契约 §2）。
func GenerateCredential() (string, error) { return generateSecret("wda_") }

func generateSecret(prefix string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return prefix + hex.EncodeToString(buf), nil
}

// HashSecret 计算令牌/凭据明文的 SHA-256 hex 摘要（服务端只存摘要；契约 §2）。
func HashSecret(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// ---------- 机器端点结构（契约 §3） ----------

// Metrics 心跳/指标快照（契约 §3.2 metrics 对象；随心跳原样落 agents.last_metrics）。
type Metrics struct {
	CPUPercent        float64 `json:"cpu_percent"`
	MemoryMB          float64 `json:"memory_mb"`
	CapturePPS        uint64  `json:"capture_pps"`
	CaptureBPS        uint64  `json:"capture_bps"`
	ForwardPPS        uint64  `json:"forward_pps"`
	ForwardBPS        uint64  `json:"forward_bps"`
	DropPPS           uint64  `json:"drop_pps"`
	QueueDepth        uint64  `json:"queue_depth"`
	BufferBytes       uint64  `json:"buffer_bytes"`
	PacketsReceived   uint64  `json:"packets_received"`
	PacketsProcessed  uint64  `json:"packets_processed"`
	PacketsForwarded  uint64  `json:"packets_forwarded"`
	PacketsDropped    uint64  `json:"packets_dropped"`
	KernelDrops       uint64  `json:"kernel_drops"`
	CurrentMbps       float64 `json:"current_mbps"`
	RawFramesReceived uint64  `json:"raw_frames_received"` // 服务端累计（RAW 通道），非 Agent 上报
	RawBytesReceived  uint64  `json:"raw_bytes_received"`  // 服务端累计（RAW 通道），非 Agent 上报
}

// InterfaceInfo 注册上报网卡（契约 §3.1 interfaces 项）。
type InterfaceInfo struct {
	Name      string `json:"name"`
	MAC       string `json:"mac"`
	IPv4      string `json:"ipv4"`
	IPv6      string `json:"ipv6"`
	MTU       int    `json:"mtu"`
	SpeedMbps int    `json:"speed_mbps"`
}

// EnrollRequest 注册入参（契约 §3.1；csr_pem 为 Phase 2-B §7 可选增量——
// Agent 本地生成 P-256 密钥对 + CSR，CN 留空由服务端填 agent_id；
// capabilities 为 v2 契约 §3 可选能力声明——缺省 = 仅 v1）。
type EnrollRequest struct {
	EnrollmentToken string             `json:"enrollment_token"`
	Hostname        string             `json:"hostname"`
	IP              string             `json:"ip"`
	OS              string             `json:"os"`
	Kernel          string             `json:"kernel"`
	Arch            string             `json:"arch"`
	Version         string             `json:"version"`
	Interfaces      []InterfaceInfo    `json:"interfaces"`
	CSRPem          string             `json:"csr_pem"`
	Capabilities    *AgentCapabilities `json:"capabilities"`
}

// Validate 注册入参校验（fail-closed：400；令牌格式先行，格式问题不烧毁令牌）。
func (req *EnrollRequest) Validate() error {
	req.EnrollmentToken = strings.TrimSpace(req.EnrollmentToken)
	if !enrollmentTokenPattern.MatchString(req.EnrollmentToken) {
		return errors.New("enrollment_token 格式非法（须为 wdt_<64 hex>）")
	}
	req.Hostname = strings.TrimSpace(req.Hostname)
	if req.Hostname == "" || len(req.Hostname) > 255 {
		return errors.New("hostname 缺失或超过 255 字符")
	}
	req.IP = strings.TrimSpace(req.IP)
	if req.IP == "" || len(req.IP) > 64 {
		return errors.New("ip 缺失或超过 64 字符")
	}
	if _, err := netip.ParseAddr(req.IP); err != nil {
		return errors.New("ip 不是合法 IP 地址")
	}
	if len(req.OS) > 255 || len(req.Kernel) > 255 {
		return errors.New("os/kernel 超过 255 字符")
	}
	if len(req.Arch) > 64 || len(req.Version) > 64 {
		return errors.New("arch/version 超过 64 字符")
	}
	if len(req.Interfaces) > 32 {
		return errors.New("interfaces 最多 32 条")
	}
	for i := range req.Interfaces {
		ifc := &req.Interfaces[i]
		ifc.Name = strings.TrimSpace(ifc.Name)
		if ifc.Name == "" || len(ifc.Name) > 128 {
			return fmt.Errorf("interfaces[%d].name 缺失或超过 128 字符", i)
		}
		if len(ifc.MAC) > 32 {
			return fmt.Errorf("interfaces[%d].mac 超过 32 字符", i)
		}
		if ifc.IPv4 != "" {
			if len(ifc.IPv4) > 64 {
				return fmt.Errorf("interfaces[%d].ipv4 超过 64 字符", i)
			}
			if _, err := netip.ParseAddr(ifc.IPv4); err != nil {
				return fmt.Errorf("interfaces[%d].ipv4 不是合法 IP 地址", i)
			}
		}
		if ifc.IPv6 != "" {
			if len(ifc.IPv6) > 128 {
				return fmt.Errorf("interfaces[%d].ipv6 超过 128 字符", i)
			}
			if _, err := netip.ParseAddr(ifc.IPv6); err != nil {
				return fmt.Errorf("interfaces[%d].ipv6 不是合法 IP 地址", i)
			}
		}
		if ifc.MTU < 0 || ifc.MTU > 65535 {
			return fmt.Errorf("interfaces[%d].mtu 须在 0~65535", i)
		}
		if ifc.SpeedMbps < 0 {
			return fmt.Errorf("interfaces[%d].speed_mbps 不能为负", i)
		}
	}
	req.CSRPem = strings.TrimSpace(req.CSRPem)
	if len(req.CSRPem) > 16384 {
		return errors.New("csr_pem 超过 16384 字符")
	}
	if err := req.Capabilities.Validate(); err != nil {
		return err
	}
	return nil
}

// HeartbeatRequest 心跳入参（契约 §3.2；metrics 原样透传落库——
// 服务端 RAW 累计键由 SQL 合并保留，Agent 上报的同名字段不生效；
// capabilities 为 v2 契约 §3 可选增量——携带时更新生效能力集，未携带保持原值）。
type HeartbeatRequest struct {
	Timestamp    int64              `json:"timestamp"`
	Status       string             `json:"status"`
	Metrics      json.RawMessage    `json:"metrics"`
	Capabilities *AgentCapabilities `json:"capabilities"`
}

// Validate 心跳入参校验（status 枚举必填；metrics 可缺省——仅刷新活性；
// 携带时须为 JSON 对象）。
func (req *HeartbeatRequest) Validate() error {
	switch req.Status {
	case StatusOnline, StatusDegraded, StatusError:
	default:
		return errors.New("status 须为 ONLINE/DEGRADED/ERROR 之一")
	}
	if len(req.Metrics) > 0 {
		var probe map[string]interface{}
		if err := json.Unmarshal(req.Metrics, &probe); err != nil || probe == nil {
			return errors.New("metrics 须为 JSON 对象")
		}
	}
	return req.Capabilities.Validate()
}

// ConfigAckRequest 配置 ACK 入参（契约 §3.3）。
type ConfigAckRequest struct {
	Version int64  `json:"version"`
	Status  string `json:"status"`
	Error   string `json:"error"`
}

// Validate ACK 入参校验。
func (req *ConfigAckRequest) Validate() error {
	if req.Version < 0 {
		return errors.New("version 不能为负")
	}
	switch req.Status {
	case "APPLIED", "FAILED":
	default:
		return errors.New("status 须为 APPLIED/FAILED 之一")
	}
	if req.Status == "FAILED" && strings.TrimSpace(req.Error) == "" {
		return errors.New("status 为 FAILED 时须携带 error 说明")
	}
	if len(req.Error) > 1024 {
		return errors.New("error 超过 1024 字符")
	}
	return nil
}

// ---------- 流量事件（契约 §3.4） ----------

// K8sMetadata is optional Agent-side enrichment. Invalid metadata is discarded
// as a whole so older/newer Agents remain wire-compatible.
type K8sMetadata struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Workload  string `json:"workload,omitempty"`
	Service   string `json:"service,omitempty"`
	Side      string `json:"side"`
}

func validK8sMetadata(m *K8sMetadata) bool {
	if m == nil {
		return true
	}
	for _, value := range []string{m.Cluster, m.Namespace, m.Pod, m.Workload, m.Service} {
		if len(value) > 253 {
			return false
		}
	}
	return m.Side == "src" || m.Side == "dst"
}

func marshalK8sMetadata(m *K8sMetadata) []byte {
	if m == nil {
		return nil
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return raw
}

// FlowEvent 流量事件（request / flow_end）。
type FlowEvent struct {
	EventType     string       `json:"event_type"`
	FlowID        string       `json:"flow_id"`
	Timestamp     int64        `json:"timestamp"`
	SrcIP         string       `json:"src_ip"`
	SrcPort       int          `json:"src_port"`
	DstIP         string       `json:"dst_ip"`
	DstPort       int          `json:"dst_port"`
	Protocol      string       `json:"protocol"`
	Direction     string       `json:"direction"`
	BytesIn       int64        `json:"bytes_in"`
	BytesOut      int64        `json:"bytes_out"`
	PacketsIn     int64        `json:"packets_in"`
	PacketsOut    int64        `json:"packets_out"`
	TLSVisibility string       `json:"tls_visibility"`
	HTTPMethod    string       `json:"http_method"`
	HTTPHost      string       `json:"http_host"`
	HTTPURI       string       `json:"http_uri"`
	HTTPStatus    int          `json:"http_status"`
	K8s           *K8sMetadata `json:"k8s,omitempty"`
}

// FlowsRequest flows 批量上报入参。
type FlowsRequest struct {
	Events []FlowEvent `json:"events"`
}

// Validate 批量校验（上限 500 条——契约 §3.4；逐事件枚举/格式校验）。
func (req *FlowsRequest) Validate() error {
	if len(req.Events) == 0 {
		return errors.New("events 不能为空")
	}
	if len(req.Events) > MaxFlowEventsPerBatch {
		return fmt.Errorf("events 每批上限 %d 条（当前 %d 条，请分批上报）", MaxFlowEventsPerBatch, len(req.Events))
	}
	for i := range req.Events {
		if err := req.Events[i].validate(); err != nil {
			return fmt.Errorf("events[%d]: %w", i, err)
		}
	}
	return nil
}

func (e *FlowEvent) validate() error {
	if !validK8sMetadata(e.K8s) {
		e.K8s = nil
	}
	if e.EventType != "request" && e.EventType != "flow_end" {
		return errors.New("event_type 须为 request/flow_end 之一")
	}
	e.FlowID = strings.TrimSpace(e.FlowID)
	if e.FlowID == "" || len(e.FlowID) > 255 {
		return errors.New("flow_id 缺失或超过 255 字符")
	}
	if e.Timestamp <= 0 {
		return errors.New("timestamp 须为正 Unix 秒")
	}
	if e.SrcIP != "" {
		if _, err := netip.ParseAddr(e.SrcIP); err != nil {
			return errors.New("src_ip 不是合法 IP 地址")
		}
	}
	if e.DstIP != "" {
		if _, err := netip.ParseAddr(e.DstIP); err != nil {
			return errors.New("dst_ip 不是合法 IP 地址")
		}
	}
	if e.SrcPort < 0 || e.SrcPort > 65535 || e.DstPort < 0 || e.DstPort > 65535 {
		return errors.New("端口须在 0~65535")
	}
	e.Protocol = strings.ToLower(strings.TrimSpace(e.Protocol))
	if e.Protocol != "tcp" {
		return errors.New("protocol 仅支持 tcp")
	}
	switch e.Direction {
	case "", "ingress", "egress", "both":
	default:
		return errors.New("direction 须为 ingress/egress/both 之一")
	}
	if e.BytesIn < 0 || e.BytesOut < 0 || e.PacketsIn < 0 || e.PacketsOut < 0 {
		return errors.New("字节/包计数不能为负")
	}
	switch e.TLSVisibility {
	case "", "PLAINTEXT", "ENCRYPTED", "UNKNOWN":
	default:
		return errors.New("tls_visibility 须为 PLAINTEXT/ENCRYPTED/UNKNOWN 之一")
	}
	if e.HTTPMethod != "" {
		if len(e.HTTPMethod) > 16 || strings.ContainsAny(e.HTTPMethod, "\r\n\t\x00 ") {
			return errors.New("http_method 非法")
		}
	}
	if len(e.HTTPHost) > 255 || strings.ContainsAny(e.HTTPHost, "\r\n\x00") {
		return errors.New("http_host 非法")
	}
	if len(e.HTTPURI) > 4096 || strings.ContainsAny(e.HTTPURI, "\r\n\x00") {
		return errors.New("http_uri 非法")
	}
	if e.HTTPStatus < 0 || e.HTTPStatus > 999 {
		return errors.New("http_status 须在 0~999")
	}
	return nil
}

// ---------- RAW 包批量（契约 §3.5） ----------

// ParsePacketBatch 解析并校验 RAW 二进制批量帧：
//
//	magic "WDP1"(4) + batch_timestamp_unix BE u64(8) + frame_count BE u16(2) + frames...
//	frame: ts_sec BE u64(8) + ts_usec BE u32(4) + orig_len BE u32(4) + cap_len BE u32(4) + packet bytes
//
// 返回帧数与载荷字节合计（cap_len 累加）。Phase 1 服务端只校验/计数/丢弃，不入库。
func ParsePacketBatch(body []byte) (frames int, payloadBytes int64, err error) {
	if len(body) > MaxPacketBatchBytes {
		return 0, 0, fmt.Errorf("批量 body 超过上限 %d 字节", MaxPacketBatchBytes)
	}
	if len(body) < packetBatchHeaderLen {
		return 0, 0, errors.New("批量头长度不足（至少 14 字节）")
	}
	if string(body[0:4]) != packetBatchMagic {
		return 0, 0, errors.New("magic 非法（须为 WDP1）")
	}
	frameCount := int(binary.BigEndian.Uint16(body[12:14]))
	off := packetBatchHeaderLen
	for i := 0; i < frameCount; i++ {
		if len(body)-off < packetFrameHeaderLen {
			return 0, 0, fmt.Errorf("第 %d 帧头长度不足", i)
		}
		capLen := int(binary.BigEndian.Uint32(body[off+16 : off+20]))
		if capLen > MaxFrameCapLen {
			return 0, 0, fmt.Errorf("第 %d 帧 cap_len %d 超过上限 %d", i, capLen, MaxFrameCapLen)
		}
		off += packetFrameHeaderLen
		if len(body)-off < capLen {
			return 0, 0, fmt.Errorf("第 %d 帧载荷长度不足（声明 %d 字节）", i, capLen)
		}
		off += capLen
		payloadBytes += int64(capLen)
	}
	if off != len(body) {
		return 0, 0, fmt.Errorf("批量尾部存在 %d 字节多余数据", len(body)-off)
	}
	return frameCount, payloadBytes, nil
}

// ---------- 策略配置（契约 §3.3 policy JSON） ----------

// PolicyConfig 采集策略（管理端创建/修改时全量校验；机器端 config 拉取原样下发）。
type PolicyConfig struct {
	Name         string         `json:"name"`
	Capture      PolicyCapture  `json:"capture"`
	CaptureLevel string         `json:"capture_level"`
	Output       PolicyOutput   `json:"output"`
	Limits       PolicyLimits   `json:"limits"`
	Sampling     PolicySampling `json:"sampling"`
	Buffer       PolicyBuffer   `json:"buffer"`
	// Masking 脱敏策略（Phase 3 契约 §5/§7：可整体缺省——Agent 本地默认值生效，
	// 服务端 config 拉取响应不补齐缺省段，避免版本噪音）。
	Masking *PolicyMasking `json:"masking,omitempty"`
}

// PolicyMasking 脱敏段（Phase 3 契约 §5：headers/params 两组可分别缺省）。
type PolicyMasking struct {
	Headers *PolicyMaskingRule `json:"headers"`
	Params  *PolicyMaskingRule `json:"params"`
}

// PolicyMaskingRule 单组脱敏规则（mode 缺省/非法 → PUT 400；names 缺省为 nil 合法，
// 匹配大小写不敏感——headers 匹配 Header 名，params 匹配 query/form/JSON Body 一级字段）。
type PolicyMaskingRule struct {
	Mode  string   `json:"mode"`
	Names []string `json:"names"`
}

// PolicyCapture 采集面（接口/方向/协议/端口/后端）。
type PolicyCapture struct {
	Interfaces []string `json:"interfaces"`
	Direction  string   `json:"direction"`
	Protocols  []string `json:"protocols"`
	Ports      []int    `json:"ports"`
	// Backend 抓包后端（afpacket/ebpf/auto），缺省空串=auto（Agent 侧语义，
	// 对应 wdsp-agent Policy.Capture.Backend；Phase 2 eBPF/TC 后端引入）。
	Backend string `json:"backend,omitempty"`
}

// PolicyOutput 输出通道（FLOW / RAW / FLOW_RAW）。
type PolicyOutput struct {
	Mode string `json:"mode"`
}

// PolicyLimits 自我保护和前向兼容上限。
type PolicyLimits struct {
	// MaxBodySize L2 Body 采集单方向上限（Phase 3 契约 §4：默认 256KB，硬上限 10MB，
	// 策略超硬上限 Agent 侧按 10MB 截断，服务端校验不拒绝）。
	MaxBodySize  int     `json:"max_body_size"`
	OutboundMbps float64 `json:"outbound_mbps"`
	CPUPercent   float64 `json:"cpu_percent"`
	MemoryMB     float64 `json:"memory_mb"`
}

// PolicySampling 采样。
type PolicySampling struct {
	Enabled bool    `json:"enabled"`
	Rate    float64 `json:"rate"`
}

// PolicyBuffer 断线本地缓存。
type PolicyBuffer struct {
	Enabled       bool `json:"enabled"`
	MaxSizeMB     int  `json:"max_size_mb"`
	MaxAgeMinutes int  `json:"max_age_minutes"`
}

// ValidatePolicyConfigJSON 解析并校验策略 config JSON（管理端创建/修改入口）。
// 枚举值按契约 §3.3 冻结集合校验；L2/L3 采集级别为合法枚举（Phase 3 契约 §2 语义：
// L2=L1+Body，L3=L2+RAW 包通道，Agent 不再降级为 L1）。
func ValidatePolicyConfigJSON(raw json.RawMessage) error {
	if len(raw) == 0 {
		return errors.New("config 缺失")
	}
	if len(raw) > 65536 {
		return errors.New("config 超过 64KB")
	}
	var cfg PolicyConfig
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("config 不是合法策略 JSON：%v", err)
	}
	return cfg.validate()
}

func (c *PolicyConfig) validate() error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" || len(c.Name) > 128 {
		return errors.New("policy.name 缺失或超过 128 字符")
	}
	switch c.Capture.Direction {
	case "ingress", "egress", "both":
	default:
		return errors.New("capture.direction 须为 ingress/egress/both 之一")
	}
	switch c.Capture.Backend {
	case "", "afpacket", "ebpf", "auto":
	default:
		return errors.New("capture.backend 须为 afpacket/ebpf/auto 之一")
	}
	switch c.CaptureLevel {
	case "L0", "L1", "L2", "L3":
	default:
		return errors.New("capture_level 须为 L0/L1/L2/L3 之一")
	}
	switch c.Output.Mode {
	case "FLOW", "RAW", "FLOW_RAW":
	default:
		return errors.New("output.mode 须为 FLOW/RAW/FLOW_RAW 之一")
	}
	if len(c.Capture.Interfaces) > 32 {
		return errors.New("capture.interfaces 最多 32 个")
	}
	for _, name := range c.Capture.Interfaces {
		if strings.TrimSpace(name) == "" || len(name) > 128 {
			return errors.New("capture.interfaces 含空名或超过 128 字符")
		}
	}
	if len(c.Capture.Protocols) == 0 {
		return errors.New("capture.protocols 不能为空")
	}
	for _, p := range c.Capture.Protocols {
		if p != "tcp" && p != "udp" {
			return errors.New("capture.protocols 仅支持 tcp/udp")
		}
	}
	if len(c.Capture.Ports) == 0 || len(c.Capture.Ports) > 64 {
		return errors.New("capture.ports 须为 1~64 个端口")
	}
	seen := map[int]bool{}
	for _, port := range c.Capture.Ports {
		if port < 1 || port > 65535 {
			return errors.New("capture.ports 端口须在 1~65535")
		}
		if seen[port] {
			return fmt.Errorf("capture.ports 端口 %d 重复", port)
		}
		seen[port] = true
	}
	if c.Limits.MaxBodySize < 0 || c.Limits.MaxBodySize > 16<<20 {
		return errors.New("limits.max_body_size 须在 0~16MB")
	}
	if c.Limits.OutboundMbps <= 0 || c.Limits.OutboundMbps > 100000 {
		return errors.New("limits.outbound_mbps 须在 (0, 100000]")
	}
	if c.Limits.CPUPercent <= 0 || c.Limits.CPUPercent > 100 {
		return errors.New("limits.cpu_percent 须在 (0, 100]")
	}
	if c.Limits.MemoryMB <= 0 || c.Limits.MemoryMB > 1048576 {
		return errors.New("limits.memory_mb 须在 (0, 1048576]")
	}
	// sampling.rate 仅在采样开启时校验（Phase 4 契约 §4：enabled=true 时 rate ∈ (0,1]，
	// 否则管理端 400；enabled=false 不校验 rate——采样未生效，值无意义）。
	if c.Sampling.Enabled && (c.Sampling.Rate <= 0 || c.Sampling.Rate > 1) {
		return errors.New("sampling.enabled=true 时 sampling.rate 须在 (0, 1]")
	}
	if c.Buffer.MaxSizeMB < 0 || c.Buffer.MaxSizeMB > 102400 {
		return errors.New("buffer.max_size_mb 须在 0~102400")
	}
	if c.Buffer.MaxAgeMinutes < 0 || c.Buffer.MaxAgeMinutes > 10080 {
		return errors.New("buffer.max_age_minutes 须在 0~10080")
	}
	if err := c.Masking.validate(); err != nil {
		return err
	}
	return nil
}

// validate 脱敏段校验（Phase 3 契约 §5：mode 非法或 names 非数组 → 管理端 PUT 400；
// masking 整段缺省或 headers/params 分组缺省均合法——Agent 本地默认值生效）。
func (m *PolicyMasking) validate() error {
	if m == nil {
		return nil
	}
	for side, rule := range map[string]*PolicyMaskingRule{"headers": m.Headers, "params": m.Params} {
		if rule == nil {
			continue
		}
		switch rule.Mode {
		case "NONE", "MASK", "HASH", "DROP":
		default:
			return fmt.Errorf("masking.%s.mode 须为 NONE/MASK/HASH/DROP 之一", side)
		}
		if len(rule.Names) > 64 {
			return fmt.Errorf("masking.%s.names 最多 64 个", side)
		}
		for _, name := range rule.Names {
			if strings.TrimSpace(name) == "" || len(name) > 128 {
				return fmt.Errorf("masking.%s.names 含空名或超过 128 字符", side)
			}
		}
	}
	return nil
}

// ---------- 持久化行结构 ----------

// EnrollmentToken 注册令牌行（永不带明文；status 为展示派生：ACTIVE/USED/REVOKED/EXPIRED）。
type EnrollmentToken struct {
	ID            uuid.UUID  `json:"id"`
	Label         string     `json:"label"`
	ExpiresAt     time.Time  `json:"expires_at"`
	UsedAt        *time.Time `json:"used_at"`
	UsedByAgentID *uuid.UUID `json:"used_by_agent_id"`
	RevokedAt     *time.Time `json:"revoked_at"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
}

// TokenStatus 令牌展示状态（派生，不落库）。
func (t *EnrollmentToken) TokenStatus(now time.Time) string {
	switch {
	case t.RevokedAt != nil:
		return "REVOKED"
	case t.UsedAt != nil:
		return "USED"
	case now.After(t.ExpiresAt):
		return "EXPIRED"
	}
	return "ACTIVE"
}

// Agent Agent 行（Status 为查询时派生——契约 §5；credential_hash 不出 JSON）。
// HealthScore/HealthReasons/ClockOffsetMS 为 Phase 2 健康评分输出（查询时计算，不落库评分；
// clock_offset_ms 落库自心跳时钟偏移，设计 §23/§54）。
type Agent struct {
	AgentID              uuid.UUID       `json:"agent_id"`
	Hostname             string          `json:"hostname"`
	IP                   string          `json:"ip"`
	OS                   string          `json:"os"`
	Kernel               string          `json:"kernel"`
	Arch                 string          `json:"arch"`
	Version              string          `json:"version"`
	Disabled             bool            `json:"disabled"`
	Status               string          `json:"status"`
	LastSeen             *time.Time      `json:"last_seen"`
	LastStatus           string          `json:"-"`
	LastMetrics          json.RawMessage `json:"last_metrics"`
	ConfigVersion        int64           `json:"config_version"`
	AppliedConfigVersion int64           `json:"applied_config_version"`
	ClockOffsetMS        *int64          `json:"clock_offset_ms"`
	HealthScore          int             `json:"health_score"`
	HealthReasons        []string        `json:"health_reasons"`
	CreatedAt            time.Time       `json:"created_at"`
	CredentialHash       string          `json:"-"`
	EnrollmentTokenID    *uuid.UUID      `json:"-"`
	// 机器身份证书（Phase 2-B §7/§10；json:"-" ——列表输出不变，详情经 AgentDetail 同名字段暴露）
	CertFingerprint *string    `json:"-"`
	CertNotAfter    *time.Time `json:"-"`
	// HTTPEventSchemas 能力协商生效的 HTTP 事件 schema 集合（v2 契约 §3；落库
	// agents.http_event_schemas，json:"-" ——列表输出不变，详情经 AgentDetail 同名字段
	// 暴露（任务书 P1-03 §4.3：管理端按能力集区分「需升级」展示）。
	HTTPEventSchemas []int `json:"-"`
	// 健康评分输入（不出 JSON；由仓储从绑定策略 config 提取，0 表示无限制/无绑定）
	cpuLimitPercent float64
	memoryLimitMB   float64
	bufferLimitMB   float64
}

// FillStatus 填充派生状态（契约 §5）。
func (a *Agent) FillStatus(now time.Time) {
	a.Status = DeriveStatus(a.Disabled, a.LastSeen, a.LastStatus, now)
}

// FillHealth 计算并填充健康评分与扣分原因（设计 §54；须在 FillStatus 之后调用）。
// 评分为查询时派生，不落库；health_reasons 保证非 nil（无扣分项为空数组）。
func (a *Agent) FillHealth() {
	var metrics *Metrics
	if len(a.LastMetrics) > 0 {
		var m Metrics
		if err := json.Unmarshal(a.LastMetrics, &m); err == nil {
			metrics = &m
		}
	}
	score, reasons := ComputeHealth(HealthInput{
		Status:               a.Status,
		Metrics:              metrics,
		ClockOffsetMS:        a.ClockOffsetMS,
		ConfigVersion:        a.ConfigVersion,
		AppliedConfigVersion: a.AppliedConfigVersion,
		CPULimitPercent:      a.cpuLimitPercent,
		MemoryLimitMB:        a.memoryLimitMB,
		BufferLimitMB:        a.bufferLimitMB,
	})
	a.HealthScore = score
	a.HealthReasons = reasons
}

// AgentDetail 详情（列表字段 + interfaces + policy_binding + 当前证书信息——
// Phase 2-B §11：cert_fingerprint/cert_not_after 仅详情输出，无证书为 null；
// 同名字段遮蔽内嵌 Agent 的 json:"-" 版本，存储扫描一律写外层字段）。
// HTTPEventSchemas 同理遮蔽（v2 契约 §3 能力集，仅详情输出——任务书 P1-03 §4.3）。
type AgentDetail struct {
	Agent
	Interfaces       []InterfaceInfo `json:"interfaces"`
	PolicyBinding    *PolicyBinding  `json:"policy_binding"`
	CertFingerprint  *string         `json:"cert_fingerprint"`
	CertNotAfter     *time.Time      `json:"cert_not_after"`
	HTTPEventSchemas []int           `json:"http_event_schemas"`
}

// PolicyBinding 生效绑定（详情内嵌；无绑定为 null）。
type PolicyBinding struct {
	PolicyID      uuid.UUID `json:"policy_id"`
	PolicyName    string    `json:"policy_name"`
	PolicyVersion int       `json:"policy_version"`
	BoundBy       string    `json:"bound_by"`
	BoundAt       time.Time `json:"bound_at"`
}

// Policy 策略行。
type Policy struct {
	ID        uuid.UUID       `json:"id"`
	Name      string          `json:"name"`
	Config    json.RawMessage `json:"config"`
	Version   int             `json:"version"`
	CreatedBy string          `json:"created_by"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// PolicyVersion 策略历史版本快照（Phase 2，设计 §68.13/§68.14：版本化+回滚）。
// 创建/每次 PUT/回滚在同一事务快照一行；(policy_id,version) 唯一。
type PolicyVersion struct {
	PolicyID  uuid.UUID       `json:"policy_id"`
	Version   int             `json:"version"`
	Config    json.RawMessage `json:"config"`
	CreatedBy string          `json:"created_by"`
	CreatedAt time.Time       `json:"created_at"`
}

// FlowEventRow 流量事件行（管理端事件分页；ts 为 RFC3339，字段同契约 §3.4 事件项）。
type FlowEventRow struct {
	ID            int64           `json:"id"`
	AgentID       uuid.UUID       `json:"agent_id"`
	Ts            time.Time       `json:"ts"`
	EventType     string          `json:"event_type"`
	FlowID        string          `json:"flow_id"`
	SrcIP         string          `json:"src_ip"`
	SrcPort       int             `json:"src_port"`
	DstIP         string          `json:"dst_ip"`
	DstPort       int             `json:"dst_port"`
	Protocol      string          `json:"protocol"`
	Direction     string          `json:"direction"`
	BytesIn       int64           `json:"bytes_in"`
	BytesOut      int64           `json:"bytes_out"`
	PacketsIn     int64           `json:"packets_in"`
	PacketsOut    int64           `json:"packets_out"`
	TLSVisibility string          `json:"tls_visibility"`
	HTTPMethod    string          `json:"http_method"`
	HTTPHost      string          `json:"http_host"`
	HTTPURI       string          `json:"http_uri"`
	HTTPStatus    int             `json:"http_status"`
	K8s           json.RawMessage `json:"k8s,omitempty"`
}

// Summary Agent 状态汇总（契约 §4 /traffic/agents/summary）。
type Summary struct {
	Total    int64 `json:"total"`
	Online   int64 `json:"online"`
	Offline  int64 `json:"offline"`
	Degraded int64 `json:"degraded"`
	Disabled int64 `json:"disabled"`
}

// ---------- 分页 ----------

// PageParams 分页参数（契约 §2：page 1 起、page_size 默认 20 最大 100）。
type PageParams struct {
	Page     int
	PageSize int
}

// ParsePageParams 解析并钳制分页参数（非法/越界一律回落默认——列表端点不因分页参数 400）。
func ParsePageParams(query func(string) string) PageParams {
	p := PageParams{Page: 1, PageSize: 20}
	if v, err := strconv.Atoi(query("page")); err == nil && v >= 1 {
		p.Page = v
	}
	if v, err := strconv.Atoi(query("page_size")); err == nil && v >= 1 {
		p.PageSize = v
	}
	if p.PageSize > 100 {
		p.PageSize = 100
	}
	return p
}

// Offset SQL 偏移。
func (p PageParams) Offset() int { return (p.Page - 1) * p.PageSize }
