// 旁路采集器配置。
//
// 配置来源与优先级（产品化：发布链路下发文件，见 fileconfig.go）：
//   - 配置文件存在即文件优先（enabled/interfaces/ports/events_log/node/discovery 以文件为准）；
//   - 文件不存在时环境变量为默认值（PoC/lab 运维路径，MIRROR_* / SITE_DISCOVERY_* 系列）。
package mirrorcap

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// 默认值。
const (
	defaultPorts          = "80,8080"
	defaultEventsLog      = "/var/log/caddy/api-runtime-events.log"
	defaultAuditLog       = "/var/log/caddy/coraza-audit.log"
	defaultRulesDir       = "/etc/caddy/rules"
	defaultBodyMax        = 64 << 10 // 65536
	defaultStatsInterval  = 60 * time.Second
	defaultStreamIdle     = 90 * time.Second
	defaultMaxStreamConns = 4096 // 同时重组的流上限（防内存失控，对齐 detectors 的有界纪律）

	// defaultDiscoveryLog 站点资产被动发现输出路径默认（JSONL，服务端采集入库）。
	defaultDiscoveryLog = "/var/log/caddy/site-discovery.jsonl"
	// defaultDiscoveryFlushInterval 发现聚合窗口落盘周期默认。
	defaultDiscoveryFlushInterval = 30 * time.Second
)

// Config 旁路采集器配置。
type Config struct {
	// Iface 监听接口（MIRROR_IFACE，空 = 非法，启动失败并提示）。
	Iface string
	// Ports 目标 TCP 端口（MIRROR_PORTS，逗号分隔；仅重组目的端口命中集合的流，
	// 即 client→server 方向；响应方向流天然被过滤）。
	Ports []uint16
	// Domains 目标站点域名过滤集合（空 = 端口上全部流量进入检测；非空 = 仅命中
	// 精确域名或 *.泛域名的流量进入检测，站点发现不受此限制仍记录全量观察）。
	Domains []string
	// EventsLog 事件输出路径（MIRROR_EVENTS_LOG，api-runtime-events JSONL 契约）。
	EventsLog string
	// AuditLog Coraza 审计日志路径（MIRROR_AUDIT_LOG；"off"/"none" 关闭审计落盘；
	// 非空时以 SecAuditEngine RelevantOnly + SecAuditLogParts ABIJDEFHZ 覆写 coraza.conf）。
	AuditLog string
	// BodyMax 单请求 Body 捕获上限字节（MIRROR_BODY_MAX；超出部分仅透传丢弃不进内存分析）。
	BodyMax int64
	// NodeName 网关节点名（GATEWAY_NODE_NAME；写入事件 gateway_node_id）。
	NodeName string
	// IdentitySalt 身份/来源指纹 HMAC 盐（MIRROR_IDENTITY_SALT；空走固定域分隔前缀）。
	IdentitySalt string
	// RulesDir Coraza/CRS 规则目录（MIRROR_RULES_DIR，与网关容器内布局一致）。
	RulesDir string
	// StatsInterval 状态统计日志周期（MIRROR_STATS_INTERVAL，秒）。
	StatsInterval time.Duration
	// StreamIdleTimeout 流空闲超时（MIRROR_STREAM_IDLE_TIMEOUT，秒；超时冲刷并关闭半开流）。
	StreamIdleTimeout time.Duration
	// MaxStreamConns 同时重组的流上限（MIRROR_MAX_STREAMS；超出丢弃新流，防内存失控）。
	MaxStreamConns int
	// Discovery 站点资产被动发现配置（文件 discovery 块 / SITE_DISCOVERY_* env）；
	// 与检测功能独立启停（见 supervisor.go）。
	Discovery DiscoveryConfig
}

// DiscoveryConfig 站点资产被动发现配置。
type DiscoveryConfig struct {
	// Enabled 发现开关（SITE_DISCOVERY_ENABLED；与检测 enabled 相互独立）。
	Enabled bool
	// Ifaces 发现监听接口集合（SITE_DISCOVERY_IFACES，逗号分隔 "name" 或 "name:MODE"，
	// MODE 缺省 MIRROR；enabled=true 时必填——同检测接口约束风格）。
	Ifaces []DiscoveryIface
	// FlushInterval 聚合窗口落盘周期（SITE_DISCOVERY_FLUSH_INTERVAL，秒）。
	FlushInterval time.Duration
	// Log 发现记录输出路径（SITE_DISCOVERY_LOG，JSONL）。
	Log string
}

// DiscoveryIface 发现接口及其流量来源模式（mode 写入记录 source_mode 字段）。
type DiscoveryIface struct {
	Name string
	Mode string // MIRROR / ROUTED / TRANSPARENT
}

// Defaults 返回内置默认配置基线（Iface 为空表示未指定接口）。
// 用途：配置文件轮询模式下 env 不完整（典型为 MIRROR_IFACE 未设置）时，
// 进程以该基线进入空转等待发布链路下发文件，而非启动即退出。
func Defaults() Config {
	return Config{
		Ports:             []uint16{80, 8080},
		EventsLog:         defaultEventsLog,
		AuditLog:          defaultAuditLog,
		NodeName:          "mirror-unknown",
		RulesDir:          defaultRulesDir,
		BodyMax:           defaultBodyMax,
		StatsInterval:     defaultStatsInterval,
		StreamIdleTimeout: defaultStreamIdle,
		MaxStreamConns:    defaultMaxStreamConns,
		Discovery: DiscoveryConfig{
			FlushInterval: defaultDiscoveryFlushInterval,
			Log:           defaultDiscoveryLog,
		},
	}
}

// FileConfigPath 返回配置文件路径（MIRROR_CONFIG_FILE 覆盖 DefaultFileConfigPath，适配裸机自定义安装根）。
func FileConfigPath() string {
	return envOr("MIRROR_CONFIG_FILE", DefaultFileConfigPath)
}

// ParseEnv 仅解析环境变量到 Config 基线（不要求 MIRROR_IFACE 必填），供文件配置模式保留
// MIRROR_RULES_DIR / MIRROR_IDENTITY_SALT / MIRROR_AUDIT_LOG 等运维环境变量。
// 仅在环境变量取值格式非法时返回错误。
func ParseEnv() (Config, error) {
	cfg := Defaults()
	cfg.Iface = strings.TrimSpace(os.Getenv("MIRROR_IFACE"))
	cfg.EventsLog = envOr("MIRROR_EVENTS_LOG", cfg.EventsLog)
	cfg.AuditLog = envOr("MIRROR_AUDIT_LOG", cfg.AuditLog)
	cfg.NodeName = envOr("GATEWAY_NODE_NAME", cfg.NodeName)
	cfg.IdentitySalt = os.Getenv("MIRROR_IDENTITY_SALT")
	cfg.RulesDir = envOr("MIRROR_RULES_DIR", cfg.RulesDir)
	ports, err := parsePorts(envOr("MIRROR_PORTS", defaultPorts))
	if err != nil {
		return Config{}, fmt.Errorf("MIRROR_PORTS: %w", err)
	}
	cfg.Ports = ports
	if v := strings.TrimSpace(os.Getenv("MIRROR_BODY_MAX")); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return Config{}, fmt.Errorf("MIRROR_BODY_MAX 非法（需正整数字节数）: %q", v)
		}
		cfg.BodyMax = n
	}
	if v := strings.TrimSpace(os.Getenv("MIRROR_STATS_INTERVAL")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return Config{}, fmt.Errorf("MIRROR_STATS_INTERVAL 非法（需正整数秒）: %q", v)
		}
		cfg.StatsInterval = time.Duration(n) * time.Second
	}
	if v := strings.TrimSpace(os.Getenv("MIRROR_STREAM_IDLE_TIMEOUT")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return Config{}, fmt.Errorf("MIRROR_STREAM_IDLE_TIMEOUT 非法（需正整数秒）: %q", v)
		}
		cfg.StreamIdleTimeout = time.Duration(n) * time.Second
	}
	if v := strings.TrimSpace(os.Getenv("MIRROR_MAX_STREAMS")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return Config{}, fmt.Errorf("MIRROR_MAX_STREAMS 非法（需正整数）: %q", v)
		}
		cfg.MaxStreamConns = n
	}
	if v := strings.TrimSpace(os.Getenv("SITE_DISCOVERY_ENABLED")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("SITE_DISCOVERY_ENABLED 非法（需 true/false）: %q", v)
		}
		cfg.Discovery.Enabled = b
	}
	cfg.Discovery.Log = envOr("SITE_DISCOVERY_LOG", cfg.Discovery.Log)
	if v := strings.TrimSpace(os.Getenv("SITE_DISCOVERY_FLUSH_INTERVAL")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return Config{}, fmt.Errorf("SITE_DISCOVERY_FLUSH_INTERVAL 非法（需正整数秒）: %q", v)
		}
		cfg.Discovery.FlushInterval = time.Duration(n) * time.Second
	}
	if v := strings.TrimSpace(os.Getenv("SITE_DISCOVERY_IFACES")); v != "" {
		ifaces, err := parseDiscoveryIfaces(v)
		if err != nil {
			return Config{}, fmt.Errorf("SITE_DISCOVERY_IFACES: %w", err)
		}
		cfg.Discovery.Ifaces = ifaces
	}
	return cfg, nil
}

// FromEnv 从环境变量读取配置（缺失项取默认值；非法值返回错误，不静默容忍）。
func FromEnv() (Config, error) {
	cfg, err := ParseEnv()
	if err != nil {
		return Config{}, err
	}
	return cfg, cfg.Validate()
}

// Validate 校验配置（Iface 必填——旁路采集无监听接口则无意义，直接失败并提示）。
func (c Config) Validate() error {
	if c.Iface == "" {
		return fmt.Errorf("MIRROR_IFACE 未设置：旁路采集器必须指定镜像监听接口（如 eth0）")
	}
	if len(c.Ports) == 0 {
		return fmt.Errorf("MIRROR_PORTS 解析结果为空")
	}
	if c.EventsLog == "" {
		return fmt.Errorf("MIRROR_EVENTS_LOG 不能为空")
	}
	if c.BodyMax <= 0 {
		return fmt.Errorf("MIRROR_BODY_MAX 必须为正数")
	}
	if c.Discovery.Enabled {
		if len(c.Discovery.Ifaces) == 0 {
			return fmt.Errorf("SITE_DISCOVERY_ENABLED=true 但 SITE_DISCOVERY_IFACES 为空")
		}
		if c.Discovery.Log == "" {
			return fmt.Errorf("SITE_DISCOVERY_LOG 不能为空")
		}
		if c.Discovery.FlushInterval <= 0 {
			return fmt.Errorf("SITE_DISCOVERY_FLUSH_INTERVAL 必须为正数")
		}
	}
	return nil
}

// PortSet 端口判断集合（包级热路径查询）。
func (c Config) PortSet() map[uint16]struct{} {
	m := make(map[uint16]struct{}, len(c.Ports))
	for _, p := range c.Ports {
		m[p] = struct{}{}
	}
	return m
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// parsePorts 解析逗号分隔端口列表（1-65535；去重保序）。
func parsePorts(s string) ([]uint16, error) {
	var out []uint16
	seen := map[uint16]struct{}{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("非法端口 %q（需 1-65535 逗号分隔）", part)
		}
		if _, ok := seen[uint16(n)]; ok {
			continue
		}
		seen[uint16(n)] = struct{}{}
		out = append(out, uint16(n))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("端口列表为空")
	}
	return out, nil
}

// parseDiscoveryIfaces 解析发现接口列表（"eth2:MIRROR,eth0:ROUTED"；mode ∈ MIRROR/ROUTED/TRANSPARENT，
// 缺省 MIRROR；去空白去重保序；非法 mode 显式报错，不静默容忍）。
func parseDiscoveryIfaces(s string) ([]DiscoveryIface, error) {
	var out []DiscoveryIface
	seen := map[string]struct{}{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, mode := part, "MIRROR"
		if i := strings.LastIndex(part, ":"); i >= 0 {
			name, mode = part[:i], strings.ToUpper(strings.TrimSpace(part[i+1:]))
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("非法接口项 %q（接口名为空）", part)
		}
		if mode != "MIRROR" && mode != "ROUTED" && mode != "TRANSPARENT" {
			return nil, fmt.Errorf("接口 %s 非法 mode %q（需 MIRROR/ROUTED/TRANSPARENT）", name, mode)
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, DiscoveryIface{Name: name, Mode: mode})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("接口列表为空")
	}
	return out, nil
}
