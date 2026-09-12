// 牵引进程配置。
//
// 配置来源与优先级（产品化：发布链路下发文件，见 fileconfig.go）：
//   - 配置文件存在即文件优先（enabled/listen/target 以文件为准）；
//   - 文件不存在时环境变量为默认值（PoC/lab 运维路径，TPROXY_* 系列）。
package tproxyd

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// 默认值。
const (
	defaultListen        = "127.0.0.1:15000" // 生产由编排显式下发桥地址监听（如 0.0.0.0:15000）
	defaultTarget        = "127.0.0.1:8080"
	defaultTargetTLS     = "127.0.0.1:8443"
	defaultMaxConns      = 1024 // 并发连接上限（防内存/句柄失控，对齐现有组件有界纪律）
	defaultStatsInterval = 60 * time.Second
	defaultDialTimeout   = 10 * time.Second
	defaultShutdownGrace = 5 * time.Second
	defaultSniffTimeout  = 3 * time.Second
	// defaultRelayIdleTimeout 透传滚动空闲超时：任一方向搬运数据即续期，
	// 两端静默超过该时长即关闭连接释放并发令牌（防空闲连接占满 MaxConns 整体 DoS）。
	defaultRelayIdleTimeout = 300 * time.Second
)

// Config 牵引进程配置。
type Config struct {
	// Listen 监听地址（TPROXY_LISTEN；REDIRECT 目标端口，桥上流量被 DNAT 到此）。
	Listen string
	// Target 下游 Caddy 地址（TPROXY_TARGET；listener 需挂 proxy_protocol wrapper）。
	Target string
	// MaxConns 并发连接上限（TPROXY_MAX_CONNS；超出立即关闭新连接，防失控）。
	MaxConns int
	// StatsInterval 状态统计日志周期（TPROXY_STATS_INTERVAL，秒）。
	StatsInterval time.Duration
	// DialTimeout 连接下游 Caddy 的超时（TPROXY_DIAL_TIMEOUT，秒）。
	DialTimeout time.Duration
	// ShutdownGrace 优雅退出宽限（TPROXY_SHUTDOWN_GRACE，秒；超时强制断开在途连接）。
	ShutdownGrace time.Duration
	// ProtectHosts SNI 防护域名清单（TPROXY_PROTECT_HOSTS，逗号分隔；空 = 功能关闭，
	// 全部流量按原路径送 Target）。非空时启用 TLS 嗅探分流：清单内域名的 TLS 连接送
	// TargetTLS 终结检测，清单外域名按原始目的直接 TCP 透传（端到端 TLS 不断开）。
	// 精确匹配，小写归一、容忍末尾点，不支持通配符。
	ProtectHosts []string
	// TargetTLS 下游 Caddy TLS 监听器地址（TPROXY_TARGET_TLS；仅 ProtectHosts 非空时
	// 生效，listener 同样需挂 proxy_protocol wrapper）。
	TargetTLS string
	// SniffTimeout SNI 嗅探读超时（TPROXY_SNIFF_TIMEOUT，秒；超时关连接，防空闲占用）。
	SniffTimeout time.Duration
	// RelayIdleTimeout 透传阶段滚动空闲超时（TPROXY_RELAY_IDLE_TIMEOUT，秒）：
	// 任一方向每搬运一块数据即续期两端读写 deadline；两端静默超过该时长即关闭
	// 连接（释放 MaxConns 令牌）。长连接业务（SSE/WebSocket）依赖心跳保活，心跳
	// 间隔必须小于该值。
	RelayIdleTimeout time.Duration
}

// Defaults 返回内置默认配置基线。
// 用途：配置文件轮询模式下 env 非法时，进程以该基线进入空转等待发布链路
// 下发文件，而非启动即退出。
func Defaults() Config {
	return Config{
		Listen:           defaultListen,
		Target:           defaultTarget,
		MaxConns:         defaultMaxConns,
		StatsInterval:    defaultStatsInterval,
		DialTimeout:      defaultDialTimeout,
		ShutdownGrace:    defaultShutdownGrace,
		TargetTLS:        defaultTargetTLS,
		SniffTimeout:     defaultSniffTimeout,
		RelayIdleTimeout: defaultRelayIdleTimeout,
	}
}

// FromEnv 从环境变量读取配置（缺失项取默认值；非法值返回错误，不静默容忍）。
func FromEnv() (Config, error) {
	cfg := Defaults()
	cfg.Listen = envOr("TPROXY_LISTEN", cfg.Listen)
	cfg.Target = envOr("TPROXY_TARGET", cfg.Target)
	if v := strings.TrimSpace(os.Getenv("TPROXY_MAX_CONNS")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return Config{}, fmt.Errorf("TPROXY_MAX_CONNS 非法（需正整数）: %q", v)
		}
		cfg.MaxConns = n
	}
	var err error
	if cfg.StatsInterval, err = envSeconds("TPROXY_STATS_INTERVAL", cfg.StatsInterval); err != nil {
		return Config{}, err
	}
	if cfg.DialTimeout, err = envSeconds("TPROXY_DIAL_TIMEOUT", cfg.DialTimeout); err != nil {
		return Config{}, err
	}
	if cfg.ShutdownGrace, err = envSeconds("TPROXY_SHUTDOWN_GRACE", cfg.ShutdownGrace); err != nil {
		return Config{}, err
	}
	cfg.TargetTLS = envOr("TPROXY_TARGET_TLS", cfg.TargetTLS)
	if cfg.SniffTimeout, err = envSeconds("TPROXY_SNIFF_TIMEOUT", cfg.SniffTimeout); err != nil {
		return Config{}, err
	}
	if cfg.RelayIdleTimeout, err = envSeconds("TPROXY_RELAY_IDLE_TIMEOUT", cfg.RelayIdleTimeout); err != nil {
		return Config{}, err
	}
	if v := strings.TrimSpace(os.Getenv("TPROXY_PROTECT_HOSTS")); v != "" {
		cfg.ProtectHosts, err = normalizeHosts(v)
		if err != nil {
			return Config{}, fmt.Errorf("TPROXY_PROTECT_HOSTS 非法: %w", err)
		}
	}
	return cfg, cfg.Validate()
}

// normalizeHosts 归一化域名清单：小写、去末尾点、去重保序；拒绝空白与非法字符
// （仅允许 DNS 标签字符 a-z 0-9 . - _ 与冒号外的可见 ASCII；精确匹配不支持通配符）。
func normalizeHosts(s string) ([]string, error) {
	parts := strings.Split(s, ",")
	seen := map[string]struct{}{}
	hosts := make([]string, 0, len(parts))
	for _, p := range parts {
		h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p), "."))
		if h == "" {
			continue
		}
		if !validHostName(h) {
			return nil, fmt.Errorf("非法域名: %q", p)
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// validHostName 宽松校验：DNS 标签字符集（含国际化域名的 punycode 形态）。
func validHostName(h string) bool {
	if len(h) > 253 {
		return false
	}
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// protectHostSet 返回防护域名匹配集合（nil 表示功能关闭）。
func (c Config) protectHostSet() map[string]struct{} {
	if len(c.ProtectHosts) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(c.ProtectHosts))
	for _, h := range c.ProtectHosts {
		set[h] = struct{}{}
	}
	return set
}

// sniDispatchEnabled 是否启用 SNI 嗅探分流。
func (c Config) sniDispatchEnabled() bool { return len(c.ProtectHosts) > 0 }

// Validate 校验配置（地址必须可解析为 host:port，牵引无监听/无下游则无意义）。
func (c Config) Validate() error {
	if err := checkAddr("TPROXY_LISTEN", c.Listen); err != nil {
		return err
	}
	if err := checkAddr("TPROXY_TARGET", c.Target); err != nil {
		return err
	}
	if c.MaxConns <= 0 {
		return fmt.Errorf("TPROXY_MAX_CONNS 必须为正数")
	}
	if c.RelayIdleTimeout <= 0 {
		return fmt.Errorf("TPROXY_RELAY_IDLE_TIMEOUT 必须为正数")
	}
	if c.sniDispatchEnabled() {
		if err := checkAddr("TPROXY_TARGET_TLS", c.TargetTLS); err != nil {
			return err
		}
		if c.SniffTimeout <= 0 {
			return fmt.Errorf("TPROXY_SNIFF_TIMEOUT 必须为正数")
		}
	}
	return nil
}

func checkAddr(name, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return fmt.Errorf("%s 非法（需 host:port）: %q", name, addr)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 0 || p > 65535 {
		return fmt.Errorf("%s 端口非法（需 0-65535）: %q", name, addr)
	}
	if host != "" && net.ParseIP(host) == nil {
		if _, err := net.ResolveIPAddr("ip", host); err != nil {
			return fmt.Errorf("%s 主机非法: %q", name, addr)
		}
	}
	return nil
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envSeconds(key string, def time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s 非法（需正整数秒）: %q", key, v)
	}
	return time.Duration(n) * time.Second, nil
}
