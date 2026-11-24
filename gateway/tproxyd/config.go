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
	defaultListen        = "0.0.0.0:15000"   // 生产由桥上 REDIRECT 牵引至此端口
	defaultTarget        = "127.0.0.1:15080" // 专用透明 HTTP 回环下游（避开控制台 8080）
	defaultTargetTLS     = "127.0.0.1:15443" // 专用透明 HTTPS 回环下游（避开控制台 8443）
	defaultMaxConns      = 1024              // 并发连接上限（防内存/句柄失控，对齐现有组件有界纪律）
	defaultStatsInterval = 60 * time.Second
	defaultDialTimeout   = 10 * time.Second
	defaultShutdownGrace = 5 * time.Second
	defaultSniffTimeout  = 3 * time.Second
	// defaultRelayIdleTimeout 透传滚动空闲超时：任一方向搬运数据即续期，
	// 两端静默超过该时长即关闭连接释放并发令牌（防空闲连接占满 MaxConns 整体 DoS）。
	defaultRelayIdleTimeout = 300 * time.Second
	// DefaultHealthAddr /healthz 默认监听地址（TPROXY_HEALTH_ADDR 可覆盖）。
	DefaultHealthAddr = "127.0.0.1:15001"
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
	// TargetTLS 终结检测；未列明域名默认 fail-closed 倒向 TargetTLS，仅显式列入
	// PassthroughAllowlist 的域名才按原始目的端到端透传。
	// 支持精确域名与 RFC 单级前导通配符（*.example.com，仅匹配单级子域名），小写归一、容忍末尾点。
	ProtectHosts []string
	// PassthroughAllowlist 显式允许按原始目的端到端透传的 TLS SNI 域名白名单
	// （TPROXY_PASSTHROUGH_ALLOWLIST，逗号分隔；默认空 = 禁止任意未列明 SNI 绕过检测）。
	// ProtectHosts 优先级高于本白名单；支持精确域名与 RFC 单级前导通配符（*.example.com）。
	PassthroughAllowlist []string
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

// FileConfigPath 返回配置文件路径（TPROXY_CONFIG_FILE 覆盖 DefaultFileConfigPath）。
func FileConfigPath() string {
	return envOr("TPROXY_CONFIG_FILE", DefaultFileConfigPath)
}

// HealthAddrFromEnv 返回健康检查 HTTP 监听地址（TPROXY_HEALTH_ADDR 覆盖 DefaultHealthAddr）。
func HealthAddrFromEnv() string {
	return envOr("TPROXY_HEALTH_ADDR", DefaultHealthAddr)
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
	if v := strings.TrimSpace(os.Getenv("TPROXY_PASSTHROUGH_ALLOWLIST")); v != "" {
		cfg.PassthroughAllowlist, err = normalizeHosts(v)
		if err != nil {
			return Config{}, fmt.Errorf("TPROXY_PASSTHROUGH_ALLOWLIST 非法: %w", err)
		}
	}
	return cfg, cfg.Validate()
}

// normalizeHosts 归一化域名清单：小写、去末尾点、去重保序；拒绝空白与非法字符。
// 支持精确域名与 RFC 单级前导通配符（*.example.com）。
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

// validHostName 校验归一化后的域名（允许精确域名或 RFC 单级前导通配符 *.example.com）。
func validHostName(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	base := h
	isWildcard := false
	if strings.HasPrefix(h, "*.") {
		isWildcard = true
		base = h[2:]
		// 单级通配符基础域必须至少包含两级标签（如 example.com），拒绝 * / *. / *.com
		if !strings.Contains(base, ".") {
			return false
		}
	}
	if len(base) == 0 || base[0] == '.' || base[len(base)-1] == '.' {
		return false
	}
	prevDot := false
	for _, r := range base {
		if r == '.' {
			if prevDot {
				return false
			}
			prevDot = true
			continue
		}
		prevDot = false
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			// 非法字符（含任意位置的额外 '*'，阻止 *.*.example.com / foo.*.com / *foo.com）
			return false
		}
	}
	_ = isWildcard
	return true
}

// hostMatcher 支持精确域名与单级前导通配符（*.example.com）的 O(1) 域名匹配器。
// 遵循 RFC 6125 单级通配语义：*.example.com 匹配 sub.example.com，不匹配 example.com，
// 也不匹配多级子域 a.b.example.com。
type hostMatcher struct {
	exact     map[string]struct{}
	wildcards map[string]struct{} // "*.example.com" 存为 "example.com"
}

func newHostMatcher(hosts []string) *hostMatcher {
	if len(hosts) == 0 {
		return nil
	}
	m := &hostMatcher{}
	for _, h := range hosts {
		norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if norm == "" {
			continue
		}
		if strings.HasPrefix(norm, "*.") && len(norm) > 2 {
			if m.wildcards == nil {
				m.wildcards = make(map[string]struct{})
			}
			m.wildcards[norm[2:]] = struct{}{}
			continue
		}
		if m.exact == nil {
			m.exact = make(map[string]struct{})
		}
		m.exact[norm] = struct{}{}
	}
	if len(m.exact) == 0 && len(m.wildcards) == 0 {
		return nil
	}
	return m
}

func (m *hostMatcher) match(host string) bool {
	if m == nil {
		return false
	}
	norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if norm == "" {
		return false
	}
	if _, ok := m.exact[norm]; ok {
		return true
	}
	if len(m.wildcards) == 0 {
		return false
	}
	idx := strings.IndexByte(norm, '.')
	if idx <= 0 || idx >= len(norm)-1 {
		return false
	}
	_, ok := m.wildcards[norm[idx+1:]]
	return ok
}

// protectHostMatcher 返回防护域名匹配器（nil 表示功能关闭）。
func (c Config) protectHostMatcher() *hostMatcher {
	return newHostMatcher(c.ProtectHosts)
}

// passthroughHostMatcher 返回显式透传白名单匹配器（nil 表示禁止任何未列明 SNI 透传）。
func (c Config) passthroughHostMatcher() *hostMatcher {
	return newHostMatcher(c.PassthroughAllowlist)
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
	if len(c.ProtectHosts) > 0 {
		if _, err := normalizeHosts(strings.Join(c.ProtectHosts, ",")); err != nil {
			return fmt.Errorf("TPROXY_PROTECT_HOSTS 非法: %w", err)
		}
	}
	if len(c.PassthroughAllowlist) > 0 {
		if _, err := normalizeHosts(strings.Join(c.PassthroughAllowlist, ",")); err != nil {
			return fmt.Errorf("TPROXY_PASSTHROUGH_ALLOWLIST 非法: %w", err)
		}
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
