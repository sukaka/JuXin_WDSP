// sidecars.go 镜像/透明部署模式边车配置（docs/NETWORK_MODES_DESIGN.md §4.2/§4.3）：
// 发布成功后由发布通道写出到与网关容器共享的卷，gateway/mirrorcap 与 gateway/tproxyd 消费。
// 边车配置属于发布的附加产物：写失败只记日志，不回滚已加载的 Caddy 配置。
package gatewayconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/nodeinterfaces"
)

const (
	// DefaultSidecarDir 边车配置目录（api 容器内路径，该卷与网关容器共享）
	DefaultSidecarDir = "/var/run/caddy/sidecars"
	// DefaultSiteDiscoveryLog 站点发现日志网关容器内路径（mirrorcap 写入；
	// 与 API 侧采集器配置 WAF_SITE_DISCOVERY_LOG 的部署值指向同一共享卷文件）
	DefaultSiteDiscoveryLog = "/var/log/caddy/site-discovery.jsonl"
	// siteDiscoveryFlushIntervalSec 发现聚合窗口 flush 周期（秒，下发 mirrorcap）
	siteDiscoveryFlushIntervalSec = 30
	// DefaultTproxydListen tproxyd 牵引默认监听地址（必须绑定全网口 0.0.0.0，
	// 因为 Linux iptables PREROUTING REDIRECT 将目的地址改写为入网口主 IP 而非 127.0.0.1）。
	DefaultTproxydListen = "0.0.0.0:15000"
	// DefaultTproxydTarget 下游 Caddy 透明 HTTP 专用回环地址（避开控制台 8080 端口）。
	DefaultTproxydTarget = "127.0.0.1:15080"
	// DefaultTproxydTargetTLS 下游 Caddy 透明 HTTPS/TLS 专用回环地址（避开控制台 8443 端口；
	// SNI 防护清单内域名的终结检测入口，见 gateway/tproxyd sni.go）。
	DefaultTproxydTargetTLS = "127.0.0.1:15443"
)

// MirrorcapSidecar 是 mirrorcap.json 内容（gateway/mirrorcap 消费）。
// Interfaces/Ports 恒为数组（空数组而非 null）；Discovery 恒存在（无可用接口时 enabled=false）。
type MirrorcapSidecar struct {
	Enabled    bool               `json:"enabled"`
	Node       string             `json:"node"`
	Interfaces []string           `json:"interfaces"`
	Ports      []int              `json:"ports"`
	Domains    []string           `json:"domains,omitempty"`
	EventsLog  string             `json:"events_log,omitempty"`
	AuditLog   string             `json:"audit_log,omitempty"`
	Discovery  MirrorcapDiscovery `json:"discovery"`
}

// MirrorcapDiscovery 是 mirrorcap.json 的 discovery 块（站点资产被动发现，
// 网关按窗口聚合写 site-discovery.jsonl，API 侧 sitediscovery 采集器入库）。
// Interfaces 恒为数组（空数组而非 null）。
type MirrorcapDiscovery struct {
	Enabled          bool                 `json:"enabled"`
	Interfaces       []DiscoveryInterface `json:"interfaces"`
	FlushIntervalSec int                  `json:"flush_interval_sec"`
	Log              string               `json:"log"`
}

// DiscoveryInterface 是 discovery 块中的一个采集接口（mode ∈ MIRROR/ROUTED/TRANSPARENT）。
type DiscoveryInterface struct {
	Name string `json:"name"`
	Mode string `json:"mode"`
}

// TproxydSidecar 是 tproxyd.json 内容（gateway/tproxyd 消费）。
// Ports/ProtectHosts/PassthroughAllowlist 恒为非 nil 数组（空配置显式输出 []，
// 确保下发空数组能覆盖 tproxyd 进程环境变量中的遗留默认值）。
// ProtectHosts 为 TLS SNI 防护域名清单：清单内域名的 TLS 连接送 TargetTLS 终结检测；
// 未列明 SNI 默认 fail-closed 倒向 TargetTLS，仅显式列入 PassthroughAllowlist 的域名才按
// 原始目的端到端透传（防止未纳入管理的恶意域名借透传绕过检测）。两者均支持精确域名与
// RFC 单级前导通配符（*.example.com）。空数组 = 关闭分流。
type TproxydSidecar struct {
	Enabled              bool     `json:"enabled"`
	Listen               string   `json:"listen"`
	Target               string   `json:"target"`
	Ports                []int    `json:"ports"`
	TargetTLS            string   `json:"target_tls"`
	ProtectHosts         []string `json:"protect_hosts"`
	PassthroughAllowlist []string `json:"passthrough_allowlist"`
}

// BridgePortsProvider 提供节点已配置网桥的成员口清单（用于透明模式站点被动发现补齐）。
type BridgePortsProvider interface {
	ListBridgePorts(ctx context.Context, nodeName string) ([]string, error)
}

// MirrorInterfacesProvider 提供节点网口清单（nodeinterfaces.Store 实现；nil 时输出空数组）。
type MirrorInterfacesProvider interface {
	// ListMirrorInterfaces 返回节点 role=MIRROR 且 present 的接口名（sort_order 升序）。
	ListMirrorInterfaces(ctx context.Context, nodeName string) ([]string, error)
	// ListInterfacesByRole 返回节点指定 role 且 present 的接口名（站点发现按角色取 TRAFFIC 口）。
	ListInterfacesByRole(ctx context.Context, nodeName, role string) ([]string, error)
}

// buildMirrorcapSidecar 由发布快照组装 mirrorcap 边车配置：
//   - 仅当存在防护模式非 OFF/BYPASS 的 MIRROR 应用、存在可检测的明文 HTTP 端口（或尚未声明域名按默认 80），
//     且该节点已配置至少一个 role=MIRROR 且 present 的网口时 enabled=true；
//     无可用镜像口时主动降为 enabled=false，避免产出被 mirrorcap 拒收的非法文件连带冻结站点发现；
//   - ports 仅收集 MIRROR 应用的明文 HTTP 端口（不含 HTTPS 端口，镜像旁路无法解密 TLS，
//     把 443 写入 ports 反而会导致 TLS 连接误入 HTTP 解析并破坏 443 端口的 SNI 站点发现）；
//   - domains 收集可检测 MIRROR 应用的规范化域名（去重排序；无域名时省略，兼容未绑域名场景）；
//   - discovery 块由 buildMirrorcapDiscovery 组装（站点资产被动发现，恒输出）。
func buildMirrorcapSidecar(apps []AppData, node string, interfaces []string, discovery MirrorcapDiscovery) MirrorcapSidecar {
	if interfaces == nil {
		interfaces = []string{}
	}
	ports, hasHTTPTarget := mirrorPlaintextPorts(apps)
	domains := mirrorDetectDomains(apps)
	enabled := hasDetectableMirrorApp(apps) && hasHTTPTarget && len(interfaces) > 0
	return MirrorcapSidecar{
		Enabled:    enabled,
		Node:       node,
		Interfaces: interfaces,
		Ports:      ports,
		Domains:    domains,
		Discovery:  discovery,
	}
}

// hasDetectableMirrorApp 是否存在需要执行镜像检测的 MIRROR 应用（排除 OFF/BYPASS）。
func hasDetectableMirrorApp(apps []AppData) bool {
	for _, app := range apps {
		if app.DeploymentMode != applications.DeployModeMirror {
			continue
		}
		if app.ProtectionMode == applications.ModeOff || app.ProtectionMode == applications.ModeBypass {
			continue
		}
		return true
	}
	return false
}

// mirrorPlaintextPorts 收集可检测 MIRROR 应用的明文 HTTP 监听端口（去重排序，绝不含 HTTPS 端口）。
// 返回值 (ports, hasTarget)：
//   - 存在 HTTP 监听端口 → 返回这些端口，hasTarget=true；
//   - 存在可检测 MIRROR 应用但未配置任何域名 → 回退 [80]，hasTarget=true；
//   - 所有可检测 MIRROR 应用均只启用了 HTTPS 端口 → 返回 [80] 占位但 hasTarget=false（不开启 HTTP 检测，仅做 SNI 发现）。
func mirrorPlaintextPorts(apps []AppData) ([]int, bool) {
	seen := map[int]bool{}
	var ports []int
	hasDomain := false
	hasMirror := false
	for _, app := range apps {
		if app.DeploymentMode != applications.DeployModeMirror {
			continue
		}
		if app.ProtectionMode == applications.ModeOff || app.ProtectionMode == applications.ModeBypass {
			continue
		}
		hasMirror = true
		for _, d := range app.Domains {
			hasDomain = true
			if d.HTTPEnabled && d.HTTPPort != nil && !seen[*d.HTTPPort] {
				seen[*d.HTTPPort] = true
				ports = append(ports, *d.HTTPPort)
			}
		}
	}
	if len(ports) > 0 {
		sort.Ints(ports)
		return ports, true
	}
	if hasMirror && !hasDomain {
		return []int{80}, true
	}
	return []int{80}, false
}

// mirrorDetectDomains 收集可检测 MIRROR 应用且启用了明文 HTTP 的规范化域名（去重排序）。
func mirrorDetectDomains(apps []AppData) []string {
	seen := map[string]bool{}
	var hosts []string
	for _, app := range apps {
		if app.DeploymentMode != applications.DeployModeMirror {
			continue
		}
		if app.ProtectionMode == applications.ModeOff || app.ProtectionMode == applications.ModeBypass {
			continue
		}
		for _, d := range app.Domains {
			if !d.HTTPEnabled {
				continue
			}
			h := d.NormalizedHostname
			if h == "" {
				h = d.Hostname
			}
			if h == "" || seen[h] {
				continue
			}
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return nil
	}
	sort.Strings(hosts)
	return hosts
}

// buildMirrorcapDiscovery 组装 mirrorcap 站点被动发现块：
//   - 节点有 MIRROR 应用 → role=MIRROR 接口逐个 mode=MIRROR；
//   - 节点有 ROUTED 或 TRANSPARENT 应用 → 追加 role=TRAFFIC 接口，
//     mode 取值：有 TRANSPARENT 应用则 TRANSPARENT，否则 ROUTED；
//   - 同名接口去重（MIRROR 优先）；enabled=有任一可用接口；
//   - flush 周期 30s；log 为网关容器内站点发现日志路径。
func buildMirrorcapDiscovery(apps []AppData, mirrorIfaces, trafficIfaces []string) MirrorcapDiscovery {
	d := MirrorcapDiscovery{
		Interfaces:       []DiscoveryInterface{},
		FlushIntervalSec: siteDiscoveryFlushIntervalSec,
		Log:              DefaultSiteDiscoveryLog,
	}
	seen := map[string]bool{}
	if hasAppMode(apps, applications.DeployModeMirror) {
		for _, name := range mirrorIfaces {
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			d.Interfaces = append(d.Interfaces, DiscoveryInterface{Name: name, Mode: applications.DeployModeMirror})
		}
	}
	if hasAppMode(apps, applications.DeployModeRouted) || hasAppMode(apps, applications.DeployModeTransparent) {
		mode := applications.DeployModeRouted
		if hasAppMode(apps, applications.DeployModeTransparent) {
			mode = applications.DeployModeTransparent
		}
		for _, name := range trafficIfaces {
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			d.Interfaces = append(d.Interfaces, DiscoveryInterface{Name: name, Mode: mode})
		}
	}
	d.Enabled = len(d.Interfaces) > 0
	return d
}

// isActiveTransparentApp 判定应用是否为需要执行透明牵引的 TRANSPARENT 应用：
// 排除 OFF/BYPASS（含授权失效强制 BYPASS），保证 BYPASS 真正关闭透明牵引。
func isActiveTransparentApp(app AppData) bool {
	if app.DeploymentMode != applications.DeployModeTransparent {
		return false
	}
	return app.ProtectionMode != applications.ModeOff && app.ProtectionMode != applications.ModeBypass
}

// isActiveDomain 判断域名是否处于生效状态（测试构造空 Status 视为 ACTIVE）。
func isActiveDomain(d applications.Domain) bool {
	return d.Status == "" || strings.EqualFold(d.Status, "ACTIVE")
}

// buildTproxydSidecar 由发布快照组装 tproxyd 边车配置（使用默认牵引/回环地址）。
func buildTproxydSidecar(apps []AppData) TproxydSidecar {
	return buildTproxydSidecarWithOptions(apps, DefaultTproxydListen, DefaultTproxydTarget, DefaultTproxydTargetTLS, nil)
}

// buildTproxydSidecarWithOptions 由发布快照与可配置地址/透传白名单组装 tproxyd 边车配置：
//   - 仅统计非 OFF/BYPASS 的 TRANSPARENT 应用及其启用域名端口；无有效端口时 enabled=false 且 ports=[]；
//   - protect_hosts 仅收集启用 HTTPS（HTTPSEnabled && HTTPSPort != nil）的规范化域名，
//     避免纯 HTTP 应用误触发 TLS SNI 嗅探与无目标 TLS 监听失败；
//   - passthrough_allowlist 来源于系统设置 network:tproxy_passthrough_allowlist（经归一化与校验）。
func buildTproxydSidecarWithOptions(apps []AppData, listen, target, targetTLS string, passthroughAllowlist []string) TproxydSidecar {
	if strings.TrimSpace(listen) == "" {
		listen = DefaultTproxydListen
	}
	if strings.TrimSpace(target) == "" {
		target = DefaultTproxydTarget
	}
	if strings.TrimSpace(targetTLS) == "" {
		targetTLS = DefaultTproxydTargetTLS
	}
	if passthroughAllowlist == nil {
		passthroughAllowlist = []string{}
	}
	ports := transparentSidecarPorts(apps)
	return TproxydSidecar{
		Enabled:              len(ports) > 0,
		Listen:               strings.TrimSpace(listen),
		Target:               strings.TrimSpace(target),
		Ports:                ports,
		TargetTLS:            strings.TrimSpace(targetTLS),
		ProtectHosts:         transparentProtectHosts(apps),
		PassthroughAllowlist: passthroughAllowlist,
	}
}

// transparentProtectHosts 收集非 OFF/BYPASS 的 TRANSPARENT 应用中启用了 HTTPS 的
// 规范化域名（去重排序；无则空数组 []）。纯 HTTP 域名不进入 protect_hosts。
func transparentProtectHosts(apps []AppData) []string {
	seen := map[string]bool{}
	var hosts []string
	for _, app := range apps {
		if !isActiveTransparentApp(app) {
			continue
		}
		for _, d := range app.Domains {
			if !isActiveDomain(d) || !d.HTTPSEnabled || d.HTTPSPort == nil {
				continue
			}
			h := d.NormalizedHostname
			if h == "" {
				h = d.Hostname
			}
			h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
			if h == "" || seen[h] {
				continue
			}
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return []string{}
	}
	sort.Strings(hosts)
	return hosts
}

// transparentSidecarPorts 收集非 OFF/BYPASS 的 TRANSPARENT 应用活动域名的监听端口
// （HTTP/HTTPS，去重排序；无则返回空数组 []，绝不凭空补 80 劫持无关流量）。
func transparentSidecarPorts(apps []AppData) []int {
	seen := map[int]bool{}
	var ports []int
	for _, app := range apps {
		if !isActiveTransparentApp(app) {
			continue
		}
		for _, d := range app.Domains {
			if !isActiveDomain(d) {
				continue
			}
			if d.HTTPEnabled && d.HTTPPort != nil && !seen[*d.HTTPPort] {
				seen[*d.HTTPPort] = true
				ports = append(ports, *d.HTTPPort)
			}
			if d.HTTPSEnabled && d.HTTPSPort != nil && !seen[*d.HTTPSPort] {
				seen[*d.HTTPSPort] = true
				ports = append(ports, *d.HTTPSPort)
			}
		}
	}
	if len(ports) == 0 {
		return []int{}
	}
	sort.Ints(ports)
	return ports
}

// ParseTproxyPassthroughAllowlist 解析系统设置 network:tproxy_passthrough_allowlist：
// 支持逗号/分号/换行分隔文本或 JSON 字符串数组，支持精确域名与单级前导通配符（*.example.com），
// 返回小写、去尾点、去重排序后的非 nil 列表（空串返回 []string{}, nil）。
func ParseTproxyPassthroughAllowlist(raw string) ([]string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return []string{}, nil
	}
	var parts []string
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &parts); err != nil {
			return nil, fmt.Errorf("passthrough_allowlist JSON 数组格式非法: %w", err)
		}
	} else {
		parts = strings.FieldsFunc(trimmed, func(r rune) bool {
			return r == ',' || r == ';' || r == '\n' || r == '\r'
		})
	}
	seen := make(map[string]struct{}, len(parts))
	hosts := make([]string, 0, len(parts))
	for _, p := range parts {
		h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p), "."))
		if h == "" {
			continue
		}
		if !validTproxyHostName(h) {
			return nil, fmt.Errorf("passthrough_allowlist 含非法域名 %q（仅允许精确域名或单级通配符 *.example.com）", p)
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 {
		return []string{}, nil
	}
	sort.Strings(hosts)
	return hosts, nil
}

// validTproxyHostName 校验归一化后的 tproxyd 域名（与 gateway/tproxyd/config.go 同口径）：
// 允许精确域名与 RFC 单级前导通配符 *.example.com（基础域至少两级标签）。
func validTproxyHostName(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	base := h
	if strings.HasPrefix(h, "*.") {
		base = h[2:]
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
			return false
		}
	}
	return true
}

func checkTproxyAddr(field, addr string) error {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return fmt.Errorf("tproxyd %s 地址非法 %q: %w", field, addr, err)
	}
	if host == "" {
		return fmt.Errorf("tproxyd %s 地址缺少主机 %q", field, addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("tproxyd %s 端口越界（1-65535）: %q", field, addr)
	}
	return nil
}

// validateTproxydSidecar 校验生成的 tproxyd.json 契约（监听/目标地址、端口、SNI 清单与透传白名单）。
func validateTproxydSidecar(sc TproxydSidecar) error {
	if err := checkTproxyAddr("listen", sc.Listen); err != nil {
		return err
	}
	if err := checkTproxyAddr("target", sc.Target); err != nil {
		return err
	}
	if err := checkTproxyAddr("target_tls", sc.TargetTLS); err != nil {
		return err
	}
	for _, port := range sc.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("tproxyd 端口越界（1-65535）: %d", port)
		}
	}
	for _, h := range sc.ProtectHosts {
		if !validTproxyHostName(h) {
			return fmt.Errorf("tproxyd protect_hosts 含非法域名: %q", h)
		}
	}
	for _, h := range sc.PassthroughAllowlist {
		if !validTproxyHostName(h) {
			return fmt.Errorf("tproxyd passthrough_allowlist 含非法域名: %q", h)
		}
	}
	return nil
}

// validateTransparentAppsUpstreams 检查透明模式应用在配置了启用域名时是否至少有一个活动源站。
// Caddy 透明反代链依赖已配置源站转发，0 活动源站会导致所有匹配请求返回 502。
func validateTransparentAppsUpstreams(apps []AppData) error {
	for _, app := range apps {
		if app.DeploymentMode != applications.DeployModeTransparent {
			continue
		}
		hasEnabledDomain := false
		for _, d := range app.Domains {
			if !isActiveDomain(d) {
				continue
			}
			if (d.HTTPEnabled && d.HTTPPort != nil) || (d.HTTPSEnabled && d.HTTPSPort != nil) {
				hasEnabledDomain = true
				break
			}
		}
		if !hasEnabledDomain {
			continue
		}
		activeUpstreams := 0
		for _, u := range app.Upstreams {
			if u.Status == "ACTIVE" {
				activeUpstreams++
			}
		}
		if activeUpstreams == 0 {
			return fmt.Errorf("透明模式应用 %s 已启用域名但缺少活动源站（0 个 ACTIVE 源站将导致 502），请至少配置一个启用状态的源站", app.Code)
		}
	}
	return nil
}

// hasAppMode 判断快照中是否存在指定部署模式的应用。
func hasAppMode(apps []AppData, mode string) bool {
	for _, app := range apps {
		if app.DeploymentMode == mode {
			return true
		}
	}
	return false
}

// sidecarPorts 收集指定部署模式应用的域名监听端口（HTTP/HTTPS，去重排序；无则 [80]）。
func sidecarPorts(apps []AppData, mode string) []int {
	seen := map[int]bool{}
	var ports []int
	for _, app := range apps {
		if app.DeploymentMode != mode {
			continue
		}
		for _, d := range app.Domains {
			if d.HTTPEnabled && d.HTTPPort != nil && !seen[*d.HTTPPort] {
				seen[*d.HTTPPort] = true
				ports = append(ports, *d.HTTPPort)
			}
			if d.HTTPSEnabled && d.HTTPSPort != nil && !seen[*d.HTTPSPort] {
				seen[*d.HTTPSPort] = true
				ports = append(ports, *d.HTTPSPort)
			}
		}
	}
	if len(ports) == 0 {
		return []int{80}
	}
	sort.Ints(ports)
	return ports
}

func (p *Publisher) effectiveTproxyListen() string {
	if s := strings.TrimSpace(p.tproxyListen); s != "" {
		return s
	}
	return DefaultTproxydListen
}

func (p *Publisher) effectiveTproxyTarget() string {
	if s := strings.TrimSpace(p.tproxyTarget); s != "" {
		return s
	}
	return DefaultTproxydTarget
}

func (p *Publisher) effectiveTproxyTargetTLS() string {
	if s := strings.TrimSpace(p.tproxyTargetTLS); s != "" {
		return s
	}
	return DefaultTproxydTargetTLS
}

func (p *Publisher) loadTproxyPassthroughAllowlist(ctx context.Context) ([]string, error) {
	if p.tproxyPassthrough == nil {
		return []string{}, nil
	}
	raw, err := p.tproxyPassthrough(ctx)
	if err != nil {
		return nil, err
	}
	return ParseTproxyPassthroughAllowlist(raw)
}

func (p *Publisher) buildTproxydSidecarFor(ctx context.Context, apps []AppData) (TproxydSidecar, error) {
	allowlist, err := p.loadTproxyPassthroughAllowlist(ctx)
	if err != nil {
		return TproxydSidecar{}, err
	}
	sc := buildTproxydSidecarWithOptions(
		apps,
		p.effectiveTproxyListen(),
		p.effectiveTproxyTarget(),
		p.effectiveTproxyTargetTLS(),
		allowlist,
	)
	return sc, nil
}

// validateTransparentConfig 在校验和发布阶段统一验证透明应用源站与 tproxyd.json 契约。
func (p *Publisher) validateTransparentConfig(ctx context.Context, apps []AppData) (TproxydSidecar, error) {
	if err := validateTransparentAppsUpstreams(apps); err != nil {
		return TproxydSidecar{}, err
	}
	sc, err := p.buildTproxydSidecarFor(ctx, apps)
	if err != nil {
		return TproxydSidecar{}, err
	}
	if err := validateTproxydSidecar(sc); err != nil {
		return TproxydSidecar{}, err
	}
	return sc, nil
}

// writeSidecarConfigs 发布成功后写镜像/透明边车配置到共享卷（附加产物，失败只记日志）。
func (p *Publisher) writeSidecarConfigs(ctx context.Context, apps []AppData) {
	p.writeMirrorcapSidecarConfig(ctx, apps)
	p.writeTproxydSidecarConfig(ctx, apps)
}

// writeMirrorcapSidecarConfig 写 mirrorcap.json 到共享卷。
// mirrorcap.json 恒含 discovery 块：接口按节点角色清单（MIRROR/TRAFFIC）以及透明网桥成员口填充，
// 清单查询失败不静默吞错（记日志并以空接口数组继续，边车配置不阻断发布结果）。
func (p *Publisher) writeMirrorcapSidecarConfig(ctx context.Context, apps []AppData) {
	dir := p.sidecarDir
	if dir == "" {
		dir = DefaultSidecarDir
	}
	var interfaces, trafficIfaces []string
	if p.mirrorIfaces != nil {
		ifs, err := p.mirrorIfaces.ListMirrorInterfaces(ctx, p.gatewayNode)
		if err != nil {
			slog.Warn("list mirror interfaces for sidecar config failed", "node", p.gatewayNode, "error", err)
		} else {
			interfaces = ifs
		}
		tifs, err := p.mirrorIfaces.ListInterfacesByRole(ctx, p.gatewayNode, nodeinterfaces.RoleTraffic)
		if err != nil {
			slog.Warn("list traffic interfaces for sidecar config failed", "node", p.gatewayNode, "error", err)
		} else {
			trafficIfaces = tifs
		}
	}
	if p.bridgePorts != nil && hasAppMode(apps, applications.DeployModeTransparent) {
		bports, err := p.bridgePorts.ListBridgePorts(ctx, p.gatewayNode)
		if err != nil {
			slog.Warn("list bridge ports for transparent site discovery failed", "node", p.gatewayNode, "error", err)
		} else {
			trafficIfaces = append(trafficIfaces, bports...)
		}
	}
	discovery := buildMirrorcapDiscovery(apps, interfaces, trafficIfaces)
	if p.sidecarDiscoveryLog != "" {
		discovery.Log = p.sidecarDiscoveryLog
	}
	mc := buildMirrorcapSidecar(apps, p.gatewayNode, interfaces, discovery)
	if p.sidecarEventsLog != "" {
		mc.EventsLog = p.sidecarEventsLog
	}
	if p.sidecarAuditLog != "" {
		mc.AuditLog = p.sidecarAuditLog
	}
	if hasDetectableMirrorApp(apps) && len(interfaces) == 0 {
		slog.Warn("mirror apps active but no MIRROR interface configured on node; mirrorcap detection kept disabled",
			"node", p.gatewayNode)
	}
	if err := writeSidecarFile(dir, "mirrorcap.json", mc); err != nil {
		slog.Warn("write mirrorcap sidecar config failed", "dir", dir, "error", err)
	}
}

// writeTproxydSidecarConfig 写 tproxyd.json 到共享卷（使用本次实际加载进 Caddy 的有效应用集合）。
func (p *Publisher) writeTproxydSidecarConfig(ctx context.Context, apps []AppData) {
	dir := p.sidecarDir
	if dir == "" {
		dir = DefaultSidecarDir
	}
	sc, err := p.buildTproxydSidecarFor(ctx, apps)
	if err != nil {
		slog.Warn("build tproxyd sidecar config failed, writing without passthrough allowlist", "error", err)
		sc = buildTproxydSidecarWithOptions(
			apps,
			p.effectiveTproxyListen(),
			p.effectiveTproxyTarget(),
			p.effectiveTproxyTargetTLS(),
			nil,
		)
	}
	if err := writeSidecarFile(dir, "tproxyd.json", sc); err != nil {
		slog.Warn("write tproxyd sidecar config failed", "dir", dir, "error", err)
	}
}

// restoreSidecarsAfterRollback 在显式回滚后同步主节点边车配置：
//   - mirrorcap.json 不依赖 Caddy 路由，按当前活动应用刷新；
//   - tproxyd.json 优先按目标版本 business_snapshot.tproxyd 恢复；若为历史版本（未记录
//     tproxyd 快照），则依据目标版本 configuration_json 是否含透明 server 决定关闭或按活库重建，
//     避免回滚到无透明应用的旧版本时残留启用状态的 tproxyd.json。
func (p *Publisher) restoreSidecarsAfterRollback(ctx context.Context, version *ConfigVersion) error {
	dir := p.sidecarDir
	if dir == "" {
		dir = DefaultSidecarDir
	}
	var liveApps []AppData
	if p.apps != nil {
		appsData, _, err := p.buildSnapshot(ctx, nil)
		if err != nil {
			return err
		}
		licenseValid := true
		if p.licenseState != nil {
			licenseValid, _ = p.licenseState(ctx)
		}
		if !licenseValid {
			for i := range appsData {
				appsData[i].ProtectionMode = applications.ModeBypass
			}
		}
		liveApps = appsData
		p.writeMirrorcapSidecarConfig(ctx, liveApps)
	}
	if version != nil {
		if sc, ok := extractTproxydFromSnapshot(version.BusinessSnapshot); ok {
			if strings.TrimSpace(sc.Listen) == "" {
				sc.Listen = p.effectiveTproxyListen()
			}
			if strings.TrimSpace(sc.Target) == "" {
				sc.Target = p.effectiveTproxyTarget()
			}
			if strings.TrimSpace(sc.TargetTLS) == "" {
				sc.TargetTLS = p.effectiveTproxyTargetTLS()
			}
			if sc.Ports == nil {
				sc.Ports = []int{}
			}
			if sc.ProtectHosts == nil {
				sc.ProtectHosts = []string{}
			}
			if sc.PassthroughAllowlist == nil {
				sc.PassthroughAllowlist = []string{}
			}
			if err := writeSidecarFile(dir, "tproxyd.json", sc); err != nil {
				slog.Warn("restore tproxyd sidecar config from version snapshot failed", "version", version.ID, "error", err)
			}
			return nil
		}
		hasTransparentServer := strings.Contains(version.ConfigurationJSON, `"srv_transparent_http"`) ||
			strings.Contains(version.ConfigurationJSON, `"srv_transparent_https"`)
		if !hasTransparentServer {
			allowlist, _ := p.loadTproxyPassthroughAllowlist(ctx)
			if allowlist == nil {
				allowlist = []string{}
			}
			disabled := TproxydSidecar{
				Enabled:              false,
				Listen:               p.effectiveTproxyListen(),
				Target:               p.effectiveTproxyTarget(),
				Ports:                []int{},
				TargetTLS:            p.effectiveTproxyTargetTLS(),
				ProtectHosts:         []string{},
				PassthroughAllowlist: allowlist,
			}
			if err := writeSidecarFile(dir, "tproxyd.json", disabled); err != nil {
				slog.Warn("write disabled tproxyd sidecar config after rollback failed", "version", version.ID, "error", err)
			}
			return nil
		}
	}
	if liveApps != nil {
		p.writeTproxydSidecarConfig(ctx, liveApps)
	}
	return nil
}

func extractTproxydFromSnapshot(snapshotJSON string) (TproxydSidecar, bool) {
	if strings.TrimSpace(snapshotJSON) == "" {
		return TproxydSidecar{}, false
	}
	var snap struct {
		Tproxyd *TproxydSidecar `json:"tproxyd"`
	}
	if err := json.Unmarshal([]byte(snapshotJSON), &snap); err != nil || snap.Tproxyd == nil {
		return TproxydSidecar{}, false
	}
	return *snap.Tproxyd, true
}

// RefreshSidecarConfigs 按当前全部活动应用与节点网口角色刷新 mirrorcap.json / tproxyd.json。
// 用于：网口角色变更（设为/取消 MIRROR 或 TRAFFIC）、回滚后同步、局部发布后保持全局边车一致。
func (p *Publisher) RefreshSidecarConfigs(ctx context.Context) error {
	if p.apps == nil {
		return nil
	}
	appsData, _, err := p.buildSnapshot(ctx, nil)
	if err != nil {
		return err
	}
	licenseValid := true
	if p.licenseState != nil {
		licenseValid, _ = p.licenseState(ctx)
	}
	if !licenseValid {
		for i := range appsData {
			appsData[i].ProtectionMode = applications.ModeBypass
		}
	}
	p.writeSidecarConfigs(ctx, appsData)
	return nil
}

// writeSidecarFile 原子写边车配置（同目录临时文件 + rename；目录不存在则创建）。
// 文件 0644 / 目录 0770（显式 Chmod 避免 umask 剥离组写位）：内容无敏感信息，
// 且供加入共享组 1000（无 CAP_DAC_OVERRIDE）的 netmgrd 等网关边车读写目录，同时不开放 other 权限。
func writeSidecarFile(dir, name string, v interface{}) error {
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return fmt.Errorf("创建边车配置目录失败: %w", err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		return fmt.Errorf("设置边车配置目录权限失败: %w", err)
	}
	buf, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("序列化边车配置失败: %w", err)
	}
	buf = append(buf, '\n')
	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return fmt.Errorf("创建边车配置临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(buf); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("写入边车配置临时文件失败: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("设置边车配置权限失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("关闭边车配置临时文件失败: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("替换边车配置失败: %w", err)
	}
	return nil
}
