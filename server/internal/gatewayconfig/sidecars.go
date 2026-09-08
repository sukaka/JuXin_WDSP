// sidecars.go 镜像/透明部署模式边车配置（docs/NETWORK_MODES_DESIGN.md §4.2/§4.3）：
// 发布成功后由发布通道写出到与网关容器共享的卷，gateway/mirrorcap 与 gateway/tproxyd 消费。
// 边车配置属于发布的附加产物：写失败只记日志，不回滚已加载的 Caddy 配置。
package gatewayconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"

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
	// tproxyd 牵引监听与下游 Caddy 地址（与 gateway/tproxyd PoC 拓扑一致，§4.3.1）
	tproxydListen = "127.0.0.1:15000"
	tproxydTarget = "127.0.0.1:8080"
	// tproxydTargetTLS 下游 Caddy TLS 监听器地址（SNI 防护清单内域名的终结检测入口，
	// 见 gateway/tproxyd sni.go；§4.3.1 HTTPS SNI 分流实测）
	tproxydTargetTLS = "127.0.0.1:8443"
)

// MirrorcapSidecar 是 mirrorcap.json 内容（gateway/mirrorcap 消费）。
// Interfaces/Ports 恒为数组（空数组而非 null）；Discovery 恒存在（无可用接口时 enabled=false）。
type MirrorcapSidecar struct {
	Enabled    bool               `json:"enabled"`
	Node       string             `json:"node"`
	Interfaces []string           `json:"interfaces"`
	Ports      []int              `json:"ports"`
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

// TproxydSidecar 是 tproxyd.json 内容（gateway/tproxyd 消费）。Ports/ProtectHosts 恒为数组。
// ProtectHosts 为 TLS SNI 防护域名清单：清单内域名的 TLS 连接送 TargetTLS 终结检测；
// 同 IP 清单外域名的加密流量按原始目的端到端透传（网关无需其证书）。空数组 = 关闭分流。
type TproxydSidecar struct {
	Enabled      bool     `json:"enabled"`
	Listen       string   `json:"listen"`
	Target       string   `json:"target"`
	Ports        []int    `json:"ports"`
	TargetTLS    string   `json:"target_tls"`
	ProtectHosts []string `json:"protect_hosts"`
}

// MirrorInterfacesProvider 提供节点网口清单（nodeinterfaces.Store 实现；nil 时输出空数组）。
type MirrorInterfacesProvider interface {
	// ListMirrorInterfaces 返回节点 role=MIRROR 且 present 的接口名（sort_order 升序）。
	ListMirrorInterfaces(ctx context.Context, nodeName string) ([]string, error)
	// ListInterfacesByRole 返回节点指定 role 且 present 的接口名（站点发现按角色取 TRAFFIC 口）。
	ListInterfacesByRole(ctx context.Context, nodeName, role string) ([]string, error)
}

// buildMirrorcapSidecar 由发布快照组装 mirrorcap 边车配置：
// 无任何 MIRROR 应用时 enabled=false（文件保留不删除）；ports 取全部 MIRROR 应用
// 域名监听端口（去重排序，无则 [80]）；interfaces 为该节点 role=MIRROR 且 present 的接口名；
// discovery 块由 buildMirrorcapDiscovery 组装（站点资产被动发现，恒输出）。
func buildMirrorcapSidecar(apps []AppData, node string, interfaces []string, discovery MirrorcapDiscovery) MirrorcapSidecar {
	if interfaces == nil {
		interfaces = []string{}
	}
	return MirrorcapSidecar{
		Enabled:    hasAppMode(apps, applications.DeployModeMirror),
		Node:       node,
		Interfaces: interfaces,
		Ports:      sidecarPorts(apps, applications.DeployModeMirror),
		Discovery:  discovery,
	}
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

// buildTproxydSidecar 由发布快照组装 tproxyd 边车配置：
// 有 TRANSPARENT 应用时 enabled=true，ports 取这些应用域名监听端口（缺省 [80]）；
// protect_hosts 自动派生自 TRANSPARENT 应用的域名清单（normalized_hostname，
// 去重排序）——同 IP 多虚拟主机场景下，仅清单内域名的 TLS 流量被终结检测，
// 清单外端到端透传，前端无需额外配置（§4.3.1 HTTPS SNI 分流）。
func buildTproxydSidecar(apps []AppData) TproxydSidecar {
	return TproxydSidecar{
		Enabled:      hasAppMode(apps, applications.DeployModeTransparent),
		Listen:       tproxydListen,
		Target:       tproxydTarget,
		Ports:        sidecarPorts(apps, applications.DeployModeTransparent),
		TargetTLS:    tproxydTargetTLS,
		ProtectHosts: transparentProtectHosts(apps),
	}
}

// transparentProtectHosts 收集 TRANSPARENT 应用的规范化域名（去重排序；无则空数组）。
func transparentProtectHosts(apps []AppData) []string {
	seen := map[string]bool{}
	var hosts []string
	for _, app := range apps {
		if app.DeploymentMode != applications.DeployModeTransparent {
			continue
		}
		for _, d := range app.Domains {
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
		return []string{}
	}
	sort.Strings(hosts)
	return hosts
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

// writeSidecarConfigs 发布成功后写镜像/透明边车配置到共享卷（附加产物，失败只记日志）。
// mirrorcap.json 恒含 discovery 块：接口按节点角色清单（MIRROR/TRAFFIC）填充，
// 清单查询失败不静默吞错（记日志并以空接口数组继续，边车配置不阻断发布结果）。
func (p *Publisher) writeSidecarConfigs(ctx context.Context, apps []AppData) {
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
	discovery := buildMirrorcapDiscovery(apps, interfaces, trafficIfaces)
	if err := writeSidecarFile(dir, "mirrorcap.json", buildMirrorcapSidecar(apps, p.gatewayNode, interfaces, discovery)); err != nil {
		slog.Warn("write mirrorcap sidecar config failed", "dir", dir, "error", err)
	}
	if err := writeSidecarFile(dir, "tproxyd.json", buildTproxydSidecar(apps)); err != nil {
		slog.Warn("write tproxyd sidecar config failed", "dir", dir, "error", err)
	}
}

// writeSidecarFile 原子写边车配置（同目录临时文件 + rename；目录不存在则创建）。
// 文件 0644 / 目录 0755：内容无敏感信息，且需跨容器（网关侧）可读。
func writeSidecarFile(dir, name string, v interface{}) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建边车配置目录失败: %w", err)
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
