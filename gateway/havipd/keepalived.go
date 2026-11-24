// keepalived 配置生成与生命周期管理（启动/重载/停止/存活判定）。
//
// 生成的配置与 pidfile 均按组名隔离；信号只发给 pidfile 记录的 PID
// （本组件管理的实例），绝不影响主机上其他 keepalived 实例。
package havipd

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// keepalivedPaths 本组件管理的文件布局（dir 一般为 /var/run/caddy/sidecars/keepalived）。
type keepalivedPaths struct {
	Conf    string // keepalived 配置（0600，含认证串）
	PidFile string // 实例 pidfile
}

func pathsFor(dir, group string) keepalivedPaths {
	return keepalivedPaths{
		Conf:    filepath.Join(dir, group+".conf"),
		PidFile: filepath.Join(dir, group+".pid"),
	}
}

// renderConfig 生成 keepalived 配置文本。
// self 为本机成员条目（优先级）；advert 秒为 keepalived advert_int 单位（其仅支持秒）。
// unicast 模式：非空 peers 时生成 unicast_peer 块（unicast_src_ip 由调用方探测本机
// 在 VIP 承载口上的首个 IPv4 地址填入；探测不到时省略该行，keepalived 自动选源）。
func renderConfig(cfg Config, self MemberSpec, selfSrcIP string) string {
	var b strings.Builder
	b.WriteString("global_defs {\n")
	fmt.Fprintf(&b, "  router_id JZ_HA_%s\n", sanitizeRouterID(cfg.Group))
	b.WriteString("}\n\n")
	fmt.Fprintf(&b, "vrrp_instance %s {\n", cfg.Group)
	b.WriteString("  state BACKUP\n") // 初始态均为 BACKUP，由选举决定 MASTER（防双主抢始态）
	fmt.Fprintf(&b, "  interface %s\n", cfg.VRRP.Iface)
	fmt.Fprintf(&b, "  virtual_router_id %d\n", cfg.VRRP.VRID)
	fmt.Fprintf(&b, "  priority %d\n", self.Priority)
	fmt.Fprintf(&b, "  advert_int %d\n", max(1, cfg.VRRP.AdvertIntMs/1000))
	if !cfg.VRRP.Preempt {
		b.WriteString("  nopreempt\n")
	}
	if cfg.VRRP.AuthPass != "" {
		b.WriteString("  authentication {\n    auth_type PASS\n")
		fmt.Fprintf(&b, "    auth_pass %s\n  }\n", cfg.VRRP.AuthPass)
	}
	if len(cfg.VRRP.UnicastPeers) > 0 {
		if selfSrcIP != "" {
			fmt.Fprintf(&b, "  unicast_src_ip %s\n", selfSrcIP)
		}
		b.WriteString("  unicast_peer {\n")
		for _, p := range cfg.VRRP.UnicastPeers {
			// 排除自身地址（keepalived 不要求写自己；写了也无害，但干净起见过滤）
			if p != selfSrcIP {
				fmt.Fprintf(&b, "    %s\n", p)
			}
		}
		b.WriteString("  }\n")
	}
	if len(cfg.VRRP.TrackInterfaces) > 0 {
		b.WriteString("  track_interface {\n")
		for _, tif := range cfg.VRRP.TrackInterfaces {
			fmt.Fprintf(&b, "    %s\n", tif)
		}
		b.WriteString("  }\n")
	}
	b.WriteString("  virtual_ipaddress {\n")
	for _, vip := range cfg.VRRP.VIPs {
		fmt.Fprintf(&b, "    %s dev %s\n", vip, cfg.VRRP.Iface)
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

// sanitizeRouterID router_id 仅保留字母数字/下划线/连字符（keepalived 标识符安全集）。
func sanitizeRouterID(group string) string {
	var b strings.Builder
	for _, r := range group {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// writeConfAtomic 原子写 keepalived 配置（0600：含认证串）。
func writeConfAtomic(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建 keepalived 配置目录: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".ha-vip-*.tmp")
	if err != nil {
		return fmt.Errorf("创建配置临时文件: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("写配置临时文件: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("设置配置权限: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("关闭配置临时文件: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("原子替换配置: %w", err)
	}
	return nil
}

// parseAddrDump 解析 `ip -j addr show dev <if>` 输出，返回首个全局 IPv4 地址
// （unicast_src_ip 探测）与 VIP 在位判定所需的地址集合。
func parseAddrDump(dump []byte) (srcIP string, addrs []string, err error) {
	var entries []struct {
		AddrInfo []struct {
			Family string `json:"family"`
			Local  string `json:"local"`
			Scope  string `json:"scope"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(dump, &entries); err != nil {
		return "", nil, fmt.Errorf("解析 ip addr 输出: %w", err)
	}
	for _, e := range entries {
		for _, a := range e.AddrInfo {
			if a.Family != "inet" {
				continue
			}
			addrs = append(addrs, a.Local)
			if srcIP == "" && a.Scope == "global" && net.ParseIP(a.Local) != nil {
				srcIP = a.Local
			}
		}
	}
	return srcIP, addrs, nil
}

// vipPresent 判定任一 VIP 是否落在给定地址集合中（按 VIP 的地址部分比对，
// 忽略掩码——keepalived 以配置掩码上地址，在位即算持有）。
func vipPresent(vips []string, addrs []string) bool {
	for _, vip := range vips {
		ip, _, err := net.ParseCIDR(vip)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a == ip.String() {
				return true
			}
		}
	}
	return false
}
