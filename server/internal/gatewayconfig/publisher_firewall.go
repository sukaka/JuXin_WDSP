package gatewayconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
)

// FirewallEnsurer 提交一组 TCP 端口的宿主防火墙放行指令。成功仅表示指令已受理。
type FirewallEnsurer func(ports []int, userID uuid.UUID, requestID string) error

var errFirewallEnsureFailed = errors.New("firewall ensure failed")

const (
	firewallEnsureFailureCode    = "FIREWALL_ENSURE_FAILED"
	firewallEnsureFailureMessage = "防火墙放行指令提交失败，已中止发布，候选配置未加载"
)

func firewallEnsureTaskFailure(err error) (code, message string, ok bool) {
	if !errors.Is(err, errFirewallEnsureFailed) {
		return "", "", false
	}
	return firewallEnsureFailureCode, firewallEnsureFailureMessage, true
}

// SetFirewallEnsurer 注入发布前防火墙放行通道；nil 保持既有发布行为。
func (p *Publisher) SetFirewallEnsurer(ensurer FirewallEnsurer) {
	p.firewallEnsurer = ensurer
}

// listenerTCPPorts 与 Generate 的对外监听生成条件保持一致：
//   - MIRROR 不生成内联站点；
//   - TRANSPARENT 仅在内部回环（127.0.0.1:15080/15443）监听（桥接流量由 netmgrd 管理专用
//     iptables REDIRECT/INPUT 链，绝不在宿主机 firewalld DEFAULT_ZONE 放行内部回环或透明端口）；
//   - BYPASS 仍生成公网监听站点，只有协议启用且端口非空时才收集。
func listenerTCPPorts(apps []AppData) []int {
	seen := make(map[int]struct{})
	ports := make([]int, 0)
	add := func(enabled bool, port *int) {
		if !enabled || port == nil {
			return
		}
		if _, exists := seen[*port]; exists {
			return
		}
		seen[*port] = struct{}{}
		ports = append(ports, *port)
	}
	for _, app := range apps {
		if app.DeploymentMode == applications.DeployModeMirror || app.DeploymentMode == applications.DeployModeTransparent {
			continue
		}
		for _, domain := range app.Domains {
			add(domain.HTTPEnabled, domain.HTTPPort)
			add(domain.HTTPSEnabled, domain.HTTPSPort)
		}
	}
	sort.Ints(ports)
	return ports
}

// isLoopbackListenAddr 判定 Caddy 监听地址是否绑定在回环地址（127.0.0.0/8、::1、localhost）。
// 回环地址仅本机进程可达（如透明模式 127.0.0.1:15080/15443），绝不应在宿主机默认防火墙区域开放。
func isLoopbackListenAddr(addr string) bool {
	trimmed := strings.TrimSpace(addr)
	trimmed = strings.TrimPrefix(trimmed, "tcp/")
	trimmed = strings.TrimPrefix(trimmed, "tcp4/")
	trimmed = strings.TrimPrefix(trimmed, "tcp6/")
	host, _, err := net.SplitHostPort(trimmed)
	if err != nil {
		return false
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// extractPublicTCPPortsFromConfig 从候选 Caddy JSON 的 apps.http.servers.*.listen 中提取
// 非回环 TCP 监听端口（跳过 127.0.0.1/::1/localhost 回环监听）。
// 若 configJSON 不是带 apps.http.servers 的 Caddy JSON，返回 (nil, false) 供调用方回退。
func extractPublicTCPPortsFromConfig(configJSON string) ([]int, bool) {
	var parsed struct {
		Apps *struct {
			HTTP *struct {
				Servers map[string]struct {
					Listen []string `json:"listen"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(configJSON), &parsed); err != nil || parsed.Apps == nil || parsed.Apps.HTTP == nil {
		return nil, false
	}
	seen := make(map[int]struct{})
	ports := make([]int, 0)
	for _, srv := range parsed.Apps.HTTP.Servers {
		for _, rawAddr := range srv.Listen {
			if isLoopbackListenAddr(rawAddr) {
				continue
			}
			addr := strings.TrimSpace(rawAddr)
			addr = strings.TrimPrefix(addr, "tcp/")
			addr = strings.TrimPrefix(addr, "tcp4/")
			addr = strings.TrimPrefix(addr, "tcp6/")
			_, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				continue
			}
			port, err := strconv.Atoi(portStr)
			if err != nil || port < 1 || port > 65535 {
				continue
			}
			if _, dup := seen[port]; dup {
				continue
			}
			seen[port] = struct{}{}
			ports = append(ports, port)
		}
	}
	sort.Ints(ports)
	return ports, true
}

func firewallEnsureSummary(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	values := make([]string, len(ports))
	for i, port := range ports {
		values[i] = strconv.Itoa(port) + "/tcp"
	}
	return "；已提交防火墙放行：" + strings.Join(values, "、")
}

// loadGatewayConfigWithFirewall 在任何网关读取或候选加载之前提交防火墙指令。
// 通道失败时返回可识别错误，调用方据此落 FAILED，且不泄露底层错误到任务信息。
func (p *Publisher) loadGatewayConfigWithFirewall(
	ctx context.Context,
	loader gatewayConfigLoader,
	configJSON string,
	apps []AppData,
	in PublishInput,
) (string, []int, error) {
	ports, ok := extractPublicTCPPortsFromConfig(configJSON)
	if !ok {
		ports = listenerTCPPorts(apps)
	}
	if p.firewallEnsurer != nil {
		if err := p.firewallEnsurer(ports, in.RequestedBy, in.RequestID); err != nil {
			return "", nil, fmt.Errorf("%w: %v", errFirewallEnsureFailed, err)
		}
	}
	previousConfig, err := loadGatewayConfig(ctx, loader, configJSON)
	if err != nil {
		return "", nil, err
	}
	return previousConfig, ports, nil
}
