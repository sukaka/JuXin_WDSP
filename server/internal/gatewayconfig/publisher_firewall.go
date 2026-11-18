package gatewayconfig

import (
	"context"
	"errors"
	"fmt"
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

// listenerTCPPorts 与 Generate 的监听生成条件保持一致：MIRROR 不生成站点，
// BYPASS 仍生成监听站点，只有协议启用且端口非空时才收集。
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
		if app.DeploymentMode == applications.DeployModeMirror {
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
	ports := listenerTCPPorts(apps)
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
