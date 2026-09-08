// outbound.go 通知出口 SSRF 防护装配（SEC-01）：webhook/短信网关统一经 outboundhttp
// 防护客户端外发（公网地址校验 + 拨号重解析复检 + 不跟随重定向）；企业微信/飞书机器人
// 额外锁定官方域名（仅 https + 默认 443 端口）。确有内网目标（如内网短信网关）时，
// 经 settings 允许列表显式放行，不接受任意私网地址。
package notify

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/jiuzhang-waf/server/internal/outboundhttp"
)

// AllowlistSettingKey 是内网目标允许列表的 settings 键（notify 组，热读生效）。
// 值为逗号分隔的 CIDR 或精确主机名，如 "10.0.0.0/8, sms.internal.example.com"；
// 默认空 = 不允许任何内网/保留地址目标。允许列表不解除企业微信/飞书的官方域名锁定。
const AllowlistSettingKey = "notify_outbound_allowlist"

// officialWebhookHosts 是官方机器人域名锁定表（渠道类型 → 允许的精确主机名）。
var officialWebhookHosts = map[string]map[string]bool{
	TypeWecom:  {"qyapi.weixin.qq.com": true},
	TypeFeishu: {"open.feishu.cn": true, "open.larksuite.com": true},
}

// outboundGuard 是出口防护装配（resolver/allowlist 源可注入；测试整体替换）。
type outboundGuard struct {
	resolver          outboundhttp.Resolver // nil = 系统 DNS
	allowlist         func() string
	lockOfficialHosts bool
}

// outbound 是当前生效的出口防护装配。默认：系统 DNS、空允许列表、锁定官方域名。
var outbound = &outboundGuard{
	allowlist:         func() string { return "" },
	lockOfficialHosts: true,
}

// SetOutboundAllowlistSource 注入允许列表配置源（app 装配层：settings notify 组；
// 每次发送/校验重新读取，settings 修改即时生效）。
func SetOutboundAllowlistSource(fn func() string) {
	if fn != nil {
		outbound.allowlist = fn
	}
}

// policy 用当前允许列表构建出口策略；配置非法时如实报错（发送/校验失败而非静默放行）。
func (g *outboundGuard) policy() (*outboundhttp.Policy, error) {
	p, err := outboundhttp.NewPolicy(outboundhttp.Options{
		Timeout:      sendTimeout,
		MaxRedirects: 0, // 通知外发不跟随重定向（重定向视为配置错误或被劫持）
		Resolver:     g.resolver,
		Allowlist:    g.allowlist(),
	})
	if err != nil {
		return nil, fmt.Errorf("出口允许列表配置无效: %w", err)
	}
	return p, nil
}

// checkWebhookURL 校验 Webhook/短信网关地址（SEC-01 校验层）：
// 语法（仅 http/https、无内嵌凭据、端口合法）+ 企业微信/飞书官方域名锁定 +
// 字面量 IP 按当前允许列表做内网拒绝。域名目标的解析校验在保存时
// （ValidateChannelConfig）与拨号时（防护 Transport）复检。
func checkWebhookURL(channelType, raw string) error {
	if raw == "" {
		return fmt.Errorf("不能为空")
	}
	if raw == MaskedValue {
		return fmt.Errorf("须提供真实地址，不能为脱敏占位符")
	}
	u, err := outboundhttp.ParseURL(raw)
	if err != nil {
		return fmt.Errorf("须为合法 http/https 地址（%w）", err)
	}
	if hosts, locked := officialWebhookHosts[channelType]; locked && outbound.lockOfficialHosts {
		if u.Scheme != "https" {
			return fmt.Errorf("官方机器人 Webhook 仅允许 https")
		}
		if port := u.Port(); port != "" && port != "443" {
			return fmt.Errorf("官方机器人 Webhook 仅允许默认 443 端口")
		}
		if !hosts[strings.ToLower(u.Hostname())] {
			return fmt.Errorf("仅允许官方机器人域名（%s）", strings.Join(officialHostNames(channelType), " / "))
		}
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		pol, err := outbound.policy()
		if err != nil {
			return err
		}
		if err := pol.CheckIP(ip); err != nil {
			return fmt.Errorf("目标地址不被允许: %w", err)
		}
	}
	return nil
}

// officialHostNames 返回渠道官方域名清单（排序，供错误文案）。
func officialHostNames(channelType string) []string {
	out := make([]string, 0, len(officialWebhookHosts[channelType]))
	for h := range officialWebhookHosts[channelType] {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// ValidateChannelConfig 保存配置时的完整校验（SEC-01 两阶段之校验层）：先做
// 语法/密值/官方域名校验（ValidateConfig），再对 webhook/短信网关目标做深度校验——
// 域名解析全部 A/AAAA 记录，任一内网/保留地址即拒绝（允许列表除外）。
// 实际拨号时仍由防护 Transport 重解析复检，此处失败说明配置当下即不可达/不合规。
func (d *Dispatcher) ValidateChannelConfig(ctx context.Context, channelType string, cfg map[string]interface{}) error {
	if err := ValidateConfig(channelType, cfg); err != nil {
		return err
	}
	var target string
	switch channelType {
	case TypeWecom:
		c, err := ParseWecomConfig(cfg)
		if err != nil {
			return err
		}
		target = c.WebhookURL
	case TypeFeishu:
		c, err := ParseFeishuConfig(cfg)
		if err != nil {
			return err
		}
		target = c.WebhookURL
	case TypeSMS:
		c, err := ParseSMSConfig(cfg)
		if err != nil {
			return err
		}
		target = c.GatewayURL
	default:
		return nil // smtp/syslog 无 HTTP 出口（SMTP 为管理员显式配置的邮件服务器）
	}
	pol, err := outbound.policy()
	if err != nil {
		return err
	}
	if _, err := pol.ValidateURL(ctx, target); err != nil {
		return fmt.Errorf("目标地址校验失败: %w", err)
	}
	return nil
}
