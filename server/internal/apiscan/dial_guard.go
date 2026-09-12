// dial_guard.go 扫描目标拨号复检（DNS 重绑定防护）。
//
// 与 apisecurity specFetchTransport 同构（DialContext 内重解析 + 逐 IP 校验），
// 但判定口径不同：规范导入要求公网地址，而扫描目标多为内网授权资产，
// 故本文件以「授权校验时刻的解析快照」为基准——执行前把 base_url 主机解析结果
// 固化为快照，每次拨号重新解析并逐一比对，出现快照外地址即拒绝拨号，
// 且只连接已复检地址，消除 hostAllowed 字符串校验与真实拨号之间的 DNS 重绑定窗口。
package apiscan

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// scanHTTPTimeout 探测拨号/握手/整体超时（与引擎默认客户端 10s 语义一致）。
const scanHTTPTimeout = 10 * time.Second

// normalizeIP IPv4 映射地址归一（::ffff:127.0.0.1 与 127.0.0.1 视为同一地址）。
func normalizeIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// resolveHostSnapshot 授权校验时刻的解析快照：base_url 主机当前全部解析结果
// （字面 IP 直接收录，不经 DNS）。解析失败/为空返回错误（fail-closed）。
func resolveHostSnapshot(ctx context.Context, rawBaseURL string) ([]net.IP, error) {
	u, err := url.Parse(rawBaseURL)
	if err != nil || u == nil || u.Hostname() == "" {
		return nil, fmt.Errorf("apiscan: 目标 base_url 非法: %q", rawBaseURL)
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{normalizeIP(ip)}, nil
	}
	return lookupHostIPs(ctx, host)
}

// lookupHostIPs 解析主机全部 A/AAAA 记录（归一化；失败/为空返回错误）。
func lookupHostIPs(ctx context.Context, host string) ([]net.IP, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("apiscan: 目标主机 %s 解析失败", host)
	}
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		out = append(out, normalizeIP(ip))
	}
	return out, nil
}

// pinnedTransport 拨号时重解析复检的 Transport：每次拨号重新解析目标主机，
// 任一解析结果落在授权快照外即拒绝（疑似 DNS 重绑定）；全部命中才拨号，
// 且直接连接已复检的快照内地址。lookup 可注入（测试），nil 用系统解析器。
func pinnedTransport(snapshot []net.IP, lookup func(ctx context.Context, host string) ([]net.IP, error)) *http.Transport {
	allowed := make(map[string]bool, len(snapshot))
	for _, ip := range snapshot {
		allowed[normalizeIP(ip).String()] = true
	}
	if lookup == nil {
		lookup = lookupHostIPs
	}
	dialer := &net.Dialer{Timeout: scanHTTPTimeout}
	return &http.Transport{
		TLSHandshakeTimeout: scanHTTPTimeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("apiscan: 拨号地址解析失败: %v", err)
			}
			ips, err := lookup(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if !allowed[normalizeIP(ip).String()] {
					return nil, fmt.Errorf("apiscan: 主机 %s 重解析出现授权快照外地址 %s，拒绝拨号（疑似 DNS 重绑定）", host, ip)
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(normalizeIP(ips[0]).String(), port))
		},
	}
}

// newPinnedHTTPClient 装配拨号复检客户端：快照复检 Transport + 10s 超时 + 不跟随重定向
// （不跟随重定向与引擎默认客户端语义一致：避免登录跳转被误判为"未认证可访问"）。
func newPinnedHTTPClient(snapshot []net.IP) *http.Client {
	return &http.Client{
		Transport: pinnedTransport(snapshot, nil),
		Timeout:   scanHTTPTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
