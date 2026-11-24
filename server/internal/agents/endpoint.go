// endpoint.go 管理端 Agent 一键部署接入地址自动探测与默认地址配置。
//
// 目标：管理员在 WDSP 控制台打开部署向导时，自动推导出客户端可直接经 IP 访问的
// WDSP HTTPS 接入地址（例如 https://192.168.10.20:8443），避免直接复制 localhost
// 或被 Agent 拒绝的非回环 http://:8080 地址，同时支持保存自定义默认对接地址（VIP/NAT IP/域名）。
package agents

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

const (
	installEndpointSettingsGroup = "traffic_agent"
	installEndpointSettingsKey   = "install_server_url"
	defaultConsoleHTTPSPort      = 8443
)

// InstallEndpointConfig WDSP 接入地址探测配置。
type InstallEndpointConfig struct {
	PublicURL        string
	ConsoleHTTPSPort int
	HostIPs          []string
	ConsoleCertFile  string
	Settings         SettingsKV
	// detectLocalIPs 供单元测试注入，生产默认调用 detectHostInterfaceIPs。
	detectLocalIPs func() []string
}

// InstallEndpointResponse GET/PUT /api/v1/traffic/agents/install-endpoint 响应。
type InstallEndpointResponse struct {
	RecommendedURL string   `json:"recommended_url"`
	SavedURL       string   `json:"saved_url"`
	Source         string   `json:"source"`
	HTTPSPort      int      `json:"https_port"`
	SelfSignedTLS  bool     `json:"self_signed_tls"`
	CandidateIPs   []string `json:"candidate_ips"`
	CandidateURLs  []string `json:"candidate_urls"`
}

// SetInstallEndpointConfig 配置 Agent 一键部署接入地址探测与持久化依赖。
func (h *Handler) SetInstallEndpointConfig(cfg InstallEndpointConfig) *Handler {
	h.endpointCfg = cfg
	return h
}

func (h *Handler) effectiveHTTPSPort() int {
	if h.endpointCfg.ConsoleHTTPSPort >= 1 && h.endpointCfg.ConsoleHTTPSPort <= 65535 {
		return h.endpointCfg.ConsoleHTTPSPort
	}
	return defaultConsoleHTTPSPort
}

// NormalizeInstallServerURL 归一化并校验 WDSP 接入地址。
// 支持裸 IP（192.168.10.20 → https://192.168.10.20:<port>）、IP:端口、域名或完整 https:// URL；
// 非回环地址严禁明文 http://（与 wdsp-agent/internal/transport MED-19 对齐），
// 并拒绝路径、查询串、凭据段与控制/Shell 元字符。空串返回 ("", nil) 表示清空覆盖。
func NormalizeInstallServerURL(raw string, defaultHTTPSPort int) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil
	}
	if len(s) > 256 {
		return "", fmt.Errorf("对接地址长度不能超过 256 字符")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(" \t\r\n'\"`$;&|<>\\", r) {
			return "", fmt.Errorf("对接地址包含非法字符")
		}
	}
	if defaultHTTPSPort < 1 || defaultHTTPSPort > 65535 {
		defaultHTTPSPort = defaultConsoleHTTPSPort
	}

	hadScheme := strings.Contains(s, "://")
	if !hadScheme {
		s = strings.TrimRight(s, "/")
		// 裸 IPv6 地址（如 fd00::1）补方括号
		if ip := net.ParseIP(s); ip != nil && ip.To4() == nil {
			s = "[" + ip.String() + "]"
		}
		s = "https://" + s
	}

	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("对接地址格式无效，请填写 IP 或 https://地址[:端口]")
	}
	if u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("对接地址仅允许协议、主机和端口，不能包含账号、查询参数或片段")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("对接地址不能包含子路径，请填写根地址（如 https://192.168.10.20:8443）")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("对接地址缺少有效的主机或 IP")
	}
	switch scheme {
	case "https":
	case "http":
		if !isLoopbackHostName(host) {
			return "", fmt.Errorf("非本机地址必须使用 https://（Agent 禁止明文 HTTP 传输凭据），请改为 https://%s:%d", formatHostForURL(host), defaultHTTPSPort)
		}
	default:
		return "", fmt.Errorf("对接地址仅支持 https:// 协议")
	}

	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("端口号无效: %s", port)
		}
	} else if !hadScheme && scheme == "https" && defaultHTTPSPort != 443 {
		port = strconv.Itoa(defaultHTTPSPort)
	}

	hostPart := formatHostForURL(host)
	if port != "" && !((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) {
		return fmt.Sprintf("%s://%s:%s", scheme, hostPart, port), nil
	}
	return fmt.Sprintf("%s://%s", scheme, hostPart), nil
}

func formatHostForURL(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

func formatHTTPSURL(host string, port int) string {
	h := formatHostForURL(host)
	if port <= 0 || port == 443 {
		return "https://" + h
	}
	return fmt.Sprintf("https://%s:%d", h, port)
}

func isLoopbackHostName(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.IsLoopback()
}

func isUsableRemoteIP(raw string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsLoopback() || addr.IsUnspecified() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() {
		return "", false
	}
	return addr.String(), true
}

func isPrivateRFC1918(ipStr string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil || !addr.Is4() {
		return false
	}
	b := addr.As4()
	return b[0] == 10 || (b[0] == 192 && b[1] == 168) || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
}

func isLikelyDockerBridgeIP(ipStr string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil || !addr.Is4() {
		return false
	}
	b := addr.As4()
	// Docker 默认网桥段常落在 172.17.0.0/16 ~ 172.31.0.0/16；当存在其他网段 IP 时排在后面
	return b[0] == 172 && b[1] >= 17 && b[1] <= 31
}

// inspectConsoleCert 仅读取控制台公开证书的 SAN IP 与是否自签，绝不触碰私钥。
func inspectConsoleCert(path string) (ips []string, selfSigned bool, loaded bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, false
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, false, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false, false
	}
	for _, ip := range cert.IPAddresses {
		if norm, ok := isUsableRemoteIP(ip.String()); ok {
			ips = append(ips, norm)
		}
	}
	// 控制台自签证书（console-cert.sh）通常带 CA:FALSE 且无 keyCertSign，
	// 因此用 RawIssuer==RawSubject + CheckSignature 校验自签（CheckSignatureFrom 会要求 KeyUsageCertSign）。
	isSelf := bytes.Equal(cert.RawIssuer, cert.RawSubject) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
	return ips, isSelf, true
}

func detectHostInterfaceIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var lanV4, dockerV4, otherV4, v6 []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := strings.ToLower(iface.Name)
		if strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") ||
			strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "cni") ||
			strings.HasPrefix(name, "flannel") || strings.HasPrefix(name, "utun") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			norm, ok := isUsableRemoteIP(ip.String())
			if !ok {
				continue
			}
			addr, _ := netip.ParseAddr(norm)
			if addr.Is4() {
				switch {
				case isLikelyDockerBridgeIP(norm):
					dockerV4 = append(dockerV4, norm)
				case isPrivateRFC1918(norm):
					lanV4 = append(lanV4, norm)
				default:
					otherV4 = append(otherV4, norm)
				}
			} else {
				v6 = append(v6, norm)
			}
		}
	}
	out := make([]string, 0, len(lanV4)+len(otherV4)+len(dockerV4)+len(v6))
	out = append(out, lanV4...)
	out = append(out, otherV4...)
	out = append(out, dockerV4...)
	out = append(out, v6...)
	return out
}

func splitHostPortSafe(hostHeader string) (host, port string) {
	h := strings.TrimSpace(hostHeader)
	if h == "" {
		return "", ""
	}
	if parsedHost, parsedPort, err := net.SplitHostPort(h); err == nil {
		return strings.Trim(parsedHost, "[]"), parsedPort
	}
	return strings.Trim(h, "[]"), ""
}

func (h *Handler) resolveInstallEndpoint(r *http.Request) InstallEndpointResponse {
	httpsPort := h.effectiveHTTPSPort()

	var savedURL string
	if h.endpointCfg.Settings != nil {
		rawSaved := strings.TrimSpace(h.endpointCfg.Settings.GetString(r.Context(), installEndpointSettingsGroup, installEndpointSettingsKey, ""))
		if norm, err := NormalizeInstallServerURL(rawSaved, httpsPort); err == nil {
			savedURL = norm
		}
	}

	envURL, _ := NormalizeInstallServerURL(h.endpointCfg.PublicURL, httpsPort)

	certIPs, certSelfSigned, certLoaded := inspectConsoleCert(h.endpointCfg.ConsoleCertFile)

	var envHostIPs []string
	for _, raw := range h.endpointCfg.HostIPs {
		if norm, ok := isUsableRemoteIP(raw); ok {
			envHostIPs = append(envHostIPs, norm)
		}
	}

	detectFn := h.endpointCfg.detectLocalIPs
	if detectFn == nil {
		detectFn = detectHostInterfaceIPs
	}
	localIPs := detectFn()

	// 解析当前浏览器请求的 Host（Caddy 反代默认透传原始 Host 与 X-Forwarded-Proto）
	reqHost, reqPort := splitHostPortSafe(r.Host)
	reqIsHTTPS := r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
	var reqURL string
	var reqIP string
	if reqHost != "" && !isLoopbackHostName(reqHost) {
		if normIP, ok := isUsableRemoteIP(reqHost); ok {
			reqIP = normIP
		}
		if reqIsHTTPS && reqPort != "" {
			if n, err := strconv.Atoi(reqPort); err == nil && n >= 1 && n <= 65535 {
				reqURL = formatHTTPSURL(reqHost, n)
			}
		} else if reqIsHTTPS {
			reqURL = formatHTTPSURL(reqHost, 443)
		} else {
			// 浏览器经 HTTP（如 :8080）访问控制台时，自动升级到 HTTPS 控制台端口（默认 :8443）
			reqURL = formatHTTPSURL(reqHost, httpsPort)
		}
	}

	// 汇总去重候选 IP（优先级：请求 IP → 安装期宿主机 IP → 证书 SAN IP → 本机网卡 IP）
	seen := make(map[string]struct{})
	candidateIPs := make([]string, 0, 8)
	addIP := func(ip string) {
		if norm, ok := isUsableRemoteIP(ip); ok {
			if _, exists := seen[norm]; !exists {
				seen[norm] = struct{}{}
				candidateIPs = append(candidateIPs, norm)
			}
		}
	}
	if reqIP != "" {
		addIP(reqIP)
	}
	for _, ip := range envHostIPs {
		addIP(ip)
	}
	for _, ip := range certIPs {
		addIP(ip)
	}
	for _, ip := range localIPs {
		addIP(ip)
	}

	candidateURLs := make([]string, 0, len(candidateIPs))
	for _, ip := range candidateIPs {
		candidateURLs = append(candidateURLs, formatHTTPSURL(ip, httpsPort))
	}

	recommendedURL := ""
	source := "unresolved"
	switch {
	case savedURL != "":
		recommendedURL = savedURL
		source = "saved"
	case envURL != "":
		recommendedURL = envURL
		source = "env"
	case reqURL != "":
		recommendedURL = reqURL
		source = "request_host"
	case len(envHostIPs) > 0:
		recommendedURL = formatHTTPSURL(envHostIPs[0], httpsPort)
		source = "configured_host_ip"
	case len(certIPs) > 0:
		recommendedURL = formatHTTPSURL(certIPs[0], httpsPort)
		source = "console_cert"
	case len(localIPs) > 0:
		recommendedURL = formatHTTPSURL(localIPs[0], httpsPort)
		source = "host_interface"
	}

	// 自签 TLS 判定：优先以 console.crt 为准；无证书文件时，若目标为 IP 直连则按 WDSP 默认自签保守提示
	selfSigned := false
	if certLoaded {
		selfSigned = certSelfSigned
	} else if u, err := url.Parse(recommendedURL); err == nil && u.Hostname() != "" {
		if _, parseErr := netip.ParseAddr(u.Hostname()); parseErr == nil {
			selfSigned = true
		}
	}

	return InstallEndpointResponse{
		RecommendedURL: recommendedURL,
		SavedURL:       savedURL,
		Source:         source,
		HTTPSPort:      httpsPort,
		SelfSignedTLS:  selfSigned,
		CandidateIPs:   candidateIPs,
		CandidateURLs:  candidateURLs,
	}
}

// GetInstallEndpoint GET /api/v1/traffic/agents/install-endpoint：返回自动探测的 WDSP IP 对接地址。
func (h *Handler) GetInstallEndpoint(w http.ResponseWriter, r *http.Request) {
	response.JSON(w, r, http.StatusOK, h.resolveInstallEndpoint(r))
}

// UpdateInstallEndpoint PUT /api/v1/traffic/agents/install-endpoint：保存/清空默认 WDSP 对接地址。
func (h *Handler) UpdateInstallEndpoint(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var body struct {
		ServerURL string `json:"server_url"`
	}
	if !decodeAdminJSON(w, r, &body) {
		return
	}
	if h.endpointCfg.Settings == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "系统设置服务未就绪，暂不支持保存默认对接地址")
		return
	}
	normalized, err := NormalizeInstallServerURL(body.ServerURL, h.effectiveHTTPSPort())
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	var operatorID uuid.UUID
	if p != nil {
		operatorID = p.UserID
	}
	if err := h.endpointCfg.Settings.UpsertString(
		r.Context(),
		installEndpointSettingsGroup,
		installEndpointSettingsKey,
		normalized,
		"WDSP 流量采集 Agent 默认对接地址（IP/域名）",
		operatorID,
	); err != nil {
		h.adminInternal(w, r, err)
		return
	}
	detailJSON, _ := json.Marshal(map[string]any{"server_url": normalized})
	h.recordAudit(r, p, "update", "agent_install_endpoint", installEndpointSettingsKey, normalized,
		"", string(detailJSON), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, h.resolveInstallEndpoint(r))
}
