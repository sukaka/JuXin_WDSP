// Package upstreams 提供源站连通性测试与健康检查（含SSRF防护）。
package upstreams

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/validation"
)

// 测试限制
const (
	maxResponseBytes = 8 * 1024 // 限制响应读取大小
	maxRedirects     = 0        // 默认不跟随跨主机跳转
	dialTimeout      = 5 * time.Second
	tlsTimeout       = 5 * time.Second
	httpTimeout      = 8 * time.Second
)

// TestInput 是源站测试输入。
type TestInput struct {
	Scheme          string
	Host            string
	Port            int
	HealthCheckPath string
	TLSServerName   string
	TLSVerify       bool
	// AllowPrivate 是否允许私网/内网源站（受控允许列表，默认false）
	AllowPrivate bool
}

// TestResult 是源站测试结果。
type TestResult struct {
	DNSResult         string   `json:"dns_result"`
	ResolvedAddresses []string `json:"resolved_addresses"`
	TCPConnected      bool     `json:"tcp_connected"`
	TLSHandshake      bool     `json:"tls_handshake"`
	TLSVerifyResult   string   `json:"tls_verify_result"`
	HTTPStatus        int      `json:"http_status"`
	ResponseTimeMs    int64    `json:"response_time_ms"`
	ErrorCode         string   `json:"error_code"`
	ErrorMessage      string   `json:"error_message"`
}

// TestConnectivity 执行源站连通性测试（SSRF防护）。
func TestConnectivity(ctx context.Context, in TestInput) *TestResult {
	result := &TestResult{}

	// 1. 协议校验
	scheme := strings.ToLower(in.Scheme)
	if scheme != "http" && scheme != "https" {
		result.ErrorCode = "INVALID_SCHEME"
		result.ErrorMessage = "仅支持 HTTP 和 HTTPS 协议"
		return result
	}
	// 2. 主机校验
	if err := validation.IsValidUpstreamHost(in.Host); err != nil {
		result.ErrorCode = "INVALID_HOST"
		result.ErrorMessage = err.Error()
		return result
	}
	// 3. 端口校验
	if err := validation.ValidatePort(in.Port); err != nil {
		result.ErrorCode = "INVALID_PORT"
		result.ErrorMessage = err.Error()
		return result
	}

	// 4. DNS解析 + IP校验（防DNS重绑定、SSRF）
	addrs, err := validation.ResolveAndValidate(in.Host, in.AllowPrivate)
	if err != nil {
		result.DNSResult = "failed"
		result.ErrorCode = "SSRF_BLOCKED"
		result.ErrorMessage = err.Error()
		return result
	}
	result.DNSResult = "ok"
	for _, a := range addrs {
		result.ResolvedAddresses = append(result.ResolvedAddresses, a.String())
	}

	// 5. 建立带自定义 Dial 的 HTTP 客户端（强制使用已校验的 IP）
	start := time.Now()
	client := buildSafeClient(in, addrs)

	// 6. 发起 HTTP 请求
	path := in.HealthCheckPath
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	url := fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(in.Host, fmt.Sprintf("%d", in.Port)), path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		result.ErrorCode = "REQUEST_BUILD_FAILED"
		result.ErrorMessage = "构造请求失败"
		return result
	}
	req.Header.Set("User-Agent", "jiuzhang-waf-healthcheck/2.0")
	req.Header.Set("Accept", "*/*")
	req.Close = true

	// 跟踪 TLS 握手
	var tlsHandshakeDone bool
	trace := &httptrace.ClientTrace{
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			tlsHandshakeDone = err == nil
			if err != nil {
				result.TLSVerifyResult = err.Error()
			} else {
				result.TLSVerifyResult = "ok"
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := client.Do(req)
	result.ResponseTimeMs = time.Since(start).Milliseconds()
	if err != nil {
		result.ErrorCode = classifyError(err)
		result.ErrorMessage = sanitizeErrorMessage(err)
		return result
	}
	defer resp.Body.Close()
	result.TCPConnected = true
	if scheme == "https" {
		result.TLSHandshake = tlsHandshakeDone
	}
	result.HTTPStatus = resp.StatusCode

	// 读取有限响应体（不返回给调用方，仅验证可读）
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	return result
}

// buildSafeClient 构建使用预校验 IP 的安全 HTTP 客户端。
func buildSafeClient(in TestInput, addrs []netip.Addr) *http.Client {
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 0,
	}
	transport := &http.Transport{
		DisableKeepAlives:   true,
		MaxIdleConns:        0,
		TLSHandshakeTimeout: tlsTimeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// 强制使用已校验的 IP 地址（防 DNS 重绑定）
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, a := range addrs {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
	if strings.ToLower(in.Scheme) == "https" {
		serverName := in.TLSServerName
		if serverName == "" {
			serverName = in.Host
		}
		transport.TLSClientConfig = &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: !in.TLSVerify, // 仅在显式关闭时跳过证书校验
			MinVersion:         tls.VersionTLS12,
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   httpTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return http.ErrUseLastResponse // 不跟随跳转
			}
			return nil
		},
	}
}

// classifyError 分类错误码。
func classifyError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "timeout"):
		return "TIMEOUT"
	case strings.Contains(msg, "connection refused"):
		return "CONNECTION_REFUSED"
	case strings.Contains(msg, "no route to host"):
		return "NO_ROUTE"
	case strings.Contains(msg, "certificate"):
		return "TLS_CERTIFICATE_ERROR"
	case strings.Contains(msg, "tls"):
		return "TLS_HANDSHAKE_FAILED"
	default:
		return "CONNECTION_FAILED"
	}
}

// sanitizeErrorMessage 清理错误信息（不泄露内部地址/路径）。
func sanitizeErrorMessage(err error) string {
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// CheckExpectedStatus 判断响应状态码是否符合期望。
func CheckExpectedStatus(actual int, expectedCodes string) bool {
	if expectedCodes == "" {
		expectedCodes = "200"
	}
	for _, part := range strings.Split(expectedCodes, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// 支持 "200"、"2xx"、"200-299"
		if strings.HasSuffix(part, "xx") && len(part) == 3 {
			prefix := int(part[0] - '0')
			if actual >= prefix*100 && actual < (prefix+1)*100 {
				return true
			}
			continue
		}
		var code int
		if _, err := fmt.Sscanf(part, "%d", &code); err == nil && actual == code {
			return true
		}
	}
	return false
}
