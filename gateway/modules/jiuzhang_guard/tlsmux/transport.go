// transport.go 实现 Caddy 反向代理传输模块 http.reverse_proxy.transport.jiuzhang_tls：
// 统一支持：
//   - 国密 TLCP 1.1 加密回源（mode="tlcp"，SM2/SM3/SM4）
//   - 国际 TLS 加密回源（mode="tls"，支持显式降级至 TLS 1.0 / 1.1）
//   - 明文 HTTP 回源（mode="plain"，支持强制降级至 HTTP/1.0）
//   - 回源 HTTP 协议降级（AUTO / HTTP/2 / HTTP/1.1 / HTTP/1.0）
package tlsmux

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/emmansun/gmsm/smx509"
)

func init() {
	caddy.RegisterModule(&UpstreamTransport{})
}

// 回源模式常量
const (
	UpstreamModeTLCP  = "tlcp"
	UpstreamModeTLS   = "tls"
	UpstreamModePlain = "plain"
)

// UpstreamTransport 是九章自定义回源传输模块（http.reverse_proxy.transport.jiuzhang_tls）。
type UpstreamTransport struct {
	Mode                  string `json:"mode,omitempty"`                    // tlcp | tls | plain
	ServerName            string `json:"server_name,omitempty"`             // SNI / 证书校验主机名
	InsecureSkipVerify    bool   `json:"insecure_skip_verify,omitempty"`    // 仅在源站 tls_verify=false 时为 true
	RootCAPEM             string `json:"root_ca_pem,omitempty"`             // 可选自定义 CA（支持 SM2 或国际 CA）
	TLSMinVersion         string `json:"tls_min_version,omitempty"`         // TLS1.0 | TLS1.1 | TLS1.2 | TLS1.3（mode=tls）
	HTTPVersion           string `json:"http_version,omitempty"`            // AUTO | HTTP/1.0 | HTTP/1.1 | HTTP/2
	DialTimeout           string `json:"dial_timeout,omitempty"`            // 默认 3s
	ResponseHeaderTimeout string `json:"response_header_timeout,omitempty"` // 默认 10s

	mode                  string
	httpVersion           string
	dialTimeout           time.Duration
	responseHeaderTimeout time.Duration
	tlsCfg                *tls.Config
	tlcpCfg               *tlcp.Config
	rt                    *http.Transport
}

// CaddyModule 返回 Caddy 模块注册信息。
func (UpstreamTransport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.transport.jiuzhang_tls",
		New: func() caddy.Module { return new(UpstreamTransport) },
	}
}

// Provision 装配拨号器、国密/国际 TLS 配置及连接池。
func (t *UpstreamTransport) Provision(caddy.Context) error {
	t.mode = strings.ToLower(strings.TrimSpace(t.Mode))
	if t.mode == "" {
		t.mode = UpstreamModeTLCP
	}
	if t.mode != UpstreamModeTLCP && t.mode != UpstreamModeTLS && t.mode != UpstreamModePlain {
		return fmt.Errorf("jiuzhang_tls transport: unsupported mode %q", t.Mode)
	}

	t.httpVersion = strings.ToUpper(strings.TrimSpace(t.HTTPVersion))
	if t.httpVersion == "" {
		t.httpVersion = "AUTO"
	}
	switch t.httpVersion {
	case "AUTO", "HTTP/1.0", "HTTP/1.1", "HTTP/2":
	default:
		return fmt.Errorf("jiuzhang_tls transport: unsupported http_version %q", t.HTTPVersion)
	}

	t.dialTimeout = 3 * time.Second
	if strings.TrimSpace(t.DialTimeout) != "" {
		d, err := time.ParseDuration(strings.TrimSpace(t.DialTimeout))
		if err != nil || d <= 0 {
			return fmt.Errorf("jiuzhang_tls transport: invalid dial_timeout %q", t.DialTimeout)
		}
		t.dialTimeout = d
	}
	t.responseHeaderTimeout = 10 * time.Second
	if strings.TrimSpace(t.ResponseHeaderTimeout) != "" {
		d, err := time.ParseDuration(strings.TrimSpace(t.ResponseHeaderTimeout))
		if err != nil || d <= 0 {
			return fmt.Errorf("jiuzhang_tls transport: invalid response_header_timeout %q", t.ResponseHeaderTimeout)
		}
		t.responseHeaderTimeout = d
	}

	switch t.mode {
	case UpstreamModeTLCP:
		cfg := &tlcp.Config{
			ServerName:         strings.TrimSpace(t.ServerName),
			InsecureSkipVerify: t.InsecureSkipVerify,
		}
		if strings.TrimSpace(t.RootCAPEM) != "" {
			pool := smx509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(t.RootCAPEM)) {
				return fmt.Errorf("jiuzhang_tls transport: invalid GM root_ca_pem")
			}
			cfg.RootCAs = pool
		}
		t.tlcpCfg = cfg

	case UpstreamModeTLS:
		minVer, err := parseTLSVersionString(t.TLSMinVersion)
		if err != nil {
			return fmt.Errorf("jiuzhang_tls transport: %w", err)
		}
		cfg := &tls.Config{
			ServerName:         strings.TrimSpace(t.ServerName),
			InsecureSkipVerify: t.InsecureSkipVerify,
			MinVersion:         minVer,
		}
		if minVer < tls.VersionTLS12 {
			cfg.CipherSuites = legacyCompatibleCipherSuites()
		}
		if strings.TrimSpace(t.RootCAPEM) != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(t.RootCAPEM)) {
				return fmt.Errorf("jiuzhang_tls transport: invalid root_ca_pem")
			}
			cfg.RootCAs = pool
		}
		t.tlsCfg = cfg
	}

	// 构建持久化连接池（HTTP/1.0 走独立短连接写盘路径，不经过 http.Transport）
	tr := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   t.dialTimeout,
		ResponseHeaderTimeout: t.responseHeaderTimeout,
		DialContext:           t.dialRaw,
	}
	switch t.mode {
	case UpstreamModeTLCP:
		tr.ForceAttemptHTTP2 = false
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		tr.DialTLSContext = t.dialTLCP
	case UpstreamModeTLS:
		tr.TLSClientConfig = t.tlsCfg
		if t.httpVersion == "HTTP/1.1" {
			tr.ForceAttemptHTTP2 = false
			tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		} else {
			tr.ForceAttemptHTTP2 = true
		}
	case UpstreamModePlain:
		tr.ForceAttemptHTTP2 = false
	}
	t.rt = tr
	return nil
}

// TLSEnabled 实现 reverseproxy.TLSTransport：国密 TLCP 与国际 TLS 回源均标记为加密回源。
func (t *UpstreamTransport) TLSEnabled() bool {
	return t.mode == UpstreamModeTLCP || t.mode == UpstreamModeTLS
}

// EnableTLS 实现 reverseproxy.TLSTransport（当 Caddyfile/reverseproxy 自动开启加密回源时调用）。
func (t *UpstreamTransport) EnableTLS(base *reverseproxy.TLSConfig) error {
	if t.mode == "" || t.mode == UpstreamModePlain {
		t.mode = UpstreamModeTLS
	}
	if base != nil {
		if base.ServerName != "" && t.ServerName == "" {
			t.ServerName = base.ServerName
		}
		if base.InsecureSkipVerify {
			t.InsecureSkipVerify = true
		}
	}
	return nil
}

// Cleanup 关闭空闲连接。
func (t *UpstreamTransport) Cleanup() error {
	if t.rt != nil {
		t.rt.CloseIdleConnections()
	}
	return nil
}

// RoundTrip 实现 http.RoundTripper。
func (t *UpstreamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "" {
		if t.TLSEnabled() {
			req.URL.Scheme = "https"
		} else {
			req.URL.Scheme = "http"
		}
	}
	if t.httpVersion == "HTTP/1.0" {
		return t.roundTripHTTP10(req)
	}
	return t.rt.RoundTrip(req)
}

func (t *UpstreamTransport) resolveDialTarget(ctx context.Context, network, addr string) (string, string) {
	if dialInfo, ok := reverseproxy.GetDialInfo(ctx); ok {
		if dialInfo.Network != "" {
			network = dialInfo.Network
		}
		if dialInfo.Address != "" {
			addr = dialInfo.Address
		}
	}
	if network == "" {
		network = "tcp"
	}
	return network, addr
}

func (t *UpstreamTransport) dialRaw(ctx context.Context, network, addr string) (net.Conn, error) {
	network, addr = t.resolveDialTarget(ctx, network, addr)
	d := &net.Dialer{Timeout: t.dialTimeout, KeepAlive: 30 * time.Second}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (t *UpstreamTransport) dialTLCP(ctx context.Context, network, addr string) (net.Conn, error) {
	rawConn, err := t.dialRaw(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	cfg := t.tlcpCfg.Clone()
	if cfg.ServerName == "" {
		if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
			cfg.ServerName = host
		}
	}
	tConn := tlcp.Client(rawConn, cfg)
	hsCtx, cancel := context.WithTimeout(ctx, t.dialTimeout)
	defer cancel()
	if err := tConn.HandshakeContext(hsCtx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tConn, nil
}

func (t *UpstreamTransport) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	rawConn, err := t.dialRaw(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	cfg := t.tlsCfg.Clone()
	if cfg.ServerName == "" {
		if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
			cfg.ServerName = host
		}
	}
	tlsConn := tls.Client(rawConn, cfg)
	hsCtx, cancel := context.WithTimeout(ctx, t.dialTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// roundTripHTTP10 以真实 HTTP/1.0 报文向源站发起回源请求（支持明文、国际 TLS 与国密 TLCP 加密回源）。
func (t *UpstreamTransport) roundTripHTTP10(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	addr := req.URL.Host
	var (
		conn net.Conn
		err  error
	)
	switch t.mode {
	case UpstreamModeTLCP:
		conn, err = t.dialTLCP(ctx, "tcp", addr)
	case UpstreamModeTLS:
		conn, err = t.dialTLS(ctx, "tcp", addr)
	default:
		conn, err = t.dialRaw(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}

	outReq := req.Clone(ctx)
	outReq.Proto = "HTTP/1.0"
	outReq.ProtoMajor = 1
	outReq.ProtoMinor = 0
	outReq.Close = true
	if outReq.Header == nil {
		outReq.Header = make(http.Header)
	}
	outReq.Header.Set("Connection", "close")
	// HTTP/1.0 不支持 Transfer-Encoding: chunked，若为流式长度交由 Request.Write 按 HTTP/1.0 处理
	outReq.TransferEncoding = nil

	if err := conn.SetWriteDeadline(time.Now().Add(t.dialTimeout)); err == nil {
		err = writeHTTP10Request(conn, outReq)
		_ = conn.SetWriteDeadline(time.Time{})
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	_ = conn.SetReadDeadline(time.Now().Add(t.responseHeaderTimeout))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, outReq)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	resp.Body = &connClosingBody{ReadCloser: resp.Body, conn: conn}
	return resp, nil
}

// maxHTTP10RequestBodyBytes 限制 HTTP/1.0 短连接回源单次缓冲请求体体积（32 MiB），防止无界 io.ReadAll 触发 OOM。
const maxHTTP10RequestBodyBytes = 32 << 20

// writeHTTP10Request 写出精确的 "METHOD /path HTTP/1.0\r\n" 请求行、请求头与请求体。
func writeHTTP10Request(w io.Writer, req *http.Request) error {
	bw := bufio.NewWriter(w)
	target := req.URL.RequestURI()
	if target == "" {
		target = "/"
	}
	if _, err := fmt.Fprintf(bw, "%s %s HTTP/1.0\r\n", req.Method, target); err != nil {
		return err
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host != "" {
		if _, err := fmt.Fprintf(bw, "Host: %s\r\n", host); err != nil {
			return err
		}
	}
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(io.LimitReader(req.Body, maxHTTP10RequestBodyBytes+1))
		_ = req.Body.Close()
		if err != nil {
			return err
		}
		if len(bodyBytes) > maxHTTP10RequestBodyBytes {
			return fmt.Errorf("jiuzhang_tls transport: HTTP/1.0 request body exceeds %d bytes limit", maxHTTP10RequestBodyBytes)
		}
		if len(bodyBytes) > 0 && req.Header.Get("Content-Length") == "" {
			req.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
		}
	}
	if err := req.Header.WriteSubset(bw, map[string]bool{"Host": true, "Transfer-Encoding": true}); err != nil {
		return err
	}
	if _, err := bw.WriteString("\r\n"); err != nil {
		return err
	}
	if len(bodyBytes) > 0 {
		if _, err := bw.Write(bodyBytes); err != nil {
			return err
		}
	}
	return bw.Flush()
}

type connClosingBody struct {
	io.ReadCloser
	conn net.Conn
}

func (b *connClosingBody) Close() error {
	err1 := b.ReadCloser.Close()
	err2 := b.conn.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func parseTLSVersionString(s string) (uint16, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "TLS1.2":
		return tls.VersionTLS12, nil
	case "TLS1.0":
		return tls.VersionTLS10, nil
	case "TLS1.1":
		return tls.VersionTLS11, nil
	case "TLS1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported tls_min_version %q", s)
	}
}

var (
	_ caddy.Provisioner         = (*UpstreamTransport)(nil)
	_ caddy.CleanerUpper        = (*UpstreamTransport)(nil)
	_ http.RoundTripper         = (*UpstreamTransport)(nil)
	_ reverseproxy.TLSTransport = (*UpstreamTransport)(nil)
)
