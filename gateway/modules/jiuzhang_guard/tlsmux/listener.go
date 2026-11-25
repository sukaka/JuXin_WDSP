// listener.go 实现 Caddy 监听包装器 caddy.listeners.jiuzhang_tls_mux：
// 同端口自识别通用国际 TLS（1.0~1.3）与国密 TLCP 1.1（SM2/SM3/SM4 双证书），
// 执行站点级协议降级（TLS 版本与 HTTP/2 ALPN 裁剪）、弱协议（SSLv2/SSLv2-v3/SSLv3）
// 识别阻断及全量加密会话分析日志输出。
package tlsmux

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&ListenerMux{})
}

// 站点协议模式（与管理面 gatewayconfig.TLSProtocolMode* 保持一致）
const (
	ModeAutoDetect        = "AUTO_DETECT"
	ModeInternationalOnly = "INTERNATIONAL_ONLY"
	ModeGMOnly            = "GM_ONLY"
)

const (
	defaultHandshakeTimeout = 10 * time.Second
	maxConcurrentHandshakes = 2048
	readyConnQueueSize      = 512
)

// TLS Alert 常量（RFC 5246 §7.2）
const (
	alertProtocolVersion  byte = 70  // protocol_version
	alertHandshakeFailure byte = 40  // handshake_failure
	alertUnrecognizedName byte = 112 // unrecognized_name
)

// SiteConfig 是监听端口上单个站点的双协议证书与 TLS/HTTP 降级策略配置。
type SiteConfig struct {
	AppID                     string   `json:"app_id,omitempty"`
	Domains                   []string `json:"domains"`
	TLSProtocolMode           string   `json:"tls_protocol_mode,omitempty"`
	AllowedTLSVersions        []string `json:"allowed_tls_versions,omitempty"`
	LegacySSLAnalysisVersions []string `json:"legacy_ssl_analysis_versions,omitempty"`
	HTTPVersions              []string `json:"http_versions,omitempty"`
	SessionAnalysisEnabled    *bool    `json:"session_analysis_enabled,omitempty"`

	// 通用国际协议证书（RSA / ECDSA / Ed25519）
	CertID  string `json:"cert_id,omitempty"`
	CertPEM string `json:"cert_pem,omitempty"`
	KeyPEM  string `json:"key_pem,omitempty"`

	// 国密 TLCP 1.1 双证书（SM2 签名证书 + SM2 加密证书）
	GMCertID      string `json:"gm_cert_id,omitempty"`
	GMSignCertPEM string `json:"gm_sign_cert_pem,omitempty"`
	GMSignKeyPEM  string `json:"gm_sign_key_pem,omitempty"`
	GMEncCertPEM  string `json:"gm_enc_cert_pem,omitempty"`
	GMEncKeyPEM   string `json:"gm_enc_key_pem,omitempty"`
}

// ListenerMux 是 Caddy 监听包装模块 caddy.listeners.jiuzhang_tls_mux。
type ListenerMux struct {
	GatewayNode          string       `json:"gateway_node,omitempty"`
	SessionLogPath       string       `json:"session_log_path,omitempty"`
	HandshakeTimeout     string       `json:"handshake_timeout,omitempty"`
	SessionTicketKeysHex []string     `json:"session_ticket_keys_hex,omitempty"`
	Sites                []SiteConfig `json:"sites"`

	logger           *zap.Logger
	handshakeTimeout time.Duration
	ticketKeys       [][32]byte
	compiledSites    []*compiledSite
	exactIndex       map[string]*compiledSite
	wildcardSites    []wildcardEntry
	sessionLog       *sessionLogWriter
	gatewayNode      string
}

type wildcardEntry struct {
	suffix string // 例如 ".example.com"（对应 *.example.com）
	site   *compiledSite
}

type compiledSite struct {
	appID                   string
	mode                    string
	allowTLCP               bool
	allowedIntlVersions     map[uint16]bool
	legacyAnalyzeSet        map[string]bool
	sessionAnalysisEnabled  bool
	hasIntlCert             bool
	hasGMCert               bool
	tlsCfg                  *tls.Config
	tlcpCfg                 *tlcp.Config
}

// CaddyModule 返回 Caddy 模块注册信息。
func (ListenerMux) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.jiuzhang_tls_mux",
		New: func() caddy.Module { return new(ListenerMux) },
	}
}

// Provision 编译所有站点的国际 TLS / 国密 TLCP 证书对、协议版本策略、STEK 票据键与会话日志。
func (m *ListenerMux) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	if envNode := strings.TrimSpace(os.Getenv("GATEWAY_NODE_NAME")); envNode != "" {
		m.gatewayNode = envNode
	} else {
		m.gatewayNode = strings.TrimSpace(m.GatewayNode)
	}
	if m.gatewayNode == "" {
		m.gatewayNode = "gateway-unknown"
	}

	m.handshakeTimeout = defaultHandshakeTimeout
	if strings.TrimSpace(m.HandshakeTimeout) != "" {
		d, err := time.ParseDuration(strings.TrimSpace(m.HandshakeTimeout))
		if err != nil || d <= 0 {
			return fmt.Errorf("jiuzhang_tls_mux: invalid handshake_timeout %q", m.HandshakeTimeout)
		}
		m.handshakeTimeout = d
	}

	if len(m.SessionTicketKeysHex) > 0 {
		keys := make([][32]byte, 0, len(m.SessionTicketKeysHex))
		for i, kh := range m.SessionTicketKeysHex {
			raw, err := hex.DecodeString(strings.TrimSpace(kh))
			if err != nil || len(raw) != 32 {
				return fmt.Errorf("jiuzhang_tls_mux: session_ticket_keys_hex[%d] must be 32-byte hex", i)
			}
			var k [32]byte
			copy(k[:], raw)
			keys = append(keys, k)
		}
		m.ticketKeys = keys
	}

	if len(m.Sites) == 0 {
		return fmt.Errorf("jiuzhang_tls_mux: sites must not be empty")
	}

	m.compiledSites = make([]*compiledSite, 0, len(m.Sites))
	m.exactIndex = make(map[string]*compiledSite, len(m.Sites))
	m.wildcardSites = nil

	for i, sc := range m.Sites {
		cs, err := m.compileSite(sc)
		if err != nil {
			return fmt.Errorf("jiuzhang_tls_mux: sites[%d]: %w", i, err)
		}
		m.compiledSites = append(m.compiledSites, cs)
		for _, rawDom := range sc.Domains {
			dom := strings.ToLower(strings.TrimSpace(rawDom))
			if dom == "" {
				continue
			}
			if strings.HasPrefix(dom, "*.") && len(dom) > 2 {
				m.wildcardSites = append(m.wildcardSites, wildcardEntry{suffix: dom[1:], site: cs})
			} else {
				m.exactIndex[dom] = cs
			}
		}
	}

	logPath := strings.TrimSpace(m.SessionLogPath)
	if logPath != "" {
		w, err := newSessionLogWriter(logPath)
		if err != nil {
			return fmt.Errorf("jiuzhang_tls_mux: %w", err)
		}
		m.sessionLog = w
	}
	return nil
}

// Cleanup 关闭会话事件日志文件。
func (m *ListenerMux) Cleanup() error {
	if m.sessionLog != nil {
		return m.sessionLog.close()
	}
	return nil
}

func (m *ListenerMux) compileSite(sc SiteConfig) (*compiledSite, error) {
	mode := strings.ToUpper(strings.TrimSpace(sc.TLSProtocolMode))
	if mode == "" {
		mode = ModeAutoDetect
	}
	if mode != ModeAutoDetect && mode != ModeInternationalOnly && mode != ModeGMOnly {
		return nil, fmt.Errorf("invalid tls_protocol_mode %q", sc.TLSProtocolMode)
	}

	allowedVersions := sc.AllowedTLSVersions
	if len(allowedVersions) == 0 {
		allowedVersions = []string{ProtoTLS12, ProtoTLS13}
		if strings.TrimSpace(sc.GMSignCertPEM) != "" && strings.TrimSpace(sc.GMEncCertPEM) != "" {
			allowedVersions = append(allowedVersions, ProtoTLCP11)
		}
	}
	cs := &compiledSite{
		appID:                  sc.AppID,
		mode:                   mode,
		allowedIntlVersions:    map[uint16]bool{},
		legacyAnalyzeSet:       map[string]bool{},
		sessionAnalysisEnabled: sc.SessionAnalysisEnabled == nil || *sc.SessionAnalysisEnabled,
	}

	var minIntl, maxIntl uint16
	for _, rawV := range allowedVersions {
		switch strings.ToUpper(strings.TrimSpace(rawV)) {
		case "TLCP1.1":
			cs.allowTLCP = true
		case "TLS1.0":
			cs.allowedIntlVersions[tls.VersionTLS10] = true
			minIntl, maxIntl = expandMinMax(minIntl, maxIntl, tls.VersionTLS10)
		case "TLS1.1":
			cs.allowedIntlVersions[tls.VersionTLS11] = true
			minIntl, maxIntl = expandMinMax(minIntl, maxIntl, tls.VersionTLS11)
		case "TLS1.2":
			cs.allowedIntlVersions[tls.VersionTLS12] = true
			minIntl, maxIntl = expandMinMax(minIntl, maxIntl, tls.VersionTLS12)
		case "TLS1.3":
			cs.allowedIntlVersions[tls.VersionTLS13] = true
			minIntl, maxIntl = expandMinMax(minIntl, maxIntl, tls.VersionTLS13)
		default:
			return nil, fmt.Errorf("unsupported allowed_tls_version %q", rawV)
		}
	}

	// 弱协议分析集合（缺省覆盖 SSLv2 / SSLv2_v3 / SSLv3）
	legacyList := sc.LegacySSLAnalysisVersions
	if legacyList == nil {
		legacyList = []string{ProtoSSLv2, "SSLv2_v3", ProtoSSLv3}
	}
	for _, lv := range legacyList {
		norm := normalizeLegacyProto(lv)
		if norm != "" {
			cs.legacyAnalyzeSet[norm] = true
		}
	}

	// 国际通用证书装配
	if strings.TrimSpace(sc.CertPEM) != "" || strings.TrimSpace(sc.KeyPEM) != "" {
		pair, err := tls.X509KeyPair([]byte(strings.TrimSpace(sc.CertPEM)), []byte(strings.TrimSpace(sc.KeyPEM)))
		if err != nil {
			return nil, fmt.Errorf("load international certificate: %w", err)
		}
		if minIntl == 0 {
			minIntl = tls.VersionTLS12
			maxIntl = tls.VersionTLS13
			cs.allowedIntlVersions[tls.VersionTLS12] = true
			cs.allowedIntlVersions[tls.VersionTLS13] = true
		}
		nextProtos := buildNextProtos(sc.HTTPVersions)
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{pair},
			MinVersion:   minIntl,
			MaxVersion:   maxIntl,
			NextProtos:   nextProtos,
		}
		// 仅当管理员显式开启 TLS 1.0/1.1 降级时补充兼容套件，默认保持 Go 现代安全套件零降级
		if minIntl < tls.VersionTLS12 {
			tlsCfg.CipherSuites = legacyCompatibleCipherSuites()
		}
		if len(m.ticketKeys) > 0 {
			tlsCfg.SetSessionTicketKeys(m.ticketKeys)
		}
		cs.hasIntlCert = true
		cs.tlsCfg = tlsCfg
	}

	// 国密 TLCP 1.1 双证书装配（签名证书 + 加密证书）
	if strings.TrimSpace(sc.GMSignCertPEM) != "" || strings.TrimSpace(sc.GMEncCertPEM) != "" {
		signPair, err := tlcp.X509KeyPair([]byte(strings.TrimSpace(sc.GMSignCertPEM)), []byte(strings.TrimSpace(sc.GMSignKeyPEM)))
		if err != nil {
			return nil, fmt.Errorf("load GM signing certificate: %w", err)
		}
		encPair, err := tlcp.X509KeyPair([]byte(strings.TrimSpace(sc.GMEncCertPEM)), []byte(strings.TrimSpace(sc.GMEncKeyPEM)))
		if err != nil {
			return nil, fmt.Errorf("load GM encryption certificate: %w", err)
		}
		cs.hasGMCert = true
		cs.tlcpCfg = &tlcp.Config{
			Certificates: []tlcp.Certificate{signPair, encPair},
		}
		// 站点配置了国密双证且未显式禁用时，自动允许 TLCP1.1（便于默认 AUTO_DETECT 开箱生效）
		if len(sc.AllowedTLSVersions) == 0 {
			cs.allowTLCP = true
		}
	}

	if !cs.hasIntlCert && !cs.hasGMCert {
		return nil, fmt.Errorf("site must provide at least one international certificate or GM dual certificate")
	}
	return cs, nil
}

func expandMinMax(minV, maxV, v uint16) (uint16, uint16) {
	if minV == 0 || v < minV {
		minV = v
	}
	if maxV == 0 || v > maxV {
		maxV = v
	}
	return minV, maxV
}

func buildNextProtos(httpVersions []string) []string {
	if len(httpVersions) == 0 {
		return []string{"h2", "http/1.1"}
	}
	hasH2 := false
	hasH1 := false
	for _, v := range httpVersions {
		switch strings.ToUpper(strings.TrimSpace(v)) {
		case "HTTP/2", "H2":
			hasH2 = true
		case "HTTP/1.1", "HTTP/1.0", "H1":
			hasH1 = true
		}
	}
	switch {
	case hasH2 && hasH1:
		return []string{"h2", "http/1.1"}
	case hasH2:
		return []string{"h2"}
	default:
		// 禁用 HTTP/2 实现现网协议降级：ALPN 仅通告 http/1.1
		return []string{"http/1.1"}
	}
}

func legacyCompatibleCipherSuites() []uint16 {
	seen := map[uint16]bool{}
	var out []uint16
	for _, cs := range tls.CipherSuites() {
		if !seen[cs.ID] {
			seen[cs.ID] = true
			out = append(out, cs.ID)
		}
	}
	// 补充 TLS 1.0/1.1 常用 CBC 套件（供现网显式降级场景，绝不影响默认仅 TLS1.2/1.3 站点）
	legacyIDs := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}
	for _, id := range legacyIDs {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func normalizeLegacyProto(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "SSLV2":
		return ProtoSSLv2
	case "SSLV2_V3", "SSLV2/V3":
		return ProtoSSLv2v3
	case "SSLV3":
		return ProtoSSLv3
	default:
		return ""
	}
}

// matchSite 按 SNI 匹配站点（精确匹配 > 单层泛域名匹配；无 SNI 时按协议兜底首站点；未知非空 SNI 拒绝）。
func (m *ListenerMux) matchSite(sni string, wantGM bool) *compiledSite {
	sni = strings.ToLower(strings.TrimSpace(sni))
	if sni != "" {
		if s, ok := m.exactIndex[sni]; ok {
			return s
		}
		for _, w := range m.wildcardSites {
			// 单层泛域名 *.example.com 匹配 foo.example.com，不匹配 a.b.example.com 或裸 example.com
			if strings.HasSuffix(sni, w.suffix) {
				prefix := strings.TrimSuffix(sni, w.suffix)
				if prefix != "" && !strings.Contains(prefix, ".") {
					return w.site
				}
			}
		}
		return nil
	}
	// 客户端未携带 SNI（例如 IP 直连或极老客户端）时，按协议选择首个具备对应证书的站点
	for _, s := range m.compiledSites {
		if wantGM && s.hasGMCert && s.mode != ModeInternationalOnly {
			return s
		}
		if !wantGM && s.hasIntlCert && s.mode != ModeGMOnly {
			return s
		}
	}
	if len(m.compiledSites) > 0 {
		return m.compiledSites[0]
	}
	return nil
}

// WrapListener 实现 caddy.ListenerWrapper：包装底层 TCP 监听器提供双协议异步握手与协议分流。
func (m *ListenerMux) WrapListener(ln net.Listener) net.Listener {
	ml := &muxListener{
		Listener: ln,
		mux:      m,
		readyCh:  make(chan net.Conn, readyConnQueueSize),
		errCh:    make(chan error, 1),
		sem:      make(chan struct{}, maxConcurrentHandshakes),
		doneCh:   make(chan struct{}),
	}
	go ml.acceptLoop()
	return ml
}

type muxListener struct {
	net.Listener
	mux       *ListenerMux
	readyCh   chan net.Conn
	errCh     chan error
	sem       chan struct{}
	doneCh    chan struct{}
	closeOnce sync.Once
}

func (l *muxListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.readyCh:
		return conn, nil
	case err := <-l.errCh:
		return nil, err
	case <-l.doneCh:
		return nil, net.ErrClosed
	}
}

func (l *muxListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.doneCh)
		err = l.Listener.Close()
		// 排空尚未被上层取走的连接，防止 fd 泄漏
		for {
			select {
			case c := <-l.readyCh:
				_ = c.Close()
			default:
				return
			}
		}
	})
	return err
}

func (l *muxListener) acceptLoop() {
	for {
		rawConn, err := l.Listener.Accept()
		if err != nil {
			select {
			case <-l.doneCh:
				return
			default:
			}
			// 临时网络错误退避重试，永久错误通知 Accept 返回
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			select {
			case l.errCh <- err:
			default:
			}
			return
		}
		select {
		case l.sem <- struct{}{}:
			go func(c net.Conn) {
				defer func() { <-l.sem }()
				l.handleConn(c)
			}(rawConn)
		case <-l.doneCh:
			_ = rawConn.Close()
			return
		default:
			// 并发握手队列饱和时快速拒绝，避免 goroutine 爆涨
			if l.mux.logger != nil {
				l.mux.logger.Warn("jiuzhang_tls_mux: handshake concurrency limit reached, dropping connection")
			}
			_ = rawConn.Close()
		}
	}
}

func (l *muxListener) handleConn(rawConn net.Conn) {
	clientIP, clientPort := splitAddr(rawConn.RemoteAddr())
	_, serverPort := splitAddr(rawConn.LocalAddr())
	peekTimeout := l.mux.handshakeTimeout
	if peekTimeout > defaultPeekTimeout {
		peekTimeout = defaultPeekTimeout
	}

	hello, pConn, err := ReadClientHelloPrefix(rawConn, peekTimeout, nil)
	if err != nil {
		l.mux.recordEvent(&HandshakeEvent{
			OccurredAt:       time.Now().UTC(),
			GatewayNode:      l.mux.gatewayNode,
			SNI:              hello.SNI,
			ClientIP:         clientIP,
			ClientPort:       clientPort,
			ServerPort:       serverPort,
			DetectedProtocol: hello.DetectedProtocol,
			IsGM:             hello.IsGM,
			JA3Hash:          hello.JA3Hash,
			Action:           ActionHandshakeFailed,
			ErrorReason:      err.Error(),
		}, true)
		_ = pConn.Close()
		return
	}

	// 1. 弱 SSL 协议（SSLv2 / SSLv2-v3 兼容头 / SSLv3）：识别、记录加密会话分析事件并发送 TLS Alert 阻断
	if hello.IsLegacySSL {
		site := l.mux.matchSite(hello.SNI, false)
		appID := ""
		shouldLog := true
		if site != nil {
			appID = site.appID
			shouldLog = site.sessionAnalysisEnabled
		}
		l.mux.recordEvent(&HandshakeEvent{
			OccurredAt:       time.Now().UTC(),
			GatewayNode:      l.mux.gatewayNode,
			ApplicationID:    appID,
			SNI:              hello.SNI,
			ClientIP:         clientIP,
			ClientPort:       clientPort,
			ServerPort:       serverPort,
			DetectedProtocol: hello.DetectedProtocol,
			IsGM:             false,
			JA3Hash:          hello.JA3Hash,
			Action:           ActionBlockedLegacySSL,
			ErrorReason:      fmt.Sprintf("legacy protocol %s rejected by TLS policy", hello.DetectedProtocol),
		}, shouldLog)
		sendTLSAlert(rawConn, alertProtocolVersion)
		_ = pConn.Close()
		return
	}

	// 2. 非加密或未知首包（例如明文打到 HTTPS 端口）：fail-closed 拒绝并记录
	if hello.DetectedProtocol == ProtoUnknown {
		l.mux.recordEvent(&HandshakeEvent{
			OccurredAt:       time.Now().UTC(),
			GatewayNode:      l.mux.gatewayNode,
			SNI:              hello.SNI,
			ClientIP:         clientIP,
			ClientPort:       clientPort,
			ServerPort:       serverPort,
			DetectedProtocol: ProtoUnknown,
			Action:           ActionHandshakeFailed,
			ErrorReason:      "unrecognized TLS/TLCP ClientHello record",
		}, true)
		_ = pConn.Close()
		return
	}

	wantGM := hello.DetectedProtocol == ProtoTLCP11
	site := l.mux.matchSite(hello.SNI, wantGM)
	if site == nil {
		l.mux.recordEvent(&HandshakeEvent{
			OccurredAt:       time.Now().UTC(),
			GatewayNode:      l.mux.gatewayNode,
			SNI:              hello.SNI,
			ClientIP:         clientIP,
			ClientPort:       clientPort,
			ServerPort:       serverPort,
			DetectedProtocol: hello.DetectedProtocol,
			IsGM:             wantGM,
			JA3Hash:          hello.JA3Hash,
			Action:           ActionHandshakeFailed,
			ErrorReason:      "unknown SNI hostname",
		}, true)
		sendTLSAlert(rawConn, alertUnrecognizedName)
		_ = pConn.Close()
		return
	}

	hsCtx, cancel := context.WithTimeout(context.Background(), l.mux.handshakeTimeout)
	defer cancel()

	// 3. 国密 TLCP 1.1 分支
	if wantGM {
		if site.mode == ModeInternationalOnly || !site.allowTLCP || !site.hasGMCert || site.tlcpCfg == nil {
			l.mux.recordEvent(&HandshakeEvent{
				OccurredAt:       time.Now().UTC(),
				GatewayNode:      l.mux.gatewayNode,
				ApplicationID:    site.appID,
				SNI:              hello.SNI,
				ClientIP:         clientIP,
				ClientPort:       clientPort,
				ServerPort:       serverPort,
				DetectedProtocol: hello.DetectedProtocol,
				IsGM:             true,
				JA3Hash:          hello.JA3Hash,
				Action:           ActionBlockedProtocolPolicy,
				ErrorReason:      "TLCP1.1 disabled or GM dual certificate not configured for site",
			}, site.sessionAnalysisEnabled)
			sendTLSAlert(rawConn, alertProtocolVersion)
			_ = pConn.Close()
			return
		}
		tConn := tlcp.Server(pConn, site.tlcpCfg)
		if err := tConn.HandshakeContext(hsCtx); err != nil {
			l.mux.recordEvent(&HandshakeEvent{
				OccurredAt:       time.Now().UTC(),
				GatewayNode:      l.mux.gatewayNode,
				ApplicationID:    site.appID,
				SNI:              hello.SNI,
				ClientIP:         clientIP,
				ClientPort:       clientPort,
				ServerPort:       serverPort,
				DetectedProtocol: hello.DetectedProtocol,
				IsGM:             true,
				JA3Hash:          hello.JA3Hash,
				Action:           ActionHandshakeFailed,
				ErrorReason:      err.Error(),
			}, site.sessionAnalysisEnabled)
			_ = tConn.Close()
			return
		}
		cs := tConn.ConnectionState()
		suiteName := CipherSuiteDisplayName(cs.CipherSuite, true)
		sni := cs.ServerName
		if sni == "" {
			sni = hello.SNI
		}
		meta := &ConnMeta{
			ApplicationID:      site.appID,
			SNI:                sni,
			DetectedProtocol:   hello.DetectedProtocol,
			NegotiatedProtocol: ProtoTLCP11,
			ProtocolVersion:    VersionTLCP11,
			CipherSuiteID:      cs.CipherSuite,
			CipherSuite:        suiteName,
			IsGM:               true,
			JA3Hash:            hello.JA3Hash,
			ALPN:               "http/1.1",
			CreatedAt:          time.Now().UTC(),
		}
		unregister := RegisterConnMeta(rawConn.RemoteAddr(), rawConn.LocalAddr(), meta)
		pConn.SetOnClose(unregister)

		l.mux.recordEvent(&HandshakeEvent{
			OccurredAt:         meta.CreatedAt,
			GatewayNode:        l.mux.gatewayNode,
			ApplicationID:      site.appID,
			SNI:                sni,
			ClientIP:           clientIP,
			ClientPort:         clientPort,
			ServerPort:         serverPort,
			DetectedProtocol:   hello.DetectedProtocol,
			NegotiatedProtocol: ProtoTLCP11,
			CipherSuite:        suiteName,
			IsGM:               true,
			JA3Hash:            hello.JA3Hash,
			ALPN:               meta.ALPN,
			Action:             ActionAllowed,
		}, site.sessionAnalysisEnabled)

		l.deliverReady(tConn)
		return
	}

	// 4. 国际通用 TLS（1.0 / 1.1 / 1.2 / 1.3）分支——返回裸 *tls.Conn 保留 Caddy/Go 原生 HTTP/2 与 r.TLS
	if site.mode == ModeGMOnly || !site.hasIntlCert || site.tlsCfg == nil {
		l.mux.recordEvent(&HandshakeEvent{
			OccurredAt:       time.Now().UTC(),
			GatewayNode:      l.mux.gatewayNode,
			ApplicationID:    site.appID,
			SNI:              hello.SNI,
			ClientIP:         clientIP,
			ClientPort:       clientPort,
			ServerPort:       serverPort,
			DetectedProtocol: hello.DetectedProtocol,
			IsGM:             false,
			JA3Hash:          hello.JA3Hash,
			Action:           ActionBlockedProtocolPolicy,
			ErrorReason:      "international TLS disabled or certificate not configured for site",
		}, site.sessionAnalysisEnabled)
		sendTLSAlert(rawConn, alertProtocolVersion)
		_ = pConn.Close()
		return
	}

	tlsConn := tls.Server(pConn, site.tlsCfg)
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		action := ActionHandshakeFailed
		if strings.Contains(strings.ToLower(err.Error()), "unsupported version") ||
			strings.Contains(strings.ToLower(err.Error()), "protocol version") {
			action = ActionBlockedProtocolPolicy
		}
		l.mux.recordEvent(&HandshakeEvent{
			OccurredAt:       time.Now().UTC(),
			GatewayNode:      l.mux.gatewayNode,
			ApplicationID:    site.appID,
			SNI:              hello.SNI,
			ClientIP:         clientIP,
			ClientPort:       clientPort,
			ServerPort:       serverPort,
			DetectedProtocol: hello.DetectedProtocol,
			IsGM:             false,
			JA3Hash:          hello.JA3Hash,
			Action:           action,
			ErrorReason:      err.Error(),
		}, site.sessionAnalysisEnabled)
		_ = tlsConn.Close()
		return
	}

	cs := tlsConn.ConnectionState()
	// 复核精确版本白名单（支持非连续版本组合如只允许 TLS1.0 + TLS1.3）
	if len(site.allowedIntlVersions) > 0 && !site.allowedIntlVersions[cs.Version] {
		l.mux.recordEvent(&HandshakeEvent{
			OccurredAt:         time.Now().UTC(),
			GatewayNode:        l.mux.gatewayNode,
			ApplicationID:      site.appID,
			SNI:                hello.SNI,
			ClientIP:           clientIP,
			ClientPort:         clientPort,
			ServerPort:         serverPort,
			DetectedProtocol:   hello.DetectedProtocol,
			NegotiatedProtocol: ProtocolLabel(cs.Version),
			CipherSuite:        CipherSuiteDisplayName(cs.CipherSuite, false),
			IsGM:               false,
			JA3Hash:            hello.JA3Hash,
			ALPN:               cs.NegotiatedProtocol,
			Action:             ActionBlockedProtocolPolicy,
			ErrorReason:        fmt.Sprintf("negotiated version %s not in allowed_tls_versions", ProtocolLabel(cs.Version)),
		}, site.sessionAnalysisEnabled)
		_ = tlsConn.Close()
		return
	}

	suiteName := CipherSuiteDisplayName(cs.CipherSuite, false)
	sni := cs.ServerName
	if sni == "" {
		sni = hello.SNI
	}
	meta := &ConnMeta{
		ApplicationID:      site.appID,
		SNI:                sni,
		DetectedProtocol:   hello.DetectedProtocol,
		NegotiatedProtocol: ProtocolLabel(cs.Version),
		ProtocolVersion:    cs.Version,
		CipherSuiteID:      cs.CipherSuite,
		CipherSuite:        suiteName,
		IsGM:               false,
		JA3Hash:            hello.JA3Hash,
		ALPN:               cs.NegotiatedProtocol,
		CreatedAt:          time.Now().UTC(),
	}
	unregister := RegisterConnMeta(rawConn.RemoteAddr(), rawConn.LocalAddr(), meta)
	pConn.SetOnClose(unregister)

	l.mux.recordEvent(&HandshakeEvent{
		OccurredAt:         meta.CreatedAt,
		GatewayNode:        l.mux.gatewayNode,
		ApplicationID:      site.appID,
		SNI:                sni,
		ClientIP:           clientIP,
		ClientPort:         clientPort,
		ServerPort:         serverPort,
		DetectedProtocol:   hello.DetectedProtocol,
		NegotiatedProtocol: meta.NegotiatedProtocol,
		CipherSuite:        suiteName,
		IsGM:               false,
		JA3Hash:            hello.JA3Hash,
		ALPN:               cs.NegotiatedProtocol,
		Action:             ActionAllowed,
	}, site.sessionAnalysisEnabled)

	l.deliverReady(tlsConn)
}

func (l *muxListener) deliverReady(conn net.Conn) {
	select {
	case l.readyCh <- conn:
	case <-l.doneCh:
		_ = conn.Close()
	}
}

func (m *ListenerMux) recordEvent(ev *HandshakeEvent, enabled bool) {
	if !enabled || m.sessionLog == nil || ev == nil {
		return
	}
	if err := m.sessionLog.write(ev); err != nil && m.logger != nil {
		m.logger.Warn("jiuzhang_tls_mux: write session log failed", zap.Error(err))
	}
}

func sendTLSAlert(conn net.Conn, alertDesc byte) {
	// Fatal TLS Alert Record: ContentType=0x15, Version=0x0301, Len=2, Level=fatal(2), Desc
	alert := []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, alertDesc}
	_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = conn.Write(alert)
	_ = conn.SetWriteDeadline(time.Time{})
}

func splitAddr(addr net.Addr) (string, int) {
	if addr == nil {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), 0
	}
	p, _ := strconv.Atoi(portStr)
	return host, p
}

var (
	_ caddy.Provisioner     = (*ListenerMux)(nil)
	_ caddy.CleanerUpper    = (*ListenerMux)(nil)
	_ caddy.ListenerWrapper = (*ListenerMux)(nil)
)
