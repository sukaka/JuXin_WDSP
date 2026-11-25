// session_log.go 加密会话分析事件落盘（JSONL）与连接级 TLS/TLCP 元数据注册表。
package tlsmux

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
)

// DefaultSessionLogPath 加密会话握手事件默认 JSONL 落盘路径。
const DefaultSessionLogPath = "/var/log/caddy/tls-handshake-events.jsonl"

// 握手处置动作常量
const (
	ActionAllowed               = "ALLOWED"
	ActionBlockedLegacySSL      = "BLOCKED_LEGACY_SSL"
	ActionBlockedProtocolPolicy = "BLOCKED_PROTOCOL_POLICY"
	ActionHandshakeFailed       = "HANDSHAKE_FAILED"
)

// HandshakeEvent 单次 SSL/TLS/TLCP 握手事件（JSONL 输出，供服务端采集入 tls_handshake_events 表）。
type HandshakeEvent struct {
	OccurredAt         time.Time `json:"occurred_at"`
	GatewayNode        string    `json:"gateway_node_id"`
	ApplicationID      string    `json:"application_id,omitempty"`
	SNI                string    `json:"sni"`
	ClientIP           string    `json:"client_ip"`
	ClientPort         int       `json:"client_port"`
	ServerPort         int       `json:"server_port"`
	DetectedProtocol   string    `json:"detected_protocol"`
	NegotiatedProtocol string    `json:"negotiated_protocol,omitempty"`
	CipherSuite        string    `json:"cipher_suite,omitempty"`
	IsGM               bool      `json:"is_gm"`
	JA3Hash            string    `json:"ja3_hash,omitempty"`
	ALPN               string    `json:"alpn,omitempty"`
	Action             string    `json:"action"`
	ErrorReason        string    `json:"error_reason,omitempty"`
}

// ConnMeta 保存单个已建立加密连接的真实握手元数据，供 jiuzhang_guard 在 ServeHTTP 中消费
// （包括为国密 TLCP 连接补齐 r.TLS，以及向全量访问日志注入 JA3、协议版本、国密标识与套件名）。
type ConnMeta struct {
	ApplicationID      string
	SNI                string
	DetectedProtocol   string // ClientHello 原始检测版本（SSLv2/v3/TLS1.0~1.3/TLCP1.1）
	NegotiatedProtocol string // 协商生效版本（TLCP1.1 / TLS1.0 / TLS1.1 / TLS1.2 / TLS1.3）
	ProtocolVersion    uint16 // 大端协议号（如 0x0101 / 0x0304）
	CipherSuiteID      uint16
	CipherSuite        string
	IsGM               bool
	JA3Hash            string
	ALPN               string
	CreatedAt          time.Time
}

// SyntheticTLSState 为国密 TLCP 连接构造真实语义的 *tls.ConnectionState，
// 供下游 reverse_proxy（X-Forwarded-Proto: https）、Bot 挑战（HTTPS 判断）与身份观测无缝消费。
func (m *ConnMeta) SyntheticTLSState() *tls.ConnectionState {
	if m == nil {
		return nil
	}
	ver := m.ProtocolVersion
	if ver == 0 && m.IsGM {
		ver = VersionTLCP11
	}
	return &tls.ConnectionState{
		Version:            ver,
		HandshakeComplete:  true,
		CipherSuite:        m.CipherSuiteID,
		NegotiatedProtocol: m.ALPN,
		ServerName:         m.SNI,
	}
}

// CipherSuiteDisplayName 返回密码套件可读名称（同时支持国密 TLCP 套件与国际标准套件）。
func CipherSuiteDisplayName(id uint16, isGM bool) string {
	if id == 0 {
		return ""
	}
	if isGM || IsGMCipherSuite(id) {
		if name := tlcp.CipherSuiteName(id); name != "" && !strings.HasPrefix(name, "0x") {
			return name
		}
		switch id {
		case 0xe011:
			return "TLCP_ECDHE_SM4_CBC_SM3"
		case 0xe013:
			return "TLCP_ECC_SM4_CBC_SM3"
		case 0xe051:
			return "TLCP_ECDHE_SM4_GCM_SM3"
		case 0xe053:
			return "TLCP_ECC_SM4_GCM_SM3"
		case 0x00c6:
			return "TLS_SM4_GCM_SM3"
		case 0x00c7:
			return "TLS_SM4_CCM_SM3"
		}
	}
	return tls.CipherSuiteName(id)
}

// ---------- 连接级元数据注册表（进程级并发安全，连接 Close 自动注销） ----------

type connMetaKey struct {
	remote string
	local  string
}

var connMetaStore sync.Map // connMetaKey -> *ConnMeta

func makeConnMetaKey(remoteAddr, localAddr net.Addr) (connMetaKey, bool) {
	if remoteAddr == nil {
		return connMetaKey{}, false
	}
	k := connMetaKey{remote: remoteAddr.String()}
	if localAddr != nil {
		k.local = localAddr.String()
	}
	return k, k.remote != ""
}

// RegisterConnMeta 在握手完成时登记连接元数据。
func RegisterConnMeta(remoteAddr, localAddr net.Addr, meta *ConnMeta) func() {
	key, ok := makeConnMetaKey(remoteAddr, localAddr)
	if !ok || meta == nil {
		return func() {}
	}
	if meta.CreatedAt.IsZero() {
		meta.CreatedAt = time.Now().UTC()
	}
	connMetaStore.Store(key, meta)
	// 同时保存仅按 remote 索引的兜底项（用于部分测试或未注入 LocalAddrContextKey 的请求）
	remoteOnly := connMetaKey{remote: key.remote}
	if key.local != "" {
		connMetaStore.Store(remoteOnly, meta)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			connMetaStore.Delete(key)
			if key.local != "" {
				// 仅在仍指向本实例时清理兜底键，避免误删同源端口快速复用的新连接
				if v, loaded := connMetaStore.Load(remoteOnly); loaded && v == meta {
					connMetaStore.Delete(remoteOnly)
				}
			}
		})
	}
}

// LookupConnMeta 按请求连接地址查询加密会话元数据（优先精确四元组，回退 remoteAddr）。
func LookupConnMeta(remoteAddr string, localAddr net.Addr) *ConnMeta {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return nil
	}
	if localAddr != nil {
		if v, ok := connMetaStore.Load(connMetaKey{remote: remoteAddr, local: localAddr.String()}); ok {
			if m, ok := v.(*ConnMeta); ok {
				return m
			}
		}
	}
	if v, ok := connMetaStore.Load(connMetaKey{remote: remoteAddr}); ok {
		if m, ok := v.(*ConnMeta); ok {
			return m
		}
	}
	return nil
}

// ---------- JSONL 会话事件记录器（并发安全，0600 权限） ----------

type sessionLogWriter struct {
	mu sync.Mutex
	f  *os.File
}

func newSessionLogWriter(path string) (*sessionLogWriter, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("mkdir session log dir: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open session log: %w", err)
	}
	return &sessionLogWriter{f: f}, nil
}

func (w *sessionLogWriter) write(ev *HandshakeEvent) error {
	if w == nil || ev == nil {
		return nil
	}
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	_, err = w.f.Write(append(data, '\n'))
	return err
}

func (w *sessionLogWriter) close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
