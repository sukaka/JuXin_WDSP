// Package tlssessions 实现 SSL/HTTPS 加密会话分析：网关 TLS/TLCP 握手事件 JSONL 采集入库、
// 分页明细查询、协议与密码套件汇总统计及到期留存清理。
package tlssessions

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 检测协议标准标签（与网关 tlsmux.Proto* 枚举完全一致）。
const (
	ProtoSSLv2   = "SSLv2"
	ProtoSSLv2v3 = "SSLv2/v3"
	ProtoSSLv3   = "SSLv3"
	ProtoTLS10   = "TLS1.0"
	ProtoTLS11   = "TLS1.1"
	ProtoTLS12   = "TLS1.2"
	ProtoTLS13   = "TLS1.3"
	ProtoTLCP11  = "TLCP1.1"
	ProtoUnknown = "UNKNOWN"
)

// 握手处置动作枚举（与网关 tlsmux.Action* 枚举完全一致）。
const (
	ActionAllowed               = "ALLOWED"
	ActionBlockedLegacySSL      = "BLOCKED_LEGACY_SSL"
	ActionBlockedProtocolPolicy = "BLOCKED_PROTOCOL_POLICY"
	ActionHandshakeFailed       = "HANDSHAKE_FAILED"
)

// 字段截断长度上限（与迁移 000241 列定义严格对齐，防止异常长输入撑爆数据库列）。
const (
	maxLineLen        = 64 * 1024 // 64 KiB 单行上限
	maxGatewayNodeLen = 64
	maxSNILen         = 255
	maxClientIPLen    = 64
	maxProtocolLen    = 24
	maxCipherSuiteLen = 64
	maxJA3Len         = 64
	maxALPNLen        = 64
	maxActionLen      = 32
	maxErrorReasonLen = 512
)

// HandshakeEntry 是网关 tls-handshake-events.jsonl 的单行事件结构
// （字段与 gateway/modules/jiuzhang_guard/tlsmux/session_log.go HandshakeEvent 一一对应）。
type HandshakeEntry struct {
	OccurredAt         time.Time `json:"occurred_at"`
	GatewayNodeID      string    `json:"gateway_node_id"`
	ApplicationID      string    `json:"application_id"`
	SNI                string    `json:"sni"`
	ClientIP           string    `json:"client_ip"`
	ClientPort         int       `json:"client_port"`
	ServerPort         int       `json:"server_port"`
	DetectedProtocol   string    `json:"detected_protocol"`
	NegotiatedProtocol string    `json:"negotiated_protocol"`
	CipherSuite        string    `json:"cipher_suite"`
	IsGM               bool      `json:"is_gm"`
	JA3Hash            string    `json:"ja3_hash"`
	ALPN               string    `json:"alpn"`
	Action             string    `json:"action"`
	ErrorReason        string    `json:"error_reason"`
}

// IsValidAction 判断握手处置动作是否合法。
func IsValidAction(action string) bool {
	switch action {
	case ActionAllowed, ActionBlockedLegacySSL, ActionBlockedProtocolPolicy, ActionHandshakeFailed:
		return true
	}
	return false
}

// IsValidDetectedProtocol 判断检测协议标签是否属于受支持的协议枚举。
func IsValidDetectedProtocol(proto string) bool {
	switch proto {
	case ProtoSSLv2, ProtoSSLv2v3, ProtoSSLv3,
		ProtoTLS10, ProtoTLS11, ProtoTLS12, ProtoTLS13,
		ProtoTLCP11, ProtoUnknown:
		return true
	}
	return false
}

// IsLegacyProtocol 判断协议是否属于已淘汰的弱 SSL 协议（SSLv2 / SSLv2/v3 / SSLv3）。
func IsLegacyProtocol(proto string) bool {
	switch proto {
	case ProtoSSLv2, ProtoSSLv2v3, ProtoSSLv3:
		return true
	}
	return false
}

// IsGMCipherSuiteName 判断密码套件名称是否属于国密套件。
func IsGMCipherSuiteName(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	if upper == "" {
		return false
	}
	return strings.HasPrefix(upper, "TLCP_") ||
		strings.Contains(upper, "_SM4_") ||
		strings.HasSuffix(upper, "_SM3")
}

// normalizeDetectedProtocol 归一化检测协议标签（兼容 SSLv2_v3 写法，空串回退 UNKNOWN）。
func normalizeDetectedProtocol(raw string) string {
	s := sanitizeField(raw, maxProtocolLen)
	if s == "" {
		return ProtoUnknown
	}
	switch strings.ToUpper(s) {
	case "SSLV2":
		return ProtoSSLv2
	case "SSLV2/V3", "SSLV2_V3":
		return ProtoSSLv2v3
	case "SSLV3":
		return ProtoSSLv3
	case "TLS1.0":
		return ProtoTLS10
	case "TLS1.1":
		return ProtoTLS11
	case "TLS1.2":
		return ProtoTLS12
	case "TLS1.3":
		return ProtoTLS13
	case "TLCP1.1":
		return ProtoTLCP11
	case "UNKNOWN":
		return ProtoUnknown
	default:
		return s
	}
}

// ParseLine 解析单行 JSONL 加密会话握手事件（校验 + NUL 剥离 + 字段截断）。
func ParseLine(line []byte) (*HandshakeEntry, error) {
	s := strings.TrimSpace(string(line))
	if s == "" {
		return nil, fmt.Errorf("empty line")
	}
	if len(s) > maxLineLen {
		return nil, fmt.Errorf("line too long: %d bytes", len(s))
	}
	var e HandshakeEntry
	if err := json.Unmarshal([]byte(s), &e); err != nil {
		return nil, fmt.Errorf("invalid tls handshake json: %w", err)
	}
	if e.OccurredAt.IsZero() {
		return nil, fmt.Errorf("missing occurred_at")
	}
	e.OccurredAt = e.OccurredAt.UTC()

	e.GatewayNodeID = sanitizeField(e.GatewayNodeID, maxGatewayNodeLen)
	e.SNI = strings.ToLower(sanitizeField(e.SNI, maxSNILen))
	e.ClientIP = sanitizeClientIP(e.ClientIP)
	e.DetectedProtocol = normalizeDetectedProtocol(e.DetectedProtocol)
	e.NegotiatedProtocol = sanitizeField(e.NegotiatedProtocol, maxProtocolLen)
	e.CipherSuite = sanitizeField(e.CipherSuite, maxCipherSuiteLen)
	e.JA3Hash = strings.ToLower(sanitizeField(e.JA3Hash, maxJA3Len))
	e.ALPN = sanitizeField(e.ALPN, maxALPNLen)
	e.ErrorReason = sanitizeField(e.ErrorReason, maxErrorReasonLen)

	action := strings.ToUpper(sanitizeField(e.Action, maxActionLen))
	if action == "" {
		action = ActionAllowed
	}
	if !IsValidAction(action) {
		return nil, fmt.Errorf("invalid action: %q", e.Action)
	}
	e.Action = action

	if e.ClientPort < 0 || e.ClientPort > 65535 {
		e.ClientPort = 0
	}
	if e.ServerPort < 0 || e.ServerPort > 65535 {
		e.ServerPort = 0
	}

	if e.DetectedProtocol == ProtoTLCP11 || IsGMCipherSuiteName(e.CipherSuite) {
		e.IsGM = true
	}

	e.ApplicationID = strings.TrimSpace(stripNUL(e.ApplicationID))
	if e.ApplicationID != "" {
		if parsed, err := uuid.Parse(e.ApplicationID); err == nil {
			e.ApplicationID = parsed.String()
		} else {
			e.ApplicationID = ""
		}
	}

	return &e, nil
}

func sanitizeClientIP(raw string) string {
	s := sanitizeField(raw, maxClientIPLen)
	if s == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap().String()
	}
	return s
}

func sanitizeField(s string, max int) string {
	s = strings.TrimSpace(stripNUL(s))
	if len(s) > max {
		return s[:max]
	}
	return s
}

func stripNUL(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}
