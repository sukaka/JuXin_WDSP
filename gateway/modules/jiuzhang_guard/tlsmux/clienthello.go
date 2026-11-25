// Package tlsmux 实现九章防护网关的通用 TLS 与国密 TLCP 同端口自识别监听包装器、
// ClientHello 全版本加密会话分析（SSLv2/SSLv2-v3/SSLv3/TLS1.0~1.3/TLCP1.1 + JA3）
// 及国密 TLCP / 协议降级回源传输模块。
package tlsmux

import (
	"crypto/md5" //nolint:gosec // JA3 行业标准指纹算法固定采用 MD5
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 协议版本号常量（网络字节序大端 uint16）
const (
	VersionTLCP11 uint16 = 0x0101 // GB/T 38636-2020 / GM/T 0024
	VersionSSLv2  uint16 = 0x0002
	VersionSSLv3  uint16 = 0x0300
	VersionTLS10  uint16 = 0x0301
	VersionTLS11  uint16 = 0x0302
	VersionTLS12  uint16 = 0x0303
	VersionTLS13  uint16 = 0x0304
)

// 标准检测协议标签（与数据库及管理面枚举一致）
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

const (
	// MaxClientHelloBytes 限制单连接首包预读上限（16 KiB + 5 字节记录头），防慢连接内存放大。
	MaxClientHelloBytes = 16*1024 + 5
	defaultPeekTimeout  = 5 * time.Second
)

// ClientHelloInfo 是从原始 TCP 首包中无损解析出的握手分析摘要。
type ClientHelloInfo struct {
	DetectedProtocol  string   // SSLv2 | SSLv2/v3 | SSLv3 | TLS1.0 | TLS1.1 | TLS1.2 | TLS1.3 | TLCP1.1 | UNKNOWN
	RecordVersion     uint16   // TLS/TLCP 记录层版本（SSLv2 格式为 0x0002）
	ClientVersion     uint16   // ClientHello 声明版本
	SupportedVersions []uint16 // 0x002B 扩展声明的协议版本列表
	SNI               string   // 0x0000 扩展中的主机名（小写归一化）
	CipherSuites      []uint16 // 客户端提议密码套件列表
	Extensions        []uint16 // 客户端扩展 ID 列表
	EllipticCurves    []uint16 // 0x000A SupportedGroups
	ECPointFormats    []uint8  // 0x000B ECPointFormats
	ALPN              []string // 0x0010 ALPN 协议列表
	IsGM              bool     // 是否国密 TLCP 或提议国密套件
	IsLegacySSL       bool     // 是否 SSLv2 / SSLv2/v3 / SSLv3
	JA3String         string   // JA3 原串
	JA3Hash           string   // JA3 MD5 32位小写十六进制
}

// IsGMCipherSuite 判断密码套件 ID 是否属于国密标准套件（TLCP 1.1 或 RFC 8998）。
func IsGMCipherSuite(id uint16) bool {
	switch id {
	case 0xe011, 0xe013, 0xe051, 0xe053, // TLCP ECC/ECDHE SM4 CBC/GCM SM3
		0xe019, 0xe01a, 0xe01b, 0xe01c, // TLCP IBC/IBSDH SM4
		0x00c6, 0x00c7: // RFC 8998 TLS_SM4_GCM_SM3 / TLS_SM4_CCM_SM3
		return true
	}
	return false
}

// ProtocolLabel 将大端协议版本号映射为统一协议名称。
func ProtocolLabel(ver uint16) string {
	switch ver {
	case VersionTLCP11:
		return ProtoTLCP11
	case VersionSSLv2:
		return ProtoSSLv2
	case VersionSSLv3:
		return ProtoSSLv3
	case VersionTLS10:
		return ProtoTLS10
	case VersionTLS11:
		return ProtoTLS11
	case VersionTLS12:
		return ProtoTLS12
	case VersionTLS13:
		return ProtoTLS13
	default:
		if ver == 0 {
			return ProtoUnknown
		}
		return fmt.Sprintf("0x%04x", ver)
	}
}

// ReadClientHelloPrefix 从 TCP 连接读取首个 SSL/TLS/TLCP ClientHello 记录（支持拆包读取并限制上限），
// 返回已解析的握手摘要与保留全部原始字节的 peekedConn。
func ReadClientHelloPrefix(conn net.Conn, timeout time.Duration, onClose func()) (*ClientHelloInfo, *peekedConn, error) {
	if timeout <= 0 {
		timeout = defaultPeekTimeout
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var head [5]byte
	n, err := io.ReadFull(conn, head[:])
	if err != nil {
		// 即使未读满 5 字节，也尽量把已读字节放回 peekedConn 便于上层按 UNKNOWN 记录或关闭
		pc := newPeekedConn(conn, head[:n], onClose)
		return &ClientHelloInfo{DetectedProtocol: ProtoUnknown}, pc, err
	}

	var buf []byte
	// 1. SSLv2 / SSLv2-v3 兼容 ClientHello 记录头：首字节最高位为 1（2-byte length），第 3 字节 msg_type=0x01
	if (head[0]&0x80) != 0 && head[2] == 0x01 {
		recLen := int(head[0]&0x7f)<<8 | int(head[1])
		totalLen := 2 + recLen
		if totalLen > MaxClientHelloBytes {
			totalLen = MaxClientHelloBytes
		}
		if totalLen <= 5 {
			buf = append([]byte(nil), head[:]...)
		} else {
			buf = make([]byte, totalLen)
			copy(buf[:5], head[:])
			readN, readErr := io.ReadFull(conn, buf[5:])
			buf = buf[:5+readN]
			if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
				pc := newPeekedConn(conn, buf, onClose)
				return ParseClientHello(buf), pc, readErr
			}
		}
		return ParseClientHello(buf), newPeekedConn(conn, buf, onClose), nil
	}

	// 2. 标准 TLS / SSLv3 / TLCP Handshake Record（ContentType = 0x16）
	if head[0] == 0x16 {
		recLen := int(binary.BigEndian.Uint16(head[3:5]))
		totalLen := 5 + recLen
		if totalLen > MaxClientHelloBytes {
			totalLen = MaxClientHelloBytes
		}
		buf = make([]byte, totalLen)
		copy(buf[:5], head[:])
		if totalLen > 5 {
			readN, readErr := io.ReadFull(conn, buf[5:])
			buf = buf[:5+readN]
			if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
				pc := newPeekedConn(conn, buf, onClose)
				return ParseClientHello(buf), pc, readErr
			}
		}
		return ParseClientHello(buf), newPeekedConn(conn, buf, onClose), nil
	}

	// 3. 非 SSL/TLS/TLCP 流量（例如明文 HTTP 打到 HTTPS 端口）
	buf = append([]byte(nil), head[:]...)
	return &ClientHelloInfo{DetectedProtocol: ProtoUnknown}, newPeekedConn(conn, buf, onClose), nil
}

// ParseClientHello 解析原始 SSL/TLS/TLCP 首包字节（纯函数，越界安全、永不 panic）。
func ParseClientHello(raw []byte) *ClientHelloInfo {
	info := &ClientHelloInfo{DetectedProtocol: ProtoUnknown}
	if len(raw) < 5 {
		return info
	}

	// 分支 A：SSLv2 及 SSLv2/v3 兼容 ClientHello
	if (raw[0]&0x80) != 0 && raw[2] == 0x01 {
		return parseSSLv2ClientHello(raw)
	}

	// 分支 B：标准 TLS / SSLv3 / TLCP Record（ContentType = 0x16）
	if raw[0] != 0x16 {
		return info
	}
	recVer := binary.BigEndian.Uint16(raw[1:3])
	recLen := int(binary.BigEndian.Uint16(raw[3:5]))
	info.RecordVersion = recVer

	payload := raw[5:]
	if recLen < len(payload) {
		payload = payload[:recLen]
	}
	// Handshake header: 1 byte type (0x01=ClientHello) + 3 bytes length
	if len(payload) < 4 || payload[0] != 0x01 {
		// 记录层合法但非完整 ClientHello 时按 RecordVersion 兜底归类
		classifyFromVersions(info)
		return info
	}
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	body := payload[4:]
	if hsLen < len(body) {
		body = body[:hsLen]
	}
	// ClientHello 固定头：2 bytes client_version + 32 bytes random
	if len(body) < 34 {
		classifyFromVersions(info)
		return info
	}
	info.ClientVersion = binary.BigEndian.Uint16(body[0:2])
	pos := 34

	// SessionID: 1-byte length + bytes
	if pos >= len(body) {
		classifyFromVersions(info)
		return info
	}
	sidLen := int(body[pos])
	pos++
	if pos+sidLen > len(body) {
		classifyFromVersions(info)
		return info
	}
	pos += sidLen

	// CipherSuites: 2-byte length + uint16 list
	if pos+2 > len(body) {
		classifyFromVersions(info)
		return info
	}
	csLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if csLen%2 != 0 || pos+csLen > len(body) {
		classifyFromVersions(info)
		return info
	}
	info.CipherSuites = make([]uint16, 0, csLen/2)
	for i := 0; i < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(body[pos+i : pos+i+2])
		info.CipherSuites = append(info.CipherSuites, cs)
		if IsGMCipherSuite(cs) {
			info.IsGM = true
		}
	}
	pos += csLen

	// CompressionMethods: 1-byte length + bytes
	if pos >= len(body) {
		finalizeClientHello(info)
		return info
	}
	compLen := int(body[pos])
	pos++
	if pos+compLen > len(body) {
		finalizeClientHello(info)
		return info
	}
	pos += compLen

	// Extensions（可选）：2-byte total length + (2-byte type, 2-byte len, data)...
	if pos+2 <= len(body) {
		extTotal := int(binary.BigEndian.Uint16(body[pos : pos+2]))
		pos += 2
		if pos+extTotal <= len(body) {
			extEnd := pos + extTotal
			for pos+4 <= extEnd {
				extType := binary.BigEndian.Uint16(body[pos : pos+2])
				extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
				pos += 4
				if pos+extLen > extEnd {
					break
				}
				extData := body[pos : pos+extLen]
				pos += extLen

				info.Extensions = append(info.Extensions, extType)
				switch extType {
				case 0x0000: // server_name (SNI)
					if sni := parseSNIExtension(extData); sni != "" {
						info.SNI = sni
					}
				case 0x000a: // supported_groups (elliptic_curves)
					info.EllipticCurves = parseUint16ListExtension(extData)
				case 0x000b: // ec_point_formats
					info.ECPointFormats = parseUint8ListExtension(extData)
				case 0x0010: // application_layer_protocol_negotiation (ALPN)
					info.ALPN = parseALPNExtension(extData)
				case 0x002b: // supported_versions (TLS 1.3 识别关键)
					info.SupportedVersions = parseSupportedVersionsExtension(extData)
				}
			}
		}
	}

	finalizeClientHello(info)
	return info
}

// parseSSLv2ClientHello 解析 SSLv2（0x0002）与 SSLv2/v3 兼容 ClientHello（0x0300~0x0304）。
func parseSSLv2ClientHello(raw []byte) *ClientHelloInfo {
	info := &ClientHelloInfo{
		RecordVersion: VersionSSLv2,
		IsLegacySSL:   true,
	}
	if len(raw) < 5 {
		info.DetectedProtocol = ProtoSSLv2
		return info
	}
	ver := binary.BigEndian.Uint16(raw[3:5])
	info.ClientVersion = ver
	if ver == VersionSSLv2 {
		info.DetectedProtocol = ProtoSSLv2
	} else if ver >= VersionSSLv3 && ver <= VersionTLS13 {
		// SSLv2 格式记录头承载 SSLv3 / TLS ClientHello（即标准的 SSLv2/v3 兼容握手）
		info.DetectedProtocol = ProtoSSLv2v3
	} else {
		info.DetectedProtocol = ProtoSSLv2
	}

	// SSLv2 ClientHello: [2 len][1 type=0x01][2 ver][2 cs_len][2 sid_len][2 chal_len][cs_specs...]
	if len(raw) >= 11 {
		csLen := int(binary.BigEndian.Uint16(raw[5:7]))
		if csLen > 0 && csLen%3 == 0 && 11+csLen <= len(raw) {
			for i := 0; i < csLen; i += 3 {
				// 3 字节 cipher spec：高字节 0x00 时低两字节对应 SSLv3/TLS 套件号
				if raw[11+i] == 0x00 {
					cs := binary.BigEndian.Uint16(raw[11+i+1 : 11+i+3])
					info.CipherSuites = append(info.CipherSuites, cs)
				}
			}
		}
	}
	computeJA3(info)
	return info
}

func finalizeClientHello(info *ClientHelloInfo) {
	classifyFromVersions(info)
	computeJA3(info)
}

func classifyFromVersions(info *ClientHelloInfo) {
	// 1. 优先识别国密 TLCP 1.1（记录层或 ClientHello 版本为 0x0101）
	if info.RecordVersion == VersionTLCP11 || info.ClientVersion == VersionTLCP11 {
		info.DetectedProtocol = ProtoTLCP11
		info.IsGM = true
		return
	}
	// 2. TLS 1.3 通过 supported_versions 扩展（0x002B）识别（其 client_version 固定填 0x0303）
	var maxSupported uint16
	for _, v := range info.SupportedVersions {
		if isGREASE(v) {
			continue
		}
		if v == VersionTLCP11 {
			info.DetectedProtocol = ProtoTLCP11
			info.IsGM = true
			return
		}
		if v > maxSupported && v <= VersionTLS13 {
			maxSupported = v
		}
	}
	if maxSupported == VersionTLS13 {
		info.DetectedProtocol = ProtoTLS13
		return
	}
	// 3. 常规 TLS 1.2 / 1.1 / 1.0 / SSLv3
	ver := info.ClientVersion
	if ver == 0 {
		ver = info.RecordVersion
	}
	switch ver {
	case VersionTLS13:
		info.DetectedProtocol = ProtoTLS13
	case VersionTLS12:
		info.DetectedProtocol = ProtoTLS12
	case VersionTLS11:
		info.DetectedProtocol = ProtoTLS11
	case VersionTLS10:
		info.DetectedProtocol = ProtoTLS10
	case VersionSSLv3:
		info.DetectedProtocol = ProtoSSLv3
		info.IsLegacySSL = true
	default:
		info.DetectedProtocol = ProtoUnknown
	}
}

func parseSNIExtension(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLen > len(data) {
		return ""
	}
	p := 2
	end := 2 + listLen
	for p+3 <= end {
		nameType := data[p]
		nameLen := int(binary.BigEndian.Uint16(data[p+1 : p+3]))
		p += 3
		if p+nameLen > end {
			return ""
		}
		if nameType == 0x00 && nameLen > 0 {
			return strings.ToLower(strings.TrimSpace(string(data[p : p+nameLen])))
		}
		p += nameLen
	}
	return ""
}

func parseUint16ListExtension(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen%2 != 0 || 2+listLen > len(data) {
		return nil
	}
	out := make([]uint16, 0, listLen/2)
	for i := 0; i < listLen; i += 2 {
		out = append(out, binary.BigEndian.Uint16(data[2+i:2+i+2]))
	}
	return out
}

func parseUint8ListExtension(data []byte) []uint8 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	if 1+listLen > len(data) {
		return nil
	}
	out := make([]uint8, listLen)
	copy(out, data[1:1+listLen])
	return out
}

func parseSupportedVersionsExtension(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	if listLen%2 != 0 || 1+listLen > len(data) {
		return nil
	}
	out := make([]uint16, 0, listLen/2)
	for i := 0; i < listLen; i += 2 {
		out = append(out, binary.BigEndian.Uint16(data[1+i:1+i+2]))
	}
	return out
}

func parseALPNExtension(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLen > len(data) {
		return nil
	}
	var protos []string
	p := 2
	end := 2 + listLen
	for p < end {
		l := int(data[p])
		p++
		if l == 0 || p+l > end {
			break
		}
		protos = append(protos, string(data[p:p+l]))
		p += l
	}
	return protos
}

// isGREASE 判断是否为 RFC 8701 GREASE 值（0x?a?a，高字节与低字节相同且低 4 位为 0xA）。
func isGREASE(v uint16) bool {
	return (v&0x0f0f) == 0x0a0a && (v>>8) == (v&0xff)
}

// computeJA3 计算标准 JA3 指纹：SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats。
func computeJA3(info *ClientHelloInfo) {
	ver := info.ClientVersion
	if ver == 0 {
		ver = info.RecordVersion
	}
	if ver == 0 {
		return
	}
	joinU16 := func(list []uint16) string {
		parts := make([]string, 0, len(list))
		for _, v := range list {
			if isGREASE(v) {
				continue
			}
			parts = append(parts, strconv.Itoa(int(v)))
		}
		return strings.Join(parts, "-")
	}
	joinU8 := func(list []uint8) string {
		parts := make([]string, 0, len(list))
		for _, v := range list {
			parts = append(parts, strconv.Itoa(int(v)))
		}
		return strings.Join(parts, "-")
	}
	ja3Str := fmt.Sprintf("%d,%s,%s,%s,%s",
		ver,
		joinU16(info.CipherSuites),
		joinU16(info.Extensions),
		joinU16(info.EllipticCurves),
		joinU8(info.ECPointFormats),
	)
	sum := md5.Sum([]byte(ja3Str)) //nolint:gosec // JA3 规范固定 MD5
	info.JA3String = ja3Str
	info.JA3Hash = hex.EncodeToString(sum[:])
}

// peekedConn 将已预读的字节无缝回放到 net.Conn 头部，供后续 tls.Server / tlcp.Server 正常握手；
// 并在底层连接关闭时触发 onClose（用于精准清理连接元数据注册表，杜绝内存泄漏）。
type peekedConn struct {
	net.Conn
	buf     []byte
	offset  int
	mu      sync.Mutex
	onClose func()
	closed  bool
}

func newPeekedConn(conn net.Conn, prefix []byte, onClose func()) *peekedConn {
	cp := make([]byte, len(prefix))
	copy(cp, prefix)
	return &peekedConn{
		Conn:    conn,
		buf:     cp,
		onClose: onClose,
	}
}

// SetOnClose 在握手成功后绑定连接关闭回调；若连接已关闭则立即执行。
func (p *peekedConn) SetOnClose(fn func()) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		if fn != nil {
			fn()
		}
		return
	}
	prev := p.onClose
	p.onClose = func() {
		if prev != nil {
			prev()
		}
		if fn != nil {
			fn()
		}
	}
	p.mu.Unlock()
}

func (p *peekedConn) Read(b []byte) (int, error) {
	if p.offset < len(p.buf) {
		n := copy(b, p.buf[p.offset:])
		p.offset += n
		if p.offset >= len(p.buf) {
			p.buf = nil // 及时释放缓冲内存
		}
		return n, nil
	}
	return p.Conn.Read(b)
}

func (p *peekedConn) Close() error {
	p.mu.Lock()
	var fn func()
	if !p.closed {
		p.closed = true
		fn = p.onClose
		p.onClose = nil
	}
	p.mu.Unlock()
	if fn != nil {
		fn()
	}
	return p.Conn.Close()
}

func (p *peekedConn) NetConn() net.Conn {
	return p.Conn
}
