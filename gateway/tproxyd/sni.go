// TLS ClientHello SNI 嗅探（纯标准库、纯函数式解析，仅 Peek 不消费字节）。
//
// 用途：透明串接 HTTPS 多虚拟主机场景（同 IP 多域名共享 443），按 SNI 决定
// 连接走向——防护清单内域名送 Caddy TLS 监听器终结检测；清单外域名直接 TCP
// 透传回源站（TLS 端到端不断开，WAF 无需其证书）。解析失败一律倒向检测路径，
// 攻击者无法靠畸形 ClientHello 绕过防护直通源站。
//
// 边界：ClientHello 跨多个 TLS record 分片（实测未见于主流栈）按解析失败处理；
// ECH 加密 ClientHello 时 SNI 不可见，同样倒向检测路径。
package tproxyd

import (
	"bufio"
	"errors"
	"fmt"
	"strings"
)

// TLS 协议常量（RFC 5246/8446，与平台无关的固定值）。
const (
	tlsRecordHandshake    = 0x16 // record 类型：握手
	tlsRecordVersionMajor = 3    // record 版本主版本号（TLS 1.x 均为 3）
	tlsHsClientHello      = 1    // handshake 类型：ClientHello
	tlsExtServerName      = 0    // 扩展类型：server_name（SNI）
	tlsSNIHostName        = 0    // SNI 名称类型：host_name
	// maxTLSRecord 单个 TLS record 载荷上限 16384 + 5 字节头（RFC 5246 §6.2.1）。
	maxTLSRecord = 16384 + 5
	// sniffBufSize 嗅探缓冲：容纳一个满载 record（Peek 上限）。
	sniffBufSize = maxTLSRecord
)

// errNotTLS 首字节非 TLS 握手 record（明文 HTTP 等），属正常分支而非错误。
var errNotTLS = errors.New("非 TLS 握手流量")

// peekClientHelloSNI 从 br 嗅探 TLS ClientHello 的 SNI server_name。
// 仅 Peek 不消费：返回后连接字节流保持完整，由调用方原样转发。
//
// 返回 (sni, isTLS, err)：
//   - isTLS=false：首字节非 TLS 握手（明文 HTTP 等），sni/err 为零值；
//   - isTLS=true、sni 非空：成功解析出 SNI（已小写归一、去末尾点）；
//   - err 非空：TLS 已识别但解析失败（截断/畸形/跨 record 分片/无 SNI 扩展）。
func peekClientHelloSNI(br *bufio.Reader) (string, bool, error) {
	// record 头 5 字节：type(1) version(2) length(2)
	hdr, err := br.Peek(5)
	if err != nil {
		return "", false, fmt.Errorf("读取 record 头失败: %w", err)
	}
	if hdr[0] != tlsRecordHandshake || hdr[1] != tlsRecordVersionMajor {
		return "", false, errNotTLS
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen <= 0 || recLen > maxTLSRecord-5 {
		return "", true, fmt.Errorf("record 长度非法: %d", recLen)
	}
	// 取完整 record（Peek 阻塞至字节齐备或连接读超时/对端关闭）
	rec, err := br.Peek(5 + recLen)
	if err != nil {
		return "", true, fmt.Errorf("读取 record 载荷失败（截断或对端关闭）: %w", err)
	}
	sni, err := parseClientHelloSNI(rec[5:])
	if err != nil {
		return "", true, err
	}
	return sni, true, nil
}

// parseClientHelloSNI 解析 ClientHello 握手消息体，提取 SNI host_name。
// 输入为单个 record 的载荷：type(1) length(3) body。逐字段跳过定长/变长段
// 定位扩展区，任一长度越界即返回错误（不信任对端自报长度）。
func parseClientHelloSNI(p []byte) (string, error) {
	if len(p) < 4 {
		return "", fmt.Errorf("握手消息过短: %d 字节", len(p))
	}
	if p[0] != tlsHsClientHello {
		return "", fmt.Errorf("首个握手消息非 ClientHello: type=%d", p[0])
	}
	hsLen := int(p[1])<<16 | int(p[2])<<8 | int(p[3])
	body := p[4:]
	if hsLen > len(body) {
		return "", fmt.Errorf("ClientHello 跨 record 分片（声明 %d 字节，本 record 仅 %d），不支持", hsLen, len(body))
	}
	body = body[:hsLen]

	// client_version(2) + random(32)
	if len(body) < 34 {
		return "", fmt.Errorf("ClientHello 体过短: %d 字节", len(body))
	}
	body = body[34:]
	// session_id(变长)
	var ok bool
	if body, ok = skipBytes(body, 1); !ok {
		return "", fmt.Errorf("session_id 字段越界")
	}
	// cipher_suites(变长)
	if body, ok = skipBytes(body, 2); !ok {
		return "", fmt.Errorf("cipher_suites 字段越界")
	}
	// compression_methods(变长)
	if body, ok = skipBytes(body, 1); !ok {
		return "", fmt.Errorf("compression_methods 字段越界")
	}
	// extensions 总长度(2)；无扩展区即无 SNI
	if len(body) < 2 {
		return "", errors.New("无扩展区（无 SNI）")
	}
	extTotal := int(body[0])<<8 | int(body[1])
	body = body[2:]
	if extTotal > len(body) {
		return "", fmt.Errorf("扩展区长度越界: 声明 %d 实际 %d", extTotal, len(body))
	}
	exts := body[:extTotal]
	// 逐个扩展：type(2) length(2) data
	for len(exts) >= 4 {
		extType := int(exts[0])<<8 | int(exts[1])
		extLen := int(exts[2])<<8 | int(exts[3])
		exts = exts[4:]
		if extLen > len(exts) {
			return "", fmt.Errorf("扩展 %d 长度越界", extType)
		}
		data := exts[:extLen]
		exts = exts[extLen:]
		if extType != tlsExtServerName {
			continue
		}
		return parseServerNameExt(data)
	}
	return "", errors.New("无 server_name 扩展（客户端未携带 SNI）")
}

// parseServerNameExt 解析 server_name 扩展数据：list_len(2) + 条目序列
// （type(1) len(2) name）。仅接受 host_name 类型条目。
func parseServerNameExt(d []byte) (string, error) {
	if len(d) < 2 {
		return "", fmt.Errorf("server_name 扩展过短: %d 字节", len(d))
	}
	listLen := int(d[0])<<8 | int(d[1])
	d = d[2:]
	if listLen > len(d) {
		return "", fmt.Errorf("server_name 列表长度越界: 声明 %d 实际 %d", listLen, len(d))
	}
	d = d[:listLen]
	for len(d) >= 3 {
		nameType := d[0]
		nameLen := int(d[1])<<8 | int(d[2])
		d = d[3:]
		if nameLen > len(d) {
			return "", fmt.Errorf("server_name 条目长度越界")
		}
		name := d[:nameLen]
		d = d[nameLen:]
		if nameType != tlsSNIHostName {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(string(name), "."))
		if host == "" {
			return "", errors.New("server_name 为空")
		}
		return host, nil
	}
	return "", errors.New("server_name 扩展中无 host_name 条目")
}

// skipBytes 跳过「n 字节长度前缀 + 相应载荷」的变长字段，返回剩余切片。
func skipBytes(b []byte, lenBytes int) ([]byte, bool) {
	if len(b) < lenBytes {
		return nil, false
	}
	var n int
	for i := 0; i < lenBytes; i++ {
		n = n<<8 | int(b[i])
	}
	b = b[lenBytes:]
	if n > len(b) {
		return nil, false
	}
	return b[n:], true
}
