// TLS ClientHello SNI 被动解析（纯标准库手写，不引入 crypto/tls——旁路只做只读识别，
// 不需要握手/解密能力，也避免为解析而引入完整 TLS 栈的攻击面）。
//
// 解析范围（RFC 5246/6066 子集）：
//   - record 层：content type 必须 0x16（handshake），版本容忍 0x0301-0x0303，
//     单条 record 声明长度上限 16384（TLS 规范上界），容忍 ClientHello 跨 record 分片；
//   - handshake 层：type 必须 1（ClientHello），依次跳过 protocol_version/random(32)/
//     session_id/cipher_suites/compression_methods，遍历 extensions 找 type=0
//     （server_name），取列表中第一个 host_name（type=0）。
//
// 护栏：读取总量不超过 maxBytes（io.LimitedReader 硬上限，绝不阻塞多读）；任何非 TLS、
// 非 ClientHello、截断、畸形长度都返回 ("", false)，绝不 panic。
//
// 返回值语义（三态，供嗅探器区分方向）：
//   - (sni, true)  ：确认是 ClientHello；sni 为空串表示该 ClientHello 未携带 SNI 扩展；
//   - ("", false)  ：不是 ClientHello（含响应方向 ServerHello）、非 TLS 或数据畸形/截断。
package mirrorcap

import (
	"encoding/binary"
	"io"
	"strings"
)

// defaultSNIMaxBytes SNI 解析读取上限（单条 TLS record 上界即 16KB，ClientHello
// 正常远小于此；超限说明畸形或异常大握手，放弃识别）。
const defaultSNIMaxBytes = 16 << 10

// maxTLSRecordPayload TLS record 载荷规范上界（RFC 5246 §6.2.1）。
const maxTLSRecordPayload = 16384

// ParseClientHelloSNI 从流中读取首个 TLS 握手消息并提取 SNI server_name。
// r 为重组流读端（调用方应已确认前两个字节为 0x16 0x03，此处仍完整校验）；
// maxBytes <= 0 时取 defaultSNIMaxBytes。
func ParseClientHelloSNI(r io.Reader, maxBytes int) (string, bool) {
	if maxBytes <= 0 {
		maxBytes = defaultSNIMaxBytes
	}
	lr := &io.LimitedReader{R: r, N: int64(maxBytes)}
	body, ok := readClientHello(lr)
	if !ok {
		return "", false
	}
	return sniFromClientHello(body)
}

// readClientHello 读取首个握手消息（ClientHello） body，容忍跨 record 分片。
// 返回的 body 不含 4 字节握手头；任何校验失败返回 false。
func readClientHello(r *io.LimitedReader) ([]byte, bool) {
	var hs []byte
	total := -1 // 握手消息全长（含 4 字节头），-1 = 尚未读到握手头
	for total < 0 || len(hs) < total {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return nil, false // 截断/EOF/丢包
		}
		if hdr[0] != 0x16 {
			return nil, false // 非 handshake record（含 CCS/Alert 穿插，ClientHello 必为首个消息）
		}
		// 版本容忍 0x0301-0x0303（TLS1.0-1.2；TLS1.3 ClientHello 同样声明 0x0301/0x0303）
		if hdr[1] != 0x03 || hdr[2] < 0x01 || hdr[2] > 0x03 {
			return nil, false
		}
		rlen := int(binary.BigEndian.Uint16(hdr[3:5]))
		if rlen == 0 || rlen > maxTLSRecordPayload {
			return nil, false
		}
		// 预算护栏：声明长度超过剩余读取预算，注定读不满，直接失败（不多等一个字节）
		if int64(rlen) > r.N {
			return nil, false
		}
		frag := make([]byte, rlen)
		if _, err := io.ReadFull(r, frag); err != nil {
			return nil, false
		}
		if hs == nil {
			// 首个 record 必须承载握手头且为 ClientHello
			if rlen < 4 || frag[0] != 1 {
				return nil, false
			}
			total = 4 + (int(frag[1])<<16 | int(frag[2])<<8 | int(frag[3]))
			// 全长同样受预算约束（ClientHello 超 maxBytes 属异常，放弃识别）
			if int64(total) > int64(len(frag))+r.N {
				return nil, false
			}
		}
		hs = append(hs, frag...)
		if len(hs) > total {
			hs = hs[:total] // record 携带了后续握手消息前缀（罕见），只取 ClientHello 部分
		}
	}
	return hs[4:total], true
}

// sniFromClientHello 解析 ClientHello body 提取 SNI（无 SNI 扩展返回 ("", true)）。
func sniFromClientHello(body []byte) (string, bool) {
	c := byteCursor{b: body}
	if !c.skip(2 + 32) { // protocol_version + random
		return "", false
	}
	if n, ok := c.u8(); !ok || !c.skip(n) { // session_id
		return "", false
	}
	if n, ok := c.u16(); !ok || !c.skip(n) { // cipher_suites
		return "", false
	}
	if n, ok := c.u8(); !ok || !c.skip(n) { // compression_methods
		return "", false
	}
	extLen, ok := c.u16()
	if !ok {
		return "", true // 无 extensions 块：合法 ClientHello，但无 SNI
	}
	ext, ok := c.take(extLen)
	if !ok {
		return "", false // extensions 声明长度超实际（畸形）
	}
	ec := byteCursor{b: ext}
	for ec.remaining() >= 4 {
		etype, _ := ec.u16()
		elen, _ := ec.u16()
		data, ok := ec.take(elen)
		if !ok {
			return "", false
		}
		if etype != 0 { // 0 = server_name
			continue
		}
		// 扩展体本身畸形则整体判定失败（false），无 host_name 条目属合法无 SNI（true）
		return parseServerNameList(data)
	}
	return "", true // 有 extensions 但无 server_name：合法无 SNI
}

// parseServerNameList 解析 server_name 扩展体，取第一个 host_name（type=0）。
// 扩展体畸形返回 ("", false)；无 host_name 条目返回 ("", true)。
func parseServerNameList(d []byte) (string, bool) {
	c := byteCursor{b: d}
	listLen, ok := c.u16()
	if !ok {
		return "", false
	}
	list, ok := c.take(listLen)
	if !ok {
		return "", false
	}
	lc := byteCursor{b: list}
	for lc.remaining() >= 3 {
		ntype, _ := lc.u8()
		nlen, _ := lc.u16()
		name, ok := lc.take(nlen)
		if !ok {
			return "", false
		}
		if ntype == 0 && nlen > 0 {
			// SNI 为 ASCII DNS 名（RFC 6066 禁止 A-label 之外的编码）；小写归一与 hostOnly 对齐
			return strings.ToLower(string(name)), true
		}
	}
	return "", true
}

// byteCursor 有界游标：所有取数先查边界，杜绝越界 panic。
type byteCursor struct {
	b   []byte
	off int
}

func (c *byteCursor) remaining() int { return len(c.b) - c.off }

func (c *byteCursor) take(n int) ([]byte, bool) {
	if n < 0 || c.remaining() < n {
		return nil, false
	}
	s := c.b[c.off : c.off+n]
	c.off += n
	return s, true
}

func (c *byteCursor) skip(n int) bool {
	_, ok := c.take(n)
	return ok
}

func (c *byteCursor) u8() (int, bool) {
	s, ok := c.take(1)
	if !ok {
		return 0, false
	}
	return int(s[0]), true
}

func (c *byteCursor) u16() (int, bool) {
	s, ok := c.take(2)
	if !ok {
		return 0, false
	}
	return int(s[0])<<8 | int(s[1]), true
}
