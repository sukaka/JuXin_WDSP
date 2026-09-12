// TLS ClientHello SNI 解析测试（手工构造字节，无需真实握手）。
package mirrorcap

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// buildClientHelloBody 构造 ClientHello handshake body（不含 4 字节握手头）。
// sni 为空串则不携带 server_name 扩展；withExts=false 则不携带 extensions 块。
func buildClientHelloBody(sni string, withExts bool) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x03, 0x03}) // protocol_version TLS1.2
	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)
	b.Write(rnd)
	b.WriteByte(0)                                      // session_id 长度 0
	b.Write([]byte{0x00, 0x04, 0x13, 0x01, 0x13, 0x02}) // cipher_suites: len 4, TLS_AES_*
	b.Write([]byte{0x01, 0x00})                         // compression_methods: len 1, null
	if !withExts {
		return b.Bytes()
	}
	var ext bytes.Buffer
	// 先放一个无关扩展（extended_master_secret, type=0x0017 空体），验证遍历跳过逻辑
	ext.Write([]byte{0x00, 0x17, 0x00, 0x00})
	if sni != "" {
		name := []byte(sni)
		var sniExt bytes.Buffer
		sniExt.Write([]byte{0x00, byte(3 + len(name))}) // server_name_list 长度
		sniExt.WriteByte(0)                             // name_type = host_name
		sniExt.Write([]byte{byte(len(name) >> 8), byte(len(name))})
		sniExt.Write(name)
		body := sniExt.Bytes()
		ext.Write([]byte{0x00, 0x00, byte(len(body) >> 8), byte(len(body))}) // type=0 server_name
		ext.Write(body)
	}
	eb := ext.Bytes()
	b.Write([]byte{byte(len(eb) >> 8), byte(len(eb))})
	b.Write(eb)
	return b.Bytes()
}

// wrapClientHello 把 ClientHello 包装为 TLS record 序列（fragSize>0 时按该粒度分片）。
func wrapClientHello(body []byte, recordVersion byte, fragSize int) []byte {
	// 握手头：type=1(ClientHello) + 24 位长度
	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	var out bytes.Buffer
	for len(hs) > 0 {
		n := len(hs)
		if fragSize > 0 && n > fragSize {
			n = fragSize
		}
		out.Write([]byte{0x16, 0x03, recordVersion, byte(n >> 8), byte(n)})
		out.Write(hs[:n])
		hs = hs[n:]
	}
	return out.Bytes()
}

func TestParseClientHelloSNIWithSNI(t *testing.T) {
	wire := wrapClientHello(buildClientHelloBody("www.example.com", true), 0x03, 0)
	sni, ok := ParseClientHelloSNI(bytes.NewReader(wire), 0)
	if !ok || sni != "www.example.com" {
		t.Fatalf("sni=%q ok=%v, want www.example.com/true", sni, ok)
	}
}

// SNI 大小写不敏感：解析结果小写归一（与 hostOnly 对齐）。
func TestParseClientHelloSNILowercases(t *testing.T) {
	wire := wrapClientHello(buildClientHelloBody("WWW.Example.COM", true), 0x03, 0)
	sni, ok := ParseClientHelloSNI(bytes.NewReader(wire), 0)
	if !ok || sni != "www.example.com" {
		t.Fatalf("sni=%q ok=%v, want www.example.com/true（小写归一）", sni, ok)
	}
}

// ClientHello 未携带 server_name 扩展（有其他扩展）：合法无 SNI → ("", true)。
func TestParseClientHelloSNINoSNIExtension(t *testing.T) {
	wire := wrapClientHello(buildClientHelloBody("", true), 0x03, 0)
	sni, ok := ParseClientHelloSNI(bytes.NewReader(wire), 0)
	if !ok || sni != "" {
		t.Fatalf("sni=%q ok=%v, want 空串/true（无 SNI 扩展仍属合法 ClientHello）", sni, ok)
	}
}

// ClientHello 完全无 extensions 块：合法无 SNI → ("", true)。
func TestParseClientHelloSNINoExtensions(t *testing.T) {
	wire := wrapClientHello(buildClientHelloBody("", false), 0x03, 0)
	sni, ok := ParseClientHelloSNI(bytes.NewReader(wire), 0)
	if !ok || sni != "" {
		t.Fatalf("sni=%q ok=%v, want 空串/true（无 extensions 块）", sni, ok)
	}
}

// record 版本容忍 0x0301-0x0303。
func TestParseClientHelloSNIToleratesRecordVersions(t *testing.T) {
	for _, v := range []byte{0x01, 0x02, 0x03} {
		wire := wrapClientHello(buildClientHelloBody("a.example.com", true), v, 0)
		if sni, ok := ParseClientHelloSNI(bytes.NewReader(wire), 0); !ok || sni != "a.example.com" {
			t.Errorf("record 版本 0x030%d 应容忍: sni=%q ok=%v", v, sni, ok)
		}
	}
	// 0x0300（SSL3.0）/0x0304 不在容忍范围
	for _, v := range []byte{0x00, 0x04} {
		wire := wrapClientHello(buildClientHelloBody("a.example.com", true), v, 0)
		if _, ok := ParseClientHelloSNI(bytes.NewReader(wire), 0); ok {
			t.Errorf("record 版本 0x030%d 应拒绝", v)
		}
	}
}

// ClientHello 跨 record 分片：应按握手消息重组后解析成功。
func TestParseClientHelloSNIFragmentedRecords(t *testing.T) {
	body := buildClientHelloBody("frag.example.com", true)
	// 分片粒度 7（刻意不对齐任何字段边界）
	wire := wrapClientHello(body, 0x03, 7)
	sni, ok := ParseClientHelloSNI(bytes.NewReader(wire), 0)
	if !ok || sni != "frag.example.com" {
		t.Fatalf("分片 ClientHello: sni=%q ok=%v, want frag.example.com/true", sni, ok)
	}
}

// 非 TLS 数据（HTTP 明文）：首字节非 0x16 → ("", false)。
func TestParseClientHelloSNINonTLS(t *testing.T) {
	if _, ok := ParseClientHelloSNI(bytes.NewReader([]byte("GET / HTTP/1.1\r\n\r\n")), 0); ok {
		t.Fatal("HTTP 明文应返回 false")
	}
}

// 响应方向 ServerHello（handshake type=2）：非 ClientHello → ("", false)。
func TestParseClientHelloSNIServerHelloRejected(t *testing.T) {
	body := buildClientHelloBody("www.example.com", true)
	hs := append([]byte{0x02, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	var wire bytes.Buffer
	wire.Write([]byte{0x16, 0x03, 0x03, byte(len(hs) >> 8), byte(len(hs))})
	wire.Write(hs)
	if _, ok := ParseClientHelloSNI(bytes.NewReader(wire.Bytes()), 0); ok {
		t.Fatal("ServerHello 应返回 false（避免响应方向误记）")
	}
}

// 截断 record：声明长度大于实际载荷 → ("", false)。
func TestParseClientHelloSNITruncatedRecord(t *testing.T) {
	wire := wrapClientHello(buildClientHelloBody("www.example.com", true), 0x03, 0)
	if _, ok := ParseClientHelloSNI(bytes.NewReader(wire[:len(wire)-10]), 0); ok {
		t.Fatal("截断 record 应返回 false")
	}
}

// 截断在 record 头内（不足 5 字节）→ ("", false)。
func TestParseClientHelloSNITruncatedHeader(t *testing.T) {
	if _, ok := ParseClientHelloSNI(bytes.NewReader([]byte{0x16, 0x03, 0x03}), 0); ok {
		t.Fatal("截断 record 头应返回 false")
	}
}

// 畸形长度字段：server_name 条目声明长度超扩展体 → ("", false)。
func TestParseClientHelloSNIMalformedLength(t *testing.T) {
	body := buildClientHelloBody("www.example.com", true)
	// 找到 server_name 扩展并把 name 长度字段改大（越界）
	// 结构：... ext(0x00 0x00 len_hi len_lo) [list_len(2) type(1) name_len(2) name...]
	idx := bytes.Index(body, []byte("www.example.com"))
	if idx < 3 {
		t.Fatal("构造体异常：未找到 SNI 名")
	}
	body[idx-2] = 0x7F // name_len 高字节改大 → 声明长度越界
	body[idx-1] = 0xFF
	wire := wrapClientHello(body, 0x03, 0)
	if _, ok := ParseClientHelloSNI(bytes.NewReader(wire), 0); ok {
		t.Fatal("畸形长度字段应返回 false")
	}
}

// 读取上限：maxBytes 小于 ClientHello 实际长度 → ("", false)，且不超读。
func TestParseClientHelloSNIMaxBytesGuard(t *testing.T) {
	wire := wrapClientHello(buildClientHelloBody("www.example.com", true), 0x03, 0)
	if _, ok := ParseClientHelloSNI(bytes.NewReader(wire), 32); ok {
		t.Fatal("maxBytes 内读不完应返回 false")
	}
}

// 随机垃圾：绝不 panic，一律 ("", false)。
func TestParseClientHelloSNIGarbage(t *testing.T) {
	buf := make([]byte, 256)
	_, _ = rand.Read(buf)
	buf[0] = 0x16
	buf[1] = 0x03
	buf[2] = 0x03                                       // 越过 record 头校验，进入载荷解析路径
	_, _ = ParseClientHelloSNI(bytes.NewReader(buf), 0) // 不 panic 即通过
}
