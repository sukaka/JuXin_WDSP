package tproxyd

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// clientHelloBytes 用 crypto/tls 经 net.Pipe 现场生成真实 ClientHello 的首个
// TLS record（type+version+length+载荷），serverName 为空则不携带 SNI 扩展。
func clientHelloBytes(t *testing.T, serverName string) []byte {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() {
		cfg := &tls.Config{InsecureSkipVerify: true, ServerName: serverName} //nolint:gosec // 测试桩不校验证书
		cli := tls.Client(c, cfg)
		_ = cli.Handshake() // 对端不响应必然失败，但 ClientHello 已写出
	}()
	_ = s.SetReadDeadline(time.Now().Add(3 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(s, hdr); err != nil {
		t.Fatalf("读取 record 头: %v", err)
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	body := make([]byte, recLen)
	if _, err := io.ReadFull(s, body); err != nil {
		t.Fatalf("读取 record 载荷: %v", err)
	}
	return append(hdr, body...)
}

func peekSNI(t *testing.T, data []byte) (string, bool, error) {
	t.Helper()
	br := bufio.NewReaderSize(bytes.NewReader(data), sniffBufSize)
	return peekClientHelloSNI(br)
}

func TestPeekSNIParsesRealClientHello(t *testing.T) {
	ch := clientHelloBytes(t, "www.test.com")
	sni, isTLS, err := peekSNI(t, ch)
	if err != nil || !isTLS {
		t.Fatalf("解析失败: sni=%q isTLS=%v err=%v", sni, isTLS, err)
	}
	if sni != "www.test.com" {
		t.Fatalf("sni = %q, want www.test.com", sni)
	}
}

func TestPeekSNINormalizesCaseAndTrailingDot(t *testing.T) {
	ch := clientHelloBytes(t, "Www.Test.COM.")
	sni, isTLS, err := peekSNI(t, ch)
	if err != nil || !isTLS {
		t.Fatalf("解析失败: err=%v", err)
	}
	if sni != "www.test.com" {
		t.Fatalf("sni = %q, want 小写归一+去末尾点 www.test.com", sni)
	}
}

func TestPeekSNINoSNIExtension(t *testing.T) {
	ch := clientHelloBytes(t, "") // 无 ServerName → 无 SNI 扩展
	sni, isTLS, err := peekSNI(t, ch)
	if !isTLS {
		t.Fatal("应识别为 TLS")
	}
	if err == nil || sni != "" {
		t.Fatalf("无 SNI 扩展应报错: sni=%q err=%v", sni, err)
	}
}

func TestPeekSNIPlainHTTPNotTLS(t *testing.T) {
	sni, isTLS, err := peekSNI(t, []byte("GET /echo HTTP/1.1\r\nHost: x\r\n\r\n"))
	if isTLS || !errors.Is(err, errNotTLS) {
		t.Fatalf("明文 HTTP 应判为非 TLS: isTLS=%v err=%v", isTLS, err)
	}
	if sni != "" {
		t.Fatalf("sni 应为空, got %q", sni)
	}
}

func TestPeekSNITruncatedRecord(t *testing.T) {
	ch := clientHelloBytes(t, "www.test.com")
	half := ch[:len(ch)/2] // record 头声明完整长度，实际载荷截断
	_, isTLS, err := peekSNI(t, half)
	if !isTLS || err == nil {
		t.Fatalf("截断 record 应报错: isTLS=%v err=%v", isTLS, err)
	}
}

func TestPeekSNIMalformedHandshake(t *testing.T) {
	// record 类型/版本合法，但握手消息类型非 ClientHello（type=2 ServerHello）
	bogus := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x03}
	_, isTLS, err := peekSNI(t, bogus)
	if !isTLS || err == nil {
		t.Fatalf("畸形握手应报错: isTLS=%v err=%v", isTLS, err)
	}
}

func TestPeekSNIDoesNotConsumeBytes(t *testing.T) {
	ch := clientHelloBytes(t, "www.test.com")
	br := bufio.NewReaderSize(bytes.NewReader(ch), sniffBufSize)
	if _, _, err := peekClientHelloSNI(br); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	rest, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(rest, ch) {
		t.Fatal("Peek 不得消费字节：读后字节流应与原 ClientHello 完全一致")
	}
}

func TestPeekSNIFragmentedDelivery(t *testing.T) {
	// 分片到达：net.Pipe 两次写入，Peek 应阻塞等待字节齐备后解析成功
	ch := clientHelloBytes(t, "www.test.com")
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() {
		cut := len(ch) / 3
		_, _ = c.Write(ch[:cut])
		time.Sleep(50 * time.Millisecond)
		_, _ = c.Write(ch[cut:])
	}()
	br := bufio.NewReaderSize(s, sniffBufSize)
	sni, isTLS, err := peekClientHelloSNI(br)
	if err != nil || !isTLS || sni != "www.test.com" {
		t.Fatalf("分片 ClientHello 解析失败: sni=%q isTLS=%v err=%v", sni, isTLS, err)
	}
}

func TestNormalizeHosts(t *testing.T) {
	hosts, err := normalizeHosts(" Www.Test.COM. ,www.test.com, *.Wild.Test.COM., api.test.com,,")
	if err != nil {
		t.Fatalf("normalizeHosts: %v", err)
	}
	if len(hosts) != 3 || hosts[0] != "www.test.com" || hosts[1] != "*.wild.test.com" || hosts[2] != "api.test.com" {
		t.Fatalf("归一化/去重/保序错误: %v", hosts)
	}
	for _, bad := range []string{
		"bad host.com",
		"*",
		"*.",
		"*.com",
		"*.*.test.com",
		"foo.*.test.com",
		"*foo.test.com",
		".test.com",
		"a..test.com",
		strings.Repeat("a", 254),
	} {
		if _, err := normalizeHosts(bad); err == nil {
			t.Fatalf("非法域名 %q 应报错", bad)
		}
	}
}

// buildFragmentedRecords 把单条 ClientHello 握手载荷按 chunkSize 拆分为多条 0x16 TLS record。
func buildFragmentedRecords(hsPayload []byte, chunkSize int) []byte {
	var out []byte
	for len(hsPayload) > 0 {
		n := chunkSize
		if n > len(hsPayload) {
			n = len(hsPayload)
		}
		chunk := hsPayload[:n]
		hsPayload = hsPayload[n:]
		out = append(out, tlsRecordHandshake, tlsRecordVersionMajor, 0x03, byte(n>>8), byte(n))
		out = append(out, chunk...)
	}
	return out
}

func TestPeekSNIMultiRecordFragmentedClientHello(t *testing.T) {
	ch := clientHelloBytes(t, "pq.example.com")
	// 原始单条 record 的握手载荷在 ch[5:]
	hs := ch[5:]
	// 场景1：跨多个小 record（甚至首条 record 仅 2 字节，把 4 字节握手头也拆开）
	frag := append(buildFragmentedRecords(hs[:2], 2), buildFragmentedRecords(hs[2:], 64)...)
	br := bufio.NewReaderSize(bytes.NewReader(frag), sniffBufSize)
	sni, isTLS, err := peekClientHelloSNI(br)
	if err != nil || !isTLS || sni != "pq.example.com" {
		t.Fatalf("多 record 分片解析失败: sni=%q isTLS=%v err=%v", sni, isTLS, err)
	}
	// Peek 不得消费字节：完整多 record 字节流应原样保留
	rest, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(rest, frag) {
		t.Fatal("多 record 分片 Peek 后字节流损坏")
	}
}

func TestPeekSNIFragmentedPQSizedClientHello(t *testing.T) {
	// 模拟后量子混合密钥交换（X25519MLKEM768 等）：在 extensions 中构造 ~2400 字节填充扩展，
	// 并将整个 ClientHello 拆分到多个 TLS 1.3 handshake record。
	host := []byte("pq-hybrid.example.com")
	var sniExt []byte
	listLen := 1 + 2 + len(host)
	sniExt = append(sniExt, byte(listLen>>8), byte(listLen), 0x00, byte(len(host)>>8), byte(len(host)))
	sniExt = append(sniExt, host...)

	padData := bytes.Repeat([]byte{0x42}, 2048)
	var exts []byte
	// padding ext (type 21) placed BEFORE server_name ext so SNI lands in a later record
	exts = append(exts, 0x00, 21, byte(len(padData)>>8), byte(len(padData)))
	exts = append(exts, padData...)
	exts = append(exts, 0x00, 0x00, byte(len(sniExt)>>8), byte(len(sniExt)))
	exts = append(exts, sniExt...)

	var body []byte
	body = append(body, 0x03, 0x03)              // client_version
	body = append(body, make([]byte, 32)...)     // random
	body = append(body, 0x00)                    // session_id len
	body = append(body, 0x00, 0x02, 0x13, 0x01)  // cipher_suites
	body = append(body, 0x01, 0x00)              // compression_methods
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	hs := make([]byte, 0, 4+len(body))
	hs = append(hs, tlsHsClientHello, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	// 拆分为 4 个 600 字节 record，SNI 位于最后一个 record
	frag := buildFragmentedRecords(hs, 600)
	sni, isTLS, err := peekSNI(t, frag)
	if err != nil || !isTLS || sni != "pq-hybrid.example.com" {
		t.Fatalf("PQ 分片 ClientHello 解析失败: sni=%q isTLS=%v err=%v", sni, isTLS, err)
	}
}

func TestPeekSNIRejectsOversizedFragmentedClientHello(t *testing.T) {
	// 声明长度超 16 KiB 上限，必须拒绝（fail-closed）
	oversized := []byte{
		tlsRecordHandshake, tlsRecordVersionMajor, 0x03, 0x00, 0x08,
		tlsHsClientHello, 0x00, 0x40, 0x01, // hsLen = 16385 -> 4+16385 > 16384
		0x03, 0x03, 0x00, 0x00,
	}
	_, isTLS, err := peekSNI(t, oversized)
	if !isTLS || err == nil {
		t.Fatalf("超 16 KiB ClientHello 应报错: isTLS=%v err=%v", isTLS, err)
	}
}
