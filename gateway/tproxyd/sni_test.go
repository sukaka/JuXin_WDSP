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
	hosts, err := normalizeHosts(" Www.Test.COM. ,www.test.com, api.test.com,,")
	if err != nil {
		t.Fatalf("normalizeHosts: %v", err)
	}
	if len(hosts) != 2 || hosts[0] != "www.test.com" || hosts[1] != "api.test.com" {
		t.Fatalf("归一化/去重/保序错误: %v", hosts)
	}
	if _, err := normalizeHosts("bad host.com"); err == nil {
		t.Fatal("含空白域名应报错")
	}
	if _, err := normalizeHosts("*.test.com"); err == nil {
		t.Fatal("通配符域名应报错（仅精确匹配）")
	}
	if _, err := normalizeHosts(strings.Repeat("a", 254)); err == nil {
		t.Fatal("超长域名应报错")
	}
}
