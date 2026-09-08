package tproxyd

import (
	"net"
	"testing"
)

func TestBuildProxyV1Header(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("192.168.50.10"), Port: 54321}
	dst := &net.TCPAddr{IP: net.ParseIP("192.168.50.20"), Port: 8081}
	hdr, err := BuildProxyV1Header(src, dst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "PROXY TCP4 192.168.50.10 192.168.50.20 54321 8081\r\n"
	if string(hdr) != want {
		t.Fatalf("header = %q, want %q", hdr, want)
	}
}

func TestBuildProxyV1HeaderIPv4Mapped(t *testing.T) {
	// IPv4-mapped IPv6（::ffff:a.b.c.d）按 IPv4 处理
	src := &net.TCPAddr{IP: net.ParseIP("::ffff:192.168.50.10"), Port: 1234}
	dst := &net.TCPAddr{IP: net.ParseIP("192.168.50.20"), Port: 80}
	hdr, err := BuildProxyV1Header(src, dst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "PROXY TCP4 192.168.50.10 192.168.50.20 1234 80\r\n"
	if string(hdr) != want {
		t.Fatalf("header = %q, want %q", hdr, want)
	}
}

func TestBuildProxyV1HeaderRejectsInvalid(t *testing.T) {
	v4 := &net.TCPAddr{IP: net.ParseIP("192.168.50.10"), Port: 1234}
	v6 := &net.TCPAddr{IP: net.ParseIP("fd00::1"), Port: 1234}
	badPort := &net.TCPAddr{IP: net.ParseIP("192.168.50.20"), Port: 0}
	overPort := &net.TCPAddr{IP: net.ParseIP("192.168.50.20"), Port: 70000}

	if _, err := BuildProxyV1Header(v6, v4); err == nil {
		t.Fatal("纯 IPv6 源地址应报错")
	}
	if _, err := BuildProxyV1Header(v4, v6); err == nil {
		t.Fatal("纯 IPv6 目的地址应报错")
	}
	if _, err := BuildProxyV1Header(v4, badPort); err == nil {
		t.Fatal("端口 0 应报错")
	}
	if _, err := BuildProxyV1Header(v4, overPort); err == nil {
		t.Fatal("端口 >65535 应报错")
	}
	if _, err := BuildProxyV1Header(nil, v4); err == nil {
		t.Fatal("空源地址应报错")
	}
}

func TestDecodeOriginalDst(t *testing.T) {
	// 8081 = 0x1F91；内存网络字节序 [0x1F 0x91]，小端主机按 uint16 读出为 0x911F
	addr, err := DecodeOriginalDst(afInet, 0x911F, [4]byte{192, 168, 50, 20})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr.IP.String() != "192.168.50.20" || addr.Port != 8081 {
		t.Fatalf("decoded = %s, want 192.168.50.20:8081", addr)
	}
}

func TestDecodeOriginalDstRejectsInvalid(t *testing.T) {
	if _, err := DecodeOriginalDst(10 /* AF_INET6 */, 0x911F, [4]byte{192, 168, 50, 20}); err == nil {
		t.Fatal("非 AF_INET 地址族应报错")
	}
	if _, err := DecodeOriginalDst(afInet, 0, [4]byte{192, 168, 50, 20}); err == nil {
		t.Fatal("端口 0 应报错")
	}
}
