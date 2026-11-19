package tproxyd

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeOriginDst 测试桩：模拟 SO_ORIGINAL_DST 返回的原始目的地址。
func fakeOriginDst(ip string, port int) resolveDstFunc {
	return func(conn *net.TCPConn) (*net.TCPAddr, error) {
		return &net.TCPAddr{IP: net.ParseIP(ip), Port: port}, nil
	}
}

// startFakeCaddy 启动模拟下游（Caddy）：首行读取 PROXY 头交给 headerCh，
// 随后按 echo 模式回传收到的全部字节。返回监听地址。
func startFakeCaddy(t *testing.T, headerCh chan<- string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake caddy listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if headerCh != nil {
					headerCh <- line
				}
				// echo 模式（读超时防止协程泄漏）
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, _ = io.Copy(c, br)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// startServer 以注入的原始目的桩启动牵引服务（测试用，端口动态分配）。
func startServer(t *testing.T, target string, maxConns int, resolve resolveDstFunc) (*Server, *Stats) {
	t.Helper()
	cfg := Config{
		Listen:           "127.0.0.1:0",
		Target:           target,
		MaxConns:         maxConns,
		StatsInterval:    time.Minute,
		DialTimeout:      2 * time.Second,
		ShutdownGrace:    time.Second,
		RelayIdleTimeout: 30 * time.Second,
	}
	stats := &Stats{}
	srv, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.resolveDst = resolve
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()
	t.Cleanup(func() {
		srv.Shutdown(2 * time.Second)
		if err := <-serveErr; err != nil {
			t.Errorf("Serve 返回错误: %v", err)
		}
	})
	return srv, stats
}

// waitFor 轮询条件直至满足或超时失败。
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等待超时: %s", what)
}

func TestRelayProxyHeaderAndBytes(t *testing.T) {
	headerCh := make(chan string, 1)
	target := startFakeCaddy(t, headerCh)
	srv, stats := startServer(t, target, 16, fakeOriginDst("192.168.50.20", 8081))

	client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// 下游必须首先收到 PROXY v1 头（真实源 127.0.0.1 + 原始目的 192.168.50.20:8081）
	select {
	case line := <-headerCh:
		if !strings.HasPrefix(line, "PROXY TCP4 127.0.0.1 192.168.50.20 ") ||
			!strings.HasSuffix(line, " 8081\r\n") {
			t.Fatalf("PROXY 头格式错误: %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("下游未收到 PROXY 头")
	}

	// 双向字节透传
	msg := []byte("GET /echo HTTP/1.1\r\n\r\n")
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
	_ = client.Close()

	waitFor(t, "连接统计归位", func() bool {
		return stats.ActiveConns.Load() == 0 && stats.BytesToTarget.Load() == uint64(len(msg))
	})
	if stats.ConnAccepted.Load() != 1 {
		t.Fatalf("accepted = %d, want 1", stats.ConnAccepted.Load())
	}
	if stats.BytesToClient.Load() != uint64(len(msg)) {
		t.Fatalf("bytes t2c = %d, want %d", stats.BytesToClient.Load(), len(msg))
	}
}

func TestBackpressureRejectsOverLimit(t *testing.T) {
	target := startFakeCaddy(t, nil) // 保持连接不回传，占用并发名额
	srv, stats := startServer(t, target, 1, fakeOriginDst("192.168.50.20", 8081))

	held, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial held: %v", err)
	}
	defer held.Close()
	waitFor(t, "首连接占住名额", func() bool { return stats.ActiveConns.Load() == 1 })

	// 第二个连接超上限：接受后立即关闭（快速失败背压）
	second, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial second: %v", err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("超上限连接应被立即关闭")
	}
	waitFor(t, "拒绝计数", func() bool { return stats.ConnRejected.Load() == 1 })
}

func TestResolveDstErrorClosesConn(t *testing.T) {
	target := startFakeCaddy(t, nil)
	resolveErr := func(conn *net.TCPConn) (*net.TCPAddr, error) {
		return nil, fmt.Errorf("getsockopt(SO_ORIGINAL_DST): 连接未经 REDIRECT 牵引")
	}
	srv, stats := startServer(t, target, 16, resolveErr)

	client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("原始目的解析失败应关闭连接")
	}
	waitFor(t, "origdst 错误计数", func() bool { return stats.OrigDstErrors.Load() == 1 })
}

// startCountingEcho 通用下游桩：每接受连接计数；readProxyLine 时首行按 PROXY
// 头读入 headerCh，随后 echo 收到的全部字节（读超时防协程泄漏）。
func startCountingEcho(t *testing.T, readProxyLine bool, headerCh chan<- string) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	conns := &atomic.Int32{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				// 读 PROXY 头与 echo 必须共用同一 bufio.Reader：头行预读可能把
				// 后续业务字节吸入缓冲，丢弃 Reader 会丢字节
				br := bufio.NewReader(c)
				if readProxyLine && headerCh != nil {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					headerCh <- line
				}
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, _ = io.Copy(c, br)
			}(conn)
		}
	}()
	return ln.Addr().String(), conns
}

// startSNIServer 以完整配置启动 SNI 分流牵引服务（测试用，端口动态分配）。
func startSNIServer(t *testing.T, cfg Config, resolve resolveDstFunc) (*Server, *Stats) {
	t.Helper()
	cfg.Listen = "127.0.0.1:0"
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 16
	}
	cfg.StatsInterval = time.Minute
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 2 * time.Second
	}
	if cfg.ShutdownGrace == 0 {
		cfg.ShutdownGrace = time.Second
	}
	if cfg.RelayIdleTimeout == 0 {
		cfg.RelayIdleTimeout = 30 * time.Second
	}
	stats := &Stats{}
	srv, err := NewServer(cfg, stats)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.resolveDst = resolve
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()
	t.Cleanup(func() {
		srv.Shutdown(2 * time.Second)
		if err := <-serveErr; err != nil {
			t.Errorf("Serve 返回错误: %v", err)
		}
	})
	return srv, stats
}

// 清单内域名的 TLS 连接：送 TargetTLS，PROXY 头先行，字节完整透传。
func TestSNIProtectedTLSRoutesToTargetTLS(t *testing.T) {
	httpHeader := make(chan string, 1)
	tlsHeader := make(chan string, 1)
	httpAddr, httpConns := startCountingEcho(t, true, httpHeader)
	tlsAddr, _ := startCountingEcho(t, true, tlsHeader)

	srv, stats := startSNIServer(t, Config{
		Target:       httpAddr,
		TargetTLS:    tlsAddr,
		ProtectHosts: []string{"www.test.com"},
		SniffTimeout: time.Second,
	}, fakeOriginDst("192.168.50.20", 443))

	client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	ch := clientHelloBytes(t, "www.test.com")
	// 先写 ClientHello（服务端嗅探到字节才会选路并连接下游），再验 PROXY 头
	if _, err := client.Write(ch); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}

	// TLS 下游必须首先收到 PROXY v1 头（真实源 + 原始目的 192.168.50.20:443）
	select {
	case line := <-tlsHeader:
		if !strings.HasPrefix(line, "PROXY TCP4 127.0.0.1 192.168.50.20 ") ||
			!strings.HasSuffix(line, " 443\r\n") {
			t.Fatalf("PROXY 头格式错误: %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TLS 下游未收到 PROXY 头")
	}

	// ClientHello 字节经嗅探后完整透传（echo 逐字回传）
	buf := make([]byte, len(ch))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, ch) {
		t.Fatal("ClientHello 透传字节与原字节不一致")
	}
	if httpConns.Load() != 0 {
		t.Fatal("TLS 防护流量不应到达 HTTP 下游")
	}
	waitFor(t, "ConnsProtected 计数", func() bool { return stats.ConnsProtected.Load() == 1 })
	if stats.ConnsPassthrough.Load() != 0 {
		t.Fatal("清单内域名不应计入透传")
	}
}

// 显式透传白名单内域名的 TLS 连接：按原始目的端到端透传，不注入 PROXY 头、不进任何下游。
func TestSNIPassthroughToOriginalDst(t *testing.T) {
	httpAddr, httpConns := startCountingEcho(t, true, nil)
	tlsAddr, tlsConns := startCountingEcho(t, true, nil)
	originAddr, _ := startCountingEcho(t, false, nil) // 假源站：原样 echo
	_, originPort, _ := net.SplitHostPort(originAddr)
	port := 0
	_, _ = fmt.Sscanf(originPort, "%d", &port)

	// 原始目的桩返回假源站地址（透传路径应 dial 该地址）
	resolve := func(conn *net.TCPConn) (*net.TCPAddr, error) {
		return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}, nil
	}
	srv, stats := startSNIServer(t, Config{
		Target:               httpAddr,
		TargetTLS:            tlsAddr,
		ProtectHosts:         []string{"www.test.com"},
		PassthroughAllowlist: []string{"www.test1.com"},
		SniffTimeout:         time.Second,
	}, resolve)

	client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	ch := clientHelloBytes(t, "www.test1.com")
	if _, err := client.Write(ch); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}

	// 源站原样 echo：收到的首字节即 TLS record 首字节（若被注入 PROXY 头则不符）
	buf := make([]byte, len(ch))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, ch) {
		t.Fatal("透传路径字节流被改动（疑似注入了 PROXY 头）")
	}
	if httpConns.Load() != 0 || tlsConns.Load() != 0 {
		t.Fatalf("透传流量不应到达下游: http=%d tls=%d", httpConns.Load(), tlsConns.Load())
	}
	waitFor(t, "ConnsPassthrough 计数", func() bool { return stats.ConnsPassthrough.Load() == 1 })
}

// 未列明 SNI（既不在 ProtectHosts 也不在 PassthroughAllowlist）：默认 fail-closed 倒向 TargetTLS，
// 绝不直连原始目的绕过 WAF。
func TestSNIUnlistedDefaultsFailClosedToTargetTLS(t *testing.T) {
	cases := []struct {
		name      string
		allowlist []string
		sni       string
	}{
		{"空透传白名单默认拒绝直通", nil, "www.test1.com"},
		{"不在白名单内的未列明域名", []string{"allowed.example.com"}, "attacker.evil"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tlsHeader := make(chan string, 1)
			httpAddr, httpConns := startCountingEcho(t, true, nil)
			tlsAddr, _ := startCountingEcho(t, true, tlsHeader)
			originAddr, originConns := startCountingEcho(t, false, nil)
			_, originPort, _ := net.SplitHostPort(originAddr)
			port := 0
			_, _ = fmt.Sscanf(originPort, "%d", &port)
			resolve := func(conn *net.TCPConn) (*net.TCPAddr, error) {
				return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}, nil
			}

			srv, stats := startSNIServer(t, Config{
				Target:               httpAddr,
				TargetTLS:            tlsAddr,
				ProtectHosts:         []string{"www.test.com"},
				PassthroughAllowlist: tc.allowlist,
				SniffTimeout:         time.Second,
			}, resolve)

			client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer client.Close()

			ch := clientHelloBytes(t, tc.sni)
			if _, err := client.Write(ch); err != nil {
				t.Fatalf("write ClientHello: %v", err)
			}
			select {
			case line := <-tlsHeader:
				if !strings.HasPrefix(line, "PROXY TCP4 ") {
					t.Fatalf("未列明 SNI 倒向 TargetTLS 缺 PROXY 头: %q", line)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("未列明 SNI 未 fail-closed 倒向 TargetTLS")
			}
			buf := make([]byte, len(ch))
			_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := io.ReadFull(client, buf); err != nil {
				t.Fatalf("read echo: %v", err)
			}
			if !bytes.Equal(buf, ch) {
				t.Fatal("ClientHello 字节流在倒向 TargetTLS 后损坏")
			}
			if originConns.Load() != 0 || httpConns.Load() != 0 {
				t.Fatalf("未列明 SNI 不得直通源站或 HTTP 路径: origin=%d http=%d", originConns.Load(), httpConns.Load())
			}
			if stats.ConnsPassthrough.Load() != 0 {
				t.Fatalf("未列明 SNI 不应计入透传: %d", stats.ConnsPassthrough.Load())
			}
			waitFor(t, "ConnsUnlistedTLS 计数", func() bool { return stats.ConnsUnlistedTLS.Load() == 1 })
		})
	}
}

// ProtectHosts 优先级高于 PassthroughAllowlist：同一域名同时出现在两份清单时必须送检测路径。
func TestSNIProtectHostsOverridesPassthroughAllowlist(t *testing.T) {
	tlsHeader := make(chan string, 1)
	httpAddr, _ := startCountingEcho(t, true, nil)
	tlsAddr, _ := startCountingEcho(t, true, tlsHeader)
	originAddr, originConns := startCountingEcho(t, false, nil)
	_, originPort, _ := net.SplitHostPort(originAddr)
	port := 0
	_, _ = fmt.Sscanf(originPort, "%d", &port)
	resolve := func(conn *net.TCPConn) (*net.TCPAddr, error) {
		return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}, nil
	}

	srv, stats := startSNIServer(t, Config{
		Target:               httpAddr,
		TargetTLS:            tlsAddr,
		ProtectHosts:         []string{"www.test.com"},
		PassthroughAllowlist: []string{"www.test.com"},
		SniffTimeout:         time.Second,
	}, resolve)

	client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	ch := clientHelloBytes(t, "www.test.com")
	if _, err := client.Write(ch); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}
	select {
	case line := <-tlsHeader:
		if !strings.HasPrefix(line, "PROXY TCP4 ") {
			t.Fatalf("防护域名缺 PROXY 头: %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("防护域名未送 TargetTLS")
	}
	if originConns.Load() != 0 || stats.ConnsPassthrough.Load() != 0 {
		t.Fatalf("防护域名被错误透传: origin=%d passthrough=%d", originConns.Load(), stats.ConnsPassthrough.Load())
	}
	waitFor(t, "ConnsProtected 计数", func() bool { return stats.ConnsProtected.Load() == 1 })
}

// 防自连环路 DoS：SO_ORIGINAL_DST 指向 tproxyd 自身监听地址/端口或任意本机接口 IP+监听端口时，
// 必须在拨号前拒绝，绝不自连放大耗尽 MaxConns。
func TestSelfDialLoopOrigDstRejected(t *testing.T) {
	httpAddr, httpConns := startCountingEcho(t, true, nil)
	tlsAddr, tlsConns := startCountingEcho(t, true, nil)

	var targetIP atomic.Value
	srv, stats := startSNIServer(t, Config{
		Target:               httpAddr,
		TargetTLS:            tlsAddr,
		ProtectHosts:         []string{"www.test.com"},
		PassthroughAllowlist: []string{"pass.test.com"},
		SniffTimeout:         time.Second,
	}, func(conn *net.TCPConn) (*net.TCPAddr, error) {
		listenTCP := conn.LocalAddr().(*net.TCPAddr)
		ip := targetIP.Load().(net.IP)
		return &net.TCPAddr{IP: ip, Port: listenTCP.Port}, nil
	})
	srv.localAddrs = func() ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.20.30.40")}, nil
	}

	cases := []struct {
		name string
		ip   string
	}{
		{"自身监听回环地址与端口", "127.0.0.1"},
		{"本机其他接口IP配自身监听端口", "10.20.30.40"},
		{"未指定地址配自身监听端口", "0.0.0.0"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			targetIP.Store(net.ParseIP(tc.ip))
			client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer client.Close()
			// 即便携带透传白名单 SNI 也应在嗅探/拨号前直接关闭
			_, _ = client.Write(clientHelloBytes(t, "pass.test.com"))
			_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := client.Read(make([]byte, 1)); err == nil {
				t.Fatalf("指向自身监听端口 %s 的连接应被立即关闭", tc.ip)
			}
			wantErrs := uint64(i + 1)
			waitFor(t, "OrigDstErrors 递增", func() bool { return stats.OrigDstErrors.Load() == wantErrs })
			if stats.ConnAccepted.Load() != wantErrs {
				t.Fatalf("疑似发生自连递归: accepted=%d want %d", stats.ConnAccepted.Load(), wantErrs)
			}
			if stats.DialErrors.Load() != 0 || stats.ConnsPassthrough.Load() != 0 || httpConns.Load() != 0 || tlsConns.Load() != 0 {
				t.Fatalf("自连目标不应发起任何拨号: dialErr=%d pass=%d http=%d tls=%d",
					stats.DialErrors.Load(), stats.ConnsPassthrough.Load(), httpConns.Load(), tlsConns.Load())
			}
		})
	}
}

// 畸形 TLS（握手消息非 ClientHello）：倒向 TargetTLS 检测路径并计数，不直通源站。
func TestMalformedTLSFallsToTLSInspection(t *testing.T) {
	tlsHeader := make(chan string, 1)
	httpAddr, httpConns := startCountingEcho(t, true, nil)
	tlsAddr, _ := startCountingEcho(t, true, tlsHeader)
	originAddr, originConns := startCountingEcho(t, false, nil)
	_, originPort, _ := net.SplitHostPort(originAddr)
	port := 0
	_, _ = fmt.Sscanf(originPort, "%d", &port)
	resolve := func(conn *net.TCPConn) (*net.TCPAddr, error) {
		return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}, nil
	}

	srv, stats := startSNIServer(t, Config{
		Target:       httpAddr,
		TargetTLS:    tlsAddr,
		ProtectHosts: []string{"www.test.com"},
		SniffTimeout: time.Second,
	}, resolve)

	client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	bogus := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x03}
	// 先写畸形 record（服务端嗅探后才会倒向 TLS 检测路径），再验 PROXY 头
	if _, err := client.Write(bogus); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case line := <-tlsHeader:
		if !strings.HasPrefix(line, "PROXY TCP4 ") {
			t.Fatalf("TLS 检测路径缺 PROXY 头: %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("畸形 TLS 未倒向 TargetTLS")
	}
	buf := make([]byte, len(bogus))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if httpConns.Load() != 0 || originConns.Load() != 0 {
		t.Fatal("畸形 TLS 不应走 HTTP 路径或直通源站")
	}
	waitFor(t, "SniffErrors 计数", func() bool { return stats.SniffErrors.Load() == 1 })
}

// 明文 HTTP（功能开启时）：维持原 Target 路径。
func TestPlainHTTPRoutesToHTTPTargetWithDispatchOn(t *testing.T) {
	httpHeader := make(chan string, 1)
	httpAddr, _ := startCountingEcho(t, true, httpHeader)
	tlsAddr, tlsConns := startCountingEcho(t, true, nil)

	srv, stats := startSNIServer(t, Config{
		Target:       httpAddr,
		TargetTLS:    tlsAddr,
		ProtectHosts: []string{"www.test.com"},
		SniffTimeout: time.Second,
	}, fakeOriginDst("192.168.50.20", 8081))

	client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	msg := []byte("GET /echo HTTP/1.1\r\n\r\n")
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case line := <-httpHeader:
		if !strings.HasPrefix(line, "PROXY TCP4 ") {
			t.Fatalf("HTTP 路径缺 PROXY 头: %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP 下游未收到 PROXY 头")
	}
	buf := make([]byte, len(msg))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if tlsConns.Load() != 0 {
		t.Fatal("明文 HTTP 不应到达 TLS 下游")
	}
	if stats.ConnsProtected.Load() != 0 || stats.ConnsPassthrough.Load() != 0 {
		t.Fatal("明文 HTTP 不应计入 SNI 分流计数")
	}
}

// 嗅探读超时：连接后长期不发字节 → 超时关连接并计数。
func TestSniffTimeoutClosesIdleConn(t *testing.T) {
	httpAddr, _ := startCountingEcho(t, true, nil)
	srv, stats := startSNIServer(t, Config{
		Target:       httpAddr,
		TargetTLS:    httpAddr, // 本用例用不到
		ProtectHosts: []string{"www.test.com"},
		SniffTimeout: 200 * time.Millisecond,
	}, fakeOriginDst("192.168.50.20", 443))

	client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("嗅探超时后连接应被关闭")
	}
	waitFor(t, "SniffTimeouts 计数", func() bool { return stats.SniffTimeouts.Load() == 1 })
	if stats.ConnAccepted.Load() != 1 {
		t.Fatalf("accepted = %d, want 1", stats.ConnAccepted.Load())
	}
}

// 透传空闲超时：连接建立后两端静默超过 RelayIdleTimeout → 关连接释放令牌并计数。
func TestRelayIdleTimeoutClosesConn(t *testing.T) {
	target := startFakeCaddy(t, nil)
	srv, stats := startSNIServer(t, Config{
		Target:           target,
		RelayIdleTimeout: 300 * time.Millisecond,
	}, fakeOriginDst("192.168.50.20", 8081))

	client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	waitFor(t, "连接建立", func() bool { return stats.ActiveConns.Load() == 1 })

	// 全程不发字节：服务端应在空闲超时后关闭连接（读返回错误/EOF）
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("空闲超时后连接应被关闭")
	}
	waitFor(t, "RelayIdleTimeouts 计数", func() bool { return stats.RelayIdleTimeouts.Load() == 1 })
	waitFor(t, "令牌释放", func() bool { return stats.ActiveConns.Load() == 0 })
}

// 滚动续期：空闲超时窗口内任一方向有数据搬运即不被误杀（长连接保活语义）。
func TestRelayActivityRenewsIdleTimeout(t *testing.T) {
	target := startFakeCaddy(t, nil)
	srv, stats := startSNIServer(t, Config{
		Target:           target,
		RelayIdleTimeout: 400 * time.Millisecond,
	}, fakeOriginDst("192.168.50.20", 8081))

	client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// 每 250ms 搬运一次（小于 400ms 超时），累计 1s+ 连接应仍然存活
	for i := 0; i < 4; i++ {
		if _, err := client.Write([]byte("x")); err != nil {
			t.Fatalf("write[%d]: %v", i, err)
		}
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := client.Read(make([]byte, 1)); err != nil {
			t.Fatalf("read echo[%d]（活跃连接不应被空闲超时切断）: %v", i, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	if stats.RelayIdleTimeouts.Load() != 0 {
		t.Fatal("活跃连接不应产生空闲超时计数")
	}
}

func TestShutdownForceCloseInflight(t *testing.T) {
	target := startFakeCaddy(t, nil)
	srv, stats := startServer(t, target, 16, fakeOriginDst("192.168.50.20", 8081))

	client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	waitFor(t, "在途连接建立", func() bool { return stats.ActiveConns.Load() == 1 })

	// 宽限 100ms：在途连接不结束，超时后强制断开
	srv.Shutdown(100 * time.Millisecond)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("Shutdown 宽限超时后应强制断开在途连接")
	}
	if stats.ShutdownForceCx.Load() == 0 {
		t.Fatal("应有强制断开计数")
	}
}
