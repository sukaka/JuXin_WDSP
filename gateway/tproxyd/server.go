// 牵引服务：accept 循环、SO_ORIGINAL_DST 解析、PROXY v1 头上报、双向透传、
// 并发上限背压与优雅退出。串接在数据通路上，任何异常都必须可计数、可观测。
package tproxyd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// resolveDstFunc 解析连接原始目的地址（生产为 SO_ORIGINAL_DST；测试可注入桩）。
type resolveDstFunc func(conn *net.TCPConn) (*net.TCPAddr, error)

// dialContextFunc 拨号上游（生产为 net.Dialer.DialContext；测试可注入桩）。
type dialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// isTimeoutErr 判定错误链中是否含网络读超时（嗅探读超时场景）。
func isTimeoutErr(err error) bool {
	return errors.Is(err, os.ErrDeadlineExceeded)
}

// Server 牵引服务。
type Server struct {
	cfg                Config
	stats              *Stats
	ln                 *net.TCPListener
	sem                chan struct{} // 并发连接上限令牌（背压护栏）
	resolveDst         resolveDstFunc
	dialContext        dialContextFunc
	protectMatcher     *hostMatcher // SNI 防护域名匹配器（nil = 功能关闭）
	passthroughMatcher *hostMatcher // 显式允许端到端透传的 SNI 白名单匹配器（nil = 禁止未列明 SNI 透传）
	localAddrs         func() ([]net.IP, error)

	ctx         context.Context
	cancel      context.CancelFunc
	closing     atomic.Bool
	wg          sync.WaitGroup
	mu          sync.Mutex
	closed      bool                  // mu 保护：与 wg.Add(1) 互斥，防止 Shutdown 后并发 wg.Add 竞态
	forceClosed bool                  // mu 保护：宽限超时强制断连后拒绝新登记连接
	conns       map[net.Conn]struct{} // 在途连接（两端均登记，供优雅退出强制断开）
}

// NewServer 绑定监听地址并返回服务（失败直接返回错误，不静默降级）。
func NewServer(cfg Config, stats *Stats) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	addr, err := net.ResolveTCPAddr("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("TPROXY_LISTEN 解析失败: %w", err)
	}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("监听 %s 失败: %w", cfg.Listen, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	dialer := &net.Dialer{Timeout: cfg.DialTimeout}
	return &Server{
		cfg:                cfg,
		stats:              stats,
		ln:                 ln,
		sem:                make(chan struct{}, cfg.MaxConns),
		resolveDst:         originalDst,
		dialContext:        dialer.DialContext,
		protectMatcher:     cfg.protectHostMatcher(),
		passthroughMatcher: cfg.passthroughHostMatcher(),
		localAddrs:         defaultLocalAddrs,
		ctx:                ctx,
		cancel:             cancel,
		conns:              make(map[net.Conn]struct{}),
	}, nil
}

// defaultLocalAddrs 枚举本机所有接口的 IP 地址，用于识别指向本机监听端口的自连环路。
func defaultLocalAddrs() ([]net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			if v.IP != nil {
				ips = append(ips, v.IP)
			}
		case *net.IPAddr:
			if v.IP != nil {
				ips = append(ips, v.IP)
			}
		}
	}
	return ips, nil
}

// isLocalInterfaceIP 判定给定 IP 是否属于本机任意网络接口；查询失败时按 fail-closed 视为本机。
func (s *Server) isLocalInterfaceIP(ip net.IP) bool {
	fn := s.localAddrs
	if fn == nil {
		fn = defaultLocalAddrs
	}
	ips, err := fn()
	if err != nil {
		return true
	}
	for _, local := range ips {
		if local.Equal(ip) {
			return true
		}
	}
	return false
}

// isLocalPassthroughIP 判定透传目标 IP 是否指向本机（回环、未指定或任意本机接口 IP）。
// 透传路径按原始目的直连，对所有端口禁止指向本机，防止借透传白名单绕过本地防火墙/访问控制台等 SSRF。
func (s *Server) isLocalPassthroughIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	return s.isLocalInterfaceIP(ip)
}

// isSelfTarget 判定原始目的地址是否指向 tproxyd 自身监听地址/端口（或任意本机接口 IP 的
// tproxyd 监听端口），在任何拨号之前拒绝，杜绝自连环路 DoS 与非 REDIRECT 直连。
func (s *Server) isSelfTarget(orig *net.TCPAddr, localAddr net.Addr) bool {
	if orig == nil || orig.IP == nil || orig.Port <= 0 {
		return true
	}
	if localTCP, ok := localAddr.(*net.TCPAddr); ok && localTCP.Port == orig.Port && localTCP.IP.Equal(orig.IP) {
		return true
	}
	listenTCP, ok := s.ln.Addr().(*net.TCPAddr)
	if !ok || orig.Port != listenTCP.Port {
		return false
	}
	if orig.IP.IsUnspecified() || orig.IP.IsLoopback() {
		return true
	}
	if listenTCP.IP != nil && !listenTCP.IP.IsUnspecified() && orig.IP.Equal(listenTCP.IP) {
		return true
	}
	return s.isLocalInterfaceIP(orig.IP)
}

// Addr 实际监听地址（测试取动态端口用）。
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Serve accept 主循环；Shutdown 关闭监听后返回 nil。
func (s *Server) Serve() error {
	for {
		conn, err := s.ln.AcceptTCP()
		if err != nil {
			if s.closing.Load() {
				return nil
			}
			// accept 异常（句柄耗尽等）：计数并短暂退避重试，不退出主循环
			s.stats.AcceptErrors.Add(1)
			log.Printf("[tproxyd] accept 异常（重试）: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		// 背压护栏：达到并发上限立即关闭新连接（快速失败，防内存/句柄失控）
		select {
		case s.sem <- struct{}{}:
		default:
			s.stats.ConnRejected.Add(1)
			_ = conn.Close()
			continue
		}
		// 原子化登记连接与 wg.Add(1)：与 Shutdown 的 closed 标记经 s.mu 互斥，
		// 彻底杜绝 Serve 调用 wg.Add(1) 与 Shutdown 调用 wg.Wait() 的数据竞争。
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			<-s.sem
			_ = conn.Close()
			return nil
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()

		s.stats.ConnAccepted.Add(1)
		s.stats.ActiveConns.Add(1)
		go s.serveConn(conn)
	}
}

// serveConn 单连接生命周期：解析原始目的 →（可选）SNI 嗅探分流 → 连下游 →
// （按需）写 PROXY 头 → 双向透传。
func (s *Server) serveConn(client *net.TCPConn) {
	defer func() {
		<-s.sem
		s.untrack(client)
		_ = client.Close()
		s.stats.ActiveConns.Add(-1)
		s.wg.Done()
	}()

	src, ok := client.RemoteAddr().(*net.TCPAddr)
	if !ok {
		log.Printf("[tproxyd] 对端地址类型异常: %T", client.RemoteAddr())
		return
	}
	orig, err := s.resolveDst(client)
	if err != nil {
		s.stats.OrigDstErrors.Add(1)
		log.Printf("[tproxyd] 原始目的解析失败 src=%s: %v", src, err)
		return
	}
	if s.isSelfTarget(orig, client.LocalAddr()) {
		s.stats.OrigDstErrors.Add(1)
		log.Printf("[tproxyd] 拒绝指向本机监听端口的原始目的（防自连环路） src=%s orig=%s listen=%s", src, orig, s.Addr())
		return
	}

	// SNI 嗅探分流（ProtectHosts 为空时功能关闭，走原路径零开销）：
	//   TLS + SNI∈ProtectHosts → TargetTLS（Caddy 终结检测）；
	//   TLS + SNI∈PassthroughAllowlist → 按原始目的透传（端到端 TLS）；
	//   TLS + 未列明 SNI → fail-closed 倒向 TargetTLS（防绕过）；
	//   明文 HTTP → Target；解析失败 → 倒向 TargetTLS（防绕过）；
	//   嗅探读超时 → 关连接（防空闲占用）。
	upstream := s.cfg.Target
	sendProxy := true
	var br *bufio.Reader
	if s.cfg.sniDispatchEnabled() {
		br = bufio.NewReaderSize(client, sniffBufSize)
		_ = client.SetReadDeadline(time.Now().Add(s.cfg.SniffTimeout))
		sni, isTLS, sniffErr := peekClientHelloSNI(br)
		_ = client.SetReadDeadline(time.Time{})
		switch {
		case sniffErr != nil && isTimeoutErr(sniffErr):
			s.stats.SniffTimeouts.Add(1)
			log.Printf("[tproxyd] SNI 嗅探读超时 src=%s orig=%s，关闭连接", src, orig)
			return
		case sniffErr != nil && errors.Is(sniffErr, errNotTLS):
			// 明文 HTTP：维持原 Target 路径
		case sniffErr != nil && !isTLS && (errors.Is(sniffErr, io.EOF) || errors.Is(sniffErr, io.ErrUnexpectedEOF)):
			// 对端在发送满 5 字节 record 头前即断开（如 TCP 探活/空连接）：安静关闭，不拨号 TargetTLS
			return
		case sniffErr != nil:
			s.stats.SniffErrors.Add(1)
			upstream = s.cfg.TargetTLS
			log.Printf("[tproxyd] ClientHello 解析失败 src=%s orig=%s，倒向 TLS 检测路径: %v", src, orig, sniffErr)
		case isTLS && s.protectMatcher.match(sni):
			upstream = s.cfg.TargetTLS
			s.stats.ConnsProtected.Add(1)
		case isTLS && s.passthroughMatcher.match(sni):
			// 透传路径禁止指向本机任意地址与端口（防本地服务 SSRF / 控制台绕过）
			if s.isLocalPassthroughIP(orig.IP) {
				s.stats.OrigDstErrors.Add(1)
				log.Printf("[tproxyd] 拒绝透传指向本机地址的原始目的 src=%s orig=%s sni=%q", src, orig, sni)
				return
			}
			// 仅显式列入透传白名单的域名允许按原始目的透传（TLS 端到端，不可注入 PROXY 头）
			upstream = orig.String()
			sendProxy = false
			s.stats.ConnsPassthrough.Add(1)
		case isTLS:
			// 未列明 SNI 默认 fail-closed 倒向 TLS 检测路径，禁止任意域名绕过 WAF 直通原始目的
			upstream = s.cfg.TargetTLS
			s.stats.ConnsUnlistedTLS.Add(1)
			log.Printf("[tproxyd] 未列明 SNI %q 不在透传白名单 src=%s orig=%s，倒向 TLS 检测路径", sni, src, orig)
		}
	}

	dialFn := s.dialContext
	if dialFn == nil {
		dialFn = (&net.Dialer{Timeout: s.cfg.DialTimeout}).DialContext
	}
	dialCtx, dialCancel := context.WithTimeout(s.ctx, s.cfg.DialTimeout)
	target, err := dialFn(dialCtx, "tcp", upstream)
	dialCancel()
	if err != nil {
		s.stats.DialErrors.Add(1)
		log.Printf("[tproxyd] 连接下游 %s 失败 src=%s orig=%s: %v", upstream, src, orig, err)
		return
	}
	tc, ok := target.(*net.TCPConn)
	if !ok {
		_ = target.Close()
		log.Printf("[tproxyd] 下游连接类型异常: %T", target)
		return
	}
	if !s.track(tc) {
		_ = tc.Close()
		return
	}
	defer func() {
		s.untrack(tc)
		_ = tc.Close()
	}()

	if sendProxy {
		hdr, err := BuildProxyV1Header(src, orig)
		if err != nil {
			s.stats.HeaderErrors.Add(1)
			log.Printf("[tproxyd] PROXY 头构造失败 src=%s orig=%s: %v", src, orig, err)
			return
		}
		// PROXY 头必须先于任何业务字节到达下游（Caddy listener wrapper 首行读取）
		_ = tc.SetWriteDeadline(time.Now().Add(s.cfg.DialTimeout))
		if _, err := tc.Write(hdr); err != nil {
			s.stats.HeaderErrors.Add(1)
			log.Printf("[tproxyd] PROXY 头写入失败 src=%s orig=%s: %v", src, orig, err)
			return
		}
		_ = tc.SetWriteDeadline(time.Time{})
	}

	s.relay(client, br, tc)
}

// renewOnWrite 透传写侧包装：每次成功写入即回调续期（滚动空闲超时的活动信号）。
// 注意：有意不内嵌 *net.TCPConn（内嵌会把 ReadFrom 方法提升上来，io.Copy 命中
// ReadFrom 后绕过 Write 钩子）；同时包装后 io.Copy 不再命中 *net.TCPConn 特化
// （splice 零拷贝），改走带缓冲拷贝（32KB）——以一次用户态拷贝换取续期钩子，
// 是空闲护栏的必要代价。
type renewOnWrite struct {
	conn  *net.TCPConn
	renew func()
}

func (w renewOnWrite) Write(p []byte) (int, error) {
	n, err := w.conn.Write(p)
	if n > 0 {
		w.renew()
	}
	return n, err
}

// relay 双向透传：先把嗅探缓冲的前置字节写往上游（保持字节流完整），再做双向拷贝，
// 半关闭语义双向传播。
// 空闲护栏（HIGH-13）：relay 期间滚动维护两端读写 deadline（任一方向每搬运一块
// 数据即续期 RelayIdleTimeout）；两端静默超时的读/写返回超时错误终止拷贝，连接
// 随后关闭并释放并发令牌——攻击者无法用空闲/不读不写的连接占满 MaxConns 造成
// 整体拒连。写 deadline 同属必需：对端只收不读（接收窗口归零）时写侧阻塞同样
// 会在超时后被解除。
func (s *Server) relay(client *net.TCPConn, br *bufio.Reader, tc *net.TCPConn) {
	// 节流续期：最多每 min(RelayIdleTimeout/4, 1s) 调用一次 SetDeadline，避免每 32KB 块触发两次系统调用
	minRenewInterval := s.cfg.RelayIdleTimeout / 4
	if minRenewInterval > time.Second {
		minRenewInterval = time.Second
	}
	var lastRenew atomic.Int64
	renew := func() {
		now := time.Now()
		nowNS := now.UnixNano()
		prev := lastRenew.Load()
		if prev != 0 && nowNS-prev < int64(minRenewInterval) {
			return
		}
		if prev != 0 && !lastRenew.CompareAndSwap(prev, nowNS) {
			return
		}
		if prev == 0 {
			lastRenew.Store(nowNS)
		}
		deadline := now.Add(s.cfg.RelayIdleTimeout)
		_ = client.SetDeadline(deadline)
		_ = tc.SetDeadline(deadline)
	}
	renew()
	done := make(chan struct{})
	var c2tErr error
	go func() {
		var n int64
		dst := renewOnWrite{conn: tc, renew: renew}
		if br != nil && br.Buffered() > 0 {
			// 仅限已缓冲字节（不会触碰底层连接），随后裸连接续传
			m, err := io.CopyN(dst, br, int64(br.Buffered()))
			n += m
			if err == nil {
				m, err = io.Copy(dst, client) // 客户端 → 上游
				n += m
			}
			c2tErr = err
		} else {
			m, err := io.Copy(dst, client)
			n, c2tErr = m, err
		}
		s.stats.BytesToTarget.Add(uint64(n))
		_ = tc.CloseWrite()
		close(done)
	}()
	t2cN, t2cErr := io.Copy(renewOnWrite{conn: client, renew: renew}, tc) // 上游 → 客户端
	s.stats.BytesToClient.Add(uint64(t2cN))
	_ = client.CloseWrite()
	<-done
	// 空闲超时（对端正常关闭/强制断开为常规路径不计）：显式计数便于观测
	if isTimeoutErr(t2cErr) || isTimeoutErr(c2tErr) {
		s.stats.RelayIdleTimeouts.Add(1)
		log.Printf("[tproxyd] 透传空闲超时，关闭连接 src=%s", client.RemoteAddr())
	}
}

// Shutdown 优雅退出：先在锁内标记 closed 并关闭监听（保证不再有新 wg.Add(1)），
// 再在宽限期内等待在途连接结束，超时则取消在途拨号并强制断开剩余连接。
func (s *Server) Shutdown(grace time.Duration) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.closing.Store(true)
	s.mu.Unlock()

	_ = s.ln.Close()

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		s.cancel()
		return
	case <-time.After(grace):
	}
	// 宽限超时：取消在途拨号上下文，并强制断开在途连接（两端均关，解除双向 io.Copy 阻塞）
	s.cancel()
	forced := 0
	s.mu.Lock()
	s.forceClosed = true
	for c := range s.conns {
		_ = c.Close()
		forced++
	}
	s.mu.Unlock()
	s.stats.ShutdownForceCx.Add(uint64(forced))
	<-done
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.forceClosed {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}
