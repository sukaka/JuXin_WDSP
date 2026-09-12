// tace2e P1-03 G3 Envoy tap 取证端工具（仅测试用途，随取证容器运行，不进产品）：
//
//	webserver   —— HTTP/1.1 业务源站：回显 X-Rid 头、支持延迟与指定状态码；
//	grpcserver  —— gRPC 源站（raw codec，无 protoc 依赖）：Unary/ServerStream，
//	              支持元数据驱动的非零 status、trailer 注入与慢响应；
//	grpcclient  —— gRPC 客户端（经 Envoy TLS h2 入口）：unary/fail/stream/
//	              cancel/deadline 场景；
//	h2client    —— HTTP/2 多路复用客户端：单连接并发 N 流（唯一标记 + 交错延迟）；
//	wsserver    —— 手写 WebSocket 源站：/ws 握手+echo 一帧，/ws-deny 返回 403；
//	wsclient    —— 手写 WebSocket 客户端：握手、发一帧、读回显、关闭，打印状态。
//
// 红线：本工具只产生/消费合成测试流量；敏感标记均为合成字符串。
package main

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tace2e webserver|grpcserver|grpcclient|h2client|wsserver|wsclient ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "webserver":
		err = runWebserver(os.Args[2:])
	case "grpcserver":
		err = runGRPCServer(os.Args[2:])
	case "grpcclient":
		err = runGRPCClient(os.Args[2:])
	case "h2client":
		err = runH2Client(os.Args[2:])
	case "wsserver":
		err = runWSServer(os.Args[2:])
	case "wsclient":
		err = runWSClient(os.Args[2:])
	case "httpget":
		err = runHTTPGet(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand:", os.Args[1])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

// ── webserver（HTTP/1.1 业务源站） ────────────────────────

func runWebserver(args []string) error {
	fs := flag.NewFlagSet("webserver", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:18090", "回环监听")
	if err := fs.Parse(args); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if rid := r.Header.Get("X-Rid"); rid != "" {
			w.Header().Set("X-Rid", rid) // 回显配对标记（断言请求/响应不串流）
		}
		if d := r.Header.Get("X-Delay-Ms"); d != "" {
			if ms, err := strconv.Atoi(d); err == nil && ms > 0 && ms <= 10000 {
				time.Sleep(time.Duration(ms) * time.Millisecond)
			}
		}
		code := http.StatusOK
		if s := r.Header.Get("X-Origin-Status"); s != "" {
			if c, err := strconv.Atoi(s); err == nil && c >= 100 && c <= 599 {
				code = c
			}
		}
		n, _ := io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"ok":true,"path":%q,"recv":%d}`, r.URL.Path, n)
	})
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	if ta, ok := ln.Addr().(*net.TCPAddr); !ok || !ta.IP.IsLoopback() {
		ln.Close()
		return fmt.Errorf("webserver 仅允许回环监听: %s", *listen)
	}
	log.Printf("webserver 就绪 %s", ln.Addr())
	return (&http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}).Serve(ln)
}

// ── gRPC（raw codec，免 protoc） ─────────────────────────

type rawMsg struct{ data []byte }

type rawCodec struct{}

func (rawCodec) Name() string                  { return "raw" }
func (rawCodec) Marshal(v any) ([]byte, error) { return v.(*rawMsg).data, nil }
func (rawCodec) Unmarshal(data []byte, v any) error {
	*v.(*rawMsg) = rawMsg{data: data}
	return nil
}

func init() { encoding.RegisterCodec(rawCodec{}) }

type echoAPI interface{}

var echoDesc = grpc.ServiceDesc{
	ServiceName: "test.Echo",
	HandlerType: (*echoAPI)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Unary", Handler: unaryHandler},
	},
	Streams: []grpc.StreamDesc{
		{StreamName: "ServerStream", Handler: serverStreamHandler, ServerStreams: true},
	},
}

func unaryHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	m := &rawMsg{}
	if err := dec(m); err != nil {
		return nil, err
	}
	md, _ := metadata.FromIncomingContext(ctx)
	if fc := md.Get("fail-code"); len(fc) > 0 {
		if n, err := strconv.Atoi(fc[0]); err == nil {
			// 注入 trailer（含合成敏感标记，验证 trailer 脱敏出口）
			grpc.SetTrailer(ctx, metadata.Pairs("set-cookie", "plain-trailer-secret-s3", "x-note", "fail-path"))
			return nil, status.Error(codes.Code(n), "synthetic-rpc-failure")
		}
	}
	grpc.SetTrailer(ctx, metadata.Pairs("x-note", "unary-ok"))
	return &rawMsg{data: m.data}, nil
}

func serverStreamHandler(srv any, stream grpc.ServerStream) error {
	m := &rawMsg{}
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	md, _ := metadata.FromIncomingContext(stream.Context())
	count, delayMs := 3, 100
	if v := md.Get("stream-count"); len(v) > 0 {
		if n, err := strconv.Atoi(v[0]); err == nil && n > 0 && n <= 10 {
			count = n
		}
	}
	if v := md.Get("stream-delay-ms"); len(v) > 0 {
		if n, err := strconv.Atoi(v[0]); err == nil && n >= 0 && n <= 10000 {
			delayMs = n
		}
	}
	for i := 0; i < count; i++ {
		if delayMs > 0 {
			select {
			case <-stream.Context().Done():
				return stream.Context().Err()
			case <-time.After(time.Duration(delayMs) * time.Millisecond):
			}
		}
		if err := stream.SendMsg(&rawMsg{data: []byte(fmt.Sprintf("stream-msg-%d", i))}); err != nil {
			return err
		}
	}
	stream.SetTrailer(metadata.Pairs("x-note", "stream-done"))
	return nil
}

func runGRPCServer(args []string) error {
	fs := flag.NewFlagSet("grpcserver", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:18091", "回环 h2c 监听")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	if ta, ok := ln.Addr().(*net.TCPAddr); !ok || !ta.IP.IsLoopback() {
		ln.Close()
		return fmt.Errorf("grpcserver 仅允许回环监听: %s", *listen)
	}
	srv := grpc.NewServer(grpc.ForceServerCodec(rawCodec{}))
	srv.RegisterService(&echoDesc, struct{}{})
	log.Printf("grpcserver 就绪 %s", ln.Addr())
	return srv.Serve(ln)
}

func runGRPCClient(args []string) error {
	fs := flag.NewFlagSet("grpcclient", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8443", "Envoy TLS h2 入口")
	mode := fs.String("mode", "unary", "unary|fail|stream|cancel|deadline")
	rid := fs.String("rid", "grpc-x", "业务标记")
	serverName := fs.String("servername", "envoy-tap-e2e.local", "TLS SNI")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cred := credentials.NewTLS(&tls.Config{InsecureSkipVerify: true, ServerName: *serverName})
	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(cred),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})))
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx := context.Background()
	md := metadata.Pairs("x-rid", *rid)
	switch *mode {
	case "fail":
		md = metadata.Join(md, metadata.Pairs("fail-code", "3"))
	case "deadline":
		md = metadata.Join(md, metadata.Pairs("stream-count", "5", "stream-delay-ms", "2000"))
	}
	ctx = metadata.NewOutgoingContext(ctx, md)

	switch *mode {
	case "unary", "fail":
		out := &rawMsg{}
		err := conn.Invoke(ctx, "/test.Echo/Unary", &rawMsg{data: []byte("ping-" + *rid)}, out)
		if err != nil {
			st, _ := status.FromError(err)
			fmt.Printf("rid=%s rpc_error code=%d (%s)\n", *rid, st.Code(), st.Message())
			if *mode == "fail" && st.Code() == codes.InvalidArgument {
				return nil
			}
			return fmt.Errorf("unary 非预期失败: %v", err)
		}
		fmt.Printf("rid=%s unary ok resp=%q\n", *rid, out.data)
		return nil
	case "stream", "cancel", "deadline":
		if *mode == "deadline" {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, 300*time.Millisecond)
			defer cancel()
		}
		cancel := func() {}
		if *mode == "cancel" {
			ctx, cancel = context.WithCancel(ctx)
		}
		defer cancel()
		stream, err := conn.NewStream(ctx, &grpc.StreamDesc{StreamName: "ServerStream", ServerStreams: true},
			"/test.Echo/ServerStream")
		if err != nil {
			return err
		}
		if err := stream.SendMsg(&rawMsg{data: []byte("open-" + *rid)}); err != nil {
			return err
		}
		recv := 0
		for {
			m := &rawMsg{}
			err := stream.RecvMsg(m)
			if err != nil {
				st, _ := status.FromError(err)
				fmt.Printf("rid=%s stream end recv=%d err_code=%d (%v)\n", *rid, recv, st.Code(), err)
				switch *mode {
				case "stream":
					if err == io.EOF && recv == 3 {
						return nil
					}
					return fmt.Errorf("stream 非预期结束: %v", err)
				case "cancel":
					return nil // 取消后 Recv 报错即符合预期
				case "deadline":
					if st.Code() == codes.DeadlineExceeded {
						return nil
					}
					return fmt.Errorf("deadline 非预期: %v", err)
				}
			}
			recv++
			fmt.Printf("rid=%s stream msg %q\n", *rid, m.data)
			if *mode == "cancel" && recv == 1 {
				cancel() // 收到首条消息后立即取消
				time.Sleep(300 * time.Millisecond)
			}
		}
	}
	return fmt.Errorf("未知 mode %q", *mode)
}

// ── h2client（HTTP/2 多路复用） ──────────────────────────

func runH2Client(args []string) error {
	fs := flag.NewFlagSet("h2client", flag.ContinueOnError)
	base := fs.String("base", "https://envoy-tap-e2e.local:8443", "入口 base URL")
	n := fs.Int("n", 6, "并发流数")
	dial := fs.String("dial", "127.0.0.1:8443", "实际拨号地址（SNI/Host 与 base 一致）")
	bodyBytes := fs.Int("body-bytes", 100, "每流正文字节数（text/plain）")
	ridPrefix := fs.String("rid", "h2", "业务标记前缀（-n 1 时直接用该值）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	hostPort := strings.TrimPrefix(strings.TrimPrefix(*base, "https://"), "http://")
	host, _, _ := net.SplitHostPort(hostPort)
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host, NextProtos: []string{"h2"}},
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			d := &net.Dialer{Timeout: 5 * time.Second}
			c, err := d.DialContext(ctx, network, *dial)
			if err != nil {
				return nil, err
			}
			tlsCfg := cfg.Clone()
			tlsCfg.ServerName = host
			tc := tls.Client(c, tlsCfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				c.Close()
				return nil, err
			}
			if tc.ConnectionState().NegotiatedProtocol != "h2" {
				tc.Close()
				return nil, fmt.Errorf("ALPN 未协商 h2: %q", tc.ConnectionState().NegotiatedProtocol)
			}
			return tc, nil
		},
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	var wg sync.WaitGroup
	errs := make([]error, *n)
	for i := 0; i < *n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rid := fmt.Sprintf("%s-%d", *ridPrefix, i)
			if *n == 1 {
				rid = *ridPrefix
			}
			// 交错延迟：强制多流在同一连接上并发在途
			delay := (i % 3) * 300
			req, err := http.NewRequest("POST",
				fmt.Sprintf("%s/h2mux?rid=%s&token=plain-h2tok-%d", *base, rid, i),
				strings.NewReader(fmt.Sprintf("body-%s-%s", rid, strings.Repeat("d", *bodyBytes))))
			if err != nil {
				errs[i] = err
				return
			}
			req.Header.Set("Content-Type", "text/plain")
			req.Header.Set("X-Rid", rid)
			req.Header.Set("X-Delay-Ms", strconv.Itoa(delay))
			resp, err := client.Do(req)
			if err != nil {
				errs[i] = err
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != 200 || resp.Header.Get("X-Rid") != rid {
				errs[i] = fmt.Errorf("%s: status=%d x-rid=%q", rid, resp.StatusCode, resp.Header.Get("X-Rid"))
				return
			}
			fmt.Printf("rid=%s status=200 x-rid=%s proto=%s\n", rid, resp.Header.Get("X-Rid"), resp.Proto)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// runHTTPGet 明文 HTTP/1.1 GET 业务探针（打印状态码；Envoy 明文入口用）。
func runHTTPGet(args []string) error {
	fs := flag.NewFlagSet("httpget", flag.ContinueOnError)
	url := fs.String("url", "http://127.0.0.1:8080/healthz", "URL")
	rid := fs.String("rid", "", "X-Rid 业务标记")
	if err := fs.Parse(args); err != nil {
		return err
	}
	req, err := http.NewRequest("GET", *url, nil)
	if err != nil {
		return err
	}
	if *rid != "" {
		req.Header.Set("X-Rid", *rid)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	fmt.Printf("rid=%s status=%d\n", *rid, resp.StatusCode)
	return nil
}

// ── WebSocket（手写握手 + 单帧 echo） ────────────────────

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

func runWSServer(args []string) error {
	fs := flag.NewFlagSet("wsserver", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:18092", "回环监听")
	if err := fs.Parse(args); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "bad upgrade", 400)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", 500)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			wsAccept(r.Header.Get("Sec-WebSocket-Key")))
		buf.Flush()
		// 读一帧并 echo，然后等待关闭
		frame, err := wsReadFrame(buf)
		if err == nil {
			wsWriteFrame(conn, frame)
		}
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		for {
			if _, err := wsReadFrame(buf); err != nil {
				return
			}
		}
	})
	mux.HandleFunc("/ws-deny", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", 403)
	})
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	if ta, ok := ln.Addr().(*net.TCPAddr); !ok || !ta.IP.IsLoopback() {
		ln.Close()
		return fmt.Errorf("wsserver 仅允许回环监听: %s", *listen)
	}
	log.Printf("wsserver 就绪 %s", ln.Addr())
	return (&http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}).Serve(ln)
}

// wsReadFrame 读一个 WS 帧（仅文本/关闭；分片帧不支持——取证单帧足够）。
func wsReadFrame(buf io.Reader) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(buf, hdr); err != nil {
		return nil, err
	}
	masked := hdr[1]&0x80 != 0
	ln := int(hdr[1] & 0x7f)
	if ln == 126 {
		ext := make([]byte, 2)
		if _, err := io.ReadFull(buf, ext); err != nil {
			return nil, err
		}
		ln = int(binary.BigEndian.Uint16(ext))
	}
	if ln > 1<<20 {
		return nil, fmt.Errorf("帧过大")
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(buf, mask[:]); err != nil {
			return nil, err
		}
	}
	payload := make([]byte, ln)
	if _, err := io.ReadFull(buf, payload); err != nil {
		return nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return payload, nil
}

func wsWriteFrame(w io.Writer, payload []byte) {
	hdr := []byte{0x81} // FIN + text
	if len(payload) < 126 {
		hdr = append(hdr, byte(len(payload)))
	} else {
		hdr = append(hdr, 126, byte(len(payload)>>8), byte(len(payload)))
	}
	w.Write(hdr)
	w.Write(payload)
}

func runWSClient(args []string) error {
	fs := flag.NewFlagSet("wsclient", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "Envoy 明文入口")
	path := fs.String("path", "/ws", "握手路径")
	host := fs.String("host", "envoy-tap-e2e.local", "Host 头")
	frameText := fs.String("frame", "", "握手成功后发送的文本帧（空=不发）")
	rid := fs.String("rid", "ws-x", "业务标记")
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", *addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	key := base64.StdEncoding.EncodeToString([]byte(*rid + "-key-1234"))
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nX-Rid: %s\r\nAuthorization: Bearer plain-ws-secret\r\n\r\n",
		*path, *host, key, *rid)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	// 读状态行与响应头
	statusLine, headers, reader, err := wsReadHandshake(conn)
	if err != nil {
		return err
	}
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return fmt.Errorf("非法状态行: %q", statusLine)
	}
	code, _ := strconv.Atoi(parts[1])
	fmt.Printf("rid=%s handshake_status=%d accept=%q\n", *rid, code, headers["sec-websocket-accept"])
	if code != 101 {
		io.Copy(io.Discard, reader)
		return nil // 失败握手同样为有效场景（如 403）
	}
	if headers["sec-websocket-accept"] != wsAccept(key) {
		return fmt.Errorf("accept 校验失败")
	}
	if *frameText != "" {
		// 客户端帧必须掩码
		payload := []byte(*frameText)
		mask := [4]byte{0x12, 0x34, 0x56, 0x78}
		hdr := []byte{0x81, byte(0x80 | len(payload))}
		conn.Write(hdr)
		conn.Write(mask[:])
		mp := make([]byte, len(payload))
		for i := range payload {
			mp[i] = payload[i] ^ mask[i%4]
		}
		conn.Write(mp)
		echo, err := wsReadFrame(reader)
		if err != nil {
			return fmt.Errorf("读回显失败: %w", err)
		}
		fmt.Printf("rid=%s echoed=%q\n", *rid, echo)
	}
	return nil
}

// wsReadHandshake 读取 HTTP 握手响应（状态行 + 头），返回带缓冲的 reader。
func wsReadHandshake(conn net.Conn) (string, map[string]string, io.Reader, error) {
	br := &wsBufReader{r: conn, buf: nil}
	line, err := br.readLine()
	if err != nil {
		return "", nil, nil, err
	}
	headers := map[string]string{}
	for {
		l, err := br.readLine()
		if err != nil {
			return "", nil, nil, err
		}
		if l == "" {
			break
		}
		k, v, _ := strings.Cut(l, ":")
		headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return line, headers, br, nil
}

type wsBufReader struct {
	r   net.Conn
	buf []byte
}

func (b *wsBufReader) Read(p []byte) (int, error) {
	if len(b.buf) > 0 {
		n := copy(p, b.buf)
		b.buf = b.buf[n:]
		return n, nil
	}
	return b.r.Read(p)
}

func (b *wsBufReader) readLine() (string, error) {
	var line []byte
	one := make([]byte, 1)
	for {
		n, err := b.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				return strings.TrimRight(string(line), "\r"), nil
			}
			line = append(line, one[0])
			if len(line) > 8192 {
				return "", fmt.Errorf("头行过长")
			}
		}
		if err != nil {
			return "", err
		}
	}
}
