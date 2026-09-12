package notify

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeSMTPServer 是最小假 SMTP 服务器（仅覆盖 security=none 明文路径）：
// 记录 MAIL FROM / RCPT TO / DATA 内容，用于验证真实 net/smtp 客户端发送路径。
type fakeSMTPServer struct {
	ln net.Listener

	mu       sync.Mutex
	mailFrom string
	rcpts    []string
	data     string
}

func newFakeSMTPServer(t *testing.T) *fakeSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeSMTPServer{ln: ln}
	go s.serve()
	t.Cleanup(func() { _ = s.ln.Close() })
	return s
}

// hostPort 拆分监听地址为主机与端口。
func (s *fakeSMTPServer) hostPort(t *testing.T) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(s.ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return host, port
}

func (s *fakeSMTPServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeSMTPServer) handle(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	write := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	write("220 localhost ESMTP fake")
	inData := false
	var dataLines []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if inData {
			if line == "." {
				inData = false
				s.mu.Lock()
				s.data = strings.Join(dataLines, "\r\n")
				s.mu.Unlock()
				write("250 2.0.0 Ok: queued")
				continue
			}
			dataLines = append(dataLines, line)
			continue
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			write("250-localhost greets")
			write("250 8BITMIME")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			addr := strings.TrimPrefix(line, "MAIL FROM:")
			if i := strings.Index(addr, " "); i >= 0 { // 剥离 BODY=8BITMIME 等参数
				addr = addr[:i]
			}
			s.mu.Lock()
			s.mailFrom = addr
			s.mu.Unlock()
			write("250 2.1.0 Ok")
		case strings.HasPrefix(upper, "RCPT TO:"):
			s.mu.Lock()
			s.rcpts = append(s.rcpts, strings.TrimPrefix(line, "RCPT TO:"))
			s.mu.Unlock()
			write("250 2.1.5 Ok")
		case upper == "DATA":
			inData = true
			dataLines = dataLines[:0]
			write("354 End data with <CR><LF>.<CR><LF>")
		case upper == "RSET", upper == "NOOP":
			write("250 2.0.0 Ok")
		case upper == "QUIT":
			write("221 2.0.0 Bye")
			return
		default:
			write("502 5.5.2 Command not recognized")
		}
	}
}

// TestSMTPSendRealOverFakeServer 走真实 net/smtp 客户端（security=none）发送到假服务器，
// 断言信封与 DATA 内容（主题 Q 编码、正文 base64 含中文类型名与本地时间）。
func TestSMTPSendRealOverFakeServer(t *testing.T) {
	srv := newFakeSMTPServer(t)
	host, port := srv.hostPort(t)
	cfg := SMTPConfig{
		Host: host, Port: port, Security: "none",
		From: "waf@example.com", To: []string{"ops@example.com", "sec@example.com"},
	}
	s := &SMTPSender{send: sendSMTPReal}
	if err := s.Send(context.Background(), cfg, renderMessage(testEvent())); err != nil {
		t.Fatalf("Send: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.mailFrom != "<waf@example.com>" {
		t.Errorf("MAIL FROM = %q, want <waf@example.com>", srv.mailFrom)
	}
	if len(srv.rcpts) != 2 || srv.rcpts[0] != "<ops@example.com>" || srv.rcpts[1] != "<sec@example.com>" {
		t.Errorf("RCPT TO = %v", srv.rcpts)
	}
	if !strings.Contains(srv.data, "Subject: =?utf-8?q?") {
		t.Errorf("DATA 缺 Q 编码主题:\n%s", srv.data)
	}
	parts := strings.SplitN(srv.data, "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Fatalf("DATA 缺空行分隔:\n%s", srv.data)
	}
	body, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(parts[1], "\r\n", ""))
	if err != nil {
		t.Fatalf("正文 base64 解码失败: %v", err)
	}
	if !strings.Contains(string(body), "网关离线（GATEWAY_DOWN）") {
		t.Errorf("正文缺少类型中文名: %s", body)
	}
	if !strings.Contains(string(body), "2026-08-18 15:00:00") {
		t.Errorf("正文时间未按 Asia/Shanghai 渲染: %s", body)
	}
}

// TestSMTPSendRealConnRefused 连接失败如实返回错误（不吞错）。
func TestSMTPSendRealConnRefused(t *testing.T) {
	// 监听后立即关闭，取得一个确定未被占用的端口（连接必被拒）
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	cfg := SMTPConfig{Host: "127.0.0.1", Port: port, Security: "none",
		From: "a@b.c", To: []string{"d@e.f"}}
	err = sendSMTPReal(cfg, []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "连接 SMTP 服务器失败") {
		t.Fatalf("应返回连接失败错误, got %v", err)
	}
}
