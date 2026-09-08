// Package httpparse HTTP/1.x 请求行+Host 轻量嗅探与 TLS ClientHello 识别。
//
// 设计依据：契约 §3.4 tls_visibility 与设计 §11.4。
//   - 仅嗅探 client→server 方向首段 payload（上限 16KB），不读 Body；
//   - 解析出合法 HTTP/1.x 请求行（METHOD SP URI SP HTTP/1.x）→ PLAINTEXT，
//     提取 method/uri 与 Host 头；
//   - 首字节 0x16 且 TLS record 版本 0x03xx → ENCRYPTED（仅标记，绝不解密）；
//   - 其余 → UNKNOWN；
//   - 分片由调用方按序 Feed 累积处理。
package httpparse

import (
	"bytes"
)

// 可见性枚举（契约 §3.4）。
const (
	Plaintext = "PLAINTEXT"
	Encrypted = "ENCRYPTED"
	Unknown   = "UNKNOWN"
)

// MaxSniffBytes 嗅探缓冲上限（契约 §6：不采集 Body，仅头部嗅探）。
const MaxSniffBytes = 16 << 10

// Result 嗅探结论。
type Result struct {
	Visibility string // PLAINTEXT | ENCRYPTED | UNKNOWN
	Method     string // 仅 PLAINTEXT 有效
	Host       string
	URI        string
}

// Sniffer 单流 client→server 方向首段 payload 嗅探器（非并发安全，由 flow 层串行调用）。
type Sniffer struct {
	buf     []byte
	max     int
	decided bool
	res     Result
}

// NewSniffer 创建嗅探器；max<=0 或超上限按 MaxSniffBytes 处理。
func NewSniffer(max int) *Sniffer {
	if max <= 0 || max > MaxSniffBytes {
		max = MaxSniffBytes
	}
	return &Sniffer{max: max}
}

// Decided 是否已得出结论。
func (s *Sniffer) Decided() bool { return s.decided }

// Result 返回当前结论（未决定时 Visibility 为空）。
func (s *Sniffer) Result() Result { return s.res }

// Feed 按序喂入 payload 字节；返回 true 表示已得出结论（此后无需再 Feed）。
func (s *Sniffer) Feed(data []byte) bool {
	if s.decided {
		return true
	}
	if room := s.max - len(s.buf); room > 0 {
		if len(data) > room {
			data = data[:room]
		}
		s.buf = append(s.buf, data...)
	}
	if len(s.buf) == 0 {
		return false
	}
	s.decided = s.classify()
	if s.decided {
		s.buf = nil // 决策后立即释放嗅探缓冲（最高 16KB），不随流常驻到驱逐
	}
	return s.decided
}

// classify 尝试对当前缓冲得出结论；证据不足返回 false 继续等待。
func (s *Sniffer) classify() bool {
	b := s.buf
	// TLS ClientHello：record type 0x16（handshake）+ 版本 0x03 0x00~0x04
	if b[0] == 0x16 {
		if len(b) < 3 {
			return false
		}
		if b[1] == 0x03 && b[2] <= 0x04 {
			s.res = Result{Visibility: Encrypted}
		} else {
			s.res = Result{Visibility: Unknown}
		}
		return true
	}
	// HTTP 方法首字符必为大写字母；否则非 HTTP/1.x 明文
	if b[0] < 'A' || b[0] > 'Z' {
		s.res = Result{Visibility: Unknown}
		return true
	}
	return s.classifyHTTP()
}

// classifyHTTP 尝试按 HTTP/1.x 解析；缓冲满仍无法定论按 UNKNOWN 收尾。
func (s *Sniffer) classifyHTTP() bool {
	b := s.buf
	lineEnd := bytes.Index(b, []byte("\r\n"))
	if lineEnd < 0 {
		if len(b) >= s.max {
			s.res = Result{Visibility: Unknown}
			return true
		}
		return false // 请求行未完整
	}
	method, uri, ok := parseRequestLine(string(b[:lineEnd]))
	if !ok {
		s.res = Result{Visibility: Unknown}
		return true
	}
	// 请求行合法即定 PLAINTEXT；Host 头尽力提取（等到头部块结束或缓冲满）。
	host, headerDone := findHost(b[lineEnd+2:])
	if !headerDone && host == "" && len(b) < s.max {
		// 继续等待 Host 头出现或头部结束
		if !hasHeaderTerminator(b) {
			return false
		}
	}
	s.res = Result{Visibility: Plaintext, Method: method, Host: host, URI: uri}
	return true
}

// parseRequestLine 解析 "METHOD SP URI SP HTTP/1.x"。
func parseRequestLine(line string) (method, uri string, ok bool) {
	sp1 := 0
	for sp1 < len(line) && line[sp1] != ' ' {
		c := line[sp1]
		if c < 'A' || c > 'Z' {
			return "", "", false // 方法必须为全大写字母
		}
		sp1++
	}
	if sp1 < 2 || sp1 > 20 || sp1 >= len(line) {
		return "", "", false
	}
	rest := line[sp1+1:]
	sp2 := -1
	for i := 0; i < len(rest); i++ {
		if rest[i] == ' ' {
			sp2 = i
			break
		}
	}
	if sp2 <= 0 {
		return "", "", false
	}
	uri = rest[:sp2]
	version := rest[sp2+1:]
	if len(version) != 8 || version[:7] != "HTTP/1." || version[7] < '0' || version[7] > '9' {
		return "", "", false
	}
	return line[:sp1], uri, true
}

// findHost 在头部块中查找 Host 头；done 表示已遇到头部结束标记。
func findHost(headers []byte) (host string, done bool) {
	for len(headers) > 0 {
		idx := bytes.Index(headers, []byte("\r\n"))
		if idx < 0 {
			return "", false // 行未完整
		}
		if idx == 0 {
			return "", true // 空行：头部结束
		}
		line := headers[:idx]
		if len(line) >= 5 && (line[0] == 'H' || line[0] == 'h') &&
			(line[1] == 'o' || line[1] == 'O') &&
			(line[2] == 's' || line[2] == 'S') &&
			(line[3] == 't' || line[3] == 'T') && line[4] == ':' {
			v := line[5:]
			for len(v) > 0 && (v[0] == ' ' || v[0] == '\t') {
				v = v[1:]
			}
			for len(v) > 0 && (v[len(v)-1] == ' ' || v[len(v)-1] == '\t') {
				v = v[:len(v)-1]
			}
			return string(v), false
		}
		headers = headers[idx+2:]
	}
	return "", false
}

func hasHeaderTerminator(b []byte) bool {
	return bytes.Contains(b, []byte("\r\n\r\n"))
}
