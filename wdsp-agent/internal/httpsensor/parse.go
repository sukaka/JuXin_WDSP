// HTTP/1.1 消息解析（请求行/状态行/Header/Body），带资源钳制。
//
// 红线：
//   - Header 存储总量钳 16KB/消息（契约 §4）；单行 >32KB 或头部块 >256KB
//     视为协议违例 → 连接回退（不报错不 panic）；
//   - Body 捕获永不超 maxBodySize 驻留内存：超出部分边读边丢（仅计原始大小），
//     截断后仍排空到消息结束以保持 keep-alive 流字节对齐（契约 §8）；
//   - 不支持 HTTP/2、gRPC、WebSocket（契约 §1）；101 Upgrade 视为协议违例回退。
package httpsensor

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// 解析钳制常量。
const (
	maxHeaderStoreBytes = 16 << 10  // Header 存储总量钳（契约 §4）
	maxHeaderRawBytes   = 256 << 10 // 头部块线上字节硬上限（超出=协议违例）
	maxLineBytes        = 32 << 10  // 单行硬上限（与 bufio 缓冲一致）
)

// errProtocol 协议违例/非 HTTP：连接回退为 flow 事件行为。
var errProtocol = errors.New("httpsensor: 协议违例")

// bodyCapture Body 捕获写器：上限内字节驻留，超出仅计数（红线：永不超上限驻留）。
type bodyCapture struct {
	buf       []byte
	max       int64
	total     int64
	truncated bool
}

func (w *bodyCapture) Write(p []byte) (int, error) {
	w.total += int64(len(p))
	if room := w.max - int64(len(w.buf)); room > 0 {
		if int64(len(p)) > room {
			w.buf = append(w.buf, p[:room]...)
			w.truncated = true
		} else {
			w.buf = append(w.buf, p...)
		}
	} else {
		w.truncated = true
	}
	return len(p), nil
}

// readLine 读一行（去 \r\n）；单行超 maxLineBytes 或流内错误 → errProtocol。
// EOF 前有残留字节 = 截断消息（非 HTTP/协议违例），按 errProtocol 回退；
// 仅干净 EOF（无任何字节）原样上抛（keep-alive 正常关闭）。
func readLine(buf *bufio.Reader) (string, error) {
	line, err := buf.ReadSlice('\n')
	if err != nil {
		if err == bufio.ErrBufferFull {
			return "", fmt.Errorf("%w: 单行超 %d 字节", errProtocol, maxLineBytes)
		}
		if err == io.EOF && len(line) > 0 {
			return "", fmt.Errorf("%w: 消息在流结束处截断", errProtocol)
		}
		return "", err // io.EOF（无残留）或重组丢失错误，原样上抛
	}
	// ReadSlice 不保证行长（正常路径 ≤32KB），双重防御
	if len(line) > maxLineBytes+2 {
		return "", fmt.Errorf("%w: 单行超 %d 字节", errProtocol, maxLineBytes)
	}
	s := strings.TrimRight(string(line), "\r\n")
	if len(s) > 0 && s[len(s)-1] == '\r' {
		s = s[:len(s)-1]
	}
	return s, nil
}

// parseHeaders 解析头部块（至空行）。存储量钳 maxHeaderStoreBytes，
// 线上总量超 maxHeaderRawBytes → errProtocol。Header 名存储为小写；
// 同名多值以 ", " 连接（契约 §3 示例为 map 结构）。
func parseHeaders(buf *bufio.Reader, onClamp func()) (map[string]string, error) {
	headers := make(map[string]string)
	raw := 0
	stored := 0
	for {
		line, err := readLine(buf)
		if err != nil {
			return nil, err
		}
		raw += len(line) + 2
		if raw > maxHeaderRawBytes {
			return nil, fmt.Errorf("%w: 头部块超 %d 字节", errProtocol, maxHeaderRawBytes)
		}
		if line == "" {
			return headers, nil
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return nil, fmt.Errorf("%w: 非法头部行", errProtocol)
		}
		name := strings.ToLower(strings.TrimSpace(line[:colon]))
		value := strings.TrimSpace(line[colon+1:])
		if !validHeaderName(name) {
			return nil, fmt.Errorf("%w: 非法头部名", errProtocol)
		}
		need := len(name) + len(value) + 4
		if stored+need > maxHeaderStoreBytes {
			if onClamp != nil {
				onClamp()
			}
			continue // 钳：只消费不存储
		}
		stored += need
		if prev, ok := headers[name]; ok {
			headers[name] = prev + ", " + value
		} else {
			headers[name] = value
		}
	}
}

// validHeaderName RFC 7230 token 校验。
func validHeaderName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' ||
			c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' ||
			c == '`' || c == '|' || c == '~'
		if !ok {
			return false
		}
	}
	return len(s) > 0
}

// parseRequestLine 解析 "METHOD SP URI SP HTTP/1.x"。
func parseRequestLine(line string) (method, uri string, err error) {
	sp1 := strings.IndexByte(line, ' ')
	if sp1 <= 0 {
		return "", "", fmt.Errorf("%w: 非法请求行", errProtocol)
	}
	method = line[:sp1]
	for i := 0; i < len(method); i++ {
		if method[i] < 'A' || method[i] > 'Z' {
			return "", "", fmt.Errorf("%w: 非法方法", errProtocol)
		}
	}
	rest := line[sp1+1:]
	sp2 := strings.LastIndexByte(rest, ' ')
	if sp2 <= 0 {
		return "", "", fmt.Errorf("%w: 非法请求行", errProtocol)
	}
	uri = rest[:sp2]
	version := rest[sp2+1:]
	if len(version) != 8 || !strings.HasPrefix(version, "HTTP/1.") ||
		version[7] < '0' || version[7] > '9' {
		return "", "", fmt.Errorf("%w: 非法版本", errProtocol)
	}
	return method, uri, nil
}

// bodyKind Body 形态判定。
type bodyKind int

const (
	bodyNone bodyKind = iota
	bodyContentLength
	bodyChunked
	bodyUntilEOF
)

// classifyBody 按 RFC 7230 判定 Body 形态（TE 优先于 CL）。
func classifyBody(headers map[string]string, isResponse bool, method string, status int) (bodyKind, int64, error) {
	if isResponse {
		if method == "HEAD" || status/100 == 1 || status == 204 || status == 304 {
			return bodyNone, 0, nil
		}
	}
	if te := headers["transfer-encoding"]; te != "" {
		// 最后一个 coding 为 chunked 才按 chunked 解析
		parts := strings.Split(te, ",")
		last := strings.ToLower(strings.TrimSpace(parts[len(parts)-1]))
		if last == "chunked" {
			return bodyChunked, 0, nil
		}
		if isResponse {
			return bodyUntilEOF, 0, nil
		}
		return bodyNone, 0, nil
	}
	if cl := headers["content-length"]; cl != "" {
		// 多值取首个（重复且不一致的 CL 属请求走私面，旁路采集不做判定）
		first := strings.TrimSpace(strings.Split(cl, ",")[0])
		n, err := strconv.ParseInt(first, 10, 64)
		if err != nil || n < 0 {
			return bodyNone, 0, fmt.Errorf("%w: 非法 Content-Length", errProtocol)
		}
		if n == 0 {
			return bodyNone, 0, nil
		}
		return bodyContentLength, n, nil
	}
	if isResponse {
		return bodyUntilEOF, 0, nil
	}
	return bodyNone, 0, nil
}

// readBody 按形态读取 Body：捕获 ≤max 字节，剩余排空（保持流对齐）。
func readBody(buf *bufio.Reader, kind bodyKind, length, maxBody int64) (*bodyCapture, error) {
	bc := &bodyCapture{max: maxBody}
	switch kind {
	case bodyNone:
		return bc, nil
	case bodyContentLength:
		if _, err := io.CopyN(bc, buf, length); err != nil {
			return nil, err // 流中断：上抛（EOF=响应未捕获）
		}
		return bc, nil
	case bodyChunked:
		if err := readChunked(buf, bc); err != nil {
			return nil, err
		}
		return bc, nil
	default: // bodyUntilEOF
		_, _ = io.Copy(bc, buf) // 读到 EOF 为止（EOF 即消息结束，非错误）
		return bc, nil
	}
}

// readChunked 解析 chunked 编码（含 trailer 消费）。
func readChunked(buf *bufio.Reader, bc *bodyCapture) error {
	for {
		line, err := readLine(buf)
		if err != nil {
			return err
		}
		// chunk-size 可带扩展（; 后忽略）
		sizeStr := line
		if i := strings.IndexByte(line, ';'); i >= 0 {
			sizeStr = line[:i]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 16, 64)
		if err != nil || size < 0 {
			return fmt.Errorf("%w: 非法 chunk 大小", errProtocol)
		}
		if size == 0 {
			// trailer 部分（通常为空），读到空行结束
			for {
				tl, err := readLine(buf)
				if err != nil {
					return err
				}
				if tl == "" {
					return nil
				}
			}
		}
		if _, err := io.CopyN(bc, buf, size); err != nil {
			return err
		}
		// chunk 数据后的 CRLF
		crlf := make([]byte, 2)
		if _, err := io.ReadFull(buf, crlf); err != nil {
			return err
		}
		if crlf[0] != '\r' || crlf[1] != '\n' {
			return fmt.Errorf("%w: chunk 后缺少 CRLF", errProtocol)
		}
	}
}

// parseRequest 从 c2s 流解析一条完整请求（含 Body 捕获）。
func parseRequest(buf *bufio.Reader, maxBody int64) (*requestInfo, error) {
	line, err := readLine(buf)
	if err != nil {
		return nil, err
	}
	method, uri, err := parseRequestLine(line)
	if err != nil {
		return nil, err
	}
	req := &requestInfo{ts: time.Now(), method: method, uri: uri}
	clamped := false
	req.headers, err = parseHeaders(buf, func() {
		if !clamped {
			clamped = true
		}
	})
	if err != nil {
		return nil, err
	}
	if clamped {
		req.headersClamped = true
	}
	req.host = req.headers["host"]
	kind, length, err := classifyBody(req.headers, false, "", 0)
	if err != nil {
		return nil, err
	}
	bc, err := readBody(buf, kind, length, maxBody)
	if err != nil {
		return nil, err
	}
	req.rawBody = bc.buf
	req.wireSize = wireBodySize(kind, length, bc)
	req.truncated = bc.truncated
	return req, nil
}

// responseHead 已解析的响应头部（Body 待定，配对请求后读取）。
type responseHead struct {
	status         int
	headers        map[string]string
	headersClamped bool
}

// parseResponseHead 从 s2c 流解析响应状态行与头部；跳过 1xx 中间响应
// （101 Upgrade 视为协议违例回退，契约 §1 不支持 WebSocket）。
// 与 Body 读取分离的原因：配对等待（nextRequest）期间绝不能停滞本向流读取
// （tcpreader 无缓冲通道，读取停滞会阻塞重组器——见 conn.go pairGrace 注释）。
func parseResponseHead(buf *bufio.Reader) (*responseHead, error) {
	for {
		line, err := readLine(buf)
		if err != nil {
			return nil, err
		}
		status, err := parseStatusLine(line)
		if err != nil {
			return nil, err
		}
		clamped := false
		headers, err := parseHeaders(buf, func() { clamped = true })
		if err != nil {
			return nil, err
		}
		if status/100 == 1 {
			if status == 101 {
				return nil, fmt.Errorf("%w: 101 协议升级（不支持 WebSocket）", errProtocol)
			}
			continue // 100 Continue 等中间响应：消费头部后读真正的状态行
		}
		return &responseHead{status: status, headers: headers, headersClamped: clamped}, nil
	}
}

// readResponseBody 按头部与请求方法读取响应 Body 并组装响应。
func readResponseBody(buf *bufio.Reader, head *responseHead, reqMethod string, maxBody int64) (*responseInfo, error) {
	resp := &responseInfo{status: head.status, headers: head.headers, headersClamped: head.headersClamped}
	kind, length, err := classifyBody(head.headers, true, reqMethod, head.status)
	if err != nil {
		return nil, err
	}
	bc, err := readBody(buf, kind, length, maxBody)
	if err != nil {
		return nil, err
	}
	resp.rawBody = bc.buf
	resp.wireSize = wireBodySize(kind, length, bc)
	resp.truncated = bc.truncated
	return resp, nil
}

// parseStatusLine 解析 "HTTP/1.x SP 3DIGIT SP reason"。
func parseStatusLine(line string) (int, error) {
	if len(line) < 9 || !strings.HasPrefix(line, "HTTP/1.") {
		return 0, fmt.Errorf("%w: 非法状态行", errProtocol)
	}
	rest := line[8:]
	if len(rest) < 1 || rest[0] != ' ' {
		return 0, fmt.Errorf("%w: 非法状态行", errProtocol)
	}
	code := strings.TrimSpace(rest[1:])
	if i := strings.IndexByte(code, ' '); i >= 0 {
		code = code[:i]
	}
	status, err := strconv.Atoi(code)
	if err != nil || status < 100 || status > 999 {
		return 0, fmt.Errorf("%w: 非法状态码", errProtocol)
	}
	return status, nil
}

// wireBodySize 线上原始 Body 长度（契约 §4 original_body_size：
// Content-Length 或实际重组长度）。
func wireBodySize(kind bodyKind, length int64, bc *bodyCapture) int64 {
	if kind == bodyContentLength {
		return length
	}
	return bc.total
}
