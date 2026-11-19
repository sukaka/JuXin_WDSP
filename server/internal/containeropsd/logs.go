// logs.go 容器日志读取：解析 Docker 非 TTY 的 8 字节多路复用头与 TTY 原始流，
// 逐行剥离控制字符、保守脱敏，并执行行数/字节上限。
package containeropsd

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const (
	// DefaultTail 日志默认返回行数
	DefaultTail = 200
	// MaxTail 日志最大返回行数
	MaxTail = 1000
	// MaxLogBytes 单次日志输出最大字节（消息体累计，超限标记 truncated）
	MaxLogBytes = 256 * 1024
	// maxFrameSize 单个多路复用帧的防御性上限（16MB，防异常长度头耗尽内存）
	maxFrameSize = 16 << 20
)

// LogLine 是一条日志行。
type LogLine struct {
	Timestamp string `json:"timestamp"` // RFC3339Nano；无法解析时为空串
	Stream    string `json:"stream"`    // stdout / stderr
	Message   string `json:"message"`
}

// LogsResult 是日志读取响应。
type LogsResult struct {
	Service   string    `json:"service"`
	Lines     []LogLine `json:"lines"`
	Truncated bool      `json:"truncated"`
	NextSince int64     `json:"next_since"`
}

// clampTail 夹紧 tail 到 [1, MaxTail]，0/负值取默认。
func clampTail(tail int) int {
	if tail <= 0 {
		return DefaultTail
	}
	if tail > MaxTail {
		return MaxTail
	}
	return tail
}

// logAccumulator 累计输出行并执行字节上限。
type logAccumulator struct {
	lines     []LogLine
	total     int
	maxBytes  int
	truncated bool
	lastTS    time.Time
}

// push 追加一条日志；超过字节上限时返回 false（调用方停止读取）。
func (a *logAccumulator) push(ts time.Time, tsRaw, stream, msg string) bool {
	if a.total+len(msg) > a.maxBytes {
		a.truncated = true
		return false
	}
	a.total += len(msg)
	a.lines = append(a.lines, LogLine{Timestamp: tsRaw, Stream: stream, Message: msg})
	if !ts.IsZero() {
		a.lastTS = ts
	}
	return true
}

// splitTimestamp 从带 timestamps=true 的行中分离 RFC3339Nano 时间戳与消息体。
// 无法解析时保留整行为消息、时间戳为空。
func splitTimestamp(raw string) (time.Time, string, string) {
	idx := -1
	for i := 0; i < len(raw); i++ {
		if raw[i] == ' ' {
			idx = i
			break
		}
	}
	if idx <= 0 {
		return time.Time{}, "", raw
	}
	ts, err := time.Parse(time.RFC3339Nano, raw[:idx])
	if err != nil {
		return time.Time{}, "", raw
	}
	return ts, raw[:idx], raw[idx+1:]
}

// emitPayload 把一段载荷按行拆分、剥离控制字符并脱敏后写入累计器。
func emitPayload(a *logAccumulator, payload []byte, stream string) bool {
	// 多路复用载荷可能含多行；逐行处理（末行通常带 \n）
	for len(payload) > 0 {
		var line []byte
		if i := indexByte(payload, '\n'); i >= 0 {
			line, payload = payload[:i], payload[i+1:]
		} else {
			line, payload = payload, nil
		}
		ts, tsRaw, msg := splitTimestamp(stripControls(string(line)))
		if !a.push(ts, tsRaw, stream, redactLine(msg)) {
			return false
		}
	}
	return true
}

func indexByte(b []byte, c byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// streamName 映射多路复用流编号。
func streamName(code byte) string {
	switch code {
	case 1:
		return "stdout"
	case 2:
		return "stderr"
	default:
		return "stdout"
	}
}

// ParseLogStream 解析 Docker 日志流（tty=false 时为 8 字节头多路复用流，否则为原始流）。
// 达到字节上限即停止读取并标记 truncated；调用方随后关闭响应体即可。
func ParseLogStream(r io.Reader, tty bool, maxBytes int) (lines []LogLine, truncated bool, nextSince int64, err error) {
	if maxBytes <= 0 {
		maxBytes = MaxLogBytes
	}
	a := &logAccumulator{maxBytes: maxBytes}
	if tty {
		err = parseRawStream(r, a)
	} else {
		err = parseMultiplexedStream(r, a)
	}
	if err != nil {
		return nil, false, 0, err
	}
	var next int64
	if !a.lastTS.IsZero() {
		next = a.lastTS.Unix()
	}
	return a.lines, a.truncated, next, nil
}

// parseMultiplexedStream 解析非 TTY 容器的多路复用日志流：
// 帧头 8 字节 = [流类型(1), 0,0,0, 长度(4, 大端)]，后跟载荷。
func parseMultiplexedStream(r io.Reader, a *logAccumulator) error {
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return fmt.Errorf("读取日志帧头失败: %w", err)
		}
		size := binary.BigEndian.Uint32(hdr[4:])
		if size > maxFrameSize {
			return fmt.Errorf("日志帧长度异常: %d", size)
		}
		if size == 0 {
			continue
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(r, payload); err != nil {
			return fmt.Errorf("读取日志帧载荷失败: %w", err)
		}
		if !emitPayload(a, payload, streamName(hdr[0])) {
			return nil
		}
	}
}

// parseRawStream 解析 TTY 容器的原始日志流（timestamps=true 时仍逐行带时间戳前缀）。
// 使用有界 LimitedReader 约束总读取量，防止超长无换行日志行耗尽内存。
func parseRawStream(r io.Reader, a *logAccumulator) error {
	limit := int64(MaxLogBytes) + 64*1024
	if a.maxBytes > 0 && int64(a.maxBytes)+64*1024 < limit {
		limit = int64(a.maxBytes) + 64*1024
	}
	lr := &io.LimitedReader{R: r, N: limit}
	br := bufio.NewReaderSize(lr, 64*1024)
	for {
		chunk, err := br.ReadBytes('\n')
		if len(chunk) > 0 {
			line := chunk
			if line[len(line)-1] == '\n' {
				line = line[:len(line)-1]
			}
			if len(line) > 0 {
				ts, tsRaw, msg := splitTimestamp(stripControls(string(line)))
				if !a.push(ts, tsRaw, "stdout", redactLine(msg)) {
					return nil
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				if lr.N <= 0 {
					a.truncated = true
				}
				return nil
			}
			return fmt.Errorf("读取日志流失败: %w", err)
		}
	}
}
