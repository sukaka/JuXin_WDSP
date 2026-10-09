// sse.go SSE（text/event-stream）事件边界读取器（NG-MCP G1 批次 A，
// docs/nextgen/NG-MCP-g1-toolcall.md §1.7/§1.10 + §5 批次 A 线契约逐字冻结）。
//
// 语义（按冻结协议文本复核——WHATWG SSE 事件流解析模型）：
//   - 事件边界=空行；行终止符 \n / \r\n / 孤立 \r 三形态全认；
//   - 字段行「name: value」（冒号后至多一个前导空格剥离）；无冒号行整行按
//     字段名空值处理（协议原语义）；
//   - data 多行按协议拼接（行间插 \n）；event/id 后值覆盖前值；retry 与其余
//     字段忽略（计入块体量预算）；
//   - 注释行（':' 前缀）不作字段——keepalive 语义按 §1.7「原样透传」承载：
//     仅含注释行的块以**零值事件**（Data/Event/ID 全空）透出，转发侧据此
//     原样放行保活；无任何内容的空行不产事件；
//   - 流尾不完整块（无空行收尾）按协议丢弃——EOF 正常结束，不产半截事件；
//   - 单事件预算（默认 1MiB，§1.10 表）：按块原文行字节累计，超限 → ErrBudget
//     （粘滞——后续 Next 恒返回同一错误，不继续走流）；
//   - 流首 BOM（U+FEFF）剥离一次；读取全在调用方 goroutine（无后台任务，
//     数据源错误（ctx 取消等）原样透传即释放）。
package mcprpc

import (
	"bufio"
	"io"
	"strings"
)

// 默认单事件预算（§1.10 表：SSE 单事件 ≤1MiB）。
const defaultMaxEventBytes = 1 << 20

// SSEEvent 一条 SSE 事件（Data 为多行 data 拼接结果；Event/ID 为字段值，
// 缺席为空串）。注释-only 块以全零值事件透出（keepalive 透传承载）。
type SSEEvent struct {
	Data  []byte
	Event string
	ID    string
}

// SSEReader SSE 事件边界读取器（io.Reader 流式，单事件预算；
// 并发模型：单流单 goroutine 顺序使用——与请求处理模型一致）。
type SSEReader struct {
	br            *bufio.Reader
	maxEventBytes int
	bomChecked    bool
	err           error // 粘滞错误（ErrBudget；io.EOF 不粘滞——正常结束）
}

// NewSSEReader 构造事件读取器（maxEventBytes ≤0 用默认 1MiB）。
func NewSSEReader(r io.Reader, maxEventBytes int) *SSEReader {
	if maxEventBytes <= 0 {
		maxEventBytes = defaultMaxEventBytes
	}
	return &SSEReader{br: bufio.NewReader(r), maxEventBytes: maxEventBytes}
}

// Next 读下一条事件；流干净结束返回 io.EOF；单事件超限返回 ErrBudget
// （*BudgetError，粘滞）；数据源错误原样透传。
func (r *SSEReader) Next() (*SSEEvent, error) {
	if r.err != nil {
		return nil, r.err
	}
	ev, err := r.next()
	if err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		r.err = err
		return nil, err
	}
	return ev, nil
}

// next 块读取与分派（WHATWG 分派口径：data 缓冲为空不分派事件——
// 仅 event/id/retry 字段的块不产事件；注释-only 块例外透出零值事件
// 作 keepalive 透传承载）。
func (r *SSEReader) next() (*SSEEvent, error) {
	if !r.bomChecked {
		r.bomChecked = true
		if b, err := r.br.Peek(3); err == nil && len(b) == 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
			_, _ = r.br.Discard(3) // 流首 BOM 剥离一次
		}
	}
	var (
		dataParts  []string
		eventField string
		idField    string
		sawComment bool
		sawField   bool // 本块已有任意字段行（分派与否另判）
		blockBytes int
	)
	for {
		line, err := r.readLine()
		if err != nil {
			// EOF（含半行 EOF）：流尾不完整块按协议丢弃——正常结束
			return nil, err
		}
		blockBytes += len(line) + 1 // 行原文 + 终止符近似（预算口径保守偏大）
		if blockBytes > r.maxEventBytes {
			return nil, &BudgetError{Rule: "event_bytes_exceeded", Limit: r.maxEventBytes, Actual: blockBytes}
		}
		if line == "" {
			// 空行=事件边界
			switch {
			case len(dataParts) > 0:
				// data 缓冲非空：分派（data 多行按协议 \n 拼接）
				return &SSEEvent{Data: []byte(strings.Join(dataParts, "\n")), Event: eventField, ID: idField}, nil
			case sawComment:
				// 注释-only 块：零值事件透出（keepalive 透传语义，§1.7）
				return &SSEEvent{}, nil
			case sawField:
				// 仅 event/id/retry/其他字段无 data：按协议不分派，复位继续下一块
				eventField, idField, sawField = "", "", false
				continue
			default:
				continue // 无内容空行跳过
			}
		}
		if strings.HasPrefix(line, ":") {
			sawComment = true // 注释行/keepalive：不计字段
			continue
		}
		name, value := line, ""
		if i := strings.IndexByte(line, ':'); i >= 0 {
			name, value = line[:i], line[i+1:]
			if strings.HasPrefix(value, " ") {
				value = value[1:] // 冒号后至多一个前导空格剥离
			}
		}
		sawField = true
		switch name {
		case "data":
			dataParts = append(dataParts, value)
		case "event":
			eventField = value // 后值覆盖前值
		case "id":
			idField = value
		default:
			// retry 与其余字段忽略（计入块体量预算）；无冒号行整行按字段名空值
		}
	}
}

// readLine 读一行（\n / \r\n / 孤立 \r 三形态）；EOF（含半行）返回 io.EOF。
func (r *SSEReader) readLine() (string, error) {
	var sb strings.Builder
	for {
		c, err := r.br.ReadByte()
		if err != nil {
			return "", io.EOF // 半行按不完整块丢弃（调用侧判 EOF 正常结束）
		}
		switch c {
		case '\n':
			return sb.String(), nil
		case '\r':
			// 孤立 \r 亦为行终止符；\r\n 吃掉配对的 \n
			if b, err := r.br.ReadByte(); err == nil && b != '\n' {
				_ = r.br.UnreadByte()
			}
			return sb.String(), nil
		default:
			sb.WriteByte(c)
		}
	}
}
