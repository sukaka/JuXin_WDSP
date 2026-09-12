// Package events 定义契约 §3.4 流量事件与 §3.5 RAW 包批量帧格式。
//
// 字段与序列化格式对齐 docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md（冻结契约），
// 任何字段变更必须与 server/web 三方同步。
package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/k8smeta"
)

// 事件类型（契约 §3.4）。
const (
	TypeRequest = "request"  // HTTP 请求行/Host 解析成功，或 TLS 可见性判定完成即上报
	TypeFlowEnd = "flow_end" // 流关闭或空闲超时，携带累计字节/包计数
)

// TLS 可见性（设计 §11.4 / 契约 §3.4）。
const (
	VisibilityPlaintext = "PLAINTEXT"
	VisibilityEncrypted = "ENCRYPTED"
	VisibilityUnknown   = "UNKNOWN"
)

// 批量上限（契约 §3.4/§3.5）。
const (
	MaxEventsPerBatch  = 500
	MaxPacketBatchSize = 8 << 20 // 8 MB
	MaxFrameCapLen     = 65535
	PacketMagic        = "WDP1"
	packetHeaderLen    = 14 // magic(4) + ts(8) + count(2)
	frameHeaderLen     = 20 // ts_sec(8) + ts_usec(4) + orig_len(4) + cap_len(4)
)

// FlowEvent 流量事件（契约 §3.4 events 数组元素）。
type FlowEvent struct {
	EventType     string            `json:"event_type"`
	FlowID        string            `json:"flow_id"`
	Timestamp     int64             `json:"timestamp"` // Unix 秒
	SrcIP         string            `json:"src_ip"`
	SrcPort       uint16            `json:"src_port"`
	DstIP         string            `json:"dst_ip"`
	DstPort       uint16            `json:"dst_port"`
	Protocol      string            `json:"protocol"` // Phase 1 恒 "tcp"
	Direction     string            `json:"direction"`
	BytesIn       uint64            `json:"bytes_in"`
	BytesOut      uint64            `json:"bytes_out"`
	PacketsIn     uint64            `json:"packets_in"`
	PacketsOut    uint64            `json:"packets_out"`
	TLSVisibility string            `json:"tls_visibility"`
	HTTPMethod    string            `json:"http_method,omitempty"`
	HTTPHost      string            `json:"http_host,omitempty"`
	HTTPURI       string            `json:"http_uri,omitempty"`
	HTTPStatus    int               `json:"http_status"` // Phase 1 恒 0
	K8s           *k8smeta.Metadata `json:"k8s,omitempty"`
}

// FlowsRequest POST /flows 请求体。
type FlowsRequest struct {
	Events []FlowEvent `json:"events"`
}

// FlowsResponse POST /flows 202 响应体。
type FlowsResponse struct {
	Accepted int `json:"accepted"`
}

// PacketsResponse POST /packets 202 响应体。
type PacketsResponse struct {
	AcceptedFrames int `json:"accepted_frames"`
}

// PacketFrame 单帧 RAW 包（含 Ethernet 头的原始字节）。
type PacketFrame struct {
	Ts      time.Time
	OrigLen uint32
	Data    []byte // cap_len 字节
}

// PacketBatcher 按契约 §3.5 累积帧并在接近 8MB 上限时切批。
type PacketBatcher struct {
	frames    []PacketFrame
	size      int // 当前批次编码后预估字节数
	maxBytes  int
	droppedFn func(n int) // 帧超长等丢弃回调（可选）
}

// NewPacketBatcher 创建批处理器；maxBytes<=0 用契约上限。
func NewPacketBatcher(maxBytes int, droppedFn func(n int)) *PacketBatcher {
	if maxBytes <= 0 || maxBytes > MaxPacketBatchSize {
		maxBytes = MaxPacketBatchSize
	}
	return &PacketBatcher{maxBytes: maxBytes, droppedFn: droppedFn}
}

// Add 追加一帧；返回 false 表示本批已满（调用方应先 Flush 再重试）。
// cap_len 超 65535 的帧直接丢弃计数（契约上限）。
func (b *PacketBatcher) Add(f PacketFrame) bool {
	if len(f.Data) > MaxFrameCapLen {
		if b.droppedFn != nil {
			b.droppedFn(1)
		}
		return true
	}
	need := frameHeaderLen + len(f.Data)
	if len(b.frames) >= 0xffff || (len(b.frames) > 0 && b.size+need > b.maxBytes) {
		return false
	}
	if len(b.frames) == 0 {
		b.size = packetHeaderLen
	}
	b.frames = append(b.frames, f)
	b.size += need
	return true
}

// Len 当前批帧数。
func (b *PacketBatcher) Len() int { return len(b.frames) }

// Flush 编码当前批为二进制 body 并清空；空批返回 nil。
// 格式（契约 §3.5）：magic "WDP1" | batch_ts BE u64 | count BE u16 | frames...
func (b *PacketBatcher) Flush(ts time.Time) []byte {
	if len(b.frames) == 0 {
		return nil
	}
	buf := bytes.NewBuffer(make([]byte, 0, b.size))
	buf.WriteString(PacketMagic)
	_ = binary.Write(buf, binary.BigEndian, uint64(ts.Unix()))
	_ = binary.Write(buf, binary.BigEndian, uint16(len(b.frames)))
	for _, f := range b.frames {
		_ = binary.Write(buf, binary.BigEndian, uint64(f.Ts.Unix()))
		_ = binary.Write(buf, binary.BigEndian, uint32(f.Ts.Nanosecond()/1000))
		_ = binary.Write(buf, binary.BigEndian, f.OrigLen)
		_ = binary.Write(buf, binary.BigEndian, uint32(len(f.Data)))
		buf.Write(f.Data)
	}
	b.frames = nil
	b.size = 0
	return buf.Bytes()
}

// DecodePacketBatch 解码校验（供测试与服务端参考实现核对格式）。
func DecodePacketBatch(body []byte) (batchTS int64, frames []PacketFrame, err error) {
	if len(body) < packetHeaderLen {
		return 0, nil, fmt.Errorf("body 过短: %d", len(body))
	}
	if string(body[:4]) != PacketMagic {
		return 0, nil, fmt.Errorf("magic 非法: %q", body[:4])
	}
	batchTS = int64(binary.BigEndian.Uint64(body[4:12]))
	count := int(binary.BigEndian.Uint16(body[12:14]))
	off := packetHeaderLen
	for i := 0; i < count; i++ {
		if off+frameHeaderLen > len(body) {
			return 0, nil, fmt.Errorf("帧 %d 头越界", i)
		}
		sec := binary.BigEndian.Uint64(body[off:])
		usec := binary.BigEndian.Uint32(body[off+8:])
		orig := binary.BigEndian.Uint32(body[off+12:])
		capLen := binary.BigEndian.Uint32(body[off+16:])
		off += frameHeaderLen
		if off+int(capLen) > len(body) {
			return 0, nil, fmt.Errorf("帧 %d 数据越界", i)
		}
		frames = append(frames, PacketFrame{
			Ts:      time.Unix(int64(sec), int64(usec)*1000),
			OrigLen: orig,
			Data:    body[off : off+int(capLen)],
		})
		off += int(capLen)
	}
	if off != len(body) {
		return 0, nil, fmt.Errorf("尾部多余 %d 字节", len(body)-off)
	}
	return batchTS, frames, nil
}
