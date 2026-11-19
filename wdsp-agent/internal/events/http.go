package events

// HTTP 记录（Phase 3 契约 §3 机器端点 POST /http 的 records 元素）。
//
// 字段与序列化格式对齐 docs/agents/WDSP_AGENT_PHASE3_CONTRACT.md（冻结契约），
// 任何字段变更必须与 server/web 三方同步。
// 红线：Record 在 Agent 内完成脱敏（httpsensor）后才允许进入本结构外发，
// 本包不做任何二次脱敏。

import (
	"encoding/json"
	"github.com/jiuzhang-waf/wdsp-agent/internal/k8smeta"
)

// 批量上限（Phase 3 契约 §3：每批 ≤100 条且序列化后 ≤8MB；P1-03 起含 JSON
// 转义与 records 包装开销的硬预算在 Agent 侧统一前置执行）。
const (
	MaxHTTPRecordsPerBatch = 100
	MaxHTTPBatchBytes      = 8 << 20
	// MaxHTTPRecordBytes 单条记录序列化硬上限：必须能独占一批（8MB 减包装
	// 与分隔符开销）。超过该上限的记录先缩减可选正文/元数据并标记截断，
	// 仍超限则丢弃并计数（dropped_by_reason=oversize）——不再放行独占批
	// 由服务端 400（否则 400→转缓存→无限重放死循环）。
	MaxHTTPRecordBytes = MaxHTTPBatchBytes - batchOverhead - 1
)

// 批次预算丢弃原因（dropped_by_reason 指标标签，冻结词表）。
const (
	DropOversize       = "oversize"       // 单条缩减后仍超 MaxHTTPRecordBytes
	DropUnserializable = "unserializable" // 记录无法 JSON 序列化
)

// BodySkippedBudgetExceeded 批次预算缩减的正文跳过标记：与服务端 v1/v2 枚举
// （"" | "content_type" | "encoding"）保持一致——预算缩减通过 body="" +
// body_truncated=true + original_body_size 表达，不再发送服务端 400 拒绝的枚举外值。
const BodySkippedBudgetExceeded = ""

// HTTPMessage 单向 HTTP 消息（请求或响应）。
type HTTPMessage struct {
	// 请求字段
	Method string `json:"method,omitempty"`
	Scheme string `json:"scheme,omitempty"`
	Host   string `json:"host,omitempty"`
	URI    string `json:"uri,omitempty"`
	// 响应字段
	Status int `json:"status,omitempty"`
	// 公共字段（Header 名为小写；Body 已按契约 §4/§5 处理）
	Headers           map[string]string `json:"headers,omitempty"`
	Body              string            `json:"body"`
	BodyTruncated     bool              `json:"body_truncated"`
	OriginalBodySize  int64             `json:"original_body_size"`
	BodySkippedReason string            `json:"body_skipped_reason"`
}

// HTTPRecord 一对关联完成的请求/响应（契约 §3 records 元素）。
type HTTPRecord struct {
	FlowID        string            `json:"flow_id"`
	RequestTS     float64           `json:"request_ts"`
	ResponseTS    *float64          `json:"response_ts"` // null=响应未捕获/超时
	LatencyMs     *int64            `json:"latency_ms"`  // null 同上
	SrcIP         string            `json:"src_ip"`
	SrcPort       uint16            `json:"src_port"`
	DstIP         string            `json:"dst_ip"`
	DstPort       uint16            `json:"dst_port"`
	Direction     string            `json:"direction"`
	TLSVisibility string            `json:"tls_visibility"` // 恒 PLAINTEXT（密文流不产生 HTTP 记录）
	Request       *HTTPMessage      `json:"request"`
	Response      *HTTPMessage      `json:"response"` // null=响应未捕获/超时
	K8s           *k8smeta.Metadata `json:"k8s,omitempty"`
}

// HTTPRequest POST /http 请求体。
type HTTPRequest struct {
	Records []HTTPRecord `json:"records"`
}

// HTTPAcceptedResponse POST /http 202 响应体。
// Duplicate 为 v2 增量（重复事件确认数，(agent_id, event_id) 幂等去重）；
// v1 服务端不返回该字段，解析为零值。
type HTTPAcceptedResponse struct {
	Accepted  int `json:"accepted"`
	Duplicate int `json:"duplicate,omitempty"`
}

// HTTPBatcher 按契约 §3 累积 HTTP 记录：≤100 条且序列化后 ≤8MB，超限切批。
// P1-03 批次预算统一：单条记录同样受 8MB 硬预算约束——超限时先缩减可选
// 正文/元数据并标记截断，仍超限则丢弃并经 onDrop 计数（oversize）；
// 不存在「首条无条件入批」放行路径。
type HTTPBatcher struct {
	records []HTTPRecord
	size    int // 当前批已序列化字节（含 records 包装开销）
	onDrop  func(reason string)
}

// NewHTTPBatcher 创建批处理器；onDrop 为丢弃计数回调（reason 为 DropXxx 词表），可为 nil。
func NewHTTPBatcher(onDrop func(reason string)) *HTTPBatcher {
	return &HTTPBatcher{onDrop: onDrop}
}

// batchOverhead records JSON 包装的固定开销（{"records":[]}）。
const batchOverhead = 13

// Add 追加一条记录；返回 false 表示本批已满且该条未消费（调用方应先 Flush 再重试）。
// 返回 true 时该条已被消费：正常入批，或经缩减后入批，或丢弃（onDrop 计数）。
func (b *HTTPBatcher) Add(r HTTPRecord) bool {
	data, err := json.Marshal(r)
	if err != nil {
		b.noteDrop(DropUnserializable)
		return true // 畸形记录不可序列化：丢弃（不阻塞本批）
	}
	if len(data) > MaxHTTPRecordBytes {
		// 单条超预算：缩减可选正文/元数据并标记截断，再复测
		shrinkHTTPRecord(&r)
		data, err = json.Marshal(r)
		if err != nil {
			b.noteDrop(DropUnserializable)
			return true
		}
		if len(data) > MaxHTTPRecordBytes {
			b.noteDrop(DropOversize)
			return true // 仍超限：丢弃并计数，杜绝服务端 400 无限重放
		}
	}
	need := len(data) + 1 // 逗号分隔
	if len(b.records) > 0 &&
		(len(b.records) >= MaxHTTPRecordsPerBatch || b.size+need > MaxHTTPBatchBytes) {
		return false
	}
	if len(b.records) == 0 {
		b.size = batchOverhead
	}
	b.records = append(b.records, r)
	b.size += need
	return true
}

func (b *HTTPBatcher) noteDrop(reason string) {
	if b.onDrop != nil {
		b.onDrop(reason)
	}
}

// shrinkHTTPRecord 缩减单条记录的可选内容以适配批次硬预算（P1-03）：
// ① 清空请求/响应 Body 并标记截断（original_body_size 保留）；
// ② 仍超限则丢弃 K8s 元数据；③ 再超限则按从大到小移除 Header。
// 调用方在缩减后复测序列化大小，仍超上限则丢弃计数。
func shrinkHTTPRecord(r *HTTPRecord) {
	for _, m := range []*HTTPMessage{r.Request, r.Response} {
		if m != nil && m.Body != "" {
			m.Body = ""
			m.BodyTruncated = true
			m.BodySkippedReason = BodySkippedBudgetExceeded
		}
	}
	if recordBytes(r) <= MaxHTTPRecordBytes {
		return
	}
	r.K8s = nil // 可选元数据次之
	for recordBytes(r) > MaxHTTPRecordBytes && dropLargestHeader(r) {
	}
}

// recordBytes 序列化大小（缩减路径低频，逐次 Marshal 可接受）。
func recordBytes(r *HTTPRecord) int {
	data, err := json.Marshal(r)
	if err != nil {
		return 0
	}
	return len(data)
}

// dropLargestHeader 移除请求/响应中最长的 Header 条目；无可移除返回 false。
func dropLargestHeader(r *HTTPRecord) bool {
	var victim map[string]string
	victimKey := ""
	victimLen := -1
	for _, m := range []*HTTPMessage{r.Request, r.Response} {
		if m == nil {
			continue
		}
		for k, v := range m.Headers {
			if len(k)+len(v) > victimLen {
				victim, victimKey, victimLen = m.Headers, k, len(k)+len(v)
			}
		}
	}
	if victim == nil {
		return false
	}
	delete(victim, victimKey)
	return true
}

// Len 当前批记录数。
func (b *HTTPBatcher) Len() int { return len(b.records) }

// Flush 取出当前批并清空；空批返回 nil。
func (b *HTTPBatcher) Flush() []HTTPRecord {
	if len(b.records) == 0 {
		return nil
	}
	out := b.records
	b.records = nil
	b.size = 0
	return out
}
