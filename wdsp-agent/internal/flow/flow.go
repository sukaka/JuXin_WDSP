// Package flow 五元组流跟踪（契约 §3.4 flow_id、设计 §22 Flow ID / TASK-006）。
//
//   - 方向归一化：以「命中采集端口的一端」为 server 端，canonical key 为
//     client→server 五元组（双向包归并到同一条流）；两端端口均在采集集时
//     以五元组排序兜底（小端点为 client 侧）；
//   - flow_id 格式：`<agent_id>-<srcip>-<srcport>-<dstip>-<dstport>-<startts>`；
//   - 空闲超时驱逐（默认 90s）与流表上限（默认 65536，满则驱逐采样到的最旧）
//     均发 flow_end 事件；上限驱逐单独计数；
//   - TCP 关闭识别（契约 §3.4 flow_end「流关闭或空闲超时」）：任一侧 RST 立即
//     结束；双方 FIN 到齐立即结束；单方 FIN 后半关闭，最后活动静默满 3s 宽限
//     后结束（对侧仍发数据不提前结束）；每流至多一条 flow_end；
//   - client→server 首段 payload 交给 httpparse 嗅探，结论发出 request 事件
//     （PLAINTEXT 带 method/host/uri；ENCRYPTED/UNKNOWN 仅带可见性标记）。
package flow

import (
	"fmt"
	"sync"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/httpparse"
)

// 默认参数（契约 §6 / 任务约定）。
const (
	DefaultIdleTimeout = 90 * time.Second
	DefaultMaxEntries  = 65536
	// DefaultFinGrace 单方 FIN 后半关闭宽限期：取 3s —— FIN/ACK 握手正常在
	// 亚 RTT 内完成，3s 可容忍对侧 FIN 丢失重传一次，同时保证 flow_end 在
	// 连接关闭后数秒内发出（不再等 90s 空闲超时）。宽限按「最后活动静默」
	// 计：半关闭后对侧仍发数据时不提前结束。
	DefaultFinGrace = 3 * time.Second
)

// Key 归一化后的五元组（client→server 视角）。
type Key struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

// FlowID 契约 §3.4 flow_id 格式。
func (k Key) FlowID(agentID string, start time.Time) string {
	return fmt.Sprintf("%s-%s-%d-%s-%d-%d",
		agentID, k.SrcIP, k.SrcPort, k.DstIP, k.DstPort, start.Unix())
}

// Packet 上层交付的单包信息（capture 层已解码并过滤）。
type Packet struct {
	Ts      time.Time
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Ingress bool // 过滤判定：dst 端口命中=true（ingress），src 命中=false（egress）
	// BothHit 连接两端端口均在采集集（逐包方向判定会随包向翻转，canonical
	// 须改用五元组排序兜底，否则同一连接被拆成两条单向流）。
	BothHit bool
	Length  int // 线上字节数（含 L2 头）
	Payload []byte
	FIN     bool // TCP FIN
	RST     bool // TCP RST
}

// Flow 单条流的累计状态。
type Flow struct {
	Key        Key
	Direction  string
	FirstSeen  time.Time
	LastSeen   time.Time
	BytesIn    uint64 // server→client
	BytesOut   uint64 // client→server
	PacketsIn  uint64
	PacketsOut uint64

	id           string // flow_id（建流时计算一次，事件复用）
	ruleLevel    int    // 定向规则提升等级（0-3，只升不降；Phase 4 契约 §2.4）
	sampled      bool   // 采样成员（建流时判定，同流一致；false=仅发 flow_end 计数）
	sensorWanted bool   // 本流曾达 L1+ 且被采样选中（上层可能已建 HTTP 连接）

	sniffer    *httpparse.Sniffer
	sniffDone  bool
	visibility string

	finClient bool      // client→server 方向已见 FIN
	finServer bool      // server→client 方向已见 FIN
	finAt     time.Time // 首次见 FIN 的时间（半关闭宽限起点参考）
}

// Evaluator 定向采集规则求值器（Phase 4 契约 §2.4；internal/override.Set 实现）。
// 返回命中规则的最高等级（0-3；无命中=0）。
type Evaluator interface {
	// EvalFlow 首包五元组求值（dst_ip/dst_port）。
	EvalFlow(dstIP string, dstPort uint16, now time.Time) int
	// EvalRequest 请求行嗅探成功后的完整求值（含 host/uri_prefix）。
	EvalRequest(dstIP string, dstPort uint16, host, uri string, now time.Time) int
}

// FlowState Track 返回的流采集状态（采集决策点统一由此驱动，Phase 4）：
// 生效等级 = 基础等级 → overrides 提升 → 降级帽压制（levelFn 内完成）；
// 采样过滤在采样阶段先行（Sampled=false 仅发 flow_end 计数）。
type FlowState struct {
	Key          Key
	FlowID       string
	Level        int  // 生效等级序数（0-3）
	Sampled      bool // 采样成员（false=仅 flow_end 计数事件）
	SensorWanted bool // 本流曾达 L1+ 且被选中（上层可能已建 HTTP 连接，帽压回落时需收尾）
	// Visibility 首段 payload 嗅探结论（PLAINTEXT/ENCRYPTED/UNKNOWN；空=未决）。
	// ENCRYPTED 流不得进 HTTP 重组器（parseRequest 必失败，半流 goroutine
	// 会 Discard 到 EOF，TLS 长连接每条钉住 2 个 goroutine）。
	Visibility string
}

// Tracker 流表（非并发安全外部由锁保护——此处内置锁，Track/Expire 可直接并发调用）。
type Tracker struct {
	mu          sync.Mutex
	agentID     string
	maxEntries  int
	idleTimeout time.Duration
	finGrace    time.Duration
	flows       map[Key]*Flow

	onEvent    func(ev events.FlowEvent) // request / flow_end 事件出口
	onOverflow func()                    // 流表满驱逐计数（可选）

	// Phase 4 采集调制（setter 热更，均随 mu 保护；Track 持锁期间使用）：
	//   - eval：定向规则求值器（nil=无规则）；
	//   - levelFn：生效等级函数 ruleLevel→effectiveRank（基础等级 max 规则、
	//     降级帽 min；nil=按 ruleLevel 原样）；
	//   - sampleFn：建流时采样成员判定（nil=全采）。
	eval     Evaluator
	levelFn  func(ruleLevel int) int
	sampleFn func(flowID string) bool
}

// NewTracker 创建流跟踪器。onEvent 必须非阻塞快速返回（自行异步化）。
func NewTracker(agentID string, maxEntries int, idleTimeout time.Duration,
	onEvent func(ev events.FlowEvent), onOverflow func()) *Tracker {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	if idleTimeout <= 0 {
		idleTimeout = DefaultIdleTimeout
	}
	return &Tracker{
		agentID: agentID, maxEntries: maxEntries, idleTimeout: idleTimeout,
		finGrace: DefaultFinGrace,
		flows:    make(map[Key]*Flow), onEvent: onEvent, onOverflow: onOverflow,
	}
}

// Len 当前流表条数。
func (t *Tracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.flows)
}

// SetEvaluator 热更定向规则求值器（nil=清除；config 热更不重启抓包）。
func (t *Tracker) SetEvaluator(eval Evaluator) {
	t.mu.Lock()
	t.eval = eval
	t.mu.Unlock()
}

// SetLevelFunc 热更生效等级函数（ruleLevel→effectiveRank；nil=按 ruleLevel 原样）。
// 单点入口：基础等级 → overrides 提升 → 降级帽压制在此完成。
func (t *Tracker) SetLevelFunc(fn func(ruleLevel int) int) {
	t.mu.Lock()
	t.levelFn = fn
	t.mu.Unlock()
}

// SetSampler 热更采样成员判定（建流时调用一次，同流一致；nil=全采）。
// 采样外 flow 仅发 flow_end 计数事件（契约 §4：统计不丢量）。
func (t *Tracker) SetSampler(fn func(flowID string) bool) {
	t.mu.Lock()
	t.sampleFn = fn
	t.mu.Unlock()
}

// effectiveLocked 生效等级序数（levelFn 缺省时按 ruleLevel 原样）。
func (t *Tracker) effectiveLocked(ruleLevel int) int {
	if t.levelFn != nil {
		return t.levelFn(ruleLevel)
	}
	return ruleLevel
}

// Track 处理一个已过滤包：建流/计数/嗅探，必要时发 request 事件；
// 识别 TCP 关闭（RST 立即结束；双方 FIN 到齐立即结束）。
// 返回流采集状态（生效等级/采样成员/传感器挂接标记），供上层统一采集决策。
func (t *Tracker) Track(p Packet) FlowState {
	t.mu.Lock()
	f, evictEv, overflow := t.getOrCreateLocked(p)
	// 计数（canonical 视角：发往 server 端为 out）
	toServer := p.DstIP == f.Key.DstIP && p.DstPort == f.Key.DstPort
	if toServer {
		f.BytesOut += uint64(p.Length)
		f.PacketsOut++
	} else {
		f.BytesIn += uint64(p.Length)
		f.PacketsIn++
	}
	if p.Ts.After(f.LastSeen) {
		f.LastSeen = p.Ts
	}
	// client→server 方向首段 payload 嗅探
	var reqEv *events.FlowEvent
	if toServer && !f.sniffDone && len(p.Payload) > 0 && f.sniffer != nil {
		if f.sniffer.Feed(p.Payload) {
			f.sniffDone = true
			r := f.sniffer.Result()
			f.visibility = r.Visibility
			f.sniffer = nil // 决策后释放嗅探器（缓冲最高 16KB，不随流常驻到驱逐）
			// 请求行嗅探成功：host/uri_prefix 规则即时提升（只升不降，
			// 从当前请求起按新等级采集，已过的不补——契约 §2.4）
			if f.visibility == httpparse.Plaintext && t.eval != nil {
				if lvl := t.eval.EvalRequest(f.Key.DstIP, f.Key.DstPort, r.Host, r.URI, p.Ts); lvl > f.ruleLevel {
					f.ruleLevel = lvl
				}
			}
			eff := t.effectiveLocked(f.ruleLevel)
			// request 事件：采样外流不发（仅 flow_end 计数）；
			// 生效等级 ≥ L1 的流停发（由 HTTP 记录通道替代，契约 §3 注）
			if f.sampled && eff < 1 {
				ev := t.baseEventLocked(f, events.TypeRequest, p.Ts)
				ev.TLSVisibility = f.visibility
				if f.visibility == httpparse.Plaintext {
					ev.HTTPMethod = r.Method
					ev.HTTPHost = r.Host
					ev.HTTPURI = r.URI
				}
				reqEv = &ev
			}
		}
	}
	eff := t.effectiveLocked(f.ruleLevel)
	if f.sampled && eff >= 1 {
		f.sensorWanted = true
	}
	state := FlowState{Key: f.Key, FlowID: f.id, Level: eff, Sampled: f.sampled,
		SensorWanted: f.sensorWanted, Visibility: f.visibility}
	// TCP 关闭识别（先计数再判关闭，FIN/RST 包本身的字节计入累计）
	var endEv *events.FlowEvent
	switch {
	case p.RST:
		// 单边 RST：立即结束（连接已异常终止，不会再有后续字节）
		endEv = t.removeLocked(f.Key, f, p.Ts)
	case p.FIN:
		if toServer {
			f.finClient = true
		} else {
			f.finServer = true
		}
		if f.finAt.IsZero() {
			f.finAt = p.Ts
		}
		if f.finClient && f.finServer {
			// 双方 FIN 到齐：连接正常关闭，立即结束
			endEv = t.removeLocked(f.Key, f, p.Ts)
		}
		// 单方 FIN：半关闭，由 Expire 在「最后活动静默满 finGrace」后结束
	}
	t.mu.Unlock()
	if t.onEvent != nil {
		if evictEv != nil {
			t.onEvent(*evictEv) // 表满驱逐的 flow_end（锁外发送）
		}
		if reqEv != nil {
			t.onEvent(*reqEv)
		}
		if endEv != nil {
			t.onEvent(*endEv)
		}
	}
	if overflow && t.onOverflow != nil {
		t.onOverflow()
	}
	return state
}

// getOrCreateLocked 归一化建流；表满驱逐采样到的最旧流（返回其 flow_end 事件
// 与 overflow 标记，由 Track 在锁外发送——onEvent 可能同步落盘，不得在全局锁内调用）。
func (t *Tracker) getOrCreateLocked(p Packet) (*Flow, *events.FlowEvent, bool) {
	// canonical：server 端 = 命中采集端口的一端（ingress 判定即 dst 命中）；
	// 两端端口均在采集集时 Ingress 逐包随方向翻转，以五元组排序固定
	// canonical（小端点为 client 侧），保证双向包归并到同一条流。
	key := Key{SrcIP: p.SrcIP, SrcPort: p.SrcPort, DstIP: p.DstIP, DstPort: p.DstPort}
	dir := "ingress"
	swap := !p.Ingress
	if p.BothHit {
		swap = !endpointLess(p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)
	}
	if swap {
		key = Key{SrcIP: p.DstIP, SrcPort: p.DstPort, DstIP: p.SrcIP, DstPort: p.SrcPort}
		dir = "egress"
	}
	if f, ok := t.flows[key]; ok {
		return f, nil, false
	}
	var evictEv *events.FlowEvent
	overflow := false
	if len(t.flows) >= t.maxEntries {
		evictEv = t.evictOldestLocked(p.Ts)
		overflow = evictEv != nil
	}
	f := &Flow{
		Key: key, Direction: dir,
		FirstSeen: p.Ts, LastSeen: p.Ts,
		sniffer: httpparse.NewSniffer(0),
		sampled: true,
	}
	f.id = key.FlowID(t.agentID, p.Ts)
	// Phase 4：首包五元组规则求值（dst_ip/dst_port）与采样成员判定
	if t.eval != nil {
		f.ruleLevel = t.eval.EvalFlow(key.DstIP, key.DstPort, p.Ts)
	}
	if t.sampleFn != nil {
		f.sampled = t.sampleFn(f.id)
	}
	t.flows[key] = f
	return f, evictEv, overflow
}

// endpointLess 五元组端点排序（双采集端口 canonical 兜底：小端点为 client 侧）。
func endpointLess(ipA string, portA uint16, ipB string, portB uint16) bool {
	if ipA != ipB {
		return ipA < ipB
	}
	return portA < portB
}

// evictSample 表满驱逐的采样条数上限：从 map 迭代的首批采样中挑 LastSeen
// 最旧者驱逐，避免满表热点路径 O(n) 全表扫描。
const evictSample = 8

// evictOldestLocked 驱逐采样到的最旧流（满表路径）；返回构造好的 flow_end
// 事件（由调用方在锁外发送）。
func (t *Tracker) evictOldestLocked(now time.Time) *events.FlowEvent {
	var oldest Key
	var oldestFlow *Flow
	n := 0
	for k, f := range t.flows {
		if oldestFlow == nil || f.LastSeen.Before(oldestFlow.LastSeen) {
			oldest, oldestFlow = k, f
		}
		if n++; n >= evictSample {
			break
		}
	}
	if oldestFlow == nil {
		return nil
	}
	return t.removeLocked(oldest, oldestFlow, now)
}

// Expire 驱逐流（由上层周期调用，建议 ≤2s 以保证 FIN 宽限及时生效）：
//   - 空闲超时（LastSeen 距今 ≥ idleTimeout）；
//   - 半关闭宽限（已见单方 FIN 且最后活动静默 ≥ finGrace）——双方 FIN 与
//     RST 已在 Track 内即时处理，这里只兜底单方 FIN 后对侧无下文的情形。
func (t *Tracker) Expire(now time.Time) {
	t.mu.Lock()
	var expired []Key
	for k, f := range t.flows {
		if now.Sub(f.LastSeen) >= t.idleTimeout {
			expired = append(expired, k)
			continue
		}
		if !f.finAt.IsZero() && !(f.finClient && f.finServer) && now.Sub(f.LastSeen) >= t.finGrace {
			expired = append(expired, k)
		}
	}
	evs := make([]events.FlowEvent, 0, len(expired))
	for _, k := range expired {
		evs = append(evs, *t.removeLocked(k, t.flows[k], now))
	}
	t.mu.Unlock()
	if t.onEvent != nil {
		for _, ev := range evs {
			t.onEvent(ev)
		}
	}
}

// Close 冲刷全部流（进程退出路径），每条发 flow_end。
func (t *Tracker) Close(now time.Time) {
	t.mu.Lock()
	evs := make([]events.FlowEvent, 0, len(t.flows))
	for k, f := range t.flows {
		evs = append(evs, *t.removeLocked(k, f, now))
	}
	t.mu.Unlock()
	if t.onEvent != nil {
		for _, ev := range evs {
			t.onEvent(ev)
		}
	}
}

// removeLocked 移除流并返回构造好的 flow_end 事件（不再内部直接发送，
// 由调用方在锁外发送；map 删除保证每流至多一条 flow_end）。
func (t *Tracker) removeLocked(k Key, f *Flow, now time.Time) *events.FlowEvent {
	delete(t.flows, k)
	ev := t.baseEventLocked(f, events.TypeFlowEnd, now)
	ev.TLSVisibility = f.visibility
	if ev.TLSVisibility == "" {
		ev.TLSVisibility = events.VisibilityUnknown
	}
	return &ev
}

// baseEventLocked 构造事件骨架（http_status Phase 1 恒 0，由零值保证）。
func (t *Tracker) baseEventLocked(f *Flow, typ string, now time.Time) events.FlowEvent {
	return events.FlowEvent{
		EventType:  typ,
		FlowID:     f.id,
		Timestamp:  now.Unix(),
		SrcIP:      f.Key.SrcIP,
		SrcPort:    f.Key.SrcPort,
		DstIP:      f.Key.DstIP,
		DstPort:    f.Key.DstPort,
		Protocol:   "tcp",
		Direction:  f.Direction,
		BytesIn:    f.BytesIn,
		BytesOut:   f.BytesOut,
		PacketsIn:  f.PacketsIn,
		PacketsOut: f.PacketsOut,
	}
}
