// 连接状态、tcpassembly 流工厂与请求/响应配对。
package httpsensor

import (
	"bufio"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// 半流索引。
const (
	halfC2S = 0 // client→server（请求方向）
	halfS2C = 1 // server→client（响应方向）
)

// pairGrace 响应头部解析完成后等待配对请求的宽限。请求包必然先于响应包进入
// 重组器（Assemble 串行、按包序），此处仅为跨 goroutine 调度的防御性宽限；
// 超时按协议违例回退（响应先于请求=违例或采集起点在连接中段）。
//
// 死锁纪律：消费 goroutine 等待配对时绝不能无限期停止读取本向流——tcpreader
// 的 Reassembled 是无缓冲通道，读取停滞会阻塞重组器进而卡死整个传感器。
// 因此配对等待必须有上限（pairGrace），超时回退后排空本向流。
const pairGrace = 100 * time.Millisecond

// streamFactory tcpassembly 流工厂：按方向把半流挂到连接表中的 conn。
// 由 Assembler 在 Sensor.mu 内同步调用，conns 查找无需再加锁。
type streamFactory struct {
	sensor *Sensor
}

// New 实现 tcpassembly.StreamFactory。找不到连接表项（防御性竞态）或半流槽位
// 冲突（4 元组快速复用等退化场景）时排空丢弃，绝不阻塞重组器。
func (f *streamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	rs := tcpreader.NewReaderStream()
	rs.LossErrors = true // 镜像丢包 → 显式错误终止本连接解析，不无限等待
	s := f.sensor
	sp := tcpFlow.Src().String()
	dp := tcpFlow.Dst().String()
	srcIP, dstIP := netFlow.Src().String(), netFlow.Dst().String()
	srcPort, dstPort := parsePort(sp), parsePort(dp)

	// server 端 = 命中采集端口的一端（与 flow 层 canonical 语义一致）；
	// 两端端口均在采集集时按五元组排序兜底（小端点为 client 侧），
	// 否则同一连接两个方向都被判为 c2s，槽位冲突导致半流被排空
	isC2S := s.isServerPort(dstPort)
	if isC2S && s.isServerPort(srcPort) {
		isC2S = endpointLess(srcIP, srcPort, dstIP, dstPort)
	}
	key := connKey{srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort}
	if !isC2S {
		key = connKey{srcIP: dstIP, srcPort: dstPort, dstIP: srcIP, dstPort: srcPort}
	}
	c := s.conns[key]
	halfIdx := halfS2C
	if isC2S {
		halfIdx = halfC2S
	}
	if c == nil || !c.attach(halfIdx) {
		// 无连接表项或槽位冲突：排空不积压
		go tcpreader.DiscardBytesToEOF(&rs)
		return &rs
	}
	if halfIdx == halfC2S {
		go c.serveRequests(&rs)
	} else {
		go c.serveResponses(&rs)
	}
	return &rs
}

func parsePort(s string) uint16 {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0
		}
		n = n*10 + int(s[i]-'0')
		if n > 65535 {
			return 0
		}
	}
	return uint16(n)
}

// requestInfo 已解析请求（Body 为线上原始字节，脱敏/解码在 emit 时进行）。
type requestInfo struct {
	ts             time.Time
	method         string
	uri            string
	host           string
	headers        map[string]string
	headersClamped bool   // Header 总量超 16KB 被钳
	rawBody        []byte // 捕获部分（≤ maxBodySize）
	wireSize       int64  // 线上原始 Body 长度（Content-Length 或实际重组长度）
	truncated      bool   // 线上 Body 超上限被截断
}

// responseInfo 已解析响应。
type responseInfo struct {
	status         int
	headers        map[string]string
	headersClamped bool
	rawBody        []byte
	wireSize       int64
	truncated      bool
}

// halfState 单向半流状态。
type halfState struct {
	done bool
}

// conn 一条 TCP 连接的 HTTP 会话状态（配对队列 + 生命周期）。
//
// 配对模型：已解析请求经 reqCh（有缓冲通道）交给响应侧 goroutine；
// reqDone 关闭表示「不会再有新请求」（c2s 半流退出或连接回退）。
// 通道语义保证一个请求只被消费一次（响应侧配对或收尾补 null，二者取一）。
type conn struct {
	sensor *Sensor
	key    connKey
	dir    string
	start  time.Time

	lastSeen atomic.Int64 // UnixNano（Assemble 在 Sensor.mu 下更新，避免嵌套锁）
	level    atomic.Value // string：本连接生效采集等级（Phase 4 按流调制，emit 时用于 Body 门控）

	mu        sync.Mutex
	halves    [2]*halfState
	started   [2]bool // 各方向是否已建立序列基准（Sensor.mu 下访问；中段建链补合成 SYN）
	failed    bool    // 解析失败/非 HTTP：回退为 flow 事件行为
	finalized bool
	inflight  *requestInfo // 响应侧已配对、正在读取 Body 的请求（截断快速失败时由 finalize 接管补发）

	reqCh       chan *requestInfo // 待配对请求队列（缓冲=maxPendingRequests）
	reqDone     chan struct{}     // 关闭=不再产生新请求
	reqDoneOnce sync.Once
}

func newConn(s *Sensor, key connKey, dir string, start time.Time) *conn {
	c := &conn{
		sensor: s, key: key, dir: dir, start: start,
		reqCh:   make(chan *requestInfo, maxPendingRequests),
		reqDone: make(chan struct{}),
	}
	c.lastSeen.Store(start.UnixNano())
	return c
}

// setLevel 更新本连接生效采集等级（AssembleLevel 在 Sensor.mu 下调用）。
func (c *conn) setLevel(level string) { c.level.Store(level) }

// getLevel 本连接生效采集等级（空=未设置，回落全局策略等级）。
func (c *conn) getLevel() string {
	if v := c.level.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// attach 挂载半流；槽位已占用返回 false（调用方排空）。
func (c *conn) attach(idx int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.halves[idx] != nil {
		return false
	}
	c.halves[idx] = &halfState{}
	return true
}

// closeReqDone 标记不再产生新请求（幂等）。
func (c *conn) closeReqDone() { c.reqDoneOnce.Do(func() { close(c.reqDone) }) }

// serveRequests c2s 半流消费：循环解析请求并入配对队列。
// 任何解析错误 → 连接回退（fail），排空残余，绝不 panic 外溢。
func (c *conn) serveRequests(rs *tcpreader.ReaderStream) {
	defer c.recover("c2s")
	defer c.halfExited(halfC2S)
	defer c.closeReqDone()
	buf := bufio.NewReaderSize(rs, 32<<10)
	for {
		if c.isFailed() {
			break
		}
		req, err := parseRequest(buf, int64(c.sensor.policy.Load().MaxBodySize))
		if err != nil {
			if err != io.EOF {
				c.fail()
			}
			break
		}
		if !c.enqueueRequest(req) {
			break
		}
	}
	// 排空残余字节（保持重组器不阻塞；失败路径尤为重要）
	_, _ = io.Copy(io.Discard, buf)
}

// enqueueRequest 请求入配对队列；false=停止解析。与 finalize 互斥（同一把
// mu）保证「入队即会被消费」：已收尾时请求由本 goroutine 直接补发 null
// （唯一持有方，不会与 finalize 的排空重复）。
func (c *conn) enqueueRequest(req *requestInfo) bool {
	c.mu.Lock()
	if c.finalized {
		c.mu.Unlock()
		c.emit(req, nil, time.Time{})
		return false
	}
	select {
	case c.reqCh <- req:
		c.mu.Unlock()
		return true
	default: // 积压超上限（对端不应答）→ 连接回退
		c.mu.Unlock()
		c.fail()
		return false
	}
}

// serveResponses s2c 半流消费：先解析响应头部，再按到达顺序取配对请求。
func (c *conn) serveResponses(rs *tcpreader.ReaderStream) {
	defer c.recover("s2c")
	defer c.halfExited(halfS2C)
	buf := bufio.NewReaderSize(rs, 32<<10)
	for {
		// 1) 先消费本向流（状态行+头部），绝不在有未读字节时空等配对
		head, err := parseResponseHead(buf)
		if err != nil {
			if err != io.EOF {
				c.fail()
			}
			break
		}
		// 2) 取配对请求（有上限等待，见 pairGrace 死锁纪律）
		req := c.nextRequest()
		if req == nil {
			break // 不会再有新请求且队列已空
		}
		if req == errPairTimeout {
			c.fail()
			break
		}
		if !c.registerInflight(req) {
			// 连接已被收尾接管（截断快速失败等）：本 goroutine 唯一持有该
			// 请求，直接补发 null（不会与 finalize 重复）
			c.emit(req, nil, time.Time{})
			break
		}
		// 3) 读取响应 Body 并配对上报（claimForEmit 保证与收尾互斥，精确一次）
		resp, err := readResponseBody(buf, head, req.method, int64(c.sensor.policy.Load().MaxBodySize))
		if err != nil {
			if c.claimForEmit(req) {
				if err == io.EOF {
					c.emit(req, nil, time.Time{}) // 响应未捕获（连接关闭）
				} else {
					c.fail()
					c.emit(req, nil, time.Time{})
				}
			} else if err != io.EOF {
				c.fail()
			}
			break
		}
		if c.claimForEmit(req) {
			c.emit(req, resp, time.Now())
		}
	}
	_, _ = io.Copy(io.Discard, buf)
}

// registerInflight 登记响应侧正在读取 Body 的配对请求；false=连接已收尾
// （收尾路径不持有该请求，调用方须自行补发 null）。
func (c *conn) registerInflight(req *requestInfo) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finalized {
		return false
	}
	c.inflight = req
	return true
}

// claimForEmit 领取该请求的 emit 权（清除 inflight）；false=收尾已接管
// （finalize 已/将补发 null，调用方不得再 emit）。
func (c *conn) claimForEmit(req *requestInfo) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finalized || c.inflight != req {
		return false
	}
	c.inflight = nil
	return true
}

func (c *conn) recover(dir string) {
	if r := recover(); r != nil {
		c.sensor.log.Error("httpsensor 流解析 panic 已捕获（连接回退）", "dir", dir, "panic", r)
		c.fail()
	}
}

// errPairTimeout 配对等待超时哨兵（响应先于请求=协议违例/采集中段切入）。
var errPairTimeout = &requestInfo{}

// nextRequest 取下一个待配对请求：
//   - 队列有请求 → 立即返回；
//   - reqDone 关闭且队列已空 → nil（正常结束）；
//   - pairGrace 内仍无请求 → errPairTimeout（回退，防重组器死锁）。
func (c *conn) nextRequest() *requestInfo {
	// 快路径：队列非空
	select {
	case req := <-c.reqCh:
		return req
	default:
	}
	timer := time.NewTimer(pairGrace)
	defer timer.Stop()
	for {
		select {
		case req := <-c.reqCh:
			return req
		case <-c.reqDone:
			// 不会再有新请求：排空残余
			select {
			case req := <-c.reqCh:
				return req
			default:
				return nil
			}
		case <-timer.C:
			return errPairTimeout
		}
	}
}

// fail 标记连接回退（解析失败/非 HTTP）：不再产出新解析，已配对记录保留，
// 未配对请求在收尾时以 response=null 补发。
func (c *conn) fail() {
	c.mu.Lock()
	if !c.failed {
		c.failed = true
		c.sensor.Stats.ParseFallbacks.Add(1)
	}
	c.mu.Unlock()
	c.closeReqDone()
}

func (c *conn) isFailed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failed
}

// halfExited 半流 goroutine 退出：标记完成，若两半流均已结束则收尾。
func (c *conn) halfExited(idx int) {
	c.mu.Lock()
	if c.halves[idx] != nil {
		c.halves[idx].done = true
	}
	bothAttached := c.halves[halfC2S] != nil && c.halves[halfS2C] != nil
	allDone := c.allHalvesDoneLocked()
	c.mu.Unlock()
	if bothAttached && allDone {
		c.finalize()
	}
}

// allHalvesDone 已挂载半流是否全部结束（供 Sweep；单边抓包连接依赖 Sweep 收尾）。
func (c *conn) allHalvesDone() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.allHalvesDoneLocked()
}

func (c *conn) allHalvesDoneLocked() bool {
	for _, h := range c.halves {
		if h != nil && !h.done {
			return false
		}
	}
	return true
}

// finalize 连接收尾（幂等）：未配对请求（reqCh 残余 + inflight 在飞请求）
// 补发 response=null 记录，移出连接表。
// 一对请求/响应只上报一次（契约 §3）：已配对的由 serveResponses 经
// claimForEmit 精确一次 emit；inflight 在此被接管后 serveResponses 不再 emit；
// reqCh 排空与 enqueueRequest 经同一把 mu 互斥（通道接收保证唯一消费）。
func (c *conn) finalize() {
	c.mu.Lock()
	if c.finalized {
		c.mu.Unlock()
		return
	}
	c.finalized = true
	inf := c.inflight
	c.inflight = nil
	c.mu.Unlock()
	if inf != nil {
		c.emit(inf, nil, time.Time{})
	}
	for {
		select {
		case req := <-c.reqCh:
			c.emit(req, nil, time.Time{})
		default:
			c.sensor.removeConn(c.key, c)
			return
		}
	}
}
