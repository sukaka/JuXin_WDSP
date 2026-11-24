// TCP 流重组与 HTTP/1.x 请求还原。
//
// 设计要点：
//   - 检测句柄仅重组「目的端口 ∈ MIRROR_PORTS」方向的流（client→server）；镜像口同时可见的
//     响应方向流（源端口 ∈ MIRROR_PORTS）在抓包层即被过滤，本组件不分析响应；
//   - 发现句柄重组全端口 TCP 流（抓包层不过滤端口），流首包经协议嗅探分类（HTTP 取 Host、
//     TLS 取 SNI）后即排空丢弃，不做完整 HTTP 解析循环（见 discovery.go）；
//   - 同一接口同时承担检测与发现角色时共用一个抓包句柄：流工厂按目的端口分流——命中
//     检测端口集合的流走检测管线，其余走发现嗅探（端口集合与抓包层共享同一原子指针，
//     SetPorts 热更新对两级过滤一致生效）；
//   - 每个四元组方向一条 ReaderStream，检测流 goroutine 内循环 http.ReadRequest 解析
//     连续/pipeline 请求；流结束（FIN/RST/空闲冲刷关闭）即退出，goroutine 不泄漏；
//   - LossErrors=true：镜像丢包（SPAN 采样/内核丢包）产生显式错误并终止该流解析，
//     而不是无限等待缺失字节（重组容错纪律参照 detectors 的有界原则）；
//   - Body 捕获上限 MIRROR_BODY_MAX：上限内字节进检测，剩余部分仅透传丢弃
//     （保持流字节对齐，供后续 pipeline 请求继续解析），不整包入内存；
//   - 头部读取上限 maxRequestHeaderBytes（64KB）：http.ReadRequest/textproto 读头
//     对单行长度与头行条数无内置上限，护栏超限即终止该流（见 headerGuardReader）。
package mirrorcap

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// FlowMeta 还原请求的四元组元信息（旁路视角：源即真实客户端，目的即真实服务器）。
type FlowMeta struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
	// SourceMode 当前抓包接口的发现来源模式（MIRROR/ROUTED/TRANSPARENT；由流工厂按接口绑定）。
	SourceMode string
	// SniffDisabled 为 true 表示该抓包接口仅承担检测角色、未启用站点发现，检测路径不得顺带写发现记录。
	SniffDisabled bool
}

// RequestHandler 消费还原出的请求（检测管线实现）。
type RequestHandler interface {
	// HandleRequest 处理一条还原请求；bodyTruncated 标记 Body 是否因超上限被截断。
	// 实现必须快速返回或自行异步化——本调用在流读取 goroutine 内同步执行，
	// 阻塞会反压该流的重组消费（单流维度，不影响其他流）。
	HandleRequest(req *http.Request, meta FlowMeta, bodyTruncated bool)
}

// maxRequestHeaderBytes 单请求头部读取上限（请求行+全部头行）。
// http.ReadRequest 经 textproto 读头对单行长度与头行条数无内置上限，旁路流量
// 攻击者可控，超长头行会撑大行缓冲；超限即报错终止该流解析（对齐发现路径
// 16KB LimitReader 护栏的「有界」纪律，检测路径取 64KB 兼容大 Cookie/JWT 场景）。
const maxRequestHeaderBytes = 64 << 10

// errHeaderOverLimit 头部硬顶触发错误（终止该流，按解析错误计数）。
var errHeaderOverLimit = errors.New("mirrorcap: 请求头超过单请求上限")

// headerGuardReader 单请求头部读取护栏：包装在重组流与 bufio 之间，按请求窗口
// 累计底层读取字节；达硬顶（上限 + bufio 过读余量）返回错误使 ReadRequest 失败。
// 硬顶放过「头合法但 bufio 顺带预读了后续 Body/pipeline 字节」的场景，
// 精确判定由 serve 在 ReadRequest 返回后按「累计读取 − bufio 残留」复核。
type headerGuardReader struct {
	r     io.Reader
	total int64 // 当前请求窗口底层累计读取字节
}

func (g *headerGuardReader) Read(p []byte) (int, error) {
	if g.total >= maxRequestHeaderBytes+(32<<10) {
		return 0, errHeaderOverLimit
	}
	n, err := g.r.Read(p)
	g.total += int64(n)
	return n, err
}

// headerBytes 本请求真实头部消耗 = 底层累计读取 − bufio 已预读但未消费字节。
func (g *headerGuardReader) headerBytes(buffered int) int64 {
	return g.total - int64(buffered)
}

func (g *headerGuardReader) reset() { g.total = 0 }

// IfaceConsumer 单接口流消费组合：检测与发现可叠加于同一抓包句柄
// （共用同一 AF_PACKET socket，绝不对同一 ifname 开两个）。
type IfaceConsumer struct {
	// Detect 检测管线消费（nil = 本句柄不承担检测角色）。
	Detect RequestHandler
	// Sniff 发现嗅探消费（nil = 本句柄不承担发现角色）。
	Sniff *DiscoverySniffer
}

// streamFactory tcpassembly 流工厂（每四元组方向一条流；按角色与端口分流消费）。
type streamFactory struct {
	detect  RequestHandler                       // 检测消费（nil = 不承担检测角色）
	sniff   *DiscoverySniffer                    // 发现嗅探消费（nil = 不承担发现角色）
	ports   *atomic.Pointer[map[uint16]struct{}] // 与抓包层共享的检测端口集合（nil = 不判定，全部走 detect）
	bodyMax int64
	stats   *Stats
	active  atomic.Int32 // 当前打开流数（MaxStreamConns 护栏）
	maxConn int32
}

// NewStreamFactory 供 capture 层创建 tcpassembly.StreamFactory（检测专用）。
func NewStreamFactory(h RequestHandler, bodyMax int64, maxConns int, stats *Stats) tcpassembly.StreamFactory {
	if maxConns <= 0 {
		maxConns = defaultMaxStreamConns
	}
	return &streamFactory{detect: h, bodyMax: bodyMax, stats: stats, maxConn: int32(maxConns)}
}

// NewDiscoveryStreamFactory 发现专用工厂：重组流全部走嗅探分支（不做端口判定与
// HTTP 解析循环）。独立发现句柄之外的复合场景由 newIfaceStreamFactory 承载。
func NewDiscoveryStreamFactory(s *DiscoverySniffer, maxConns int, stats *Stats) tcpassembly.StreamFactory {
	if maxConns <= 0 {
		maxConns = defaultMaxStreamConns
	}
	return &streamFactory{sniff: s, stats: stats, maxConn: int32(maxConns)}
}

// newIfaceStreamFactory 单接口复合工厂：检测端口集合与抓包层共享（SetPorts 热更新
// 对抓包过滤与流分流一致生效）；命中检测端口的流走检测管线，其余流走发现嗅探。
func newIfaceStreamFactory(consumer IfaceConsumer, ports *atomic.Pointer[map[uint16]struct{}], bodyMax int64, maxConns int, stats *Stats) tcpassembly.StreamFactory {
	if maxConns <= 0 {
		maxConns = defaultMaxStreamConns
	}
	return &streamFactory{
		detect: consumer.Detect, sniff: consumer.Sniff, ports: ports,
		bodyMax: bodyMax, stats: stats, maxConn: int32(maxConns),
	}
}

// New 实现 tcpassembly.StreamFactory：按角色分流为流启动消费 goroutine。
func (f *streamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	rs := tcpreader.NewReaderStream()
	rs.LossErrors = true // 镜像丢包 → 显式错误终止解析，不无限等待缺失字节
	if f.active.Add(1) > f.maxConn {
		// 超上限：丢弃本流内容（仍需排空，否则重组器阻塞）
		f.active.Add(-1)
		if f.stats != nil {
			f.stats.StreamsRejected.Add(1)
		}
		go tcpreader.DiscardBytesToEOF(&rs)
		return &rs
	}
	if f.stats != nil {
		f.stats.StreamsOpened.Add(1)
	}
	meta := flowMetaFrom(netFlow, tcpFlow)
	if f.sniff != nil {
		meta.SourceMode = f.sniff.mode
	} else {
		meta.SniffDisabled = true
	}
	switch {
	case f.detect != nil && f.isDetectPort(meta.DstPort):
		go f.serve(&rs, meta)
	case f.sniff != nil:
		go f.serveSniff(&rs, meta)
	default:
		// 无消费者（端口热更新竞态等防御场景）：排空不积压，绝不让重组器阻塞
		f.active.Add(-1)
		if f.stats != nil {
			f.stats.StreamsClosed.Add(1)
		}
		go tcpreader.DiscardBytesToEOF(&rs)
	}
	return &rs
}

// isDetectPort 目的端口是否命中检测集合（无共享集合时全部视为检测流——
// 检测专用句柄已在抓包层完成端口过滤）。
func (f *streamFactory) isDetectPort(p uint16) bool {
	if f.ports == nil {
		return true
	}
	_, ok := (*f.ports.Load())[p]
	return ok
}

// serve 循环解析一条流上的连续 HTTP 请求，直到流关闭或解析失败。
func (f *streamFactory) serve(rs *tcpreader.ReaderStream, meta FlowMeta) {
	defer func() {
		f.active.Add(-1)
		if f.stats != nil {
			f.stats.StreamsClosed.Add(1)
		}
	}()
	guard := &headerGuardReader{r: rs}
	buf := bufio.NewReaderSize(guard, 32<<10)
	// 防御性护栏：若检测端口误收到了 TLS 加密流（首两字节 0x16 0x03，如误配 443 端口），
	// 且本接口启用了站点发现，则转交 TLS SNI 嗅探而不报错丢弃发现证据；嗅探后直接排空 rs
	// 绕开 headerGuardReader 字节上限，避免大 TLS 流阻塞重组器。
	if f.sniff != nil {
		if head, _ := buf.Peek(2); len(head) >= 2 && head[0] == 0x16 && head[1] == 0x03 {
			f.sniff.Sniff(io.LimitReader(buf, int64(f.sniff.maxBytes)), meta)
			tcpreader.DiscardBytesToEOF(rs)
			return
		}
	}
	for {
		guard.reset()
		req, err := http.ReadRequest(buf)
		if err != nil {
			// EOF（FIN/RST/空闲冲刷关闭）为正常结束；其余（畸形/丢包/头部超硬顶）计一次解析错误
			if err != io.EOF {
				if f.stats != nil {
					f.stats.RequestErrors.Add(1)
				}
				// 终止解析后同步排空该流：不消费会反压阻塞重组器，且同步排空使异常长连接在 EOF/冲刷前持续计入 MaxStreamConns
				tcpreader.DiscardBytesToEOF(rs)
			}
			return
		}
		// 头部精确复核：硬顶放过了 bufio 顺带预读 Body/下条 pipeline 请求的场景，
		// 此处按真实头部消耗判定，超限终止该流（攻击者可控输入必须有界）
		if guard.headerBytes(buf.Buffered()) > maxRequestHeaderBytes {
			if f.stats != nil {
				f.stats.RequestErrors.Add(1)
			}
			tcpreader.DiscardBytesToEOF(rs) // 同步排空防重组器反压并保持 MaxStreamConns 有界
			return
		}
		body, truncated, err := captureBody(req, f.bodyMax)
		if err != nil {
			if f.stats != nil {
				f.stats.RequestErrors.Add(1)
			}
			tcpreader.DiscardBytesToEOF(rs) // 终止解析后同步排空该流，防重组器反压并保持 MaxStreamConns 有界
			return
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		if truncated && req.Header.Get("Content-Length") != "" {
			req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		}
		// TransferEncoding 保留原值：Coraza 保真需要（CRS 920171 走私检测），
		// 统一管线只读 r.Body，不受影响
		// 旁路无 Caddy 入口注入 Request ID：缺失时本地生成，保证事件可关联
		if req.Header.Get("X-Request-Id") == "" {
			req.Header.Set("X-Request-Id", "mirror-"+randHex16())
		}
		// 真实源地址：四元组源即客户端（不依赖任何代理头，无伪造面）
		req.RemoteAddr = meta.SrcIP + ":" + strconv.Itoa(int(meta.SrcPort))
		if f.stats != nil {
			f.stats.RequestsParsed.Add(1)
		}
		f.detect.HandleRequest(req, meta, truncated)
	}
}

// serveSniff 发现流消费：首包分类嗅探一次后由 Sniff 内部排空剩余内容。
func (f *streamFactory) serveSniff(rs *tcpreader.ReaderStream, meta FlowMeta) {
	defer func() {
		f.active.Add(-1)
		if f.stats != nil {
			f.stats.StreamsClosed.Add(1)
		}
	}()
	f.sniff.Sniff(rs, meta)
}

// captureBody 读取请求体：上限内字节进内存（供检测），剩余部分透传丢弃以保持流对齐。
// 返回 (捕获字节, 是否截断, 错误)。
func captureBody(req *http.Request, max int64) ([]byte, bool, error) {
	if req.Body == nil || max <= 0 {
		return nil, false, nil
	}
	defer req.Body.Close()
	// 多读 1 字节探测是否超限
	buf, err := io.ReadAll(io.LimitReader(req.Body, max+1))
	if err != nil {
		return nil, false, err
	}
	truncated := int64(len(buf)) > max
	if truncated {
		buf = buf[:max]
		// 排空剩余体字节，保持流字节对齐（否则后续请求会被误解析）
		if _, err := io.Copy(io.Discard, req.Body); err != nil {
			return nil, false, err
		}
	}
	return buf, truncated, nil
}

// flowMetaFrom 从 gopacket 流端点提取四元组（调用方保证为 IPv4/IPv6 + TCP）。
func flowMetaFrom(netFlow, tcpFlow gopacket.Flow) FlowMeta {
	sp, _ := strconv.Atoi(tcpFlow.Src().String())
	dp, _ := strconv.Atoi(tcpFlow.Dst().String())
	return FlowMeta{
		SrcIP:   netFlow.Src().String(),
		SrcPort: uint16(sp),
		DstIP:   netFlow.Dst().String(),
		DstPort: uint16(dp),
	}
}

// randHex16 生成 16 字节随机 hex（Request ID 本地生成用）。
func randHex16() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "norand"
	}
	return hex.EncodeToString(b[:])
}
