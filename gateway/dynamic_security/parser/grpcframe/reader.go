// Package grpcframe gRPC Length-Prefixed 帧流式读取器与四重预算执行
// （NG-GRPC G1 批次 A，docs/nextgen/NG-GRPC-g1-unary.md §1.2/D2 冻结）。
//
// 帧格式（gRPC over h2；Caddy 已终结 HTTP/2，请求体即帧序列）：
//
//	1 字节压缩标志（bit0；其余位为保留位，非零按畸形）+ 4 字节大端声明长度 + 消息体
//
// 纪律：
//   - 流式重组（R01）：不从「完整请求体」假设出发，按数据片段流式读取，
//     跨片段（任意切分）的帧头/帧体都能正确重组，不错位读取；
//   - 先验证声明长度再分配：读满 5 字节帧头 → 校验标志位 → 校验声明长度过
//     四重预算 → 按声明长度分配并读满；声明 > 剩余预算即拒，不预分配攻击者
//     声明值；
//   - 四重预算逐层执行（§1.2 冻结值）：单消息 ≤4MiB / 单请求 ≤64 消息 /
//     单请求声明合计 ≤16MiB / 全局并发合计 ≤64MiB（带上限原子计数器，
//     超限拒绝新解析不排队膨胀）；预算耗尽（BudgetError）与格式错误
//     （ProtocolError）语义分离——D6 状态映射的输入；
//   - 显式状态机随请求创建/销毁：无后台 goroutine、无跨请求状态（R06 泄漏
//     测试基础）；错误粘滞——任何畸形/预算拒绝后不再走帧（不错位、不污染），
//     后续体由 Drain 丢弃（§1.2 畸形处置）。
//
// 与现状 parser/parse_grpc.go 的关系：本包独立新建，现状代码不动
// （替换/并存由批次 B 决定——设计 D2 注）；本批不接 pipeline。
package grpcframe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
)

// 四重预算冻结值（§1.2；单消息默认与现状 dsctx.DefaultGRPCMaxFrameBytes 4MiB
// 同源——发布通道 api_grpc_max_frame_bytes 覆盖值由装配层经 Config 注入）。
const (
	DefaultMaxMessageBytes   = 4 << 20  // 单消息 ≤4MiB
	DefaultMaxMessages       = 64       // 单请求 ≤64 消息
	DefaultMaxRequestBytes   = 16 << 20 // 单请求声明合计 ≤16MiB
	DefaultGlobalBudgetBytes = 64 << 20 // 全局并发合计 ≤64MiB
)

// 压缩预算冻结值（§1.5/D5）。
const (
	MaxCompressedBytes   = 4 << 20  // 压缩体 ≤4MiB（与单消息上限同源）
	MaxDecompressedBytes = 16 << 20 // 解压 ≤16MiB
	MaxDecompressRatio   = 100      // 倍率 ≤100×
)

// ProtocolError 协议格式错误类（格式错误语义；OBSERVE 记 grpc.malformed_frame /
// PROTECT 协议化拒绝的输入——D6 映射由执行层（批次 B）消费）。
type ProtocolError struct {
	Kind   string // truncated_header / truncated_body / reserved_flag_bits / invalid_gzip
	Detail string
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("grpcframe: protocol error %s (%s)", e.Kind, e.Detail)
}

// BudgetError 预算耗尽类（RESOURCE_EXHAUSTED 语义；与格式错误分离——
// 拒绝事实含触顶层与读数，证据可答「哪层预算」）。
type BudgetError struct {
	Kind   string // message_bytes / message_count / request_bytes / global_budget / compressed_bytes / decompressed_bytes / decompress_ratio
	Limit  int64  // 触顶预算上限
	Actual int64  // 实际声明/读取量（越界值）
}

func (e *BudgetError) Error() string {
	return fmt.Sprintf("grpcframe: budget exceeded %s (limit %d, actual %d)", e.Kind, e.Limit, e.Actual)
}

// EncodingError 未知压缩算法（§1.5：grpc-encoding 非 identity/gzip——
// UNIMPLEMENTED(12) 语义，gRPC 规范的标准应答而非安全误断）。
type EncodingError struct {
	Encoding string // 客户端声明的未支持编码值
}

func (e *EncodingError) Error() string {
	return fmt.Sprintf("grpcframe: unsupported encoding %q", e.Encoding)
}

// IsProtocolError/IsBudgetError/IsEncodingError 错误类判定（执行层映射输入）。
func IsProtocolError(err error) bool {
	var pe *ProtocolError
	return errors.As(err, &pe)
}

func IsBudgetError(err error) bool {
	var be *BudgetError
	return errors.As(err, &be)
}

func IsEncodingError(err error) bool {
	var ee *EncodingError
	return errors.As(err, &ee)
}

// GlobalBudget 全局并发缓冲预算（§1.2 第四层：网关总 gRPC 缓冲 ≤64MiB；
// 带上限原子计数器——TryAcquire 非阻塞，超限拒绝新解析不排队膨胀；
// 预算端到端计算：4MiB×16 并发全消息驻留上限）。
type GlobalBudget struct {
	limit int64
	used  atomic.Int64
}

// NewGlobalBudget 构造全局预算（limit ≤0 用冻结默认 64MiB）。
func NewGlobalBudget(limit int64) *GlobalBudget {
	if limit <= 0 {
		limit = DefaultGlobalBudgetBytes
	}
	return &GlobalBudget{limit: limit}
}

// DefaultGlobalBudget 进程级默认全局预算（Config.Global 为 nil 时使用；
// 测试应实例化独立预算互不影响）。
var DefaultGlobalBudget = NewGlobalBudget(DefaultGlobalBudgetBytes)

// TryAcquire 尝试占有 n 字节预算（CAS 非阻塞；不足即拒不排队）。
func (g *GlobalBudget) TryAcquire(n int64) bool {
	if n <= 0 {
		return true
	}
	for {
		cur := g.used.Load()
		if cur+n > g.limit {
			return false
		}
		if g.used.CompareAndSwap(cur, cur+n) {
			return true
		}
	}
}

// Release 归还 n 字节预算（防御负值——重复归还按 0 夹紧不穿透）。
func (g *GlobalBudget) Release(n int64) {
	if n <= 0 {
		return
	}
	g.used.Add(-n)
	if g.used.Load() < 0 {
		g.used.Store(0)
	}
}

// Used 当前持有量（泄漏断言与覆盖读数）。
func (g *GlobalBudget) Used() int64 { return g.used.Load() }

// Limit 上限。
func (g *GlobalBudget) Limit() int64 { return g.limit }

// Config 读取器预算配置（≤0 项用冻结默认值；Global 为 nil 用 DefaultGlobalBudget）。
type Config struct {
	MaxMessageBytes int64         // 单消息上限（发布值注入点；≤0 → 4MiB）
	MaxMessages     int           // 单请求消息数（≤0 → 64）
	MaxRequestBytes int64         // 单请求声明合计（≤0 → 16MiB）
	Global          *GlobalBudget // 全局并发预算
}

func (c Config) withDefaults() Config {
	if c.MaxMessageBytes <= 0 {
		c.MaxMessageBytes = DefaultMaxMessageBytes
	}
	if c.MaxMessages <= 0 {
		c.MaxMessages = DefaultMaxMessages
	}
	if c.MaxRequestBytes <= 0 {
		c.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if c.Global == nil {
		c.Global = DefaultGlobalBudget
	}
	return c
}

// Frame 一条重组完成的消息帧（Body 长度已通过四重预算校验；
// 压缩时 Body 为线格式（压缩）字节——解压经 Gunzip/Message）。
type Frame struct {
	Index      int  // 消息序号（1 起）
	Compressed bool // 压缩标志位（bit0）置位
	Body       []byte
}

// Message 消息字节（Compressed 时经 Gunzip 有界解压——四重压缩预算；
// 嵌套 gzip 不递归解压，内层按数据处理）。
func (f *Frame) Message() ([]byte, error) {
	if f == nil {
		return nil, nil
	}
	if !f.Compressed {
		return f.Body, nil
	}
	return Gunzip(f.Body)
}

// Reader 流式帧读取器（显式状态机：读帧头 → 读消息体 → 复位；随请求创建/销毁，
// 无后台 goroutine、无跨请求状态）。错误粘滞：任何畸形/预算拒绝后 Next 恒返回
// 同一错误（不再走帧——不错位、不污染后继），后续体由 Drain 丢弃。
// 并发模型：单请求单 goroutine 使用（非并发安全——与请求处理模型一致）。
type Reader struct {
	r   io.Reader
	cfg Config

	messages      int   // 已重组消息数
	totalDeclared int64 // 已重组消息声明合计
	held          int64 // 全局预算当前持有量（已重组未 Close 的消息体合计）
	err           error // 粘滞终止错误（非 io.EOF）
	done          bool  // 干净结束（帧边界 io.EOF）
}

// NewReader 构造流式读取器（r 为请求体流——任意片段切分的 io.Reader 均可；
// 预算配置见 Config）。
func NewReader(r io.Reader, cfg Config) *Reader {
	return &Reader{r: r, cfg: cfg.withDefaults()}
}

// Next 重组下一条消息帧；帧序列干净结束返回 io.EOF；畸形/预算/编码错误
// 分类返回（*ProtocolError/*BudgetError/*EncodingError；底层源错误原样透传）。
func (rd *Reader) Next() (*Frame, error) {
	if rd.err != nil {
		return nil, rd.err // 粘滞：不再走帧
	}
	if rd.done {
		return nil, io.EOF
	}
	fr, err := rd.next()
	if err != nil {
		if err == io.EOF {
			rd.done = true
			return nil, io.EOF
		}
		rd.err = err
		rd.releaseHeld() // 错误路径释放全局持有（无缓冲驻留——R06）
		return nil, err
	}
	return fr, nil
}

func (rd *Reader) next() (*Frame, error) {
	var hdr [5]byte
	n, err := io.ReadFull(rd.r, hdr[:])
	if err != nil {
		if errors.Is(err, io.EOF) && n == 0 {
			return nil, io.EOF // 帧边界干净结束
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, &ProtocolError{Kind: "truncated_header", Detail: fmt.Sprintf("frame prefix %d/5 bytes", n)}
		}
		return nil, err // 底层源错误（如 ctx 取消）原样透传
	}
	if hdr[0]&^byte(0x01) != 0 {
		return nil, &ProtocolError{Kind: "reserved_flag_bits", Detail: fmt.Sprintf("flag byte 0x%02x", hdr[0])}
	}
	compressed := hdr[0]&0x01 != 0
	declared := int64(binary.BigEndian.Uint32(hdr[1:5]))

	// 四重预算逐层：先验证声明长度再分配
	if declared > rd.cfg.MaxMessageBytes {
		return nil, &BudgetError{Kind: "message_bytes", Limit: rd.cfg.MaxMessageBytes, Actual: declared}
	}
	if rd.messages+1 > rd.cfg.MaxMessages {
		return nil, &BudgetError{Kind: "message_count", Limit: int64(rd.cfg.MaxMessages), Actual: int64(rd.messages + 1)}
	}
	if rd.totalDeclared+declared > rd.cfg.MaxRequestBytes {
		return nil, &BudgetError{Kind: "request_bytes", Limit: rd.cfg.MaxRequestBytes, Actual: rd.totalDeclared + declared}
	}
	if !rd.cfg.Global.TryAcquire(declared) {
		return nil, &BudgetError{Kind: "global_budget", Limit: rd.cfg.Global.Limit(), Actual: rd.cfg.Global.Used() + declared}
	}

	// 全部预算通过，按声明长度分配并读满
	body := make([]byte, declared)
	if _, err := io.ReadFull(rd.r, body); err != nil {
		rd.cfg.Global.Release(declared)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, &ProtocolError{Kind: "truncated_body", Detail: fmt.Sprintf("message %d declared %d bytes, body short", rd.messages+1, declared)}
		}
		return nil, err
	}
	rd.held += declared
	rd.messages++
	rd.totalDeclared += declared
	return &Frame{Index: rd.messages, Compressed: compressed, Body: body}, nil
}

// Messages 已重组消息数（覆盖读数）。
func (rd *Reader) Messages() int { return rd.messages }

// TotalDeclared 已重组消息声明合计（覆盖读数）。
func (rd *Reader) TotalDeclared() int64 { return rd.totalDeclared }

// Close 释放全局预算持有（幂等；请求生命周期终点调用——读取器随请求销毁）。
func (rd *Reader) Close() error {
	rd.releaseHeld()
	return nil
}

// Drain 丢弃后续体（§1.2 畸形处置：畸形后不再走帧，剩余字节读出即弃——
// 返回丢弃字节数；底层错误原样返回）。
func (rd *Reader) Drain() (int64, error) {
	return io.Copy(io.Discard, rd.r)
}

func (rd *Reader) releaseHeld() {
	if rd.held > 0 {
		rd.cfg.Global.Release(rd.held)
		rd.held = 0
	}
}
