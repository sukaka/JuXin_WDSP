// Package metrics 网关进程内 API 动态防护指标（阶段8 任务书 §54 可行子集）。
//
// 数据源与口径：
//
//   - 请求解析耗时：parser.ParseRequest 全程埋点，进程内累计 count/sum/max（原子操作，
//     热路径无锁）；
//
//   - 进程内存占用：runtime.ReadMemStats 实时采样（Render/Snapshot 时读取，非累计值）。
//
//   - 检测耗时：pipeline.Process 请求相位检测段全程埋点；
//
//   - 响应解析耗时：pipeline.ProcessResponse 响应 JSON 解析段埋点；
//
//   - 事件积压：事件上报器装配点经 SetEventBacklog 写入队列深度（gauge；
//     未挂接时 Snapshot/Render 不输出该序列——未挂载不报假值）。
//
// 出口说明：网关当前无 Prometheus 抓取端点（docs/API_SECURITY_CURRENT_STATE.md），
// 本包提供进程内累计 + Snapshot/Render 文本输出，供后续状态端点/心跳通道消费。
//
// 指标名只允许本包枚举（防高基数与动态起名），Observe 对未注册名静默忽略。
package metrics

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// 耗时序列名（固定枚举）。值不带单位后缀；Render 输出时追加 _seconds_* 三段。
const (
	// ParseRequestDuration 请求解析耗时（parser.ParseRequest 全程，含各格式子解析）。
	ParseRequestDuration = "api_parse_request_duration"
	// DetectDuration 检测耗时（pipeline.Process 请求相位检测段全程，含统一决策）。
	DetectDuration = "api_detect_duration"
	// ResponseParseDuration 响应解析耗时（pipeline.ProcessResponse 响应 JSON 解析段）。
	ResponseParseDuration = "api_response_parse_duration"
)

// durationSeries 单序列累计（全部原子操作；调用方共享包级实例）。
type durationSeries struct {
	help  string
	count int64
	sumNs int64
	maxNs int64
}

func (s *durationSeries) observe(d time.Duration) {
	ns := int64(d)
	atomic.AddInt64(&s.count, 1)
	atomic.AddInt64(&s.sumNs, ns)
	for {
		cur := atomic.LoadInt64(&s.maxNs)
		if ns <= cur || atomic.CompareAndSwapInt64(&s.maxNs, cur, ns) {
			return
		}
	}
}

// durations 已注册耗时序列（固定集合，包初始化后即只读 map）。
var durations = map[string]*durationSeries{
	ParseRequestDuration:  {help: "请求解析耗时（parser.ParseRequest 全程）"},
	DetectDuration:        {help: "检测耗时（pipeline.Process 请求相位检测段全程，含统一决策）"},
	ResponseParseDuration: {help: "响应解析耗时（pipeline.ProcessResponse 响应 JSON 解析段）"},
}

// durationOrder Render 输出顺序（map 遍历序抖动会使 exposition 不稳定）。
var durationOrder = []string{ParseRequestDuration, DetectDuration, ResponseParseDuration}

// 事件积压 gauge 状态（setter 由事件上报器装配点挂接；未挂接不输出，不报假值）。
var (
	eventBacklog        int64
	eventBacklogMounted int64 // 0/1：SetEventBacklog 首次调用后置 1
)

// SetEventBacklog 写入事件上报器积压队列深度（gauge；负值按 0 计）。
// 挂接纪律：由事件上报器装配点在入队/补写后按真实队列深度写入；本包只存值不读队列。
func SetEventBacklog(depth int64) {
	if depth < 0 {
		depth = 0
	}
	atomic.StoreInt64(&eventBacklog, depth)
	atomic.StoreInt64(&eventBacklogMounted, 1)
}

// Observe 登记一次耗时观测；未注册序列名或非正时长静默忽略（埋点不得影响主流程）。
func Observe(name string, d time.Duration) {
	if s, ok := durations[name]; ok && d > 0 {
		s.observe(d)
	}
}

// Track 返回耗时观测收尾函数（defer 用法：defer metrics.Track(metrics.ParseRequestDuration)()）。
func Track(name string) func() {
	start := time.Now()
	return func() { Observe(name, time.Since(start)) }
}

// DurationStat 单序列快照（Sum/Max 为观测累计/峰值）。
type DurationStat struct {
	Count int64
	Sum   time.Duration
	Max   time.Duration
}

// Snapshot 进程指标快照（内存为采样瞬间值）。
type Snapshot struct {
	Durations      map[string]DurationStat
	MemAllocBytes  uint64 // runtime.MemStats.Alloc：当前堆存活对象占用
	HeapInuseBytes uint64 // runtime.MemStats.HeapInuse：堆在用跨度
	SysBytes       uint64 // runtime.MemStats.Sys：从 OS 取得的内存总量
	Goroutines     int    // runtime.NumGoroutine
	// EventBacklog 事件上报器积压队列深度（SetEventBacklog 最近一次写入值）
	EventBacklog int64
	// EventBacklogMounted 事件积压 setter 是否已挂接（false 时 Render 不输出该序列）
	EventBacklogMounted bool
}

// Snapshot 读取当前进程指标快照。
func ReadSnapshot() Snapshot {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	out := Snapshot{
		Durations:           make(map[string]DurationStat, len(durations)),
		MemAllocBytes:       ms.Alloc,
		HeapInuseBytes:      ms.HeapInuse,
		SysBytes:            ms.Sys,
		Goroutines:          runtime.NumGoroutine(),
		EventBacklog:        atomic.LoadInt64(&eventBacklog),
		EventBacklogMounted: atomic.LoadInt64(&eventBacklogMounted) == 1,
	}
	for name, s := range durations {
		out.Durations[name] = DurationStat{
			Count: atomic.LoadInt64(&s.count),
			Sum:   time.Duration(atomic.LoadInt64(&s.sumNs)),
			Max:   time.Duration(atomic.LoadInt64(&s.maxNs)),
		}
	}
	return out
}

// Render 输出当前快照的 Prometheus 文本 exposition。
// 耗时序列输出三段：_seconds_count（counter）/_seconds_sum（counter）/_seconds_max（gauge）。
func Render() string {
	return RenderSnapshot(ReadSnapshot())
}

// RenderSnapshot 渲染快照为 Prometheus 文本（纯函数，便于测试与装配复用）。
func RenderSnapshot(s Snapshot) string {
	var b strings.Builder
	for _, name := range durationOrder {
		st := s.Durations[name]
		help := durations[name].help
		fmt.Fprintf(&b, "# HELP %s_seconds %s（进程内累计统计）\n", name, help)
		fmt.Fprintf(&b, "# TYPE %s_seconds_count counter\n", name)
		fmt.Fprintf(&b, "%s_seconds_count %d\n", name, st.Count)
		fmt.Fprintf(&b, "# TYPE %s_seconds_sum counter\n", name)
		fmt.Fprintf(&b, "%s_seconds_sum %s\n", name, formatSeconds(st.Sum))
		fmt.Fprintf(&b, "# TYPE %s_seconds_max gauge\n", name)
		fmt.Fprintf(&b, "%s_seconds_max %s\n", name, formatSeconds(st.Max))
	}
	b.WriteString("# HELP process_memory_alloc_bytes 网关进程当前堆存活对象占用字节（runtime.ReadMemStats Alloc）\n")
	b.WriteString("# TYPE process_memory_alloc_bytes gauge\n")
	fmt.Fprintf(&b, "process_memory_alloc_bytes %d\n", s.MemAllocBytes)
	b.WriteString("# HELP process_memory_heap_inuse_bytes 网关进程堆在用跨度字节（runtime.ReadMemStats HeapInuse）\n")
	b.WriteString("# TYPE process_memory_heap_inuse_bytes gauge\n")
	fmt.Fprintf(&b, "process_memory_heap_inuse_bytes %d\n", s.HeapInuseBytes)
	b.WriteString("# HELP process_memory_sys_bytes 网关进程从 OS 取得的内存总量字节（runtime.ReadMemStats Sys）\n")
	b.WriteString("# TYPE process_memory_sys_bytes gauge\n")
	fmt.Fprintf(&b, "process_memory_sys_bytes %d\n", s.SysBytes)
	b.WriteString("# HELP process_goroutines 网关进程当前 goroutine 数\n")
	b.WriteString("# TYPE process_goroutines gauge\n")
	fmt.Fprintf(&b, "process_goroutines %d\n", s.Goroutines)
	if s.EventBacklogMounted {
		b.WriteString("# HELP api_event_backlog 事件上报器积压队列深度（装配点经 SetEventBacklog 写入）\n")
		b.WriteString("# TYPE api_event_backlog gauge\n")
		fmt.Fprintf(&b, "api_event_backlog %d\n", s.EventBacklog)
	}
	return b.String()
}

// formatSeconds 时长 → 秒文本（精度自适应，与 server 侧 float gauge 同一 FormatFloat 口径）。
func formatSeconds(d time.Duration) string {
	return strconv.FormatFloat(d.Seconds(), 'f', -1, 64)
}
