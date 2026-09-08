package detectors

import (
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 检测器计数存储可插拔（docs/API_MICRO_MODELS.md §四第 9 项、docs/API_BEHAVIOR_ANALYSIS.md §八）：
// behavior/ratelimit 滑窗、resource 对象游标、envanomaly 跨 IP 集合与并发计数、
// webshellc2 加密 WebShell C&C 会话统计
// 默认全部为进程内 LRU 实现（行为与既有版本逐字节一致）；装配层（jiuzhang_guard）
// 可按 behavior_store 配置注入 Valkey 实现，消除多节点计数盲区。
//
// 实现方契约：存储实现负责自身故障策略（Fail-open 时自行降级并告警，见
// jiuzhang_guard/behaviorstore），调用方不感知后端故障——检测语义不得因存储故障中断，
// 故接口方法不返回错误。

// 导出窗口常量（供装配层 Valkey 实现对齐同一窗口边界/样本上限/集合上限）。
const (
	// WindowSize 行为/限速统计窗口（= windowSize）。
	WindowSize = windowSize
	// MaxHistoryWindows 每键保留的历史窗口样本上限（= maxHistoryWindows）。
	MaxHistoryWindows = maxHistoryWindows
	// MaxSpreadIPsPerWindow 单键单窗口 distinct IP 指纹集合上限（= maxSpreadIPsPerWindow）。
	MaxSpreadIPsPerWindow = maxSpreadIPsPerWindow
	// DefaultStoreCapacity 内存存储默认 LRU 容量（behavior/apiwrite/object/envanomaly/webshellc2 同为 10000）。
	DefaultStoreCapacity = 10000
)

// WindowStore 滑窗计数存储（behavior 行为基线 / apiwrite 写限速共用形态）。
type WindowStore interface {
	// AddAndCount 记录一次命中，返回当前窗口计数与已完成窗口样本（升序，封顶 MaxHistoryWindows；
	// 窗口按自然分钟对齐，空窗不补零——与 windowTracker 同一纪律）。
	AddAndCount(key string) (count int, history []int)
}

// ObjectCursorStore 对象 ID 游标存储（连续数字 ID 遍历识别）。
type ObjectCursorStore interface {
	// Consecutive 记录本次对象 ID；返回是否紧邻上一 ID（id == prev+1）。
	Consecutive(key string, id int64) bool
}

// IPSpreadStore 同凭据窗口 distinct IP 指纹集合存储。
type IPSpreadStore interface {
	// AddDistinct 记录一次来源指纹，返回当前窗口 distinct 数（窗口滚动即重置）。
	AddDistinct(key, member string) int
}

// ConcurrencyStore 同凭据 in-flight 计数存储。
type ConcurrencyStore interface {
	// Acquire 并发 +1，返回当前并发数。
	Acquire(key string) int
	// Release 并发 -1（键不存在视为计数已丢失，静默返回；由调用方保证幂等配对）。
	Release(key string)
	// Current 读取当前并发数。
	Current(key string) int
}

// WebShellC2SessionStore 加密 WebShell C&C 会话统计存储（webshellc2 用；统计口径与
// webshellc2.go 进程内存实现一致：计数/和/平方和直接累加，布尔粘性置真，UA 族
// distinct 计数封顶，单值 16 MiB 钳制 + 单会话计数封顶保证 int64 不溢出）。
type WebShellC2SessionStore interface {
	// ObserveRequest 记录一次请求侧观测，返回更新后的会话统计快照。
	ObserveRequest(key string, o WebShellC2RequestStat) WebShellC2SessionStats
	// ObserveResponse 记录一次响应侧观测，返回更新后的会话统计快照。
	ObserveResponse(key string, o WebShellC2ResponseStat) WebShellC2SessionStats
}

// StoreOverrides 检测器计数存储注入集合：nil 字段 = 该检测面维持进程内默认实现。
type StoreOverrides struct {
	BehaviorWindow    WindowStore            // behavior 行为基线滑窗
	APIWriteWindow    WindowStore            // apiwrite 写限速滑窗（与行为滑窗键空间须隔离）
	ObjectCursor      ObjectCursorStore      // resource 对象 ID 游标
	IPSpread          IPSpreadStore          // 同凭据跨 IP 跳变集合
	Concurrency       ConcurrencyStore       // 同凭据 in-flight 并发计数
	WebShellC2Session WebShellC2SessionStore // webshellc2 加密 WebShell C&C 会话统计
}

// storeOverridesFor 读取管线绑定到本请求的存储选择。未绑定或显式绑定 nil
// 都使用默认内存，避免一个 Guard 的配置污染同进程中的其他 Guard。
func storeOverridesFor(ctx *dsctx.RequestContext) *StoreOverrides {
	if raw, bound := ctx.DetectorStoreOverrides(); bound {
		o, _ := raw.(*StoreOverrides)
		return o
	}
	return nil
}

// ---------- 默认内存实现适配（装配层 Fail-open 回退/测试用；与默认路径同一代码） ----------

type memoryWindowStore struct{ t *windowTracker }

func (m memoryWindowStore) AddAndCount(key string) (int, []int) { return m.t.add(key) }

type memoryObjectCursorStore struct{ t *objectTracker }

func (m memoryObjectCursorStore) Consecutive(key string, id int64) bool {
	return m.t.consecutive(key, id)
}

type memoryIPSpreadStore struct{ t *ipSpreadTracker }

func (m memoryIPSpreadStore) AddDistinct(key, member string) int { return m.t.add(key, member) }

type memoryConcurrencyStore struct{ t *credentialConcurrencyTracker }

func (m memoryConcurrencyStore) Acquire(key string) int { return m.t.acquire(key) }
func (m memoryConcurrencyStore) Release(key string)     { m.t.release(key) }
func (m memoryConcurrencyStore) Current(key string) int { return m.t.current(key) }

// NewMemoryWindowStore 构造进程内滑窗存储（LRU 定容；capacity≤0 取 DefaultStoreCapacity；
// now 为 nil 用系统时钟——装配层可注入与主存储一致的时钟保证降级期窗口边界确定性）。
func NewMemoryWindowStore(capacity int, now func() time.Time) WindowStore {
	if capacity <= 0 {
		capacity = DefaultStoreCapacity
	}
	return memoryWindowStore{t: newWindowTracker(capacity, now)}
}

// NewMemoryObjectCursorStore 构造进程内对象游标存储。
func NewMemoryObjectCursorStore(capacity int) ObjectCursorStore {
	if capacity <= 0 {
		capacity = DefaultStoreCapacity
	}
	return memoryObjectCursorStore{t: &objectTracker{entries: newLRU(capacity)}}
}

// NewMemoryIPSpreadStore 构造进程内跨 IP 集合存储（now 语义同 NewMemoryWindowStore）。
func NewMemoryIPSpreadStore(capacity int, now func() time.Time) IPSpreadStore {
	if capacity <= 0 {
		capacity = DefaultStoreCapacity
	}
	return memoryIPSpreadStore{t: newIPSpreadTracker(capacity, now)}
}

// NewMemoryConcurrencyStore 构造进程内并发计数存储。
func NewMemoryConcurrencyStore(capacity int) ConcurrencyStore {
	if capacity <= 0 {
		capacity = DefaultStoreCapacity
	}
	return memoryConcurrencyStore{t: &credentialConcurrencyTracker{entries: newLRU(capacity)}}
}

// NewMemoryWebShellC2SessionStore 构造进程内会话统计存储（LRU 定容；capacity≤0 取
// DefaultStoreCapacity）。追踪器方法集直接实现 WebShellC2SessionStore，无需适配层。
func NewMemoryWebShellC2SessionStore(capacity int) WebShellC2SessionStore {
	if capacity <= 0 {
		capacity = DefaultStoreCapacity
	}
	return newWebShellC2Tracker(capacity)
}

// ---------- 检测器调用侧路由（注入优先，默认内存兜底；各检测器仅改一行调用点） ----------

// behaviorCounts 行为基线滑窗计数（behavior.go 用）。
func behaviorCounts(ctx *dsctx.RequestContext, key string) (int, []int) {
	if o := storeOverridesFor(ctx); o != nil && o.BehaviorWindow != nil {
		return o.BehaviorWindow.AddAndCount(key)
	}
	return defaultBehaviorTracker.add(key)
}

// apiWriteCounts 写限速滑窗计数（ratelimit.go 用）。
func apiWriteCounts(ctx *dsctx.RequestContext, key string) (int, []int) {
	if o := storeOverridesFor(ctx); o != nil && o.APIWriteWindow != nil {
		return o.APIWriteWindow.AddAndCount(key)
	}
	return defaultAPIWriteTracker.add(key)
}

// objectConsecutive 对象游标连续判定（resource.go 用）。
func objectConsecutive(ctx *dsctx.RequestContext, key string, id int64) bool {
	if o := storeOverridesFor(ctx); o != nil && o.ObjectCursor != nil {
		return o.ObjectCursor.Consecutive(key, id)
	}
	return defaultObjectTracker.consecutive(key, id)
}

// ipSpreadAdd 跨 IP 集合记录（envanomaly.go 用）。
func ipSpreadAdd(ctx *dsctx.RequestContext, key, member string) int {
	if o := storeOverridesFor(ctx); o != nil && o.IPSpread != nil {
		return o.IPSpread.AddDistinct(key, member)
	}
	return defaultIPSpreadTracker.add(key, member)
}

// credentialInflightCurrent 当前并发数读取（envanomaly.go 用）。
func credentialInflightCurrent(ctx *dsctx.RequestContext, key string) int {
	if o := storeOverridesFor(ctx); o != nil && o.Concurrency != nil {
		return o.Concurrency.Current(key)
	}
	return defaultCredentialConcurrency.current(key)
}

// webShellC2ObserveRequest 加密 WebShell C&C 会话请求侧记录（webshellc2.go 用）。
func webShellC2ObserveRequest(key string, o WebShellC2RequestStat) WebShellC2SessionStats {
	return defaultWebShellC2Tracker.ObserveRequest(key, o)
}

// webShellC2ObserveRequestWithStores 使用调用方实例绑定的存储；stores=nil 明确走默认内存。
func webShellC2ObserveRequestWithStores(stores *StoreOverrides, key string, o WebShellC2RequestStat) WebShellC2SessionStats {
	if stores != nil && stores.WebShellC2Session != nil {
		return stores.WebShellC2Session.ObserveRequest(key, o)
	}
	return defaultWebShellC2Tracker.ObserveRequest(key, o)
}

// webShellC2ObserveResponse 加密 WebShell C&C 会话响应侧记录（webshellc2.go 用）。
func webShellC2ObserveResponse(ctx *dsctx.RequestContext, key string, o WebShellC2ResponseStat) WebShellC2SessionStats {
	if ov := storeOverridesFor(ctx); ov != nil && ov.WebShellC2Session != nil {
		return ov.WebShellC2Session.ObserveResponse(key, o)
	}
	return defaultWebShellC2Tracker.ObserveResponse(key, o)
}
