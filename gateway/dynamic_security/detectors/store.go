package detectors

import (
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 检测器计数存储可插拔（docs/API_MICRO_MODELS.md §四第 9 项、docs/API_BEHAVIOR_ANALYSIS.md §八）：
// behavior/apiwrite/credrate/objrate/tenrate/actionrate/grouprate 滑窗、quota_hour/quota_day 定窗配额、resource 对象游标与对象集合、
// envanomaly 跨 IP 集合与并发计数、webshellc2 加密 WebShell C&C 会话统计。
// 默认全部为进程内 LRU 实现；装配层（jiuzhang_guard）可按 behavior_store 配置
// 为已接入的存储注入 Valkey 实现。对象集合窗口使用 Valkey 时为共享原子计数；
// memory 模式或故障降级期间各节点独立计数，不宣称这些阶段的集群级视图。
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
	// DefaultStoreCapacity 内存存储默认 LRU 容量（滑窗、配额、对象及环境异常等存储同为 10000）。
	DefaultStoreCapacity = 10000
	// ObjectEnumerationWindow 对象枚举滚动窗口（首次访问起 60 秒，与自然分钟窗口不同）。
	ObjectEnumerationWindow = objectEnumerationWindow
	// ObjectEnumerationMinObjects 连续序列信号所需最少不同对象数。
	ObjectEnumerationMinObjects = objectEnumerationMinObjects
	// ObjectEnumerationMinSequence 连续序列信号所需最少递增步进数。
	ObjectEnumerationMinSequence = objectEnumerationMinSequence
	// ObjectEnumerationHighCardinality 异常对象集合独立告警阈值。
	ObjectEnumerationHighCardinality = objectEnumerationHighCardinality
	// ObjectEnumerationMaxObjects 每窗口最多保留的 HMAC 对象引用数。
	ObjectEnumerationMaxObjects = objectEnumerationMaxObjects
)

// WindowStore 滑窗计数存储（behavior/apiwrite/credrate/objrate/tenrate/actionrate/grouprate 共用自然分钟窗口形态）。
type WindowStore interface {
	// AddAndCount 记录一次命中，返回当前窗口计数与已完成窗口样本（升序，封顶 MaxHistoryWindows；
	// 窗口按自然分钟对齐，空窗不补零——与 windowTracker 同一纪律）。
	AddAndCount(key string) (count int, history []int)
}

// QuotaStore 小时/日配额定窗计数存储（跨窗重置，不保留历史样本）。
type QuotaStore interface {
	AddAndCount(key string) int
}

// ObjectCursorStore 对象 ID 游标存储（连续数字 ID 遍历识别）。
type ObjectCursorStore interface {
	// Consecutive 记录本次对象 ID；返回是否紧邻上一 ID（id == prev+1）。
	Consecutive(key string, id int64) bool
}

// ObjectEnumerationStore 可信主体对象集合窗口存储。ref/nextRef 必须是已完成
// 域分隔的 HMAC，存储不得接收原始对象标识。默认实现为单节点有界内存窗口。
type ObjectEnumerationStore interface {
	ObserveObject(key, ref, nextRef string) ObjectEnumerationResult
}

// IPSpreadStore 同凭据/同设备窗口 distinct 指纹集合存储。
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

// FlowSessionStore 业务流程会话状态存储（flow 流程偏离检测用；语义与 flow.go
// 进程内存实现一致：会话空闲超 FlowSessionTTL 重置，步骤集合/对象状态/幂等键
// 槽位定容，重复提交短窗 FlowDuplicateWindow）。
type FlowSessionStore interface {
	// Observe 记录一次步骤观测，返回会话快照（Before 字段为记录前状态，
	// SeenSteps/DuplicateCount 含本次，字段语义见 FlowSessionSnapshot）。
	Observe(key string, o FlowObservation) FlowSessionSnapshot
}

// StoreOverrides 检测器计数存储注入集合：nil 字段 = 该检测面维持进程内默认实现。
type StoreOverrides struct {
	BehaviorWindow       WindowStore            // behavior 行为基线滑窗
	APIWriteWindow       WindowStore            // apiwrite 写限速滑窗（与行为滑窗键空间须隔离）
	CredentialRateWindow WindowStore            // 凭据每分钟限速滑窗（独立键空间）
	ObjectRateWindow     WindowStore            // 对象每分钟限速滑窗（独立键空间）
	TenantRateWindow     WindowStore            // 可信租户每分钟限速滑窗（独立键空间）
	ActionRateWindow     WindowStore            // 操作动作每分钟限速滑窗（独立键空间）
	GroupRateWindow      WindowStore            // 业务功能接口组每分钟限速滑窗（独立键空间）
	HourlyQuota          QuotaStore             // 身份+端点自然小时配额（独立键空间）
	DailyQuota           QuotaStore             // 身份+端点 UTC 自然日配额（独立键空间）
	ObjectCursor         ObjectCursorStore      // resource 对象 ID 游标
	ObjectEnumeration    ObjectEnumerationStore // resource 可信主体对象集合窗口（默认单节点内存）
	IPSpread             IPSpreadStore          // 同凭据跨 IP 跳变集合
	Concurrency          ConcurrencyStore       // 同凭据 in-flight 并发计数
	WebShellC2Session    WebShellC2SessionStore // webshellc2 加密 WebShell C&C 会话统计
	FlowSession          FlowSessionStore       // flow 业务流程会话状态（§44）
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

type memoryQuotaStore struct{ t *fixedWindowTracker }

func (m memoryQuotaStore) AddAndCount(key string) int { return m.t.add(key) }

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

// NewMemoryQuotaStore 构造进程内小时/日配额定窗存储（复用 fixedWindowTracker；
// capacity≤0 取 DefaultStoreCapacity，now 语义同 NewMemoryWindowStore）。
func NewMemoryQuotaStore(window time.Duration, capacity int, now func() time.Time) QuotaStore {
	if capacity <= 0 {
		capacity = DefaultStoreCapacity
	}
	return memoryQuotaStore{t: newFixedWindowTracker(window, capacity, now)}
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

// NewMemoryFlowSessionStore 构造进程内流程会话存储（LRU 定容；capacity≤0 取
// DefaultStoreCapacity；now 语义同 NewMemoryWindowStore）。
func NewMemoryFlowSessionStore(capacity int, now func() time.Time) FlowSessionStore {
	if capacity <= 0 {
		capacity = DefaultStoreCapacity
	}
	return newFlowSessionTracker(capacity, now)
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

// credentialRateCounts 凭据每分钟限速滑窗计数（quota.go 用）。
func credentialRateCounts(ctx *dsctx.RequestContext, key string) (int, []int) {
	if o := storeOverridesFor(ctx); o != nil && o.CredentialRateWindow != nil {
		return o.CredentialRateWindow.AddAndCount(key)
	}
	return defaultCredentialRateTracker.add(key)
}

// objectRateCounts 对象每分钟限速滑窗计数（quota.go 用）。
func objectRateCounts(ctx *dsctx.RequestContext, key string) (int, []int) {
	if o := storeOverridesFor(ctx); o != nil && o.ObjectRateWindow != nil {
		return o.ObjectRateWindow.AddAndCount(key)
	}
	return defaultObjectRateTracker.add(key)
}

// defaultTenantRateTracker 可信租户限速的进程内默认滑窗（LRU 定容，进程重启清零）。
var defaultTenantRateTracker = newWindowTracker(DefaultStoreCapacity, nil)

// tenantRateCounts 可信租户每分钟限速滑窗计数。
func tenantRateCounts(ctx *dsctx.RequestContext, key string) (int, []int) {
	if o := storeOverridesFor(ctx); o != nil && o.TenantRateWindow != nil {
		return o.TenantRateWindow.AddAndCount(key)
	}
	return defaultTenantRateTracker.add(key)
}

// defaultActionRateTracker 操作动作限速的进程内默认滑窗（LRU 定容，进程重启清零）。
var defaultActionRateTracker = newWindowTracker(DefaultStoreCapacity, nil)

// actionRateCounts 操作动作每分钟限速滑窗计数（quota.go 用）。
func actionRateCounts(ctx *dsctx.RequestContext, key string) (int, []int) {
	if o := storeOverridesFor(ctx); o != nil && o.ActionRateWindow != nil {
		return o.ActionRateWindow.AddAndCount(key)
	}
	return defaultActionRateTracker.add(key)
}

// defaultGroupRateTracker 业务功能接口组限速的进程内默认滑窗（LRU 定容，进程重启清零）。
var defaultGroupRateTracker = newWindowTracker(DefaultStoreCapacity, nil)

// groupRateCounts 业务功能接口组每分钟限速滑窗计数（quota.go 用）。
func groupRateCounts(ctx *dsctx.RequestContext, key string) (int, []int) {
	if o := storeOverridesFor(ctx); o != nil && o.GroupRateWindow != nil {
		return o.GroupRateWindow.AddAndCount(key)
	}
	return defaultGroupRateTracker.add(key)
}

// hourlyQuotaCounts 自然小时配额定窗计数（quota.go 用）。
func hourlyQuotaCounts(ctx *dsctx.RequestContext, key string) int {
	if o := storeOverridesFor(ctx); o != nil && o.HourlyQuota != nil {
		return o.HourlyQuota.AddAndCount(key)
	}
	return defaultHourlyQuotaTracker.add(key)
}

// dailyQuotaCounts UTC 自然日配额定窗计数（quota.go 用）。
func dailyQuotaCounts(ctx *dsctx.RequestContext, key string) int {
	if o := storeOverridesFor(ctx); o != nil && o.DailyQuota != nil {
		return o.DailyQuota.AddAndCount(key)
	}
	return defaultDailyQuotaTracker.add(key)
}

// defaultMCPCallTracker MCP 调用预算进程内默认滑窗（mcpguard 用；
// 与写限速同一自然分钟定窗语义——max_calls_per_minute 即当前窗口计数上限；
// 多节点一致性以 behavior_store=valkey 共享存储为准，存储缺席按进程内如实披露）。
var defaultMCPCallTracker = newWindowTracker(DefaultStoreCapacity, nil)

// MCPCallCounts MCP 工具调用预算滑窗计数（mcpguard 导出调用点；behavior_store
// 配置 Valkey 时经 APIWriteWindow 命名空间共享（键前缀 mcpcall| 隔离写限速键形），
// 未配置/未绑定按进程内默认实现——与 flow 存储同纪律）。
func MCPCallCounts(ctx *dsctx.RequestContext, key string) (int, []int) {
	if o := storeOverridesFor(ctx); o != nil && o.APIWriteWindow != nil {
		return o.APIWriteWindow.AddAndCount(key)
	}
	return defaultMCPCallTracker.add(key)
}

// objectConsecutive 对象游标连续判定（resource.go 用）。
func objectConsecutive(ctx *dsctx.RequestContext, key string, id int64) bool {
	if o := storeOverridesFor(ctx); o != nil && o.ObjectCursor != nil {
		return o.ObjectCursor.Consecutive(key, id)
	}
	return defaultObjectTracker.consecutive(key, id)
}

// ipSpreadAdd distinct 指纹集合记录（envanomaly/group_control 用）。
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

// flowSessionObserve 流程会话观测记录（flow.go 用；注入优先，默认内存兜底）。
func flowSessionObserve(ctx *dsctx.RequestContext, key string, o FlowObservation) FlowSessionSnapshot {
	if ov := storeOverridesFor(ctx); ov != nil && ov.FlowSession != nil {
		return ov.FlowSession.Observe(key, o)
	}
	return defaultFlowSessionTracker.Observe(key, o)
}
