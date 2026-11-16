// Package behaviorstore API 动态防护计数存储的 Valkey 实现
// （docs/API_MICRO_MODELS.md §四第 9 项、docs/API_BEHAVIOR_ANALYSIS.md §八演进方向）。
//
// 设计纪律（复用阶段5 CC 防护已建立的 Valkey 键纪律）：
//   - 键前缀 jiuzhang:guard:api:<用途>:<sha256 截断哈希>，键材料一律经 counters.HashParts
//     哈希，禁止拼接原始输入（凭据指纹/端点路径/IP 均不落明文键）；
//   - 全部键带 TTL 自动过期（各类键有内置下限，可由 behavior_store_ttl_seconds 调高）；
//   - 计数经 Lua 脚本单次原子往返（HINCRBY/INCR/SADD + PEXPIRE），多节点并发安全；
//   - Fail-open：任何 Valkey 故障降级到进程内内存实现（detectors.NewMemory*，与默认
//     路径同一代码）并以 zap Warn 告警（每分钟节流），检测语义不中断；
//     故障期间的计数留在内存侧，恢复后 Valkey 侧基线可能滞后——OBSERVE 级信号可接受。
package behaviorstore

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
	"go.uber.org/zap"
)

// DefaultKeyPrefix Valkey 键前缀（阶段5 既有命名：jiuzhang:guard:cc / jiuzhang:guard:tempblocks）。
const DefaultKeyPrefix = "jiuzhang:guard:api"

// 键空间子用途（各滑窗及小时/日配额必须隔离命名空间防串计数）。
const (
	nsBehavior          = "behavior"
	nsAPIWrite          = "apiwrite"
	nsCredentialRate    = "credrate"
	nsObjectRate        = "objrate"
	nsTenantRate        = "tenrate"
	nsActionRate        = "actionrate"
	nsGroupRate         = "grouprate"
	nsHourlyQuota       = "quota_hour"
	nsDailyQuota        = "quota_day"
	nsObjectCursor      = "objcur"
	nsObjectEnumeration = "objenum"
	nsIPSpread          = "ipspread"
	nsConcurrency       = "concur"
)

// 各类键 TTL 内置下限：窗口键须覆盖历史样本跨度（10 个历史窗 + 当前窗 + 1 窗余量）；
// distinct 集合为窗口级键（键名含窗口起点，滚动即换新键）；对象游标/并发计数在内存实现中
// 无时间界（仅 LRU 定容），Valkey 侧给保守下限防无限堆积；并发计数 TTL 同时承担
// 节点崩溃未释放的脏计数清理。对象枚举为首次访问起 60 秒滚动窗口，TTL 另留一个窗口余量。
// 小时/日配额键的哈希材料含自然窗口起点，TTL 分别保留两个完整窗口。
const (
	windowTTLFloor            = (detectors.MaxHistoryWindows + 2) * detectors.WindowSize // 12min
	spreadTTLFloor            = 2 * detectors.WindowSize                                 // 2min
	objectEnumerationTTLFloor = 2 * detectors.ObjectEnumerationWindow
	hourlyQuotaTTLFloor       = 2 * time.Hour
	dailyQuotaTTLFloor        = 48 * time.Hour
	cursorTTLFloor            = time.Hour
	concurTTLFloor            = 5 * time.Minute
)

// defaultOpTimeout 单次 Eval 超时上限。行为计数在请求热路径，Valkey 与网关同机/同网段，
// 正常往返毫秒级；300ms 既留足余量，又保证 Valkey 悬挂（TCP 活但不响应）时
// Fail-open 亚秒内触发、请求 goroutine 阻塞时间有界。
const defaultOpTimeout = 300 * time.Millisecond

// errEmptyEvalResult Lua 返回空数组（不应发生；按故障走 Fail-open）。
var errEmptyEvalResult = errors.New("behaviorstore: empty eval result")

// eval 单次 Eval 包装：固定 defaultOpTimeout 超时，超时/错误由调用方走既有
// Fail-open 降级。不从请求 ctx 派生：Release 路径在请求结束后才执行（请求 ctx
// 已取消，派生会立即失败），且各操作独立计时、与请求生命周期解耦。
func (s *Store) eval(script string, keys []string, args []string) ([]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultOpTimeout)
	defer cancel()
	return s.cli.Eval(ctx, script, keys, args)
}

// windowAddLua 窗口计数哈希：field=窗口起点秒，value=计数。原子完成
// 当前窗 +1 → 汇总已完成窗口（升序、封顶 maxHist、淘汰更老 field）→ 刷新 TTL。
// 返回 {当前窗计数, 已完成窗计数...（升序）}；空窗不补零（field 仅存在于有命中的窗口），
// 与进程内 windowTracker 的样本语义一致。
const windowAddLua = `
local cur = redis.call('HINCRBY', KEYS[1], ARGV[1], 1)
local curW = tonumber(ARGV[1])
local maxHist = tonumber(ARGV[2])
local all = redis.call('HGETALL', KEYS[1])
local windows = {}
local counts = {}
for i = 1, #all, 2 do
  local w = tonumber(all[i])
  if w < curW then
    windows[#windows + 1] = w
    counts[w] = tonumber(all[i + 1])
  end
end
table.sort(windows)
if #windows > maxHist then
  local drop = {}
  for i = 1, #windows - maxHist do
    drop[#drop + 1] = tostring(windows[i])
  end
  redis.call('HDEL', KEYS[1], unpack(drop))
  local kept = {}
  for i = #windows - maxHist + 1, #windows do
    kept[#kept + 1] = windows[i]
  end
  windows = kept
end
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[3]))
local out = {cur}
for _, w in ipairs(windows) do
  out[#out + 1] = counts[w]
end
return out
`

// quotaAddLua 小时/日配额定窗计数：窗口起点已进入键哈希，原子 INCR 并刷新 TTL。
const quotaAddLua = `
local v = redis.call('INCR', KEYS[1])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[1]))
return {v}
`

// cursorSetLua 对象游标：读旧值 → 写新值 → 刷新 TTL，返回 {是否紧邻上一 ID（id==prev+1）}。
const cursorSetLua = `
local prev = redis.call('GET', KEYS[1])
redis.call('SET', KEYS[1], ARGV[1])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]))
if prev and tonumber(prev) + 1 == tonumber(ARGV[1]) then
  return {1}
end
return {0}
`

// spreadAddLua 窗口级 distinct 集合（键名含窗口起点）：达上限不再新增（远超判定阈值，
// 不影响检测结论；防 botnet 泛洪撑爆内存——与内存实现 maxSpreadIPsPerWindow 同一纪律）。
const spreadAddLua = `
local cap = tonumber(ARGV[2])
local n = redis.call('SCARD', KEYS[1])
if n < cap then
  redis.call('SADD', KEYS[1], ARGV[1])
  n = redis.call('SCARD', KEYS[1])
end
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[3]))
return {n}
`

// concurAcquireLua 并发 +1 并刷新 TTL。
const concurAcquireLua = `
local v = redis.call('INCR', KEYS[1])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[1]))
return {v}
`

// concurReleaseLua 并发 -1（下界 0；键已过期/不存在视为计数已丢失，不重建）。
const concurReleaseLua = `
local v = redis.call('GET', KEYS[1])
if not v then
  return {0}
end
v = tonumber(v) - 1
if v < 0 then
  v = 0
end
redis.call('SET', KEYS[1], v)
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[1]))
return {v}
`

// concurCurrentLua 当前并发数读取（无键 = 0）。
const concurCurrentLua = `
local v = redis.call('GET', KEYS[1])
if not v then
  return {0}
end
return {tonumber(v)}
`

// Store Valkey 计数存储：同时实现对象游标/跨 IP 集合/并发计数接口，
// 滑窗与小时/日配额经 Overrides() 按独立命名空间适配。
type Store struct {
	cli    counters.ValkeyClient
	pfx    string
	ttl    time.Duration // 配置覆盖（behavior_store_ttl_seconds）；≤内置下限时用下限
	now    func() time.Time
	logger *zap.Logger

	mu       sync.Mutex
	lastWarn time.Time // Warn 节流（每分钟最多一条，防日志洪泛）

	// Fail-open 内存回退（与 detectors 默认实现同一代码；各自独立实例，不回灌包级默认追踪器）
	memBehavior       detectors.WindowStore
	memAPIWrite       detectors.WindowStore
	memCredentialRate detectors.WindowStore
	memObjectRate     detectors.WindowStore
	memTenantRate     detectors.WindowStore
	memActionRate     detectors.WindowStore
	memGroupRate      detectors.WindowStore
	memHourlyQuota    detectors.QuotaStore
	memDailyQuota     detectors.QuotaStore
	memCursor         detectors.ObjectCursorStore
	memEnumeration    detectors.ObjectEnumerationStore
	memSpread         detectors.IPSpreadStore
	memConcur         detectors.ConcurrencyStore
}

// New 构造 Valkey 计数存储（keyPrefix 空取 DefaultKeyPrefix；ttl≤0 全部用内置下限；
// logger 为 nil 时降级告警静默——装配层必须传 logger）。
// 内存回退实例与主存储共用同一时钟源（闭包转发，测试注入时钟对降级路径同样确定）。
func New(cli counters.ValkeyClient, keyPrefix string, ttl time.Duration, logger *zap.Logger) *Store {
	if keyPrefix == "" {
		keyPrefix = DefaultKeyPrefix
	}
	s := &Store{
		cli:    cli,
		pfx:    keyPrefix,
		ttl:    ttl,
		now:    time.Now,
		logger: logger,
	}
	nowFn := func() time.Time { return s.now() }
	s.memBehavior = detectors.NewMemoryWindowStore(detectors.DefaultStoreCapacity, nowFn)
	s.memAPIWrite = detectors.NewMemoryWindowStore(detectors.DefaultStoreCapacity, nowFn)
	s.memCredentialRate = detectors.NewMemoryWindowStore(detectors.DefaultStoreCapacity, nowFn)
	s.memObjectRate = detectors.NewMemoryWindowStore(detectors.DefaultStoreCapacity, nowFn)
	s.memTenantRate = detectors.NewMemoryWindowStore(detectors.DefaultStoreCapacity, nowFn)
	s.memActionRate = detectors.NewMemoryWindowStore(detectors.DefaultStoreCapacity, nowFn)
	s.memGroupRate = detectors.NewMemoryWindowStore(detectors.DefaultStoreCapacity, nowFn)
	s.memHourlyQuota = detectors.NewMemoryQuotaStore(time.Hour, detectors.DefaultStoreCapacity, nowFn)
	s.memDailyQuota = detectors.NewMemoryQuotaStore(24*time.Hour, detectors.DefaultStoreCapacity, nowFn)
	s.memCursor = detectors.NewMemoryObjectCursorStore(detectors.DefaultStoreCapacity)
	s.memEnumeration = detectors.NewMemoryObjectEnumerationStore(detectors.DefaultStoreCapacity, nowFn)
	s.memSpread = detectors.NewMemoryIPSpreadStore(detectors.DefaultStoreCapacity, nowFn)
	s.memConcur = detectors.NewMemoryConcurrencyStore(detectors.DefaultStoreCapacity)
	return s
}

// windowStoreAdapter 滑窗接口适配（同一 Store、不同键命名空间）。
type windowStoreAdapter struct {
	s  *Store
	ns string
}

func (a windowStoreAdapter) AddAndCount(key string) (int, []int) {
	return a.s.windowAdd(a.ns, key)
}

// quotaStoreAdapter 小时/日配额定窗接口适配。
type quotaStoreAdapter struct {
	s        *Store
	ns       string
	window   time.Duration
	ttlFloor time.Duration
}

func (a quotaStoreAdapter) AddAndCount(key string) int {
	return a.s.quotaAdd(a.ns, a.window, a.ttlFloor, key)
}

// Overrides 导出检测器存储注入集合（由 pipeline.Config.Stores 按请求绑定）。
func (s *Store) Overrides() *detectors.StoreOverrides {
	return &detectors.StoreOverrides{
		BehaviorWindow:       windowStoreAdapter{s: s, ns: nsBehavior},
		APIWriteWindow:       windowStoreAdapter{s: s, ns: nsAPIWrite},
		CredentialRateWindow: windowStoreAdapter{s: s, ns: nsCredentialRate},
		ObjectRateWindow:     windowStoreAdapter{s: s, ns: nsObjectRate},
		TenantRateWindow:     windowStoreAdapter{s: s, ns: nsTenantRate},
		ActionRateWindow:     windowStoreAdapter{s: s, ns: nsActionRate},
		GroupRateWindow:      windowStoreAdapter{s: s, ns: nsGroupRate},
		HourlyQuota:          quotaStoreAdapter{s: s, ns: nsHourlyQuota, window: time.Hour, ttlFloor: hourlyQuotaTTLFloor},
		DailyQuota:           quotaStoreAdapter{s: s, ns: nsDailyQuota, window: 24 * time.Hour, ttlFloor: dailyQuotaTTLFloor},
		ObjectCursor:         s,
		ObjectEnumeration:    s,
		IPSpread:             s,
		Concurrency:          s,
	}
}

// ttlFor 有效 TTL：配置值大于内置下限时生效，否则用下限。
func (s *Store) ttlFor(floor time.Duration) time.Duration {
	if s.ttl > floor {
		return s.ttl
	}
	return floor
}

// warn Fail-open 告警（每分钟节流一条）。
func (s *Store) warn(op string, err error) {
	if s.logger == nil {
		return
	}
	s.mu.Lock()
	now := s.now()
	if !s.lastWarn.IsZero() && now.Sub(s.lastWarn) < time.Minute {
		s.mu.Unlock()
		return
	}
	s.lastWarn = now
	s.mu.Unlock()
	s.logger.Warn("api behavior store valkey error, fail-open to memory",
		zap.String("op", op), zap.Error(err))
}

// memWindow 按命名空间取独立的内存回退滑窗。
func (s *Store) memWindow(ns string) detectors.WindowStore {
	switch ns {
	case nsAPIWrite:
		return s.memAPIWrite
	case nsCredentialRate:
		return s.memCredentialRate
	case nsObjectRate:
		return s.memObjectRate
	case nsTenantRate:
		return s.memTenantRate
	case nsActionRate:
		return s.memActionRate
	case nsGroupRate:
		return s.memGroupRate
	default:
		return s.memBehavior
	}
}

// windowAdd 行为/写限速/凭据/对象/租户/动作/接口组限速滑窗：当前自然分钟窗 +1，返回当前窗计数与已完成窗样本。
func (s *Store) windowAdd(ns, key string) (int, []int) {
	cur := s.now().UTC().Truncate(detectors.WindowSize).Unix()
	fullKey := s.pfx + ":" + ns + ":" + counters.HashParts(key)
	out, err := s.eval(windowAddLua, []string{fullKey}, []string{
		strconv.FormatInt(cur, 10),
		strconv.Itoa(detectors.MaxHistoryWindows),
		strconv.FormatInt(s.ttlFor(windowTTLFloor).Milliseconds(), 10),
	})
	if err == nil && len(out) == 0 {
		err = errEmptyEvalResult
	}
	if err != nil {
		s.warn(ns+".window_add", err)
		return s.memWindow(ns).AddAndCount(key)
	}
	count := int(luaInt(out[0]))
	hist := make([]int, 0, len(out)-1)
	for _, v := range out[1:] {
		hist = append(hist, int(luaInt(v)))
	}
	return count, hist
}

// memQuota 按命名空间取独立的小时/日配额内存回退。
func (s *Store) memQuota(ns string) detectors.QuotaStore {
	if ns == nsDailyQuota {
		return s.memDailyQuota
	}
	return s.memHourlyQuota
}

// quotaAdd 小时/日配额定窗计数；自然窗口起点进入键哈希，跨窗使用新键。
func (s *Store) quotaAdd(ns string, window, ttlFloor time.Duration, key string) int {
	cur := s.now().UTC().Truncate(window).Unix()
	fullKey := s.pfx + ":" + ns + ":" + counters.HashParts(key, strconv.FormatInt(cur, 10))
	out, err := s.eval(quotaAddLua, []string{fullKey}, []string{
		strconv.FormatInt(s.ttlFor(ttlFloor).Milliseconds(), 10),
	})
	if err == nil && len(out) == 0 {
		err = errEmptyEvalResult
	}
	if err != nil {
		s.warn(ns+".quota_add", err)
		return s.memQuota(ns).AddAndCount(key)
	}
	return int(luaInt(out[0]))
}

// Consecutive 对象游标（detectors.ObjectCursorStore 实现）。
func (s *Store) Consecutive(key string, id int64) bool {
	fullKey := s.pfx + ":" + nsObjectCursor + ":" + counters.HashParts(key)
	out, err := s.eval(cursorSetLua, []string{fullKey}, []string{
		strconv.FormatInt(id, 10),
		strconv.FormatInt(s.ttlFor(cursorTTLFloor).Milliseconds(), 10),
	})
	if err == nil && len(out) == 0 {
		err = errEmptyEvalResult
	}
	if err != nil {
		s.warn("object_cursor", err)
		return s.memCursor.Consecutive(key, id)
	}
	return luaInt(out[0]) == 1
}

// AddDistinct 同凭据窗口 distinct IP 集合（detectors.IPSpreadStore 实现）。
// 键名含窗口起点（自然分钟对齐），窗口滚动即换新键，旧键 TTL 自动过期。
func (s *Store) AddDistinct(key, member string) int {
	win := s.now().UTC().Truncate(detectors.WindowSize).Unix()
	fullKey := s.pfx + ":" + nsIPSpread + ":" + counters.HashParts(key) + ":" + strconv.FormatInt(win, 10)
	out, err := s.eval(spreadAddLua, []string{fullKey}, []string{
		member,
		strconv.Itoa(detectors.MaxSpreadIPsPerWindow),
		strconv.FormatInt(s.ttlFor(spreadTTLFloor).Milliseconds(), 10),
	})
	if err == nil && len(out) == 0 {
		err = errEmptyEvalResult
	}
	if err != nil {
		s.warn("ip_spread", err)
		return s.memSpread.AddDistinct(key, member)
	}
	return int(luaInt(out[0]))
}

// Acquire 同凭据并发 +1（detectors.ConcurrencyStore 实现）。
func (s *Store) Acquire(key string) int {
	fullKey := s.pfx + ":" + nsConcurrency + ":" + counters.HashParts(key)
	out, err := s.eval(concurAcquireLua, []string{fullKey}, []string{
		strconv.FormatInt(s.ttlFor(concurTTLFloor).Milliseconds(), 10),
	})
	if err == nil && len(out) == 0 {
		err = errEmptyEvalResult
	}
	if err != nil {
		s.warn("concurrency_acquire", err)
		return s.memConcur.Acquire(key)
	}
	return int(luaInt(out[0]))
}

// Release 同凭据并发 -1（detectors.ConcurrencyStore 实现）。
// Fail-open 说明：Acquire 落 Valkey 而 Release 遇故障时，Valkey 侧计数由 TTL 兜底清理，
// 内存侧对未记账键的 release 为空操作，两侧互不击穿。
func (s *Store) Release(key string) {
	fullKey := s.pfx + ":" + nsConcurrency + ":" + counters.HashParts(key)
	_, err := s.eval(concurReleaseLua, []string{fullKey}, []string{
		strconv.FormatInt(s.ttlFor(concurTTLFloor).Milliseconds(), 10),
	})
	if err != nil {
		s.warn("concurrency_release", err)
		s.memConcur.Release(key)
	}
}

// Current 当前并发数（detectors.ConcurrencyStore 实现）。
func (s *Store) Current(key string) int {
	fullKey := s.pfx + ":" + nsConcurrency + ":" + counters.HashParts(key)
	out, err := s.eval(concurCurrentLua, []string{fullKey}, nil)
	if err == nil && len(out) == 0 {
		err = errEmptyEvalResult
	}
	if err != nil {
		s.warn("concurrency_current", err)
		return s.memConcur.Current(key)
	}
	return int(luaInt(out[0]))
}

// luaInt 解析 Lua 返回值（int64 或数字字符串）。
func luaInt(v interface{}) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	default:
		return 0
	}
}
