package identitybehavior

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
	"go.uber.org/zap"
)

// DefaultKeyPrefix Valkey 键前缀（与 jiuzhang:guard:cc / jiuzhang:guard:api 同一命名纪律）。
const DefaultKeyPrefix = "jiuzhang:guard:ibh"

// opTimeout 单次 Eval 超时上限（行为计数在请求收束路径；300ms 保证 Valkey 悬挂时
// fail-open 亚秒内触发、请求 goroutine 阻塞有界——与 behaviorstore 同一取值）。
const opTimeout = 300 * time.Millisecond

// 键 TTL：桶键覆盖 current+previous 两桶（2×窗口）；known-URI HLL 48h；
// method 集合与参数签名 HLL 30m（与方法枚举/参数变异判定窗口一致）。
const (
	knownTTLMs = int64(48 * time.Hour / time.Millisecond)
	auxTTLMs   = int64(30 * time.Minute / time.Millisecond)
)

// errBadEvalResult Lua 返回数量不符（不应发生；按故障走 fail-open）。
var errBadEvalResult = errors.New("identitybehavior: unexpected eval result length")

// observeLua 单请求全量记账单 round-trip：
//   - KEYS[1..8]   计数桶哈希（每窗口 current+previous，按窗口对齐，桶起点在键名）；
//   - KEYS[9..16]  URI 去重 HLL 桶（同上双桶；PFCOUNT 合并两桶估计）；
//   - KEYS[17]     全局 known-URI HLL（48h；PFADD 返回变化即 new_uri）；
//   - KEYS[18]     (identity,uri) distinct method 集合（30m）；
//   - KEYS[19]     (identity,uri) 参数签名 HLL（30m；PFADD 变化即参数变异）；
//   - KEYS[20..27] 账号标识 HLL（各窗口 current+previous）；
//   - KEYS[28..35] 对象标识 HLL（各窗口 current+previous）；
//   - ARGV[1..7]   status / sensitive / method / paramsig / uriMember / accountMember / objectMember；
//   - ARGV[8..11]  各窗口当前桶已流逝秒数（elapsed，估值权重用）；
//   - ARGV[12..15] 各窗口时长秒数；ARGV[16..19] 各窗口桶 TTL ms；
//   - ARGV[20]     known TTL ms；ARGV[21] method/paramsig TTL ms。
//
// 返回 67 个 int64：每窗口 10 个计数估值（×1000 缩放：current + previous×(dur-elapsed)/dur）
// + URI/account/object 三个 unique（PFCOUNT 原始估计），窗口序 1m/5m/30m/24h；随后 distinct method 数
// 与参数签名新旧（0/1）；末尾 13 个为 1m 上一桶原始计数（未缩放整数，字段序同 fields）
// 与 1m 上一桶 URI/account/object unique（PFCOUNT）——完成桶回放用。HLL 近似语义：unique 与 paramsig
// 新旧的假阳/假阴率有界，OBSERVE 级信号可接受。
const observeLua = `
local status = tonumber(ARGV[1])
local sensitive = tonumber(ARGV[2])
local method = ARGV[3]
local paramsig = ARGV[4]
local uriMember = ARGV[5]
local accountMember = ARGV[6]
local objectMember = ARGV[7]

local paramNew = 0
if paramsig ~= "" then
  paramNew = redis.call('PFADD', KEYS[19], paramsig)
end
redis.call('PEXPIRE', KEYS[19], tonumber(ARGV[21]))

redis.call('SADD', KEYS[18], method)
local mcount = redis.call('SCARD', KEYS[18])
redis.call('PEXPIRE', KEYS[18], tonumber(ARGV[21]))

local knownNew = redis.call('PFADD', KEYS[17], uriMember)
redis.call('PEXPIRE', KEYS[17], tonumber(ARGV[20]))

local fields = {'req','s401','s403','s404','s405','s500','authf','pmut','sens','newuri'}
local out = {}
local prev1m = nil
local prevH1m = nil
for i = 0, 3 do
  local curC = KEYS[1 + i * 2]
  local prevC = KEYS[2 + i * 2]
  local curH = KEYS[9 + i * 2]
  local prevH = KEYS[10 + i * 2]
  local accCurH = KEYS[20 + i * 2]
  local accPrevH = KEYS[21 + i * 2]
  local objCurH = KEYS[28 + i * 2]
  local objPrevH = KEYS[29 + i * 2]
  local elapsed = tonumber(ARGV[8 + i])
  local dur = tonumber(ARGV[12 + i])
  local ttl = tonumber(ARGV[16 + i])

  redis.call('HINCRBY', curC, 'req', 1)
  if status == 401 then
    redis.call('HINCRBY', curC, 's401', 1)
    redis.call('HINCRBY', curC, 'authf', 1)
  elseif status == 403 then
    redis.call('HINCRBY', curC, 's403', 1)
  elseif status == 404 then
    redis.call('HINCRBY', curC, 's404', 1)
  elseif status == 405 then
    redis.call('HINCRBY', curC, 's405', 1)
  elseif status == 500 then
    redis.call('HINCRBY', curC, 's500', 1)
  end
  if paramNew == 1 then redis.call('HINCRBY', curC, 'pmut', 1) end
  if sensitive == 1 then redis.call('HINCRBY', curC, 'sens', 1) end
  if knownNew == 1 then redis.call('HINCRBY', curC, 'newuri', 1) end
  redis.call('PEXPIRE', curC, ttl)

  redis.call('PFADD', curH, uriMember)
  redis.call('PEXPIRE', curH, ttl)
  if accountMember ~= "" then redis.call('PFADD', accCurH, accountMember) end
  redis.call('PEXPIRE', accCurH, ttl)
  if objectMember ~= "" then redis.call('PFADD', objCurH, objectMember) end
  redis.call('PEXPIRE', objCurH, ttl)

  local cur = {}
  local cv = redis.call('HGETALL', curC)
  for j = 1, #cv, 2 do cur[cv[j]] = tonumber(cv[j + 1]) end
  local prev = {}
  local pv = redis.call('HGETALL', prevC)
  for j = 1, #pv, 2 do prev[pv[j]] = tonumber(pv[j + 1]) end
  if i == 0 then
    prev1m = prev
    prevH1m = prevH
  end

  local remain = dur - elapsed
  if remain < 0 then remain = 0 end
  for _, f in ipairs(fields) do
    local c = cur[f] or 0
    local p = prev[f] or 0
    out[#out + 1] = c * 1000 + math.floor(p * remain * 1000 / dur)
  end
  out[#out + 1] = redis.call('PFCOUNT', curH, prevH)
  out[#out + 1] = redis.call('PFCOUNT', accCurH, accPrevH)
  out[#out + 1] = redis.call('PFCOUNT', objCurH, objPrevH)
end
out[#out + 1] = mcount
out[#out + 1] = paramNew
for _, f in ipairs(fields) do
  out[#out + 1] = prev1m[f] or 0
end
out[#out + 1] = redis.call('PFCOUNT', prevH1m)
out[#out + 1] = redis.call('PFCOUNT', KEYS[21])
out[#out + 1] = redis.call('PFCOUNT', KEYS[29])
return out
`

// observeResultLen Lua 返回长度（4 窗口 × 13 + distinct method/paramsig 2 + 1m 完成桶回放 13）。
const observeResultLen = 4*13 + 2 + 13

// ValkeyStore Valkey 行为滑窗统计（跨节点共享；任何 Valkey 故障 fail-open 回退进程内存
// 并以 zap Warn 告警（节流 1/min），观测语义不中断——与 behaviorstore 同一纪律）。
type ValkeyStore struct {
	cli    counters.ValkeyClient
	pfx    string
	mem    *MemoryStore
	logger *zap.Logger
	now    func() time.Time

	mu       sync.Mutex
	lastWarn time.Time // Warn 节流（每分钟最多一条，防日志洪泛）
}

// NewValkeyStore 构造 Valkey 存储（mem 为 nil 时自建内存回退；keyPrefix 空取
// DefaultKeyPrefix；logger 为 nil 时告警静默——装配层必须传 logger）。
func NewValkeyStore(cli counters.ValkeyClient, mem *MemoryStore, logger *zap.Logger) *ValkeyStore {
	if mem == nil {
		mem = NewMemoryStore(0, logger)
	}
	return &ValkeyStore{
		cli:    cli,
		pfx:    DefaultKeyPrefix,
		mem:    mem,
		logger: logger,
		now:    time.Now,
	}
}

// Observe 单 Lua Eval 原子记账并解析快照；任何故障回退内存实现（fail-open）。
func (s *ValkeyStore) Observe(in ObserveInput) (*Snapshot, error) {
	snap, err := s.observeRemote(in)
	if err != nil {
		s.warn("observe", err)
		return s.mem.Observe(in)
	}
	return snap, nil
}

// observeRemote 远端记账：键材料一律 counters.HashParts（禁止拼接原始输入），
// 桶键名含窗口起点（滚动即换新键，旧键 TTL 自动过期）。
func (s *ValkeyStore) observeRemote(in ObserveInput) (*Snapshot, error) {
	now := s.now().UTC()
	ihash := counters.HashParts(in.IdentityKey)
	uhash := counters.HashParts(in.URI)

	keys := make([]string, 0, 35)
	args := make([]string, 0, 21)
	args = append(args,
		strconv.Itoa(in.Status),
		bool01(in.SensitivePath),
		in.Method,
		in.ParamSignature,
		uhash,
		in.AccountKey,
		in.ObjectKey,
	)
	// 计数桶键（cur+prev × 4 窗口）
	for w := Window1m; w < NumWindows; w++ {
		d := w.Duration()
		cur := now.Truncate(d)
		keys = append(keys, s.bucketKey("c", w, ihash, cur), s.bucketKey("c", w, ihash, cur.Add(-d)))
	}
	// URI 去重 HLL 桶键（cur+prev × 4 窗口）
	for w := Window1m; w < NumWindows; w++ {
		d := w.Duration()
		cur := now.Truncate(d)
		keys = append(keys, s.bucketKey("u", w, ihash, cur), s.bucketKey("u", w, ihash, cur.Add(-d)))
	}
	keys = append(keys,
		s.pfx+":k:"+ihash,
		s.pfx+":m:"+ihash+":"+uhash,
		s.pfx+":ps:"+ihash+":"+uhash,
	)
	for w := Window1m; w < NumWindows; w++ {
		d := w.Duration()
		cur := now.Truncate(d)
		keys = append(keys, s.bucketKey("a", w, ihash, cur), s.bucketKey("a", w, ihash, cur.Add(-d)))
	}
	for w := Window1m; w < NumWindows; w++ {
		d := w.Duration()
		cur := now.Truncate(d)
		keys = append(keys, s.bucketKey("o", w, ihash, cur), s.bucketKey("o", w, ihash, cur.Add(-d)))
	}
	// 各窗口 elapsed / dur / ttl 参数
	for w := Window1m; w < NumWindows; w++ {
		d := w.Duration()
		args = append(args, strconv.FormatInt(int64(now.Sub(now.Truncate(d)).Seconds()), 10))
	}
	for w := Window1m; w < NumWindows; w++ {
		args = append(args, strconv.FormatInt(int64(w.Duration().Seconds()), 10))
	}
	for w := Window1m; w < NumWindows; w++ {
		args = append(args, strconv.FormatInt(int64(2*w.Duration()/time.Millisecond), 10))
	}
	args = append(args, strconv.FormatInt(knownTTLMs, 10), strconv.FormatInt(auxTTLMs, 10))

	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	out, err := s.cli.Eval(ctx, observeLua, keys, args)
	if err != nil {
		return nil, err
	}
	if len(out) != observeResultLen {
		return nil, fmt.Errorf("%w: got %d, want %d", errBadEvalResult, len(out), observeResultLen)
	}

	snap := &Snapshot{}
	i := 0
	for w := Window1m; w < NumWindows; w++ {
		wc := WindowCounts{WindowStart: now.Truncate(w.Duration())}
		wc.RequestCount = scaled(out[i])
		i++
		wc.Status401Count = scaled(out[i])
		i++
		wc.Status403Count = scaled(out[i])
		i++
		wc.Status404Count = scaled(out[i])
		i++
		wc.Status405Count = scaled(out[i])
		i++
		wc.Status500Count = scaled(out[i])
		i++
		wc.AuthFailCount = scaled(out[i])
		i++
		wc.ParameterMutationCount = scaled(out[i])
		i++
		wc.SensitivePathHits = scaled(out[i])
		i++
		wc.NewURICount = scaled(out[i])
		i++
		wc.UniqueURICount = luaInt(out[i])
		i++
		wc.AccountEnumCount = luaInt(out[i])
		i++
		wc.ObjectEnumCount = luaInt(out[i])
		i++
		snap.Windows[w] = wc
	}
	snap.DistinctMethods = int(luaInt(out[i]))
	i++
	snap.ParamSigNew = luaInt(out[i]) == 1
	i++
	// 1m 完成桶回放块（原始整数，未缩放；字段序同 Lua fields：
	// req,s401,s403,s404,s405,s500,authf,pmut,sens,newuri + unique）。
	cw := WindowCounts{WindowStart: now.Truncate(Window1m.Duration()).Add(-Window1m.Duration())}
	cw.RequestCount = float64(luaInt(out[i]))
	i++
	cw.Status401Count = float64(luaInt(out[i]))
	i++
	cw.Status403Count = float64(luaInt(out[i]))
	i++
	cw.Status404Count = float64(luaInt(out[i]))
	i++
	cw.Status405Count = float64(luaInt(out[i]))
	i++
	cw.Status500Count = float64(luaInt(out[i]))
	i++
	cw.AuthFailCount = float64(luaInt(out[i]))
	i++
	cw.ParameterMutationCount = float64(luaInt(out[i]))
	i++
	cw.SensitivePathHits = float64(luaInt(out[i]))
	i++
	cw.NewURICount = float64(luaInt(out[i]))
	i++
	cw.UniqueURICount = luaInt(out[i])
	i++
	cw.AccountEnumCount = luaInt(out[i])
	i++
	cw.ObjectEnumCount = luaInt(out[i])
	snap.CompletedWindow = cw
	return snap, nil
}

// bucketKey 桶键：<前缀>:<命名空间>:<窗口>:<identity哈希>:<桶起点unix>。
func (s *ValkeyStore) bucketKey(ns string, w Window, ihash string, bucket time.Time) string {
	return s.pfx + ":" + ns + ":" + w.Name() + ":" + ihash + ":" + strconv.FormatInt(bucket.Unix(), 10)
}

// warn fail-open 告警（每分钟节流一条，防日志洪泛）。
func (s *ValkeyStore) warn(op string, err error) {
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
	s.logger.Warn("identitybehavior valkey error, fail-open to memory",
		zap.String("op", op), zap.Error(err))
}

// Close 不关闭共享 Valkey 连接（连接归共享引擎所有，随进程/引擎重建生命周期）。
func (s *ValkeyStore) Close() error { return nil }

// bool01 布尔转 0/1 字符串（Lua ARGV）。
func bool01(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// scaled ×1000 缩放计数转浮点估值。
func scaled(v interface{}) float64 { return float64(luaInt(v)) / 1000 }

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
