package identitybehavior

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
)

// peek.go 只读行为快照（WDSP P1-02 B3：Bot 挑战信号评估在请求处理中途同步读取
// 窗口计数——Observe 在请求收束时才记账，读取侧不能复用）。纪律：
//   - Peek 不记账、不改写任何计数；窗口惰性轮转与估值口径与 Observe 完全一致
//     （同一时刻对同一身份的 Peek 与 Observe 仅差本次请求的 +1 计数）。
//   - Valkey 实现单 Lua 只读往返（300ms 超时），远端故障回退进程内存并以
//     Warn 告警（与 Observe 同一 fail-open 纪律；回退内存可能只有局部数据，
//     消费方按 UNKNOWN/UNAVAILABLE 语义处理，不得当作零风险或高风险）。
//   - Store 接口本体不加方法（不破坏既有实现）；能力经可选接口 peeker 判定，
//     不支持时 Engine.PeekSnapshot 返回 ErrPeekUnsupported。

// ErrPeekUnsupported 存储不支持只读快照（观测源缺失——消费方按 UNKNOWN 处理）。
var ErrPeekUnsupported = errors.New("identitybehavior: store does not support read-only peek")

// peeker 只读快照能力（MemoryStore/ValkeyStore 实现）。
type peeker interface {
	Peek(identityKey, uri string, at time.Time) (*Snapshot, error)
}

// PeekSnapshot 只读行为快照（B3 Bot 信号评估挂点）：引擎未启用/存储不支持/
// 读取失败均返回错误，绝不返回半成品零值快照冒充「无风险」。
func (e *Engine) PeekSnapshot(identityKey, uri string) (*Snapshot, error) {
	if e == nil || e.store == nil {
		return nil, ErrPeekUnsupported
	}
	p, ok := e.store.(peeker)
	if !ok {
		return nil, ErrPeekUnsupported
	}
	return p.Peek(identityKey, uri, e.now().UTC())
}

// ---------- 内存实现 ----------

// Peek 只读快照（单 identity 锁临界区；惰性轮转是记账语义的一部分而非计数改写——
// 跨桶读取不轮转会把已过期桶当当前桶，估值失真）。
// 未知身份经 GetOrCreate 建空条目（LRU 有界，与 Observe 同一容量纪律）。
func (s *MemoryStore) Peek(identityKey, uri string, at time.Time) (*Snapshot, error) {
	v := s.ids.GetOrCreate(identityKey, func() interface{} { return newMemIdentity() })
	id := v.(*memIdentity)
	id.mu.Lock()
	defer id.mu.Unlock()

	snap := &Snapshot{}
	if uri != "" {
		if st, ok := id.uris.get(counters.HashParts(uri)); ok {
			snap.DistinctMethods = len(st.(*memURI).methods)
		}
	}
	for w := Window1m; w < NumWindows; w++ {
		mw := &id.windows[w]
		mw.rotate(at, w.Duration())
		est := mw.estimate(at, w.Duration())
		snap.Windows[w] = WindowCounts{
			WindowStart:            mw.curStart,
			RequestCount:           est[cReq],
			UniqueURICount:         int64(mw.unique()),
			NewURICount:            est[cNewURI],
			Status401Count:         est[c401],
			Status403Count:         est[c403],
			Status404Count:         est[c404],
			Status405Count:         est[c405],
			Status500Count:         est[c500],
			AuthFailCount:          est[cAuthFail],
			ParameterMutationCount: est[cParamMut],
			SensitivePathHits:      est[cSensitive],
			AccountEnumCount:       int64(mw.uniqueSet(mw.accountSet, mw.prevAccountSet)),
			ObjectEnumCount:        int64(mw.uniqueSet(mw.objectSet, mw.prevObjectSet)),
		}
	}
	return snap, nil
}

// ---------- Valkey 实现 ----------

// peekLua 只读快照（observeLua 的只读镜像：相同键布局、相同估值公式，
// 无任何写操作——不 HINCRBY/PFADD/SADD/PEXPIRE）。
// KEYS[1..8] 计数桶（cur+prev × 4 窗口）；KEYS[9..16] URI 去重 HLL 桶；
// KEYS[17] known-URI HLL（不读取，保留键位对齐）；KEYS[18] (identity,uri) 方法集合；
// KEYS[19] 参数签名 HLL（不读取）；KEYS[20..27] 账号 HLL 桶；KEYS[28..35] 对象 HLL 桶。
// ARGV[1..4] 各窗口当前桶已流逝秒数；ARGV[5..8] 各窗口时长秒数。
// 返回 53 个 int64：每窗口 13（10 个 ×1000 缩放计数估值 + URI/account/object unique），
// 窗口序 1m/5m/30m/24h；末尾 distinct method 数（uri 为空时传空键，SCARD 得 0）。
const peekLua = `
local fields = {'req','s401','s403','s404','s405','s500','authf','pmut','sens','newuri'}
local out = {}
for i = 0, 3 do
  local curC = KEYS[1 + i * 2]
  local prevC = KEYS[2 + i * 2]
  local curH = KEYS[9 + i * 2]
  local prevH = KEYS[10 + i * 2]
  local accCurH = KEYS[20 + i * 2]
  local accPrevH = KEYS[21 + i * 2]
  local objCurH = KEYS[28 + i * 2]
  local objPrevH = KEYS[29 + i * 2]
  local elapsed = tonumber(ARGV[1 + i])
  local dur = tonumber(ARGV[5 + i])

  local cur = {}
  local cv = redis.call('HGETALL', curC)
  for j = 1, #cv, 2 do cur[cv[j]] = tonumber(cv[j + 1]) end
  local prev = {}
  local pv = redis.call('HGETALL', prevC)
  for j = 1, #pv, 2 do prev[pv[j]] = tonumber(pv[j + 1]) end

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
out[#out + 1] = redis.call('SCARD', KEYS[18])
return out
`

// peekResultLen peekLua 返回长度（4 窗口 × 13 + distinct method 1）。
const peekResultLen = 4*13 + 1

// Peek 只读快照（单 Lua 往返；远端故障回退进程内存并告警——与 Observe 同一纪律）。
func (s *ValkeyStore) Peek(identityKey, uri string, at time.Time) (*Snapshot, error) {
	snap, err := s.peekRemote(identityKey, uri, at)
	if err != nil {
		s.recordFailure(err)
		s.warn("peek", err)
		return s.mem.Peek(identityKey, uri, at)
	}
	return snap, nil
}

func (s *ValkeyStore) peekRemote(identityKey, uri string, now time.Time) (*Snapshot, error) {
	ihash := counters.HashParts(identityKey)
	uhash := counters.HashParts(uri)
	if uri == "" {
		uhash = ""
	}

	// 键布局与 observeRemote 完全一致（35 键）
	keys := make([]string, 0, 35)
	for w := Window1m; w < NumWindows; w++ {
		d := w.Duration()
		cur := now.Truncate(d)
		keys = append(keys, s.bucketKey("c", w, ihash, cur), s.bucketKey("c", w, ihash, cur.Add(-d)))
	}
	for w := Window1m; w < NumWindows; w++ {
		d := w.Duration()
		cur := now.Truncate(d)
		keys = append(keys, s.bucketKey("u", w, ihash, cur), s.bucketKey("u", w, ihash, cur.Add(-d)))
	}
	methodKey := ""
	if uhash != "" {
		methodKey = s.pfx + ":m:" + ihash + ":" + uhash
	}
	keys = append(keys,
		s.pfx+":k:"+ihash,
		methodKeyOrSentinel(methodKey),
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
	args := make([]string, 0, 8)
	for w := Window1m; w < NumWindows; w++ {
		d := w.Duration()
		args = append(args, strconv.FormatInt(int64(now.Sub(now.Truncate(d)).Seconds()), 10))
	}
	for w := Window1m; w < NumWindows; w++ {
		args = append(args, strconv.FormatInt(int64(w.Duration().Seconds()), 10))
	}

	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	out, err := s.cli.Eval(ctx, peekLua, keys, args)
	if err != nil {
		return nil, err
	}
	if len(out) != peekResultLen {
		return nil, fmt.Errorf("%w: got %d, want %d", errBadEvalResult, len(out), peekResultLen)
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
	return snap, nil
}

// methodKeyOrSentinel 空 uri 时给 SCARD 一个永不存在的哨兵键（返回 0），
// 避免空键名触发 Valkey 错误。
func methodKeyOrSentinel(k string) string {
	if k == "" {
		return DefaultKeyPrefix + ":m:__peek_no_uri__"
	}
	return k
}
