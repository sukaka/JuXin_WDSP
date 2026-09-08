package riskengine

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
	"go.uber.org/zap"
)

// DefaultKeyPrefix Valkey 键前缀（与 jiuzhang:guard:cc / jiuzhang:guard:ibh 同一命名纪律）。
const DefaultKeyPrefix = "jiuzhang:guard:risk"

// opTimeout 单次 Eval 超时上限（风险评估在请求热路径；300ms 保证 Valkey 悬挂时
// fail-open 亚秒内触发、请求 goroutine 阻塞有界——与 behaviorstore 同一取值）。
const opTimeout = 300 * time.Millisecond

// ttlBuffer 键 TTL 在滑窗之上的余量（窗口外成员由 ZREMRANGEBYSCORE 清除，TTL 仅兜底存活）。
const ttlBuffer = time.Minute

// errBadEvalResult Lua 返回不符（不应发生；按故障走 fail-open）。
var errBadEvalResult = errors.New("riskengine: unexpected eval result")

// addLua 信号入账单 Lua 原子往返：清窗 → ZADD（变参 score/member 对）→ 超上限裁最旧 → 刷 TTL。
// KEYS[1] = 风险 ZSET 键；ARGV[1..4] = now_ms / window_ms / ttl_ms / cap；
// ARGV[5..] = 变参（score_ms, member_json）对。
const addLua = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local n = 0
for i = 5, #ARGV, 2 do
  redis.call('ZADD', key, tonumber(ARGV[i]), ARGV[i + 1])
  n = n + 1
end
local count = redis.call('ZCARD', key)
local cap = tonumber(ARGV[4])
if count > cap then
  redis.call('ZREMRANGEBYRANK', key, 0, count - cap - 1)
end
redis.call('PEXPIRE', key, tonumber(ARGV[3]))
return {n}
`

// stateLua 滑窗读取单 Lua 原子往返：清窗 → 返回窗口内全部 member（ZRANGE 按 score 升序 = 时间升序）。
const stateLua = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
return redis.call('ZRANGE', key, 0, -1)
`

// memberJSON 信号明细 ZSET member 线格式（紧凑键名控制键体积；"n" 为进程内唯一序列，
// 防同毫秒同内容信号互相覆盖）。
type memberJSON struct {
	Type   string `json:"t"`
	Score  int    `json:"s"`
	Reason string `json:"r,omitempty"`
	At     int64  `json:"at"` // Unix 秒
	N      int64  `json:"n"`
}

// ValkeyStore Valkey 风险累加（跨节点共享；任何 Valkey 故障 fail-open 回退进程内存并以
// zap Warn 告警（节流 1/min），处置语义不中断——与 identitybehavior/behaviorstore 同一纪律。
// 故障期间的信号只落在内存侧；State 成功路径合并内存回退中仍在窗口内的条目，
// 避免抖动窗口内的风险分在 Valkey 恢复后被整体遗忘（同一条信号只落一侧，合并不重复计数）。
type ValkeyStore struct {
	cli    counters.ValkeyClient
	pfx    string
	window time.Duration
	mem    *MemoryStore
	logger *zap.Logger
	now    func() time.Time
	seq    atomic.Int64

	mu       sync.Mutex
	lastWarn time.Time
}

// NewValkeyStore 构造 Valkey 存储（mem 为 nil 时按同窗口自建内存回退；keyPrefix 空取
// DefaultKeyPrefix；logger 为 nil 时告警静默——装配层必须传 logger）。
func NewValkeyStore(cli counters.ValkeyClient, window time.Duration, mem *MemoryStore, logger *zap.Logger) *ValkeyStore {
	if mem == nil {
		mem = NewMemoryStore(window, 0, logger)
	}
	if window <= 0 {
		window = time.Duration(DefaultSignalWindowSeconds) * time.Second
	}
	return &ValkeyStore{
		cli:    cli,
		pfx:    DefaultKeyPrefix,
		window: window,
		mem:    mem,
		logger: logger,
		now:    time.Now,
	}
}

// key 风险键：<前缀>:<identity 哈希>（identity_key 已为 HMAC 指纹，仍走 HashParts 统一键纪律）。
func (s *ValkeyStore) key(identityKey string) string {
	return s.pfx + ":" + counters.HashParts(identityKey)
}

// Add 单 Lua 原子入账；任何故障回退内存实现（fail-open）。
func (s *ValkeyStore) Add(identityKey string, entries ...SignalEntry) error {
	if len(entries) == 0 {
		return nil
	}
	nowMs := s.now().UnixMilli()
	args := make([]string, 0, 4+2*len(entries))
	args = append(args,
		strconv.FormatInt(nowMs, 10),
		strconv.FormatInt(s.window.Milliseconds(), 10),
		strconv.FormatInt((s.window+ttlBuffer).Milliseconds(), 10),
		strconv.Itoa(MaxEntriesPerIdentity),
	)
	for _, e := range entries {
		at := e.At
		if at.IsZero() {
			at = s.now().UTC()
		}
		m, err := json.Marshal(memberJSON{Type: e.Type, Score: e.Score, Reason: e.Reason, At: at.Unix(), N: s.seq.Add(1)})
		if err != nil {
			return err
		}
		args = append(args, strconv.FormatInt(at.UnixMilli(), 10), string(m))
	}
	out, err := s.eval(addLua, []string{s.key(identityKey)}, args)
	if err == nil && len(out) != 1 {
		err = errBadEvalResult
	}
	if err != nil {
		s.warn("add", err)
		return s.mem.Add(identityKey, entries...)
	}
	return nil
}

// State 单 Lua 原子读取并求和截断 [0,100]；任何故障回退内存实现（fail-open）。
// 成功路径合并内存回退中仍在窗口内的条目（故障窗口内经 Add 落入内存的信号只在内存侧；
// 同一条信号要么 Valkey 入账成功、要么整体回退内存，两侧不重复计数）。
func (s *ValkeyStore) State(identityKey string) (int, []SignalEntry, error) {
	nowMs := s.now().UnixMilli()
	out, err := s.eval(stateLua, []string{s.key(identityKey)}, []string{
		strconv.FormatInt(nowMs, 10),
		strconv.FormatInt(s.window.Milliseconds(), 10),
	})
	if err != nil {
		s.warn("state", err)
		return s.mem.State(identityKey)
	}
	sum := 0
	entries := make([]SignalEntry, 0, len(out))
	for _, v := range out {
		raw, ok := v.(string)
		if !ok {
			return 0, nil, errBadEvalResult
		}
		var m memberJSON
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			return 0, nil, errBadEvalResult
		}
		entries = append(entries, SignalEntry{Type: m.Type, Score: m.Score, Reason: m.Reason, At: time.Unix(m.At, 0).UTC()})
		sum += m.Score
	}
	if _, memEntries, memErr := s.mem.State(identityKey); memErr != nil {
		s.warn("state-mem", memErr)
	} else if len(memEntries) > 0 {
		for _, e := range memEntries {
			sum += e.Score
		}
		entries = append(entries, memEntries...)
		// 合并后恢复时间升序契约（稳定排序：同秒条目保持 Valkey 毫秒序在前）
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].At.Before(entries[j].At) })
	}
	return clampScore(sum), entries, nil
}

// eval 单次 Eval 包装：固定 opTimeout 超时（不从请求 ctx 派生——End/事件路径在请求收束后
// 执行，各操作独立计时、与请求生命周期解耦；与 behaviorstore 同一纪律）。
func (s *ValkeyStore) eval(script string, keys []string, args []string) ([]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	return s.cli.Eval(ctx, script, keys, args)
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
	s.logger.Warn("riskengine valkey error, fail-open to memory",
		zap.String("op", op), zap.Error(err))
}

// Close 不关闭共享 Valkey 连接（连接归共享引擎所有，随进程/引擎重建生命周期）。
func (s *ValkeyStore) Close() error { return nil }
