package botchallenge

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
)

// 共享 Valkey 键结构（独立命名空间 jiuzhang:guard:bot，B0 冻结）：
//   挑战状态 HASH  <pfx>:c:<HashParts("c", appID, challengeID)>
//     字段：v=1 / sd=会话摘要 / hh=Host 摘要 / ep=策略代次 / df=难度 / nc=nonce(hex，
//     题目参数) / exp=过期毫秒 / att=已消费尝试数；PEXPIRE = nonce_ttl（自动回收）。
//     服务端只存摘要与题目参数（任务书 §5.2），不落明文会话 ID、不存 solution。
//   在途计量 ZSET  <pfx>:if:<HashParts("if", appID)>
//     member=challengeID(hex)，score=过期毫秒；签发前惰性清理过期 member 后
//     ZCARD 做容量判定（精确有界，不允许无限增长）；消费/耗尽/过期判定后 ZREM。
//
// 单 Lua 原子往返纪律与 riskengine/behaviorstore 一致（300ms 超时）；
// 消费为「原子比较并消费」——比较在 Lua 内完成，禁止先查再删（任务书 §5.2）。

// issueLua 签发：容量清理/判定 → NX 防碰撞 → HSET 状态 → 计量入账。
// KEYS[1]=在途 ZSET, KEYS[2]=挑战 HASH；
// ARGV: now_ms, cap, ttl_ms, exp_ms, member(challengeID), sd, hh, ep, df, nc。
// 返回 {1,"OK"} | {0,"CAP"} | {0,"EXISTS"}。
const issueLua = `
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, ARGV[1])
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[2]) then
  return {0, 'CAP'}
end
if redis.call('EXISTS', KEYS[2]) == 1 then
  return {0, 'EXISTS'}
end
redis.call('HSET', KEYS[2],
  'v', '1',
  'sd', ARGV[6],
  'hh', ARGV[7],
  'ep', ARGV[8],
  'df', ARGV[9],
  'nc', ARGV[10],
  'exp', ARGV[4],
  'att', 0)
redis.call('PEXPIRE', KEYS[2], tonumber(ARGV[3]))
redis.call('ZADD', KEYS[1], tonumber(ARGV[4]), ARGV[5])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[3]) + 60000)
return {1, 'OK'}
`

// readLua 读取（单往返）：HGETALL 挑战字段 + 在途计量过期提示（区分 expired 与
// 未知/已消费——HASH 随 TTL 消失后 ZSET member 仍按 score 留存至惰性清理）。
// 返回扁平数组：[字段条目数 n, k1,v1,...,kn,vn, hint]；hint: "0"=member 缺失 /
// "1"=member 已过期 / "2"=member 在效。HASH 缺失时 n=0。
const readLua = `
local f = redis.call('HGETALL', KEYS[1])
local sc = redis.call('ZSCORE', KEYS[2], ARGV[1])
local out = { #f }
for i = 1, #f do out[#out + 1] = f[i] end
local hint = '0'
if sc then
  if tonumber(sc) <= tonumber(ARGV[2]) then hint = '1' else hint = '2' end
end
out[#out + 1] = hint
return out
`

// consumeLua 原子比较并消费（先查再删禁止：全部比较在 Lua 内完成）：
// 绑定字段（会话/Host/代次/难度/nonce）逐一比对 + 未过期 + 尝试数未耗尽 → DEL+ZREM。
// KEYS[1]=挑战 HASH, KEYS[2]=在途 ZSET；
// ARGV: sd, hh, ep, df, nc, exp, member, now_ms, max_attempts。
// 返回 {1,"OK"} | {0,"NOT_FOUND"|"MISMATCH"|"EXPIRED"|"EXHAUSTED"}。
const consumeLua = `
local f = redis.call('HMGET', KEYS[1], 'sd','hh','ep','df','nc','exp','att')
if f[1] == false then return {0, 'NOT_FOUND'} end
if f[1] ~= ARGV[1] or f[2] ~= ARGV[2] or f[3] ~= ARGV[3] or f[4] ~= ARGV[4] or f[5] ~= ARGV[5] then
  return {0, 'MISMATCH'}
end
if tonumber(f[6]) <= tonumber(ARGV[8]) then
  redis.call('DEL', KEYS[1])
  -- 保留在途计量 member（score 已过期）：Read 据此把「已过期」与「未知/已消费」
  -- 区分开（expired 事件归因）；member 由 issueLua 惰性清理与计量键 TTL 兜底
  return {0, 'EXPIRED'}
end
if tonumber(f[7]) >= tonumber(ARGV[9]) then
  return {0, 'EXHAUSTED'}
end
redis.call('DEL', KEYS[1])
redis.call('ZREM', KEYS[2], ARGV[7])
return {1, 'OK'}
`

// failLua 错误解答记账（原子比较 + 尝试计数）：比对绑定字段 → HINCRBY att →
// 达 max_attempts 即作废（DEL+ZREM），防无限尝试。
// ARGV 同 consumeLua。返回 {2,"ATTEMPT",att} | {0,"NOT_FOUND"|"MISMATCH"|"EXPIRED"|"EXHAUSTED",att}。
const failLua = `
local f = redis.call('HMGET', KEYS[1], 'sd','hh','ep','df','nc','exp','att')
if f[1] == false then return {0, 'NOT_FOUND', 0} end
if f[1] ~= ARGV[1] or f[2] ~= ARGV[2] or f[3] ~= ARGV[3] or f[4] ~= ARGV[4] or f[5] ~= ARGV[5] then
  return {0, 'MISMATCH', 0}
end
if tonumber(f[6]) <= tonumber(ARGV[8]) then
  redis.call('DEL', KEYS[1])
  -- 保留在途计量 member（score 已过期）：Read 据此归因 EXPIRED
  return {0, 'EXPIRED', 0}
end
local att = redis.call('HINCRBY', KEYS[1], 'att', 1)
if att >= tonumber(ARGV[9]) then
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[2], ARGV[7])
  return {0, 'EXHAUSTED', att}
end
return {2, 'ATTEMPT', att}
`

// errBadEvalResult Lua 返回形状不符（按 ErrStateUnavailable 处理）。
var errBadEvalResult = errors.New("botchallenge: unexpected eval result")

// ChallengeState 服务端挑战状态（只含摘要/题目参数/代次/过期/尝试数）。
type ChallengeState struct {
	SessionDigest string // SHA-256(sid) hex
	HostDigest    string // counters.HashParts(normalizeHost(host))
	PolicyEpoch   int
	Difficulty    int
	Nonce         string // 题目 nonce（hex，128bit；事件绝不记录）
	ExpiresAt     time.Time
	Attempts      int
}

// Store Valkey 挑战状态存储（跨节点共享；无内存回退——Bot PROTECT 为
// fail-closed 例外：任何存储故障返回包装 ErrStateUnavailable 的错误，
// 由调用方按模式决定 503（PROTECT）或记录放行（OBSERVE））。
type Store struct {
	cli counters.ValkeyClient
	pfx string
	now func() time.Time
}

// NewStore 构造存储（keyPrefix 空 = ValkeyKeyPrefix）。
func NewStore(cli counters.ValkeyClient, keyPrefix string) *Store {
	if keyPrefix == "" {
		keyPrefix = ValkeyKeyPrefix
	}
	return &Store{cli: cli, pfx: keyPrefix, now: time.Now}
}

// challengeKey 挑战键（challengeID 来自客户端回交，一律 HashParts 哈希后入键，
// 禁止原始输入拼键——与 counters 键纪律一致）。
func (s *Store) challengeKey(appID, challengeID string) string {
	return s.pfx + ":c:" + counters.HashParts("c", appID, challengeID)
}

// inflightKey 在途计量键。
func (s *Store) inflightKey(appID string) string {
	return s.pfx + ":if:" + counters.HashParts("if", appID)
}

// eval 单往返包装（固定 300ms 超时；不派生请求 ctx——与 riskengine 同一纪律，
// 错误统一包装 ErrStateUnavailable 供 errors.Is 判定）。
func (s *Store) eval(script string, keys []string, args []string) ([]interface{}, error) {
	ctx, cancel := contextWithOpTimeout()
	defer cancel()
	out, err := s.cli.Eval(ctx, script, keys, args)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStateUnavailable, err)
	}
	return out, nil
}

// contextWithOpTimeout 单次存储/限速操作超时（300ms，与 riskengine/behaviorstore 同值）。
func contextWithOpTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), opTimeout)
}

// Issue 签发挑战（容量有界：达到 cap 返回 ok=false；状态写 Valkey 独立命名空间）。
func (s *Store) Issue(appID, challengeID string, st ChallengeState, ttl time.Duration, cap int) (bool, error) {
	nowMs := s.now().UnixMilli()
	args := []string{
		strconv.FormatInt(nowMs, 10),
		strconv.Itoa(cap),
		strconv.FormatInt(ttl.Milliseconds(), 10),
		strconv.FormatInt(st.ExpiresAt.UnixMilli(), 10),
		challengeID,
		st.SessionDigest,
		st.HostDigest,
		strconv.Itoa(st.PolicyEpoch),
		strconv.Itoa(st.Difficulty),
		st.Nonce,
	}
	out, err := s.eval(issueLua, []string{s.inflightKey(appID), s.challengeKey(appID, challengeID)}, args)
	if err != nil {
		return false, err
	}
	if len(out) != 2 {
		return false, errBadEvalResult
	}
	code, _ := out[0].(int64)
	reason, _ := out[1].(string)
	switch {
	case code == 1:
		return true, nil
	case reason == "CAP":
		return false, nil
	case reason == "EXISTS":
		// 128bit 随机碰撞理论不可达；防御性按容量不可用处理（调用方可重试新 ID）
		return false, fmt.Errorf("%w: challenge id collision", ErrStateUnavailable)
	}
	return false, errBadEvalResult
}

// ReadResult 读取结果（Found=false 时 Hint 区分 NOT_FOUND / EXPIRED——
// 供 verify 归因与 expired 事件；Hint 仅供观测，不构成安全判定依据）。
type ReadResult struct {
	State *ChallengeState
	Hint  string // OK | NOT_FOUND | EXPIRED
}

// Read 读取挑战状态（单 Lua 往返；返回内容未校验——绑定/过期/尝试数的权威
// 判定在 consume/fail 的原子 Lua 内重做，Read 仅用于计算解答摘要与早期归因）。
func (s *Store) Read(appID, challengeID string) (*ReadResult, error) {
	out, err := s.eval(readLua, []string{s.challengeKey(appID, challengeID), s.inflightKey(appID)},
		[]string{challengeID, strconv.FormatInt(s.now().UnixMilli(), 10)})
	if err != nil {
		return nil, err
	}
	if len(out) < 2 {
		return nil, errBadEvalResult
	}
	n, ok := out[0].(int64)
	if !ok || n < 0 || int64(len(out)) != n+2 {
		return nil, errBadEvalResult
	}
	hint := luaFieldString(out[len(out)-1])
	if n == 0 {
		if hint == "1" {
			return &ReadResult{Hint: "EXPIRED"}, nil
		}
		return &ReadResult{Hint: "NOT_FOUND"}, nil
	}
	fields := map[string]string{}
	for i := int64(0); i+1 < n+1; i += 2 {
		k, _ := out[1+i].(string)
		// 值类型容忍：counters.Eval 对可解析的数字串返回 int64（bulk string
		// 被按 int 解析），字段值须两型兼容——绝不能把数字静默吞成空串
		// （f["v"] 缺失会被当成未知版本存储故障）。
		fields[k] = luaFieldString(out[1+i+1])
	}
	st, err := parseChallengeFields(fields)
	if err != nil {
		return nil, err
	}
	return &ReadResult{State: st, Hint: "OK"}, nil
}

// luaFieldString Lua 返回值字符串化（Eval 解码对数字串给 int64——两型统一还原十进制串）。
func luaFieldString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case int64:
		return strconv.FormatInt(t, 10)
	default:
		return ""
	}
}

// parseChallengeFields HASH 字段解析（损坏状态按存储故障处理——不静默吞掉）。
func parseChallengeFields(f map[string]string) (*ChallengeState, error) {
	if f["v"] != "1" {
		return nil, fmt.Errorf("%w: unknown challenge payload version %q", ErrStateUnavailable, f["v"])
	}
	ep, err1 := strconv.Atoi(f["ep"])
	df, err2 := strconv.Atoi(f["df"])
	exp, err3 := strconv.ParseInt(f["exp"], 10, 64)
	att, err4 := strconv.Atoi(f["att"])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return nil, fmt.Errorf("%w: malformed challenge fields", ErrStateUnavailable)
	}
	return &ChallengeState{
		SessionDigest: f["sd"],
		HostDigest:    f["hh"],
		PolicyEpoch:   ep,
		Difficulty:    df,
		Nonce:         f["nc"],
		ExpiresAt:     time.UnixMilli(exp).UTC(),
		Attempts:      att,
	}, nil
}

// ConsumeResult 消费结果（Reason 为结构化归因码）。
type ConsumeResult struct {
	Consumed bool
	Reason   string // OK | NOT_FOUND | MISMATCH | EXPIRED | EXHAUSTED
}

// Consume 原子比较并消费（跨节点并发提交同一 nonce 至多一次成功——
// Lua 原子执行，先查再删禁止；调用方传入 Read 所得状态作期望值）。
func (s *Store) Consume(appID, challengeID string, expect *ChallengeState, maxAttempts int) (*ConsumeResult, error) {
	return s.compareAndAct(consumeLua, appID, challengeID, expect, maxAttempts)
}

// FailResult 错误解答记账结果。
type FailResult struct {
	Recorded bool   // true = 已记一次尝试
	Reason   string // ATTEMPT | NOT_FOUND | MISMATCH | EXPIRED | EXHAUSTED
	Attempts int
}

// FailAttempt 错误解答原子记账（达 max_attempts 作废挑战）。
func (s *Store) FailAttempt(appID, challengeID string, expect *ChallengeState, maxAttempts int) (*FailResult, error) {
	out, err := s.compareArgs(failLua, appID, challengeID, expect, maxAttempts)
	if err != nil {
		return nil, err
	}
	if len(out) != 3 {
		return nil, errBadEvalResult
	}
	code, _ := out[0].(int64)
	reason, _ := out[1].(string)
	att, _ := out[2].(int64)
	return &FailResult{Recorded: code == 2, Reason: reason, Attempts: int(att)}, nil
}

// Consume 共享参数构造与执行。
func (s *Store) compareAndAct(script, appID, challengeID string, expect *ChallengeState, maxAttempts int) (*ConsumeResult, error) {
	out, err := s.compareArgs(script, appID, challengeID, expect, maxAttempts)
	if err != nil {
		return nil, err
	}
	if len(out) != 2 {
		return nil, errBadEvalResult
	}
	code, _ := out[0].(int64)
	reason, _ := out[1].(string)
	return &ConsumeResult{Consumed: code == 1, Reason: reason}, nil
}

// compareArgs 比较型 Lua 的参数装配与执行（期望值逐字段入 ARGV，Lua 内比对）。
func (s *Store) compareArgs(script, appID, challengeID string, expect *ChallengeState, maxAttempts int) ([]interface{}, error) {
	args := []string{
		expect.SessionDigest,
		expect.HostDigest,
		strconv.Itoa(expect.PolicyEpoch),
		strconv.Itoa(expect.Difficulty),
		expect.Nonce,
		strconv.FormatInt(expect.ExpiresAt.UnixMilli(), 10),
		challengeID,
		strconv.FormatInt(s.now().UnixMilli(), 10),
		strconv.Itoa(maxAttempts),
	}
	return s.eval(script, []string{s.challengeKey(appID, challengeID), s.inflightKey(appID)}, args)
}

// Ping 依赖健康检查（B3 可用作启动自检；失败按 ErrStateUnavailable）。
func (s *Store) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	if err := s.cli.Ping(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrStateUnavailable, err)
	}
	return nil
}
