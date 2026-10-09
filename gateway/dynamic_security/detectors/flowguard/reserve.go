// reserve.go 强流程原子预留/提交/释放（NG-FLOW-02 §1.3 D3 冻结选型：
// Valkey Lua 脚本共享原子域 + fencing=实例级 INCR 单调序号；PG 只做事件溯源
// 兜底，不承担热路径原子判定）。
//
// 键模式（冻结；同实例全部键以 {实例键} 为 hash tag 同槽，集群安全）：
//
//	sflow:v1:{<instance_id>}:fence            INCR 单调序号 = fencing token
//	sflow:v1:{<instance_id>}:state            hash：status/current_step/created_ms/completed_ms
//	sflow:v1:{<instance_id>}:step:<step_key>  预留槽 hash：state(PENDING/CONFIRMED/RELEASED)/
//	                                          token/lease_exp(ms)/idem/digest/confirmed_ms
//
// 纪律：
//   - fencing（F05）：reserve 成功经 INCR 发 token；commit/release 必须携带 token 且
//     token == 当前 fence 才接受；lease 过期后新 reserve 得更大 token，旧 token 提交
//     一律拒绝（迟到响应不覆盖新状态）；失败的 reserve 不 INCR（不殃及持槽者）。
//   - 幂等（F03）：幂等键哈希 + 参数摘要绑定「实例+步骤」槽；同键同摘要重试 = 幂等
//     返回既有结果；同键异摘要 = 冲突拒绝（IDEMPOTENT-CONFLICT-001）；不同键重走已
//     CONFIRMED 步骤 = 违规；无幂等键的请求不参与幂等语义（同摘要重放仍幂等去重）。
//   - 时钟（D7/§14.3）：lease 判定一律用 Valkey 服务端 TIME（单一时间源），
//     不消费网关本地时钟——多节点时钟漂移不污染租约判定。
//   - 故障（D8 红线）：Valkey 不可用/超时/协议异常 → 恒 UNKNOWN（放行+披露
//     dependency_unavailable），严禁切换本地内存（严格流程不静默降级，
//     分布式唯一事实源）；网关重启后状态从 Valkey 读回（本包无进程内权威态）。
//   - lease 语义：租约过期仅在「被争夺时」生效——过期未被重预留的槽上，
//     持 token 的 commit 仍接受（F04：超时但源站可能已成功，不自动回滚诱导重复扣款）。
package flowguard

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// KeyPrefix 强流程 Valkey 键前缀（§1.2 冻结：版本化命名空间 v1 嵌入键前缀，
// 与观察态 flow: 会话键物理隔离，无任何共享键形）。
const KeyPrefix = "sflow:v1:"

// 实例热状态 TTL：每次成功变更刷新。Valkey = 热状态（非事实源——实例行与步骤
// 事件在 PG，§1.8）；TTL 到期即热状态消失，触碰按 UNKNOWN/违规如实判定不伪造
// 恢复（D8）。24h 覆盖全部合法窗口（步骤 timeout≤600s、lease≤300s）。
const DefaultInstanceTTL = 24 * time.Hour

// DefaultOpTimeout 单次 Eval 超时上限（与 behaviorstore 同一量纲：Valkey 同机/
// 同网段毫秒级，悬挂时 UNKNOWN 亚秒内触发、请求 goroutine 阻塞有界）。
const DefaultOpTimeout = 300 * time.Millisecond

// 操作结果码（Lua 返回值第 1 元素；与事件 result 词表映射见 OpResult）。
const (
	luaOK            = 0 // 成功
	luaOKReplay      = 1 // 幂等重放（同键同摘要），返回既有结果
	luaConflict      = 2 // 冲突（同键异摘要 / 槽被他人持有）
	luaRejected      = 3 // 违规拒绝（前置非法/终态重入/fencing 过期/不可释放）
	luaUnknownScript = 4 // 脚本内状态判定不可服务（实例 INDETERMINATE）
)

// 原因码词表（§1.6 冻结，检测器决策组与事件 reason_code 共用）。
const (
	ReasonReserveDenied      = "FLOW-RESERVE-001"        // 预留违规（无有效预留执行依赖步骤/重复执行已确认步骤/非法并行/终态重入）
	ReasonFenceStale         = "FENCE-001"               // fencing 过期提交/释放（迟到响应不覆盖新状态）
	ReasonIdempotentConflict = "IDEMPOTENT-CONFLICT-001" // 同幂等键异参数摘要冲突
	ReasonUnknown            = "UNKNOWN-001"             // 证据不足/依赖不可用（恒不阻断）
	// ReasonAccepted202 异步受理标记（§1.5：步骤 allows_202=true 且响应 202 →
	// 已受理待完成，不自动完成；随 RESERVE OK 条目如实标注）
	ReasonAccepted202 = "FLOW-ACCEPTED-202"
)

// Evaluator Valkey 最小 Eval 接口（与 counters.ValkeyClient.Eval 同签名，
// 装配层结构化满足；便于测试替身与故障注入——本模块零新依赖）。
type Evaluator interface {
	Eval(ctx context.Context, script string, keys []string, args []string) ([]interface{}, error)
}

// errEmptyEvalResult Lua 返回空数组（协议异常；按 UNKNOWN 处理）。
var errEmptyEvalResult = errors.New("flowguard: empty eval result")

// OpResult 单次原子操作结果（事件条目与决策组的共同输入）。
type OpResult struct {
	Outcome string // dsevents.SFlowResult* 词表：OK/CONFLICT/REJECTED/UNKNOWN
	Reason  string // 原因码（OK 时为空）
	Detail  string // 子原因（证据明细；词表见各 Lua 脚本注释）
	// Token fencing token（§8.4-2 裁决语义：恒为本操作自己持有的 token——
	// OK/重放为持槽 token（MarkAccepted 为受理轮换后的新 token）；REJECTED 为
	// 被拒的旧 token（当前 fence 读数在 FenceCurrent，唯一键不再碰撞）；UNKNOWN 为 0）
	Token int64
	// FenceCurrent REJECTED 时的当前 fence 读数（迟到拒绝的参照系——事件
	// evidence fence_current 承载；非 REJECTED 为 0）。
	FenceCurrent int64
	// InstanceNew reserve 创建了实例（state 槽首次写入）——事件补 INSTANCE_NEW。
	InstanceNew bool
	// ExpiredTakeover reserve 接管了 lease 过期的旧槽——事件补 EXPIRE（携带旧 token）。
	ExpiredTakeover bool
	// ExpiredToken 被接管槽的旧 fencing token（ExpiredTakeover 时有效）。
	ExpiredToken int64
	// InstanceConfirmed commit 后实例全部步骤 CONFIRMED——事件补 INSTANCE_CONFIRMED。
	InstanceConfirmed bool
	// IdempotentReplay 幂等重放命中（未变更状态，返回既有结果）。
	IdempotentReplay bool
}

// Store 强流程原子操作存储（Valkey Lua 单次原子往返；并发安全）。
// cli 为 nil = 未配置 Valkey 连接：所有操作恒 UNKNOWN（D8：不切本地内存，
// 装配层告警）。warnf 故障告警回调（实现内每分钟节流；nil = 静默——装配层必须传）。
type Store struct {
	cli         Evaluator
	opTimeout   time.Duration
	instanceTTL time.Duration
	warnf       func(op string, err error)

	mu       sync.Mutex
	lastWarn time.Time
	now      func() time.Time
}

// NewStore 构造强流程原子操作存储（opTimeout/instanceTTL ≤0 用缺省；
// cli 允许为 nil——D8 UNKNOWN 语义的合法承载）。
func NewStore(cli Evaluator, warnf func(op string, err error)) *Store {
	return &Store{
		cli:         cli,
		opTimeout:   DefaultOpTimeout,
		instanceTTL: DefaultInstanceTTL,
		warnf:       warnf,
		now:         time.Now,
	}
}

// 键构造（hash tag {instance_id} 同槽；instance_id 为 sfref: 形态——
// 64 位小写 hex 无大括号，hash tag 内容安全）。
func fenceKey(instanceID string) string { return KeyPrefix + "{" + instanceID + "}:fence" }
func stateKey(instanceID string) string { return KeyPrefix + "{" + instanceID + "}:state" }
func stepSlotKey(instanceID, stepKey string) string {
	return KeyPrefix + "{" + instanceID + "}:step:" + stepKey
}

// warn 故障告警（每分钟节流一条，防 Valkey 故障期日志洪泛）。
func (s *Store) warn(op string, err error) {
	if s.warnf == nil {
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
	s.warnf(op, err)
}

// unknownResult 故障/不可服务结果（UNKNOWN 恒不阻断红线的统一承载）。
func unknownResult(detail string) OpResult {
	return OpResult{Outcome: "UNKNOWN", Reason: ReasonUnknown, Detail: detail}
}

// eval 单次 Eval 包装（固定 opTimeout；不从请求 ctx 派生——与请求生命周期解耦，
// 各操作独立计时，behaviorstore 同纪律）。
func (s *Store) eval(script string, keys []string, args []string) ([]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.opTimeout)
	defer cancel()
	return s.cli.Eval(ctx, script, keys, args)
}

// parseOpReply 解析 Lua 返回数组 {code, reason, token, detail, flags, auxToken}
// （auxToken 双态：OK+expired_takeover 时为被接管槽旧 token；REJECTED 时为当前
// fence 读数 → FenceCurrent，§8.4-2 裁决）。
func parseOpReply(out []interface{}) (OpResult, error) {
	if len(out) < 5 {
		return OpResult{}, errEmptyEvalResult
	}
	res := OpResult{
		Reason: luaStr(out[1]),
		Token:  luaInt(out[2]),
		Detail: luaStr(out[3]),
	}
	flags := luaInt(out[4])
	res.InstanceNew = flags&1 != 0
	res.ExpiredTakeover = flags&2 != 0
	res.InstanceConfirmed = flags&4 != 0
	switch luaInt(out[0]) {
	case luaOK:
		res.Outcome = "OK"
		if len(out) >= 6 && res.ExpiredTakeover {
			res.ExpiredToken = luaInt(out[5])
		}
	case luaOKReplay:
		res.Outcome = "OK"
		res.IdempotentReplay = true
	case luaConflict:
		res.Outcome = "CONFLICT"
	case luaRejected:
		res.Outcome = "REJECTED"
		if len(out) >= 6 {
			res.FenceCurrent = luaInt(out[5])
		}
	case luaUnknownScript:
		res.Outcome = "UNKNOWN"
	default:
		return OpResult{}, fmt.Errorf("flowguard: unknown lua result code %v", out[0])
	}
	return res, nil
}

// Reserve 步骤预留（Lua 单次原子往返）：
// 前置状态合法（序小于本步组起点的全部步骤已 CONFIRMED）+ 实例非终态 +
// 无冲突预留/幂等重放判定 → INCR fence 发 token 占槽带 lease。
// predStepKeys 为前置步骤槽的 step_key 列表（序列 < 本步并行组起点；首步为空）。
// allowNewInstance 定义级建实例闸（联调裁决 §8.4-1 育龄窗）：false=RETIRED 下发
// 版本——仅存量实例续跑（实例状态键存在），全新实例键拒入（definition_retired）；
// true=ACTIVE 版本（可 INSTANCE_NEW）。
// 任何 Valkey 故障 → UNKNOWN（不阻断；披露由调用方完成）。
func (s *Store) Reserve(instanceID, stepKey string, predStepKeys []string, leaseSeconds int, idemHash, digest string, allowNewInstance bool) OpResult {
	if s.cli == nil {
		return unknownResult("valkey_unconfigured")
	}
	allowNew := "0"
	if allowNewInstance {
		allowNew = "1"
	}
	keys := make([]string, 0, 3+len(predStepKeys))
	keys = append(keys, fenceKey(instanceID), stateKey(instanceID), stepSlotKey(instanceID, stepKey))
	for _, p := range predStepKeys {
		keys = append(keys, stepSlotKey(instanceID, p))
	}
	out, err := s.eval(reserveLua, keys, []string{
		stepKey,
		strconv.Itoa(leaseSeconds * 1000),
		idemHash,
		digest,
		strconv.FormatInt(s.instanceTTL.Milliseconds(), 10),
		allowNew,
	})
	if err != nil {
		s.warn("reserve", err)
		return unknownResult("valkey_error")
	}
	res, err := parseOpReply(out)
	if err != nil {
		s.warn("reserve", err)
		return unknownResult("eval_protocol_error")
	}
	return res
}

// Commit 步骤提交（FLOW-03 响应回程判定的接线预留；本批运行时不调用）。
// token == 当前 fence 且槽为 PENDING 持该 token 才接受（F05 旧 token 拒）；
// 同 token 同幂等键同摘要对已 CONFIRMED 槽重放 = 幂等返回。
// allStepKeys 为定义全部步骤（sequence 升序）——实例完成判定（全步骤 CONFIRMED
// → 实例 CONFIRMED）在同一原子域内完成。
func (s *Store) Commit(instanceID, stepKey string, allStepKeys []string, token int64, idemHash, digest string) OpResult {
	if s.cli == nil {
		return unknownResult("valkey_unconfigured")
	}
	keys := make([]string, 0, 3+len(allStepKeys))
	keys = append(keys, fenceKey(instanceID), stateKey(instanceID), stepSlotKey(instanceID, stepKey))
	for _, k := range allStepKeys {
		if k == stepKey {
			continue
		}
		keys = append(keys, stepSlotKey(instanceID, k))
	}
	out, err := s.eval(commitLua, keys, []string{
		stepKey,
		strconv.FormatInt(token, 10),
		strconv.FormatInt(s.instanceTTL.Milliseconds(), 10),
		idemHash,
		digest,
	})
	if err != nil {
		s.warn("commit", err)
		return unknownResult("valkey_error")
	}
	res, err := parseOpReply(out)
	if err != nil {
		s.warn("commit", err)
		return unknownResult("eval_protocol_error")
	}
	return res
}

// Release 步骤释放（同 token 校验；FLOW-03/对账链接线预留，本批运行时不调用）。
func (s *Store) Release(instanceID, stepKey string, token int64) OpResult {
	if s.cli == nil {
		return unknownResult("valkey_unconfigured")
	}
	out, err := s.eval(releaseLua, []string{
		fenceKey(instanceID), stateKey(instanceID), stepSlotKey(instanceID, stepKey),
	}, []string{
		stepKey,
		strconv.FormatInt(token, 10),
		strconv.FormatInt(s.instanceTTL.Milliseconds(), 10),
	})
	if err != nil {
		s.warn("release", err)
		return unknownResult("valkey_error")
	}
	res, err := parseOpReply(out)
	if err != nil {
		s.warn("release", err)
		return unknownResult("eval_protocol_error")
	}
	return res
}

// MarkAccepted 异步受理标记（NG-FLOW-03 §1.5 + §8.4-2 裁决：步骤 allows_202=true
// 且响应 202 → 已受理待完成，不自动完成）：同 token 校验后 **INCR fence 取新
// token**（受理即预留轮换——受理事件 fencing_token 携新 token，与首 RESERVE 事件
// 不再同键碰撞），槽位标记 accepted_202=1 + token/lease 随新 token 刷新，
// 步骤保持 PENDING、实例保持 ACTIVE——后续判定或人工对账收口。
func (s *Store) MarkAccepted(instanceID, stepKey string, token int64, leaseSeconds int) OpResult {
	if s.cli == nil {
		return unknownResult("valkey_unconfigured")
	}
	out, err := s.eval(markAcceptedLua, []string{
		fenceKey(instanceID), stateKey(instanceID), stepSlotKey(instanceID, stepKey),
	}, []string{
		stepKey,
		strconv.FormatInt(token, 10),
		strconv.Itoa(leaseSeconds * 1000),
		strconv.FormatInt(s.instanceTTL.Milliseconds(), 10),
	})
	if err != nil {
		s.warn("mark_accepted", err)
		return unknownResult("valkey_error")
	}
	res, err := parseOpReply(out)
	if err != nil {
		s.warn("mark_accepted", err)
		return unknownResult("eval_protocol_error")
	}
	return res
}

// MarkIndeterminate 实例 INDETERMINATE 标记（NG-FLOW-03 F04：超时/连接失败/
// 判定式不命中/形态无法解析 → 未知待对账）：仅 ACTIVE → INDETERMINATE；
// 热状态缺失不伪造（UNKNOWN state_missing）；终态/已 INDETERMINATE 幂等重放。
// 步骤槽保持 PENDING——绝不自动 release 为可重试（F04 红线：超时可能已成功，
// 回滚诱导重复扣款）；恢复由管理对账链收口（server 轨）。
func (s *Store) MarkIndeterminate(instanceID string) OpResult {
	if s.cli == nil {
		return unknownResult("valkey_unconfigured")
	}
	out, err := s.eval(markIndeterminateLua, []string{
		fenceKey(instanceID), stateKey(instanceID),
	}, []string{
		strconv.FormatInt(s.instanceTTL.Milliseconds(), 10),
	})
	if err != nil {
		s.warn("mark_indeterminate", err)
		return unknownResult("valkey_error")
	}
	res, err := parseOpReply(out)
	if err != nil {
		s.warn("mark_indeterminate", err)
		return unknownResult("eval_protocol_error")
	}
	return res
}

// luaInt 解析 Lua 数值返回（int64 或数字字符串）。
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

// luaStr 解析 Lua 字符串返回。
func luaStr(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// reserveLua 预留脚本。返回 {code, reason, token, detail, flags, auxToken}：
//
//	flags bit0=instance_new（实例首建），bit1=expired_takeover（接管过期槽），
//	auxToken=被接管槽旧 token；detail 子原因词表：reserved/instance_new/
//	idempotent_replay/digest_mismatch/reserve_conflict/already_confirmed/
//	predecessor_unconfirmed/instance_terminal/instance_indeterminate/
//	definition_retired。
//
// 幂等语义（F03）：idem 为空（未携带幂等键）不参与幂等键判定——同摘要重放仍
// 幂等去重（无害），异摘要按槽冲突处理（不升级为 IDEMPOTENT-CONFLICT，
// 冲突拒绝语义专属「同键异摘要」）。
//
// 育龄窗闸（§8.4-1 裁决）：allow_new=0（RETIRED 下发版本）且实例状态键不存在
// （全新实例键）→ definition_retired 拒入——RETIRED 版本仅存量实例续跑，
// 新实例必须按 ACTIVE 版本键。
const reserveLua = `
local fenceK = KEYS[1]
local stateK = KEYS[2]
local slotK = KEYS[3]
local stepKey = ARGV[1]
local leaseMs = tonumber(ARGV[2])
local idem = ARGV[3]
local digest = ARGV[4]
local ttlMs = tonumber(ARGV[5])
local allowNew = ARGV[6]

local t = redis.call('TIME')
local nowMs = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)

-- 实例状态：终态（CONFIRMED/CANCELLED/FAILED）拒入；INDETERMINATE 不可服务
-- （未知待对账——UNKNOWN 恒不阻断，由调用方放行+披露）
local status = redis.call('HGET', stateK, 'status')
if status then
  if status == 'CONFIRMED' or status == 'CANCELLED' or status == 'FAILED' then
    return {3, 'FLOW-RESERVE-001', 0, 'instance_terminal', 0, 0}
  end
  if status == 'INDETERMINATE' then
    return {4, 'UNKNOWN-001', 0, 'instance_indeterminate', 0, 0}
  end
else
  -- 育龄窗闸：RETIRED 版本不得创建新实例（存量续跑走 status 存在分支）
  if allowNew == '0' then
    return {3, 'FLOW-RESERVE-001', 0, 'definition_retired', 0, 0}
  end
end

-- 前置合法：序小于本步组起点的全部步骤须 CONFIRMED（PENDING 含 lease 有效
-- 亦未确认——非法并行与「无有效预留执行依赖步骤」同一承载）
for i = 4, #KEYS do
  local pst = redis.call('HGET', KEYS[i], 'state')
  if pst ~= 'CONFIRMED' then
    return {3, 'FLOW-RESERVE-001', 0, 'predecessor_unconfirmed', 0, 0}
  end
end

-- 目标步骤槽
local sv = {}
local slot = redis.call('HGETALL', slotK)
for i = 1, #slot, 2 do sv[slot[i]] = slot[i + 1] end

if sv['state'] == 'CONFIRMED' then
  if idem ~= '' and sv['idem'] == idem then
    if sv['digest'] == digest then
      return {1, '', tonumber(sv['token']), 'idempotent_replay', 0, 0}
    end
    return {2, 'IDEMPOTENT-CONFLICT-001', tonumber(sv['token']), 'digest_mismatch', 0, 0}
  end
  if idem == '' and sv['idem'] == '' and sv['digest'] == digest then
    return {1, '', tonumber(sv['token']), 'idempotent_replay', 0, 0}
  end
  return {3, 'FLOW-RESERVE-001', tonumber(sv['token']), 'already_confirmed', 0, 0}
end

local flags = 0
local auxToken = 0
if sv['state'] == 'PENDING' then
  if tonumber(sv['lease_exp']) > nowMs then
    if idem ~= '' and sv['idem'] == idem then
      if sv['digest'] == digest then
        return {1, '', tonumber(sv['token']), 'idempotent_replay', 0, 0}
      end
      return {2, 'IDEMPOTENT-CONFLICT-001', tonumber(sv['token']), 'digest_mismatch', 0, 0}
    end
    if idem == '' and sv['idem'] == '' and sv['digest'] == digest then
      return {1, '', tonumber(sv['token']), 'idempotent_replay', 0, 0}
    end
    return {2, 'FLOW-RESERVE-001', tonumber(sv['token']), 'reserve_conflict', 0, 0}
  end
  -- lease 过期：接管槽位，旧 token 随 fence INCR 失效（F05）
  flags = flags + 2
  auxToken = tonumber(sv['token']) or 0
end

local token = redis.call('INCR', fenceK)
redis.call('HSET', slotK, 'state', 'PENDING', 'token', token, 'lease_exp', nowMs + leaseMs,
  'idem', idem, 'digest', digest, 'reserved_ms', nowMs)
redis.call('PEXPIRE', slotK, ttlMs)
if status then
  redis.call('HSET', stateK, 'status', 'ACTIVE', 'current_step', stepKey)
else
  redis.call('HSET', stateK, 'status', 'ACTIVE', 'current_step', stepKey, 'created_ms', nowMs)
  flags = flags + 1
end
redis.call('PEXPIRE', stateK, ttlMs)
redis.call('PEXPIRE', fenceK, ttlMs)
if flags >= 2 then
  return {0, '', token, 'reserved', flags, auxToken}
end
return {0, '', token, 'reserved', flags, 0}
`

// commitLua 提交脚本。返回同 reserveLua 形状；flags bit2=instance_confirmed
// （定义全部步骤 CONFIRMED → 实例 CONFIRMED）。detail 词表：committed/
// instance_confirmed/idempotent_replay/stale_token/not_pending。
//
// 事件 token 语义（§8.4-2 裁决）：REJECTED（FENCE-001）时 token 位恒为**被拒的
// 旧 token**（事件自己持有的 token——唯一键 (instance,step,action,token) 不再与
// 同步骤后续 COMMIT OK 碰撞），当前 fence 读数移 auxToken（OpResult.FenceCurrent，
// 事件 evidence fence_current 承载）。
const commitLua = `
local fenceK = KEYS[1]
local stateK = KEYS[2]
local slotK = KEYS[3]
local stepKey = ARGV[1]
local token = tonumber(ARGV[2])
local ttlMs = tonumber(ARGV[3])
local idem = ARGV[4]
local digest = ARGV[5]

local t = redis.call('TIME')
local nowMs = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)

local sv = {}
local slot = redis.call('HGETALL', slotK)
for i = 1, #slot, 2 do sv[slot[i]] = slot[i + 1] end

-- 幂等重放先于 fencing 校验（F03 优先于 F05 的本案边界）：已 CONFIRMED 槽上
-- 同 token 同键同摘要的 commit 重试是只读返回既有结果，不覆盖任何新状态——
-- 即使 fence 已随后续步骤前移（迟到重试 ≠ 迟到覆盖）
if sv['state'] == 'CONFIRMED' then
  if tonumber(sv['token']) == token and sv['idem'] == idem and sv['digest'] == digest then
    return {1, '', token, 'idempotent_replay', 0, 0}
  end
  return {3, 'FENCE-001', token, 'not_pending', 0, tonumber(redis.call('GET', fenceK) or '0')}
end

-- fencing 校验：token 须等于当前 fence（lease 过期后被重预留 → fence 已前移，
-- 旧 token 一律拒绝——迟到响应不覆盖新状态，F05）
local cur = tonumber(redis.call('GET', fenceK) or '0')
if token ~= cur then
  return {3, 'FENCE-001', token, 'stale_token', 0, cur}
end

if sv['state'] ~= 'PENDING' or tonumber(sv['token']) ~= token then
  return {3, 'FENCE-001', token, 'not_pending', 0, cur}
end

redis.call('HSET', slotK, 'state', 'CONFIRMED', 'confirmed_ms', nowMs)
redis.call('PEXPIRE', slotK, ttlMs)

-- 实例完成判定：定义全部步骤 CONFIRMED → 实例 CONFIRMED（同一原子域）
local done = 1
for i = 4, #KEYS do
  local pst = redis.call('HGET', KEYS[i], 'state')
  if pst ~= 'CONFIRMED' then
    done = 0
    break
  end
end
local flags = 0
local detail = 'committed'
if done == 1 then
  redis.call('HSET', stateK, 'status', 'CONFIRMED', 'completed_ms', nowMs)
  flags = flags + 4
  detail = 'instance_confirmed'
end
redis.call('PEXPIRE', stateK, ttlMs)
redis.call('PEXPIRE', fenceK, ttlMs)
return {0, '', token, detail, flags, 0}
`

// releaseLua 释放脚本。返回同形状（FENCE-001 token 语义同 commitLua §8.4-2 裁决）；
// detail 词表：released/stale_token/not_releasable。
const releaseLua = `
local fenceK = KEYS[1]
local slotK = KEYS[3]
local token = tonumber(ARGV[2])
local ttlMs = tonumber(ARGV[3])

local t = redis.call('TIME')
local nowMs = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)

local cur = tonumber(redis.call('GET', fenceK) or '0')
if token ~= cur then
  return {3, 'FENCE-001', token, 'stale_token', 0, cur}
end

local sv = {}
local slot = redis.call('HGETALL', slotK)
for i = 1, #slot, 2 do sv[slot[i]] = slot[i + 1] end
if sv['state'] ~= 'PENDING' or tonumber(sv['token']) ~= token then
  return {3, 'FLOW-RESERVE-001', token, 'not_releasable', 0, cur}
end

redis.call('HSET', slotK, 'state', 'RELEASED', 'released_ms', nowMs)
redis.call('PEXPIRE', slotK, ttlMs)
redis.call('PEXPIRE', KEYS[2], ttlMs)
redis.call('PEXPIRE', fenceK, ttlMs)
return {0, '', token, 'released', 0, 0}
`

// markAcceptedLua 异步受理标记脚本（同 token 校验；受理即预留轮换——INCR fence
// 取新 token，槽 token/lease 随新 token 刷新，事件携新 token（§8.4-2 裁决：
// 与首 RESERVE 事件不再同键碰撞）；FENCE-001 token 语义同 commitLua。
// detail：accepted_202/stale_token/not_pending）。
const markAcceptedLua = `
local fenceK = KEYS[1]
local slotK = KEYS[3]
local stepKey = ARGV[1]
local token = tonumber(ARGV[2])
local leaseMs = tonumber(ARGV[3])
local ttlMs = tonumber(ARGV[4])

local t = redis.call('TIME')
local nowMs = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)

local cur = tonumber(redis.call('GET', fenceK) or '0')
if token ~= cur then
  return {3, 'FENCE-001', token, 'stale_token', 0, cur}
end

local sv = {}
local slot = redis.call('HGETALL', slotK)
for i = 1, #slot, 2 do sv[slot[i]] = slot[i + 1] end
if sv['state'] ~= 'PENDING' or tonumber(sv['token']) ~= token then
  return {3, 'FENCE-001', token, 'not_pending', 0, cur}
end

local newToken = redis.call('INCR', fenceK)
redis.call('HSET', slotK, 'accepted_202', 1, 'accepted_ms', nowMs,
  'token', newToken, 'lease_exp', nowMs + leaseMs)
redis.call('PEXPIRE', slotK, ttlMs)
redis.call('PEXPIRE', fenceK, ttlMs)
return {0, '', newToken, 'accepted_202', 0, 0}
`

// markIndeterminateLua 实例 INDETERMINATE 标记脚本（仅 ACTIVE 迁移；
// 热状态缺失不伪造 UNKNOWN state_missing；终态/已 INDETERMINATE 幂等重放）。
const markIndeterminateLua = `
local stateK = KEYS[2]
local ttlMs = tonumber(ARGV[1])

local t = redis.call('TIME')
local nowMs = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)

local status = redis.call('HGET', stateK, 'status')
if not status then
  return {4, 'UNKNOWN-001', 0, 'state_missing', 0, 0}
end
if status == 'ACTIVE' then
  redis.call('HSET', stateK, 'status', 'INDETERMINATE', 'indeterminate_ms', nowMs)
  redis.call('PEXPIRE', stateK, ttlMs)
  return {0, '', 0, 'marked', 0, 0}
end
return {1, '', 0, 'terminal_or_indeterminate', 0, 0}
`
