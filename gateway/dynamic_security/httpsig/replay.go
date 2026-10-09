// replay.go 重放原子存储（NG-ID G1 批次 A，§1.5/D5 冻结形态）：
// Valkey Lua **单次原子往返** SET NX PX（存在即重放）；键
// `mid:v1:nonce:{identity_fp}:{nonce_sha256_hex32}`（版本化命名空间 +
// hash tag 同槽——flowguard reserve.go 同形）；TTL=证明 expires 剩余期
// （上界 120s，§1.4-5——PX 相对 TTL 不依赖跨节点时钟）。
//
// 纪律（flowguard D8 红线承接）：
//   - Evaluator 接口形态（Eval(ctx, script, keys, args)——counters.ValkeyClient.Eval
//     结构化满足，零新依赖类型）；
//   - 单次 Eval 超时 300ms（同量纲）；不从请求 ctx 派生（与请求生命周期解耦，
//     behaviorstore/flowguard 同纪律）；
//   - 存储故障/超时/协议异常 → 错误透传（链位与 OBSERVE 放行披露/PROTECT 503
//     处置策略在 B2——本层不静默吞错、严禁本地内存回退去重（无进程内权威态，
//     存储即唯一事实源））。
package httpsig

import (
	"context"
	"errors"
	"sync"
	"time"
)

// 重放存储键域（版本化命名空间 v1 + hash tag 同槽）。
const replayKeyPrefix = "mid:v1:nonce:"

// defaultReplayOpTimeout 单次 Eval 超时上限（flowguard reserve.go 同量纲）。
const defaultReplayOpTimeout = 300 * time.Millisecond

// Evaluator Valkey 最小 Eval 接口（counters.ValkeyClient.Eval 同签名——
// 装配层结构化满足；便于测试替身与故障注入）。
type Evaluator interface {
	Eval(ctx context.Context, script string, keys []string, args []string) ([]interface{}, error)
}

// replaySetNXLua SET NX PX 单次原子往返（存在即重放）。返回 {1}=首次登记（非重放）、
// {0}=键已存在（重放）——数组形态：共享装配通道 counters.realValkey.Eval 只接受
// array 回复（标量 int64 触发「eval result not array」，S7 批次 C 联调实证——跨轨
// 对齐修复，登记于出口记录）。键形态：mid:v1:nonce:{identityFP}:{nonceDigestHex32}。
const replaySetNXLua = `
return {redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PX', tonumber(ARGV[2])) and 1 or 0}
`

// ReplayStore 重放存储（线契约逐字冻结形状：Evaluator 接口 + 300ms 超时）。
// cli 为 nil = 未配置存储：CheckAndSet 恒返回错误（errStoreUnconfigured——
// 处置策略（OBSERVE 放行披露/PROTECT 503）在 B2，本层不静默、不本机去重）。
type ReplayStore struct {
	cli Evaluator
	// now 时钟源（测试注入；nil = 系统时钟——仅用于告警节流，不参与 TTL 语义
	// （TTL 由调用方按证明 expires 剩余期计算，PX 相对时长由 Valkey 服务端承载））
	now      func() time.Time
	mu       sync.Mutex
	lastWarn time.Time
}

// errStoreUnconfigured 存储未配置（B2 按 UNAVAILABLE 处置语义消费——不判无效）。
var errStoreUnconfigured = errors.New("httpsig: replay store unconfigured")

// errReplayProtocol Lua 返回形态异常（按故障透传——B2 UNAVAILABLE 语义消费）。
var errReplayProtocol = errors.New("httpsig: replay eval protocol error")

// NewReplayStore 构造重放存储（cli 允许 nil——缺席语义由 B2 处置）。
func NewReplayStore(cli Evaluator) *ReplayStore {
	return &ReplayStore{cli: cli, now: time.Now}
}

// CheckAndSet 重放原子检查+登记（线契约逐字冻结签名）：nonce 键不存在 →
// 登记成功返回 (false, nil)；已存在 → (true, nil)（MID-REPLAY-DETECTED 语义
// 由 B2 映射）；存储故障 → (false, err)（err 如实透传——B2 UNAVAILABLE 处置，
// 不判无效、严禁本机去重）。
// ttl 为证明 expires 剩余期（调用方计算；≤0 防御归一 1s——零/负 TTL 键即生即灭
// 语义不清，防御为最小存活期并登记偏差）。
func (s *ReplayStore) CheckAndSet(ctx context.Context, identityFP, nonceDigestHex32 string, ttl time.Duration) (isReplay bool, err error) {
	if s == nil || s.cli == nil {
		return false, errStoreUnconfigured
	}
	if ttl <= 0 {
		ttl = time.Second // 防御归一（§1.4-5 时效校验在 B2 已拒过期证明——此处为边界防御）
	}
	key := replayKeyPrefix + "{" + identityFP + "}:" + nonceDigestHex32
	opCtx, cancel := context.WithTimeout(context.Background(), defaultReplayOpTimeout)
	defer cancel()
	out, err := s.cli.Eval(opCtx, replaySetNXLua, []string{key}, []string{"1", strconv64(ttl.Milliseconds())})
	if err != nil {
		return false, err // 故障如实透传（不静默）
	}
	if len(out) != 1 {
		return false, errReplayProtocol
	}
	switch v := out[0].(type) {
	case int64:
		return v == 0, nil
	case string:
		if v == "1" {
			return false, nil
		}
		if v == "0" {
			return true, nil
		}
		return false, errReplayProtocol
	default:
		return false, errReplayProtocol
	}
}

// strconv64 毫秒十进制。
func strconv64(v int64) string {
	return itoa64(v)
}
