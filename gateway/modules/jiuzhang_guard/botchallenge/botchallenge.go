// Package botchallenge Bot 浏览器挑战（WDSP P1-02 B2，任务书
// docs/tasks/wdsp-p1/P1-02_BOT_CHALLENGE.md §5/§6）：有界挑战状态、nonce 原子消费、
// clearance 签名与跨节点轮换、verify 本地端点处理逻辑。
//
// 纪律：
//   - 本包为可独立单测的纯逻辑包：**不接入 ServeHTTP 请求链**（B3 挂接），
//     不持有任何反向代理句柄——verify/命名空间处理只写本地响应，结构上不可能转发源站。
//   - 状态只存共享 Valkey 独立命名空间（键前缀 jiuzhang:guard:bot，B0 冻结），
//     单 Lua 原子往返 + 300ms 超时纪律与 riskengine/behaviorstore 一致；
//     服务端只存会话摘要/题目参数/应用/Host 摘要/策略代次/过期/已消费尝试数，
//     不落明文会话 ID 之外的业务数据，不写业务数据库。
//   - 故障语义（任务书 §5.4，fail-closed 例外仅适用于 Bot 步骤，不改变 riskengine
//     既有 fail-open 契约）：状态存储或所需密钥不可用 → ErrStateUnavailable /
//     ErrKeyUnavailable，verify 与 PROTECT 签发返回 503+Retry-After；
//     OBSERVE 的降级放行由调用方（B3）依据错误类型决定。
//   - 事件出口对齐 guard events.Logger 通道形状（EventSink 接口由 *events.Logger
//     满足）；绝不记录 nonce/solution/通行 Cookie/会话 Cookie/签名材料——
//     flow_id 为挑战 ID 的 SHA-256 截断指纹（单向脱敏）。
//   - 签名密钥独立于 JWT/CSRF/管理会话/Agent CA：经 Keyring 注入（配置发布通道
//     下发，key_ref 只引用预置密钥；key_id 仅本地允许列表选择，禁止拼接路径/URL）。
package botchallenge

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/ratelimit"
	"go.uber.org/zap"
)

// B0 冻结值（与 jiuzhang_guard/bot_policy.go、server/internal/botpolicy 逐条对应）。
const (
	// ValkeyKeyPrefix Valkey 独立命名空间（B0 冻结）。
	ValkeyKeyPrefix = "jiuzhang:guard:bot"
	// ReservedNamespace / VerifyPath 保留端点（B0 冻结；永不反向代理）。
	ReservedNamespace = "/_wdsp/bot/v1/"
	VerifyPath        = "/_wdsp/bot/v1/verify"
	// SessionCookieName / ClearanceCookieName 独立 __Host- Cookie（Secure/HttpOnly/
	// SameSite=Lax/Path=/无 Domain，仅 HTTPS；与管理登录会话完全隔离）。
	SessionCookieName   = "__Host-wdsp-bot-session"
	ClearanceCookieName = "__Host-wdsp-bot-clearance"
)

// 挑战参数边界（B0 冻结：nonce_ttl 90s(30..300)、clearance_ttl 900s(60..3600)、
// difficulty 14bit(10..18)、max_attempts 3(1..5)；Config.Validate 复检，
// 不信任调用方已校验——与 bot_policy.go 同一 fail-closed 口径）。
const (
	MinNonceTTL     = 30 * time.Second
	MaxNonceTTL     = 300 * time.Second
	MinClearanceTTL = 60 * time.Second
	MaxClearanceTTL = 3600 * time.Second
	MinDifficulty   = 10
	MaxDifficulty   = 18
	MinMaxAttempts  = 1
	MaxMaxAttempts  = 5
)

// 随机数与线格式边界（B2 冻结）。
const (
	sessionIDBytes   = 32 // 会话 ID 256 bit（任务书 §5.2 建议）
	challengeIDBytes = 16 // 挑战 ID 128 bit（≥128 bit 要求）
	nonceBytes       = 16 // 题目 nonce 128 bit
	cspNonceBytes    = 16 // CSP nonce 128 bit
	maxSolutionLen   = 20 // solution 为 uint64 十进制串（0..18446744073709551615）
	// MaxVerifyBodyBytes verify 正文上限 8 KiB（任务书 §3.2 冻结）。
	MaxVerifyBodyBytes = 8192
	// verifyReadTimeout 正文读取超时（尽力而为：http.ResponseController
	// SetReadDeadline 在 HTTP/2 等不支持时忽略错误，8KiB 上限仍是硬边界）。
	verifyReadTimeout = 2 * time.Second
	// computeBudgetMS 浏览器单次计算预算上限（任务书 §5.2：≤2s，超时手动重试，
	// 不无限加难度）。
	computeBudgetMS = 2000
	// clockSkew 时间比较容差（跨节点时钟微差）。
	clockSkew = 5 * time.Second
)

// 容量与速率上限（B2 冻结常量；任务书 §5.2 末段「所有服务端状态有容量和速率上限」）。
// 维度设计（任务书 §5.3：共享 NAT 不被简单 IP 阈值整体误伤）：
//   - 会话维为主限（会话 Cookie 为网关联名签发，伪造会话无法通过绑定校验）；
//   - 真实客户端 IP 维取宽松值，仅防单连接源洪峰，不等同用户（移动网络换 IP /
//     共享 NAT 正常通行不受影响：每维超限只返回 429，携带 Retry-After）；
//   - 应用维兜底，防签发洪峰撑大在途状态；
//   - 在途挑战总数硬上限：约 1 万条 × 约 300 字节 ≈ 数 MB Valkey 内存上界，
//     达到上限返回 503（容量是服务级条件），不允许无限增长。
const (
	IssueRatePerSession  = 6    // 次/分钟：正常浏览器一次挑战签发 1 次，留手动重试余量
	IssueRatePerIP       = 60   // 次/分钟：宽松（NAT 出口共享），主限在会话维
	IssueRatePerApp      = 600  // 次/分钟：应用级兜底
	VerifyRatePerSession = 12   // 次/分钟：max_attempts(≤5)/题 × 少量刷新重试
	VerifyRatePerIP      = 120  // 次/分钟：宽松
	VerifyRatePerApp     = 1200 // 次/分钟：应用级兜底
	MaxInFlightPerApp    = 10000
	rateWindow           = time.Minute
	// retryAfterRateLimited / retryAfterUnavailable 429/503 的 Retry-After 秒数（冻结）。
	retryAfterRateLimited = 30
	retryAfterUnavailable = 15
)

// opTimeout 单次 Valkey 往返超时（与 riskengine/behaviorstore 同一 300ms 纪律：
// 保证存储悬挂时请求 goroutine 阻塞有界；超时按 ErrStateUnavailable 处理）。
const opTimeout = 300 * time.Millisecond

// 错误类型（OBSERVE 降级判定依据；errors.Is 可判）。
var (
	// ErrStateUnavailable 共享状态存储不可用/超时/容量耗尽（PROTECT fail-closed 503）。
	ErrStateUnavailable = errors.New("botchallenge: state store unavailable")
	// ErrKeyUnavailable 所需签名密钥不可用（未注入或 key_ref 不在允许列表；
	// PROTECT fail-closed 503，绝不静默签发无法验证的通行）。
	ErrKeyUnavailable = errors.New("botchallenge: signing key unavailable")
	// ErrRateLimited 签发/验证速率超限（429）。
	ErrRateLimited = errors.New("botchallenge: rate limited")
	// ErrClearanceMissing 请求未携带通行 Cookie（正常业务流，非错误事件）。
	ErrClearanceMissing = errors.New("botchallenge: clearance cookie missing")
	// ErrClearanceExpired 通行已过期（B3 据此重新挑战；事件 reason CLEARANCE_EXPIRED）。
	ErrClearanceExpired = errors.New("botchallenge: clearance expired")
	// ErrClearanceRevoked 策略代次撤销（policy_epoch 不符；紧急撤销经新版本发布生效）。
	ErrClearanceRevoked = errors.New("botchallenge: clearance revoked by policy epoch")
	// ErrClearanceInvalid 签名/绑定/结构非法（伪造、跨应用/Host/会话、未知 key_id）。
	ErrClearanceInvalid = errors.New("botchallenge: clearance invalid")
)

// keyIDPattern key_id 词形（与 bot_policy.go botKeyRefPattern 同一正则：
// 仅引用名——禁止任何路径/URL 拼接形态）。
var keyIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// Mode 策略模式（与 bot_policy.go 枚举同值；OFF 不构造 Service——零依赖初始化）。
const (
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"
)

// RateLimits 三维速率上限（默认取 B2 冻结常量；仅测试可覆盖注入小值）。
type RateLimits struct {
	IssuePerSession  int64
	IssuePerIP       int64
	IssuePerApp      int64
	VerifyPerSession int64
	VerifyPerIP      int64
	VerifyPerApp     int64
}

// DefaultRateLimits B2 冻结默认限速。
func DefaultRateLimits() RateLimits {
	return RateLimits{
		IssuePerSession:  IssueRatePerSession,
		IssuePerIP:       IssueRatePerIP,
		IssuePerApp:      IssueRatePerApp,
		VerifyPerSession: VerifyRatePerSession,
		VerifyPerIP:      VerifyRatePerIP,
		VerifyPerApp:     VerifyRatePerApp,
	}
}

// EventSink 事件出口（与 guard events.Logger 通道同形；*events.Logger 直接满足）。
type EventSink interface {
	Emit(e events.Event) error
}

// Config Service 装配入参（B3 由 Guard.botPolicy 映射构造；本包不 import
// jiuzhang_guard 内部类型，保持可独立单测）。
type Config struct {
	AppID   string // 应用 ID（事件 application_id）
	AppCode string // 应用编码（事件 application_code）
	Mode    string // OBSERVE | PROTECT（OFF 不得构造 Service）
	// PolicyVersion 策略有效版本；B2 冻结：policy_epoch = PolicyVersion
	// （B1 schema 无独立 policy_epoch 字段；紧急撤销经新版本策略发布生效——
	// 版本递增即旧代次通行全部失效）。
	PolicyVersion int
	NonceTTL      time.Duration
	ClearanceTTL  time.Duration
	Difficulty    int
	MaxAttempts   int
	KeyRef        string            // 策略 challenge.key_ref（仅引用名；空 = 不限定当前签名 key_id）
	Keyring       *Keyring          // 独立签名密钥环（不得与 JWT/CSRF/管理会话/Agent CA 共用）
	Store         *Store            // Valkey 挑战状态存储（共享引擎连接）
	Limiter       ratelimit.Limiter // 速率上限（共享引擎限速器，键前缀独立）
	Sink          EventSink         // 事件出口（nil = 静默丢弃，仅测试用）
	Node          string            // 网关节点标识（事件 gateway_node_id 由 Logger 覆盖，此处兜底）
	Logger        *zap.Logger       // nil = 告警静默（装配层必须传）
	Limits        RateLimits        // 零值 = DefaultRateLimits()
	InFlightCap   int               // 零值 = MaxInFlightPerApp
}

// Validate 装配期校验（fail-closed：任一非法拒绝构造——与 bot_policy.go 同一口径）。
func (c *Config) Validate() error {
	if c.AppID == "" {
		return fmt.Errorf("botchallenge: app_id required")
	}
	switch c.Mode {
	case ModeObserve, ModeProtect:
	default:
		return fmt.Errorf("botchallenge: unknown mode %q（OFF 不得构造 Service）", c.Mode)
	}
	if c.PolicyVersion <= 0 {
		return fmt.Errorf("botchallenge: policy_version must be > 0")
	}
	if c.NonceTTL < MinNonceTTL || c.NonceTTL > MaxNonceTTL {
		return fmt.Errorf("botchallenge: nonce_ttl %v 越界 [%v,%v]", c.NonceTTL, MinNonceTTL, MaxNonceTTL)
	}
	if c.ClearanceTTL < MinClearanceTTL || c.ClearanceTTL > MaxClearanceTTL {
		return fmt.Errorf("botchallenge: clearance_ttl %v 越界 [%v,%v]", c.ClearanceTTL, MinClearanceTTL, MaxClearanceTTL)
	}
	if c.Difficulty < MinDifficulty || c.Difficulty > MaxDifficulty {
		return fmt.Errorf("botchallenge: difficulty %d 越界 [%d,%d]", c.Difficulty, MinDifficulty, MaxDifficulty)
	}
	if c.MaxAttempts < MinMaxAttempts || c.MaxAttempts > MaxMaxAttempts {
		return fmt.Errorf("botchallenge: max_attempts %d 越界 [%d,%d]", c.MaxAttempts, MinMaxAttempts, MaxMaxAttempts)
	}
	if c.KeyRef != "" && !keyIDPattern.MatchString(c.KeyRef) {
		return fmt.Errorf("botchallenge: key_ref 非法引用名 %q", c.KeyRef)
	}
	if c.Keyring == nil {
		return fmt.Errorf("botchallenge: keyring required（独立签名密钥，不得与其他用途共用）")
	}
	if c.Store == nil {
		return fmt.Errorf("botchallenge: store required")
	}
	if c.Limiter == nil {
		return fmt.Errorf("botchallenge: rate limiter required")
	}
	return nil
}

// CallContext 单次调用上下文（由 B3 从 Guard 请求链提取；本包不自行解析真实 IP）。
type CallContext struct {
	RequestID    string // X-Request-Id（链路已生成）
	ClientIP     string // 真实客户端 IP（Guard 真实 IP 识别结果）
	ConnectionIP string // 连接源 IP
}

// Service Bot 挑战服务（每应用一个实例；并发安全）。
type Service struct {
	cfg     Config
	limits  RateLimits
	capN    int
	now     func() time.Time // 测试可注入
	logger  *zap.Logger
	emitted *emittedFlows // clearance_accepted 每 flow 每节点只记一次（有界 LRU）
}

// NewService 构造服务（Config.Validate fail-closed；OFF 不应到达此处）。
func NewService(cfg Config) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	limits := cfg.Limits
	if limits == (RateLimits{}) {
		limits = DefaultRateLimits()
	}
	capN := cfg.InFlightCap
	if capN <= 0 {
		capN = MaxInFlightPerApp
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	// key_ref 限定：策略引用名必须落在密钥环允许列表（key_id 仅本地允许列表选择；
	// 装配期 fail-closed，避免运行期才暴露密钥缺失导致全站挑战故障——任务书 §5.4 末段）。
	if cfg.KeyRef != "" {
		if _, ok := cfg.Keyring.Lookup(cfg.KeyRef); !ok {
			return nil, fmt.Errorf("%w: key_ref %q 不在密钥环允许列表", ErrKeyUnavailable, cfg.KeyRef)
		}
	}
	return &Service{
		cfg:     cfg,
		limits:  limits,
		capN:    capN,
		now:     time.Now,
		logger:  logger,
		emitted: newEmittedFlows(4096),
	}, nil
}

// sessionTTL 会话 Cookie 有效期（B2 冻结：nonce_ttl + clearance_ttl——
// 会话须覆盖「挑战→通行」全程，通行校验绑定会话摘要）。
func (s *Service) sessionTTL() time.Duration { return s.cfg.NonceTTL + s.cfg.ClearanceTTL }

// policyEpoch 撤销代次（B2 冻结 = 策略版本）。
func (s *Service) policyEpoch() int { return s.cfg.PolicyVersion }

// serveHTTPQuiet 工具：写纯文本错误（非 verify 结构化路径用——503 挑战不可用页等）。
func writePlain(w http.ResponseWriter, status int, retryAfter int, msg string) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	if retryAfter > 0 {
		h.Set("Retry-After", fmt.Sprintf("%d", retryAfter))
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}
