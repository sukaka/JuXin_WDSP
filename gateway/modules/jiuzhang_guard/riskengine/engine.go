package riskengine

import (
	"net/http"
	"strings"
	"sync"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
	"go.uber.org/zap"
)

// emitThrottleInterval 处置事件节流间隔（60s / identity+action，防扫描洪泛撑爆事件通道）。
const emitThrottleInterval = time.Minute

// throttleCap 事件节流状态键上限（identity 键量级与内存存储一致）。
const throttleCap = 50000

// Engine 身份风险引擎：信号累加（AddSignal 族）+ 滑窗评估（Evaluate）+ 事件节流（ShouldEmit）。
// 所有方法 nil 安全、内部 fail-open——存储故障仅告警，绝不向请求路径返回错误外的副作用。
type Engine struct {
	cfg    *Config
	store  Store
	logger *zap.Logger
	now    func() time.Time

	thMu      sync.Mutex
	throttle  map[string]time.Time // identity|action -> 上次发出时间
	throttled int                  // 节流状态键数（超 throttleCap 重建）
}

// NewEngine 装配引擎（cfg 为 Compile 产物；store 由装配层按配置选定实现）。
func NewEngine(cfg *Config, store Store, logger *zap.Logger) *Engine {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Engine{
		cfg:      cfg,
		store:    store,
		logger:   logger,
		now:      time.Now,
		throttle: map[string]time.Time{},
	}
}

// Config 返回编译后策略（请求路径只读）。
func (e *Engine) Config() *Config { return e.cfg }

// AddSignal 单条信号入账：policy.scores 有对应 signal_type 键时覆盖信号自带分
// （覆盖为 0 = 该信号不计分）；存储失败 fail-open 仅告警。
func (e *Engine) AddSignal(identityKey, signalType string, score int, reason string) {
	if e == nil || e.cfg == nil || e.store == nil || identityKey == "" || signalType == "" {
		return
	}
	if v, ok := e.cfg.Scores[signalType]; ok {
		score = v
	}
	if score <= 0 {
		return
	}
	if len(reason) > maxReasonLen {
		reason = reason[:maxReasonLen]
	}
	entry := SignalEntry{Type: signalType, Score: score, Reason: reason, At: e.now().UTC()}
	if err := e.store.Add(identityKey, entry); err != nil {
		// 存储实现内部已 fail-open，到达此处为防御性兜底（如实告警，不静默）
		e.logger.Warn("riskengine: add signal failed (fail-open)",
			zap.Error(err), zap.String("signal_type", signalType))
	}
}

// AddIdentitySignals identitybehavior 侦察信号汇聚入口（信号名原样为 signal_type，
// 如 SENSITIVE_PATH_PROBE / HEADLESS；与 apiprotect DetectorMatch 路径互不重迭，无双计）。
func (e *Engine) AddIdentitySignals(identityKey string, sigs []identitybehavior.Signal) {
	for _, s := range sigs {
		e.AddSignal(identityKey, s.Signal, s.ScoreDelta, s.Reason)
	}
}

// AddDetectorMatches apiprotect 统一管线信号入口：每条 ScoreDelta>0 的 DetectorMatch
// 入账（signal_type = detector 名大写蛇形，如 WAF/API_SCHEMA/API_PARSER/AUTHENTICATION；
// detector 名本身即蛇形小写，ToUpper 即契约形态）。
func (e *Engine) AddDetectorMatches(identityKey string, matches []dsctx.DetectorMatch) {
	for _, m := range matches {
		if m.ScoreDelta <= 0 {
			continue
		}
		e.AddSignal(identityKey, strings.ToUpper(m.Detector), m.ScoreDelta, matchReason(m))
	}
}

// Decision 单请求风险处置评估结果（策略判定与模式无关；OBSERVE/PROTECT 语义由调用方执行）。
type Decision struct {
	Action      string // PASS | RATE_LIMIT | BLOCK
	IdentityKey string
	Score       int    // 滑窗求和并截断 [0,100]
	Level       string // LOW | MEDIUM | HIGH | CRITICAL
	Threshold   int    // 命中的阈值（PASS 为 0）
	Signals     []SignalEntry
}

// Evaluate 滑窗评估：score>=block_threshold → BLOCK；>=rate_limit_threshold → RATE_LIMIT；
// 否则 PASS。返回完整 signals 明细（可解释性：事件必须能说明"为什么得 N 分"）。
// 存储故障 fail-open 返回错误——调用方按放行处理（评估失败永不实断）。
func (e *Engine) Evaluate(identityKey string) (Decision, error) {
	if e == nil || e.cfg == nil || e.store == nil || identityKey == "" {
		return Decision{Action: ActionPass, IdentityKey: identityKey}, nil
	}
	score, entries, err := e.store.State(identityKey)
	if err != nil {
		return Decision{Action: ActionPass, IdentityKey: identityKey}, err
	}
	dec := Decision{
		Action:      ActionPass,
		IdentityKey: identityKey,
		Score:       score,
		Level:       e.cfg.Level(score),
		Signals:     entries,
	}
	switch {
	case score >= e.cfg.BlockThreshold:
		dec.Action = ActionBlock
		dec.Threshold = e.cfg.BlockThreshold
	case score >= e.cfg.RateLimitThreshold:
		dec.Action = ActionRateLimit
		dec.Threshold = e.cfg.RateLimitThreshold
	}
	return dec, nil
}

// ShouldEmit 处置事件节流（60s / identity+action；状态随引擎实例，配置重载即复位——
// 与 identitybehavior 事件节流同实例语义）。
func (e *Engine) ShouldEmit(identityKey, action string) bool {
	if e == nil {
		return true
	}
	e.thMu.Lock()
	defer e.thMu.Unlock()
	now := e.now()
	k := identityKey + "|" + action
	if t, ok := e.throttle[k]; ok && now.Sub(t) < emitThrottleInterval {
		return false
	}
	e.throttle[k] = now
	e.throttled++
	if e.throttled > throttleCap {
		// 容量纪律：整体重建保近期项（近似 LRU；防随机 identity 键撑爆内存）
		kept := make(map[string]time.Time, throttleCap/2)
		for kk, v := range e.throttle {
			if now.Sub(v) < emitThrottleInterval {
				kept[kk] = v
			}
		}
		e.throttle = kept
		e.throttled = len(kept)
	}
	return true
}

// Close 释放存储（Valkey 共享连接不在此关闭——归共享引擎所有）。
func (e *Engine) Close() error {
	if e == nil || e.store == nil {
		return nil
	}
	return e.store.Close()
}

// IdentityKeyFor 请求身份键：优先身份引擎 Begin 写入的上下文结果；无（identity_behavior
// 未启用或白名单跳过）时按同一算法现场解析（确定性同键，盐 = identity_salt）。
func IdentityKeyFor(r *http.Request, salt, clientIP string) string {
	if id := identitybehavior.IdentityFrom(r.Context()); id != nil {
		return id.Key
	}
	return identitybehavior.ResolveIdentity(r, salt, clientIP).Key
}

// matchReason DetectorMatch 信号原因（rule_id + message，去敏截断由 AddSignal 兜底）。
func matchReason(m dsctx.DetectorMatch) string {
	return strings.TrimSpace(strings.TrimSpace(m.RuleID) + " " + strings.TrimSpace(m.Message))
}
