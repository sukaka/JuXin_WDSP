// 身份风险策略（WDSP AI 自动化渗透防护增强 阶段3：Risk Engine + Enforcement）的 Guard 装配桥接。
//
// 纪律（与 identitybehavior_module.go 同一模式）：
//   - 配置缺省 = 零行为变化：risk_policy 段不下发或 enabled=false 时不装配引擎，
//     请求链路无评估、无事件、无存储；challenge_threshold 缺省为 0，新挑战档关闭；
//   - 任何配置缺失/非法 fail-open 按 OBSERVE（riskengine.Compile 逐项消毒 + Warn，
//     装配永不失败；非法 mode 按 OBSERVE；非法/倒置挑战阈值仅关闭新档——绝不据非法配置实断）；
//   - OBSERVE 永不实断：达阈仅记录"假设会处置"事件（含 would_challenge）；
//     PROTECT 的 BLOCK/RATE_LIMIT 保持原位执行，CHALLENGE 只登记请求上下文并继续配额/CC，
//     由 Bot 统一步骤实际签发；事件 reason 固定 identity_risk_policy，不伪装成规则阻断；
//   - 白名单优先：IP 白名单/L7 allow 在执行点之前已提前放行；身份行为白名单（identitybehavior
//     whitelist）命中在执行点显式跳过，且不累积该请求的信号（三入口同一口径）；
//   - 执行点在 serveGuard 前置链路（自动临时封禁之后、授权限速与 CC 之前），与人工/自动
//     临时封禁同层；不改 dynamic_security/decision 的可信 BLOCK 源（红线）；
//   - 运行期失败 fail-open：评估/限速引擎故障仅告警放行（fail-closed 实例限速故障按既有
//     CC 口径 429），存储故障由 riskengine 实现内回退内存；Bot Offer 自身故障保持真实 429/503。
package jiuzhang_guard

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/ratelimit"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/riskengine"
	"go.uber.org/zap"
)

// riskPolicyJSON 发布通道下发原文（risk_policy 段，与 identity_behavior 同级；json tag
// 为跨分片冻结契约，不得改动）。定义为 riskengine.Params 的别名，发布契约与引擎编译入参同源。
type riskPolicyJSON = riskengine.Params

// pendingRiskChallenge 仅在当前请求内传递已达阈的风险挑战决策；不写全局状态，
// 不代表挑战已签发。Bot 只有在实际写出 403 挑战页后才发 challenged 事件。
type pendingRiskChallenge struct {
	engine   *riskengine.Engine
	decision riskengine.Decision
}

type pendingRiskChallengeKey struct{}

func registerRiskChallenge(r *http.Request, eng *riskengine.Engine, dec riskengine.Decision) {
	ctx := context.WithValue(r.Context(), pendingRiskChallengeKey{}, &pendingRiskChallenge{engine: eng, decision: dec})
	*r = *r.WithContext(ctx)
}

func pendingRiskChallengeFor(r *http.Request) *pendingRiskChallenge {
	pending, _ := r.Context().Value(pendingRiskChallengeKey{}).(*pendingRiskChallenge)
	return pending
}

// validateRiskChallengeDependency 校验当前应用实际生效的风险策略。仅 PROTECT 且
// 挑战档经 Compile 消毒后仍启用时要求 Bot PROTECT；其他应用覆盖不影响本路由。
func (g *Guard) validateRiskChallengeDependency(bp *botPolicyJSON) error {
	policy := g.RiskPolicy
	for _, override := range g.RiskPolicyOverrides {
		if override.ApplicationID == g.AppID {
			policy = &override.Policy
		}
	}
	cfg, err := riskengine.Compile(policy, g.logger)
	if err != nil {
		return fmt.Errorf("risk_policy: compile for challenge dependency: %w", err)
	}
	if cfg == nil || cfg.Mode != riskengine.ModeProtect || cfg.ChallengeThreshold == 0 {
		return nil
	}
	if bp == nil {
		return fmt.Errorf("risk_policy: PROTECT challenge_threshold requires bot_policy mode=PROTECT")
	}
	if bp.Mode != botModeProtect {
		return fmt.Errorf("risk_policy: PROTECT challenge_threshold requires bot_policy mode=PROTECT, got %s", bp.Mode)
	}
	return nil
}

// provisionRiskPolicy 装配身份风险策略：编译配置 → 选定 Store（behavior_store=valkey 且共享
// 引擎 Valkey 连接可用 → Valkey 实现，否则进程内存实现；与 identitybehavior 同一口径）→ 建引擎
// → 注入身份行为信号汇聚回调。需在共享引擎就绪后调用；Compile 按契约 fail-open 不返回错误。
func (g *Guard) provisionRiskPolicy(eng *sharedEngine) {
	g.risk = g.buildRiskEngine(g.RiskPolicy, eng)
	g.riskOverrides = nil
	g.sharedDeviceAccountLimits = nil
	if len(g.RiskPolicyOverrides) > 0 {
		g.riskOverrides = make(map[string]*riskengine.Engine, len(g.RiskPolicyOverrides))
		for _, override := range g.RiskPolicyOverrides {
			g.riskOverrides[override.ApplicationID] = g.buildRiskEngine(&override.Policy, eng)
			limit := override.SharedDeviceAccountLimit
			if limit == 0 {
				delete(g.sharedDeviceAccountLimits, override.ApplicationID)
				continue
			}
			if limit < 2 || limit > 1000 {
				g.logger.Warn("invalid shared-device account limit, using default",
					zap.String("application_id", override.ApplicationID), zap.Int("limit", limit))
				delete(g.sharedDeviceAccountLimits, override.ApplicationID)
				continue
			}
			if g.sharedDeviceAccountLimits == nil {
				g.sharedDeviceAccountLimits = make(map[string]int)
			}
			g.sharedDeviceAccountLimits[override.ApplicationID] = limit
		}
	}
	if g.ibh != nil && (g.risk != nil || len(g.riskOverrides) > 0) {
		g.ibh.SetSignalSink(g.addRiskIdentitySignals)
	}
}

// enforceRiskPolicy 身份风险策略执行点（serveGuard 前置链路：自动临时封禁之后、授权限速与
// CC 之前——与人工/自动临时封禁同层）。handled=true 表示已响应（403/429）。
// OBSERVE 模式永不实断（仅记录"假设会处置"事件）；评估/存储故障 fail-open 放行。
func (g *Guard) enforceRiskPolicy(w http.ResponseWriter, r *http.Request, res clientip.Result, base events.Event) (bool, error) {
	eng := g.riskEngineForApp()
	if eng == nil {
		return false, nil
	}
	cfg := eng.Config()
	// 身份行为白名单优先：命中完全跳过风险处置（信号在入口侧同样不累积）
	if g.ibh != nil && g.ibh.Whitelisted(res.ClientIP, r.Header.Get("User-Agent")) {
		return false, nil
	}
	// H-08：评估请求携带的全部候选身份键，取最严格处置（BLOCK > CHALLENGE > RATE_LIMIT > PASS），
	// 防止攻击者在已受罚的 X-API-Key/Cookie 之外附加无关 Authorization 头绕过风险策略。
	keys := riskengine.IdentityKeysFor(r, g.IdentitySalt, res.ClientIP.String())
	var dec riskengine.Decision
	var firstErr error
	evaluated := false
	for _, k := range keys {
		d, err := eng.Evaluate(g.riskIdentityKey(k))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !evaluated || riskDecisionMoreSevere(d, dec) {
			dec = d
			evaluated = true
		}
	}
	if !evaluated {
		if firstErr != nil {
			g.logger.Warn("risk_policy: 评估失败（fail-open 放行）", zap.Error(firstErr), zap.String("path", r.URL.Path))
		}
		return false, nil
	}
	switch dec.Action {
	case riskengine.ActionBlock:
		if cfg.Mode != riskengine.ModeProtect {
			DispositionFrom(r.Context()).RecordStep(ExecutorRiskPolicy, StepObserved,
				fmt.Sprintf("would_block score=%d threshold=%d", dec.Score, dec.Threshold))
			g.emitRiskEvent(eng, r, res, base, dec, events.RiskPolicyBlock, "would_block", 0)
			return false, nil
		}
		g.setRiskResponseHeaders(w, base.RequestID, cfg.Version)
		dispo := DispositionFrom(r.Context())
		dispo.RecordTerminal(ExecutorRiskPolicy, DisActionBlock, http.StatusForbidden, false,
			[]string{"IDENTITY_RISK_POLICY"}, nil)
		g.emitRiskEvent(eng, r, res, base, dec, events.RiskPolicyBlock, "blocked", http.StatusForbidden)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return true, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("blocked by identity risk policy"))
	case riskengine.ActionChallenge:
		if cfg.Mode != riskengine.ModeProtect {
			DispositionFrom(r.Context()).RecordStep(ExecutorRiskPolicy, StepObserved,
				fmt.Sprintf("would_challenge score=%d threshold=%d", dec.Score, dec.Threshold))
			g.emitRiskEvent(eng, r, res, base, dec, events.RiskPolicyChallenge, "would_challenge", 0)
			return false, nil
		}
		DispositionFrom(r.Context()).RecordStep(ExecutorRiskPolicy, StepExecuted,
			fmt.Sprintf("challenge pending score=%d threshold=%d", dec.Score, dec.Threshold))
		registerRiskChallenge(r, eng, dec)
		return false, nil
	case riskengine.ActionRateLimit:
		if cfg.Mode != riskengine.ModeProtect {
			DispositionFrom(r.Context()).RecordStep(ExecutorRiskPolicy, StepObserved,
				fmt.Sprintf("would_rate_limit score=%d threshold=%d", dec.Score, dec.Threshold))
			g.emitRiskEvent(eng, r, res, base, dec, events.RiskPolicyRateLimit, "would_rate_limit", 0)
			return false, nil
		}
		lim, lerr := g.engine.limiter.Allow(r.Context(), "risk:"+dec.IdentityKey,
			ratelimit.TokenBucket, int64(cfg.RateLimitRPS), time.Second, 0)
		if lerr != nil {
			// 限速引擎故障按本实例故障策略（与 CC 同一口径）：Fail-open 放行 / Fail-closed 429
			g.logger.Warn("risk_policy: 限速引擎故障",
				zap.Error(lerr), zap.Bool("fail_open", g.failOpen))
			if g.failOpen {
				return false, nil
			}
			g.setRiskResponseHeaders(w, base.RequestID, cfg.Version)
			g.writeTooMany(w, r, base.RequestID, 60)
			DispositionFrom(r.Context()).RecordTerminal(ExecutorRiskPolicy, DisActionRateLimit,
				http.StatusTooManyRequests, true, []string{"IDENTITY_RISK_POLICY"}, nil)
			g.emitRiskEvent(eng, r, res, base, dec, events.RiskPolicyRateLimit, "rate_limited", http.StatusTooManyRequests)
			accessLogAnnotate(r.Context(), wafActionBlock)
			return true, nil
		}
		if lim.Allowed {
			return false, nil
		}
		g.setRiskResponseHeaders(w, base.RequestID, cfg.Version)
		g.writeTooMany(w, r, base.RequestID, int(lim.RetryAfter.Seconds())+1)
		DispositionFrom(r.Context()).RecordTerminal(ExecutorRiskPolicy, DisActionRateLimit,
			http.StatusTooManyRequests, true, []string{"IDENTITY_RISK_POLICY"}, nil)
		g.emitRiskEvent(eng, r, res, base, dec, events.RiskPolicyRateLimit, "rate_limited", http.StatusTooManyRequests)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return true, nil
	}
	return false, nil
}

// emitRiskEvent 输出身份风险策略处置事件（含 OBSERVE 模式"假设会处置"记录）：
// 60s / identity+action 节流防洪；signals 完整列表随事件（可解释"为什么得 N 分"）；
// reason 固定 identity_risk_policy（设计 #15.2 红线：不伪装成规则阻断）。
func (g *Guard) emitRiskEvent(eng *riskengine.Engine, r *http.Request, res clientip.Result, base events.Event, dec riskengine.Decision, t events.Type, taken string, status int) {
	if !eng.ShouldEmit(dec.IdentityKey, taken) {
		return
	}
	ev := base
	sigs := make([]events.RiskSignalEntry, len(dec.Signals))
	for i, s := range dec.Signals {
		sigs[i] = events.RiskSignalEntry{Type: s.Type, Score: s.Score, Reason: s.Reason, At: s.At}
	}
	ev.Risk = &events.RiskPolicyDetail{
		IdentityKey:   dec.IdentityKey,
		Score:         dec.Score,
		RiskLevel:     dec.Level,
		Threshold:     dec.Threshold,
		Mode:          eng.Config().Mode,
		PolicyVersion: eng.Config().Version,
		Reason:        "identity_risk_policy",
		ActionTaken:   taken,
		Signals:       sigs,
	}
	// P0-04：仅 PROTECT 实际终止事件挂 final_decision（would_* 观察事件不挂——
	// 请求未终止，提前 Finalize 会锁死后续记录）；challenged 仅在 Bot 403 后调用。
	if taken == "blocked" || taken == "challenged" || taken == "rate_limited" {
		if d := DispositionFrom(r.Context()); d != nil {
			ev.FinalDecision = d.JSON()
		}
	}
	g.emit(ev, t, taken, status)
}

// feedRiskSignals apiprotect 统一管线信号入口：事件 Details 中每条 ScoreDelta>0 的
// DetectorMatch → 风险累加器（signal_type=detector 名大写蛇形）。identitybehavior 信号
// 不经此路径（Signal 非 DetectorMatch，无双计）。任何异常 recover + Warn（fail-open）。
func (g *Guard) feedRiskSignals(r *http.Request, matches []dsctx.DetectorMatch) {
	defer func() {
		if rec := recover(); rec != nil {
			g.logger.Error("risk_policy: feed signals panic (fail-open)", zap.Any("panic", rec))
		}
	}()
	eng := g.riskEngineForApp()
	if eng == nil || len(matches) == 0 {
		return
	}
	ip, err := clientip.ConnectionIP(r)
	if err != nil || !ip.IsValid() {
		return
	}
	// 身份行为白名单命中不累积（与执行点跳过同一口径：白名单身份零风险记账）
	if g.ibh != nil && g.ibh.Whitelisted(ip, r.Header.Get("User-Agent")) {
		return
	}
	// H-08：向全部候选凭据键同步累计检测器风险信号。
	for _, k := range riskengine.IdentityKeysFor(r, g.IdentitySalt, ip.String()) {
		eng.AddDetectorMatches(g.riskIdentityKey(k), matches)
	}
}

func riskActionRank(action string) int {
	switch action {
	case riskengine.ActionBlock:
		return 3
	case riskengine.ActionChallenge:
		return 2
	case riskengine.ActionRateLimit:
		return 1
	default:
		return 0
	}
}

func riskDecisionMoreSevere(a, b riskengine.Decision) bool {
	ra, rb := riskActionRank(a.Action), riskActionRank(b.Action)
	if ra != rb {
		return ra > rb
	}
	return a.Score > b.Score
}
