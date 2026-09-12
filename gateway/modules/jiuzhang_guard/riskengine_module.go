// 身份风险策略（WDSP AI 自动化渗透防护增强 阶段3：Risk Engine + Enforcement）的 Guard 装配桥接。
//
// 纪律（与 identitybehavior_module.go 同一模式）：
//   - 配置缺省 = 零行为变化：risk_policy 段不下发或 enabled=false 时不装配引擎，
//     请求链路无评估、无事件、无存储；
//   - 任何配置缺失/非法 fail-open 按 OBSERVE（riskengine.Compile 逐项消毒 + Warn，
//     装配永不失败；非法 mode 按 OBSERVE——绝不据非法配置实断）；
//   - OBSERVE 永不实断：达阈仅记录"假设会处置"事件（action_taken=would_block/would_rate_limit）；
//     PROTECT 按阈值实断 403/429，事件 reason 固定 identity_risk_policy，不伪装成规则阻断；
//   - 白名单优先：IP 白名单/L7 allow 在执行点之前已提前放行；身份行为白名单（identitybehavior
//     whitelist）命中在执行点显式跳过，且不累积该请求的信号（三入口同一口径）；
//   - 执行点在 serveGuard 前置链路（自动临时封禁之后、授权限速与 CC 之前），与人工/自动
//     临时封禁同层；不改 dynamic_security/decision 的可信 BLOCK 源（红线）；
//   - 运行期失败 fail-open：评估/限速引擎故障仅告警放行（fail-closed 实例限速故障按既有
//     CC 口径 429），存储故障由 riskengine 实现内回退内存——请求永不因本功能失败而失败。
package jiuzhang_guard

import (
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

// provisionRiskPolicy 装配身份风险策略：编译配置 → 选定 Store（behavior_store=valkey 且共享
// 引擎 Valkey 连接可用 → Valkey 实现，否则进程内存实现；与 identitybehavior 同一口径）→ 建引擎
// → 注入身份行为信号汇聚回调。需在共享引擎就绪后调用；Compile 按契约 fail-open 不返回错误。
func (g *Guard) provisionRiskPolicy(eng *sharedEngine) {
	p := g.RiskPolicy
	if p == nil || !p.Enabled {
		return
	}
	cfg, err := riskengine.Compile(p, g.logger)
	if err != nil {
		// 契约约定 Compile 不失败；到达此处为防御性兜底（fail-open：记 Error 并关闭本功能）
		g.logger.Error("risk_policy: 配置编译失败，功能关闭（fail-open）", zap.Error(err))
		return
	}
	if cfg == nil {
		return
	}
	// 内存实现为 Valkey 故障的运行期回退与缺省路径；identity 键上限复用 max_counter_keys
	// （与 identitybehavior 同一容量纪律）
	mem := riskengine.NewMemoryStore(cfg.Window(), g.MaxCounterKeys, g.logger)
	var store riskengine.Store = mem
	valkeyStore := g.BehaviorStore == "valkey" && eng != nil && eng.valkey != nil
	if valkeyStore {
		store = riskengine.NewValkeyStore(eng.valkey, cfg.Window(), mem, g.logger)
	}
	g.risk = riskengine.NewEngine(cfg, store, g.logger)
	// 信号汇聚挂点：identitybehavior 侦察信号（含 HEADLESS-001）→ 风险累加器
	if g.ibh != nil {
		g.ibh.SetSignalSink(g.risk.AddIdentitySignals)
	}
	g.logger.Info("identity risk policy enabled",
		zap.String("mode", cfg.Mode),
		zap.Int("version", cfg.Version),
		zap.Int("block_threshold", cfg.BlockThreshold),
		zap.Int("rate_limit_threshold", cfg.RateLimitThreshold),
		zap.Int("rate_limit_rps", cfg.RateLimitRPS),
		zap.Int("signal_window_seconds", cfg.SignalWindowSeconds),
		zap.Int("score_overrides", len(cfg.Scores)),
		zap.Bool("valkey_store", valkeyStore))
}

// enforceRiskPolicy 身份风险策略执行点（serveGuard 前置链路：自动临时封禁之后、授权限速与
// CC 之前——与人工/自动临时封禁同层）。handled=true 表示已响应（403/429）。
// OBSERVE 模式永不实断（仅记录"假设会处置"事件）；评估/存储故障 fail-open 放行。
func (g *Guard) enforceRiskPolicy(w http.ResponseWriter, r *http.Request, res clientip.Result, base events.Event) (bool, error) {
	eng := g.risk
	cfg := eng.Config()
	// 身份行为白名单优先：命中完全跳过风险处置（信号在入口侧同样不累积）
	if g.ibh != nil && g.ibh.Whitelisted(res.ClientIP, r.Header.Get("User-Agent")) {
		return false, nil
	}
	dec, err := eng.Evaluate(riskengine.IdentityKeyFor(r, g.IdentitySalt, res.ClientIP.String()))
	if err != nil {
		g.logger.Warn("risk_policy: 评估失败（fail-open 放行）", zap.Error(err), zap.String("path", r.URL.Path))
		return false, nil
	}
	switch dec.Action {
	case riskengine.ActionBlock:
		if cfg.Mode != riskengine.ModeProtect {
			DispositionFrom(r.Context()).RecordStep(ExecutorRiskPolicy, StepObserved,
				fmt.Sprintf("would_block score=%d threshold=%d", dec.Score, dec.Threshold))
			g.emitRiskEvent(r, res, base, dec, events.RiskPolicyBlock, "would_block", 0)
			return false, nil
		}
		g.setRiskResponseHeaders(w, base.RequestID, cfg.Version)
		dispo := DispositionFrom(r.Context())
		dispo.RecordTerminal(ExecutorRiskPolicy, DisActionBlock, http.StatusForbidden, false,
			[]string{"IDENTITY_RISK_POLICY"}, nil)
		g.emitRiskEvent(r, res, base, dec, events.RiskPolicyBlock, "blocked", http.StatusForbidden)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return true, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("blocked by identity risk policy"))
	case riskengine.ActionRateLimit:
		if cfg.Mode != riskengine.ModeProtect {
			DispositionFrom(r.Context()).RecordStep(ExecutorRiskPolicy, StepObserved,
				fmt.Sprintf("would_rate_limit score=%d threshold=%d", dec.Score, dec.Threshold))
			g.emitRiskEvent(r, res, base, dec, events.RiskPolicyRateLimit, "would_rate_limit", 0)
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
			g.emitRiskEvent(r, res, base, dec, events.RiskPolicyRateLimit, "rate_limited", http.StatusTooManyRequests)
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
		g.emitRiskEvent(r, res, base, dec, events.RiskPolicyRateLimit, "rate_limited", http.StatusTooManyRequests)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return true, nil
	}
	return false, nil
}

// emitRiskEvent 输出身份风险策略处置事件（含 OBSERVE 模式"假设会处置"记录）：
// 60s / identity+action 节流防洪；signals 完整列表随事件（可解释"为什么得 N 分"）；
// reason 固定 identity_risk_policy（设计 #15.2 红线：不伪装成规则阻断）。
func (g *Guard) emitRiskEvent(r *http.Request, res clientip.Result, base events.Event, dec riskengine.Decision, t events.Type, taken string, status int) {
	if !g.risk.ShouldEmit(dec.IdentityKey, taken) {
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
		Mode:          g.risk.Config().Mode,
		PolicyVersion: g.risk.Config().Version,
		Reason:        "identity_risk_policy",
		ActionTaken:   taken,
		Signals:       sigs,
	}
	// P0-04：仅 PROTECT 实断事件挂 final_decision（would_* 观察事件不挂——
	// 请求未终止，提前 Finalize 会锁死后续记录）
	if taken == "blocked" || taken == "rate_limited" {
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
	if g.risk == nil || len(matches) == 0 {
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
	g.risk.AddDetectorMatches(riskengine.IdentityKeyFor(r, g.IdentitySalt, ip.String()), matches)
}
