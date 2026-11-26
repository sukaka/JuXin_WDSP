// aicrawl_step.go Phase 9A-2 AI 爬虫治理、Web Bot Auth 与离线 AI Labyrinth 在 jiuzhang_guard 的挂点。
//
// 链路与安全纪律：
//   - 配置段 ai_crawl_policy 严格解码（DisallowUnknownFields）+ 全量校验，fail-closed 拒载；
//   - 热路径零网络 IO：公钥查找走 DirectoryStore 不可变原子快照，远程刷新仅后台异步执行并受 SSRF 约束；
//   - 保留命名空间 /_wdsp/labyrinth/v1/ 在 serveNextViaBot 内最前置（仅次于发布冒烟）本地处理，
//     绝不反向代理，且任何命中一律上报 AI_CRAWL_TRAP_HIT 事件；
//   - 位于 serveNextViaBot 内执行：保护地址、IP/URL 白名单与 L7 allow 均不得绕过 AI 爬虫治理；
//   - 仅密码学验签通过的 Web Bot Auth 且命中 exempt_bot_challenge=true 规则可豁免 Bot JS 挑战，
//     且仅豁免 Bot 挑战，仍完整经过 JWT PROTECT、MachineID、API 动态防护与 Coraza WAF。
package jiuzhang_guard

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/aicrawl"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/ratelimit"
	"go.uber.org/zap"
)

type aiCrawlStepOutcome struct {
	eval               aicrawl.EvalResult
	exemptBotChallenge bool
	forceBotChallenge  bool
	injectTrapLink     bool
	agentSlug          string
}

func (g *Guard) validateAICrawlPolicy() error {
	if len(g.AICrawlPolicy) == 0 {
		return nil
	}
	_, err := aicrawl.ParseAndValidatePolicy(g.AICrawlPolicy)
	return err
}

func (g *Guard) assembleAICrawl() error {
	if len(g.AICrawlPolicy) == 0 {
		g.aiCrawl = nil
		return nil
	}
	pol, err := aicrawl.ParseAndValidatePolicy(g.AICrawlPolicy)
	if err != nil {
		return err
	}
	if pol.Mode == aicrawl.ModeOff {
		g.aiCrawl = nil
		return nil
	}
	var warnFn func(msg string, err error)
	if g.logger != nil {
		warnFn = func(msg string, err error) {
			g.logger.Warn(msg, zap.String("app_id", pol.ApplicationID), zap.Error(err))
		}
	}
	eng, err := aicrawl.NewEngine(pol, aicrawl.EngineOptions{
		Fetcher: g.aiCrawlFetcher,
		OnWarn:  warnFn,
	})
	if err != nil {
		return err
	}
	g.aiCrawl = eng
	if g.logger != nil {
		g.logger.Info("ai crawl policy loaded",
			zap.String("app_id", pol.ApplicationID),
			zap.String("mode", pol.Mode),
			zap.Int("policy_version", pol.Version),
			zap.String("default_ai_action", pol.DefaultAIAction),
			zap.Bool("verify_web_bot_auth", pol.VerifyWebBotAuth),
			zap.Bool("labyrinth_enabled", pol.LabyrinthEnabled),
			zap.Int("rules", len(pol.Rules)),
			zap.Int("directories", len(pol.Directories)))
	}
	return nil
}

// serveAICrawlLabyrinth 本地处理保留命名空间 /_wdsp/labyrinth/v1/（绝不反向代理），
// 任何命中一律产生 AI_CRAWL_TRAP_HIT 事件。
func (g *Guard) serveAICrawlLabyrinth(w http.ResponseWriter, r *http.Request, canonPath string, base events.Event) error {
	dispo := DispositionFrom(r.Context())
	if g.aiCrawl != nil && g.aiCrawl.Policy().LabyrinthEnabled {
		tr := g.aiCrawl.Labyrinth().ServeLabyrinthRequest(w, r, canonPath, g.aiCrawl.ContentSignal())
		action := DisActionBlock
		if tr.Status == http.StatusTooManyRequests {
			action = DisActionRateLimit
		}
		ruleRefs := []string{"ai-crawl-policy:v" + strconv.Itoa(g.aiCrawl.Policy().Version)}
		dispo.RecordTerminal(ExecutorBot, action, tr.Status, true, []string{"AI_CRAWL_TRAP_HIT"}, ruleRefs)
		ev := base
		ev.AICrawl = &events.AICrawlDetail{
			PolicyVersion:  g.aiCrawl.Policy().Version,
			Mode:           g.aiCrawl.Mode(),
			Action:         aicrawl.ActionTarpit,
			LabyrinthDepth: tr.Depth,
			TrapValid:      tr.Valid,
		}
		ev.FinalDecision = dispo.JSON()
		g.emit(ev, events.AICrawlTrapHit, aicrawl.ActionTarpit, tr.Status)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return nil
	}

	// 策略未开启迷宫或 OFF：本地 404 墓碑响应（绝不落入源站）+ 仍上报 AI_CRAWL_TRAP_HIT。
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if g.aiCrawl != nil && g.aiCrawl.ContentSignal() != "" {
		w.Header().Set(aicrawl.ContentSignalHeader, g.aiCrawl.ContentSignal())
	}
	w.WriteHeader(http.StatusNotFound)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte("404 not found"))
	}
	dispo.RecordTerminal(ExecutorBot, DisActionNone, http.StatusNotFound, true, []string{"AI_CRAWL_TRAP_HIT"}, nil)
	if g.events != nil {
		ev := base
		detail := &events.AICrawlDetail{
			Action:    "TRAP_TOMBSTONE",
			TrapValid: false,
		}
		if g.aiCrawl != nil {
			detail.PolicyVersion = g.aiCrawl.Policy().Version
			detail.Mode = g.aiCrawl.Mode()
		}
		ev.AICrawl = detail
		ev.FinalDecision = dispo.JSON()
		g.emit(ev, events.AICrawlTrapHit, "TRAP_TOMBSTONE", http.StatusNotFound)
	}
	accessLogAnnotate(r.Context(), wafActionBlock)
	return nil
}

// evaluateAndEnforceAICrawl 执行 Web Bot Auth 验签与 AI 爬虫规则处置。
func (g *Guard) evaluateAndEnforceAICrawl(w http.ResponseWriter, r *http.Request, canonPath string, base events.Event, res clientip.Result, dispo *Disposition) (aiCrawlStepOutcome, bool, error) {
	eval := g.aiCrawl.Evaluate(r)
	out := aiCrawlStepOutcome{
		eval:               eval,
		exemptBotChallenge: eval.ExemptBotChallenge,
		injectTrapLink:     eval.InjectTrapLink,
		agentSlug:          eval.AgentSlug,
	}

	// Web Bot Auth 验签通过始终留痕 AI_CRAWL_VERIFIED。
	if eval.Verified {
		dispo.RecordStep(ExecutorBot, StepExecuted, "web-bot-auth verified agent="+eval.AgentSlug)
		g.emitAICrawlEvent(base, events.AICrawlVerified, eval.Action, 0, eval, nil)
	}

	if !eval.Matched {
		return out, false, nil
	}

	// OBSERVE 模式：仅记录 AI_CRAWL_OBSERVED，永不实断（但允许已配置的隐形陷阱链接注入）。
	if eval.Mode == aicrawl.ModeObserve {
		dispo.RecordStep(ExecutorBot, StepObserved, "ai-crawl observe action="+eval.Action)
		g.emitAICrawlEvent(base, events.AICrawlObserved, eval.Action, 0, eval, nil)
		accessLogAnnotate(r.Context(), wafActionObserve)
		return out, false, nil
	}

	// PROTECT 模式按命中动作实断。
	ruleRefs := aiCrawlRuleRefs(eval)
	switch eval.Action {
	case aicrawl.ActionAllow:
		if eval.RuleID != "" && !eval.Verified {
			dispo.RecordStep(ExecutorBot, StepExecuted, "ai-crawl allow rule="+eval.RuleID)
			g.emitAICrawlEvent(base, events.AICrawlAction, aicrawl.ActionAllow, 0, eval, nil)
		}
		return out, false, nil

	case aicrawl.ActionBlock:
		aicrawl.WriteBlock(w, r, g.aiCrawl.ContentSignal(), base.RequestID, "")
		dispo.RecordTerminal(ExecutorBot, DisActionBlock, http.StatusForbidden, true,
			[]string{"AI_CRAWL_BLOCK"}, ruleRefs)
		g.emitAICrawlEvent(base, events.AICrawlAction, aicrawl.ActionBlock, http.StatusForbidden, eval, dispo.JSON())
		accessLogAnnotate(r.Context(), wafActionBlock)
		return out, true, nil

	case aicrawl.ActionHTTP402:
		aicrawl.WriteHTTP402(w, r, g.aiCrawl.Policy().HTTP402, g.aiCrawl.ContentSignal(), base.RequestID)
		dispo.RecordTerminal(ExecutorBot, DisActionBlock, http.StatusPaymentRequired, true,
			[]string{"AI_CRAWL_HTTP_402"}, ruleRefs)
		g.emitAICrawlEvent(base, events.AICrawlAction, aicrawl.ActionHTTP402, http.StatusPaymentRequired, eval, dispo.JSON())
		accessLogAnnotate(r.Context(), wafActionBlock)
		return out, true, nil

	case aicrawl.ActionTarpit:
		tr := g.aiCrawl.Labyrinth().ServeEntryTarpit(w, r, canonPath, g.aiCrawl.ContentSignal())
		disAction := DisActionBlock
		if tr.Status == http.StatusTooManyRequests {
			disAction = DisActionRateLimit
		}
		dispo.RecordTerminal(ExecutorBot, disAction, tr.Status, true,
			[]string{"AI_CRAWL_TARPIT"}, ruleRefs)
		g.emitAICrawlEvent(base, events.AICrawlAction, aicrawl.ActionTarpit, tr.Status, eval, dispo.JSON())
		accessLogAnnotate(r.Context(), wafActionBlock)
		return out, true, nil

	case aicrawl.ActionRateLimit:
		if g.engine == nil || g.engine.limiter == nil {
			if g.logger != nil {
				g.logger.Warn("ai crawl rate limit skipped: limiter unavailable")
			}
			return out, false, nil
		}
		rpm := eval.RateLimitRPM
		if rpm <= 0 {
			rpm = aicrawl.DefaultRateLimitRPM
		}
		ruleKey := eval.RuleID
		if ruleKey == "" {
			ruleKey = "default"
		}
		subject := res.ClientIP.String()
		if eval.Verified && eval.AgentSlug != "" {
			subject = "agent:" + eval.AgentSlug
		}
		rlKey := "aicrawl:" + g.AppID + ":" + ruleKey + ":" + subject
		rlRes, err := g.engine.limiter.Allow(r.Context(), rlKey, ratelimit.SlidingWindow, int64(rpm), time.Minute, 0)
		if err != nil {
			if g.logger != nil {
				g.logger.Warn("ai crawl rate limit engine error", zap.Error(err))
			}
			if g.failOpen {
				return out, false, nil
			}
			aicrawl.WriteRateLimit(w, r, 60, g.aiCrawl.ContentSignal(), base.RequestID)
			dispo.RecordTerminal(ExecutorBot, DisActionRateLimit, http.StatusTooManyRequests, true,
				[]string{"AI_CRAWL_RATE_LIMIT_ERROR"}, ruleRefs)
			g.emitAICrawlEvent(base, events.AICrawlAction, aicrawl.ActionRateLimit, http.StatusTooManyRequests, eval, dispo.JSON())
			accessLogAnnotate(r.Context(), wafActionBlock)
			return out, true, nil
		}
		if rlRes.Allowed {
			return out, false, nil
		}
		retrySec := int(rlRes.RetryAfter.Seconds()) + 1
		aicrawl.WriteRateLimit(w, r, retrySec, g.aiCrawl.ContentSignal(), base.RequestID)
		dispo.RecordTerminal(ExecutorBot, DisActionRateLimit, http.StatusTooManyRequests, true,
			[]string{"AI_CRAWL_RATE_LIMIT"}, ruleRefs)
		g.emitAICrawlEvent(base, events.AICrawlAction, aicrawl.ActionRateLimit, http.StatusTooManyRequests, eval, dispo.JSON())
		accessLogAnnotate(r.Context(), wafActionBlock)
		return out, true, nil

	case aicrawl.ActionChallenge:
		out.forceBotChallenge = true
		return out, false, nil
	}

	return out, false, nil
}

func (g *Guard) emitAICrawlEvent(base events.Event, typ events.Type, action string, status int, eval aicrawl.EvalResult, finalDecision json.RawMessage) {
	if g.events == nil {
		return
	}
	ev := base
	ev.AICrawl = &events.AICrawlDetail{
		PolicyVersion:      eval.PolicyVersion,
		Mode:               eval.Mode,
		Category:           eval.Category,
		AgentID:            eval.AgentID,
		AgentSlug:          eval.AgentSlug,
		AgentName:          eval.AgentName,
		SignatureAgent:     eval.SignatureAgent,
		SignatureVerified:  eval.Verified,
		SignatureKeyID:     eval.KeyID,
		SignatureReason:    eval.SigReason,
		RuleID:             eval.RuleID,
		RuleName:           eval.RuleName,
		Action:             action,
		ExemptBotChallenge: eval.ExemptBotChallenge,
	}
	if len(finalDecision) > 0 {
		ev.FinalDecision = finalDecision
	}
	g.emit(ev, typ, action, status)
}

func aiCrawlRuleRefs(eval aicrawl.EvalResult) []string {
	refs := []string{"ai-crawl-policy:v" + strconv.Itoa(eval.PolicyVersion)}
	if eval.RuleID != "" {
		refs = append(refs, eval.RuleID)
	}
	return refs
}
