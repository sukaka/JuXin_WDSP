// Bot 挑战步骤请求链接入（WDSP P1-02 B3，任务书 docs/tasks/wdsp-p1/P1-02_BOT_CHALLENGE.md
// §3.2/§5/§6）：Bot 业务判定位于 CC 之后、统一放行出口 serveNext 之前。
//
// 链路纪律（任务书 §3.2 新增约定）：
//   - 保护地址 / IP 白名单 / L7 allow 三个直达分支与常规路径统一经 serveNextViaBot
//     进入 Bot 步骤——白名单/L7 allow 不隐式跳过 Bot；人工封禁、IP 黑名单、L7 拒绝、
//     自动封禁、风险引擎、配额与 CC 的既有拒绝优先（Bot 步骤在这些步骤之后执行，
//     结构上不可能先于它们放行）。
//   - 有效 clearance 只通过 Bot 步骤，不绕过任何既有拒绝，也不绕过其后的
//     API 动态防护、请求大小/协议检查与 Coraza WAF（BOT-014 集成测试实证）。
//   - 风险 CHALLENGE 经请求上下文在本步骤消费：不再要求 Bot 多信号达阈，但仍须通过
//     selector、clearance、eligibility 与机器身份豁免；只有真实 403 才发风险 challenged。
//   - 精确发布探针 /_wdsp/internal/v1/publish-smoke 在 Bot 策略读取之前由 guard
//     独立验签并本地应答，先于 Bot 保留命名空间；它不属于 Bot 命名空间，OFF、
//     bp==nil 与 RELEASED 均不影响探针，且任何结局都不进入下游。
//   - Bot 保留命名空间 /_wdsp/bot/v1/ 在发布探针之后、Bot 业务判定之前本地处理
//     （verify 固定协议端点；未知子路径本地 404、错误方法 405，均不反向代理——BOT-016）；
//     从已启用状态关闭后保留本地 404/405 墓碑（route_reservation=RESERVED_TOMBSTONE），
//     防止旧挑战提交落入业务源站；首次 OFF 且保留已解除（RELEASED）不抢占业务路径。
//   - OFF 不初始化挑战依赖（assembleBotService 不构造 Service）；OBSERVE 只记录
//     不实断；PROTECT 挑战/验通行依赖故障 fail-closed 503（任务书 §5.4，
//     仅适用于 Bot 步骤，不改变风险引擎既有 fail-open 契约）。
package jiuzhang_guard

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/aicrawl"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/botchallenge"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientside"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
)

// serveNextViaBot 是 CC 之后、serveNext 之前的统一收口：先处理独立发布探针与
// AI Labyrinth 保留命名空间，再执行 AI 爬虫治理（Web Bot Auth / 策略处置 / Content-Signal）
// 与 Bot 挑战步骤。保护地址/白名单/L7 allow 三个直达分支与常规链路全部经此进入——
// 白名单/L7 allow 不隐式跳过 AI 爬虫治理与 Bot（BOT-015 / Phase 9A-2）。
func (g *Guard) serveNextViaBot(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, base events.Event, res clientip.Result) error {
	// 发布冒烟是独立 WDSP 内部精确端点：必须在 bp==nil 与 RELEASED 分支之前处理，
	// 且无论认证成败都不得进入 AI 爬虫治理、Bot、API/WAF 或 reverse_proxy 下游。
	canonPath := normalizer.CanonicalPath(r.URL.Path)
	if canonPath == publishSmokePath {
		return g.servePublishSmoke(w, r)
	}
	// AI Labyrinth 保留命名空间 /_wdsp/labyrinth/v1/：一律本地处理（绝不反向代理），
	// 并强制上报 AI_CRAWL_TRAP_HIT 事件。
	if strings.HasPrefix(canonPath, aicrawl.LabyrinthReservedNamespace) {
		return g.serveAICrawlLabyrinth(w, r, canonPath, base)
	}
	// 客户端供应链安全保留命名空间 /_wdsp/csp/v1/ 与 /_wdsp/cs/v1/：
	// 一律本地处理（绝不反向代理），无论策略开关或白名单状态。
	if strings.HasPrefix(canonPath, clientside.CSPReservedNamespace) {
		return g.serveClientSideReportNamespace(w, r, canonPath, base, res)
	}
	if strings.HasPrefix(canonPath, clientside.CSReservedNamespace) {
		return g.serveClientSideProbeNamespace(w, r, canonPath)
	}

	bp := g.botPolicy
	dispo := DispositionFrom(r.Context())

	// 1. Bot 保留命名空间最前置本地处理（verify 固定协议端点 / 墓碑；全部结局本地响应，
	// 结构上不可能反向代理——任务书 §3.2 末段）。在 AI 爬虫判定之前处理，确保挑战验证提交
	// 不被 AI 爬虫策略误拦截。
	if bp != nil && strings.HasPrefix(canonPath, botReservedNamespace) {
		if g.botSvc != nil || botNamespaceActive(bp) {
			cc := g.buildBotCallContext(bp, base, res, dispo)
			return g.serveBotNamespace(w, r, bp, cc)
		}
	}

	// 1.5 Content-Signal 响应头（配置且模式非 OFF 时对业务与网关响应统一附带）。
	if g.aiCrawl != nil {
		if cs := g.aiCrawl.ContentSignal(); cs != "" {
			w = aicrawl.NewContentSignalWriter(w, cs)
		}
	}

	// 1.6 Web Bot Auth（RFC 9421）与 AI 爬虫治理评估（白名单/L7 allow 不可绕过）。
	var aiRes aiCrawlStepOutcome
	if g.aiCrawl != nil {
		var handled bool
		var err error
		aiRes, handled, err = g.evaluateAndEnforceAICrawl(w, r, canonPath, base, res, dispo)
		if handled {
			return err
		}
	}

	// 1.7 未验证可疑爬虫的 HTML GET 响应可选注入不可见陷阱链接（labyrinth_inject_links）。
	var trapInjector *aicrawl.TrapLinkInjectorWriter
	if aiRes.injectTrapLink && g.aiCrawl != nil {
		trapInjector = g.aiCrawl.Labyrinth().NewTrapLinkInjectorWriter(w, r.Host, canonPath)
		w = trapInjector
	}

	// 1.8 客户端供应链安全 HTML 响应包装器（策略开启时启用：CSP 头注入 + 有界 HTML 脚本扫描/
	// 篡改检测/可选未授权脚本剥离 + 敏感路径防窃取探针注入；缺省/OFF 零开销直通）。
	var csWrapper *clientside.HTMLResponseWrapper
	if g.clientSide != nil {
		csWrapper = g.wrapClientSideResponse(w, r, canonPath, base)
		w = csWrapper
	}

	err := g.serveBotStep(w, r, next, canonPath, base, res, bp, dispo, aiRes)
	skipRewrite := err != nil || (dispo != nil && dispo.Terminated())
	if csWrapper != nil {
		csWrapper.Finish(skipRewrite)
	}
	if trapInjector != nil {
		trapInjector.Finish(skipRewrite)
	}
	return err
}

func (g *Guard) buildBotCallContext(bp *botPolicyJSON, base events.Event, res clientip.Result, dispo *Disposition) botchallenge.CallContext {
	cc := botchallenge.CallContext{
		RequestID:    base.RequestID,
		ClientIP:     res.ClientIP.String(),
		ConnectionIP: res.ConnectionIP.String(),
		// 阶段5 §6.5 三字段（与 eventBase 同口径）
		ClientIPSource:        string(res.Source),
		TrustedProxyUsed:      res.TrustedProxyUsed,
		ForwardedChainSummary: res.ChainSummary,
	}
	cc.RecordTerminal = func(action string, status int, committed bool, reasons []string) {
		dispo.RecordTerminal(ExecutorBot, action, status, committed, reasons,
			[]string{"bot-policy:v" + strconv.Itoa(bp.Version)})
	}
	// final_decision 挂载门禁与既有契约一致：仅终止分支（Settled）挂载——
	// 放行/观察事件提前 Finalize 会落 UNKNOWN 且锁死后续记录。
	cc.FinalDecision = func() json.RawMessage {
		if !dispo.Settled() {
			return nil
		}
		return dispo.JSON()
	}
	return cc
}

func (g *Guard) serveBotStep(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, canonPath string, base events.Event, res clientip.Result, bp *botPolicyJSON, dispo *Disposition, aiRes aiCrawlStepOutcome) error {
	// Web Bot Auth 验签通过且命中规则显式开启 exempt_bot_challenge=true：
	// 仅跳过 Bot JS 挑战，仍完整经过后续 JWT / MachineID / API 动态防护 / Coraza WAF。
	if aiRes.exemptBotChallenge {
		dispo.RecordStep(ExecutorBot, StepObserved, "AI-CRAWL-BOT-EXEMPT agent="+aiRes.agentSlug)
		return g.serveNext(w, r, next)
	}

	// AI 爬虫策略在 PROTECT 模式命中 CHALLENGE 动作：优先复用 Bot PROTECT JS 挑战，
	// 若已持有效通行 Cookie 则放行至 serveNext；Bot 未启用/不可挑战时 fail-closed 403。
	if aiRes.forceBotChallenge {
		if bp != nil && g.botSvc != nil && bp.Mode == botModeProtect {
			cc := g.buildBotCallContext(bp, base, res, dispo)
			if cl, cerr := g.botSvc.ValidateClearance(r, cc); cerr == nil {
				dispo.RecordStep(ExecutorBot, StepExecuted, "clearance accepted flow="+cl.FlowID)
				return g.serveNext(w, r, next)
			}
			if eligOK, _ := botRiskChallengeEligibility(r); eligOK {
				g.offerBotChallenge(w, r, g.botSvc, cc, base, res, "AI_CRAWL_POLICY")
				g.emitAICrawlEvent(base, events.AICrawlAction, "CHALLENGE", http.StatusForbidden, aiRes.eval, dispo.JSON())
				return nil
			}
		}
		aicrawl.WriteBlock(w, r, g.aiCrawl.ContentSignal(), base.RequestID, "Automated AI crawler challenge required.")
		dispo.RecordTerminal(ExecutorBot, DisActionBlock, http.StatusForbidden, true,
			[]string{"AI_CRAWL_CHALLENGE_REQUIRED"}, aiCrawlRuleRefs(aiRes.eval))
		g.emitAICrawlEvent(base, events.AICrawlAction, "CHALLENGE", http.StatusForbidden, aiRes.eval, dispo.JSON())
		accessLogAnnotate(r.Context(), wafActionBlock)
		return nil
	}

	if bp == nil {
		return g.serveNext(w, r, next)
	}
	svc := g.botSvc
	if svc == nil {
		// OFF（无服务）或 OBSERVE 依赖缺失降级：请求链零变化（观测降级已在装配期 Warn）
		return g.serveNext(w, r, next)
	}
	cc := g.buildBotCallContext(bp, base, res, dispo)

	// 2. 选择器（显式配置路径；不匹配零行为）
	if !botSelectorMatch(bp.Selectors, canonPath) {
		return g.serveNext(w, r, next)
	}

	// 3. 有效通行先行：只通过 Bot 步骤，继续完整后续防护链（不绕过既有拒绝——
	// 既有拒绝步骤在本步骤之前已执行；不绕过 API/WAF——本步骤之后经 serveNext 继续）
	cl, cerr := svc.ValidateClearance(r, cc)
	if cerr == nil {
		dispo.RecordStep(ExecutorBot, StepExecuted, "clearance accepted flow="+cl.FlowID)
		return g.serveNext(w, r, next)
	}
	reChallenge := ""
	switch {
	case errors.Is(cerr, botchallenge.ErrClearanceMissing):
		// 无通行 Cookie：正常业务流，继续评估
	case errors.Is(cerr, botchallenge.ErrClearanceExpired):
		reChallenge = "CLEARANCE_EXPIRED"
	case errors.Is(cerr, botchallenge.ErrClearanceRevoked):
		reChallenge = "CLEARANCE_EPOCH_REVOKED"
	default: // ErrClearanceInvalid：伪造/跨应用/Host/会话/未知 key_id
		reChallenge = "CLEARANCE_INVALID"
	}

	// 4. 挑战合格性（任务书 §3.1：仅显式配置路径上的 HTTPS GET 浏览器文档导航；
	// HEAD/POST/JSON/上传/WebSocket/gRPC/流式不返回 HTML 挑战，默认仅观测记录 INELIGIBLE）。
	// M-G2：当风险引擎已判定 CHALLENGE 且 Bot 处于 PROTECT 模式时，仅以协议硬条件
	// （HTTPS + GET + 非 Upgrade）过滤，避免攻击者通过伪造 X-Requested-With / Accept: */*
	// 或 Sec-Fetch-* 头静默绕过风险挑战；常规非风险 Bot 判定维持原 botEligibility（BOT-001..024）。
	pendingRisk := pendingRiskChallengeFor(r)
	var eligOK bool
	var eligReason string
	if pendingRisk != nil && bp.Mode == botModeProtect {
		eligOK, eligReason = botRiskChallengeEligibility(r)
	} else {
		eligOK, eligReason = botEligibility(r)
	}
	if !eligOK {
		svc.LogObservedOffer(r, cc, eligReason)
		dispo.RecordStep(ExecutorBot, StepObserved, eligReason)
		return g.serveNext(w, r, next)
	}

	// 4.5 机器身份 Bot 豁免（NG-ID G1 §1.7/D7：三重显式——身份行
	// bot_challenge_exempt=true ∩ 当前请求命中该身份的绑定 selector ∩ 验证链
	// 全步通过（VERIFIED）；豁免事实进事件（MID_BOT_EXEMPT，含身份指纹与绑定
	// 标识）；未豁免的 VERIFIED 机器照走挑战（默认不免——机器身份不产生全局放行）
	if g.machineIDBotExempt(r) {
		if outcome := machineIDOutcomeFrom(r.Context()); outcome != nil && outcome.Result != nil {
			g.emitMachineIDEvent(r, events.MIDBotExempt, "OBSERVE", 0, outcome)
			dispo.RecordStep(ExecutorBot, StepObserved, "MID-BOT-EXEMPT binding="+outcome.Result.BindingID)
		}
		return g.serveNext(w, r, next)
	}

	// 5. 风险达阈挑战直接复用本步骤，不再要求 Bot 多信号二次达阈；
	// 无风险待挑战事实时保持原有多信号判定（≥2 独立信号组且 ≥1 行为组）。
	dec := botDecision{}
	if pendingRisk != nil {
		dec = botDecision{challenge: true, reason: "IDENTITY_RISK_POLICY"}
	} else {
		dec = g.evaluateBotSignals(r, bp)
	}
	if reChallenge != "" {
		// 持有过期/撤销/非法通行的合格请求：PROTECT 重新挑战（与信号判定独立——
		// 通行曾签发说明已被判定需挑战；伪造通行在 PROTECT 下不得静默放行转业务）
		if bp.Mode == botModeProtect {
			g.offerBotChallenge(w, r, svc, cc, base, res, reChallenge)
			return nil
		}
		dispo.RecordStep(ExecutorBot, StepObserved, reChallenge)
		return g.serveNext(w, r, next)
	}
	if !dec.challenge {
		return g.serveNext(w, r, next)
	}
	if bp.Mode == botModeObserve {
		// OBSERVE 只记录"假设会挑战"，不实断（任务书 §4.2/BOT-001）
		svc.LogObservedOffer(r, cc, dec.reason)
		dispo.RecordStep(ExecutorBot, StepObserved, "would challenge: "+dec.reason)
		return g.serveNext(w, r, next)
	}
	// PROTECT：挑战（B2 语义——403 挑战页 / 429 / 503 fail-closed；
	// 终止事实由 Offer 内经 cc.RecordTerminal 按真实结局记录）
	g.offerBotChallenge(w, r, svc, cc, base, res, dec.reason)
	return nil
}

// offerBotChallenge 保留 Offer 的真实结局；仅实际写出 403 挑战页时补发风险
// challenged 事件。429/503 已由 Bot 按限速/依赖故障记录，不冒充挑战成功。
func (g *Guard) offerBotChallenge(w http.ResponseWriter, r *http.Request, svc *botchallenge.Service, cc botchallenge.CallContext, base events.Event, res clientip.Result, reason string) {
	cw := &botStatusCapture{ResponseWriter: w}
	svc.Offer(cw, r, cc, reason)
	if cw.status != http.StatusForbidden {
		return
	}
	pending := pendingRiskChallengeFor(r)
	if pending == nil {
		return
	}
	g.emitRiskEvent(pending.engine, r, res, base, pending.decision, events.RiskPolicyChallenge, "challenged", http.StatusForbidden)
}

// botNamespaceActive 保留命名空间是否激活（ENABLED 注册或 TOMBSTONE 墓碑保留；
// RELEASED = 已解除不抢占业务路径）。
func botNamespaceActive(bp *botPolicyJSON) bool {
	st := bp.RouteReservation.State
	return st == botReservationEnabled || st == botReservationTombstone
}

// botStatusCapture 命名空间本地处理的写出状态采集（verify 结局众多，
// 由包装 writer 采集真实状态码记入终止事实；仅记状态，其余全部透传）。
type botStatusCapture struct {
	http.ResponseWriter
	status int
}

func (w *botStatusCapture) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *botStatusCapture) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

// Unwrap 供 http.ResponseController 取底层 writer（verify 读取超时 SetReadDeadline 依赖）。
func (w *botStatusCapture) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Flush/Hijack 透传（与本模块 statusWriter 同一透传纪律）。
func (w *botStatusCapture) Flush() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// serveBotNamespace 保留命名空间本地处理（verify 端点 / 墓碑 / 降级；
// 全部结局只写本地响应，永不调用 next）。
func (g *Guard) serveBotNamespace(w http.ResponseWriter, r *http.Request, bp *botPolicyJSON, cc botchallenge.CallContext) error {
	dispo := DispositionFrom(r.Context())
	cw := &botStatusCapture{ResponseWriter: w}
	switch {
	case g.botSvc != nil:
		// verify 固定协议端点（POST-only 405、未知子路径本地 404 由 ServeNamespace 保证）
		g.botSvc.ServeNamespace(cw, r, cc)
		dispo.RecordTerminal(ExecutorBot, DisActionNone, cw.status, true,
			[]string{"BOT_LOCAL_ENDPOINT"}, []string{"bot-policy:v" + strconv.Itoa(bp.Version)})
		return nil
	case !botNamespaceActive(bp):
		// 不可达：调用方已按 svc/botNamespaceActive 门控（RELEASED 无服务不进入本函数）。
		// 防御性兜底显式报错，不放行也不静默。
		return fmt.Errorf("bot namespace not reserved")
	default:
		// 墓碑 / 依赖降级本地处理：verify 错误方法 405（Allow: POST）；
		// OFF 墓碑 verify POST 本地 404（旧挑战提交绝不落入业务源站）；
		// OBSERVE 依赖缺失 verify POST 503 + Retry-After（状态不可签验，如实）；
		// 未知子路径一律本地 404。
		canonPath := normalizer.CanonicalPath(r.URL.Path)
		status := http.StatusNotFound
		reason := "BOT_ROUTE_TOMBSTONE"
		if canonPath == botReservedVerifyPath && r.Method != http.MethodPost {
			status = http.StatusMethodNotAllowed
			w.Header().Set("Allow", http.MethodPost)
		} else if canonPath == botReservedVerifyPath && bp.Mode != botModeOff {
			status = http.StatusServiceUnavailable
			reason = "BOT_STATE_UNAVAILABLE"
			w.Header().Set("Retry-After", "15")
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		w.Header().Set("Cache-Control", "no-store")
		DefaultCovCounters.Inc(StageBotIntercept)
		dispo.RecordTerminal(ExecutorBot, DisActionNone, status, true,
			[]string{reason}, []string{"bot-policy:v" + strconv.Itoa(bp.Version)})
		w.WriteHeader(status)
		if status == http.StatusServiceUnavailable {
			_, _ = w.Write([]byte(`{"error":"STATE_UNAVAILABLE","message":"验证服务暂时不可用，请稍后重试"}`))
		} else if status == http.StatusMethodNotAllowed {
			_, _ = w.Write([]byte("405 method not allowed"))
		} else {
			_, _ = w.Write([]byte("404 not found"))
		}
		return nil
	}
}

// botSelectorMatch 选择器匹配（规范化路径精确 / 规范化前缀——前缀按完整路径段匹配，
// 防相邻目录前缀及 '//'/'.'/'..' 绕过；路径形态非法性在配置校验期已拒绝）。
func botSelectorMatch(sels []botSelectorJSON, path string) bool {
	canonPath := normalizer.CanonicalPath(path)
	for _, s := range sels {
		if s.PathExact != "" && canonPath == normalizer.CanonicalPath(s.PathExact) {
			return true
		}
		if p := s.PathPrefix; p != "" && normalizer.PrefixSegmentMatch(p, canonPath) {
			return true
		}
	}
	return false
}

// botRiskChallengeEligibility 风险引擎 CHALLENGE 在 PROTECT 下的合格性检查（M-G2）：
// 仅保留协议层不可挑战条件（非 GET / 非 HTTPS / Upgrade），不被客户端可随意伪造的
// X-Requested-With / Accept: */* / Sec-Fetch-* 请求头绕过。
func botRiskChallengeEligibility(r *http.Request) (bool, string) {
	if r.Method != http.MethodGet {
		return false, "INELIGIBLE_METHOD"
	}
	if r.TLS == nil {
		return false, "INELIGIBLE_SCHEME"
	}
	if r.Header.Get("Upgrade") != "" {
		return false, "INELIGIBLE_UPGRADE"
	}
	return true, ""
}

// botEligibility 挑战合格性（任务书 §3.1：仅 HTTPS、GET、浏览器文档导航）。
// 不合格仅观测（调用方记录 INELIGIBLE），绝不返回 HTML 挑战。
func botEligibility(r *http.Request) (bool, string) {
	if r.Method != http.MethodGet {
		return false, "INELIGIBLE_METHOD"
	}
	if r.TLS == nil {
		// 挑战仅覆盖 HTTPS（__Host- Cookie Secure 契约；网关 TLS 终止后 r.TLS 非空）
		return false, "INELIGIBLE_SCHEME"
	}
	if upgrade := r.Header.Get("Upgrade"); upgrade != "" {
		// WebSocket 等升级请求不返回 HTML 挑战
		return false, "INELIGIBLE_UPGRADE"
	}
	if r.Header.Get("X-Requested-With") != "" {
		// XHR/fetch 业务请求不是文档导航
		return false, "INELIGIBLE_NAVIGATION"
	}
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" && dest != "document" {
		return false, "INELIGIBLE_NAVIGATION"
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" && mode != "navigate" {
		return false, "INELIGIBLE_NAVIGATION"
	}
	accept := r.Header.Get("Accept")
	if !strings.Contains(accept, "text/html") {
		// JSON API / 资源请求等非文档导航（浏览器地址栏/链接导航恒携带 text/html）
		return false, "INELIGIBLE_ACCEPT"
	}
	return true, ""
}

// ---------- 多信号判定（任务书 §4.2 + B0 冻结口径） ----------

// botDecision Bot 步骤判定结果。
type botDecision struct {
	challenge bool   // 是否提出挑战（≥min_independent_groups 且含行为组）
	reason    string // 结构化理由码（事件 bot.reason）
}

// botWindowFor 规则窗口秒数映射到行为观测固定窗口（1m/5m/30m/24h 取不小于
// 规则窗口的最近档；B0 冻结窗口范围 30..3600 秒——超出 30m 档的映射到 24h）。
func botWindowFor(seconds int) identitybehavior.Window {
	switch {
	case seconds <= 90:
		return identitybehavior.Window1m
	case seconds <= 450:
		return identitybehavior.Window5m
	case seconds <= 1800:
		return identitybehavior.Window30m
	default:
		return identitybehavior.Window24h
	}
}

// evaluateBotSignals 多信号判定（§4.2）：
//   - 组满足 = 组内已触发且可用的规则权重和 ≥1；提出挑战需满足组数 ≥
//     min_independent_groups 且至少 1 个行为组（request_behavior/access_sequence）；
//   - 客户端声明组（UA/TLS 轻量特征）为可伪造弱信号，不能单独构成挑战依据；
//   - 观测缺失/读取失败按 UNKNOWN/UNAVAILABLE 处理：该规则不计触发，
//     不得把"未采集到"当作零风险或高风险（identity_behavior 未启用时行为组
//     恒不可用——PROTECT 策略须有身份行为观测配套，见 preflight/文档说明）。
func (g *Guard) evaluateBotSignals(r *http.Request, bp *botPolicyJSON) botDecision {
	sr := bp.SignalRules
	// 行为组数据按需读取一次（同请求多规则共用快照）
	var snap *identitybehavior.Snapshot
	snapFetched := false
	fetchSnap := func() *identitybehavior.Snapshot {
		if snapFetched {
			return snap
		}
		snapFetched = true
		if g.ibh == nil {
			return nil
		}
		id := identitybehavior.IdentityFrom(r.Context())
		if id == nil {
			return nil
		}
		s, err := g.ibh.PeekSnapshot(id.Key, r.URL.Path)
		if err != nil {
			g.logger.Warn("bot signal behavior snapshot unavailable（按 UNKNOWN 处理）")
			return nil
		}
		snap = s
		return snap
	}

	groupWeight := map[string]float64{}
	for _, rule := range sr.Rules {
		triggered, available := g.evalBotRule(r, rule, fetchSnap)
		if available && triggered {
			groupWeight[rule.Group] += rule.Weight
		}
	}
	satisfied := 0
	behaviorOK := false
	for grp, w := range groupWeight {
		if w < 1 {
			continue
		}
		satisfied++
		if grp == "request_behavior" || grp == "access_sequence" {
			behaviorOK = true
		}
	}
	if satisfied >= sr.MinIndependentGroups && behaviorOK {
		return botDecision{challenge: true, reason: "SIGNAL_THRESHOLD_MET"}
	}
	return botDecision{challenge: false, reason: "SIGNAL_THRESHOLD_NOT_MET"}
}

// evalBotRule 单规则评估。available=false 表示观测缺失/指标无既有计数源
// （UNKNOWN/UNAVAILABLE，不计触发、不计权重）。
func (g *Guard) evalBotRule(r *http.Request, rule botSignalRuleJSON, fetchSnap func() *identitybehavior.Snapshot) (triggered, available bool) {
	switch rule.Metric {
	case "ua_class_match":
		// 客户端声明（可伪造弱信号）：UA 分类启发
		return identitybehavior.ClassifyUA(r.Header.Get("User-Agent")) == rule.Params["class"], true
	case "tls_client_hint":
		// TLS 版本/密码套件轻量特征（可伪造声明，非 JA3/JA4 指纹）
		if r.TLS == nil {
			return false, false
		}
		switch rule.Params["field"] {
		case "version":
			return botTLSVersionString(r.TLS.Version) == rule.Params["equals"], true
		case "cipher_suite":
			return tls.CipherSuiteName(r.TLS.CipherSuite) == rule.Params["equals"], true
		}
		return false, false
	}

	// 行为组指标：依赖身份行为观测窗口计数
	snap := fetchSnap()
	if snap == nil {
		return false, false
	}
	wc := snap.Windows[botWindowFor(rule.WindowSeconds)]
	req := wc.RequestCount
	switch rule.Metric {
	case "status_family_ratio":
		// 既有计数仅含 401/403/404/405/500：4xx/5xx 为可计算近似（如实注明）；
		// 2xx/3xx 无对应计数源——按 UNAVAILABLE 处理，不以 0 冒充。
		if req <= 0 {
			return false, false
		}
		var n float64
		switch rule.Params["family"] {
		case "4xx":
			n = wc.Status401Count + wc.Status403Count + wc.Status404Count + wc.Status405Count
		case "5xx":
			n = wc.Status500Count
		default:
			return false, false
		}
		return n/req >= rule.Threshold, true
	case "method_ratio":
		// 既有窗口计数不含每方法计数（仅 (identity,uri) distinct method 集合）——
		// 该指标当前无计数源，按 UNAVAILABLE 处理（已知限制，见 WORKLOG/文档）。
		return false, false
	case "uri_concentration":
		if req <= 0 {
			return false, false
		}
		return 1-float64(wc.UniqueURICount)/req >= rule.Threshold, true
	case "known_uri_ratio":
		if req <= 0 {
			return false, false
		}
		known := 1 - wc.NewURICount/req
		if known < 0 {
			known = 0
		}
		return known <= rule.Threshold, true
	case "method_enumeration_size":
		return float64(snap.DistinctMethods) >= rule.Threshold, true
	}
	return false, false
}

// botTLSVersionString TLS 版本号字符串化（crypto/tls 无内置版本名函数）；
// 策略值示例 "TLS 1.3"/"TLS 1.2"（配置校验期已限定取值域）。
func botTLSVersionString(v uint16) string {
	switch v {
	case 0x0101:
		return "TLCP 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return ""
}
