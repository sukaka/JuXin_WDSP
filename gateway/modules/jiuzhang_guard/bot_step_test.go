// bot_step_test.go Bot 挑战步骤请求链单元测试（WDSP P1-02 B3，任务书 §3.2/§5）：
// 覆盖 OFF 零变化 / OBSERVE 只记录 / PROTECT 挑战→verify→clearance 通行全流程 /
// 墓碑 404/405 / 命名空间不反代 / 白名单·保护地址·L7 allow 仍经 Bot（BOT-015）/
// 人工封禁·黑名单·CC 优先于 Bot / Store 故障 PROTECT fail-closed 503 /
// INELIGIBLE 仅观测放行 / 挑战事件 final_decision security_action=CHALLENGE。
//
// 测试替身纪律：fakeGuardValkey 为 botchallenge 四个 Lua 脚本语义感知的内存
// Valkey 替身（按脚本内容特征分发，与 botchallenge/fakevalkey_test.go 同一语义；
// fail 注入验证 fail-closed 故障语义）；身份行为观测用 MemoryStore 真实实现，
// 种子流量在策略装配前经完整 ServeHTTP 链路记账（与生产同一身份解析路径；
// 装配后种子会触发挑战，故顺序固定为 种子→装配→被测请求）。
package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/botchallenge"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/l7rules"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/ratelimit"
	"go.uber.org/zap"
)

// ---------- fakeGuardValkey：botchallenge 四脚本语义感知的内存 Valkey 替身 ----------

type fakeGuardValkey struct {
	mu     sync.Mutex
	hashes map[string]map[string]string // 挑战 HASH
	zsets  map[string]map[string]float64
	fail   bool
}

func newFakeGuardValkey() *fakeGuardValkey {
	return &fakeGuardValkey{hashes: map[string]map[string]string{}, zsets: map[string]map[string]float64{}}
}

// Eval 按脚本内容特征分发（脚本常量为 botchallenge 包内私有，特征串唯一可辨）。
func (f *fakeGuardValkey) Eval(_ context.Context, script string, keys []string, args []string) ([]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return nil, errors.New("valkey down")
	}
	switch {
	case strings.Contains(script, "ZREMRANGEBYSCORE"):
		return f.evalIssue(keys, args), nil
	case strings.Contains(script, "ZSCORE"):
		return f.evalRead(keys, args), nil
	case strings.Contains(script, "HINCRBY"):
		return f.evalFail(keys, args), nil
	case strings.Contains(script, "HMGET"):
		return f.evalConsume(keys, args), nil
	}
	return nil, errors.New("unexpected script")
}

func (f *fakeGuardValkey) evalIssue(keys, args []string) []interface{} {
	ifKey, cKey := keys[0], keys[1]
	nowMs, _ := strconv.ParseFloat(args[0], 64)
	capN, _ := strconv.Atoi(args[1])
	expMs, _ := strconv.ParseFloat(args[3], 64)
	member := args[4]
	zs := f.zsets[ifKey]
	if zs == nil {
		zs = map[string]float64{}
		f.zsets[ifKey] = zs
	}
	for m, sc := range zs {
		if sc <= nowMs {
			delete(zs, m)
		}
	}
	if len(zs) >= capN {
		return []interface{}{int64(0), "CAP"}
	}
	if _, ok := f.hashes[cKey]; ok {
		return []interface{}{int64(0), "EXISTS"}
	}
	f.hashes[cKey] = map[string]string{
		"v": "1", "sd": args[5], "hh": args[6], "ep": args[7], "df": args[8],
		"nc": args[9], "exp": args[3], "att": "0",
	}
	zs[member] = expMs
	return []interface{}{int64(1), "OK"}
}

func (f *fakeGuardValkey) evalRead(keys, args []string) []interface{} {
	cKey, ifKey := keys[0], keys[1]
	member := args[0]
	nowMs, _ := strconv.ParseFloat(args[1], 64)
	out := []interface{}{}
	var flds []string
	if h, ok := f.hashes[cKey]; ok {
		for _, k := range []string{"v", "sd", "hh", "ep", "df", "nc", "exp", "att"} {
			flds = append(flds, k, h[k])
		}
	}
	out = append(out, int64(len(flds)))
	for _, s := range flds {
		out = append(out, s)
	}
	hint := "0"
	if sc, ok := f.zsets[ifKey][member]; ok {
		if sc <= nowMs {
			hint = "1"
		} else {
			hint = "2"
		}
	}
	out = append(out, hint)
	return out
}

// evalCompare 共用比对段（consume/fail 同口径）；返回 (f, reason)。
func (f *fakeGuardValkey) evalCompare(keys, args []string) (map[string]string, string) {
	h, ok := f.hashes[keys[0]]
	if !ok {
		return nil, "NOT_FOUND"
	}
	if h["sd"] != args[0] || h["hh"] != args[1] || h["ep"] != args[2] || h["df"] != args[3] || h["nc"] != args[4] {
		return nil, "MISMATCH"
	}
	expMs, _ := strconv.ParseFloat(h["exp"], 64)
	nowMs, _ := strconv.ParseFloat(args[7], 64)
	if expMs <= nowMs {
		delete(f.hashes, keys[0])
		return nil, "EXPIRED"
	}
	return h, ""
}

func (f *fakeGuardValkey) evalConsume(keys, args []string) []interface{} {
	h, reason := f.evalCompare(keys, args)
	if reason != "" {
		return []interface{}{int64(0), reason}
	}
	att, _ := strconv.Atoi(h["att"])
	maxAtt, _ := strconv.Atoi(args[8])
	if att >= maxAtt {
		return []interface{}{int64(0), "EXHAUSTED"}
	}
	delete(f.hashes, keys[0])
	delete(f.zsets[keys[1]], args[6])
	return []interface{}{int64(1), "OK"}
}

func (f *fakeGuardValkey) evalFail(keys, args []string) []interface{} {
	h, reason := f.evalCompare(keys, args)
	if reason != "" {
		return []interface{}{int64(0), reason, int64(0)}
	}
	att, _ := strconv.Atoi(h["att"])
	att++
	h["att"] = strconv.Itoa(att)
	maxAtt, _ := strconv.Atoi(args[8])
	if att >= maxAtt {
		delete(f.hashes, keys[0])
		delete(f.zsets[keys[1]], args[6])
		return []interface{}{int64(0), "EXHAUSTED", int64(att)}
	}
	return []interface{}{int64(2), "ATTEMPT", int64(att)}
}

func (f *fakeGuardValkey) HSet(context.Context, string, string, string) error { return nil }
func (f *fakeGuardValkey) HGetAll(context.Context, string) (map[string]string, error) {
	return nil, nil
}
func (f *fakeGuardValkey) HDel(context.Context, string, ...string) error { return nil }
func (f *fakeGuardValkey) Ping(context.Context) error                    { return nil }
func (f *fakeGuardValkey) Close() error                                  { return nil }

// ---------- 夹具 ----------

// botStepSection Bot 步骤测试策略段基线（ua_class_match BOT 声明组 + uri_concentration
// 行为组，min_independent_groups=2 且含行为组——达阈即挑战；难度最小值 10 供快速求解）。
func botStepSection(mode string) *botPolicyJSON {
	return &botPolicyJSON{
		SchemaVersion: botPolicySchemaVersion,
		ApplicationID: "app1",
		Mode:          mode,
		Version:       1,
		Selectors:     []botSelectorJSON{{PathPrefix: "/docs"}},
		SignalRules: botSignalRulesJSON{
			MinIndependentGroups: 2,
			RequireBehaviorGroup: true,
			Rules: []botSignalRuleJSON{
				{ID: "ua_bot", Group: "client_claim", Metric: "ua_class_match",
					Params: map[string]string{"class": "BOT"}, WindowSeconds: 300, Weight: 1},
				{ID: "uc", Group: "request_behavior", Metric: "uri_concentration",
					WindowSeconds: 300, Weight: 1, Threshold: 0.5},
			},
		},
		Challenge: botChallengeJSON{Type: "JS", NonceTTLSeconds: 90, ClearanceTTLSeconds: 900,
			Difficulty: 10, MaxAttempts: 3, KeyRef: botTestKeyID},
		RouteReservation: botRouteReservationJSON{State: botReservationEnabled, Namespace: botReservedNamespace},
		SigningKeys:      map[string]string{botTestKeyID: botTestKeyHex},
	}
}

// newBotStepGuard 构建 Bot 步骤测试 Guard：内存后端 + fake Valkey + 身份行为观测
// （MemoryStore 真实实现）。不装配 bot 策略——种子流量须在装配前发送。
func newBotStepGuard(t *testing.T, cfg Guard) (*Guard, *fakeGuardValkey) {
	t.Helper()
	if cfg.AppID == "" {
		cfg.AppID = "app1"
	}
	if cfg.AppCode == "" {
		cfg.AppCode = "shop"
	}
	g := newTestGuard(t, cfg)
	fk := newFakeGuardValkey()
	g.engine.valkey = fk
	ibCfg, err := identitybehavior.Compile(&identitybehavior.Params{Enabled: true}, zap.NewNop())
	if err != nil {
		t.Fatalf("compile identity behavior: %v", err)
	}
	ibEvents, err := identitybehavior.NewEventLogger(t.TempDir()+"/identity-events.log", "test-node", zap.NewNop())
	if err != nil {
		t.Fatalf("identity event logger: %v", err)
	}
	t.Cleanup(func() { ibEvents.Close() })
	g.ibh = identitybehavior.NewEngine(ibCfg, identitybehavior.NewMemoryStore(10000, zap.NewNop()),
		ibEvents, identitybehavior.Options{AppID: g.AppID, AppCode: g.AppCode, GatewayNode: "test-node", Salt: "test-salt"})
	return g, fk
}

// assembleBotStep 装配 bot 策略（种子流量之后调用）。
func assembleBotStep(t *testing.T, g *Guard, sec *botPolicyJSON) {
	t.Helper()
	g.BotPolicy = mustJSON(t, sec)
	if err := g.assembleBotPolicy(); err != nil {
		t.Fatalf("assemble bot policy: %v", err)
	}
}

// botStepUA 触发 ua_class_match BOT 的 UA。
const botStepUA = "curl/8.1"

// botStepReq 构造 HTTPS 测试请求（r.TLS 由 https scheme 自动携带——挑战合格性依赖）。
func botStepReq(remoteAddr, target string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	r.Header.Set("X-Request-Id", "11111111-2222-3333-4444-555555555555")
	return r
}

// botBrowserHeaders 合格文档导航头（curl UA + 浏览器导航元数据——刻意组合以同时
// 命中 ua_class_match 与合格性；UA 可伪造恰是声明组为弱信号的原因）。
func botBrowserHeaders() map[string]string {
	return map[string]string{
		"User-Agent":      botStepUA,
		"Accept":          "text/html,application/xhtml+xml",
		"Sec-Fetch-Dest":  "document",
		"Sec-Fetch-Mode":  "navigate",
		"Sec-Fetch-Site":  "none",
		"Accept-Language": "zh-CN",
	}
}

// seedBotBehavior 种子行为计数：同 IP+UA 对同 URI 发 n 次请求（策略装配前调用；
// uri_concentration = 1-1/n ≥ 0.5 需 n≥2）。
func seedBotBehavior(t *testing.T, g *Guard, remoteAddr, target string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		called := false
		if err := g.ServeHTTP(httptest.NewRecorder(), botStepReq(remoteAddr, target, botBrowserHeaders()),
			nextHandler{&called}); err != nil || !called {
			t.Fatalf("seed request %d must pass: err=%v called=%v", i, err, called)
		}
	}
}

// botChallengeParams 挑战页内嵌题目参数（render.go wdsp-bot-params JSON 块）。
type botChallengeParams struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	Difficulty  int    `json:"difficulty"`
	App         string `json:"app"`
	Host        string `json:"host"`
	VerifyPath  string `json:"verify_path"`
	BudgetMS    int    `json:"budget_ms"`
}

var botParamsRe = regexp.MustCompile(`id="wdsp-bot-params" type="application/json">([^<]+)</script>`)

// extractChallenge 从 403 挑战页提取题目参数与会话 Cookie。
func extractChallenge(t *testing.T, rec *httptest.ResponseRecorder) (botChallengeParams, string) {
	t.Helper()
	m := botParamsRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("challenge params block missing in page: %.200s", rec.Body.String())
	}
	var p botChallengeParams
	if err := json.Unmarshal([]byte(m[1]), &p); err != nil {
		t.Fatalf("parse challenge params: %v", err)
	}
	sess := ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == botchallenge.SessionCookieName {
			sess = c.Value
		}
	}
	if sess == "" {
		t.Fatal("session cookie missing on challenge page")
	}
	return p, sess
}

// solveChallenge 暴力求解 PoW（difficulty 10 平均 ~1024 次迭代）。
func solveChallenge(t *testing.T, p botChallengeParams) string {
	t.Helper()
	for i := 0; i < 1<<24; i++ {
		s := strconv.Itoa(i)
		ok, err := botchallenge.CheckSolution(p.ChallengeID, p.Nonce, p.App, p.Host, s, p.Difficulty)
		if err != nil {
			t.Fatalf("check solution: %v", err)
		}
		if ok {
			return s
		}
	}
	t.Fatal("no PoW solution found within bound")
	return ""
}

// botVerify 提交 verify（同源 Origin + 会话 Cookie + JSON 正文），返回记录器。
func botVerify(t *testing.T, g *Guard, remoteAddr, host, sess, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://"+host+botReservedVerifyPath, strings.NewReader(body))
	r.RemoteAddr = remoteAddr
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://"+host)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Cookie", botchallenge.SessionCookieName+"="+sess)
	rec := httptest.NewRecorder()
	called := false
	if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil {
		t.Fatalf("verify serve: %v", err)
	}
	if called {
		t.Fatal("verify must never reach upstream (BOT-016)")
	}
	return rec
}

// findBotEvent 按类型取首个 Bot 事件（无匹配返回 nil）。
func findBotEvent(t *testing.T, g *Guard, typ events.Type) *events.Event {
	t.Helper()
	evs := g.readEvents(t)
	for i := range evs {
		if evs[i].EventType == typ {
			return &evs[i]
		}
	}
	return nil
}

// ---------- 用例 ----------

// TestBotStepOffZeroChange OFF + 保留已解除（RELEASED）：请求链零变化，无 Bot 事件，
// 命名空间不抢占业务路径。
func TestBotStepOffZeroChange(t *testing.T) {
	sec := botStepSection(botModeOff)
	sec.RouteReservation.State = botReservationReleased
	sec.SigningKeys = nil
	g, _ := newBotStepGuard(t, Guard{})
	assembleBotStep(t, g, sec)
	if g.botPolicy == nil {
		t.Fatal("OFF must retain section (tombstone needs route_reservation)")
	}
	if g.botSvc != nil {
		t.Fatal("OFF must not construct challenge service")
	}
	called := false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, botStepReq("203.0.113.10:1", "https://waf-test.local/docs/x", botBrowserHeaders()),
		nextHandler{&called}); err != nil || !called {
		t.Fatalf("OFF must pass through: err=%v called=%v", err, called)
	}
	// 保留已解除：verify 路径落入业务（不抢占）
	called = false
	r := httptest.NewRequest(http.MethodPost, "https://waf-test.local"+botReservedVerifyPath, nil)
	r.RemoteAddr = "203.0.113.10:1"
	if err := g.ServeHTTP(httptest.NewRecorder(), r, nextHandler{&called}); err != nil || !called {
		t.Fatalf("RELEASED namespace must not intercept: err=%v called=%v", err, called)
	}
	for _, e := range g.readEvents(t) {
		if e.Bot != nil {
			t.Fatalf("OFF must emit no bot events: %+v", e)
		}
	}
}

// TestBotStepTombstone 从已启用状态关闭（OFF + RESERVED_TOMBSTONE）：verify POST
// 本地 404、错误方法 405（Allow: POST）、未知子路径 404——全部本地响应不反代。
func TestBotStepTombstone(t *testing.T) {
	sec := botStepSection(botModeOff)
	sec.RouteReservation.State = botReservationTombstone
	sec.SigningKeys = nil
	g, _ := newBotStepGuard(t, Guard{})
	assembleBotStep(t, g, sec)

	for _, tc := range []struct {
		method, path string
		wantStatus   int
	}{
		{http.MethodPost, botReservedVerifyPath, http.StatusNotFound},
		{http.MethodGet, botReservedVerifyPath, http.StatusMethodNotAllowed},
		{http.MethodGet, botReservedNamespace + "legacy", http.StatusNotFound},
	} {
		called := false
		r := httptest.NewRequest(tc.method, "https://waf-test.local"+tc.path, nil)
		r.RemoteAddr = "203.0.113.10:1"
		rec := httptest.NewRecorder()
		if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		if called || rec.Code != tc.wantStatus {
			t.Errorf("%s %s: code=%d called=%v, want %d local", tc.method, tc.path, rec.Code, called, tc.wantStatus)
		}
		if tc.wantStatus == http.StatusMethodNotAllowed && rec.Header().Get("Allow") != http.MethodPost {
			t.Errorf("405 must carry Allow: POST, got %q", rec.Header().Get("Allow"))
		}
	}
}

// TestBotStepObserveRecordOnly OBSERVE：达阈仅记录「假设会挑战」，请求放行。
func TestBotStepObserveRecordOnly(t *testing.T) {
	g, _ := newBotStepGuard(t, Guard{})
	seedBotBehavior(t, g, "203.0.113.10:1", "https://waf-test.local/docs/x", 6)
	assembleBotStep(t, g, botStepSection(botModeObserve))
	if g.botSvc == nil {
		t.Fatal("OBSERVE with valkey+keyring must construct service")
	}
	called := false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, botStepReq("203.0.113.10:1", "https://waf-test.local/docs/x", botBrowserHeaders()),
		nextHandler{&called}); err != nil || !called {
		t.Fatalf("OBSERVE must pass through: err=%v called=%v", err, called)
	}
	ev := findBotEvent(t, g, events.BotChallengeOffered)
	if ev == nil {
		t.Fatal("OBSERVE threshold-met must log would-challenge event")
	}
	if ev.Action != "OBSERVE" || ev.Bot == nil || ev.Bot.Mode != botModeObserve {
		t.Errorf("observe event: action=%q bot=%+v", ev.Action, ev.Bot)
	}
	// OBSERVE 非终止：不挂 final_decision（提前 Finalize 会锁死 disposition）
	if len(ev.FinalDecision) != 0 {
		t.Errorf("OBSERVE event must not carry final_decision: %s", ev.FinalDecision)
	}
}

// TestBotStepProtectChallengeVerifyFlow PROTECT 全流程：挑战 403（事件带
// final_decision CHALLENGE/BOT）→ verify 204 + clearance → 携通行 Cookie 放行。
func TestBotStepProtectChallengeVerifyFlow(t *testing.T) {
	g, _ := newBotStepGuard(t, Guard{})
	seedBotBehavior(t, g, "203.0.113.10:1", "https://waf-test.local/docs/x", 6)
	assembleBotStep(t, g, botStepSection(botModeProtect))

	// 1. 达阈请求 → 403 挑战页（不反代）
	called := false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, botStepReq("203.0.113.10:1", "https://waf-test.local/docs/x", botBrowserHeaders()),
		nextHandler{&called}); err != nil {
		t.Fatalf("challenge serve: %v", err)
	}
	if called || rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 challenge page, got code=%d called=%v", rec.Code, called)
	}
	params, sess := extractChallenge(t, rec)
	if params.Difficulty != 10 || params.VerifyPath != botReservedVerifyPath {
		t.Errorf("params = %+v", params)
	}

	// 2. 挑战事件携带 final_decision：security_action=CHALLENGE / executor_module=BOT
	ev := findBotEvent(t, g, events.BotChallengeOffered)
	if ev == nil {
		t.Fatal("challenge offered event missing")
	}
	fd := decodeEventFD(t, *ev)
	if fd["security_action"] != "CHALLENGE" || fd["executor_module"] != "BOT" {
		t.Errorf("final_decision action/executor = %v/%v", fd["security_action"], fd["executor_module"])
	}
	if fd["http_status"].(float64) != 403 || fd["response_committed"] != true ||
		fd["completion_status"] != "ABORTED" {
		t.Errorf("final_decision status/committed/completion = %v/%v/%v",
			fd["http_status"], fd["response_committed"], fd["completion_status"])
	}

	// 3. verify：求解提交 → 204 + clearance Cookie
	solution := solveChallenge(t, params)
	body := `{"challenge_id":"` + params.ChallengeID + `","solution":"` + solution + `"}`
	vrec := botVerify(t, g, "203.0.113.10:1", "waf-test.local", sess, body)
	if vrec.Code != http.StatusNoContent {
		t.Fatalf("verify = %d, want 204: %s", vrec.Code, vrec.Body.String())
	}
	clearance := ""
	for _, c := range vrec.Result().Cookies() {
		if c.Name == botchallenge.ClearanceCookieName {
			clearance = c.Value
		}
	}
	if clearance == "" {
		t.Fatal("clearance cookie missing after verify success")
	}

	// 4. 携通行 Cookie（会话绑定：clearance 与 session 双 Cookie 同时携带）：
	// 只通过 Bot 步骤，继续完整后续防护链（到达下游）
	hdrs := botBrowserHeaders()
	hdrs["Cookie"] = botchallenge.SessionCookieName + "=" + sess + "; " +
		botchallenge.ClearanceCookieName + "=" + clearance
	called = false
	rec = httptest.NewRecorder()
	if err := g.ServeHTTP(rec, botStepReq("203.0.113.10:1", "https://waf-test.local/docs/x", hdrs),
		nextHandler{&called}); err != nil || !called {
		t.Fatalf("clearance request must pass bot step: err=%v called=%v", err, called)
	}
}

// TestBotStepNamespaceLocal 命名空间本地处理（服务装配时）：verify 错误方法 405、
// 未知子路径 404，均不反代（BOT-016）。
func TestBotStepNamespaceLocal(t *testing.T) {
	g, _ := newBotStepGuard(t, Guard{})
	assembleBotStep(t, g, botStepSection(botModeProtect))
	for _, tc := range []struct {
		method, path string
		wantStatus   int
	}{
		{http.MethodGet, botReservedVerifyPath, http.StatusMethodNotAllowed},
		{http.MethodGet, botReservedNamespace + "other", http.StatusNotFound},
	} {
		called := false
		r := httptest.NewRequest(tc.method, "https://waf-test.local"+tc.path, nil)
		r.RemoteAddr = "203.0.113.10:1"
		rec := httptest.NewRecorder()
		if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		if called || rec.Code != tc.wantStatus {
			t.Errorf("%s %s: code=%d called=%v, want %d local", tc.method, tc.path, rec.Code, called, tc.wantStatus)
		}
	}
}

// TestBotStepAllowlistStillChallenged 白名单/保护地址/L7 allow 不跳过 Bot（BOT-015）。
func TestBotStepAllowlistStillChallenged(t *testing.T) {
	ip := "203.0.113.10"
	mk := func(cfg Guard) *Guard {
		t.Helper()
		g, _ := newBotStepGuard(t, cfg)
		seedBotBehavior(t, g, ip+":1", "https://waf-test.local/docs/x", 6)
		assembleBotStep(t, g, botStepSection(botModeProtect))
		return g
	}
	guards := map[string]*Guard{
		"allowlist": mk(Guard{
			GlobalAllow: []ruleJSON{{ID: "a1", Address: ip, Priority: 1}},
		}),
		"protected": mk(Guard{
			ProtectedAddresses: []string{ip},
		}),
		"l7allow": mk(Guard{
			L7Rules: l7Config(l7rules.RuleJSON{
				ID: "l7a1", Name: "docs 放行", Priority: 100, Enabled: true,
				Conditions: []l7rules.ConditionJSON{{Type: "uri", Op: "prefix", Value: "/docs"}},
				Action:     "allow",
			}),
		}),
	}
	for name, g := range guards {
		called := false
		rec := httptest.NewRecorder()
		if err := g.ServeHTTP(rec, botStepReq(ip+":1", "https://waf-test.local/docs/x", botBrowserHeaders()),
			nextHandler{&called}); err != nil {
			t.Fatalf("%s: serve: %v", name, err)
		}
		if called || rec.Code != http.StatusForbidden {
			t.Errorf("%s: allow path must still be challenged, code=%d called=%v", name, rec.Code, called)
		}
		if ev := findBotEvent(t, g, events.BotChallengeOffered); ev == nil {
			t.Errorf("%s: challenge event missing", name)
		}
	}
}

// TestBotStepPriorDenialsWin 既有拒绝优先于 Bot：IP 黑名单/CC 拒绝时
// Bot 步骤不会执行（结构上不可能先于它们放行）；clearance 不可能绕过既有拒绝
// （拒绝步骤在 Bot 步骤之前执行）。
func TestBotStepPriorDenialsWin(t *testing.T) {
	// IP 黑名单优先：挑战不发起（含伪造 clearance Cookie 也不影响既有拒绝；
	// 黑名单在 Bot 步骤之前执行，种子无意义——请求根本到不了 Bot）
	g, _ := newBotStepGuard(t, Guard{
		GlobalDeny: []ruleJSON{{ID: "d1", Address: "203.0.113.10", Priority: 1}},
	})
	assembleBotStep(t, g, botStepSection(botModeProtect))
	called := false
	hdrs := botBrowserHeaders()
	hdrs["Cookie"] = botchallenge.ClearanceCookieName + "=forged"
	err := g.ServeHTTP(httptest.NewRecorder(), botStepReq("203.0.113.10:1", "https://waf-test.local/docs/x", hdrs),
		nextHandler{&called})
	if err == nil || called {
		t.Fatalf("blacklist must deny before bot: err=%v called=%v", err, called)
	}
	if ev := findBotEvent(t, g, events.BotChallengeOffered); ev != nil {
		t.Errorf("no challenge may be offered after blacklist deny: %+v", ev.Bot)
	}

	// CC 优先：超限 429 而非挑战
	g2, _ := newBotStepGuard(t, Guard{
		RateLimits: []policyJSON{{
			ID: "cc1", Dimension: "CLIENT_IP", Algorithm: "TOKEN_BUCKET",
			URIMatchType: "ALL", RequestsLimit: 1, WindowSeconds: 60, BurstCapacity: 1,
			Action: "REJECT", Priority: 1,
		}},
	})
	seedBotBehavior(t, g2, "203.0.113.10:1", "https://waf-test.local/docs/x", 1)
	assembleBotStep(t, g2, botStepSection(botModeProtect))
	called = false
	rec := httptest.NewRecorder()
	err = g2.ServeHTTP(rec, botStepReq("203.0.113.10:1", "https://waf-test.local/docs/x", botBrowserHeaders()),
		nextHandler{&called})
	if err != nil || called || rec.Code != http.StatusTooManyRequests {
		t.Fatalf("CC must reject 429 before bot: err=%v called=%v code=%d", err, called, rec.Code)
	}
	if ev := findBotEvent(t, g2, events.BotChallengeOffered); ev != nil {
		t.Errorf("no challenge may be offered after CC reject: %+v", ev.Bot)
	}
}

// TestBotStepStoreFailureProtect503 挑战状态存储故障：PROTECT fail-closed 503
// （绝不静默放行转业务）。
func TestBotStepStoreFailureProtect503(t *testing.T) {
	g, fk := newBotStepGuard(t, Guard{})
	seedBotBehavior(t, g, "203.0.113.10:1", "https://waf-test.local/docs/x", 6)
	assembleBotStep(t, g, botStepSection(botModeProtect))
	fk.fail = true
	called := false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, botStepReq("203.0.113.10:1", "https://waf-test.local/docs/x", botBrowserHeaders()),
		nextHandler{&called}); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if called || rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("store failure must fail-closed 503, code=%d called=%v", rec.Code, called)
	}
	ev := findBotEvent(t, g, events.BotStateUnavailable)
	if ev == nil {
		t.Fatal("state unavailable event missing")
	}
	fd := decodeEventFD(t, *ev)
	if fd["security_action"] != "BLOCK" || fd["executor_module"] != "BOT" {
		t.Errorf("503 final_decision = %v/%v", fd["security_action"], fd["executor_module"])
	}
}

// TestBotStepIneligiblePassThrough 不合格请求（POST/JSON Accept/无 TLS）
// 不返回挑战，仅观测记录 INELIGIBLE 后放行。
func TestBotStepIneligiblePassThrough(t *testing.T) {
	g, _ := newBotStepGuard(t, Guard{})
	seedBotBehavior(t, g, "203.0.113.10:1", "https://waf-test.local/docs/x", 6)
	assembleBotStep(t, g, botStepSection(botModeProtect))

	// POST：方法不合格
	called := false
	r := httptest.NewRequest(http.MethodPost, "https://waf-test.local/docs/x", nil)
	r.RemoteAddr = "203.0.113.10:1"
	r.Header.Set("User-Agent", botStepUA)
	if err := g.ServeHTTP(httptest.NewRecorder(), r, nextHandler{&called}); err != nil || !called {
		t.Errorf("POST must pass through: err=%v called=%v", err, called)
	}
	// JSON Accept：非文档导航
	hdrs := botBrowserHeaders()
	hdrs["Accept"] = "application/json"
	called = false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, botStepReq("203.0.113.10:1", "https://waf-test.local/docs/x", hdrs),
		nextHandler{&called}); err != nil || !called {
		t.Errorf("JSON accept must pass through: err=%v called=%v", err, called)
	}
	if rec.Code == http.StatusForbidden {
		t.Error("ineligible request must not get challenge page")
	}
	// HTTP（无 TLS）：不合格
	called = false
	r = httptest.NewRequest(http.MethodGet, "http://waf-test.local/docs/x", nil)
	r.RemoteAddr = "203.0.113.10:1"
	for k, v := range botBrowserHeaders() {
		r.Header.Set(k, v)
	}
	if err := g.ServeHTTP(httptest.NewRecorder(), r, nextHandler{&called}); err != nil || !called {
		t.Errorf("plain HTTP must pass through: err=%v called=%v", err, called)
	}
	// INELIGIBLE 观测事件已记录
	found := false
	for _, e := range g.readEvents(t) {
		if e.EventType == events.BotChallengeOffered && e.Bot != nil &&
			strings.HasPrefix(e.Bot.Reason, "INELIGIBLE") {
			found = true
		}
	}
	if !found {
		t.Error("INELIGIBLE observation event missing")
	}
}

// TestBotStepNoSignalNoChallenge 信号未达阈（行为观测未种子）：PROTECT 也放行。
// 另证 identity_behavior 未启用时行为组 UNKNOWN 不构成挑战依据。
func TestBotStepNoSignalNoChallenge(t *testing.T) {
	// 不种子：首次请求 uri_concentration 无计数（req=0 → UNAVAILABLE）
	g, _ := newBotStepGuard(t, Guard{})
	assembleBotStep(t, g, botStepSection(botModeProtect))
	called := false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, botStepReq("203.0.113.10:1", "https://waf-test.local/docs/x", botBrowserHeaders()),
		nextHandler{&called}); err != nil || !called {
		t.Fatalf("below-threshold must pass: err=%v called=%v", err, called)
	}
	if rec.Code == http.StatusForbidden {
		t.Error("below-threshold must not be challenged")
	}

	// ibh 未启用：行为组恒 UNKNOWN，即使声明组命中也不挑战
	g2, _ := newBotStepGuard(t, Guard{})
	g2.ibh = nil
	assembleBotStep(t, g2, botStepSection(botModeProtect))
	called = false
	rec = httptest.NewRecorder()
	if err := g2.ServeHTTP(rec, botStepReq("203.0.113.10:1", "https://waf-test.local/docs/x", botBrowserHeaders()),
		nextHandler{&called}); err != nil || !called {
		t.Fatalf("identity behavior disabled must not challenge: err=%v called=%v", err, called)
	}
}

// ---------- 身份风险 CHALLENGE 纵向测试 ----------

func riskChallengeTestPolicy() riskPolicyJSON {
	return riskPolicyJSON{
		Enabled: true, Mode: "PROTECT", Version: 9,
		RateLimitThreshold: 20, ChallengeThreshold: 40, BlockThreshold: 80,
	}
}

func newRiskChallengeBotGuard(t *testing.T, cfg Guard, beforeBot ...func(*Guard)) (*Guard, *fakeGuardValkey) {
	t.Helper()
	if cfg.IdentitySalt == "" {
		cfg.IdentitySalt = "test-salt"
	}
	if cfg.RiskPolicy == nil && len(cfg.RiskPolicyOverrides) == 0 {
		policy := riskChallengeTestPolicy()
		cfg.RiskPolicy = &policy
	}
	g, fk := newBotStepGuard(t, cfg)
	g.provisionRiskPolicy(g.engine)
	for _, configure := range beforeBot {
		configure(g)
	}
	sec := botStepSection(botModeProtect)
	sec.ApplicationID = g.AppID
	assembleBotStep(t, g, sec)
	return g, fk
}

func seedRiskChallengeScore(t *testing.T, g *Guard, ip, target string, headers map[string]string, score int) {
	t.Helper()
	r := botStepReq(ip+":1", target, headers)
	key := identitybehavior.ResolveIdentity(r, "test-salt", ip).Key
	eng := g.riskEngineForApp()
	if eng == nil {
		t.Fatal("risk engine must be assembled")
	}
	eng.AddSignal(g.riskIdentityKey(key), "WAF", score, "risk challenge test seed")
}

func riskChallengeEventsFrom(evs []events.Event) []events.Event {
	out := []events.Event{}
	for _, ev := range evs {
		if ev.EventType == events.RiskPolicyChallenge {
			out = append(out, ev)
		}
	}
	return out
}

func TestRiskChallengeProtectOffersWithoutSecondBotThreshold(t *testing.T) {
	g, _ := newRiskChallengeBotGuard(t, Guard{})
	ip := "203.0.113.10"
	target := "https://waf-test.local/docs/x"
	headers := botBrowserHeaders()
	seedRiskChallengeScore(t, g, ip, target, headers, 50)

	called := false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, botStepReq(ip+":1", target, headers), nextHandler{&called}); err != nil {
		t.Fatalf("risk challenge serve: %v", err)
	}
	if called || rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "wdsp-bot-params") {
		t.Fatalf("risk threshold must offer real 403 page without bot behavior seed: code=%d called=%v body=%.100s",
			rec.Code, called, rec.Body.String())
	}

	params, sess := extractChallenge(t, rec)
	solution := solveChallenge(t, params)
	vrec := botVerify(t, g, ip+":1", "waf-test.local", sess,
		`{"challenge_id":"`+params.ChallengeID+`","solution":"`+solution+`"}`)
	if vrec.Code != http.StatusNoContent {
		t.Fatalf("verify=%d body=%s", vrec.Code, vrec.Body.String())
	}
	clearance := ""
	for _, cookie := range vrec.Result().Cookies() {
		if cookie.Name == botchallenge.ClearanceCookieName {
			clearance = cookie.Value
		}
	}
	if clearance == "" {
		t.Fatal("clearance missing after risk challenge verify")
	}
	withClearance := botBrowserHeaders()
	withClearance["Cookie"] = botchallenge.SessionCookieName + "=" + sess + "; " +
		botchallenge.ClearanceCookieName + "=" + clearance
	called = false
	if err := g.ServeHTTP(httptest.NewRecorder(), botStepReq(ip+":1", target, withClearance), nextHandler{&called}); err != nil || !called {
		t.Fatalf("clearance must pass only the Bot step and continue downstream: err=%v called=%v", err, called)
	}

	evs := g.readEvents(t)
	riskEvs := riskChallengeEventsFrom(evs)
	if len(riskEvs) != 1 || riskEvs[0].Action != "challenged" || riskEvs[0].ResponseStatus != http.StatusForbidden {
		t.Fatalf("actual 403 must emit one challenged event: %+v", riskEvs)
	}
	risk := riskEvs[0].Risk
	if risk == nil || risk.ActionTaken != "challenged" || risk.Score != 50 || risk.Threshold != 40 ||
		risk.Mode != "PROTECT" || risk.PolicyVersion != 9 || risk.Reason != "identity_risk_policy" {
		t.Fatalf("challenged risk detail=%+v", risk)
	}
	fd := decodeEventFD(t, riskEvs[0])
	if fd["security_action"] != "CHALLENGE" || fd["executor_module"] != "BOT" || fd["http_status"].(float64) != 403 {
		t.Fatalf("challenged final_decision=%v", fd)
	}
	botEvent := false
	for _, ev := range evs {
		if ev.EventType == events.BotChallengeOffered && ev.Action == "CHALLENGE" && ev.Bot != nil && ev.Bot.Reason == "IDENTITY_RISK_POLICY" {
			botEvent = true
		}
	}
	if !botEvent {
		t.Fatal("Bot event must identify the identity-risk challenge source")
	}
}

func TestRiskChallengeDefaultOffAndPassThrough(t *testing.T) {
	t.Run("default_off_preserves_legacy_behavior", func(t *testing.T) {
		policy := riskChallengeTestPolicy()
		policy.ChallengeThreshold = 0
		g, _ := newRiskChallengeBotGuard(t, Guard{RiskPolicy: &policy})
		ip := "203.0.113.11"
		target := "https://waf-test.local/docs/x"
		headers := botBrowserHeaders()
		seedRiskChallengeScore(t, g, ip, target, headers, 50)
		called := false
		rec := httptest.NewRecorder()
		if err := g.ServeHTTP(rec, botStepReq(ip+":1", target, headers), nextHandler{&called}); err != nil || !called {
			t.Fatalf("default-off challenge tier must retain legacy pass/rate-limit behavior: err=%v called=%v", err, called)
		}
		if evs := riskChallengeEventsFrom(g.readEvents(t)); len(evs) != 0 {
			t.Fatalf("default-off must emit no risk challenge event: %+v", evs)
		}
	})

	for _, tc := range []struct {
		name   string
		method string
		target string
	}{
		{name: "selector_outside", method: http.MethodGet, target: "https://waf-test.local/api/x"},
		{name: "ineligible_post", method: http.MethodPost, target: "https://waf-test.local/docs/x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := newRiskChallengeBotGuard(t, Guard{})
			ip := "203.0.113.12"
			headers := botBrowserHeaders()
			seedRiskChallengeScore(t, g, ip, tc.target, headers, 50)
			r := httptest.NewRequest(tc.method, tc.target, nil)
			r.RemoteAddr = ip + ":1"
			for k, v := range headers {
				r.Header.Set(k, v)
			}
			called := false
			rec := httptest.NewRecorder()
			if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil || !called || rec.Code != http.StatusOK {
				t.Fatalf("out-of-scope/ineligible request must continue: err=%v called=%v code=%d", err, called, rec.Code)
			}
			if strings.Contains(rec.Body.String(), "wdsp-bot-params") {
				t.Fatal("out-of-scope/ineligible request must never receive challenge HTML")
			}
			evs := g.readEvents(t)
			if riskEvs := riskChallengeEventsFrom(evs); len(riskEvs) != 0 {
				t.Fatalf("no challenged event without actual 403 offer: %+v", riskEvs)
			}
			for _, ev := range evs {
				if ev.EventType == events.BotChallengeOffered && ev.Action == "CHALLENGE" {
					t.Fatalf("no actual Bot challenge expected: %+v", ev)
				}
			}
		})
	}
}

func TestRiskChallengeBlockAndCCPriority(t *testing.T) {
	t.Run("block_before_bot", func(t *testing.T) {
		g, _ := newRiskChallengeBotGuard(t, Guard{})
		ip := "203.0.113.13"
		target := "https://waf-test.local/docs/x"
		headers := botBrowserHeaders()
		seedRiskChallengeScore(t, g, ip, target, headers, 80)
		called := false
		err := g.ServeHTTP(httptest.NewRecorder(), botStepReq(ip+":1", target, headers), nextHandler{&called})
		var handlerErr caddyhttp.HandlerError
		if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusForbidden || called {
			t.Fatalf("risk BLOCK must precede Bot: err=%v called=%v", err, called)
		}
		evs := g.readEvents(t)
		if len(riskChallengeEventsFrom(evs)) != 0 {
			t.Fatal("BLOCK must not emit a risk challenge event")
		}
		blocked := false
		for _, ev := range evs {
			if ev.EventType == events.RiskPolicyBlock && ev.Action == "blocked" {
				blocked = true
			}
			if ev.EventType == events.BotChallengeOffered {
				t.Fatalf("BLOCK must not reach Bot Offer: %+v", ev)
			}
		}
		if !blocked {
			t.Fatal("risk blocked event missing")
		}
	})

	t.Run("cc_before_pending_challenge", func(t *testing.T) {
		g, _ := newRiskChallengeBotGuard(t, Guard{RateLimits: []policyJSON{{
			ID: "cc-risk-challenge", Dimension: "CLIENT_IP", Algorithm: "TOKEN_BUCKET",
			URIMatchType: "ALL", RequestsLimit: 1, WindowSeconds: 60, BurstCapacity: 1,
			Action: "REJECT", Priority: 1,
		}}})
		ip := "203.0.113.14"
		target := "https://waf-test.local/docs/x"
		headers := botBrowserHeaders()
		seedRiskChallengeScore(t, g, ip, target, headers, 50)
		called := false
		first := httptest.NewRecorder()
		if err := g.ServeHTTP(first, botStepReq(ip+":1", target, headers), nextHandler{&called}); err != nil || called || first.Code != http.StatusForbidden {
			t.Fatalf("first request must pass CC then challenge: err=%v called=%v code=%d", err, called, first.Code)
		}
		second := httptest.NewRecorder()
		if err := g.ServeHTTP(second, botStepReq(ip+":1", target, headers), nextHandler{&called}); err != nil || called || second.Code != http.StatusTooManyRequests {
			t.Fatalf("second request must be rejected by CC before Bot: err=%v called=%v code=%d", err, called, second.Code)
		}
		evs := g.readEvents(t)
		if riskEvs := riskChallengeEventsFrom(evs); len(riskEvs) != 1 {
			t.Fatalf("CC rejection must not be counted as another challenge: %+v", riskEvs)
		}
		ccRejected := false
		for _, ev := range evs {
			if ev.EventType == events.CCRequestRejected && ev.ResponseStatus == http.StatusTooManyRequests {
				ccRejected = true
			}
		}
		if !ccRejected {
			t.Fatal("CC rejection event missing")
		}
	})
}

type rejectBotIssueLimiter struct{}

func (rejectBotIssueLimiter) Allow(_ context.Context, key string, _ ratelimit.Algorithm, _ int64, _ time.Duration, _ int64) (ratelimit.Result, error) {
	if strings.HasPrefix(key, "iss-") {
		return ratelimit.Result{Allowed: false, RetryAfter: time.Second}, nil
	}
	return ratelimit.Result{Allowed: true}, nil
}

func (rejectBotIssueLimiter) Peek(context.Context, string, ratelimit.Algorithm, int64, time.Duration, int64) (int64, bool, error) {
	return 0, false, nil
}

func TestRiskChallengeOfferFailuresAreNotChallenged(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configure  func(*Guard)
		failStore  bool
		wantStatus int
	}{
		{
			name: "rate_limited_429", wantStatus: http.StatusTooManyRequests,
			configure: func(g *Guard) { g.engine.limiter = rejectBotIssueLimiter{} },
		},
		{name: "store_unavailable_503", failStore: true, wantStatus: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var before []func(*Guard)
			if tc.configure != nil {
				before = append(before, tc.configure)
			}
			g, fk := newRiskChallengeBotGuard(t, Guard{}, before...)
			fk.fail = tc.failStore
			ip := "203.0.113.15"
			target := "https://waf-test.local/docs/x"
			headers := botBrowserHeaders()
			seedRiskChallengeScore(t, g, ip, target, headers, 50)
			called := false
			rec := httptest.NewRecorder()
			if err := g.ServeHTTP(rec, botStepReq(ip+":1", target, headers), nextHandler{&called}); err != nil {
				t.Fatalf("Offer failure serve: %v", err)
			}
			if called || rec.Code != tc.wantStatus {
				t.Fatalf("Offer must preserve real failure status: code=%d called=%v want=%d", rec.Code, called, tc.wantStatus)
			}
			evs := g.readEvents(t)
			if riskEvs := riskChallengeEventsFrom(evs); len(riskEvs) != 0 {
				t.Fatalf("failed Offer must not emit challenged: %+v", riskEvs)
			}
			failureEvent := false
			for _, ev := range evs {
				if ev.EventType == events.BotStateUnavailable && ev.ResponseStatus == tc.wantStatus {
					failureEvent = true
					fd := decodeEventFD(t, ev)
					if fd["security_action"] == "CHALLENGE" {
						t.Fatalf("failed Offer final decision must not be CHALLENGE: %v", fd)
					}
				}
			}
			if !failureEvent {
				t.Fatal("real Bot failure event missing")
			}
		})
	}
}

func TestRiskChallengeApplicationOverride(t *testing.T) {
	appID := "app-risk-challenge-override"
	override := riskChallengeTestPolicy()
	override.Version = 12
	g, _ := newRiskChallengeBotGuard(t, Guard{
		AppID:               appID,
		RiskPolicy:          &riskPolicyJSON{Enabled: true, Mode: "OBSERVE"},
		RiskPolicyOverrides: []riskPolicyOverrideJSON{{ApplicationID: appID, Policy: override}},
	})
	ip := "203.0.113.16"
	target := "https://waf-test.local/docs/x"
	headers := botBrowserHeaders()
	seedRiskChallengeScore(t, g, ip, target, headers, 50)
	called := false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, botStepReq(ip+":1", target, headers), nextHandler{&called}); err != nil || called || rec.Code != http.StatusForbidden {
		t.Fatalf("application override must challenge: err=%v called=%v code=%d", err, called, rec.Code)
	}
	evs := riskChallengeEventsFrom(g.readEvents(t))
	if len(evs) != 1 || evs[0].Risk == nil || evs[0].Risk.PolicyVersion != 12 || evs[0].Risk.Threshold != 40 {
		t.Fatalf("application override challenge event=%+v", evs)
	}
}

func TestRiskChallengePassThroughKeepsJWTAndDownstreamWAF(t *testing.T) {
	g, _ := newRiskChallengeBotGuard(t, Guard{AppID: "app-1"})
	key := jwtTestRSA(t)
	jwtSec := jwtStaticSection("PROTECT", true, jwtTestJWKS(t, &key.PublicKey, "risk-challenge-jwt"))
	jwtSec.ApplicationID = g.AppID
	jwtSec.Selectors[0].PathPrefix = "/docs"
	jwtSec.Selectors[0].Methods = []string{http.MethodPost}
	g.JWTTrust = mustJSON(t, jwtSec)
	if err := g.assembleJWTTrust(); err != nil {
		t.Fatalf("assemble JWT: %v", err)
	}

	ip := "203.0.113.17"
	target := "https://waf-test.local/docs/x"
	headers := botBrowserHeaders()
	seedRiskChallengeScore(t, g, ip, target, headers, 50)
	newPost := func(token string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, target, nil)
		r.RemoteAddr = ip + ":1"
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		return r
	}
	called := false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, newPost(""), nextHandler{&called}); err != nil || called || rec.Code != http.StatusUnauthorized {
		t.Fatalf("ineligible risk challenge pass-through must still enforce JWT: err=%v called=%v code=%d", err, called, rec.Code)
	}

	token := jwtSignRS256(t, key, "risk-challenge-jwt", jwtValidClaims())
	wafCalled := false
	err := g.ServeHTTP(httptest.NewRecorder(), newPost(token), ibHandlerFunc(func(http.ResponseWriter, *http.Request) error {
		wafCalled = true
		return caddyhttp.Error(http.StatusForbidden, errors.New("downstream WAF test interception"))
	}))
	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusForbidden || !wafCalled {
		t.Fatalf("downstream WAF handler must remain reachable after Bot pass-through: err=%v called=%v", err, wafCalled)
	}
	evs := g.readEvents(t)
	if riskEvs := riskChallengeEventsFrom(evs); len(riskEvs) != 0 {
		t.Fatalf("JWT/downstream WAF outcomes must not be marked challenged: %+v", riskEvs)
	}
	jwtRejected := false
	for _, ev := range evs {
		if ev.EventType == events.JWTAuthFailed && ev.ResponseStatus == http.StatusUnauthorized {
			jwtRejected = true
		}
	}
	if !jwtRejected {
		t.Fatal("JWT rejection fact missing")
	}
}

// M-G2 + C-07 回归：
// 1. 风险引擎 CHALLENGE 在 Bot PROTECT 下不得被 X-Requested-With / Accept: */* / Sec-Fetch-* 头绕过；
// 2. C-07 Bot 选择器与保留命名空间路径规范化防 // 与 .. 绕过。
func TestMG2RiskChallengeNotBypassedBySpoofedHeadersAndC07CanonicalPaths(t *testing.T) {
	t.Run("风险 CHALLENGE 不得被 X-Requested-With 或 Accept:*/* 绕过", func(t *testing.T) {
		target := "https://waf-test.local/docs/x"
		for i, tc := range []struct {
			name    string
			headers map[string]string
		}{
			{"X-Requested-With", map[string]string{"User-Agent": "Mozilla/5.0", "Accept": "text/html", "X-Requested-With": "XMLHttpRequest"}},
			{"Accept_star", map[string]string{"User-Agent": "Mozilla/5.0", "Accept": "*/*"}},
			{"Sec-Fetch-Mode_cors", map[string]string{"User-Agent": "Mozilla/5.0", "Accept": "text/html", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				g, _ := newRiskChallengeBotGuard(t, Guard{})
				ip := "203.0.113." + strconv.Itoa(71+i)
				seedRiskChallengeScore(t, g, ip, target, tc.headers, 50)
				called := false
				rec := httptest.NewRecorder()
				err := g.ServeHTTP(rec, botStepReq(ip+":1", target, tc.headers), nextHandler{&called})
				if err != nil || called || rec.Code != http.StatusForbidden {
					t.Fatalf("M-G2: %s 不得绕过风险 CHALLENGE: err=%v called=%v code=%d", tc.name, err, called, rec.Code)
				}
				if !strings.Contains(rec.Body.String(), "wdsp-bot-params") {
					t.Fatalf("M-G2: 应签发 Bot 挑战页: %s", rec.Body.String())
				}
			})
		}
	})

	t.Run("C-07 Bot 选择器与保留命名空间规范化拦截 // 和 ..", func(t *testing.T) {
		g, _ := newRiskChallengeBotGuard(t, Guard{})
		ip := "203.0.113.72"
		headers := botBrowserHeaders()
		seedRiskChallengeScore(t, g, ip, "https://waf-test.local/docs/x", headers, 50)
		for _, target := range []string{
			"https://waf-test.local//docs//x",
			"https://waf-test.local/public/../docs/x",
		} {
			called := false
			rec := httptest.NewRecorder()
			err := g.ServeHTTP(rec, botStepReq(ip+":1", target, headers), nextHandler{&called})
			if err != nil || called || rec.Code != http.StatusForbidden {
				t.Fatalf("C-07: %q 不得绕过 Bot 选择器: err=%v called=%v code=%d", target, err, called, rec.Code)
			}
		}
		// 保留命名空间 //_wdsp/bot/v1/unknown 必须本地 404，不得穿透到上游
		called := false
		rec := httptest.NewRecorder()
		err := g.ServeHTTP(rec, botStepReq(ip+":1", "https://waf-test.local//_wdsp/bot/v1/unknown", headers), nextHandler{&called})
		if err != nil || called || rec.Code != http.StatusNotFound {
			t.Fatalf("C-07: //_wdsp/bot/v1/unknown 必须本地 404: err=%v called=%v code=%d", err, called, rec.Code)
		}
	})
}
