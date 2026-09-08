package botchallenge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
)

// service_test.go / verify_test.go 共享夹具：Offer 一次并解析挑战页参数与 Cookie。

var paramsRe = regexp.MustCompile(`(?s)<script nonce="[^"]*" id="wdsp-bot-params" type="application/json">(.*?)</script>`)

type offerResult struct {
	recorder    *httptest.ResponseRecorder
	params      paramsJSON
	sessionC    *http.Cookie
	clearanceC  *http.Cookie
	requestHost string
}

// doOffer 执行一次挑战签发并解析产物。
func doOffer(t *testing.T, svc *Service, host, clientIP string, cookies ...*http.Cookie) offerResult {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "https://"+host+"/products", nil)
	r.Host = host
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	svc.Offer(rec, r, CallContext{RequestID: "req-1", ClientIP: clientIP, ConnectionIP: "10.0.0.1"}, "SIGNAL_RULE_HIT")
	res := offerResult{recorder: rec, requestHost: host}
	if rec.Code != http.StatusForbidden {
		return res
	}
	m := paramsRe.FindStringSubmatch(rec.Body.String())
	if len(m) != 2 {
		t.Fatalf("challenge params block not found in page")
	}
	if err := json.Unmarshal([]byte(m[1]), &res.params); err != nil {
		t.Fatalf("params json: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case SessionCookieName:
			res.sessionC = c
		case ClearanceCookieName:
			res.clearanceC = c
		}
	}
	return res
}

// verifyRequest 构造一次 verify POST。
func doVerify(t *testing.T, svc *Service, o offerResult, solution string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"challenge_id": o.params.ChallengeID, "solution": solution})
	r := httptest.NewRequest(http.MethodPost, "https://"+o.requestHost+VerifyPath, strings.NewReader(string(body)))
	r.Host = o.requestHost
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://"+o.requestHost)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if o.sessionC != nil {
		r.AddCookie(o.sessionC)
	}
	if o.clearanceC != nil {
		r.AddCookie(o.clearanceC)
	}
	if mutate != nil {
		mutate(r)
	}
	rec := httptest.NewRecorder()
	svc.ServeVerify(rec, r, CallContext{RequestID: "req-2", ClientIP: "203.0.113.7", ConnectionIP: "10.0.0.1"})
	return rec
}

// solveFor 用页面参数求解（与服务端同一编码）。
func solveFor(t *testing.T, svc *Service, o offerResult) string {
	t.Helper()
	sol, ok := Solve(o.params.ChallengeID, o.params.Nonce, svc.cfg.AppID, o.requestHost, svc.cfg.Difficulty, 1<<22)
	if !ok {
		t.Fatal("solver failed within bound")
	}
	return sol
}

// 完整闭环：签发 → 求解 → 验证 204 → clearance 属性断言 → ValidateClearance 通过 →
// 事件链（offered/verify_success 同 flow_id）。
func TestOfferVerifyHappyPath(t *testing.T) {
	fk := newFakeBotValkey()
	sink := &captureSink{}
	svc, _ := newTestService(t, fk, nil, sink, testServiceOpts{})
	host := "shop.example.com"

	o := doOffer(t, svc, host, "203.0.113.7")
	if o.recorder.Code != http.StatusForbidden {
		t.Fatalf("offer status: %d", o.recorder.Code)
	}
	// 会话 Cookie 属性（__Host- 契约）
	if o.sessionC == nil {
		t.Fatal("session cookie must be set")
	}
	assertHostCookie(t, o.sessionC, SessionCookieName, int(svc.sessionTTL().Seconds()))
	// 挑战页不得携带 clearance
	if o.clearanceC != nil {
		t.Fatal("challenge page must never set clearance")
	}
	// 缓存与嵌入纪律
	if cc := o.recorder.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control: %q", cc)
	}

	sol := solveFor(t, svc, o)
	rec := doVerify(t, svc, o, sol, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("verify status: %d body=%s", rec.Code, rec.Body.String())
	}
	var clearanceC *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == ClearanceCookieName {
			clearanceC = c
		}
	}
	if clearanceC == nil {
		t.Fatal("clearance cookie must be set on success")
	}
	assertHostCookie(t, clearanceC, ClearanceCookieName, int(svc.cfg.ClearanceTTL.Seconds()))

	// ValidateClearance（B3 挂点语义）：携带双 Cookie 的业务请求通过
	r2 := httptest.NewRequest(http.MethodGet, "https://"+host+"/products", nil)
	r2.Host = host
	r2.AddCookie(o.sessionC)
	r2.AddCookie(clearanceC)
	cl, err := svc.ValidateClearance(r2, CallContext{RequestID: "req-3", ClientIP: "203.0.113.7"})
	if err != nil || cl == nil {
		t.Fatalf("validate clearance: %v", err)
	}
	if cl.FlowID == "" || cl.KeyID != "bot-key-a" {
		t.Fatalf("clearance info: %+v", cl)
	}

	// 事件链：offered + verify_success + clearance_accepted，flow_id 一致且脱敏
	offered := sink.byType(events.BotChallengeOffered)
	success := sink.byType(events.BotVerifySuccess)
	accepted := sink.byType(events.BotClearanceAccepted)
	if len(offered) != 1 || len(success) != 1 || len(accepted) != 1 {
		t.Fatalf("events: offered=%d success=%d accepted=%d", len(offered), len(success), len(accepted))
	}
	fl := offered[0].Bot.FlowID
	if fl == "" || success[0].Bot.FlowID != fl || accepted[0].Bot.FlowID != fl {
		t.Fatalf("flow_id correlation: %q / %q / %q", fl, success[0].Bot.FlowID, accepted[0].Bot.FlowID)
	}
	if success[0].Bot.PolicyVersion != 7 || success[0].Bot.PolicyEpoch != 7 || success[0].Bot.Mode != ModeProtect {
		t.Fatalf("policy version/epoch/mode in event: %+v", success[0].Bot)
	}
	// 第二次 ValidateClearance 不重复记事件（每 flow 每节点一次）
	if _, err := svc.ValidateClearance(r2, CallContext{RequestID: "req-4", ClientIP: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	if got := len(sink.byType(events.BotClearanceAccepted)); got != 1 {
		t.Fatalf("clearance_accepted must be throttled per flow: %d", got)
	}
}

// assertHostCookie __Host- 前缀契约断言。
func assertHostCookie(t *testing.T, c *http.Cookie, name string, maxAge int) {
	t.Helper()
	if c.Name != name || !strings.HasPrefix(name, "__Host-") {
		t.Fatalf("cookie name: %q", c.Name)
	}
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie flags: %+v", c)
	}
	if c.Path != "/" || c.Domain != "" {
		t.Fatalf("__Host- requires Path=/ and no Domain: %+v", c)
	}
	if c.MaxAge != maxAge {
		t.Fatalf("cookie max-age: %d want %d", c.MaxAge, maxAge)
	}
}

// 固定方法：GET/PUT/DELETE 405 + Allow；未知子路径 404；均不反向代理。
func TestVerifyMethodAndPath(t *testing.T) {
	svc, _ := newTestService(t, nil, nil, nil, testServiceOpts{})
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		r := httptest.NewRequest(m, "https://shop.example.com"+VerifyPath, nil)
		rec := httptest.NewRecorder()
		svc.ServeNamespace(rec, r, CallContext{ClientIP: "203.0.113.7"})
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
			t.Fatalf("%s must 405 with Allow: POST: %d", m, rec.Code)
		}
	}
	for _, p := range []string{"/_wdsp/bot/v1/", "/_wdsp/bot/v1/verify/x", "/_wdsp/bot/v1/status", "/_wdsp/bot/v1/VERIFY"} {
		r := httptest.NewRequest(http.MethodPost, "https://shop.example.com"+p, nil)
		rec := httptest.NewRecorder()
		if !svc.ServeNamespace(rec, r, CallContext{ClientIP: "203.0.113.7"}) {
			t.Fatalf("%s must be handled locally", p)
		}
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s must 404: %d", p, rec.Code)
		}
	}
}

// 正文边界：>8KiB 拒绝；坏 JSON / 未知字段 / 非法 challenge_id / 超长 solution 拒绝；
// 非 JSON Content-Type 拒绝。全部 400 且无 clearance。
func TestVerifyBodyBounds(t *testing.T) {
	svc, _ := newTestService(t, nil, nil, nil, testServiceOpts{})
	host := "shop.example.com"
	mk := func(body string, ct string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "https://"+host+VerifyPath, strings.NewReader(body))
		r.Host = host
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		r.Header.Set("Origin", "https://"+host)
		rec := httptest.NewRecorder()
		svc.ServeVerify(rec, r, CallContext{ClientIP: "203.0.113.7"})
		return rec
	}
	// 超限正文
	big := `{"challenge_id":"` + strings.Repeat("ab", challengeIDBytes) + `","solution":"1","pad":"` + strings.Repeat("x", MaxVerifyBodyBytes) + `"}`
	if rec := mk(big, "application/json"); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversize body must 400: %d", rec.Code)
	}
	// 未知字段（含 difficulty——客户端不可降难度，严格解码直接拒绝）
	if rec := mk(`{"challenge_id":"`+strings.Repeat("ab", challengeIDBytes)+`","solution":"1","difficulty":1}`, "application/json"); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field must 400: %d", rec.Code)
	}
	if rec := mk(`{"challenge_id":"`+strings.Repeat("ab", challengeIDBytes)+`","solution":"1","nonce":"00"}`, "application/json"); rec.Code != http.StatusBadRequest {
		t.Fatalf("client-supplied nonce must 400: %d", rec.Code)
	}
	// 坏 JSON / 词形
	for _, body := range []string{`{`, `[]`, `{"challenge_id":"xy","solution":"1"}`, `{"challenge_id":"` + strings.Repeat("ab", challengeIDBytes) + `","solution":"` + strings.Repeat("9", 21) + `"}`, `{"challenge_id":"` + strings.Repeat("ab", challengeIDBytes) + `","solution":""}`} {
		if rec := mk(body, "application/json"); rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q must 400: %d", body[:min(len(body), 40)], rec.Code)
		}
	}
	// 非 JSON 类型
	if rec := mk(`{"challenge_id":"x"}`, "text/plain"); rec.Code != http.StatusBadRequest {
		t.Fatalf("text/plain must 400: %d", rec.Code)
	}
	// 任何失败不得携带 clearance
	if rec := mk(`{`, "application/json"); len(rec.Result().Cookies()) != 0 {
		t.Fatal("failure must never set cookies")
	}
}

// 来源校验：缺 Origin 默认拒绝；跨域/HTTP Origin 拒绝；cross-site Fetch Metadata 拒绝。
func TestVerifyOriginAndFetchMetadata(t *testing.T) {
	fk := newFakeBotValkey()
	sink := &captureSink{}
	svc, _ := newTestService(t, fk, nil, sink, testServiceOpts{})
	host := "shop.example.com"
	o := doOffer(t, svc, host, "203.0.113.7")
	sol := solveFor(t, svc, o)

	// 缺 Origin → 403 ORIGIN_REQUIRED
	rec := doVerify(t, svc, o, sol, func(r *http.Request) { r.Header.Del("Origin") })
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errOriginRequired) {
		t.Fatalf("missing origin: %d %s", rec.Code, rec.Body.String())
	}
	// 跨域 → 403 ORIGIN_MISMATCH
	rec = doVerify(t, svc, o, sol, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example.com") })
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errOriginMismatch) {
		t.Fatalf("cross origin: %d", rec.Code)
	}
	// http scheme → 403
	rec = doVerify(t, svc, o, sol, func(r *http.Request) { r.Header.Set("Origin", "http://"+host) })
	if rec.Code != http.StatusForbidden {
		t.Fatalf("http origin must 403: %d", rec.Code)
	}
	// Origin host 不匹配（含端口差异）→ 403
	rec = doVerify(t, svc, o, sol, func(r *http.Request) { r.Header.Set("Origin", "https://"+host+":8443") })
	if rec.Code != http.StatusForbidden {
		t.Fatalf("port-mismatched origin must 403: %d", rec.Code)
	}
	// cross-site Fetch Metadata → 403
	rec = doVerify(t, svc, o, sol, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") })
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errFetchRejected) {
		t.Fatalf("cross-site fetch metadata: %d", rec.Code)
	}
	// 以上全部失败不得消费挑战：正确解答仍可通过
	rec = doVerify(t, svc, o, sol, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("legit verify after rejected attempts: %d", rec.Code)
	}
	// 拒绝事件归因
	rejected := sink.byType(events.BotVerifyRejected)
	if len(rejected) < 5 {
		t.Fatalf("rejected events: %d", len(rejected))
	}
}

// 会话绑定：无会话 Cookie / 伪造会话（攻击者密钥签发）/ 跨会话（另一会话的 Cookie）拒绝。
func TestVerifySessionBinding(t *testing.T) {
	fk := newFakeBotValkey()
	svc, _ := newTestService(t, fk, nil, nil, testServiceOpts{})
	host := "shop.example.com"
	o := doOffer(t, svc, host, "203.0.113.7")
	sol := solveFor(t, svc, o)

	// 无会话 Cookie → 403 SESSION_INVALID
	rec := doVerify(t, svc, o, sol, func(r *http.Request) {
		r.Header.Del("Cookie")
	})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errSessionInvalid) {
		t.Fatalf("no session: %d", rec.Code)
	}
	// 伪造会话 Cookie（攻击者密钥环签发）→ 403
	attackerKr := testKeyring(t, "attacker-key")
	forged, err := signToken(mustLookup(t, attackerKr, "attacker-key"), purposeSession, sessionPayload{
		V: 1, Sid: strings.Repeat("00", sessionIDBytes), Exp: time.Now().Add(time.Hour).Unix(), Kid: "attacker-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	rec = doVerify(t, svc, o, sol, func(r *http.Request) {
		r.Header.Del("Cookie")
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: forged})
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("forged session: %d", rec.Code)
	}
	// 跨会话：另一 Offer 签发的会话 Cookie 不能用于本挑战（绑定摘要不符）→ 403 BINDING_MISMATCH
	o2 := doOffer(t, svc, host, "203.0.113.8")
	rec = doVerify(t, svc, o, sol, func(r *http.Request) {
		r.Header.Del("Cookie")
		r.AddCookie(o2.sessionC)
	})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errBindingMismatch) {
		t.Fatalf("cross-session: %d %s", rec.Code, rec.Body.String())
	}
}

// 错误解答：403 BAD_SOLUTION 记账；达 max_attempts 作废（409 ATTEMPTS_EXHAUSTED）；
// 作废后正确解答也 409（挑战已不存在）。
func TestVerifyBadSolutionAndExhaustion(t *testing.T) {
	fk := newFakeBotValkey()
	sink := &captureSink{}
	svc, _ := newTestService(t, fk, nil, sink, testServiceOpts{})
	host := "shop.example.com"
	o := doOffer(t, svc, host, "203.0.113.7")

	// 构造一个必然错误的解答：找不满足 difficulty 的候选
	bad := ""
	for i := uint64(0); i < 1<<20; i++ {
		cand := strconv.FormatUint(i, 10)
		ok, _ := CheckSolution(o.params.ChallengeID, o.params.Nonce, svc.cfg.AppID, host, cand, svc.cfg.Difficulty)
		if !ok {
			bad = cand
			break
		}
	}
	if bad == "" {
		t.Fatal("no bad solution found")
	}
	rec := doVerify(t, svc, o, bad, nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errBadSolution) {
		t.Fatalf("bad solution 1: %d %s", rec.Code, rec.Body.String())
	}
	rec = doVerify(t, svc, o, bad, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad solution 2: %d", rec.Code)
	}
	rec = doVerify(t, svc, o, bad, nil) // 第 3 次（=max_attempts）作废
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), errAttemptsExhaust) {
		t.Fatalf("exhausted: %d %s", rec.Code, rec.Body.String())
	}
	// 作废后正确解答也拒绝（409）
	rec = doVerify(t, svc, o, solveFor(t, svc, o), nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("exhausted challenge must stay dead: %d", rec.Code)
	}
	// 事件：verify_rejected 含 attempts 计数
	rejected := sink.byType(events.BotVerifyRejected)
	if len(rejected) != 4 {
		t.Fatalf("rejected events: %d", len(rejected))
	}
	if rejected[0].Bot.Attempts != 1 || rejected[1].Bot.Attempts != 2 || rejected[2].Bot.Attempts != 3 {
		t.Fatalf("attempts in events: %+v / %+v / %+v", rejected[0].Bot, rejected[1].Bot, rejected[2].Bot)
	}
}

// 重放：成功消费后再次提交同一 nonce → 409（跨节点并发见 TestCrossNodeConcurrentVerify）。
func TestVerifyReplay(t *testing.T) {
	fk := newFakeBotValkey()
	sink := &captureSink{}
	svc, _ := newTestService(t, fk, nil, sink, testServiceOpts{})
	host := "shop.example.com"
	o := doOffer(t, svc, host, "203.0.113.7")
	sol := solveFor(t, svc, o)
	if rec := doVerify(t, svc, o, sol, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("first verify: %d", rec.Code)
	}
	rec := doVerify(t, svc, o, sol, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), errChallengeGone) {
		t.Fatalf("replay must 409: %d %s", rec.Code, rec.Body.String())
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("replay must never set clearance")
	}
}

// 过期 nonce：时钟越过 nonce_ttl → 409 CHALLENGE_EXPIRED + expired 事件。
func TestVerifyExpiredChallenge(t *testing.T) {
	fk := newFakeBotValkey()
	sink := &captureSink{}
	svc, now := newTestService(t, fk, nil, sink, testServiceOpts{})
	host := "shop.example.com"
	o := doOffer(t, svc, host, "203.0.113.7")
	*now = now.Add(91 * time.Second)
	rec := doVerify(t, svc, o, solveFor(t, svc, o), nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), errChallengeExpired) {
		t.Fatalf("expired: %d %s", rec.Code, rec.Body.String())
	}
	if got := len(sink.byType(events.BotChallengeExpired)); got != 1 {
		t.Fatalf("expired event: %d", got)
	}
}

// 跨节点：节点 A 签发、节点 B 验证成功（共享 Valkey + 同密钥环）；
// 并发提交同一 nonce 到两节点 → 至多一次 204，其余 409。
func TestCrossNodeConcurrentVerify(t *testing.T) {
	fk := newFakeBotValkey()
	kr := testKeyring(t, "bot-key-a")
	sinkA, sinkB := &captureSink{}, &captureSink{}
	nodeA, _ := newTestService(t, fk, nil, sinkA, testServiceOpts{keyring: kr, node: "gw-a"})
	nodeB, _ := newTestService(t, fk, nil, sinkB, testServiceOpts{keyring: kr, node: "gw-b"})
	host := "shop.example.com"

	o := doOffer(t, nodeA, host, "203.0.113.7")
	sol := solveFor(t, nodeA, o)

	// 单发跨节点验证（A 签发 B 验证）
	if rec := doVerify(t, nodeB, o, sol, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("cross-node verify: %d %s", rec.Code, rec.Body.String())
	}

	// 并发：新挑战，16 个 goroutine 交替打到 A/B
	o2 := doOffer(t, nodeA, host, "203.0.113.9")
	sol2 := solveFor(t, nodeA, o2)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			node := nodeA
			if i%2 == 1 {
				node = nodeB
			}
			rec := doVerify(t, node, o2, sol2, nil)
			mu.Lock()
			codes[rec.Code]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if codes[http.StatusNoContent] != 1 {
		t.Fatalf("exactly-once violated: %v", codes)
	}
	if codes[http.StatusConflict] != 15 {
		t.Fatalf("losers must 409: %v", codes)
	}
	// 成功事件只在一侧出现一次
	if got := len(sinkA.byType(events.BotVerifySuccess)) + len(sinkB.byType(events.BotVerifySuccess)); got != 2 {
		// 2 = 单发 1 次 + 并发 1 次
		t.Fatalf("verify_success events across nodes: %d", got)
	}
}
