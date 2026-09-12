package botchallenge

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
)

// 签发速率上限：会话维超限 → 429 + Retry-After，不写挑战状态、不设 clearance。
func TestOfferRateLimited(t *testing.T) {
	fk := newFakeBotValkey()
	lim := &fakeLimiter{denyKeys: map[string]bool{}, failKeys: map[string]bool{}}
	sink := &captureSink{}
	lim.deny("iss-ip")
	svc, _ := newTestService(t, fk, lim, sink, testServiceOpts{})
	o := doOffer(t, svc, "shop.example.com", "203.0.113.7")
	if o.recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limited offer: %d", o.recorder.Code)
	}
	if o.recorder.Header().Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
	if o.clearanceC != nil {
		t.Fatal("429 must never set clearance")
	}
	if got := len(fk.keyDump()); got != 0 {
		t.Fatalf("rate limited offer must not write state: %d keys", got)
	}
	evs := sink.byType(events.BotStateUnavailable)
	if len(evs) != 1 || evs[0].Bot.Reason != "ISSUE_RATE_LIMITED" {
		t.Fatalf("event: %+v", evs)
	}
}

// 在途容量上限：InFlightCap=1 时第二次签发 → 503 + Retry-After。
func TestOfferCapacityExceeded(t *testing.T) {
	fk := newFakeBotValkey()
	sink := &captureSink{}
	svc, _ := newTestService(t, fk, nil, sink, testServiceOpts{capN: 1})
	host := "shop.example.com"
	if o := doOffer(t, svc, host, "203.0.113.7"); o.recorder.Code != http.StatusForbidden {
		t.Fatalf("first offer: %d", o.recorder.Code)
	}
	o2 := doOffer(t, svc, host, "203.0.113.8")
	if o2.recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("cap exceeded offer: %d", o2.recorder.Code)
	}
	if o2.recorder.Header().Get("Retry-After") == "" {
		t.Fatal("503 must carry Retry-After")
	}
	evs := sink.byType(events.BotStateUnavailable)
	if len(evs) != 1 || evs[0].Bot.Reason != "INFLIGHT_CAP_REACHED" {
		t.Fatalf("event: %+v", evs)
	}
}

// 存储故障：Offer 503（fail-closed）；verify 503；限速器故障 503。绝不静默签发。
func TestStateUnavailableFailClosed(t *testing.T) {
	fk := newFakeBotValkey()
	sink := &captureSink{}
	svc, _ := newTestService(t, fk, nil, sink, testServiceOpts{})
	host := "shop.example.com"

	// 先正常签发一次（verify 路径读状态故障）
	o := doOffer(t, svc, host, "203.0.113.7")
	if o.recorder.Code != http.StatusForbidden {
		t.Fatalf("offer: %d", o.recorder.Code)
	}
	fk.fail = true
	// Offer：存储故障 503
	o2 := doOffer(t, svc, host, "203.0.113.8")
	if o2.recorder.Code != http.StatusServiceUnavailable || o2.recorder.Header().Get("Retry-After") == "" {
		t.Fatalf("offer with store down: %d", o2.recorder.Code)
	}
	// verify：读状态故障 503（不设置 clearance）
	rec := doVerify(t, svc, o, "1", nil)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("verify with store down: %d", rec.Code)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("503 must never set clearance")
	}
	evs := sink.byType(events.BotStateUnavailable)
	if len(evs) != 2 {
		t.Fatalf("state_unavailable events: %d", len(evs))
	}
	for _, e := range evs {
		if e.Bot.Reason != "STORE_ERROR" {
			t.Fatalf("reason: %+v", e.Bot)
		}
	}

	// 限速器故障 → 503
	fk.fail = false
	lim := &fakeLimiter{denyKeys: map[string]bool{}, failKeys: map[string]bool{"iss": true}}
	svc2, _ := newTestService(t, newFakeBotValkey(), lim, nil, testServiceOpts{})
	o3 := doOffer(t, svc2, host, "203.0.113.9")
	if o3.recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("offer with limiter down: %d", o3.recorder.Code)
	}
}

// verify 速率超限 → 429（不消耗尝试次数）。
func TestVerifyRateLimited(t *testing.T) {
	fk := newFakeBotValkey()
	lim := &fakeLimiter{denyKeys: map[string]bool{}, failKeys: map[string]bool{}}
	lim.deny("vfy-sess")
	svc, _ := newTestService(t, fk, lim, nil, testServiceOpts{})
	host := "shop.example.com"
	o := doOffer(t, svc, host, "203.0.113.7")
	rec := doVerify(t, svc, o, "1", nil)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("verify rate limited: %d", rec.Code)
	}
	// 未消费尝试：解除限速后正确解答仍通过
	lim.denyKeys = map[string]bool{}
	if rec := doVerify(t, svc, o, solveFor(t, svc, o), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("verify after rate limit lifted: %d", rec.Code)
	}
}

// key_ref 绑定：引用名不在密钥环允许列表 → 装配 fail-closed；
// 在列表中 → 签名用该 key_id（事件可溯源）。
func TestKeyRefBinding(t *testing.T) {
	kr := testKeyring(t, "bot-key-a", "bot-key-old")
	_, err := NewService(Config{
		AppID: "app-1", Mode: ModeProtect, PolicyVersion: 1,
		NonceTTL: 90 * time.Second, ClearanceTTL: 900 * time.Second,
		Difficulty: MinDifficulty, MaxAttempts: 3,
		KeyRef:  "not-provisioned",
		Keyring: kr, Store: NewStore(newFakeBotValkey(), ""),
		Limiter: &fakeLimiter{denyKeys: map[string]bool{}, failKeys: map[string]bool{}},
	})
	if err == nil || !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("unknown key_ref must fail closed: %v", err)
	}
	sink := &captureSink{}
	svc, _ := newTestService(t, nil, nil, sink, testServiceOpts{keyring: kr, keyRef: "bot-key-old"})
	o := doOffer(t, svc, "shop.example.com", "203.0.113.7")
	if rec := doVerify(t, svc, o, solveFor(t, svc, o), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("verify: %d", rec.Code)
	}
	evs := sink.byType(events.BotVerifySuccess)
	if len(evs) != 1 || evs[0].Bot.KeyID != "bot-key-old" {
		t.Fatalf("key_id in event: %+v", evs)
	}
	// 该 clearance 必须由 key_ref 指定的旧密钥可验
	if _, ok := kr.Lookup("bot-key-old"); !ok {
		t.Fatal("old key must remain in allow list")
	}
}

// Config.Validate 边界（fail-closed；不信任调用方已校验）。
func TestConfigValidate(t *testing.T) {
	kr := testKeyring(t, "k1")
	base := func() Config {
		return Config{
			AppID: "app-1", Mode: ModeProtect, PolicyVersion: 1,
			NonceTTL: 90 * time.Second, ClearanceTTL: 900 * time.Second,
			Difficulty: 14, MaxAttempts: 3,
			Keyring: kr, Store: NewStore(newFakeBotValkey(), ""),
			Limiter: &fakeLimiter{denyKeys: map[string]bool{}, failKeys: map[string]bool{}},
		}
	}
	if _, err := NewService(base()); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	bad := []func(*Config){
		func(c *Config) { c.Mode = "OFF" },
		func(c *Config) { c.Mode = "X" },
		func(c *Config) { c.NonceTTL = 29 * time.Second },
		func(c *Config) { c.NonceTTL = 301 * time.Second },
		func(c *Config) { c.ClearanceTTL = 59 * time.Second },
		func(c *Config) { c.ClearanceTTL = 3601 * time.Second },
		func(c *Config) { c.Difficulty = 9 },
		func(c *Config) { c.Difficulty = 19 },
		func(c *Config) { c.MaxAttempts = 0 },
		func(c *Config) { c.MaxAttempts = 6 },
		func(c *Config) { c.PolicyVersion = 0 },
		func(c *Config) { c.AppID = "" },
		func(c *Config) { c.Keyring = nil },
		func(c *Config) { c.Store = nil },
		func(c *Config) { c.Limiter = nil },
		func(c *Config) { c.KeyRef = "../etc/keys" },
	}
	for i, mut := range bad {
		c := base()
		mut(&c)
		if _, err := NewService(c); err == nil {
			t.Errorf("bad config %d must be rejected", i)
		}
	}
}

// clearance 生命周期：过期 / 伪造签名 / 未知 key_id / 跨 Host / 跨应用 /
// 策略代次撤销 / 缺会话。
func TestClearanceLifecycle(t *testing.T) {
	fk := newFakeBotValkey()
	kr := testKeyring(t, "bot-key-a")
	sink := &captureSink{}
	svc, now := newTestService(t, fk, nil, sink, testServiceOpts{keyring: kr})
	host := "shop.example.com"
	pass := func() (*http.Cookie, *http.Cookie) {
		o := doOffer(t, svc, host, "203.0.113.7")
		rec := doVerify(t, svc, o, solveFor(t, svc, o), nil)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("verify: %d", rec.Code)
		}
		var cl *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if c.Name == ClearanceCookieName {
				cl = c
			}
		}
		return o.sessionC, cl
	}
	sess, clearance := pass()
	mkReq := func(hostIn string, withSess bool, cl *http.Cookie) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://"+hostIn+"/products", nil)
		r.Host = hostIn
		if withSess {
			r.AddCookie(sess)
		}
		if cl != nil {
			r.AddCookie(cl)
		}
		return r
	}
	cc := CallContext{RequestID: "r-x", ClientIP: "203.0.113.7"}

	// 无 clearance → ErrClearanceMissing（静默，无事件）
	if _, err := svc.ValidateClearance(mkReq(host, true, nil), cc); !errors.Is(err, ErrClearanceMissing) {
		t.Fatalf("missing: %v", err)
	}
	// 合法 → 通过
	if _, err := svc.ValidateClearance(mkReq(host, true, clearance), cc); err != nil {
		t.Fatalf("valid: %v", err)
	}
	// 过期 → ErrClearanceExpired + expired 事件
	*now = now.Add(16 * time.Minute)
	if _, err := svc.ValidateClearance(mkReq(host, true, clearance), cc); !errors.Is(err, ErrClearanceExpired) {
		t.Fatalf("expired: %v", err)
	}
	*now = now.Add(-16 * time.Minute) // 回拨时钟
	// 伪造签名 → Invalid
	forged := &http.Cookie{Name: ClearanceCookieName, Value: clearance.Value[:len(clearance.Value)-2] + "00"}
	if _, err := svc.ValidateClearance(mkReq(host, true, forged), cc); !errors.Is(err, ErrClearanceInvalid) {
		t.Fatalf("forged: %v", err)
	}
	// 未知 key_id → Invalid
	otherKr := testKeyring(t, "k-unknown")
	rawOther, err := signToken(mustLookup(t, otherKr, "k-unknown"), purposeClearance, clearancePayload{
		V: 1, App: "app-1", Hh: "x", Sd: "y", Ep: 7, Iat: now.Unix(), Exp: now.Add(time.Hour).Unix(), Kid: "k-unknown",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ValidateClearance(mkReq(host, true, &http.Cookie{Name: ClearanceCookieName, Value: rawOther}), cc); !errors.Is(err, ErrClearanceInvalid) {
		t.Fatalf("unknown key_id: %v", err)
	}
	// 跨 Host → Invalid
	if _, err := svc.ValidateClearance(mkReq("other.example.com", true, clearance), cc); !errors.Is(err, ErrClearanceInvalid) {
		t.Fatalf("cross host: %v", err)
	}
	// 缺会话 Cookie → Invalid（通行绑定会话）
	if _, err := svc.ValidateClearance(mkReq(host, false, clearance), cc); !errors.Is(err, ErrClearanceInvalid) {
		t.Fatalf("session-less clearance: %v", err)
	}
	// 跨应用：另一应用 Service 不接受本通行 → Invalid
	svcB, _ := newTestService(t, fk, nil, nil, testServiceOpts{keyring: kr, appID: "app-2"})
	if _, err := svcB.ValidateClearance(mkReq(host, true, clearance), cc); !errors.Is(err, ErrClearanceInvalid) {
		t.Fatalf("cross app: %v", err)
	}
	// 策略代次撤销：PolicyVersion+1 后旧通行 → ErrClearanceRevoked
	svcRev, _ := newTestService(t, fk, nil, nil, testServiceOpts{keyring: kr, version: 8})
	if _, err := svcRev.ValidateClearance(mkReq(host, true, clearance), cc); !errors.Is(err, ErrClearanceRevoked) {
		t.Fatalf("epoch revoked: %v", err)
	}
}

// 密钥轮换下的通行：旧 key 签发 → 轮换后（旧 key 在窗口）仍可验；
// 旧 key 移出窗口 → 不可验。
func TestClearanceRotation(t *testing.T) {
	fk := newFakeBotValkey()
	krV1 := testKeyring(t, "key-v1")
	svc1, _ := newTestService(t, fk, nil, nil, testServiceOpts{keyring: krV1})
	host := "shop.example.com"
	o := doOffer(t, svc1, host, "203.0.113.7")
	rec := doVerify(t, svc1, o, solveFor(t, svc1, o), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("verify: %d", rec.Code)
	}
	var clearance *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == ClearanceCookieName {
			clearance = c
		}
	}
	mkReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://"+host+"/products", nil)
		r.Host = host
		r.AddCookie(o.sessionC)
		r.AddCookie(clearance)
		return r
	}
	cc := CallContext{RequestID: "r-r", ClientIP: "203.0.113.7"}
	// 轮换：key-v2 为当前，key-v1 保留验签窗口
	krV2 := testKeyring(t, "key-v2", "key-v1")
	svc2, _ := newTestService(t, fk, nil, nil, testServiceOpts{keyring: krV2})
	if _, err := svc2.ValidateClearance(mkReq(), cc); err != nil {
		t.Fatalf("rotated (old key in window) must verify: %v", err)
	}
	// 旧 key 移出 → 拒绝
	krV3 := testKeyring(t, "key-v2")
	svc3, _ := newTestService(t, fk, nil, nil, testServiceOpts{keyring: krV3})
	if _, err := svc3.ValidateClearance(mkReq(), cc); !errors.Is(err, ErrClearanceInvalid) {
		t.Fatalf("removed key must not verify: %v", err)
	}
	// 新服务签发的通行用新 key_id
	o2 := doOffer(t, svc2, host, "203.0.113.8")
	rec2 := doVerify(t, svc2, o2, solveFor(t, svc2, o2), nil)
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("verify after rotation: %d", rec2.Code)
	}
	for _, c := range rec2.Result().Cookies() {
		if c.Name == ClearanceCookieName {
			parts := splitToken(c.Value)
			if parts == nil {
				t.Fatal("clearance format")
			}
			var p clearancePayload
			if err := decodePayload(parts[1], &p); err != nil {
				t.Fatal(err)
			}
			if p.Kid != "key-v2" {
				t.Fatalf("new clearance must use current key: %q", p.Kid)
			}
		}
	}
}

// 事件脱敏断言：构造含敏感标记的完整流程，断言全部事件 JSON 不泄漏
// nonce/solution/通行 Cookie/会话 Cookie/签名材料。
func TestEventRedaction(t *testing.T) {
	fk := newFakeBotValkey()
	kr := testKeyring(t, "bot-key-a")
	sink := &captureSink{}
	svc, _ := newTestService(t, fk, nil, sink, testServiceOpts{keyring: kr})
	host := "shop.example.com"
	o := doOffer(t, svc, host, "203.0.113.7")
	sol := solveFor(t, svc, o)
	rec := doVerify(t, svc, o, sol, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("verify: %d", rec.Code)
	}
	var clearance *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == ClearanceCookieName {
			clearance = c
		}
	}
	r2 := httptest.NewRequest(http.MethodGet, "https://"+host+"/products", nil)
	r2.Host = host
	r2.AddCookie(o.sessionC)
	r2.AddCookie(clearance)
	if _, err := svc.ValidateClearance(r2, CallContext{RequestID: "r-3", ClientIP: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) == 0 {
		t.Fatal("events expected")
	}
	secrets := []string{
		o.params.Nonce,                      // nonce
		o.sessionC.Value,                    // 会话 Cookie
		clearance.Value,                     // 通行 Cookie
		"test-secret-material-bot-key-a",    // 签名材料
		sessionDigest(mustSessionSid(t, o)), // 会话摘要也不应出现
	}
	for _, e := range sink.events {
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range secrets {
			if s != "" && strings.Contains(string(raw), s) {
				t.Fatalf("event leaks secret material (%s…): %s", s[:min(len(s), 12)], raw)
			}
		}
		// solution 不落事件（无 solution/nonce 键；短数字值无法可靠 contains 断言，按键名判定）
		if strings.Contains(string(raw), `"solution"`) || strings.Contains(string(raw), `"nonce"`) {
			t.Fatalf("event must not carry solution/nonce fields: %s", raw)
		}
		// flow_id 为脱敏指纹（≠ challenge_id）
		if e.Bot != nil && e.Bot.FlowID == o.params.ChallengeID {
			t.Fatalf("flow_id must be redacted fingerprint, not raw challenge id")
		}
	}
}

func mustSessionSid(t *testing.T, o offerResult) string {
	t.Helper()
	parts := splitToken(o.sessionC.Value)
	if parts == nil {
		t.Fatal("session token format")
	}
	var p sessionPayload
	if err := decodePayload(parts[1], &p); err != nil {
		t.Fatal(err)
	}
	return p.Sid
}
