package detectors

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
)

// resetWebShellC2TrackerForTest 重置包级默认会话追踪器（防用例间污染）。
func resetWebShellC2TrackerForTest() {
	defaultWebShellC2Tracker = newWebShellC2Tracker(webShellC2MaxKeys)
}

// xorshift 确定性伪随机字节源（仅测试数据生成，非安全用途）。
type xorshift struct{ s uint32 }

func (x *xorshift) bytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		x.s ^= x.s << 13
		x.s ^= x.s >> 17
		x.s ^= x.s << 5
		out[i] = byte(x.s)
	}
	return out
}

// c2Base64Blob 确定性高熵 base64 串（模拟 AES 密文的 base64 形态，长度 ≈ 4n/3）。
func c2Base64Blob(n int) string {
	x := &xorshift{s: 0x9e3779b9}
	return base64.StdEncoding.EncodeToString(x.bytes(n))
}

// c2Post 构造带固定 UA 的 POST 请求（httptest 对 strings.Reader 自动设置 ContentLength）。
func c2Post(t *testing.T, uri, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, uri, strings.NewReader(body))
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	return r
}

// 命中：四组弱特征全部满足的会话，第 5 个样本起产出 webshell.c2_suspected；
// 且该信号在 PROTECT 模式下也只落到 OBSERVE（绝不单独定案阻断）。
func TestWebShellC2_SuspectedSessionFires(t *testing.T) {
	resetWebShellC2TrackerForTest()
	const identity, uri = "ip:10.9.0.1", "/upload/shell.jsp"
	body := c2Base64Blob(512)         // 定长、高熵、全 base64 字符集
	resp := []byte(c2Base64Blob(256)) // 定长、高熵、无 HTML 标签
	var last *dsctx.RequestContext
	for i := 1; i <= 5; i++ {
		r := c2Post(t, uri, body)
		ObserveWebShellC2Request(r, identity, uri, []byte(body))
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckWebShellC2Response(ctx, r, identity, uri, resp, int64(len(resp)))
		if i < webShellC2MinSamples && ctx.MatchCount() != 0 {
			t.Fatalf("round %d below min samples must not fire: %+v", i, ctx.CopyMatches())
		}
		last = ctx
	}
	m := findMatch(last, "webshell.c2_suspected")
	if m == nil {
		t.Fatalf("full c2 profile must fire, got %+v", last.CopyMatches())
	}
	if m.Detector != "webshell" || m.Category != "OBSERVE" || m.Severity != "MEDIUM" || m.ScoreDelta != 20 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Confidence != 0.5 {
		t.Fatalf("bad confidence: %+v", m.Confidence)
	}
	if m.Evidence["signals"] != "body_profile,size_stability,header_profile,response_profile" ||
		m.Evidence["signal_count"] != "4" {
		t.Fatalf("bad signals evidence: %+v", m.Evidence)
	}
	if m.Evidence["session_samples"] != "5" ||
		m.Evidence["encrypted_req_ratio"] != "100%" || m.Evidence["encrypted_resp_ratio"] != "100%" {
		t.Fatalf("bad stats evidence: %+v", m.Evidence)
	}
	if m.Evidence["req_cv"] != "0.000" || m.Evidence["resp_cv"] != "0.000" {
		t.Fatalf("constant sizes must give zero cv: %+v", m.Evidence)
	}
	// 绝不单独定案：检测器不触碰 FinalAction；PROTECT 模式决策也只落到 OBSERVE。
	if last.GetFinalAction() != dsctx.ActionUnset {
		t.Fatalf("detector must not finalize, got %s", last.GetFinalAction())
	}
	if act := decision.Decide(last, decision.Input{Mode: decision.ModeProtect}); act != dsctx.ActionObserve {
		t.Fatalf("webshell.c2_suspected must stay OBSERVE even in PROTECT, got %s", act)
	}
}

// 不命中（边界）：会话样本数不足 webShellC2MinSamples 时，形态再典型也不报。
func TestWebShellC2_InsufficientSamplesNoFire(t *testing.T) {
	resetWebShellC2TrackerForTest()
	const identity, uri = "ip:10.9.0.2", "/upload/s.jsp"
	body := c2Base64Blob(512)
	resp := []byte(c2Base64Blob(256))
	for i := 0; i < webShellC2MinSamples-1; i++ {
		r := c2Post(t, uri, body)
		ObserveWebShellC2Request(r, identity, uri, []byte(body))
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckWebShellC2Response(ctx, r, identity, uri, resp, int64(len(resp)))
		if ctx.MatchCount() != 0 {
			t.Fatalf("below min samples must not fire: %+v", ctx.CopyMatches())
		}
	}
}

// 不命中（误报纪律）：常规 API 轮询画像（定长明文 JSON 请求/响应、无 Cookie/Referer、
// UA 恒定）只命中 size_stability+header_profile 两组弱特征，达不到 3 项门槛。
func TestWebShellC2_APIPollingProfileNoFire(t *testing.T) {
	resetWebShellC2TrackerForTest()
	const identity, uri = "key:abc123", "/api/v1/metrics"
	body := `{"window":"1m","metrics":["cpu","mem","disk"],"labels":["host","region"]}` // 定长明文 JSON
	resp := []byte(`{"cpu":0.42,"mem":0.71,"disk":0.33,"host":"edge-01"}`)              // 低熵明文 JSON 响应
	for i := 0; i < 8; i++ {
		r := c2Post(t, uri, body)
		ObserveWebShellC2Request(r, identity, uri, []byte(body))
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckWebShellC2Response(ctx, r, identity, uri, resp, int64(len(resp)))
		if ctx.MatchCount() != 0 {
			t.Fatalf("only size_stability+header_profile (2 signals) must not fire: %+v", ctx.CopyMatches())
		}
	}
}

// 命中（弱依赖③）：会话携带 Cookie/Referer（冰蝎/哥斯拉会回放服务端种下的会话 Cookie）
// 时 header_profile 不命中，但 body/size/response 三组仍凑满门槛产出。
func TestWebShellC2_CookieSessionStillFires(t *testing.T) {
	resetWebShellC2TrackerForTest()
	const identity, uri = "sess:f00d", "/upload/shell.jsp"
	body := c2Base64Blob(512)
	resp := []byte(c2Base64Blob(256))
	for i := 0; i < 6; i++ {
		r := c2Post(t, uri, body)
		r.Header.Set("Cookie", "JSESSIONID=0ABC123DEF")
		r.Header.Set("Referer", "https://www.example.com/upload")
		ObserveWebShellC2Request(r, identity, uri, []byte(body))
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckWebShellC2Response(ctx, r, identity, uri, resp, int64(len(resp)))
		if i < webShellC2MinSamples-1 && ctx.MatchCount() != 0 {
			t.Fatalf("round %d must not fire yet: %+v", i, ctx.CopyMatches())
		}
		if i == 5 {
			m := findMatch(ctx, "webshell.c2_suspected")
			if m == nil {
				t.Fatalf("body/size/response 3 signals must fire despite cookie: %+v", ctx.CopyMatches())
			}
			if m.Evidence["signals"] != "body_profile,size_stability,response_profile" {
				t.Fatalf("header_profile must be absent with cookie+referer: %+v", m.Evidence)
			}
		}
	}
}

// 边界（②的门槛作用）：①不命中（明文 JSON 体）时，②③④ 凑满 3 项仍产出；
// 响应长度大幅抖动把 size_stability 打掉后只剩 ③④ 两组，不报。
func TestWebShellC2_SizeStabilityTipsSignalCount(t *testing.T) {
	t.Run("stable sizes fire", func(t *testing.T) {
		resetWebShellC2TrackerForTest()
		const identity, uri = "ip:10.9.1.1", "/upload/x.jsp"
		body := `{"op":"read","path":"/etc/hosts","args":["-a","--long"]}` // 明文：①不命中
		resp := []byte(c2Base64Blob(200))                                  // 定长加密块响应：④命中
		for i := 0; i < 6; i++ {
			r := c2Post(t, uri, body)
			ObserveWebShellC2Request(r, identity, uri, []byte(body))
			ctx := dsctx.New("t", dsctx.DefaultParseLimits())
			CheckWebShellC2Response(ctx, r, identity, uri, resp, int64(len(resp)))
			if i < webShellC2MinSamples-1 && ctx.MatchCount() != 0 {
				t.Fatalf("round %d must not fire yet: %+v", i, ctx.CopyMatches())
			}
			if i == 5 {
				m := findMatch(ctx, "webshell.c2_suspected")
				if m == nil || m.Evidence["signals"] != "size_stability,header_profile,response_profile" {
					t.Fatalf("signals ②③④ must fire: %+v", ctx.CopyMatches())
				}
			}
		}
	})
	t.Run("jittered sizes suppress", func(t *testing.T) {
		resetWebShellC2TrackerForTest()
		const identity, uri = "ip:10.9.1.2", "/upload/x.jsp"
		body := `{"op":"read","path":"/etc/hosts","args":["-a","--long"]}`
		for i := 0; i < 6; i++ {
			r := c2Post(t, uri, body)
			ObserveWebShellC2Request(r, identity, uri, []byte(body))
			resp := []byte(c2Base64Blob(80 + i*160)) // 响应长度逐轮大增：②不命中
			ctx := dsctx.New("t", dsctx.DefaultParseLimits())
			CheckWebShellC2Response(ctx, r, identity, uri, resp, int64(len(resp)))
			if ctx.MatchCount() != 0 {
				t.Fatalf("only header_profile+response_profile (2 signals) must not fire: %+v", ctx.CopyMatches())
			}
		}
	})
}

// 边界（③的轮换判定）：UA 族逐轮轮换时 header_profile 不命中（distinct 族数 >1），
// ①②④ 仍凑满门槛产出；distinct 族数证据按上限封顶。
func TestWebShellC2_UARotationSuppressesHeaderProfile(t *testing.T) {
	resetWebShellC2TrackerForTest()
	const identity, uri = "ip:10.9.6.1", "/upload/shell.jsp"
	body := c2Base64Blob(512)
	resp := []byte(c2Base64Blob(256))
	// 覆盖全部 5 个 UA 族（script/browser/bot/empty/other）：distinct 数超上限封顶 4
	uas := []string{"curl/7.88.1", "Mozilla/5.0 Firefox/120.0", "Googlebot/2.1 (+http://google.com/bot.html)", "", "weird-agent-x"}
	for i := 0; i < 6; i++ {
		r := c2Post(t, uri, body)
		r.Header.Set("User-Agent", uas[i%len(uas)])
		ObserveWebShellC2Request(r, identity, uri, []byte(body))
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckWebShellC2Response(ctx, r, identity, uri, resp, int64(len(resp)))
		if i == 5 {
			m := findMatch(ctx, "webshell.c2_suspected")
			if m == nil {
				t.Fatalf("signals ①②④ must still fire: %+v", ctx.CopyMatches())
			}
			if m.Evidence["signals"] != "body_profile,size_stability,response_profile" {
				t.Fatalf("header_profile must be suppressed by UA rotation: %+v", m.Evidence)
			}
			if m.Evidence["ua_families"] != "4" {
				t.Fatalf("ua families must be capped at 4: %+v", m.Evidence)
			}
		}
	}
}

// 门槛：非 POST 请求两侧均不记账（重复 POST 会话才是检测对象），永不产出。
func TestWebShellC2_NonPOSTNotTracked(t *testing.T) {
	resetWebShellC2TrackerForTest()
	const identity, uri = "ip:10.9.2.1", "/upload/shell.jsp"
	body := c2Base64Blob(512)
	resp := []byte(c2Base64Blob(256))
	for i := 0; i < 8; i++ {
		r := httptest.NewRequest(http.MethodGet, uri, nil)
		r.Header.Set("User-Agent", "Mozilla/5.0")
		ObserveWebShellC2Request(r, identity, uri, []byte(body))
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckWebShellC2Response(ctx, r, identity, uri, resp, int64(len(resp)))
		if ctx.MatchCount() != 0 {
			t.Fatalf("non-POST must never fire: %+v", ctx.CopyMatches())
		}
	}
	if _, ok := defaultWebShellC2Tracker.entries.get(identity + "|" + uri); ok {
		t.Fatal("non-POST session must not be tracked")
	}
}

// 隔离：不同 identity 的会话统计互不污染（另一 identity 无历史，形态相同也不报）。
func TestWebShellC2_IdentityIsolation(t *testing.T) {
	resetWebShellC2TrackerForTest()
	const uri = "/upload/shell.jsp"
	body := c2Base64Blob(512)
	resp := []byte(c2Base64Blob(256))
	for i := 0; i < 6; i++ {
		r := c2Post(t, uri, body)
		ObserveWebShellC2Request(r, "ip:10.9.3.1", uri, []byte(body))
		CheckWebShellC2Response(dsctx.New("t", dsctx.DefaultParseLimits()), r, "ip:10.9.3.1", uri, resp, int64(len(resp)))
	}
	r := c2Post(t, uri, body)
	ObserveWebShellC2Request(r, "ip:10.9.3.2", uri, []byte(body))
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckWebShellC2Response(ctx, r, "ip:10.9.3.2", uri, resp, int64(len(resp)))
	if ctx.MatchCount() != 0 {
		t.Fatalf("other identity must not inherit session stats: %+v", ctx.CopyMatches())
	}
}

// 防御：空参数/nil 全部为空操作（不记账、不产出、不 panic）。
func TestWebShellC2_EmptyParamsNoop(t *testing.T) {
	resetWebShellC2TrackerForTest()
	r := c2Post(t, "/upload/x.jsp", c2Base64Blob(128))
	ObserveWebShellC2Request(nil, "ip:10.9.4.1", "/upload/x.jsp", nil)
	ObserveWebShellC2Request(r, "", "/upload/x.jsp", nil)
	ObserveWebShellC2Request(r, "ip:10.9.4.1", "", nil)
	CheckWebShellC2Response(nil, r, "ip:10.9.4.1", "/upload/x.jsp", nil, 0)
	CheckWebShellC2Response(dsctx.New("t", dsctx.DefaultParseLimits()), nil, "ip:10.9.4.1", "/upload/x.jsp", nil, 0)
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckWebShellC2Response(ctx, r, "", "", nil, 0)
	if ctx.MatchCount() != 0 {
		t.Fatalf("empty params must be noop: %+v", ctx.CopyMatches())
	}
}

// 体形态边界（①④的双门槛）：长度下限、熵阈值、字符集占比、HTML 标签排除。
func TestWebShellC2_BodyProfileBoundaries(t *testing.T) {
	// 请求侧：高熵 + base64 字符集双门槛
	if !encryptedWebShellC2Body([]byte(c2Base64Blob(512))) {
		t.Fatal("base64 ciphertext body must match encrypted profile")
	}
	if encryptedWebShellC2Body([]byte(c2Base64Blob(8))) {
		t.Fatal("sample below min length must not match")
	}
	plain := strings.Repeat("the quick brown fox jumps over the lazy dog. ", 8)
	if encryptedWebShellC2Body([]byte(plain)) {
		t.Fatal("plain english text must not match (low entropy)")
	}
	jsonBody := `{"username":"admin","password":"123456","action":"login","remember":true}`
	if encryptedWebShellC2Body([]byte(jsonBody)) {
		t.Fatal("json body must not match (charset ratio below threshold)")
	}
	// 响应侧：高熵 + 无 HTML 标签双门槛（熵阈值高于请求侧，压 JSON 误判）
	if !encryptedWebShellC2Resp([]byte(c2Base64Blob(256))) {
		t.Fatal("base64 ciphertext response must match encrypted profile")
	}
	html := `<!DOCTYPE html><html><head><title>ok</title></head><body><div class="x">done</div><script>var a=1;</script></body></html>`
	if encryptedWebShellC2Resp([]byte(html)) {
		t.Fatal("html page must not match (tag signature)")
	}
	if encryptedWebShellC2Resp([]byte(`{"cpu":0.42,"mem":0.71,"disk":0.33}`)) {
		t.Fatal("plain json response must not match (entropy below response threshold)")
	}
}

// 统计原语：熵/字符集占比/标签计数的确定性行为。
func TestWebShellC2_EntropyCharsetTagHelpers(t *testing.T) {
	if got := shannonEntropyBits(nil); got != 0 {
		t.Fatalf("empty sample entropy must be 0, got %v", got)
	}
	if got := shannonEntropyBits([]byte("aaaaaaaaaaaaaaaa")); got != 0 {
		t.Fatalf("single-symbol entropy must be 0, got %v", got)
	}
	if got := shannonEntropyBits([]byte(c2Base64Blob(512))); got < 5.5 {
		t.Fatalf("base64 of random bytes entropy must be high, got %v", got)
	}
	if got := base64CharsetRatio([]byte("aGVsbG8=")); got != 1 {
		t.Fatalf("pure base64 ratio must be 1, got %v", got)
	}
	if got := base64CharsetRatio(nil); got != 0 {
		t.Fatalf("empty sample ratio must be 0, got %v", got)
	}
	if got := base64CharsetRatio([]byte("ab{}cd{}")); got != 0.5 {
		t.Fatalf("half-charset ratio must be 0.5, got %v", got)
	}
	if got := htmlTagCount([]byte(`<div><!DOCTYPE html><span>x</span>`)); got != 3 {
		t.Fatalf("tag count must be 3, got %d", got)
	}
	if got := htmlTagCount([]byte(c2Base64Blob(256))); got != 0 {
		t.Fatalf("base64 must have zero tags, got %d", got)
	}
}

// 存储可插拔：注入 WebShellC2Session 后请求/响应两侧记账走注入实现，
// 评估基于注入快照产出；默认内存追踪器零触碰。
func TestWebShellC2_StoreOverrideRouted(t *testing.T) {
	resetWebShellC2TrackerForTest()
	fake := &fakeWebShellC2SessionStore{stats: WebShellC2SessionStats{
		ReqCount: 6, ReqSizeSum: 6 * 700, ReqSizeSumSq: 6 * 700 * 700, EncryptedReqs: 6,
		UAFamilies: 1,
		RespCount:  6, RespSizeSum: 6 * 300, RespSizeSumSq: 6 * 300 * 300, EncryptedResps: 6,
	}}
	stores := &StoreOverrides{WebShellC2Session: fake}
	const identity, uri = "ip:10.9.5.1", "/upload/shell.jsp"
	r := c2Post(t, uri, c2Base64Blob(64))
	ObserveWebShellC2RequestWithStores(r, identity, uri, nil, stores)
	ctx := contextWithOverrides(stores)
	CheckWebShellC2Response(ctx, r, identity, uri, nil, 0)
	if len(fake.reqKeys) != 1 || fake.reqKeys[0] != identity+"|"+uri {
		t.Fatalf("request override not used: %v", fake.reqKeys)
	}
	if len(fake.respKeys) != 1 || fake.respKeys[0] != identity+"|"+uri {
		t.Fatalf("response override not used: %v", fake.respKeys)
	}
	m := findMatch(ctx, "webshell.c2_suspected")
	if m == nil || m.Evidence["signal_count"] != "4" {
		t.Fatalf("override stats must drive match: %+v", ctx.CopyMatches())
	}
	if _, ok := defaultWebShellC2Tracker.entries.get(identity + "|" + uri); ok {
		t.Fatal("default memory tracker must not be touched when override set")
	}
}

// fakeWebShellC2SessionStore 记录调用并返回预设快照（注入路由测试替身）。
type fakeWebShellC2SessionStore struct {
	reqKeys  []string
	respKeys []string
	stats    WebShellC2SessionStats
}

func (f *fakeWebShellC2SessionStore) ObserveRequest(key string, _ WebShellC2RequestStat) WebShellC2SessionStats {
	f.reqKeys = append(f.reqKeys, key)
	return f.stats
}

func (f *fakeWebShellC2SessionStore) ObserveResponse(key string, _ WebShellC2ResponseStat) WebShellC2SessionStats {
	f.respKeys = append(f.respKeys, key)
	return f.stats
}

// 追踪器 LRU 定容：超容量淘汰最久未用会话，存活会话累计不丢。
func TestWebShellC2_TrackerLRUEviction(t *testing.T) {
	tr := newWebShellC2Tracker(2)
	tr.ObserveRequest("a", WebShellC2RequestStat{Size: 10})
	tr.ObserveRequest("b", WebShellC2RequestStat{Size: 10})
	tr.ObserveRequest("c", WebShellC2RequestStat{Size: 10})
	if _, ok := tr.entries.get("a"); ok {
		t.Fatal("oldest session must be evicted at capacity")
	}
	s := tr.ObserveRequest("b", WebShellC2RequestStat{Size: 10, EncryptedProfile: true})
	if s.ReqCount != 2 || s.EncryptedReqs != 1 {
		t.Fatalf("surviving session must keep accumulations: %+v", s)
	}
}
