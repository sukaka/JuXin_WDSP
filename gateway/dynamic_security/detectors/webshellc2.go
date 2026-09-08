// webshellc2.go 加密 WebShell C&C 会话行为检测（BAS 覆盖基线：冰蝎/哥斯拉/蚁剑 AES
// 加密通信重放缺口——密文无固定特征，特征规则无解，需在行为层补 OBSERVE 信号）。
//
// 合规说明：本检测逻辑为依据公开漏洞知识（公开的冰蝎/哥斯拉/蚁剑加密通信行为分析）
// 自行设计的统计启发式，不引用任何第三方 WAF 产品的规则文本、阈值或界面文案。
//
// 会话维度：identity（TrackingKey 输出，凭据指纹优先、无凭据回退 IP）+ URI 的重复 POST。
// 四组弱特征（全部统计量，不落 body 明文）：
//
//	① body_profile      请求体高熵且 base64/url-safe 字符占比高（密文 base64 载荷形态）；
//	② size_stability    请求与响应长度各自高度一致（变异系数 CV 极低；加密心跳/轮询的定长块特征）；
//	③ header_profile    会话全程无 Cookie、无 Referer 且 UA 族无轮换（自动化客户端画像）；
//	④ response_profile  响应高熵且无 HTML 标签特征（加密块而非页面/文本）。
//
// 定案纪律：单项均为弱特征（API 轮询命中②③、二进制下载命中④、base64 上传命中①），
// 命中 ≥3 项才产一条 webshell.c2_suspected（OBSERVE/MEDIUM，ScoreDelta 20 < 50 定案线），
// 绝不单独定案阻断——decision 引擎对该明细只会落到 OBSERVE（见 engine.go 类别/严重度分支）。
//
// 挂点建议（由装配集成侧接线，本文件不改 pipeline/挂点等共享文件）：
//   - 请求相位拿到请求体样本后调 ObserveWebShellC2Request（样本仅请求内存活，截断 4 KiB；
//     parser 之后 r.Body 已消费，样本须由挂点侧在读体处供给）；
//   - 响应收束处调 CheckWebShellC2Response（不挂 api.IsAPI 分类门槛：WebShell 端点通常
//     非 API 分类，分类漏判不应关掉观测）；
//   - identity 用 TrackingKey(r, salt)；uri 建议与 endpoint_key 同源的归一化路径。
//
// 状态与单节点限制：会话统计为累计型（跨窗口聚合，LRU 定容淘汰；与 hourHist/uaFamily
// 追踪器同为累计型，故无窗口滚动），复用 window.go 的 LRU 与互斥构造纪律；存储可插拔
// （store.go WebShellC2SessionStore），默认进程内存——多网关部署时各节点独立累计，
// 不共享会话基线；配置重载不重置，进程重启清零。
//
// 已知局限（诚实声明，误报纪律优先、宁可漏报）：原始二进制密文（未 base64 包裹）同时
// 命中不了①的字符集判定与④的标签判定，只剩②③达不到 3 项门槛，本期不覆盖该形态。
package detectors

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

const (
	// webShellC2MaxKeys 会话统计 LRU 容量上限（与 behavior/envanomaly 同一纪律）。
	webShellC2MaxKeys = 10000
	// webShellC2MinSamples 判定所需最少会话请求样本数（不足不判，与 behaviorMinHistory 同纪律）。
	webShellC2MinSamples = 5
	// webShellC2MinSignals 产出信号所需最少命中特征组数（弱特征叠加纪律：单项/双项不报）。
	webShellC2MinSignals = 3
	// webShellC2MaxBodySample 体统计样本上限（熵/字符集/标签只算前缀，防大报文开销）。
	webShellC2MaxBodySample = 4096
	// webShellC2MinBodyForStats 参与熵/字符集统计的最小体长（样本过短统计无意义）。
	webShellC2MinBodyForStats = 32
	// webShellC2ReqEntropyBits 请求体高熵阈值（Shannon bits/byte；base64 载荷实测 ~5.5-6.0，
	// 普通英文文本 ~4.0-4.5，取 4.7 给 base64 包裹低熵明文留裕量）。
	webShellC2ReqEntropyBits = 4.7
	// webShellC2RespEntropyBits 响应高熵阈值（高于请求侧：密集 JSON 响应可达 4.7-4.9，
	// base64 密文响应 ≥5.5，取 5.0 压低 JSON API 响应误判）。
	webShellC2RespEntropyBits = 5.0
	// webShellC2CharsetRatio base64/url-safe 字符（A-Za-z0-9 与 +/=_-）占比阈值。
	webShellC2CharsetRatio = 0.85
	// webShellC2SizeCVMax 长度变异系数上限（stddev/mean；请求与响应同阈值）。
	webShellC2SizeCVMax = 0.15
	// webShellC2SizeMeanMin 长度均值下限（字节）：排除空响应门/健康检查类恒定小体。
	webShellC2SizeMeanMin = 8
	// webShellC2EncryptedRatio 加密特征请求/响应占比阈值。
	webShellC2EncryptedRatio = 0.8
	// webShellC2MaxUAFamilies 会话 distinct UA 族集合上限（防脏数据放大，已远超判定需要）。
	webShellC2MaxUAFamilies = 4
	// webShellC2MaxCountedSamples 单会话计数样本封顶（配合长度钳制保证平方和不溢出 int64）。
	webShellC2MaxCountedSamples = 10000
	// webShellC2MaxStatSize 参与长度统计的单体字节数钳制上限（16 MiB：
	// (2^24)²×10000 ≈ 2.8e18 < int64 上限 9.2e18；超大下载钳为定长只会抬高方差，方向保守）。
	webShellC2MaxStatSize = 16 << 20
)

// WebShellC2RequestStat 单次请求侧会话观测（仅统计量，不含任何明文）。
type WebShellC2RequestStat struct {
	Size             int64  // 请求体字节数（Content-Length，缺失时为样本长）
	EncryptedProfile bool   // 体高熵且 base64/url-safe 字符占比达标
	HasCookie        bool   // 携带 Cookie 头
	HasReferer       bool   // 携带 Referer 头
	UAFamily         string // 粗粒度 UA 族（uaFamily 输出，不落完整 UA）
}

// WebShellC2ResponseStat 单次响应侧会话观测（仅统计量，不含任何明文）。
type WebShellC2ResponseStat struct {
	Size             int64 // 响应体字节数（实际传输，缺失时为样本长）
	EncryptedProfile bool  // 高熵且无 HTML 标签特征
}

// WebShellC2SessionStats 会话累计统计快照（评估输入；存储实现须按同一口径累计：
// 计数/和/平方和直接累加，布尔粘性置真，UA 族 distinct 计数封顶 webShellC2MaxUAFamilies；
// 单值经 16 MiB 钳制、单会话计数封顶 10000 后 int64 不溢出）。
type WebShellC2SessionStats struct {
	ReqCount       int
	ReqSizeSum     int64
	ReqSizeSumSq   int64
	EncryptedReqs  int
	CookieSeen     bool
	RefererSeen    bool
	UAFamilies     int // distinct UA 族数（封顶 webShellC2MaxUAFamilies）
	RespCount      int
	RespSizeSum    int64
	RespSizeSumSq  int64
	EncryptedResps int
}

// webShellC2Session 单会话累计状态（进程内存形态，与 WebShellC2SessionStats 同一口径）。
type webShellC2Session struct {
	reqCount       int
	reqSizeSum     int64
	reqSizeSumSq   int64
	encryptedReqs  int
	cookieSeen     bool
	refererSeen    bool
	uaFamilies     map[string]struct{}
	respCount      int
	respSizeSum    int64
	respSizeSumSq  int64
	encryptedResps int
}

// webShellC2Tracker 会话统计追踪器：复用 window.go 的 LRU 定容与互斥纪律
// （累计型，无窗口滚动——会话跨分钟聚合，滑窗会切碎会话形态）。
type webShellC2Tracker struct {
	mu      sync.Mutex
	entries *lru
}

func newWebShellC2Tracker(capacity int) *webShellC2Tracker {
	return &webShellC2Tracker{entries: newLRU(capacity)}
}

// defaultWebShellC2Tracker 包级默认会话统计追踪器。
var defaultWebShellC2Tracker = newWebShellC2Tracker(webShellC2MaxKeys)

func (t *webShellC2Tracker) entry(key string) *webShellC2Session {
	if v, ok := t.entries.get(key); ok {
		return v.(*webShellC2Session)
	}
	e := &webShellC2Session{uaFamilies: map[string]struct{}{}}
	t.entries.set(key, e)
	return e
}

// ObserveRequest 记录一次请求侧观测，返回更新后会话快照（实现 WebShellC2SessionStore）。
func (t *webShellC2Tracker) ObserveRequest(key string, o WebShellC2RequestStat) WebShellC2SessionStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entry(key)
	if e.reqCount < webShellC2MaxCountedSamples {
		e.reqCount++
		sz := clampWebShellC2Size(o.Size)
		e.reqSizeSum += sz
		e.reqSizeSumSq += sz * sz
		if o.EncryptedProfile {
			e.encryptedReqs++
		}
		if o.HasCookie {
			e.cookieSeen = true
		}
		if o.HasReferer {
			e.refererSeen = true
		}
		if o.UAFamily != "" {
			if _, ok := e.uaFamilies[o.UAFamily]; !ok && len(e.uaFamilies) < webShellC2MaxUAFamilies {
				e.uaFamilies[o.UAFamily] = struct{}{}
			}
		}
	}
	return e.snapshot()
}

// ObserveResponse 记录一次响应侧观测，返回更新后会话快照（实现 WebShellC2SessionStore）。
func (t *webShellC2Tracker) ObserveResponse(key string, o WebShellC2ResponseStat) WebShellC2SessionStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entry(key)
	if e.respCount < webShellC2MaxCountedSamples {
		e.respCount++
		sz := clampWebShellC2Size(o.Size)
		e.respSizeSum += sz
		e.respSizeSumSq += sz * sz
		if o.EncryptedProfile {
			e.encryptedResps++
		}
	}
	return e.snapshot()
}

func (e *webShellC2Session) snapshot() WebShellC2SessionStats {
	return WebShellC2SessionStats{
		ReqCount:       e.reqCount,
		ReqSizeSum:     e.reqSizeSum,
		ReqSizeSumSq:   e.reqSizeSumSq,
		EncryptedReqs:  e.encryptedReqs,
		CookieSeen:     e.cookieSeen,
		RefererSeen:    e.refererSeen,
		UAFamilies:     len(e.uaFamilies),
		RespCount:      e.respCount,
		RespSizeSum:    e.respSizeSum,
		RespSizeSumSq:  e.respSizeSumSq,
		EncryptedResps: e.encryptedResps,
	}
}

// clampWebShellC2Size 长度统计值钳制（负值归零，超限钳到上限；见 webShellC2MaxStatSize）。
func clampWebShellC2Size(n int64) int64 {
	if n < 0 {
		return 0
	}
	if n > webShellC2MaxStatSize {
		return webShellC2MaxStatSize
	}
	return n
}

// ---------- 检测入口（请求侧只记账，响应侧记账+评估；两侧均只限 POST 会话） ----------

// ObserveWebShellC2Request 请求相位会话观测：仅 POST 参与；体样本仅用于统计（截断 4 KiB，
// 不落证据、不入事件）。本函数只记账，绝不产检测明细。
// bodySample 由挂点侧在读体处供给（parser 之后 r.Body 已消费；nil = 本请求无体统计，
// 仍参与长度/头画像累计）。
func ObserveWebShellC2Request(r *http.Request, identity, uri string, bodySample []byte) {
	observeWebShellC2Request(r, identity, uri, bodySample, nil, false)
}

// ObserveWebShellC2RequestWithStores 使用调用方 Guard 实例绑定的会话存储；stores=nil
// 明确走默认内存，避免配置重载后继承旧实例的进程级覆盖。
func ObserveWebShellC2RequestWithStores(r *http.Request, identity, uri string, bodySample []byte, stores *StoreOverrides) {
	observeWebShellC2Request(r, identity, uri, bodySample, stores, true)
}

func observeWebShellC2Request(r *http.Request, identity, uri string, bodySample []byte, stores *StoreOverrides, bound bool) {
	if r == nil || identity == "" || uri == "" {
		return
	}
	if r.Method != http.MethodPost {
		return
	}
	size := r.ContentLength
	if size < 0 {
		size = int64(len(bodySample))
	}
	stat := WebShellC2RequestStat{
		Size:             size,
		EncryptedProfile: encryptedWebShellC2Body(capWebShellC2Sample(bodySample)),
		HasCookie:        strings.TrimSpace(r.Header.Get("Cookie")) != "",
		HasReferer:       strings.TrimSpace(r.Header.Get("Referer")) != "",
		UAFamily:         uaFamily(r.Header.Get("User-Agent")),
	}
	if bound {
		webShellC2ObserveRequestWithStores(stores, identity+"|"+uri, stat)
		return
	}
	webShellC2ObserveRequest(identity+"|"+uri, stat)
}

// CheckWebShellC2Response 响应相位会话观测与评估：仅 POST 参与（与请求侧同一门槛；
// 挂点仅在请求侧已观测的会话调用本函数）。四组弱特征命中 ≥3 项产一条
// webshell.c2_suspected（OBSERVE/MEDIUM，只 AddMatch 不定案）。
// 证据只含统计特征（样本数/占比/变异系数/UA 族数），不落 body 明文、UA 原文与身份指纹。
func CheckWebShellC2Response(ctx *dsctx.RequestContext, r *http.Request, identity, uri string, respBodySample []byte, respBodySize int64) {
	if ctx == nil || r == nil || identity == "" || uri == "" {
		return
	}
	if r.Method != http.MethodPost {
		return
	}
	size := respBodySize
	if size <= 0 {
		size = int64(len(respBodySample))
	}
	stats := webShellC2ObserveResponse(ctx, identity+"|"+uri, WebShellC2ResponseStat{
		Size:             size,
		EncryptedProfile: encryptedWebShellC2Resp(capWebShellC2Sample(respBodySample)),
	})
	rep := evaluateWebShellC2(stats)
	if len(rep.fired) < webShellC2MinSignals {
		return
	}
	ev := map[string]string{
		"session_samples":      strconv.Itoa(stats.ReqCount),
		"signal_count":         strconv.Itoa(len(rep.fired)),
		"signals":              strings.Join(rep.fired, ","),
		"encrypted_req_ratio":  webShellC2RatioPercent(stats.EncryptedReqs, stats.ReqCount),
		"encrypted_resp_ratio": webShellC2RatioPercent(stats.EncryptedResps, stats.RespCount),
		"ua_families":          strconv.Itoa(stats.UAFamilies),
	}
	if rep.reqCV >= 0 {
		ev["req_cv"] = strconv.FormatFloat(rep.reqCV, 'f', 3, 64)
	}
	if rep.respCV >= 0 {
		ev["resp_cv"] = strconv.FormatFloat(rep.respCV, 'f', 3, 64)
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "webshell",
		RuleID:     "webshell.c2_suspected",
		Category:   "OBSERVE",
		Severity:   "MEDIUM",
		Message:    "encrypted webshell c&c session suspected (behavioral multi-signal heuristic)",
		Evidence:   ev,
		ScoreDelta: 20,  // < 50 定案线：decision 引擎对该明细只会落到 OBSERVE
		Confidence: 0.5, // 统计/行为推断，与 context 置信取值纪律一致（不高估）
	})
}

// ---------- 评估 ----------

// webShellC2Report 评估结果：命中特征组（固定序）与长度变异系数（<0 = 样本不足未计算）。
type webShellC2Report struct {
	fired  []string
	reqCV  float64
	respCV float64
}

// evaluateWebShellC2 四组弱特征判定（全部统计量）：
// 请求样本不足 webShellC2MinSamples 直接不判（基线未建立）；
// 响应样本不足时②④不判（保守，不凭空判）；特征组按固定序产出（事件可重现）。
func evaluateWebShellC2(s WebShellC2SessionStats) webShellC2Report {
	rep := webShellC2Report{reqCV: -1, respCV: -1}
	if s.ReqCount >= webShellC2MinSamples {
		rep.reqCV, _ = webShellC2SizeCV(s.ReqSizeSum, s.ReqSizeSumSq, s.ReqCount)
	}
	if s.RespCount >= webShellC2MinSamples {
		rep.respCV, _ = webShellC2SizeCV(s.RespSizeSum, s.RespSizeSumSq, s.RespCount)
	}
	if s.ReqCount < webShellC2MinSamples {
		return rep
	}
	// ① body_profile：加密特征请求占比达标
	if webShellC2RatioGE(s.EncryptedReqs, s.ReqCount, webShellC2EncryptedRatio) {
		rep.fired = append(rep.fired, "body_profile")
	}
	// ② size_stability：请求与响应长度变异系数同时极低（有一方抖动即不命中）
	if rep.reqCV >= 0 && rep.respCV >= 0 &&
		rep.reqCV <= webShellC2SizeCVMax && rep.respCV <= webShellC2SizeCVMax {
		rep.fired = append(rep.fired, "size_stability")
	}
	// ③ header_profile：全程无 Cookie、无 Referer 且 UA 族无轮换
	if !s.CookieSeen && !s.RefererSeen && s.UAFamilies <= 1 {
		rep.fired = append(rep.fired, "header_profile")
	}
	// ④ response_profile：加密块特征响应占比达标
	if s.RespCount >= webShellC2MinSamples &&
		webShellC2RatioGE(s.EncryptedResps, s.RespCount, webShellC2EncryptedRatio) {
		rep.fired = append(rep.fired, "response_profile")
	}
	return rep
}

// webShellC2SizeCV 长度变异系数（stddev/mean，总体口径）；样本为空或均值低于下限
// （空调门/健康检查类恒定小体无统计意义）时 ok=false。
func webShellC2SizeCV(sum, sumSq int64, n int) (cv float64, ok bool) {
	if n <= 0 {
		return 0, false
	}
	fn := float64(n)
	mean := float64(sum) / fn
	if mean < webShellC2SizeMeanMin {
		return 0, false
	}
	variance := float64(sumSq)/fn - mean*mean
	if variance < 0 {
		variance = 0 // 浮点误差钳制
	}
	return math.Sqrt(variance) / mean, true
}

// webShellC2RatioGE 占比判定（分母为 0 不命中，宁缺毋滥）。
func webShellC2RatioGE(part, total int, ratio float64) bool {
	return total > 0 && float64(part)/float64(total) >= ratio
}

// webShellC2RatioPercent 证据用整数百分比（分母为 0 给 "0%"，不泄露除零）。
func webShellC2RatioPercent(part, total int) string {
	if total <= 0 {
		return "0%"
	}
	return strconv.Itoa(part*100/total) + "%"
}

// ---------- 体形态统计（样本只算前缀；统计量即时消费，不留存明文） ----------

// encryptedWebShellC2Body 请求体加密载荷形态：样本 ≥32 字节、高熵且 base64/url-safe
// 字符占比达标（base64 包裹密文/代码的形态；原始二进制密文命中不了字符集判定——
// 已知局限见文件头）。
func encryptedWebShellC2Body(sample []byte) bool {
	if len(sample) < webShellC2MinBodyForStats {
		return false
	}
	return shannonEntropyBits(sample) >= webShellC2ReqEntropyBits &&
		base64CharsetRatio(sample) >= webShellC2CharsetRatio
}

// encryptedWebShellC2Resp 响应加密块形态：样本 ≥32 字节、高熵且无 HTML 标签特征
// （base64 字母表不含 '<'，密文 base64 响应标签计数恒 0；页面/文本由标签判定排除）。
func encryptedWebShellC2Resp(sample []byte) bool {
	if len(sample) < webShellC2MinBodyForStats {
		return false
	}
	return shannonEntropyBits(sample) >= webShellC2RespEntropyBits &&
		htmlTagCount(sample) == 0
}

// shannonEntropyBits 字节样本香农熵（bits/byte；空样本 0）。
func shannonEntropyBits(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	n := float64(len(b))
	var h float64
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}

// base64CharsetRatio base64/url-safe 字符（A-Za-z0-9 与 +/=_-）占比（空样本 0）。
func base64CharsetRatio(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	n := 0
	for _, c := range b {
		if isBase64CharsetByte(c) {
			n++
		}
	}
	return float64(n) / float64(len(b))
}

func isBase64CharsetByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '+', '/', '=', '_', '-':
		return true
	}
	return false
}

// htmlTagCount HTML 标签形态计数（'<' 后随 ASCII 字母或 '!'，如 <div / <!DOCTYPE）。
func htmlTagCount(b []byte) int {
	n := 0
	for i := 0; i+1 < len(b); i++ {
		if b[i] != '<' {
			continue
		}
		if c := b[i+1]; c == '!' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			n++
		}
	}
	return n
}

// capWebShellC2Sample 体样本截断（统计只算前缀）。
func capWebShellC2Sample(b []byte) []byte {
	if len(b) > webShellC2MaxBodySample {
		return b[:webShellC2MaxBodySample]
	}
	return b
}
