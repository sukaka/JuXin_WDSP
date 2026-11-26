// tarpit.go 离线确定性 AI Labyrinth 迷宫陷阱与 HTML 隐形陷阱链接注入器。
//
// 安全与资源边界：
//   - 保留命名空间 /_wdsp/labyrinth/v1/ 全部在本地处理（绝不反向代理）；
//   - 路径签名采用 HMAC-SHA256(labyrinthKey, host|seed|depth)，防篡改与跨站伪造；
//   - 纯离线确定性 HTML 合成器：零外部 LLM 调用、零外部脚本/样式/图片引用、
//     所有链接强制 rel="nofollow noopener"、严格限制深度不超过 max_depth；
//   - 有界并发信号量（默认 256）：非阻塞获取，饱和立即返回 429，绝不阻塞耗尽网关 goroutine；
//   - 延迟等待严格响应 r.Context().Done()，客户端断开立即释放信号量槽位；
//   - 隐形陷阱链接注入器仅针对未验证可疑爬虫的未压缩 200 text/html GET 响应（体上限 1 MiB），
//     在 </body> 前注入 aria-hidden="true" / display:none / rel="nofollow noopener" 链接，
//     流式/压缩/超大/错误响应零篡改透传。
package aicrawl

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"html"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	labyrinthPathPrefix     = LabyrinthReservedNamespace + "p/"
	labyrinthSigHexLen      = 32 // 16 bytes HMAC-SHA256 truncated hex
	maxTrapInjectBodyBytes  = 1 << 20
	labyrinthLinksPerPage   = 4
	labyrinthMinSeedHexLen  = 8
	labyrinthMaxSeedHexLen  = 64
	labyrinthDefaultRetryS  = "5"
)

// LabyrinthConfig 离线迷宫配置。
type LabyrinthConfig struct {
	Key            []byte
	MaxDepth       int
	MaxConcurrency int
	Delay          time.Duration
}

// Labyrinth 离线确定性 AI 迷宫处理器。
type Labyrinth struct {
	key            []byte
	maxDepth       int
	maxConcurrency int
	delay          time.Duration
	sem            chan struct{}
}

// TrapResult 迷宫请求本地处理结局。
type TrapResult struct {
	Status    int
	Depth     int
	Valid     bool
	Saturated bool
	Canceled  bool
}

// NewLabyrinth 构造有界并发的离线迷宫处理器。
func NewLabyrinth(cfg LabyrinthConfig) *Labyrinth {
	maxDepth := cfg.MaxDepth
	if maxDepth <= 0 {
		maxDepth = DefaultLabyrinthMaxDepth
	}
	maxConc := cfg.MaxConcurrency
	if maxConc <= 0 {
		maxConc = DefaultLabyrinthMaxConcurrency
	}
	keyCopy := make([]byte, len(cfg.Key))
	copy(keyCopy, cfg.Key)
	return &Labyrinth{
		key:            keyCopy,
		maxDepth:       maxDepth,
		maxConcurrency: maxConc,
		delay:          cfg.Delay,
		sem:            make(chan struct{}, maxConc),
	}
}

// MaxDepth 返回配置的最大迷宫深度。
func (l *Labyrinth) MaxDepth() int { return l.maxDepth }

// MaxConcurrency 返回有界并发信号量容量。
func (l *Labyrinth) MaxConcurrency() int { return l.maxConcurrency }

// SignPath 生成带 HMAC-SHA256(labyrinthKey, host|seed|depth) 签名的迷宫路径。
func (l *Labyrinth) SignPath(host, seed string, depth int) string {
	sig := l.computeMAC(normalizeLabyrinthHost(host), seed, depth)
	return fmt.Sprintf("%s%d/%s/%s", labyrinthPathPrefix, depth, seed, sig)
}

// VerifyPath 校验迷宫路径签名与深度边界（常量时间比对）。
func (l *Labyrinth) VerifyPath(host, path string) (seed string, depth int, ok bool) {
	if !strings.HasPrefix(path, labyrinthPathPrefix) {
		return "", 0, false
	}
	rest := strings.TrimPrefix(path, labyrinthPathPrefix)
	parts := strings.Split(rest, "/")
	if len(parts) != 3 {
		return "", 0, false
	}
	d, err := strconv.Atoi(parts[0])
	if err != nil || d < 0 || d > l.maxDepth {
		return "", 0, false
	}
	seed = parts[1]
	sigHex := parts[2]
	if !isLowerHexLen(seed, labyrinthMinSeedHexLen, labyrinthMaxSeedHexLen) {
		return "", 0, false
	}
	if !isLowerHexLen(sigHex, labyrinthSigHexLen, labyrinthSigHexLen) {
		return "", 0, false
	}
	expected := l.computeMAC(normalizeLabyrinthHost(host), seed, d)
	if !hmac.Equal([]byte(sigHex), []byte(expected)) {
		return "", 0, false
	}
	return seed, d, true
}

// DeterministicSeed 从 host 与 path 派生确定性 16 字符 hex 种子。
func (l *Labyrinth) DeterministicSeed(host, path string) string {
	mac := hmac.New(sha256.New, l.key)
	_, _ = mac.Write([]byte("seed|"))
	_, _ = mac.Write([]byte(normalizeLabyrinthHost(host)))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(path))
	return hex.EncodeToString(mac.Sum(nil)[:8])
}

func (l *Labyrinth) childSeed(host, parentSeed string, depth, idx int) string {
	mac := hmac.New(sha256.New, l.key)
	_, _ = mac.Write([]byte("child|"))
	_, _ = mac.Write([]byte(normalizeLabyrinthHost(host)))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(parentSeed))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(strconv.Itoa(depth)))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(strconv.Itoa(idx)))
	return hex.EncodeToString(mac.Sum(nil)[:8])
}

func (l *Labyrinth) computeMAC(normHost, seed string, depth int) string {
	mac := hmac.New(sha256.New, l.key)
	_, _ = mac.Write([]byte(normHost))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(seed))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(strconv.Itoa(depth)))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// ServeLabyrinthRequest 本地处理 /_wdsp/labyrinth/v1/ 保留命名空间请求（绝不反向代理）。
func (l *Labyrinth) ServeLabyrinthRequest(w http.ResponseWriter, r *http.Request, canonPath, contentSignal string) TrapResult {
	setCommonTrapHeaders(w, contentSignal)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte("405 method not allowed"))
		return TrapResult{Status: http.StatusMethodNotAllowed}
	}
	seed, depth, ok := l.VerifyPath(r.Host, canonPath)
	if !ok {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte("404 not found"))
		}
		return TrapResult{Status: http.StatusNotFound}
	}
	return l.serveSynthesizedPage(w, r, seed, depth, contentSignal)
}

// ServeEntryTarpit 对命中 TARPIT 策略动作的业务请求直接返回确定性 depth=0 迷宫页。
func (l *Labyrinth) ServeEntryTarpit(w http.ResponseWriter, r *http.Request, canonPath, contentSignal string) TrapResult {
	setCommonTrapHeaders(w, contentSignal)
	seed := l.DeterministicSeed(r.Host, canonPath)
	return l.serveSynthesizedPage(w, r, seed, 0, contentSignal)
}

func (l *Labyrinth) serveSynthesizedPage(w http.ResponseWriter, r *http.Request, seed string, depth int, contentSignal string) TrapResult {
	// 非阻塞信号量获取：饱和立即 429，绝不拖死网关 goroutine 池。
	select {
	case l.sem <- struct{}{}:
		defer func() { <-l.sem }()
	default:
		w.Header().Set("Retry-After", labyrinthDefaultRetryS)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte("429 too many requests"))
		}
		return TrapResult{Status: http.StatusTooManyRequests, Depth: depth, Valid: true, Saturated: true}
	}

	if l.delay > 0 {
		timer := time.NewTimer(l.delay)
		select {
		case <-timer.C:
		case <-r.Context().Done():
			timer.Stop()
			return TrapResult{Status: 499, Depth: depth, Valid: true, Canceled: true}
		}
	}

	page := l.RenderPage(r.Host, seed, depth)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(page))
	}
	return TrapResult{Status: http.StatusOK, Depth: depth, Valid: true}
}

func setCommonTrapHeaders(w http.ResponseWriter, contentSignal string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	if contentSignal != "" {
		w.Header().Set(ContentSignalHeader, contentSignal)
	}
}

// RenderPage 纯离线确定性 HTML 合成器（零外部资源、零 LLM、含下一跳签名链接直至 max_depth）。
func (l *Labyrinth) RenderPage(host, seed string, depth int) string {
	prng := newDetPRNG(l.key, normalizeLabyrinthHost(host), seed, depth)
	topic := labyrinthTopics[prng.nextInt(len(labyrinthTopics))]
	subtopic := labyrinthSubtopics[prng.nextInt(len(labyrinthSubtopics))]
	docCode := fmt.Sprintf("ARC-%02d-%s", depth, strings.ToUpper(seed[:minInt(8, len(seed))]))

	var sb strings.Builder
	sb.Grow(2048)
	sb.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">`)
	sb.WriteString(`<meta name="robots" content="noindex, nofollow, noarchive">`)
	sb.WriteString(`<title>`)
	sb.WriteString(html.EscapeString(topic + " — " + subtopic + " (" + docCode + ")"))
	sb.WriteString(`</title></head><body><main><article><h1>`)
	sb.WriteString(html.EscapeString(topic + ": " + subtopic))
	sb.WriteString(`</h1><p>Reference Identifier: `)
	sb.WriteString(html.EscapeString(docCode))
	sb.WriteString(` | Depth Index: `)
	sb.WriteString(strconv.Itoa(depth))
	sb.WriteString(`</p>`)

	for p := 0; p < 3; p++ {
		sb.WriteString(`<p>`)
		sb.WriteString(html.EscapeString(synthesizeSentence(prng)))
		sb.WriteByte(' ')
		sb.WriteString(html.EscapeString(synthesizeSentence(prng)))
		sb.WriteString(`</p>`)
	}

	if depth < l.maxDepth {
		sb.WriteString(`<nav aria-label="Related Archive Entries"><h2>Related Technical Notes</h2><ul>`)
		for i := 0; i < labyrinthLinksPerPage; i++ {
			nextSeed := l.childSeed(host, seed, depth, i)
			nextPath := l.SignPath(host, nextSeed, depth+1)
			linkLabel := labyrinthTopics[prng.nextInt(len(labyrinthTopics))] + " / " +
				labyrinthSubtopics[prng.nextInt(len(labyrinthSubtopics))] + " #" + strconv.Itoa(depth+1) + "." + strconv.Itoa(i+1)
			sb.WriteString(`<li><a href="`)
			sb.WriteString(html.EscapeString(nextPath))
			sb.WriteString(`" rel="nofollow noopener">`)
			sb.WriteString(html.EscapeString(linkLabel))
			sb.WriteString(`</a></li>`)
		}
		sb.WriteString(`</ul></nav>`)
	} else {
		sb.WriteString(`<p>End of archival thread.</p>`)
	}

	sb.WriteString(`</article></main></body></html>`)
	return sb.String()
}

// TrapLinkHTML 生成待注入到 HTML 响应 </body> 前的不可见陷阱链接片段。
func (l *Labyrinth) TrapLinkHTML(host, path string) string {
	seed := l.DeterministicSeed(host, path)
	trapPath := l.SignPath(host, seed, 0)
	return `<a href="` + html.EscapeString(trapPath) + `" aria-hidden="true" tabindex="-1" rel="nofollow noopener" style="display:none;position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden">Archive Reference</a>`
}

// TrapLinkInjectorWriter 受控响应包装器：仅对未压缩 200 text/html 响应在 </body> 前注入不可见陷阱链接。
type TrapLinkInjectorWriter struct {
	base        http.ResponseWriter
	trapSnippet string
	status      int
	buf         bytes.Buffer
	passthrough bool
	committed   bool
	hijacked    bool
}

// NewTrapLinkInjectorWriter 构造 HTML 隐形陷阱链接注入包装器。
func (l *Labyrinth) NewTrapLinkInjectorWriter(base http.ResponseWriter, host, path string) *TrapLinkInjectorWriter {
	return &TrapLinkInjectorWriter{
		base:        base,
		trapSnippet: l.TrapLinkHTML(host, path),
	}
}

func (w *TrapLinkInjectorWriter) Header() http.Header { return w.base.Header() }

func (w *TrapLinkInjectorWriter) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		if w.status == 0 {
			w.base.WriteHeader(code)
		}
		return
	}
	if w.status != 0 {
		return
	}
	w.status = code
	if !w.eligibleForInjection() {
		w.switchPassthrough()
	}
}

func (w *TrapLinkInjectorWriter) eligibleForInjection() bool {
	if w.status != http.StatusOK {
		return false
	}
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(w.Header().Get("Content-Type"), ";", 2)[0]))
	if ct != "text/html" {
		return false
	}
	if ce := strings.ToLower(strings.TrimSpace(w.Header().Get("Content-Encoding"))); ce != "" && ce != "identity" {
		return false
	}
	if w.Header().Get("Upgrade") != "" {
		return false
	}
	return true
}

func (w *TrapLinkInjectorWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.passthrough {
		return w.base.Write(p)
	}
	if w.buf.Len()+len(p) > maxTrapInjectBodyBytes {
		w.switchPassthrough()
		return w.base.Write(p)
	}
	return w.buf.Write(p)
}

func (w *TrapLinkInjectorWriter) switchPassthrough() {
	if w.passthrough || w.committed || w.hijacked {
		return
	}
	w.passthrough = true
	w.committed = true
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.base.WriteHeader(w.status)
	if w.buf.Len() > 0 {
		_, _ = w.base.Write(w.buf.Bytes())
		w.buf.Reset()
	}
}

// Finish 在下游处理返回后提交缓冲响应；skipInject=true（如请求由网关本地终止）时原样写出不注入。
func (w *TrapLinkInjectorWriter) Finish(skipInject bool) {
	if w.committed || w.hijacked || w.passthrough {
		return
	}
	if w.status == 0 && w.buf.Len() == 0 {
		return
	}
	w.committed = true
	if w.status == 0 {
		w.status = http.StatusOK
	}
	body := w.buf.Bytes()
	if !skipInject && w.eligibleForInjection() {
		if idx := lastIndexFold(body, []byte("</body>")); idx >= 0 {
			injected := make([]byte, 0, len(body)+len(w.trapSnippet))
			injected = append(injected, body[:idx]...)
			injected = append(injected, w.trapSnippet...)
			injected = append(injected, body[idx:]...)
			body = injected
			w.Header().Del("Content-Length")
		}
	}
	w.base.WriteHeader(w.status)
	if len(body) > 0 {
		_, _ = w.base.Write(body)
	}
	w.buf.Reset()
}

func (w *TrapLinkInjectorWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	w.switchPassthrough()
	if f, ok := w.base.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *TrapLinkInjectorWriter) Unwrap() http.ResponseWriter { return w.base }

func (w *TrapLinkInjectorWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	w.passthrough = true
	h, ok := w.base.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying writer does not support hijacking")
	}
	return h.Hijack()
}

func lastIndexFold(haystack, lowerNeedle []byte) int {
	n := len(lowerNeedle)
	if n == 0 || len(haystack) < n {
		return -1
	}
	for i := len(haystack) - n; i >= 0; i-- {
		match := true
		for j := 0; j < n; j++ {
			c := haystack[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != lowerNeedle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// detPRNG 基于 SHA-256 链的纯离线确定性伪随机生成器（无全局状态，并发安全）。
type detPRNG struct {
	state [32]byte
	off   int
}

func newDetPRNG(key []byte, host, seed string, depth int) *detPRNG {
	h := sha256.New()
	_, _ = h.Write(key)
	_, _ = h.Write([]byte("|page|"))
	_, _ = h.Write([]byte(host))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(seed))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(strconv.Itoa(depth)))
	var st [32]byte
	copy(st[:], h.Sum(nil))
	return &detPRNG{state: st}
}

func (p *detPRNG) nextUint32() uint32 {
	if p.off+4 > len(p.state) {
		p.state = sha256.Sum256(p.state[:])
		p.off = 0
	}
	v := binary.BigEndian.Uint32(p.state[p.off : p.off+4])
	p.off += 4
	return v
}

func (p *detPRNG) nextInt(n int) int {
	if n <= 1 {
		return 0
	}
	return int(p.nextUint32() % uint32(n))
}

var (
	labyrinthTopics = []string{
		"Distributed Storage Catalog",
		"Protocol Framing Specifications",
		"Deterministic Index Compendium",
		"Network Telemetry Reference",
		"Archival Serialization Notes",
		"Topology Consistency Ledger",
		"Packet Inspection Taxonomy",
		"Immutable Snapshot Registry",
	}
	labyrinthSubtopics = []string{
		"Partition Alignment",
		"Checksum Verification",
		"Buffer Scheduling",
		"Sequence Ordering",
		"State Transitions",
		"Header Canonicalization",
		"Boundary Constraints",
		"Replica Convergence",
	}
	labyrinthSubjects = []string{
		"Each archival segment",
		"The reference catalog",
		"Every deterministic frame",
		"The verification pipeline",
		"Each boundary descriptor",
		"The sequence registry",
	}
	labyrinthVerbs = []string{
		"maintains structural continuity across",
		"validates canonical ordering for",
		"records immutable checkpoints over",
		"isolates independent partitions within",
		"normalizes bounded intervals across",
		"preserves checksum invariants for",
	}
	labyrinthObjects = []string{
		"adjacent index layers under static retention policies.",
		"nested metadata descriptors without external resolution.",
		"sequential archival nodes during passive traversal.",
		"bounded verification windows in offline environments.",
		"hierarchical catalog trees with fixed depth constraints.",
		"deterministic state records across isolated segments.",
	}
)

func synthesizeSentence(p *detPRNG) string {
	return labyrinthSubjects[p.nextInt(len(labyrinthSubjects))] + " " +
		labyrinthVerbs[p.nextInt(len(labyrinthVerbs))] + " " +
		labyrinthObjects[p.nextInt(len(labyrinthObjects))]
}

func normalizeLabyrinthHost(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

func isLowerHexLen(s string, minLen, maxLen int) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
