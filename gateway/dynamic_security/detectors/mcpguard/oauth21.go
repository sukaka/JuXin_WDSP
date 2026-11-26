// oauth21.go Phase 9C-1 Streamable HTTP 会话绑定与 OAuth 2.1 Protected Resource Metadata 支持：
//   - SessionBinder：进程内有界（max 8192、TTL 30m、并发安全 O(1) LRU）会话归属绑定器，
//     将 (appID, endpointPath, Mcp-Session-Id 指纹) 绑定至已验签 JWT 主体指纹（未认证时回退追踪键指纹）；
//     不同主体尝试复用同一 Mcp-Session-Id 时触发 mcp.session_hijack_suspected（HIGH；双闸 PROTECT 阻断 -32010）；
//   - ValidateOAuthResourceMetadataURL / FormatOAuth21Challenge：严格校验 https:// 受保护资源元数据 URL
//     并生成 RFC 9728 / MCP OAuth 2.1 `Bearer resource_metadata="<escaped>"` 挑战头（防头注入）。
package mcpguard

import (
	"container/list"
	"crypto/subtle"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
)

const (
	// DefaultMaxSessions SessionBinder 最大并发保留会话条数（有界内存）。
	DefaultMaxSessions = 8192
	// DefaultSessionTTL SessionBinder 会话绑定生存时间。
	DefaultSessionTTL = 30 * time.Minute

	maxOAuthMetadataURLLen = 512
	sessionCheckedExtKey   = "mcp.session_checked"
)

type sessionRecord struct {
	key         string
	principalFP string
	expiresAt   time.Time
}

// SessionBinder 进程内有界、并发安全的 Streamable HTTP 会话绑定表（O(1) LRU + TTL）。
type SessionBinder struct {
	mu         sync.Mutex
	maxEntries int
	ttl        time.Duration
	now        func() time.Time
	lru        *list.List
	items      map[string]*list.Element
}

// NewSessionBinder 创建默认配置的会话绑定器（max 8192, TTL 30m）。
func NewSessionBinder() *SessionBinder {
	return NewSessionBinderWithLimits(DefaultMaxSessions, DefaultSessionTTL)
}

// NewSessionBinderWithLimits 创建自定义上限与 TTL 的会话绑定器（零值回退默认）。
func NewSessionBinderWithLimits(maxEntries int, ttl time.Duration) *SessionBinder {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxSessions
	}
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	return &SessionBinder{
		maxEntries: maxEntries,
		ttl:        ttl,
		now:        time.Now,
		lru:        list.New(),
		items:      make(map[string]*list.Element),
	}
}

// BindOrVerify 绑定或核验 (appID, endpointPath, sessionID) 的归属主体：
//   - 首次出现或前条已过期：绑定至 principalFP 并返回 true；
//   - 未过期且主体一致（常量时间比对）：刷新滑动过期时间并返回 true；
//   - 未过期但主体不一致：保持原归属不变并返回 false（疑似会话劫持）。
func (b *SessionBinder) BindOrVerify(appID, endpointPath, sessionID, principalFP string) bool {
	if b == nil || sessionID == "" || principalFP == "" {
		return true
	}
	key := appID + "\x00" + normalizer.CanonicalPath(endpointPath) + "\x00" + sessionID

	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if elem, ok := b.items[key]; ok {
		rec := elem.Value.(*sessionRecord)
		if !now.After(rec.expiresAt) {
			if subtle.ConstantTimeCompare([]byte(rec.principalFP), []byte(principalFP)) == 1 {
				rec.expiresAt = now.Add(b.ttl)
				b.lru.MoveToFront(elem)
				return true
			}
			// 不同主体复用：不覆写原合法归属，返回 false
			return false
		}
		// 已过期：原地覆盖为新绑定
		rec.principalFP = principalFP
		rec.expiresAt = now.Add(b.ttl)
		b.lru.MoveToFront(elem)
		return true
	}

	b.evictExpiredTailLocked(now)
	for len(b.items) >= b.maxEntries {
		back := b.lru.Back()
		if back == nil {
			break
		}
		b.removeElemLocked(back)
	}

	rec := &sessionRecord{
		key:         key,
		principalFP: principalFP,
		expiresAt:   now.Add(b.ttl),
	}
	elem := b.lru.PushFront(rec)
	b.items[key] = elem
	return true
}

// Len 返回当前驻留会话条数（用于测试与观测）。
func (b *SessionBinder) Len() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}

func (b *SessionBinder) evictExpiredTailLocked(now time.Time) {
	for back := b.lru.Back(); back != nil; {
		prev := back.Prev()
		rec := back.Value.(*sessionRecord)
		if now.After(rec.expiresAt) {
			b.removeElemLocked(back)
		} else {
			break // 尾部按最近访问/续期时间递增，未过期即可提前终止
		}
		back = prev
	}
}

func (b *SessionBinder) removeElemLocked(elem *list.Element) {
	rec := elem.Value.(*sessionRecord)
	delete(b.items, rec.key)
	b.lru.Remove(elem)
}

// deriveSessionPrincipal 提取会话绑定主体指纹：
// 优先使用已验签 JWT 主体（tenant + principal 加盐指纹），未认证时回退请求追踪键指纹。
func deriveSessionPrincipal(cfg *Config, jwtRes *jwtverify.VerificationResult, trackingKey string) string {
	salt := ""
	if cfg != nil {
		salt = cfg.IdentitySalt
	}
	if jwtRes != nil && jwtRes.Status == jwtverify.StatusVerified && jwtRes.VerifiedPrincipalID != "" {
		return "jwt:" + fingerprint(salt, jwtRes.VerifiedTenantID+"\x00"+jwtRes.VerifiedPrincipalID)
	}
	if trackingKey != "" {
		return "trk:" + fingerprint(salt, trackingKey)
	}
	return ""
}

// headObsSessionFP 从 RequestContext 头观测扩展读取 Mcp-Session-Id 盐指纹。
func headObsSessionFP(ctx *dsctx.RequestContext) string {
	if ctx == nil {
		return ""
	}
	v, ok := ctx.GetExtension(headObsExtKey)
	if !ok {
		return ""
	}
	obs, ok := v.(map[string]string)
	if !ok {
		return ""
	}
	return obs["session_id_fp"]
}

// checkSessionBindingFromContext Evaluate 内部入口：复用 NoteHeadObservations 与 EvaluateCandidate
// 写入的会话指纹与追踪键，幂等避免同一请求重复检查。返回 true 表示双闸 PROTECT 触发阻断。
func checkSessionBindingFromContext(ctx *dsctx.RequestContext, cfg *Config, ep *Endpoint, jwtRes *jwtverify.VerificationResult, appID, method string, engineProtect bool) bool {
	if ctx == nil || cfg == nil || ep == nil || !ep.RequireSessionBinding {
		return false
	}
	if checked, ok := ctx.GetExtension(sessionCheckedExtKey); ok {
		if b, _ := checked.(bool); b {
			return false
		}
	}
	sessFP := headObsSessionFP(ctx)
	if sessFP == "" {
		return false
	}
	principalFP := deriveSessionPrincipal(cfg, jwtRes, trackingKeyFromContext(ctx))
	if principalFP == "" {
		return false
	}
	ctx.SetExtension(sessionCheckedExtKey, true)
	binder := cfg.sessionBinder()
	if binder == nil {
		return false
	}
	effAppID := appID
	if effAppID == "" {
		effAppID = cfg.resolvedAppID
	}
	if binder.BindOrVerify(effAppID, cfg.resolvedPath, sessFP, principalFP) {
		return false
	}
	return emitSessionHijackMatch(ctx, ep, sessFP, method, engineProtect)
}

// CheckSessionBinding 供挂点侧（如 Streamable HTTP GET 或直接单测）调用的会话绑定检查入口。
// 同一 RequestContext 幂等只校验一次；若 Mcp-Session-Id 被异主体复用则发射
// mcp.session_hijack_suspected，并在双闸 PROTECT 时返回 true（阻断，-32010）。
func CheckSessionBinding(ctx *dsctx.RequestContext, r *http.Request, cfg *Config, jwtRes *jwtverify.VerificationResult, appID, endpointPath string, engineProtect bool) bool {
	if ctx == nil || r == nil || cfg == nil {
		return false
	}
	if checked, ok := ctx.GetExtension(sessionCheckedExtKey); ok {
		if b, _ := checked.(bool); b {
			return false
		}
	}
	scoped := cfg
	if scoped.resolved == nil {
		scoped = cfg.ForEndpoint(appID, endpointPath)
		if scoped == nil {
			return false
		}
	}
	ep := scoped.resolvedEndpoint(appID)
	if ep == nil || !ep.RequireSessionBinding {
		return false
	}
	rawSess := headerOf(r, "Mcp-Session-Id")
	if rawSess == "" {
		return false
	}
	sessFP := fingerprint(scoped.IdentitySalt, rawSess)
	trackingKey := trackingKeyFromContext(ctx)
	if trackingKey == "" {
		trackingKey = detectors.TrackingKey(r, scoped.IdentitySalt)
	}
	principalFP := deriveSessionPrincipal(scoped, jwtRes, trackingKey)
	if principalFP == "" {
		return false
	}
	ctx.SetExtension(sessionCheckedExtKey, true)
	binder := scoped.sessionBinder()
	if binder == nil {
		return false
	}
	path := scoped.resolvedPath
	if path == "" {
		path = normalizer.CanonicalPath(endpointPath)
	}
	effAppID := appID
	if effAppID == "" {
		effAppID = scoped.resolvedAppID
	}
	if binder.BindOrVerify(effAppID, path, sessFP, principalFP) {
		return false
	}
	return emitSessionHijackMatch(ctx, ep, sessFP, r.Method, engineProtect)
}

func emitSessionHijackMatch(ctx *dsctx.RequestContext, ep *Endpoint, sessFP, method string, engineProtect bool) bool {
	doubleGate := ep.Mode == ModeProtect && engineProtect
	category := "OBSERVE"
	if doubleGate {
		category = "BLOCK"
	}
	ev := map[string]string{
		"session_id_fp":   sessFP,
		"reason_code":     "MCP_SESSION_HIJACK_SUSPECTED",
		"mcp_error_code":  strconv.Itoa(CodeSubjectUntrusted),
		"mcp_http_status": "403",
	}
	if method != "" {
		ev["method"] = truncateString(method, 128)
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "mcpguard",
		RuleID:     "mcp.session_hijack_suspected",
		Category:   category,
		Severity:   "HIGH",
		Message:    "mcp session id reused by a different principal",
		Confidence: 1.0,
		Evidence:   ev,
	})
	return doubleGate
}

// ValidateOAuthResourceMetadataURL 校验 OAuth 2.1 Protected Resource Metadata URL（RFC 9728）：
// 仅接受合法 https:// URL（非空主机名、无嵌入式凭据、无 fragment、无控制/空白/引号/反斜杠字符、长度 ≤512）。
func ValidateOAuthResourceMetadataURL(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > maxOAuthMetadataURLLen {
		return "", false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' || unicode.IsSpace(r) {
			return "", false
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", false
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return "", false
	}
	return s, true
}

// FormatOAuth21Challenge 生成 RFC 9728 / MCP OAuth 2.1 WWW-Authenticate 挑战值：
// 合法 https:// URL 返回 `Bearer resource_metadata="<escaped>"`；非法或空串返回 ""（防头注入）。
func FormatOAuth21Challenge(metadataURL string) string {
	clean, ok := ValidateOAuthResourceMetadataURL(metadataURL)
	if !ok {
		return ""
	}
	escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(clean)
	return `Bearer resource_metadata="` + escaped + `"`
}
