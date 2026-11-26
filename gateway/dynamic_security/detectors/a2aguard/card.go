package a2aguard

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
)

const (
	WellKnownAgentJSON     = "/.well-known/agent.json"
	WellKnownAgentCardJSON = "/.well-known/agent-card.json"
)

// AgentCard 解析并脱敏后的 A2A Agent Card 资产元数据（供 AgBOM 发现与事件上报）。
type AgentCard struct {
	Name        string
	URL         string
	Version     string
	Skills      []string
	AuthSchemes []string
}

// IsWellKnownAgentCardPath 判断规范化路径是否为 A2A Agent Card 标准发现端点。
func IsWellKnownAgentCardPath(reqPath string) bool {
	cp := normalizer.CanonicalPath(reqPath)
	return cp == WellKnownAgentJSON || cp == WellKnownAgentCardJSON
}

// SanitizeAgentURL 剥离 URL 中的凭据（userinfo）、查询串与 fragment，并限制长度与协议。
// 仅保留 http/https 绝对 URL 或以 / 开头的相对路径，拒绝 javascript:/data: 等危险方案。
func SanitizeAgentURL(raw string) string {
	raw = stripControlChars(raw, 1024)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		if idx := strings.IndexAny(raw, "?#"); idx >= 0 {
			raw = raw[:idx]
		}
		if len(raw) > 512 {
			raw = raw[:512]
		}
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme != "http" && scheme != "https" {
		return ""
	}
	if strings.TrimSpace(u.Host) == "" {
		return ""
	}
	u.Scheme = scheme
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	out := u.String()
	if len(out) > 512 {
		out = out[:512]
	}
	return out
}

// ParseAgentCard 从 <=256KiB 的 JSON 响应体中提取并脱敏 A2A Agent Card。
// 解析失败、超限或缺少 name 字段返回 (nil, false)。
func ParseAgentCard(body []byte, fallbackURL string) (*AgentCard, bool) {
	if len(body) == 0 || len(body) > MaxAgentCardBytes {
		return nil, false
	}
	var doc struct {
		Name           string            `json:"name"`
		URL            string            `json:"url"`
		Version        string            `json:"version"`
		Skills         []json.RawMessage `json:"skills"`
		Authentication *struct {
			Schemes []string `json:"schemes"`
		} `json:"authentication"`
		SecuritySchemes map[string]struct {
			Type string `json:"type"`
		} `json:"securitySchemes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	name := stripControlChars(doc.Name, 256)
	if name == "" {
		return nil, false
	}
	agentURL := SanitizeAgentURL(doc.URL)
	if agentURL == "" {
		agentURL = SanitizeAgentURL(fallbackURL)
	}
	version := stripControlChars(doc.Version, 64)

	skills := extractCardSkills(doc.Skills)
	var authSchemes []string
	if doc.Authentication != nil && len(doc.Authentication.Schemes) > 0 {
		authSchemes = normalizeBoundedStrings(doc.Authentication.Schemes, MaxAgentAuthSchemes, MaxAuthSchemeLen)
	} else if len(doc.SecuritySchemes) > 0 {
		keys := make([]string, 0, len(doc.SecuritySchemes))
		for k := range doc.SecuritySchemes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		rawSchemes := make([]string, 0, len(keys))
		for _, k := range keys {
			if t := strings.TrimSpace(doc.SecuritySchemes[k].Type); t != "" {
				rawSchemes = append(rawSchemes, t)
			} else {
				rawSchemes = append(rawSchemes, k)
			}
		}
		authSchemes = normalizeBoundedStrings(rawSchemes, MaxAgentAuthSchemes, MaxAuthSchemeLen)
	}

	return &AgentCard{
		Name:        name,
		URL:         agentURL,
		Version:     version,
		Skills:      skills,
		AuthSchemes: authSchemes,
	}, true
}

func extractCardSkills(rawSkills []json.RawMessage) []string {
	if len(rawSkills) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(rawSkills))
	out := make([]string, 0, minInt(len(rawSkills), MaxAgentSkills))
	for _, raw := range rawSkills {
		if len(out) >= MaxAgentSkills {
			break
		}
		var candidate string
		var obj struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if json.Unmarshal(raw, &obj) == nil {
			candidate = strings.TrimSpace(obj.ID)
			if candidate == "" {
				candidate = strings.TrimSpace(obj.Name)
			}
		} else {
			var s string
			if json.Unmarshal(raw, &s) == nil {
				candidate = strings.TrimSpace(s)
			}
		}
		candidate = stripControlChars(candidate, MaxSkillLen)
		if candidate == "" {
			continue
		}
		if _, dup := seen[candidate]; dup {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeBoundedStrings(in []string, maxItems, maxLen int) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, minInt(len(in), maxItems))
	for _, s := range in {
		if len(out) >= maxItems {
			break
		}
		clean := stripControlChars(s, maxLen)
		if clean == "" {
			continue
		}
		if _, dup := seen[clean]; dup {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// IsUncompressedJSONResponse 校验是否为 2xx、未压缩且 JSON 媒体类型的响应。
func IsUncompressedJSONResponse(status int, contentType, contentEncoding string) bool {
	if status < 200 || status > 299 {
		return false
	}
	enc := strings.ToLower(strings.TrimSpace(contentEncoding))
	if enc != "" && enc != "identity" {
		return false
	}
	media := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	return media == "application/json" || strings.HasSuffix(media, "+json")
}

// ObserveAgentCard 对 Agent Card 响应执行合格性判断、提取、脱敏与有界 LRU 去重（60s TTL / 2048 项）。
// 返回 (card, true) 表示首次发现或 TTL 过期后应上报 A2A_AGENT_CARD_DISCOVERED；
// 返回 (nil, false) 表示不合格、不可解析或去重窗口内已上报。
func (e *Engine) ObserveAgentCard(appID string, status int, contentType, contentEncoding string, body []byte, fallbackURL string) (*AgentCard, bool) {
	if e == nil || e.policy.Mode == ModeOff || !e.policy.CardDiscoveryEnabled {
		return nil, false
	}
	if !IsUncompressedJSONResponse(status, contentType, contentEncoding) {
		return nil, false
	}
	card, ok := ParseAgentCard(body, fallbackURL)
	if !ok {
		return nil, false
	}
	if appID == "" {
		appID = e.policy.ApplicationID
	}
	key := agentCardDedupKey(appID, card)
	if !e.cardDedup.Allow(key, e.now()) {
		return nil, false
	}
	return card, true
}

func agentCardDedupKey(appID string, c *AgentCard) string {
	h := sha256.New()
	writePart := func(s string) {
		_, _ = h.Write([]byte(s))
		_, _ = h.Write([]byte{0})
	}
	writePart(appID)
	writePart(c.Name)
	writePart(c.URL)
	writePart(c.Version)
	writePart(strings.Join(c.Skills, "\x1f"))
	writePart(strings.Join(c.AuthSchemes, "\x1f"))
	return hex.EncodeToString(h.Sum(nil))
}

// cardDedupCache 有界 LRU + TTL 去重缓存（并发安全，默认 60s TTL、上限 2048）。
type cardDedupCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	maxSize int
	order   *list.List
	items   map[string]*list.Element
}

type cardDedupEntry struct {
	key       string
	expiresAt time.Time
}

func newCardDedupCache(ttl time.Duration, maxSize int) *cardDedupCache {
	return &cardDedupCache{
		ttl:     ttl,
		maxSize: maxSize,
		order:   list.New(),
		items:   make(map[string]*list.Element),
	}
}

// Allow 若 key 在 TTL 内已记录返回 false；否则登记/续期并按 LRU 淘汰超限旧项返回 true。
func (c *cardDedupCache) Allow(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		ent := el.Value.(*cardDedupEntry)
		if now.Before(ent.expiresAt) {
			c.order.MoveToFront(el)
			return false
		}
		ent.expiresAt = now.Add(c.ttl)
		c.order.MoveToFront(el)
		return true
	}
	// 淘汰少量尾部已过期条目，必要时按 LRU 淘汰确保 len <= maxSize。
	for i := 0; i < 4 && c.order.Len() >= c.maxSize; i++ {
		back := c.order.Back()
		if back == nil {
			break
		}
		ent := back.Value.(*cardDedupEntry)
		if now.Before(ent.expiresAt) {
			break
		}
		c.order.Remove(back)
		delete(c.items, ent.key)
	}
	for c.order.Len() >= c.maxSize {
		back := c.order.Back()
		if back == nil {
			break
		}
		ent := back.Value.(*cardDedupEntry)
		c.order.Remove(back)
		delete(c.items, ent.key)
	}
	el := c.order.PushFront(&cardDedupEntry{
		key:       key,
		expiresAt: now.Add(c.ttl),
	})
	c.items[key] = el
	return true
}

func (c *cardDedupCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
