package securityevents

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// appLinkEntry 是域名→应用的映射条目。
type appLinkEntry struct {
	applicationID   uuid.UUID
	applicationName string
}

// appResolverTTL 是域名映射缓存的有效期（惰性刷新）。
const appResolverTTL = 60 * time.Second

// appResolver 域名→应用解析器：全量加载 application_domains 到内存映射，
// 缓存 appResolverTTL 后惰性刷新（sync.Mutex 保护）。刷新失败时沿用旧缓存，
// 不阻断事件采集。
type appResolver struct {
	db       *pgxpool.Pool
	mu       sync.Mutex
	entries  map[string]appLinkEntry
	loadedAt time.Time
}

// newAppResolver 创建域名→应用解析器。
func newAppResolver(db *pgxpool.Pool) *appResolver {
	return &appResolver{db: db}
}

// resolve 解析 Host 头到应用（未命中或映射不可用时返回 false）。
func (r *appResolver) resolve(ctx context.Context, host string) (uuid.UUID, string, bool) {
	return matchApplication(host, r.load(ctx))
}

// load 返回缓存的域名映射，过期时重新全量加载。
func (r *appResolver) load(ctx context.Context) map[string]appLinkEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil || time.Since(r.loadedAt) >= appResolverTTL {
		entries, err := r.query(ctx)
		if err != nil {
			// 刷新失败沿用旧缓存（首次失败则保持空映射，本轮不回填应用）
			slog.Warn("app resolver refresh failed", "error", err)
		} else {
			r.entries = entries
			r.loadedAt = time.Now()
		}
	}
	return r.entries
}

// query 从 application_domains 全量加载域名→应用映射（已软删应用除外）。
func (r *appResolver) query(ctx context.Context) (map[string]appLinkEntry, error) {
	rows, err := r.db.Query(ctx, `
SELECT d.normalized_hostname, d.application_id, a.name
FROM application_domains d
JOIN applications a ON a.id = d.application_id AND a.deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := make(map[string]appLinkEntry)
	for rows.Next() {
		var host string
		var e appLinkEntry
		if err := rows.Scan(&host, &e.applicationID, &e.applicationName); err != nil {
			return nil, err
		}
		entries[host] = e
	}
	return entries, rows.Err()
}

// matchApplication 将 Host 头匹配到应用：host 先小写化、剥离端口
// （仅当存在 : 且冒号后全为数字；hostname 本身不含冒号，不考虑 IPv6），
// 先精确匹配 normalized_hostname，未命中再对 *. 前缀的泛域名做后缀匹配
// （*.example.com 匹配 example.com 与 a.example.com）。
func matchApplication(host string, entries map[string]appLinkEntry) (uuid.UUID, string, bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || len(entries) == 0 {
		return uuid.Nil, "", false
	}
	if idx := strings.IndexByte(host, ':'); idx >= 0 && isAllDigits(host[idx+1:]) {
		host = host[:idx]
	}
	if e, ok := entries[host]; ok {
		return e.applicationID, e.applicationName, true
	}
	for key, e := range entries {
		if !strings.HasPrefix(key, "*.") {
			continue
		}
		if host == key[2:] || strings.HasSuffix(host, key[1:]) {
			return e.applicationID, e.applicationName, true
		}
	}
	return uuid.Nil, "", false
}

// isAllDigits 判断字符串是否全为数字（空串返回 false）。
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
