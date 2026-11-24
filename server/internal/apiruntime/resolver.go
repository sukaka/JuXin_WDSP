// resolver.go 采集端归属解析：app_code → application_id，hostname → domain_id。
// 正结果永久缓存；负结果（未知应用/域名）60 秒后重试，避免新接入应用长期不可见。
package apiruntime

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
)

// Resolver 归属解析接口（采集器依赖，便于单测注入假实现）。
type Resolver interface {
	ResolveApplication(ctx context.Context, code string) (*uuid.UUID, error)
	ResolveDomain(ctx context.Context, appID *uuid.UUID, hostname string) (*uuid.UUID, error)
}

// DomainAppResolver 可选扩展接口：按 Host/域名反查归属应用与域名 ID。
// 用于镜像旁路（mirrorcap）等无 app_code/application_id 的事件来源回填归属。
type DomainAppResolver interface {
	ResolveApplicationByDomain(ctx context.Context, hostname string) (appID *uuid.UUID, domID *uuid.UUID, err error)
}

type negativeEntry struct {
	at time.Time
}

type domainAppEntry struct {
	appID uuid.UUID
	domID uuid.UUID
}

const negativeRetryAfter = 60 * time.Second

// appResolver 基于 applications 仓储的缓存解析器（并发安全）。
type appResolver struct {
	store          *applications.Store
	mu             sync.Mutex
	apps           map[string]*uuid.UUID
	doms           map[string]*uuid.UUID // key: appID|lower(host)
	negA           map[string]negativeEntry
	negD           map[string]negativeEntry
	hostMap        map[string]domainAppEntry // normalized_hostname -> (appID, domID)
	hostMapLoaded  time.Time
}

// NewAppResolver 创建归属解析器。
func NewAppResolver(store *applications.Store) Resolver {
	return &appResolver{
		store: store,
		apps:  map[string]*uuid.UUID{},
		doms:  map[string]*uuid.UUID{},
		negA:  map[string]negativeEntry{},
		negD:  map[string]negativeEntry{},
	}
}

func (r *appResolver) ResolveApplication(ctx context.Context, code string) (*uuid.UUID, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, nil
	}
	r.mu.Lock()
	if id, ok := r.apps[code]; ok {
		r.mu.Unlock()
		return id, nil
	}
	if neg, ok := r.negA[code]; ok && time.Since(neg.at) < negativeRetryAfter {
		r.mu.Unlock()
		return nil, nil
	}
	r.mu.Unlock()

	app, err := r.store.GetByCode(ctx, code)
	if err != nil {
		r.mu.Lock()
		r.negA[code] = negativeEntry{at: time.Now()}
		r.mu.Unlock()
		return nil, nil // 未知应用按未归属处理（不视为错误，事件照常入库）
	}
	id := new(uuid.UUID)
	*id = app.ID
	r.mu.Lock()
	r.apps[code] = id
	delete(r.negA, code)
	r.mu.Unlock()
	return id, nil
}

func (r *appResolver) ResolveDomain(ctx context.Context, appID *uuid.UUID, hostname string) (*uuid.UUID, error) {
	host := strings.ToLower(strings.TrimSpace(hostname))
	if appID == nil || host == "" {
		return nil, nil
	}
	// 去掉端口
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	key := appID.String() + "|" + host
	r.mu.Lock()
	if id, ok := r.doms[key]; ok {
		r.mu.Unlock()
		return id, nil
	}
	if neg, ok := r.negD[key]; ok && time.Since(neg.at) < negativeRetryAfter {
		r.mu.Unlock()
		return nil, nil
	}
	r.mu.Unlock()

	domains, err := r.store.ListDomains(ctx, *appID)
	if err != nil {
		return nil, err // 查询失败如实返回错误（采集器记录日志）
	}
	var found *uuid.UUID
	for _, d := range domains {
		h := strings.ToLower(d.NormalizedHostname)
		if h == "" {
			h = strings.ToLower(d.Hostname)
		}
		if h == host {
			v := d.ID
			found = &v
			break
		}
	}
	r.mu.Lock()
	if found != nil {
		r.doms[key] = found
		delete(r.negD, key)
	} else {
		r.negD[key] = negativeEntry{at: time.Now()}
	}
	r.mu.Unlock()
	return found, nil
}

// ResolveApplicationByDomain 按 Host（去端口小写）反查归属应用与域名 ID（精确优先，次选 *. 泛域名）。
// 60s 周期刷新缓存，供 mirrorcap 旁路等不含 app_code/application_id 的事件自动归属应用。
func (r *appResolver) ResolveApplicationByDomain(ctx context.Context, hostname string) (*uuid.UUID, *uuid.UUID, error) {
	host := normalizeResolveHost(hostname)
	if host == "" || r.store == nil || r.store.DB() == nil {
		return nil, nil, nil
	}
	r.mu.Lock()
	entries := r.hostMap
	needRefresh := entries == nil || time.Since(r.hostMapLoaded) >= negativeRetryAfter
	r.mu.Unlock()

	if needRefresh {
		loaded, err := r.loadHostMap(ctx)
		if err != nil {
			if entries == nil {
				return nil, nil, err
			}
		} else {
			r.mu.Lock()
			r.hostMap = loaded
			r.hostMapLoaded = time.Now()
			entries = loaded
			r.mu.Unlock()
		}
	}
	if e, ok := matchHostEntry(host, entries); ok {
		a, d := e.appID, e.domID
		return &a, &d, nil
	}
	return nil, nil, nil
}

func (r *appResolver) loadHostMap(ctx context.Context) (map[string]domainAppEntry, error) {
	rows, err := r.store.DB().Query(ctx, `
SELECT d.normalized_hostname, d.hostname, d.application_id, d.id
FROM application_domains d
JOIN applications a ON a.id = d.application_id AND a.deleted_at IS NULL
ORDER BY (a.status = 'ACTIVE') DESC, (d.status = 'ACTIVE') DESC, (a.deployment_mode = 'MIRROR') DESC, d.created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]domainAppEntry)
	for rows.Next() {
		var norm, raw string
		var appID, domID uuid.UUID
		if err := rows.Scan(&norm, &raw, &appID, &domID); err != nil {
			return nil, err
		}
		key := strings.ToLower(strings.TrimSpace(norm))
		if key == "" {
			key = strings.ToLower(strings.TrimSpace(raw))
		}
		if key == "" {
			continue
		}
		if _, exists := out[key]; !exists {
			out[key] = domainAppEntry{appID: appID, domID: domID}
		}
	}
	return out, rows.Err()
}

func normalizeResolveHost(hostname string) string {
	host := strings.ToLower(strings.TrimSpace(hostname))
	if host == "" {
		return ""
	}
	if i := strings.LastIndex(host, ":"); i > 0 {
		allDigits := true
		for j := i + 1; j < len(host); j++ {
			if host[j] < '0' || host[j] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			host = host[:i]
		}
	}
	return host
}

func matchHostEntry(host string, entries map[string]domainAppEntry) (domainAppEntry, bool) {
	if len(entries) == 0 || host == "" {
		return domainAppEntry{}, false
	}
	if e, ok := entries[host]; ok {
		return e, true
	}
	var bestKey string
	var best domainAppEntry
	for key, e := range entries {
		if !strings.HasPrefix(key, "*.") {
			continue
		}
		if host == key[2:] || strings.HasSuffix(host, key[1:]) {
			// 更长后缀优先（更具体泛域名优先于更宽泛域名）
			if len(key) > len(bestKey) {
				bestKey = key
				best = e
			}
		}
	}
	if bestKey != "" {
		return best, true
	}
	return domainAppEntry{}, false
}
