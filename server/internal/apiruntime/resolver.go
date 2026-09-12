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

type negativeEntry struct {
	at time.Time
}

const negativeRetryAfter = 60 * time.Second

// appResolver 基于 applications 仓储的缓存解析器（并发安全）。
type appResolver struct {
	store *applications.Store
	mu    sync.Mutex
	apps  map[string]*uuid.UUID
	doms  map[string]*uuid.UUID // key: appID|lower(host)
	negA  map[string]negativeEntry
	negD  map[string]negativeEntry
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
