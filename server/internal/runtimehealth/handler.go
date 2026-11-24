package runtimehealth

import (
	"context"
	"net/http"
	"time"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/response"
)

type snapshotStore interface {
	LatestAll(ctx context.Context) ([]Snapshot, error)
	LatestByComponent(ctx context.Context, component string) (*Snapshot, error)
	HistoryByComponent(ctx context.Context, component string, since time.Time, limit int) ([]Snapshot, error)
}

// GatewayRuntimeProvider abstracts read-only gateway runtime snapshot & history queries.
type GatewayRuntimeProvider interface {
	GetRuntimeSnapshot(ctx context.Context) (*gatewayconfig.GatewayRuntimeSnapshot, error)
	GetRuntimeHistory(ctx context.Context) (*gatewayconfig.GatewayRuntimeHistory, error)
}

// AppMeta holds application code and display name resolved from applications table.
type AppMeta struct {
	Code string
	Name string
}

// AppNameLookupFunc resolves application IDs to their code and display name.
type AppNameLookupFunc func(ctx context.Context, appIDs []string) (map[string]AppMeta, error)

// Handler 是运行监控处理器。
type Handler struct {
	store           snapshotStore
	storage         *StorageProbe
	gatewayProvider GatewayRuntimeProvider
	appNameLookup   AppNameLookupFunc
	now             func() time.Time
}

// NewHandler 创建处理器。
func NewHandler(store *Store, storage *StorageProbe) *Handler {
	var st snapshotStore
	if store != nil {
		st = store
	}
	return &Handler{store: st, storage: storage, now: func() time.Time { return time.Now().UTC() }}
}

// SetGatewayRuntimeProvider 注入网关实时运行指标读取器（可选，nil 时自动降级查库）。
func (h *Handler) SetGatewayRuntimeProvider(provider GatewayRuntimeProvider) {
	h.gatewayProvider = provider
}

// SetAppNameLookup 注入应用 ID 到编码/名称的查询函数（可选，缺失或出错时降级用 app_id 本身）。
func (h *Handler) SetAppNameLookup(fn AppNameLookupFunc) {
	h.appNameLookup = fn
}

// OverallStatus 汇总整体状态：DOWN > DEGRADED > UNKNOWN > UP。
func OverallStatus(statuses []string) string {
	worst := StatusUp
	rank := map[string]int{StatusUp: 0, StatusUnknown: 1, StatusDegraded: 2, StatusDown: 3}
	for _, s := range statuses {
		if rank[s] > rank[worst] {
			worst = s
		}
	}
	return worst
}

// SystemHealth 系统健康汇总（GET /system-health）。
func (h *Handler) SystemHealth(w http.ResponseWriter, r *http.Request) {
	snaps, err := h.store.LatestAll(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	byComponent := make(map[string]*Snapshot, len(snaps))
	statuses := make([]string, 0, len(snaps))
	counts := map[string]int{StatusUp: 0, StatusDown: 0, StatusDegraded: 0, StatusUnknown: 0}
	for i := range snaps {
		byComponent[snaps[i].Component] = &snaps[i]
		statuses = append(statuses, snaps[i].Status)
		counts[snaps[i].Status]++
	}
	// 未采集到的组件按 UNKNOWN 计入
	missing := []string{}
	for _, comp := range AllComponents() {
		if _, ok := byComponent[comp]; !ok {
			missing = append(missing, comp)
			counts[StatusUnknown]++
			statuses = append(statuses, StatusUnknown)
		}
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"status":             OverallStatus(statuses),
		"status_counts":      counts,
		"components":         snaps,
		"missing_components": missing,
		"checked_at":         h.now(),
	})
}

// Components 各组件最新快照（GET /system-health/components）。
func (h *Handler) Components(w http.ResponseWriter, r *http.Request) {
	snaps, err := h.store.LatestAll(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if snaps == nil {
		snaps = []Snapshot{}
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"components": snaps,
		"checked_at": h.now(),
	})
}

// Storage 存储监控（GET /system-health/storage）。
func (h *Handler) Storage(w http.ResponseWriter, r *http.Request) {
	stats, err := h.storage.Collect(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, stats)
}
