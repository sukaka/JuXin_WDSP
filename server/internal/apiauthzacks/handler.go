// handler.go 节点授权 ACK 查询 API（NG-AZ-02 §1.4/D6）：
//
//	GET /api/v1/api-security/authz/node-acks  全节点 ACK 视图（api_authorization.read）
//
// 只读端点：无写操作、无新权限点（读沿用 api_authorization.read，000048 已种，
// 与 000169/000170 先例一致），故无 CSRF/审计——与 authorities 只读端点同纪律。
package apiauthzacks

import (
	"context"
	"net/http"
	"time"

	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// PermAuthzRead 权限点（种子见迁移 000048；与 apiauthzauthority 只读端点同一点，
// 本包自定义常量避免耦合并行开发中的兄弟包）。
const PermAuthzRead = "api_authorization.read"

// StoreAPI 仓储接口（*Store 实现；测试注入 fake）。
type StoreAPI interface {
	ListNodeAcks(ctx context.Context) ([]AckRow, error)
	ManagementWatermark(ctx context.Context) (apiruntime.VectorWatermark, error)
}

// SettingsReader 时钟漂移上限读取（*settings.Service 实现；nil = 常量默认 60s，
// 见 derive.go 上限注释——系统设置机制存在时经 authz.clock_skew_max_seconds 覆盖）。
type SettingsReader interface {
	GetInt(ctx context.Context, group, key string, def int) int
}

// Handler 节点授权 ACK 查询处理器。
type Handler struct {
	store    StoreAPI
	settings SettingsReader
	now      func() time.Time // 测试注入；nil = time.Now
}

// NewHandler 创建处理器。
func NewHandler(store StoreAPI, settings SettingsReader) *Handler {
	return &Handler{store: store, settings: settings}
}

// RegisterRoutes 注册路由（/api/v1/api-security/authz 命名空间）。
func RegisterRoutes(mux *http.ServeMux, authzFn func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/authz/node-acks",
		authzFn(middleware.RequirePermission(PermAuthzRead)(http.HandlerFunc(h.List))))
}

// List GET /api/v1/api-security/authz/node-acks
// 全节点 ACK 视图：ack_state 五态派生 + 最大陈旧窗口 + 管理面向量水位（§8.3-5
// 「必须显示未 ACK 节点及最大陈旧窗口」的直接载体）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.store.ListNodeAcks(ctx)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	mgmt, err := h.store.ManagementWatermark(ctx)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	now := time.Now().UTC()
	if h.now != nil {
		now = h.now()
	}
	response.JSON(w, r, http.StatusOK, BuildView(rows, mgmt, now, h.clockSkewMaxSeconds(ctx)))
}

// clockSkewMaxSeconds 漂移上限：系统设置覆盖（读取失败由 settings 层回落默认值），
// 夹紧 10~300s（D8）。
func (h *Handler) clockSkewMaxSeconds(ctx context.Context) int64 {
	v := DefaultClockSkewMaxSeconds
	if h.settings != nil {
		v = h.settings.GetInt(ctx, "authz", "clock_skew_max_seconds", DefaultClockSkewMaxSeconds)
	}
	return clampClockSkewMax(v)
}
