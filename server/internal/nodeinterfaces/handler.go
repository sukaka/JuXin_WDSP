package nodeinterfaces

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// BridgePortChecker 检查节点上指定接口是否已作为网桥成员口（返回所属桥名；空串 = 未入桥）。
type BridgePortChecker func(ctx context.Context, nodeName, ifname string) (bridgeName string, err error)

// Handler 网口管理处理器。
type Handler struct {
	store         Repository
	audits        *audits.Service
	onChange      func(ctx context.Context)
	bridgeChecker BridgePortChecker
}

// NewHandler 创建处理器（构造注入审计服务，语义同 customrules）。
func NewHandler(store Repository, audit *audits.Service) *Handler {
	return &Handler{store: store, audits: audit}
}

// SetOnChange 注册网口角色/排序变更后的联动回调（如刷新 mirrorcap.json 边车配置）。
func (h *Handler) SetOnChange(fn func(ctx context.Context)) *Handler {
	h.onChange = fn
	return h
}

// SetBridgePortChecker 注入网桥成员口检查器：禁止将已加入网桥的接口设为 MANAGEMENT 或 MIRROR 角色。
func (h *Handler) SetBridgePortChecker(fn BridgePortChecker) *Handler {
	h.bridgeChecker = fn
	return h
}

// RegisterRoutes 注册网口管理接口（权限：读 system_health.read，排序/角色 system_settings.update，
// 复用既有权限点不新增，见 docs/NETWORK_MODES_DESIGN.md §2.4）。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/gateway/interfaces", authz(middleware.RequirePermission("system_health.read")(http.HandlerFunc(h.List))))
	mux.Handle("PUT /api/v1/gateway/interfaces/order", authz(middleware.RequirePermission("system_settings.update")(http.HandlerFunc(h.UpdateOrder))))
}

// List GET /api/v1/gateway/interfaces?node_name=
// 按节点分组返回网口清单（组内 sort_order 升序）；node_name 为空时返回全部节点。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	nodeName := strings.TrimSpace(r.URL.Query().Get("node_name"))
	groups, err := h.store.ListGrouped(r.Context(), nodeName)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if groups == nil {
		groups = []NodeInterfaces{}
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"nodes": groups})
}

type updateOrderRequest struct {
	NodeName string      `json:"node_name"`
	Items    []OrderItem `json:"items"`
}

// UpdateOrder PUT /api/v1/gateway/interfaces/order
// 整体替换节点下指定接口的排序与角色（role 恒传，空串 = 清除角色；词表 MANAGEMENT/TRAFFIC/MIRROR），
// 写操作审计（LOW）。
func (h *Handler) UpdateOrder(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req updateOrderRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	req.NodeName = strings.TrimSpace(req.NodeName)
	if req.NodeName == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "node_name 不能为空")
		return
	}
	if len(req.Items) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "items 不能为空")
		return
	}
	if len(req.Items) > 128 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "items 数量超出上限（128）")
		return
	}
	seen := make(map[string]bool, len(req.Items))
	for i := range req.Items {
		it := &req.Items[i]
		it.Ifname = strings.TrimSpace(it.Ifname)
		if it.Ifname == "" {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "ifname 不能为空")
			return
		}
		if seen[it.Ifname] {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "ifname 重复: "+it.Ifname)
			return
		}
		seen[it.Ifname] = true
		if it.SortOrder < 0 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "sort_order 不能为负数")
			return
		}
		it.Role = strings.TrimSpace(it.Role)
		if !ValidRole(it.Role) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				"role 取值非法（允许 MANAGEMENT/TRAFFIC/MIRROR 或空串）")
			return
		}
		if h.bridgeChecker != nil && (it.Role == RoleManagement || it.Role == RoleMirror) {
			bridgeName, err := h.bridgeChecker(r.Context(), req.NodeName, it.Ifname)
			if err != nil {
				response.InternalError(w, r, err)
				return
			}
			if bridgeName != "" {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
					fmt.Sprintf("接口 %s 已加入网桥 %s，禁止设为 %s 角色（请先从网桥移除）", it.Ifname, bridgeName, it.Role))
				return
			}
		}
	}

	// 审计 before 摘要（读取失败不阻断主流程，降级为空摘要并记日志）
	before := ""
	if groups, err := h.store.ListGrouped(r.Context(), req.NodeName); err != nil {
		slog.Warn("load interfaces for audit before-summary failed", "node", req.NodeName, "error", err)
	} else {
		before = orderSummary(groups)
	}

	if err := h.store.ReplaceOrder(r.Context(), req.NodeName, req.Items); err != nil {
		if errors.Is(err, ErrUnknownInterface) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				"接口不存在于该节点: "+strings.TrimPrefix(err.Error(), ErrUnknownInterface.Error()+": "))
			return
		}
		response.InternalError(w, r, err)
		return
	}

	if h.onChange != nil {
		h.onChange(r.Context())
	}
	groups, err := h.store.ListGrouped(r.Context(), req.NodeName)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if h.audits != nil && p != nil {
		if err := h.audits.Record(r.Context(), audits.RecordInput{
			UserID:        &p.UserID,
			Username:      p.Username,
			SourceIP:      middleware.RemoteIP(r),
			ConnectionIP:  middleware.ConnectionIP(r),
			UserAgent:     r.UserAgent(),
			Module:        "system",
			Action:        "update_gateway_interface_order",
			ObjectType:    "gateway_node_interfaces",
			ObjectID:      req.NodeName,
			ObjectName:    req.NodeName,
			BeforeSummary: before,
			AfterSummary:  orderSummary(groups),
			Result:        audits.ResultSuccess,
			RiskLevel:     audits.RiskLow,
			RequestID:     response.RequestIDFrom(r),
		}); err != nil {
			slog.Error("record interface order audit failed", "node", req.NodeName, "error", err)
		}
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"nodes": groups})
}

// orderSummary 生成排序审计摘要（ifname/sort_order/role 紧凑列表，截断防爆长）。
func orderSummary(groups []NodeInterfaces) string {
	type entry struct {
		Ifname    string `json:"ifname"`
		SortOrder int    `json:"sort_order"`
		Role      string `json:"role,omitempty"`
	}
	var list []entry
	for _, g := range groups {
		for _, it := range g.Interfaces {
			list = append(list, entry{Ifname: it.Ifname, SortOrder: it.SortOrder, Role: it.Role})
		}
	}
	raw, err := json.Marshal(map[string]interface{}{"items": list})
	if err != nil {
		return ""
	}
	const limit = 4000
	if len(raw) > limit {
		return string(raw[:limit])
	}
	return string(raw)
}
