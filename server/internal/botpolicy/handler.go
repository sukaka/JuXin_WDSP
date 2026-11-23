// handler.go Bot 挑战策略管理面接口（WDSP P1-02 B1；路由在 app.go 注册）：
//
//	GET  /api/v1/applications/{id}/bot-policy           读取草稿+发布/节点同步状态摘要
//	      （bot_policy.read；草稿版本、发布批次、节点有效版本分离返回，不混成一个 enabled）
//	PUT  /api/v1/applications/{id}/bot-policy           校验并全量保存草稿（bot_policy.edit；
//	      expected_version 乐观锁冲突 409、非法 400、应用不存在 404；保存成功触发既有
//	      gateway-config 发布通道——bot_policy 段随整站快照下发，保存草稿不等于节点已生效）
//	POST /api/v1/applications/{id}/bot-policy/preflight 路由保留冲突预检（bot_policy.edit；
//	      保留命名空间与 L7 拒绝规则/保护地址/既有应用路径/路径转发的冲突列表 +
//	      PROTECT 共享状态依赖、key_ref 签名密钥就绪与节点状态检查；不保存、不自动发布）
//
// 发布链路纪律（与 guardconfig/bot_policy.go 同源）：读取失败中止发布（fail-hard）；
// 存在 PROTECT 策略而共享状态存储（Valkey）未配置、或 key_ref 引用的签名密钥未就绪时
// 拒绝发布。挑战生成/verify 端点/Eval 处置在网关侧 botchallenge/bot_step（B2/B3）。
package botpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apinodes"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/guardconfig"
	"github.com/jiuzhang-waf/server/internal/l7rules"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
	"github.com/jiuzhang-waf/server/internal/response"
)

// AppGetter 应用查询接口（applications.Store 实现；不存在 → 404）。
type AppGetter interface {
	GetByID(ctx context.Context, id uuid.UUID) (*applications.Application, error)
}

// NodeLister 网关节点查询接口（apinodes.Store 实现；GET 节点同步状态摘要与
// 预检节点检查用——已知同步失败的节点不接收含 PROTECT 的新配置）。
type NodeLister interface {
	ListNodes(ctx context.Context) ([]apinodes.Node, error)
}

// L7RuleLister L7 访问控制规则读取接口（l7rules.Store 实现；预检拒绝规则冲突用——
// 规则为全局生效，命中保留命名空间的拒绝规则会把挑战 verify 挡在 Bot 步骤之前形成循环）。
type L7RuleLister interface {
	ListAllOrdered(ctx context.Context) ([]l7rules.Rule, error)
}

// PathRouteLister 应用路径转发读取接口（appconfigs.Store 实现；预检路径转发冲突用——
// 覆盖保留命名空间的前缀会把 verify 转发到源站，违反「保留端点永不反向代理」）。
type PathRouteLister interface {
	ListEnabledPathRoutes(ctx context.Context, appID uuid.UUID) ([]gatewayconfig.AppPathRoute, error)
}

// ProtectedLister 保护地址读取接口（protectedaddresses.Store 实现；预检范围提示用——
// 保护地址来源跳过封禁/CC 等前置检查，与「内部端点仍经过前面检查」的口径需操作者知悉）。
type ProtectedLister interface {
	List(ctx context.Context, addressType string) ([]protectedaddresses.ProtectedAddress, error)
}

// SharedStateFunc 共享状态存储（Valkey）就绪读取（装配层注入；
// 与发布门禁 checkBotPolicyDeps 同口径：PROTECT 无共享状态必然全站 fail-closed 503）。
type SharedStateFunc func(ctx context.Context) bool

// PublishFunc 发布触发函数（app 装配注入 gatewayconfig.Publisher.Publish；nil = 发布通道不可用）。
type PublishFunc func(ctx context.Context, uid uuid.UUID, requestID string)

// Handler 是 Bot 挑战策略处理器。
type Handler struct {
	store       *Store
	apps        AppGetter
	audits      *audits.Service
	publish     PublishFunc
	nodes       NodeLister
	l7          L7RuleLister
	pathRoutes  PathRouteLister
	protected   ProtectedLister
	sharedState SharedStateFunc
	signingKeys guardconfig.BotSigningKeysLoader
}

// NewHandler 创建处理器。
func NewHandler(store *Store, apps AppGetter, au *audits.Service) *Handler {
	return &Handler{store: store, apps: apps, audits: au}
}

// SetPublishFunc 注入发布触发函数（publisher 不可用时保持 nil：策略落库成功但不下发，
// 与装配层其他策略同一口径——发布通道恢复后任意发布动作即带上最新策略）。
func (h *Handler) SetPublishFunc(fn PublishFunc) { h.publish = fn }

// SetNodeLister 注入网关节点查询（GET 状态摘要与预检节点检查用）。
func (h *Handler) SetNodeLister(l NodeLister) { h.nodes = l }

// SetL7RuleLister 注入 L7 规则读取（预检拒绝规则冲突用）。
func (h *Handler) SetL7RuleLister(l L7RuleLister) { h.l7 = l }

// SetPathRouteLister 注入路径转发读取（预检路径转发冲突用）。
func (h *Handler) SetPathRouteLister(l PathRouteLister) { h.pathRoutes = l }

// SetProtectedLister 注入保护地址读取（预检范围提示用）。
func (h *Handler) SetProtectedLister(l ProtectedLister) { h.protected = l }

// SetSharedStateFunc 注入共享状态存储就绪读取（预检与发布门禁同口径）。
func (h *Handler) SetSharedStateFunc(fn SharedStateFunc) { h.sharedState = fn }

// SetSigningKeysLoader 注入 Bot 签名密钥读取（预检 signing_key 检查用；
// 与发布门禁 checkBotPolicyDeps 的 key_ref 就绪判定同一加载器与同一口径——
// guardconfig.NewBotSigningKeysLoader 一行接线，nil = 未装配视同密钥未就绪）。
func (h *Handler) SetSigningKeysLoader(l guardconfig.BotSigningKeysLoader) { h.signingKeys = l }

// ---------- 请求/响应 DTO ----------

// challengeRequest 挑战参数请求（指针字段区分「未提供=默认值」与显式 0——显式 0
// 进入校验按越界拒绝；key_ref 仅引用名，不承接任何密钥材料）。
type challengeRequest struct {
	Type                string `json:"type"`
	NonceTTLSeconds     *int   `json:"nonce_ttl_seconds"`
	ClearanceTTLSeconds *int   `json:"clearance_ttl_seconds"`
	Difficulty          *int   `json:"difficulty"`
	MaxAttempts         *int   `json:"max_attempts"`
	KeyRef              string `json:"key_ref"`
}

// signalRulesRequest 信号判定请求（指针字段区分「未提供=B0 默认」与显式值——
// 显式 require_behavior_group=false 进入校验按契约拒绝）。
type signalRulesRequest struct {
	MinIndependentGroups *int         `json:"min_independent_groups"`
	RequireBehaviorGroup *bool        `json:"require_behavior_group"`
	Rules                []SignalRule `json:"rules"`
}

// putRequest PUT 请求体（全量草稿 + 乐观锁 + 变更理由；显式承接字段，
// id/application_id/version/updated_by 为服务端字段，请求体不承接）。
type putRequest struct {
	Mode             string              `json:"mode"`
	ExpectedVersion  int                 `json:"expected_version"`
	Selectors        []Selector          `json:"selectors"`
	SignalRules      *signalRulesRequest `json:"signal_rules"`
	Challenge        *challengeRequest   `json:"challenge"`
	RouteReservation *RouteReservation   `json:"route_reservation"`
	Reason           string              `json:"reason"`
}

// toPolicy 转换为领域策略（缺省段应用 B0 默认值；未归一化——Normalize 由调用方执行）。
func (r *putRequest) toPolicy(appID uuid.UUID) *Policy {
	p := &Policy{
		ApplicationID:    appID,
		Mode:             strings.ToUpper(strings.TrimSpace(r.Mode)),
		Selectors:        append([]Selector{}, r.Selectors...),
		SignalRules:      DefaultSignalRules(),
		Challenge:        DefaultChallenge(),
		RouteReservation: RouteReservation{State: ReservationReleased, Namespace: ReservedNamespace},
	}
	if r.SignalRules != nil {
		if r.SignalRules.MinIndependentGroups != nil {
			p.SignalRules.MinIndependentGroups = *r.SignalRules.MinIndependentGroups
		}
		if r.SignalRules.RequireBehaviorGroup != nil {
			p.SignalRules.RequireBehaviorGroup = *r.SignalRules.RequireBehaviorGroup
		}
		if r.SignalRules.Rules != nil {
			p.SignalRules.Rules = append([]SignalRule{}, r.SignalRules.Rules...)
		}
	}
	if r.Challenge != nil {
		if r.Challenge.Type != "" {
			p.Challenge.Type = strings.ToUpper(strings.TrimSpace(r.Challenge.Type))
		}
		if r.Challenge.NonceTTLSeconds != nil {
			p.Challenge.NonceTTLSeconds = *r.Challenge.NonceTTLSeconds
		}
		if r.Challenge.ClearanceTTLSeconds != nil {
			p.Challenge.ClearanceTTLSeconds = *r.Challenge.ClearanceTTLSeconds
		}
		if r.Challenge.Difficulty != nil {
			p.Challenge.Difficulty = *r.Challenge.Difficulty
		}
		if r.Challenge.MaxAttempts != nil {
			p.Challenge.MaxAttempts = *r.Challenge.MaxAttempts
		}
		p.Challenge.KeyRef = r.Challenge.KeyRef
	}
	if r.RouteReservation != nil {
		p.RouteReservation = *r.RouteReservation
		if p.RouteReservation.Namespace == "" {
			p.RouteReservation.Namespace = ReservedNamespace
		}
	}
	return p
}

// ---------- GET ----------

// Get 读取应用 Bot 策略（草稿 + 最近成功发布快照中的生效状态 + 节点同步状态摘要；
// 无记录返回默认 OFF 空策略 version=0）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	app, ok := h.resolveApp(w, r)
	if !ok {
		return
	}
	p, err := h.store.GetByApp(r.Context(), app.ID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			p = DefaultPolicy(app.ID)
		} else {
			response.InternalError(w, r, err)
			return
		}
	}
	summary, err := h.buildSummary(r.Context(), app.Code, p)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"policy":  p,
		"summary": summary,
	})
}

// buildSummary 构造状态摘要（草稿版本 vs 发布批次 vs 节点有效版本分离——
// 发布失败不回退草稿，旧有效版本继续运行；节点查询未装配时省略 nodes）。
func (h *Handler) buildSummary(ctx context.Context, appCode string, p *Policy) (StatusSummary, error) {
	published, err := h.store.LatestPublishState(ctx, appCode)
	if err != nil {
		return StatusSummary{}, err
	}
	summary := StatusSummary{
		State:        StateNotConfigured,
		DraftVersion: p.Version,
		Published:    published,
	}
	if p.Version > 0 {
		if published.Found && published.PolicyVersion == p.Version {
			summary.State = StatePublished
		} else {
			summary.State = StateDraftPending
		}
	}
	if h.nodes == nil {
		return summary, nil
	}
	nodes, err := h.nodes.ListNodes(ctx)
	if err != nil {
		return StatusSummary{}, fmt.Errorf("list gateway nodes: %w", err)
	}
	out := []NodeSyncState{}
	for _, n := range nodes {
		if !n.SyncEnabled {
			continue
		}
		st := NodeSyncState{
			NodeName:          n.NodeName,
			LastSyncResult:    n.LastSyncResult,
			LastSyncVersionID: n.LastSyncVersionID,
		}
		st.Effective = published.Found && n.LastSyncVersionID != nil && *n.LastSyncVersionID == published.VersionID
		out = append(out, st)
	}
	summary.Nodes = out
	return summary, nil
}

// ---------- PUT ----------

// Put 校验并保存草稿（expected_version 乐观锁冲突 409；保存成功写操作审计并触发
// 既有发布通道——bot_policy 段随整站快照下发；触发失败仅记日志，策略已落库，
// 发布任务可追踪重试，与其他策略变更同一口径）。
func (h *Handler) Put(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	app, ok := h.resolveApp(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetByApp(r.Context(), app.ID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		response.InternalError(w, r, err)
		return
	}

	var req putRequest
	if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过",
			[]FieldError{{Field: "reason", Message: "变更理由不能为空"}})
		return
	}
	if len(req.Reason) > MaxReasonLen {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过",
			[]FieldError{{Field: "reason", Message: fmt.Sprintf("变更理由不能超过 %d 字符", MaxReasonLen)}})
		return
	}
	if req.ExpectedVersion < 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过",
			[]FieldError{{Field: "expected_version", Message: "expected_version 不能为负数"}})
		return
	}
	// 已有草稿时不允许再以 expected_version=0 创建；无草稿时必须以 0 创建
	if before != nil && req.ExpectedVersion == 0 {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
		return
	}
	if before == nil && req.ExpectedVersion != 0 {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
		return
	}

	p := req.toPolicy(app.ID)
	// 路由保留生命周期：请求未携带时沿用上版草稿状态（防全量替换静默解除墓碑保留；
	// 状态机流转由操作者显式给出——从已启用状态关闭应显式置 RESERVED_TOMBSTONE）
	if req.RouteReservation == nil && before != nil {
		p.RouteReservation = before.RouteReservation
	}
	Normalize(p)
	if errs := ValidateStructure(p); len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过", errs)
		return
	}

	if err := h.store.SaveDraft(r.Context(), p, req.ExpectedVersion, req.Reason, principal.Username); err != nil {
		if errors.Is(err, ErrConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
			return
		}
		var ve *ValidationError
		if errors.As(err, &ve) {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过", ve.Errors)
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, principal, "update", app, before, p, req.Reason, audits.ResultSuccess, "")

	// 触发网关配置发布（bot_policy 段随整站快照下发；发布通道不可用/触发失败仅记日志，
	// 策略本身已落库——发布为独立任务可追踪重试，与行为/风险策略变更同一口径）
	if h.publish != nil {
		h.publish(context.Background(), principal.UserID,
			fmt.Sprintf("bot-policy-%s-v%d", app.Code, p.Version))
	} else {
		slog.Warn("bot policy saved but publish channel unavailable, gateway sync deferred")
	}

	final, err := h.store.GetByApp(r.Context(), app.ID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"policy": final})
}

// ---------- Preflight ----------

// PreflightCheck 单项预检结果（PASS/FAIL/WARN/SKIP）。
type PreflightCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// 预检状态词表。
const (
	CheckPass = "PASS"
	CheckFail = "FAIL"
	CheckWarn = "WARN"
	CheckSkip = "SKIP"
)

// RouteConflict 保留路由冲突条目（type 区分冲突来源；status=FAIL 阻断发布，
// WARN 仅提示——冲突列表随预检响应返回，供 UI 逐项展示）。
type RouteConflict struct {
	Type    string `json:"type"`    // l7_deny_rule | l7_allow_rule | reserved_path_asset | path_route | protected_address_scope
	Status  string `json:"status"`  // FAIL | WARN
	Message string `json:"message"` // 可读原因（不含秘密材料）
	Ref     string `json:"ref"`     // 定位信息（规则名/路径/地址段）
}

// preflightRequest 预检请求体（全部缺省时检查当前草稿；不保存、不发布）。
type preflightRequest struct {
	Mode             string              `json:"mode"`
	Selectors        []Selector          `json:"selectors"`
	SignalRules      *signalRulesRequest `json:"signal_rules"`
	Challenge        *challengeRequest   `json:"challenge"`
	RouteReservation *RouteReservation   `json:"route_reservation"`
}

// Preflight 路由保留冲突预检：结构校验、保留命名空间与 L7 拒绝/放行规则、
// 既有应用路径（api_endpoints 登记）、路径转发、保护地址范围的冲突列表，
// 以及 PROTECT 共享状态依赖与目标节点状态检查（与发布链路同口径——
// publishable=false 时发布将以同口径拒绝或于网关侧 fail-closed）。不保存、不发布。
func (h *Handler) Preflight(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	app, ok := h.resolveApp(w, r)
	if !ok {
		return
	}
	var req preflightRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
			return
		}
	}

	// 评估对象：请求体提供的候选策略，否则当前草稿（无草稿=默认 OFF）
	var p *Policy
	if req.Mode != "" || req.Selectors != nil || req.SignalRules != nil || req.Challenge != nil || req.RouteReservation != nil {
		put := putRequest{
			Mode:             req.Mode,
			Selectors:        req.Selectors,
			SignalRules:      req.SignalRules,
			Challenge:        req.Challenge,
			RouteReservation: req.RouteReservation,
		}
		p = put.toPolicy(app.ID)
		// 与 PUT 同一口径：候选未给路由保留时沿用当前草稿状态
		if req.RouteReservation == nil {
			if before, err := h.store.GetByApp(r.Context(), app.ID); err == nil {
				p.RouteReservation = before.RouteReservation
			} else if !errors.Is(err, ErrNotFound) {
				response.InternalError(w, r, err)
				return
			}
		}
		Normalize(p)
	} else {
		var err error
		p, err = h.store.GetByApp(r.Context(), app.ID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				p = DefaultPolicy(app.ID)
			} else {
				response.InternalError(w, r, err)
				return
			}
		}
	}

	checks := []PreflightCheck{}
	conflicts := []RouteConflict{}
	publishable := true
	fail := func(name, msg string) {
		checks = append(checks, PreflightCheck{Name: name, Status: CheckFail, Message: msg})
		publishable = false
	}

	// 1. 结构校验（与保存同一校验函数）
	if errs := ValidateStructure(p); len(errs) > 0 {
		msg, _ := json.Marshal(errs)
		fail("structure", "结构校验未通过: "+string(msg))
	} else {
		checks = append(checks, PreflightCheck{Name: "structure", Status: CheckPass, Message: "结构校验通过"})
	}

	// 2. 路由保留冲突（保留路由注册期间——非 OFF 或保留未解除——才有冲突面；
	// 首次 OFF 且从未启用的应用不抢占业务路径，无冲突面）
	if p.Mode != ModeOff || p.RouteReservation.State != ReservationReleased {
		conflicts = append(conflicts, h.routeConflicts(r.Context(), app.ID)...)
	} else {
		checks = append(checks, PreflightCheck{Name: "route_conflicts", Status: CheckSkip,
			Message: "OFF 且保留已解除：不注册保留路由，无冲突面"})
	}
	failConflicts := 0
	for _, c := range conflicts {
		if c.Status == CheckFail {
			failConflicts++
		}
	}
	if p.Mode != ModeOff || p.RouteReservation.State != ReservationReleased {
		switch {
		case failConflicts > 0:
			publishable = false
			checks = append(checks, PreflightCheck{Name: "route_conflicts", Status: CheckFail,
				Message: fmt.Sprintf("保留命名空间 %s 存在 %d 项阻断性冲突（详见 conflicts）：有冲突拒绝发布，请调整自身路径/规则或在 S0 更换保留命名空间", ReservedNamespace, failConflicts)})
		case len(conflicts) > 0:
			checks = append(checks, PreflightCheck{Name: "route_conflicts", Status: CheckWarn,
				Message: fmt.Sprintf("保留命名空间 %s 存在 %d 项提示性冲突（详见 conflicts）", ReservedNamespace, len(conflicts))})
		default:
			checks = append(checks, PreflightCheck{Name: "route_conflicts", Status: CheckPass,
				Message: "保留命名空间与 L7 规则/既有应用路径/路径转发/保护地址无冲突"})
		}
	}

	// 3. 共享状态依赖（与发布门禁 checkBotPolicyDeps 同口径：PROTECT 无共享 Valkey
	// 必然全站 fail-closed 503；OBSERVE 判定状态缺失时仅降级观测，不阻断）
	switch p.Mode {
	case ModeProtect:
		if h.sharedState == nil || !h.sharedState(r.Context()) {
			fail("shared_state", "共享状态存储（Valkey）未配置：挑战 nonce 与通行状态依赖共享 Valkey（键前缀 "+ValkeyKeyPrefix+"），PROTECT 发布会把网关置于全站 fail-closed 503，拒绝发布")
		} else {
			checks = append(checks, PreflightCheck{Name: "shared_state", Status: CheckPass, Message: "共享状态存储（Valkey）已配置"})
		}
	case ModeObserve:
		if h.sharedState == nil || !h.sharedState(r.Context()) {
			checks = append(checks, PreflightCheck{Name: "shared_state", Status: CheckWarn,
				Message: "共享状态存储（Valkey）未配置：OBSERVE 判定状态不可用时应答 UNKNOWN/UNAVAILABLE，不阻断但观测失真"})
		} else {
			checks = append(checks, PreflightCheck{Name: "shared_state", Status: CheckPass, Message: "共享状态存储（Valkey）已配置"})
		}
	default:
		checks = append(checks, PreflightCheck{Name: "shared_state", Status: CheckSkip, Message: "OFF 不初始化挑战依赖"})
	}

	// 3.5 签名密钥就绪（与发布门禁 checkBotPolicyDeps 的 key_ref 判定同一加载器、同一口径：
	// PROTECT 的 challenge.key_ref 未在已配置密钥集合中就绪时拒绝发布——防新 key 未安装
	// 导致网关全站挑战 fail-closed 503；OBSERVE 未就绪仅降级观测，WARN 不阻断）
	switch p.Mode {
	case ModeProtect:
		keyErr := ""
		ready := false
		if h.signingKeys == nil {
			keyErr = "签名密钥加载器未装配"
		} else if keys, err := h.signingKeys(r.Context()); err != nil {
			keyErr = "签名密钥读取失败: " + err.Error()
		} else if kr := p.Challenge.KeyRef; kr == "" {
			keyErr = "challenge.key_ref 未配置"
		} else if keys[kr] != "" {
			ready = true
		} else {
			keyErr = fmt.Sprintf("key_ref %q 未在已配置签名密钥集合中就绪", kr)
		}
		if !ready {
			fail("signing_key", "签名密钥未就绪（"+keyErr+"）：密钥须经系统设置 gateway_runtime.bot_signing_keys 配置并随发布下发，缺少密钥时网关对挑战/通行只能 fail-closed 503，拒绝发布（多节点先完成密钥准备再发布策略）")
		} else {
			checks = append(checks, PreflightCheck{Name: "signing_key", Status: CheckPass, Message: "challenge.key_ref 引用的签名密钥已就绪"})
		}
	case ModeObserve:
		ready := false
		if h.signingKeys != nil && p.Challenge.KeyRef != "" {
			if keys, err := h.signingKeys(r.Context()); err == nil && keys[p.Challenge.KeyRef] != "" {
				ready = true
			}
		}
		if !ready {
			checks = append(checks, PreflightCheck{Name: "signing_key", Status: CheckWarn,
				Message: "签名密钥未就绪：OBSERVE 不签发挑战不阻断，但网关侧挑战服务将降级（观测失真）"})
		} else {
			checks = append(checks, PreflightCheck{Name: "signing_key", Status: CheckPass, Message: "challenge.key_ref 引用的签名密钥已就绪"})
		}
	default:
		checks = append(checks, PreflightCheck{Name: "signing_key", Status: CheckSkip, Message: "OFF 不初始化挑战依赖"})
	}

	// 4. 目标节点状态（已知同步失败的扇出节点不接收含 PROTECT 的新配置）
	checks = append(checks, h.nodeChecks(p.Mode == ModeProtect, &publishable)...)

	h.recordAudit(r, principal, "preflight", app, nil, p, "", audits.ResultSuccess, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"policy":      p,
		"checks":      checks,
		"conflicts":   conflicts,
		"publishable": publishable,
	})
}

// routeConflicts 保留命名空间冲突扫描（数据源全部读取失败如实返回错误降级 FAIL 项，
// 不静默放行——预检失真比拒绝更危险）。
func (h *Handler) routeConflicts(ctx context.Context, appID uuid.UUID) []RouteConflict {
	out := []RouteConflict{}
	out = append(out, h.l7Conflicts(ctx)...)
	out = append(out, h.assetConflicts(ctx, appID)...)
	out = append(out, h.pathRouteConflicts(ctx, appID)...)
	out = append(out, h.protectedScopeConflicts(ctx)...)
	return out
}

// l7Conflicts L7 规则冲突：拒绝类动作（block/redirect/custom_page）确定性覆盖 verify
// 端点 → FAIL（挑战提交被挡在 Bot 步骤之前形成循环，任务书 §3.2「不能发布后让用户
// 陷入循环」）；含正则/客户端依赖条件无法静态判定 → WARN；放行类动作覆盖保留命名
// 空间 → WARN（L7 allow 直达统一放行出口，是否跳过 Bot 步骤取决于 B3 挂接，操作者须知悉）。
func (h *Handler) l7Conflicts(ctx context.Context) []RouteConflict {
	if h.l7 == nil {
		return []RouteConflict{{Type: "l7_deny_rule", Status: CheckFail,
			Message: "L7 规则读取未装配，无法执行冲突预检", Ref: ReservedVerifyPath}}
	}
	rules, err := h.l7.ListAllOrdered(ctx)
	if err != nil {
		return []RouteConflict{{Type: "l7_deny_rule", Status: CheckFail,
			Message: "读取 L7 规则失败，预检降级: " + err.Error(), Ref: ReservedVerifyPath}}
	}
	out := []RouteConflict{}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		deny := rule.Action == l7rules.ActionBlock || rule.Action == l7rules.ActionRedirect || rule.Action == l7rules.ActionCustomPage
		allow := rule.Action == l7rules.ActionAllow
		if !deny && !allow {
			continue
		}
		v := ruleCoversVerify(rule)
		typ := "l7_deny_rule"
		if allow {
			typ = "l7_allow_rule"
		}
		switch v {
		case verdictMatch:
			if deny {
				out = append(out, RouteConflict{Type: typ, Status: CheckFail, Ref: rule.Name,
					Message: fmt.Sprintf("L7 拒绝规则 %q（动作 %s）覆盖保留端点 %s：挑战提交会被拒绝形成循环", rule.Name, rule.Action, ReservedVerifyPath)})
			} else {
				out = append(out, RouteConflict{Type: typ, Status: CheckWarn, Ref: rule.Name,
					Message: fmt.Sprintf("L7 放行规则 %q 覆盖保留端点 %s：放行命中跳过封禁/CC 直达统一放行出口，与 Bot 步骤的先后关系以 B3 挂接为准", rule.Name, ReservedVerifyPath)})
			}
		case verdictUnknown:
			out = append(out, RouteConflict{Type: typ, Status: CheckWarn, Ref: rule.Name,
				Message: fmt.Sprintf("L7 规则 %q（动作 %s）含正则/客户端依赖条件，无法静态判定是否覆盖保留端点，请人工核对", rule.Name, rule.Action)})
		}
	}
	return out
}

// 条件判定词表（L7 规则多条件 AND：全部命中才覆盖 verify）。
type condVerdict int

const (
	verdictNoMatch condVerdict = iota // 确定性不覆盖
	verdictMatch                      // 确定性覆盖
	verdictUnknown                    // 无法静态判定（正则/客户端依赖）
)

// ruleCoversVerify 静态判定 L7 规则是否覆盖保留 verify 端点（合成请求：
// POST + path=ReservedVerifyPath；多条件 AND——任一条件确定性不中即整体不中）。
func ruleCoversVerify(rule l7rules.Rule) condVerdict {
	overall := verdictMatch
	for _, c := range rule.Conditions {
		v := condCoversVerify(c)
		if v == verdictNoMatch {
			return verdictNoMatch
		}
		if v == verdictUnknown {
			overall = verdictUnknown
		}
	}
	return overall
}

// condCoversVerify 单条件静态判定（verify 固定协议：POST + 保留路径）。
func condCoversVerify(c l7rules.Condition) condVerdict {
	switch c.Type {
	case l7rules.CondTypeURI:
		switch c.Op {
		case l7rules.OpEq:
			if c.Value == ReservedVerifyPath {
				return verdictMatch
			}
			return verdictNoMatch
		case l7rules.OpNe:
			if c.Value == ReservedVerifyPath {
				return verdictNoMatch
			}
			return verdictMatch
		case l7rules.OpPrefix:
			if strings.HasPrefix(ReservedVerifyPath, c.Value) {
				return verdictMatch
			}
			return verdictNoMatch
		case l7rules.OpContains:
			if strings.Contains(ReservedVerifyPath, c.Value) {
				return verdictMatch
			}
			return verdictNoMatch
		case l7rules.OpRegex:
			return verdictUnknown
		default:
			return verdictUnknown
		}
	case l7rules.CondTypeMethod:
		for _, m := range c.Values {
			if strings.EqualFold(m, http.MethodPost) {
				return verdictMatch
			}
		}
		return verdictNoMatch
	default:
		// host/header/cookie/query/client_ip 依赖请求现场，无法静态判定
		return verdictUnknown
	}
}

// assetConflicts 既有应用路径冲突：api_endpoints 已登记路径落入保留命名空间
// （管理面唯一已知的应用路径登记；未登记的业务路径预检无法发现，由 B3 启用手册与实测兜底）。
func (h *Handler) assetConflicts(ctx context.Context, appID uuid.UUID) []RouteConflict {
	assets, err := h.store.ListReservedNamespacePaths(ctx, appID)
	if err != nil {
		return []RouteConflict{{Type: "reserved_path_asset", Status: CheckFail,
			Message: "读取已登记应用路径失败，预检降级: " + err.Error(), Ref: ReservedNamespace}}
	}
	out := []RouteConflict{}
	for _, a := range assets {
		out = append(out, RouteConflict{Type: "reserved_path_asset", Status: CheckFail, Ref: a.Method + " " + a.Path,
			Message: fmt.Sprintf("既有应用路径 %s %s（来源 %s）落入 Bot 保留命名空间 %s：启用后该路径由网关本地接管，业务端点被遮蔽", a.Method, a.Path, a.Source, ReservedNamespace)})
	}
	return out
}

// pathRouteConflicts 路径转发冲突：ENABLED 路径转发前缀覆盖 verify（保留端点
// 会被转发到源站，违反「永不反向代理」）或落入保留命名空间内部（转发遮蔽保留子路径）。
func (h *Handler) pathRouteConflicts(ctx context.Context, appID uuid.UUID) []RouteConflict {
	if h.pathRoutes == nil {
		return []RouteConflict{{Type: "path_route", Status: CheckFail,
			Message: "路径转发读取未装配，无法执行冲突预检", Ref: ReservedVerifyPath}}
	}
	routes, err := h.pathRoutes.ListEnabledPathRoutes(ctx, appID)
	if err != nil {
		return []RouteConflict{{Type: "path_route", Status: CheckFail,
			Message: "读取路径转发失败，预检降级: " + err.Error(), Ref: ReservedVerifyPath}}
	}
	out := []RouteConflict{}
	for _, pr := range routes {
		prefix := pr.PathPrefix
		switch {
		case strings.HasPrefix(ReservedVerifyPath, prefix):
			out = append(out, RouteConflict{Type: "path_route", Status: CheckFail, Ref: prefix,
				Message: fmt.Sprintf("路径转发前缀 %q 覆盖保留端点 %s：挑战提交会被转发到源站 %s:%d，违反保留端点永不反向代理", prefix, ReservedVerifyPath, pr.UpstreamHost, pr.UpstreamPort)})
		case strings.HasPrefix(prefix, ReservedNamespace):
			out = append(out, RouteConflict{Type: "path_route", Status: CheckFail, Ref: prefix,
				Message: fmt.Sprintf("路径转发前缀 %q 落入 Bot 保留命名空间 %s：启用后该前缀由网关本地接管，转发规则失效", prefix, ReservedNamespace)})
		}
	}
	return out
}

// protectedScopeConflicts 保护地址范围提示：全量地址段（0.0.0.0/0、::/0）启用时，
// 所有来源跳过封禁/CC 等前置检查——与「内部端点仍经过前面的地址、封禁、L7、风险、
// 配额与 CC 检查」口径相左，提示操作者知悉（WARN，不阻断；保护地址为客户端 IP 维度，
// 不直接遮蔽保留路径）。
func (h *Handler) protectedScopeConflicts(ctx context.Context) []RouteConflict {
	if h.protected == nil {
		return nil
	}
	addrs, err := h.protected.List(ctx, "")
	if err != nil {
		return []RouteConflict{{Type: "protected_address_scope", Status: CheckWarn,
			Message: "读取保护地址失败，范围提示降级: " + err.Error(), Ref: ""}}
	}
	out := []RouteConflict{}
	for _, a := range addrs {
		if a.CIDR == "0.0.0.0/0" || a.CIDR == "::/0" {
			out = append(out, RouteConflict{Type: "protected_address_scope", Status: CheckWarn, Ref: a.CIDR,
				Message: fmt.Sprintf("保护地址 %q（%s）覆盖全部来源：这些客户端跳过封禁/CC 前置检查，挑战与 verify 的前置约束对其失效", a.CIDR, a.Name)})
		}
	}
	return out
}

// nodeChecks 目标节点检查（无注册节点=单网关部署，SKIP；sync_enabled 节点
// 存在已知同步失败时，PROTECT 策略判 FAIL 阻断发布，其余判 WARN）。
func (h *Handler) nodeChecks(protect bool, publishable *bool) []PreflightCheck {
	if h.nodes == nil {
		return []PreflightCheck{{Name: "node_capability", Status: CheckSkip, Message: "节点查询未装配"}}
	}
	nodes, err := h.nodes.ListNodes(context.Background())
	if err != nil {
		*publishable = false
		return []PreflightCheck{{Name: "node_capability", Status: CheckFail, Message: "读取网关节点状态失败: " + err.Error()}}
	}
	targets := []apinodes.Node{}
	for _, n := range nodes {
		if n.SyncEnabled {
			targets = append(targets, n)
		}
	}
	if len(targets) == 0 {
		return []PreflightCheck{{Name: "node_capability", Status: CheckSkip,
			Message: "无登记参与发布扇出的次要节点（单网关部署）"}}
	}
	out := []PreflightCheck{}
	for _, n := range targets {
		switch {
		case n.LastSyncResult == gatewayconfig.NodeSyncFailed || n.LastSyncResult == gatewayconfig.NodeSyncHashMismatch:
			msg := fmt.Sprintf("节点 %s 上次配置同步结果为 %s（%s），存在已知不可用目标", n.NodeName, n.LastSyncResult, n.LastSyncError)
			if protect {
				*publishable = false
				out = append(out, PreflightCheck{Name: "node_capability", Status: CheckFail, Message: msg})
			} else {
				out = append(out, PreflightCheck{Name: "node_capability", Status: CheckWarn, Message: msg})
			}
		case n.Status == apinodes.StatusSilent:
			out = append(out, PreflightCheck{Name: "node_capability", Status: CheckWarn,
				Message: fmt.Sprintf("节点 %s 超过 1 小时无事件（SILENT），请确认节点在线后再发布", n.NodeName)})
		default:
			out = append(out, PreflightCheck{Name: "node_capability", Status: CheckPass,
				Message: fmt.Sprintf("节点 %s 状态 %s，最近同步 %s", n.NodeName, n.Status, emptyAs(n.LastSyncResult, "未同步"))})
		}
	}
	return out
}

func emptyAs(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// resolveApp 解析路径应用 ID 并校验存在（不存在 404；非法 ID 400）。
func (h *Handler) resolveApp(w http.ResponseWriter, r *http.Request) (*applications.Application, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的应用 ID")
		return nil, false
	}
	app, err := h.apps.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, applications.ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
			return nil, false
		}
		response.InternalError(w, r, err)
		return nil, false
	}
	return app, true
}

// auditSummary 审计差异摘要（策略无任何秘密材料——key_ref 仅引用名；
// 含变更理由与版本，供前后对照）。
type auditSummary struct {
	Mode             string           `json:"mode"`
	Version          int              `json:"version"`
	Reason           string           `json:"reason,omitempty"`
	Selectors        []Selector       `json:"selectors"`
	SignalRules      SignalRules      `json:"signal_rules"`
	Challenge        Challenge        `json:"challenge"`
	RouteReservation RouteReservation `json:"route_reservation"`
}

func summarizePolicy(p *Policy, reason string) auditSummary {
	return auditSummary{
		Mode:             p.Mode,
		Version:          p.Version,
		Reason:           reason,
		Selectors:        p.Selectors,
		SignalRules:      p.SignalRules,
		Challenge:        p.Challenge,
		RouteReservation: p.RouteReservation,
	}
}

// recordAudit 操作审计（保存/预检：含操作人、reason、版本与字段差异摘要；
// mode 升级为 PROTECT（观测转强制挑战）提升为高风险审计，其余中风险；预检低风险）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action string,
	app *applications.Application, before, after *Policy, reason, result, failureReason string) {
	var beforeJSON, afterJSON []byte
	if before != nil {
		beforeJSON, _ = json.Marshal(summarizePolicy(before, ""))
	}
	if after != nil {
		afterJSON, _ = json.Marshal(summarizePolicy(after, reason))
	}
	risk := audits.RiskMedium
	switch {
	case action == "preflight":
		risk = audits.RiskLow
	case before != nil && before.Mode != ModeProtect && after != nil && after.Mode == ModeProtect:
		risk = audits.RiskHigh
	}
	objID := app.ID.String()
	if after != nil && after.ID != uuid.Nil {
		objID = after.ID.String()
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "security",
		Action:        action,
		ObjectType:    "bot_policy",
		ObjectID:      objID,
		ObjectName:    app.Code,
		BeforeSummary: string(beforeJSON),
		AfterSummary:  string(afterJSON),
		Result:        result,
		FailureReason: failureReason,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}
