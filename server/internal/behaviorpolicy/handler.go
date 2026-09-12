// handler.go 行为策略管理面接口（WDSP AI 自动化渗透防护增强 阶段1）。
// 路由（app.go 注册）：
//
//	GET /api/v1/security/behavior-policy  读取 GLOBAL 策略（权限 behavior_policy.read）
//	PUT /api/v1/security/behavior-policy  全量更新（权限 behavior_policy.edit；version
//	  乐观锁冲突 409；成功后审计 + 触发网关配置发布——identity_behavior 段热生效）
package behaviorpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// PublishFunc 发布触发函数（app 装配注入 gatewayconfig.Publisher.Publish；nil = 发布通道不可用）。
type PublishFunc func(ctx context.Context, uid uuid.UUID, requestID string)

// Handler 是行为策略处理器。
type Handler struct {
	store   *Store
	audits  *audits.Service
	publish PublishFunc
}

// NewHandler 创建处理器。
func NewHandler(store *Store, au *audits.Service) *Handler {
	return &Handler{store: store, audits: au}
}

// SetPublishFunc 注入发布触发函数（publisher 不可用时保持 nil：策略落库成功但不下发，
// 与装配层其他策略同一口径——发布通道恢复后任意发布动作即带上最新策略）。
func (h *Handler) SetPublishFunc(fn PublishFunc) { h.publish = fn }

// Get 读取 GLOBAL 全局策略（全字段 + version）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	p, err := h.store.Get(r.Context())
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"policy": p})
}

// updateRequest 是全量更新请求体（version 为乐观锁预期值；scope 可选、不可变，
// 允许前端按 GET 全量行回传，若提供则必须与当前值一致）。
type updateRequest struct {
	Scope                    string         `json:"scope"`
	Enabled                  bool           `json:"enabled"`
	Mode                     string         `json:"mode"`
	Version                  int            `json:"version"`
	URIEnumUniqueThreshold   int            `json:"uri_enum_unique_threshold"`
	URIEnumNewRatioThreshold float64        `json:"uri_enum_new_ratio_threshold"`
	NotFoundRatioThreshold   float64        `json:"not_found_ratio_threshold"`
	NotFoundMinRequests      int            `json:"not_found_min_requests"`
	MethodEnumThreshold      int            `json:"method_enum_threshold"`
	ParamMutationThreshold   int            `json:"param_mutation_threshold"`
	AuthFailThreshold        int            `json:"auth_fail_threshold"`
	LowSlowSensitiveMinHits  int            `json:"low_slow_sensitive_min_hits"`
	AccountEnumThreshold     int            `json:"account_enum_threshold"`
	ObjectEnumThreshold      int            `json:"object_enum_threshold"`
	AccountIdentifierFields  []string       `json:"account_identifier_fields"`
	ObjectIdentifierFields   []string       `json:"object_identifier_fields"`
	SensitivePaths           []string       `json:"sensitive_paths"`
	Scores                   map[string]int `json:"scores"`
	WhitelistIPs             []string       `json:"whitelist_ips"`
	WhitelistUAs             []string       `json:"whitelist_uas"`
}

// Update 全量更新 GLOBAL 策略（乐观锁 + 校验 + 审计 + 触发发布）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	before, err := h.store.Get(r.Context())
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	var req updateRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.Scope != "" && req.Scope != before.Scope {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过",
			[]FieldError{{Field: "scope", Message: "scope 不可变，须与当前值一致"}})
		return
	}
	if req.Version != before.Version {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
		return
	}
	updated := &Policy{
		ID:                       before.ID,
		Scope:                    before.Scope, // scope 不可变
		Enabled:                  req.Enabled,
		Mode:                     req.Mode,
		Version:                  req.Version,
		URIEnumUniqueThreshold:   req.URIEnumUniqueThreshold,
		URIEnumNewRatioThreshold: req.URIEnumNewRatioThreshold,
		NotFoundRatioThreshold:   req.NotFoundRatioThreshold,
		NotFoundMinRequests:      req.NotFoundMinRequests,
		MethodEnumThreshold:      req.MethodEnumThreshold,
		ParamMutationThreshold:   req.ParamMutationThreshold,
		AuthFailThreshold:        req.AuthFailThreshold,
		LowSlowSensitiveMinHits:  req.LowSlowSensitiveMinHits,
		AccountEnumThreshold:     req.AccountEnumThreshold,
		ObjectEnumThreshold:      req.ObjectEnumThreshold,
		AccountIdentifierFields:  req.AccountIdentifierFields,
		ObjectIdentifierFields:   req.ObjectIdentifierFields,
		SensitivePaths:           req.SensitivePaths,
		Scores:                   req.Scores,
		WhitelistIPs:             req.WhitelistIPs,
		WhitelistUAs:             req.WhitelistUAs,
	}
	if errs := Validate(updated); len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过", errs)
		return
	}
	if err := h.store.Update(r.Context(), updated, p.Username); err != nil {
		if errors.Is(err, ErrConflict) {
			// 预检后发生并发修改
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
	h.recordAudit(r, p, before, updated)

	// 触发网关配置发布（identity_behavior 段热生效；发布通道不可用/触发失败仅记日志，
	// 策略本身已落库——与发布触发路径其他策略变更同一口径：发布为独立任务可追踪重试）
	if h.publish != nil {
		h.publish(context.Background(), p.UserID, "behavior-policy-"+updated.ID.String()+"-v"+strconv.Itoa(updated.Version))
	} else {
		slog.Warn("behavior policy updated but publish channel unavailable, gateway sync deferred")
	}

	// 回读最终行（含 updated_at/version 服务端真值）
	final, err := h.store.Get(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"policy": final})
}

// writeStoreError 统一处理读取错误：策略行缺失按内部错误（迁移种子保证存在，缺失即数据异常）。
func (h *Handler) writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	response.InternalError(w, r, err)
}

// recordAudit 策略变更审计（Before/AfterSummary 为全量 JSON；策略无秘密字段，
// 白名单/阈值如实记录——与系统设置变更审计口径一致）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, before, after *Policy) {
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(after)
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "security",
		Action:        "update",
		ObjectType:    "behavior_policy",
		ObjectID:      after.ID.String(),
		ObjectName:    after.Scope,
		BeforeSummary: string(beforeJSON),
		AfterSummary:  string(afterJSON),
		Result:        audits.ResultSuccess,
		RiskLevel:     audits.RiskMedium,
		RequestID:     response.RequestIDFrom(r),
	})
}
