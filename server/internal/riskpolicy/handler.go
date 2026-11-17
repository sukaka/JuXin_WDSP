// handler.go 风险策略管理面接口（WDSP AI 自动化渗透防护增强 阶段3）。
// 路由（app.go 注册）：
//
//	GET /api/v1/security/risk-policy  读取 GLOBAL 策略（权限 risk_policy.read）
//	PUT /api/v1/security/risk-policy  全量更新（权限 risk_policy.edit；version
//	  乐观锁冲突 409；成功后审计 + 触发网关配置发布——risk_policy 段热生效）
package riskpolicy

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

// Handler 是风险策略处理器。
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
// 允许前端按 GET 全量行回传，若提供则必须与当前值一致；id/updated_by/updated_at
// 为服务端只读字段，请求体不承接。challenge_threshold 用指针区分省略与显式 0：
// 旧客户端省略时继承原值，新建应用覆盖省略时为 0）。
type updateRequest struct {
	Scope                    string         `json:"scope"`
	Enabled                  bool           `json:"enabled"`
	Mode                     string         `json:"mode"`
	Version                  int            `json:"version"`
	BlockThreshold           int            `json:"block_threshold"`
	RateLimitThreshold       int            `json:"rate_limit_threshold"`
	ChallengeThreshold       *int           `json:"challenge_threshold"`
	RateLimitRPS             int            `json:"rate_limit_rps"`
	SignalWindowSeconds      int            `json:"signal_window_seconds"`
	SharedDeviceAccountLimit int            `json:"shared_device_account_limit"`
	Scores                   map[string]int `json:"scores"`
	RiskLevels               map[string]int `json:"risk_levels"`
}

func (r updateRequest) challengeThreshold(before *Policy) int {
	if r.ChallengeThreshold != nil {
		return *r.ChallengeThreshold
	}
	if before != nil {
		return before.ChallengeThreshold
	}
	return 0
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
		BlockThreshold:           req.BlockThreshold,
		RateLimitThreshold:       req.RateLimitThreshold,
		ChallengeThreshold:       req.challengeThreshold(before),
		RateLimitRPS:             req.RateLimitRPS,
		SignalWindowSeconds:      req.SignalWindowSeconds,
		SharedDeviceAccountLimit: req.SharedDeviceAccountLimit,
		Scores:                   req.Scores,
		RiskLevels:               req.RiskLevels,
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

	// 触发网关配置发布（risk_policy 段热生效；发布通道不可用/触发失败仅记日志，
	// 策略本身已落库——与发布触发路径其他策略变更同一口径：发布为独立任务可追踪重试）
	if h.publish != nil {
		h.publish(context.Background(), p.UserID, "risk-policy-"+updated.ID.String()+"-v"+strconv.Itoa(updated.Version))
	} else {
		slog.Warn("risk policy updated but publish channel unavailable, gateway sync deferred")
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
// 阈值/分值如实记录——与系统设置变更审计口径一致）。mode 从 OBSERVE 升级为
// PROTECT（观测转实际处置，影响面扩大）提升为高风险审计，其余变更中风险。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, before, after *Policy) {
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(after)
	risk := audits.RiskMedium
	if before.Mode == ModeObserve && after.Mode == ModeProtect {
		risk = audits.RiskHigh
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "security",
		Action:        "update",
		ObjectType:    "risk_policy",
		ObjectID:      after.ID.String(),
		ObjectName:    after.Scope,
		BeforeSummary: string(beforeJSON),
		AfterSummary:  string(afterJSON),
		Result:        audits.ResultSuccess,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}
