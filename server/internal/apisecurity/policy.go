// policy.go API 动态防护策略接口组：策略视图 GET / 模式覆盖 PUT / 发布触发 POST。
// 模式取值顺序：settings 表覆盖（api_protection.mode）> 环境变量 > 内置默认（OBSERVE，fail-safe）。
package apisecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/product"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 策略覆盖在 system_settings 表中的定位（组 api_protection / 键 mode）。
const (
	PolicySettingsGroup = "api_protection"
	PolicyModeKey       = "mode"
)

// 防护模式白名单（与网关 jiuzhang_guard 约定一致）。
var validPolicyModes = map[string]bool{"OFF": true, "OBSERVE": true, "PROTECT": true}

// PolicySource 产品侧策略数据源（app 装配时由 product.Settings 构造注入）。
type PolicySource struct {
	Edition              string
	APIDynamicProtection bool
	Mode                 string // env/默认模式（OFF/OBSERVE/PROTECT，product 已归一化）
	ModeFromEnv          bool   // Mode 是否显式来自环境变量
	MaxBodyParseBytes    int
	MaxBodySampleBytes   int
	MaxJSONDepth         int
	MaxFieldCount        int
}

// PolicySourceFromProduct 从 product.Settings 构造策略数据源（app 装配料）。
func PolicySourceFromProduct(s product.Settings) PolicySource {
	return PolicySource{
		Edition:              string(s.Edition),
		APIDynamicProtection: s.APIDynamicProtectionEnabled(),
		Mode:                 s.EffectiveAPIProtectionMode(),
		ModeFromEnv:          s.APIProtectionModeFromEnv,
		MaxBodyParseBytes:    s.MaxBodyParseBytes,
		MaxBodySampleBytes:   s.MaxBodySampleBytes,
		MaxJSONDepth:         s.MaxJSONDepth,
		MaxFieldCount:        s.MaxFieldCount,
	}
}

// PolicySettings 策略覆盖读写接口（由 settings.Service 实现，便于单测假实现）。
type PolicySettings interface {
	GetStringWithSource(ctx context.Context, group, key string) (value string, found bool, err error)
	UpsertString(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) error
}

// PolicyPublishResult 发布触发结果（映射 gatewayconfig.PublishTask 摘要）。
type PolicyPublishResult struct {
	TaskID string `json:"task_id"`
	Status string `json:"status"`
}

// PolicyPublishFunc 触发一次配置发布（同步等待最终状态），使模式下发网关。
type PolicyPublishFunc func(ctx context.Context, requestedBy uuid.UUID, requestID string) (*PolicyPublishResult, error)

// SetPolicySource 注入产品侧策略数据（app 装配调用）。
func (h *Handler) SetPolicySource(src PolicySource) { h.policySource = src }

// SetPolicySettings 注入设置表访问（app 装配调用；nil 时策略接口返回 503）。
func (h *Handler) SetPolicySettings(s PolicySettings) { h.policySettings = s }

// SetPolicyPublishFunc 注入发布触发（app 装配调用；nil 时发布接口返回 503）。
func (h *Handler) SetPolicyPublishFunc(fn PolicyPublishFunc) { h.publishFn = fn }

// policyLimits 解析限制视图。
type policyLimits struct {
	MaxBodyParseBytes  int `json:"max_body_parse_bytes"`
	MaxBodySampleBytes int `json:"max_body_sample_bytes"`
	MaxJSONDepth       int `json:"max_json_depth"`
	MaxFieldCount      int `json:"max_field_count"`
}

// policyView 策略接口响应视图。
type policyView struct {
	Edition              string       `json:"edition"`
	APIDynamicProtection bool         `json:"api_dynamic_protection"`
	Mode                 string       `json:"mode"`
	ModeSource           string       `json:"mode_source"` // env | db | default
	Limits               policyLimits `json:"limits"`
}

// resolveMode 计算生效模式与来源：settings 表覆盖（合法值）优先，其次 env，最后内置默认。
// 覆盖值非法时回退产品侧模式（fail-safe，网关行为不被脏数据改变）。
func (h *Handler) resolveMode(ctx context.Context) (mode, source string, err error) {
	mode, source = h.policySource.Mode, "default"
	if h.policySource.ModeFromEnv {
		source = "env"
	}
	if h.policySettings == nil {
		return mode, source, nil
	}
	override, found, err := h.policySettings.GetStringWithSource(ctx, PolicySettingsGroup, PolicyModeKey)
	if err != nil {
		return "", "", err
	}
	if found && validPolicyModes[strings.ToUpper(strings.TrimSpace(override))] {
		return strings.ToUpper(strings.TrimSpace(override)), "db", nil
	}
	return mode, source, nil
}

// currentPolicyView 组装策略视图（GET 响应与 PUT 后视图共用）。
func (h *Handler) currentPolicyView(ctx context.Context) (*policyView, error) {
	mode, source, err := h.resolveMode(ctx)
	if err != nil {
		return nil, err
	}
	return &policyView{
		Edition:              h.policySource.Edition,
		APIDynamicProtection: h.policySource.APIDynamicProtection,
		Mode:                 mode,
		ModeSource:           source,
		Limits: policyLimits{
			MaxBodyParseBytes:  h.policySource.MaxBodyParseBytes,
			MaxBodySampleBytes: h.policySource.MaxBodySampleBytes,
			MaxJSONDepth:       h.policySource.MaxJSONDepth,
			MaxFieldCount:      h.policySource.MaxFieldCount,
		},
	}, nil
}

// GetPolicy GET /api/v1/api-security/policy
// 返回 edition/能力开关/生效模式与来源/解析限制（数据来自 product.Settings + settings 表覆盖）。
func (h *Handler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	view, err := h.currentPolicyView(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, view)
}

type putPolicyRequest struct {
	Mode string `json:"mode"`
}

// PutPolicy PUT /api/v1/api-security/policy
// body {mode} 仅接受 OFF/OBSERVE/PROTECT；覆盖写入 settings 表 api_protection.mode，写操作审计。
func (h *Handler) PutPolicy(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req putPolicyRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	mode := strings.ToUpper(strings.TrimSpace(req.Mode))
	if !validPolicyModes[mode] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的防护模式（仅接受 OFF/OBSERVE/PROTECT）")
		return
	}
	if h.policySettings == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "设置服务未配置")
		return
	}
	// 审计前摘要：覆盖前的生效模式与来源
	beforeMode, beforeSource, err := h.resolveMode(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if err := h.policySettings.UpsertString(r.Context(), PolicySettingsGroup, PolicyModeKey, mode,
		"API 动态防护模式覆盖（OFF/OBSERVE/PROTECT；发布后与 env/默认值形成 db>env>default 取值顺序）", p.UserID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	beforeJSON, _ := json.Marshal(map[string]string{"mode": beforeMode, "mode_source": beforeSource})
	afterJSON, _ := json.Marshal(map[string]string{"mode": mode, "mode_source": "db"})
	h.recordAudit(r, p, "update", "api_policy", PolicySettingsGroup+"."+PolicyModeKey,
		"API动态防护模式", string(beforeJSON), string(afterJSON),
		audits.ResultSuccess, audits.RiskMedium)
	view, err := h.currentPolicyView(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"policy":  view,
		"message": "防护模式已更新，发布后生效",
	})
}

// PublishPolicy POST /api/v1/api-security/policy/publish
// 触发一次配置发布（同步等待最终状态），使模式下发网关，写操作审计。
func (h *Handler) PublishPolicy(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if h.publishFn == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "发布能力未配置")
		return
	}
	result, err := h.publishFn(r.Context(), p.UserID, response.RequestIDFrom(r))
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	auditResult := audits.ResultSuccess
	if result.Status != "SUCCESS" {
		auditResult = audits.ResultFailure
	}
	h.recordAudit(r, p, "publish", "api_policy", result.TaskID,
		"API动态防护策略发布", "",
		fmt.Sprintf("task_id=%s status=%s", result.TaskID, result.Status),
		auditResult, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]any{
		"task_id": result.TaskID,
		"status":  result.Status,
		"message": "配置发布已触发",
	})
}
