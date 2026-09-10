// models_handler.go 模型供应商/模型/路由档位管理。
// 密钥仅创建与轮换时入参，加密存储（ai_provider_secrets），任何响应不回传密钥。
// 路由档位持久化在 system_settings（组 ai，键 route_simple/route_standard/route_high，
// 值为 model_code 字符串），变更后 LoadRoutes + SetRoutes 热生效。
package aihandlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aiaudit"
	"github.com/jiuzhang-waf/server/internal/aimodel"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// providerDTO 供应商输出（绝不含密钥明文/密文，仅引用名）。
type providerDTO struct {
	ID              uuid.UUID `json:"id"`
	Name            string    `json:"name"`
	ProviderType    string    `json:"provider_type"`
	BaseURL         string    `json:"base_url"`
	CanonicalOrigin string    `json:"canonical_origin"`
	AllowedTargets  []string  `json:"allowed_targets"`
	KeyReference    string    `json:"api_key_reference"`
	Status          string    `json:"status"`
}

func toProviderDTO(p *aimodel.Provider) providerDTO {
	return providerDTO{
		ID: p.ID, Name: p.Name, ProviderType: string(p.Type),
		BaseURL: p.BaseURL, CanonicalOrigin: p.CanonicalOrigin,
		AllowedTargets: append([]string{}, p.AllowedTargets...),
		KeyReference:   p.KeyReference, Status: p.Status,
	}
}

// modelDTO 模型输出。
type modelDTO struct {
	ID                uuid.UUID `json:"id"`
	ProviderID        uuid.UUID `json:"provider_id"`
	ModelCode         string    `json:"model_code"`
	DisplayName       string    `json:"display_name"`
	ContextWindow     int       `json:"context_window"`
	MaxOutputTokens   int       `json:"max_output_tokens"`
	SupportsTools     bool      `json:"supports_tools"`
	SupportsStreaming bool      `json:"supports_streaming"`
	Priority          int       `json:"priority"`
	TimeoutSeconds    int       `json:"timeout_seconds"`
	CostInputUnit     float64   `json:"cost_input_unit"`
	CostOutputUnit    float64   `json:"cost_output_unit"`
	Status            string    `json:"status"`
}

func toModelDTO(m *aimodel.Model) modelDTO {
	return modelDTO{
		ID: m.ID, ProviderID: m.ProviderID, ModelCode: m.Code, DisplayName: m.DisplayName,
		ContextWindow: m.ContextWindow, MaxOutputTokens: m.MaxOutputTokens,
		SupportsTools: m.SupportsTools, SupportsStreaming: m.SupportsStreaming,
		Priority: m.Priority, TimeoutSeconds: m.TimeoutSeconds,
		CostInputUnit: m.CostInputUnit, CostOutputUnit: m.CostOutputUnit, Status: m.Status,
	}
}

// 供应商类型白名单。
var providerTypes = map[string]bool{
	"openai_compatible": true, "anthropic": true, "ollama": true, "local": true,
}

// ProviderList 供应商列表。
func (d *Deps) ProviderList(w http.ResponseWriter, r *http.Request) {
	list, err := d.Models.ListProviders(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	out := make([]providerDTO, 0, len(list))
	for i := range list {
		out = append(out, toProviderDTO(&list[i]))
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": out})
}

type providerRequest struct {
	Name           string    `json:"name"`
	ProviderType   string    `json:"provider_type"`
	BaseURL        string    `json:"base_url"`
	AllowedTargets *[]string `json:"allowed_targets"`
	APIKey         string    `json:"api_key"`
	Status         string    `json:"status"`
}

// ProviderCreate 创建供应商（api_key 可选，明文入参即加密存储）。
func (d *Deps) ProviderCreate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req providerRequest
	if err := decodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.BaseURL = strings.TrimSpace(req.BaseURL)
	if req.Name == "" || len(req.Name) > 100 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "供应商名称必填且不超过 100 字符")
		return
	}
	if !providerTypes[req.ProviderType] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的供应商类型（openai_compatible/anthropic/ollama/local）")
		return
	}
	if req.BaseURL == "" || len(req.BaseURL) > 255 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "Base URL 必填且不超过 255 字符")
		return
	}
	status := "ENABLED"
	if req.Status != "" {
		if req.Status != "ENABLED" && req.Status != "DISABLED" {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的状态（ENABLED/DISABLED）")
			return
		}
		status = req.Status
	}
	prov := &aimodel.Provider{
		Name: req.Name, Type: aimodel.ProviderType(req.ProviderType),
		BaseURL: req.BaseURL, Status: status,
	}
	if req.AllowedTargets != nil {
		prov.AllowedTargets = append([]string{}, (*req.AllowedTargets)...)
	}
	if err := d.Models.CreateProvider(r.Context(), prov, req.APIKey); err != nil {
		d.modelError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "model_provider_create", RequestSummary: "创建供应商 " + req.Name, ResultSummary: "SUCCESS",
	})
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"provider": toProviderDTO(prov)})
}

// ProviderPatch 更新供应商（名称/BaseURL/状态；密钥走 rotate-key）。
func (d *Deps) ProviderPatch(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的供应商ID")
		return
	}
	var req providerRequest
	if err := decodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	prov, err := d.Models.GetProvider(r.Context(), id)
	if err != nil {
		d.modelError(w, r, err)
		return
	}
	previousKeyReference := prov.KeyReference
	if req.Name != "" {
		if len(req.Name) > 100 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "供应商名称不超过 100 字符")
			return
		}
		prov.Name = strings.TrimSpace(req.Name)
	}
	if req.ProviderType != "" {
		if !providerTypes[req.ProviderType] {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的供应商类型")
			return
		}
		prov.Type = aimodel.ProviderType(req.ProviderType)
	}
	if req.BaseURL != "" {
		baseURL := strings.TrimSpace(req.BaseURL)
		if baseURL == "" || len(baseURL) > 255 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "Base URL 不能为空且不超过 255 字符")
			return
		}
		prov.BaseURL = baseURL
	}
	if req.AllowedTargets != nil {
		prov.AllowedTargets = append([]string{}, (*req.AllowedTargets)...)
	}
	if req.Status != "" {
		if req.Status != "ENABLED" && req.Status != "DISABLED" {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的状态（ENABLED/DISABLED）")
			return
		}
		prov.Status = req.Status
	}
	if err := d.Models.UpdateProvider(r.Context(), prov); err != nil {
		d.modelError(w, r, err)
		return
	}
	// 供应商状态/BaseURL 影响路由，热更新
	if err := d.ReloadRoutes(r.Context()); err != nil {
		response.InternalError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "model_provider_update", RequestSummary: "更新供应商 " + prov.Name,
		ResultSummary: providerUpdateResult(previousKeyReference, prov.KeyReference),
	})
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"provider": toProviderDTO(prov)})
}

func providerUpdateResult(previousKeyReference, currentKeyReference string) string {
	if previousKeyReference != "" && currentKeyReference == "" {
		return "SUCCESS_KEY_INVALIDATED"
	}
	return "SUCCESS"
}

// ProviderRotateKey 轮换供应商密钥（明文仅入参，加密覆盖存储）。
func (d *Deps) ProviderRotateKey(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的供应商ID")
		return
	}
	var req struct {
		APIKey string `json:"api_key"`
	}
	if err := decodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.APIKey) == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "新密钥不能为空")
		return
	}
	if err := d.Models.RotateKey(r.Context(), id, req.APIKey); err != nil {
		d.modelError(w, r, err)
		return
	}
	// 审计摘要不包含任何密钥材料
	d.recordAIAudit(p, aiaudit.Record{
		Action: "model_key_rotate", RequestSummary: "轮换供应商密钥 " + id.String(), ResultSummary: "SUCCESS",
	})
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "密钥已轮换"})
}

// ProviderDelete 删除供应商（下无模型时才允许；同步清理密钥密文）。
func (d *Deps) ProviderDelete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的供应商ID")
		return
	}
	prov, err := d.Models.GetProvider(r.Context(), id)
	if err != nil {
		d.modelError(w, r, err)
		return
	}
	if err := d.Models.DeleteProvider(r.Context(), id); err != nil {
		if errors.Is(err, aimodel.ErrProviderHasModels) {
			response.Error(w, r, http.StatusConflict, response.CodeInvalidArgument,
				"该供应商下仍有模型，请先删除全部关联模型后再删除供应商")
			return
		}
		d.modelError(w, r, err)
		return
	}
	if err := d.ReloadRoutes(r.Context()); err != nil {
		response.InternalError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "model_provider_delete", RequestSummary: "删除供应商 " + prov.Name, ResultSummary: "SUCCESS",
	})
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "供应商已删除"})
}

// ModelList 模型列表。
func (d *Deps) ModelList(w http.ResponseWriter, r *http.Request) {
	models, _, err := d.Models.ListModels(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	out := make([]modelDTO, 0, len(models))
	for i := range models {
		out = append(out, toModelDTO(&models[i]))
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": out})
}

type modelRequest struct {
	ProviderID        string  `json:"provider_id"`
	ModelCode         string  `json:"model_code"`
	DisplayName       string  `json:"display_name"`
	ContextWindow     int     `json:"context_window"`
	MaxOutputTokens   int     `json:"max_output_tokens"`
	SupportsTools     bool    `json:"supports_tools"`
	SupportsStreaming bool    `json:"supports_streaming"`
	Priority          int     `json:"priority"`
	TimeoutSeconds    int     `json:"timeout_seconds"`
	CostInputUnit     float64 `json:"cost_input_unit"`
	CostOutputUnit    float64 `json:"cost_output_unit"`
}

// ModelCreate 创建模型。
func (d *Deps) ModelCreate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req modelRequest
	if err := decodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	provID, err := uuid.Parse(req.ProviderID)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的供应商ID")
		return
	}
	if _, err := d.Models.GetProvider(r.Context(), provID); err != nil {
		if errors.Is(err, aimodel.ErrNotFound) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "供应商不存在")
		} else {
			response.InternalError(w, r, err)
		}
		return
	}
	req.ModelCode = strings.TrimSpace(req.ModelCode)
	if req.ModelCode == "" || len(req.ModelCode) > 100 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "模型编码必填且不超过 100 字符")
		return
	}
	m := &aimodel.Model{
		ProviderID: provID, Code: req.ModelCode, DisplayName: req.DisplayName,
		ContextWindow: req.ContextWindow, MaxOutputTokens: req.MaxOutputTokens,
		SupportsTools: req.SupportsTools, SupportsStreaming: req.SupportsStreaming,
		Priority: req.Priority, TimeoutSeconds: req.TimeoutSeconds,
		CostInputUnit: req.CostInputUnit, CostOutputUnit: req.CostOutputUnit,
		Status: "ENABLED",
	}
	normalizeModel(m)
	if m.DisplayName == "" {
		m.DisplayName = m.Code
	}
	if err := d.Models.CreateModel(r.Context(), m); err != nil {
		response.InternalError(w, r, err)
		return
	}
	if err := d.ReloadRoutes(r.Context()); err != nil {
		response.InternalError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "model_create", ModelCode: m.Code, RequestSummary: "创建模型 " + m.Code, ResultSummary: "SUCCESS",
	})
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"model": toModelDTO(m)})
}

// normalizeModel 模型参数默认值与边界归一。
func normalizeModel(m *aimodel.Model) {
	if m.ContextWindow <= 0 {
		m.ContextWindow = 8192
	}
	if m.MaxOutputTokens <= 0 {
		m.MaxOutputTokens = 2048
	}
	if m.TimeoutSeconds <= 0 || m.TimeoutSeconds > 600 {
		m.TimeoutSeconds = 60
	}
	if m.Priority <= 0 {
		m.Priority = 100
	}
	if m.CostInputUnit < 0 {
		m.CostInputUnit = 0
	}
	if m.CostOutputUnit < 0 {
		m.CostOutputUnit = 0
	}
}

// ModelUpdate 更新模型（不含状态与密钥）。
func (d *Deps) ModelUpdate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模型ID")
		return
	}
	var req modelRequest
	if err := decodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	m, err := d.Models.GetModel(r.Context(), id)
	if err != nil {
		d.modelError(w, r, err)
		return
	}
	m.DisplayName = req.DisplayName
	m.ContextWindow = req.ContextWindow
	m.MaxOutputTokens = req.MaxOutputTokens
	m.SupportsTools = req.SupportsTools
	m.SupportsStreaming = req.SupportsStreaming
	m.Priority = req.Priority
	m.TimeoutSeconds = req.TimeoutSeconds
	m.CostInputUnit = req.CostInputUnit
	m.CostOutputUnit = req.CostOutputUnit
	normalizeModel(m)
	if m.DisplayName == "" {
		m.DisplayName = m.Code
	}
	if err := d.Models.UpdateModel(r.Context(), m); err != nil {
		d.modelError(w, r, err)
		return
	}
	if err := d.ReloadRoutes(r.Context()); err != nil {
		response.InternalError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "model_update", ModelCode: m.Code, RequestSummary: "更新模型 " + m.Code, ResultSummary: "SUCCESS",
	})
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"model": toModelDTO(m)})
}

// ModelDelete 删除模型。
func (d *Deps) ModelDelete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模型ID")
		return
	}
	m, err := d.Models.GetModel(r.Context(), id)
	if err != nil {
		d.modelError(w, r, err)
		return
	}
	if err := d.Models.DeleteModel(r.Context(), id); err != nil {
		d.modelError(w, r, err)
		return
	}
	if err := d.ReloadRoutes(r.Context()); err != nil {
		response.InternalError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "model_delete", ModelCode: m.Code, RequestSummary: "删除模型 " + m.Code, ResultSummary: "SUCCESS",
	})
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "模型已删除"})
}

// ModelEnable 启用模型。
func (d *Deps) ModelEnable(w http.ResponseWriter, r *http.Request) {
	d.setModelStatus(w, r, "ENABLED")
}

// ModelDisable 停用模型。
func (d *Deps) ModelDisable(w http.ResponseWriter, r *http.Request) {
	d.setModelStatus(w, r, "DISABLED")
}

func (d *Deps) setModelStatus(w http.ResponseWriter, r *http.Request, status string) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模型ID")
		return
	}
	if err := d.Models.SetModelStatus(r.Context(), id, status); err != nil {
		d.modelError(w, r, err)
		return
	}
	if err := d.ReloadRoutes(r.Context()); err != nil {
		response.InternalError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "model_status", RequestSummary: "模型 " + id.String() + " → " + status, ResultSummary: "SUCCESS",
	})
	msg := "模型已启用"
	if status == "DISABLED" {
		msg = "模型已停用"
	}
	response.JSON(w, r, http.StatusOK, map[string]string{"message": msg})
}

// ModelTest 单模型健康检查（连通性 + 短对话）。
func (d *Deps) ModelTest(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模型ID")
		return
	}
	m, err := d.Models.GetModel(r.Context(), id)
	if err != nil {
		d.modelError(w, r, err)
		return
	}
	prov, err := d.Models.GetProvider(r.Context(), m.ProviderID)
	if err != nil {
		d.modelError(w, r, err)
		return
	}
	testErr := d.Gateway.HealthCheckModel(r.Context(), m, prov)
	result := "SUCCESS"
	if testErr != nil {
		result = "FAILED"
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "model_test", ModelCode: m.Code, RequestSummary: "健康检查 " + m.Code, ResultSummary: result,
	})
	if testErr != nil {
		response.JSON(w, r, http.StatusOK, map[string]interface{}{
			"ok": false, "message": "模型连通性检查失败，请检查供应商地址与密钥",
		})
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"ok": true, "message": "模型连通性正常"})
}

// ModelRoutesGet 读取模型路由档位。
func (d *Deps) ModelRoutesGet(w http.ResponseWriter, r *http.Request) {
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"routes": map[string]string{
			"simple":   d.Settings.GetString(r.Context(), "ai", "route_simple", defaultModelCode),
			"standard": d.Settings.GetString(r.Context(), "ai", "route_standard", defaultModelCode),
			"high":     d.Settings.GetString(r.Context(), "ai", "route_high", defaultModelCode),
		},
		"loaded_models": d.Gateway.ModelCount(),
	})
}

// ModelRoutesPut 更新模型路由档位（持久化 system_settings + 热生效）。
func (d *Deps) ModelRoutesPut(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req struct {
		Simple   string `json:"simple"`
		Standard string `json:"standard"`
		High     string `json:"high"`
	}
	if err := decodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	// 校验提供的档位模型编码存在
	models, _, err := d.Models.ListModels(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	known := map[string]bool{}
	for i := range models {
		known[models[i].Code] = true
	}
	updates := map[string]string{
		"route_simple":   strings.TrimSpace(req.Simple),
		"route_standard": strings.TrimSpace(req.Standard),
		"route_high":     strings.TrimSpace(req.High),
	}
	for key, code := range updates {
		if code == "" {
			delete(updates, key) // 未提供的档位保持现状
			continue
		}
		if !known[code] {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "模型编码不存在："+code)
			return
		}
	}
	if len(updates) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "未提供任何档位配置")
		return
	}
	for key, code := range updates {
		if err := d.upsertRouteSetting(r.Context(), key, code); err != nil {
			response.InternalError(w, r, err)
			return
		}
	}
	if err := d.ReloadRoutes(r.Context()); err != nil {
		response.InternalError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "model_route_update", RequestSummary: "更新路由档位", ResultSummary: "SUCCESS",
	})
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "模型路由已更新"})
}

// upsertRouteSetting 持久化路由档位到 system_settings（ai 组；种子迁移预置三行）。
func (d *Deps) upsertRouteSetting(ctx context.Context, key, code string) error {
	val, _ := json.Marshal(code)
	_, err := d.DB.Exec(ctx, `
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)
VALUES ('ai', $1, $2::jsonb, 'string', 'AI 模型路由档位（simple/standard/high → model_code）')
ON CONFLICT (setting_group, setting_key) DO UPDATE
SET setting_value = EXCLUDED.setting_value, updated_at = now(), version = system_settings.version + 1`,
		key, string(val))
	return err
}

// ReloadRoutes 重新加载路由档位并热生效（配置缺失回退默认本地模型，不致命）。
func (d *Deps) ReloadRoutes(ctx context.Context) error {
	routes, err := d.Models.LoadRoutes(ctx,
		d.Settings.GetString(ctx, "ai", "route_simple", defaultModelCode),
		d.Settings.GetString(ctx, "ai", "route_standard", defaultModelCode),
		d.Settings.GetString(ctx, "ai", "route_high", defaultModelCode))
	if err != nil {
		return err
	}
	d.Gateway.SetRoutes(routes)
	return nil
}

// modelError 模型仓储错误映射。
func (d *Deps) modelError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, aimodel.ErrInvalidProviderEndpoint) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "模型供应商地址或目标白名单不符合安全策略")
		return
	}
	if errors.Is(err, aimodel.ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "资源不存在")
		return
	}
	response.InternalError(w, r, err)
}
