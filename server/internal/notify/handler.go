// handler.go 告警通知渠道接口：元数据 / CRUD / 发送测试。
// 写操作全部记操作审计（范式仿 settings/handler.go 与 syslogfw/handler.go）。
package notify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// HandlerStore 是 handler 依赖的仓储接口（*Store 实现）。
type HandlerStore interface {
	Create(ctx context.Context, c *Channel) error
	Update(ctx context.Context, c *Channel) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetDecrypted(ctx context.Context, id uuid.UUID) (*Channel, error)
	GetMasked(ctx context.Context, id uuid.UUID) (*Channel, error)
	ListMasked(ctx context.Context) ([]Channel, error)
}

// Handler 是告警通知处理器。
type Handler struct {
	store      HandlerStore
	dispatcher *Dispatcher
	audits     *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(store HandlerStore, dispatcher *Dispatcher, au *audits.Service) *Handler {
	return &Handler{store: store, dispatcher: dispatcher, audits: au}
}

// Meta 返回通知元数据（固定 8 类告警类别 + 可选最低级别词表）。
func (h *Handler) Meta(w http.ResponseWriter, r *http.Request) {
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"categories": Categories(),
		"severities": Severities(),
	})
}

// List 列出全部渠道（密值脱敏）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.ListMasked(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": list})
}

// channelInput 是渠道创建/更新请求体。
type channelInput struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Enabled     bool                   `json:"enabled"`
	MinSeverity string                 `json:"min_severity"`
	Categories  []string               `json:"categories"`
	Config      map[string]interface{} `json:"config"`
}

// validateBasics 校验非 config 部分；返回规整后的副本。
func (in *channelInput) validateBasics() error {
	in.Name = strings.TrimSpace(in.Name)
	in.Type = strings.ToLower(strings.TrimSpace(in.Type))
	in.MinSeverity = strings.ToUpper(strings.TrimSpace(in.MinSeverity))
	if in.Name == "" || len(in.Name) > 128 {
		return fmt.Errorf("name 不能为空且不超过 128 字符")
	}
	if !IsValidType(in.Type) {
		return fmt.Errorf("type 须为 wecom/feishu/smtp/sms/syslog")
	}
	if in.MinSeverity == "" {
		in.MinSeverity = SeverityLow
	}
	if !IsValidMinSeverity(in.MinSeverity) {
		return fmt.Errorf("min_severity 须为 LOW/MEDIUM/HIGH/CRITICAL")
	}
	seen := map[string]bool{}
	dedup := make([]string, 0, len(in.Categories))
	for _, code := range in.Categories {
		code = strings.TrimSpace(code)
		if !IsValidCategory(code) {
			return fmt.Errorf("categories 含未知类别: %s", code)
		}
		if !seen[code] {
			seen[code] = true
			dedup = append(dedup, code)
		}
	}
	in.Categories = dedup
	if in.Config == nil {
		in.Config = map[string]interface{}{}
	}
	if in.Type == TypeSyslog {
		in.Config = map[string]interface{}{} // syslog 渠道无自有配置
	}
	return nil
}

// resolveSecrets 处理密值占位符语义：******** = 保留原值（仅更新且渠道类型不变时允许）；
// existing 为 nil（新建）或类型变更时占位符非法。处理后用现有明文替换，供校验与加密落库。
func resolveSecrets(in *channelInput, existing *Channel) error {
	for _, field := range secretFields[in.Type] {
		raw, _ := in.Config[field].(string)
		if raw != MaskedValue {
			continue
		}
		if existing == nil {
			return fmt.Errorf("密值字段 %s 不能为空", field)
		}
		if existing.Type != in.Type {
			return fmt.Errorf("更换渠道类型后须重新填写密值字段 %s", field)
		}
		old, _ := existing.Config[field].(string)
		if old == "" {
			return fmt.Errorf("密值字段 %s 无原值可保留，请填写真实值", field)
		}
		in.Config[field] = old
	}
	return nil
}

// Create 新建渠道。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var in channelInput
	if err := response.DecodeJSON(w, r, &in, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if err := in.validateBasics(); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := resolveSecrets(&in, nil); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := h.dispatcher.ValidateChannelConfig(r.Context(), in.Type, in.Config); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	c := &Channel{
		Name: in.Name, Type: in.Type, Enabled: in.Enabled,
		MinSeverity: in.MinSeverity, Categories: in.Categories, Config: in.Config,
	}
	if err := h.store.Create(r.Context(), c); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", c.ID.String(), c.Name, audits.ResultSuccess)
	// 返回脱敏后的完整渠道（创建响应不回显明文密值）
	masked, err := h.store.GetMasked(r.Context(), c.ID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, masked)
}

// Update 更新渠道（密值字段写 ******** = 保留原值）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的渠道ID")
		return
	}
	var in channelInput
	if err := response.DecodeJSON(w, r, &in, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if err := in.validateBasics(); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	existing, err := h.store.GetDecrypted(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "通知渠道不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if err := resolveSecrets(&in, existing); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := h.dispatcher.ValidateChannelConfig(r.Context(), in.Type, in.Config); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	c := &Channel{
		ID: id, Name: in.Name, Type: in.Type, Enabled: in.Enabled,
		MinSeverity: in.MinSeverity, Categories: in.Categories, Config: in.Config,
	}
	if err := h.store.Update(r.Context(), c); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", id.String(), c.Name, audits.ResultSuccess)
	masked, err := h.store.GetMasked(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, masked)
}

// Delete 删除渠道。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的渠道ID")
		return
	}
	existing, err := h.store.GetMasked(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "通知渠道不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.Delete(r.Context(), id); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", id.String(), existing.Name, audits.ResultSuccess)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "通知渠道已删除"})
}

// Test 用渠道当前配置立即发送一条测试消息（不经过队列与抑制），如实返回失败原因。
func (h *Handler) Test(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的渠道ID")
		return
	}
	c, err := h.store.GetDecrypted(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "通知渠道不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	sendErr := h.dispatcher.SendTest(r.Context(), c)
	result := audits.ResultSuccess
	if sendErr != nil {
		result = audits.ResultFailure
	}
	h.recordAudit(r, p, "test", id.String(), c.Name, result)
	if sendErr != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"测试消息发送失败: "+sendErr.Error())
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "测试消息已发送"})
}

// recordAudit 记录操作审计（渠道配置属系统运维面，统一中风险）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, result string) {
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "notification",
		Action:       action,
		ObjectType:   "notification_channel",
		ObjectID:     objID,
		ObjectName:   objName,
		Result:       result,
		RiskLevel:    audits.RiskMedium,
		RequestID:    response.RequestIDFrom(r),
	})
}
