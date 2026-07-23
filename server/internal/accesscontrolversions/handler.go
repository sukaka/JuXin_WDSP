package accesscontrolversions

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// redactVersionConfig 脱敏版本 config 中的 valkey.password，避免 API 回传明文密钥。
func redactVersionConfig(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	if v, ok := m["valkey"].(map[string]interface{}); ok {
		if pwd, ok := v["password"].(string); ok && pwd != "" && pwd != "***" {
			v["password"] = "***"
			m["valkey"] = v
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

// versionMeta 列表项：不含完整 config（防大数据与密钥外泄）。
func versionMeta(v Version) map[string]interface{} {
	return map[string]interface{}{
		"id":                  v.ID,
		"version_no":          v.VersionNo,
		"config_hash":         v.ConfigHash,
		"change_summary":      v.ChangeSummary,
		"previous_version_id": v.PreviousVersionID,
		"publish_task_id":     v.PublishTaskID,
		"publish_result":      v.PublishResult,
		"created_by":          v.CreatedBy,
		"created_at":          v.CreatedAt,
	}
}

// RollbackFunc 是回滚回调（由 publisher 装配注入）：
// 返回回滚产生的发布结果（如发布任务信息），错误表示回滚失败。
type RollbackFunc func(ctx context.Context, versionID uuid.UUID, requestedBy uuid.UUID, requestID string) (interface{}, error)

// Handler 是访问控制配置版本处理器。
type Handler struct {
	store      *Store
	audits     *audits.Service
	rollbackFn RollbackFunc // 可为 nil（nil 时 Rollback 返回未配置错误）
}

// NewHandler 创建版本处理器。
func NewHandler(store *Store, au *audits.Service, rollbackFn RollbackFunc) *Handler {
	return &Handler{store: store, audits: au, rollbackFn: rollbackFn}
}

// SetRollbackFunc 设置回滚回调（应用装配时使用）。
func (h *Handler) SetRollbackFunc(fn RollbackFunc) {
	h.rollbackFn = fn
}

// List 版本列表（仅元数据，不含 config 正文）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.List(r.Context(), page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	items := make([]map[string]interface{}, 0, len(list))
	for _, v := range list {
		items = append(items, versionMeta(v))
	}
	response.Page(w, r, items, total, page, pageSize)
}

// Get 版本详情（config 已脱敏）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的版本ID")
		return
	}
	v, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "版本不存在")
		return
	}
	meta := versionMeta(*v)
	meta["config"] = json.RawMessage(redactVersionConfig(v.Config))
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"version": meta})
}

// Diff 两版本配置对比（顶层浅层 diff，输出人类可读摘要行）。
// compare_with 为空时默认与上一版本对比。
func (h *Handler) Diff(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的版本ID")
		return
	}
	target, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "版本不存在")
		return
	}

	var base *Version
	if cw := r.URL.Query().Get("compare_with"); cw != "" {
		baseID, err := uuid.Parse(cw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 compare_with 版本ID")
			return
		}
		base, err = h.store.GetByID(r.Context(), baseID)
		if err != nil {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "对比版本不存在")
			return
		}
	} else if target.PreviousVersionID != nil {
		base, err = h.store.GetByID(r.Context(), *target.PreviousVersionID)
		if err != nil {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "上一版本不存在")
			return
		}
	} else {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "该版本没有上一版本，请指定 compare_with 参数")
		return
	}

	lines, err := DiffConfigs(base.Config, target.Config)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"version_id":      target.ID,
		"version_no":      target.VersionNo,
		"compare_with":    base.ID,
		"compare_with_no": base.VersionNo,
		"differences":     lines,
	})
}

// Rollback 回滚到指定版本（调用注入的 RollbackFunc 完成实际发布）。
func (h *Handler) Rollback(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的版本ID")
		return
	}
	if _, err := h.store.GetByID(r.Context(), id); err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "版本不存在")
		return
	}
	if h.rollbackFn == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "发布服务未配置")
		return
	}
	result, err := h.rollbackFn(r.Context(), id, p.UserID, response.RequestIDFrom(r))
	if err != nil {
		h.recordAudit(r, p, "rollback", id.String(), "", audits.ResultFailure, audits.RiskHigh, err.Error())
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "rollback", id.String(), "", audits.ResultSuccess, audits.RiskHigh, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"message": "回滚已提交",
		"result":  result,
	})
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, result, risk, failureReason string) {
	_ = h.audits.Record(r.Context(), audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "access_control_versions",
		Action:        action,
		ObjectType:    "access_control_version",
		ObjectID:      objID,
		ObjectName:    objName,
		Result:        result,
		FailureReason: failureReason,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
