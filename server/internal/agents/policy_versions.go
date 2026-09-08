// policy_versions.go 策略版本化与回滚管理端点（Phase 2，设计 §68.13/§68.14）：
//
//	GET  /api/v1/traffic/policies/{id}/versions  历史版本列表（version 倒序，标记当前版本）
//	POST /api/v1/traffic/policies/{id}/rollback  回滚到指定历史版本（生成新版本 version+1，
//	                                             联动绑定 Agent config_version+1，HIGH 审计）
//
// 快照时机：策略创建 / 每次 PUT / 每次回滚均在同一事务写入 agent_policy_versions 一行
// （store.snapshotPolicyVersion）；既有策略由迁移 000110 回填当前版本快照。
// 响应同 handler.go：统一信封 response.Body，成功 data 承载契约结构。
package agents

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// policyVersionItem 版本列表项（current 标记是否为当前生效版本）。
type policyVersionItem struct {
	Version   int             `json:"version"`
	Config    json.RawMessage `json:"config"`
	CreatedBy string          `json:"created_by"`
	CreatedAt time.Time       `json:"created_at"`
	Current   bool            `json:"current"`
}

// ListPolicyVersions GET /api/v1/traffic/policies/{id}/versions（traffic.agents.view）。
func (h *Handler) ListPolicyVersions(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略 ID 非法")
		return
	}
	policy, err := h.store.GetPolicy(r.Context(), id)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	versions, err := h.store.ListPolicyVersions(r.Context(), id)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	items := make([]policyVersionItem, 0, len(versions))
	for i := range versions {
		v := &versions[i]
		items = append(items, policyVersionItem{
			Version:   v.Version,
			Config:    v.Config,
			CreatedBy: v.CreatedBy,
			CreatedAt: v.CreatedAt,
			Current:   v.Version == policy.Version,
		})
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

// rollbackPolicyRequest 回滚入参（目标历史版本号）。
type rollbackPolicyRequest struct {
	Version int `json:"version"`
}

// RollbackPolicy POST /api/v1/traffic/policies/{id}/rollback（traffic.agents.manage）。
// 以历史版本 config 生成新版本（version+1）——回滚自身也是一次版本演进，历史链不可变。
func (h *Handler) RollbackPolicy(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略 ID 非法")
		return
	}
	var req rollbackPolicyRequest
	if !decodeAdminJSON(w, r, &req) {
		return
	}
	if req.Version < 1 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "version 须为正整数")
		return
	}
	before, err := h.store.GetPolicy(r.Context(), id)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	updated, err := h.store.RollbackPolicy(r.Context(), id, req.Version, principalName(p))
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "rollback", "agent_policy", id.String(), updated.Name,
		rollbackAuditBefore(before.Version), rollbackAuditAfter(updated.Version, req.Version),
		audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, updated)
}

// rollbackAuditBefore 回滚审计 before（合法 JSON；from_version 为操作前当前版本）。
func rollbackAuditBefore(fromVersion int) string {
	raw, _ := json.Marshal(map[string]interface{}{"from_version": fromVersion})
	return string(raw)
}

// rollbackAuditAfter 回滚审计 after（合法 JSON；to_version 为回滚生成的新版本，
// rolled_back_from 为目标历史版本——before/after 合含 from_version/to_version 以便溯源）。
func rollbackAuditAfter(toVersion, rolledBackFrom int) string {
	raw, _ := json.Marshal(map[string]interface{}{
		"to_version":       toVersion,
		"rolled_back_from": rolledBackFrom,
	})
	return string(raw)
}
