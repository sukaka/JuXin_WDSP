// audits_handler.go AI 审计查询与哈希链完整性校验。
package aihandlers

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aiaudit"
	"github.com/jiuzhang-waf/server/internal/response"
)

// AuditList AI 审计分页查询（user_id/session_id/action/task_type/时间范围可选过滤）。
func (d *Deps) AuditList(w http.ResponseWriter, r *http.Request) {
	f := aiaudit.ListFilter{
		Action:   r.URL.Query().Get("action"),
		TaskType: r.URL.Query().Get("task_type"),
		Page:     queryInt(r, "page", 1),
		PageSize: queryInt(r, "page_size", 20),
	}
	if s := r.URL.Query().Get("user_id"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的用户ID")
			return
		}
		f.UserID = &id
	}
	if s := r.URL.Query().Get("session_id"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的会话ID")
			return
		}
		f.SessionID = &id
	}
	if s := r.URL.Query().Get("start_time"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "开始时间格式须为 RFC3339")
			return
		}
		f.Start = t
	}
	if s := r.URL.Query().Get("end_time"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "结束时间格式须为 RFC3339")
			return
		}
		f.End = t
	}
	list, total, err := d.Audit.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// AuditVerify 审计哈希链完整性校验。
func (d *Deps) AuditVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Limit int `json:"limit"`
	}
	if err := decodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 10000
	}
	if limit > 100000 {
		limit = 100000
	}
	mismatches, err := d.Audit.VerifyChain(r.Context(), limit)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	var total int64
	if err := d.DB.QueryRow(r.Context(), `SELECT count(*) FROM ai_audit_records`).Scan(&total); err != nil {
		response.InternalError(w, r, err)
		return
	}
	checked := int64(limit)
	if total < checked {
		checked = total
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"checked":    checked,
		"mismatches": mismatches,
		"ok":         mismatches == 0,
	})
}
