// tasks_handler.go AI 任务记录查询（编排执行的历史记录，按用户属主隔离）。
package aihandlers

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// TaskList 任务记录分页列表（仅本人；支持 status/task_type 过滤）。
func (d *Deps) TaskList(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录或会话已过期")
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	items, total, err := d.Orch.Tasks().List(r.Context(), p.UserID,
		r.URL.Query().Get("status"), r.URL.Query().Get("task_type"), page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, items, total, page, pageSize)
}

// TaskGet 任务记录详情（非属主一律 404）。
func (d *Deps) TaskGet(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录或会话已过期")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的任务ID")
		return
	}
	t, err := d.Orch.Tasks().Get(r.Context(), id, p.UserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "任务不存在")
		} else {
			response.InternalError(w, r, err)
		}
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"task": t})
}
