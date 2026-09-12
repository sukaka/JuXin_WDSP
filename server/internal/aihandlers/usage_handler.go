// usage_handler.go AI 用量与成本统计查询。
package aihandlers

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/response"
)

// UsageOverview 今日用量总览（Token/调用次数/成本）。
func (d *Deps) UsageOverview(w http.ResponseWriter, r *http.Request) {
	u, err := d.Cost.Overview(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"usage": u})
}

// UsageByUser 按用户统计（近 7 天，前 20）。
func (d *Deps) UsageByUser(w http.ResponseWriter, r *http.Request) {
	list, err := d.Cost.ByUser(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": list})
}

// UsageByAgent 按 Agent 统计。
func (d *Deps) UsageByAgent(w http.ResponseWriter, r *http.Request) {
	list, err := d.Cost.ByAgent(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": list})
}

// UsageByTask 按任务类型统计。
func (d *Deps) UsageByTask(w http.ResponseWriter, r *http.Request) {
	list, err := d.Cost.ByTask(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": list})
}
