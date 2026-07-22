// drafts_handler.go AI 草稿（推荐）查询与废弃：数据源 ai_recommendations。
// 所有草稿保持 DRAFT 语义，本层绝不执行发布/生效操作，生效须走既有人工校验发布流程。
package aihandlers

import (
	"errors"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aiaudit"
	"github.com/jiuzhang-waf/server/internal/aitools"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 草稿类型与状态白名单。
var draftTypes = map[string]bool{
	"EXCEPTION": true, "BLACKLIST": true, "CC_POLICY": true, "CUSTOM_RULE": true,
	"POLICY_CHANGE": true, "REPORT_SUMMARY": true,
}
var draftStatuses = map[string]bool{
	"DRAFT": true, "PENDING_REVIEW": true, "ACCEPTED": true, "REJECTED": true, "EXPIRED": true,
}

// DraftList 草稿分页列表（recommendation_type/status 可选过滤）。
func (d *Deps) DraftList(w http.ResponseWriter, r *http.Request) {
	recType := r.URL.Query().Get("recommendation_type")
	status := r.URL.Query().Get("status")
	if recType != "" && !draftTypes[recType] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的草稿类型")
		return
	}
	if status != "" && !draftStatuses[status] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的草稿状态")
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := d.Drafts.List(r.Context(), recType, status, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// DraftGet 草稿详情。
func (d *Deps) DraftGet(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的草稿ID")
		return
	}
	rec, err := d.Drafts.Get(r.Context(), id)
	if err != nil {
		d.draftError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"draft": rec})
}

// DraftDiscard 废弃草稿（逻辑标记 REJECTED，不删除记录，不触碰草稿指向的业务配置）。
func (d *Deps) DraftDiscard(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的草稿ID")
		return
	}
	if err := d.Drafts.Discard(r.Context(), id, p.UserID); err != nil {
		d.draftError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "draft_discard", DraftReference: id.String(),
		RequestSummary: "废弃草稿 " + id.String(), ResultSummary: "REJECTED",
	})
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "草稿已废弃"})
}

// RecommendationAccept 接受推荐（仅标记 ACCEPTED，进入人工草稿流程，不发布）。
func (d *Deps) RecommendationAccept(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的推荐ID")
		return
	}
	if err := d.Drafts.Accept(r.Context(), id, p.UserID); err != nil {
		d.draftError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "recommendation_accept", DraftReference: id.String(),
		RequestSummary: "接受推荐 " + id.String(), ResultSummary: "ACCEPTED",
	})
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "推荐已接受，请在对应业务页面完成人工校验与发布"})
}

// RecommendationReject 拒绝推荐。
func (d *Deps) RecommendationReject(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的推荐ID")
		return
	}
	if err := d.Drafts.Reject(r.Context(), id, p.UserID); err != nil {
		d.draftError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "recommendation_reject", DraftReference: id.String(),
		RequestSummary: "拒绝推荐 " + id.String(), ResultSummary: "REJECTED",
	})
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "推荐已拒绝"})
}

// DraftCreateByTool 通过 Tool 创建草稿（HTTP 入口，内部走 Tool 完整校验）。
func (d *Deps) DraftCreateByTool(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	toolCode := r.PathValue("type")
	codeMap := map[string]string{
		"exception": "draft.exception.create", "blacklist": "draft.blacklist.create",
		"cc-policy": "draft.cc_policy.create", "custom-rule": "draft.custom_rule.create",
	}
	toolCode = codeMap[toolCode]
	if toolCode == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的草稿类型")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 32768))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if len(body) == 0 {
		body = []byte("{}")
	}
	prin := &aitools.Principal{UserID: p.UserID, Username: p.Username, Permissions: p.PermsSet}
	if prin.Permissions == nil {
		prin.Permissions = map[string]bool{}
	}
	res, ref, err := d.Tools.Execute(r.Context(), prin, uuid.New(), nil, toolCode, body, nil)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "draft_create", DraftReference: ref,
		RequestSummary: "HTTP 创建草稿 " + toolCode, ResultSummary: "DRAFT",
	})
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"result": res, "tool_ref": ref})
}

// draftError 草稿错误映射。
func (d *Deps) draftError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, aitools.ErrDraftNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "草稿不存在")
	case errors.Is(err, aitools.ErrDraftState):
		response.Error(w, r, http.StatusConflict, response.CodeInvalidArgument, "草稿已处理，无法废弃")
	default:
		response.InternalError(w, r, err)
	}
}
