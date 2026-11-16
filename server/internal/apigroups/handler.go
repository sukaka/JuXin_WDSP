package apigroups

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

const bodyMaxBytes = 16 << 10

type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

type Handler struct {
	repo   Repository
	audits auditRecorder
}

func NewHandler(repo Repository, audit *audits.Service) *Handler {
	h := &Handler{repo: repo}
	if audit != nil {
		h.audits = audit
	}
	return h
}

type groupRequest struct {
	ApplicationID uuid.UUID `json:"application_id"`
	Code          string    `json:"code"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	Enabled       *bool     `json:"enabled"`
}

type updateGroupRequest struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     *bool  `json:"enabled"`
}

type addEndpointRequest struct {
	EndpointID uuid.UUID `json:"endpoint_id"`
}

func enabledOrDefault(value *bool) bool {
	if value == nil {
		return true
	}
	return *value
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	page, pageSize, err := parsePagination(r)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	filter := ListFilter{Page: page, PageSize: pageSize}
	if raw := strings.TrimSpace(r.URL.Query().Get("application_id")); raw != "" {
		applicationID, err := uuid.Parse(raw)
		if err != nil || applicationID == uuid.Nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "application_id 非法")
			return
		}
		filter.ApplicationID = &applicationID
	}
	items, total, err := h.repo.List(r.Context(), filter)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	response.Page(w, r, items, total, page, pageSize)
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req groupRequest
	if err := response.DecodeJSON(w, r, &req, bodyMaxBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	g, err := h.repo.Create(r.Context(), CreateInput{
		ApplicationID: req.ApplicationID,
		Code:          req.Code,
		Name:          req.Name,
		Description:   req.Description,
		Enabled:       enabledOrDefault(req.Enabled),
	})
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", "api_endpoint_group", g.ID.String(), g.Code, "", groupSummary(g), audits.RiskMedium)
	response.JSON(w, r, http.StatusCreated, g)
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	g, err := h.repo.Get(r.Context(), id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, g)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	var req updateGroupRequest
	if err := response.DecodeJSON(w, r, &req, bodyMaxBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	before, err := h.repo.Get(r.Context(), id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	g, err := h.repo.Update(r.Context(), id, UpdateInput{
		Code:        req.Code,
		Name:        req.Name,
		Description: req.Description,
		Enabled:     enabledOrDefault(req.Enabled),
	})
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", "api_endpoint_group", g.ID.String(), g.Code, groupSummary(before), groupSummary(g), audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, g)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	g, err := h.repo.Get(r.Context(), id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if err := h.repo.Delete(r.Context(), id); err != nil {
		h.writeError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", "api_endpoint_group", id.String(), g.Code, groupSummary(g), "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *Handler) ListEndpoints(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	page, pageSize, err := parsePagination(r)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	items, total, err := h.repo.ListEndpoints(r.Context(), id, page, pageSize)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	response.Page(w, r, items, total, page, pageSize)
}

func (h *Handler) AddEndpoint(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	var req addEndpointRequest
	if err := response.DecodeJSON(w, r, &req, bodyMaxBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.EndpointID == uuid.Nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "endpoint_id 必填")
		return
	}
	member, err := h.repo.AddEndpoint(r.Context(), id, req.EndpointID)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.recordAudit(r, p, "member_add", "api_endpoint_group_member", id.String(), req.EndpointID.String(), "",
		"endpoint_id="+req.EndpointID.String(), audits.RiskMedium)
	response.JSON(w, r, http.StatusCreated, member)
}

func (h *Handler) RemoveEndpoint(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r, "id")
	if !ok {
		return
	}
	endpointID, ok := parsePathID(w, r, "endpoint_id")
	if !ok {
		return
	}
	if err := h.repo.RemoveEndpoint(r.Context(), id, endpointID); err != nil {
		h.writeError(w, r, err)
		return
	}
	h.recordAudit(r, p, "member_remove", "api_endpoint_group_member", id.String(), endpointID.String(),
		"endpoint_id="+endpointID.String(), "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

func parsePathID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil || id == uuid.Nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, name+" 非法")
		return uuid.Nil, false
	}
	return id, true
}

func parsePagination(r *http.Request) (int, int, error) {
	page, err := parsePositiveQuery(r, "page", 1)
	if err != nil {
		return 0, 0, err
	}
	pageSize, err := parsePositiveQuery(r, "page_size", 20)
	if err != nil {
		return 0, 0, err
	}
	if pageSize > maxPageSize {
		return 0, 0, fmt.Errorf("page_size 不能超过 %d", maxPageSize)
	}
	return page, pageSize, nil
}

func parsePositiveQuery(r *http.Request, name string, defaultValue int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return defaultValue, nil
	}
	value, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s 须为正整数", name)
	}
	return int(value), nil
}

func groupSummary(g *Group) string {
	if g == nil {
		return ""
	}
	return fmt.Sprintf("application_id=%s code=%s name=%s enabled=%t endpoint_count=%d",
		g.ApplicationID, g.Code, g.Name, g.Enabled, g.EndpointCount)
}

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var validation *ValidationError
	switch {
	case errors.As(err, &validation):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, validation.Error())
	case errors.Is(err, ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口分组不存在")
	case errors.Is(err, ErrApplicationNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
	case errors.Is(err, ErrEndpointNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
	case errors.Is(err, ErrMemberNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口成员不存在")
	case errors.Is(err, ErrDuplicate):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "同应用内 code 已存在")
	case errors.Is(err, ErrDuplicateMember):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "接口已在该分组中")
	case errors.Is(err, ErrApplicationMismatch):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "接口必须属于分组所在应用")
	default:
		response.InternalError(w, r, err)
	}
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objectType, objectID, objectName, before, after, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "api_security",
		Action:        action,
		ObjectType:    objectType,
		ObjectID:      objectID,
		ObjectName:    objectName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        audits.ResultSuccess,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}
