package securityidentities

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

type identityTransitionFunc func(ctx context.Context, id uuid.UUID, reason string, operatorID uuid.UUID) (*Identity, bool, error)

type IdentityPublishFunc func(ctx context.Context, operatorID uuid.UUID, requestID string)

func (h *Handler) SetAudits(a *audits.Service) *Handler {
	h.audits = a
	return h
}

func (h *Handler) SetPublishFunc(fn IdentityPublishFunc) *Handler {
	h.publish = fn
	return h
}

func (h *Handler) Block(w http.ResponseWriter, r *http.Request) {
	h.transition(w, r, true)
}

func (h *Handler) Unblock(w http.ResponseWriter, r *http.Request) {
	h.transition(w, r, false)
}

func (h *Handler) transition(w http.ResponseWriter, r *http.Request, block bool) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未认证")
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	reason := ""
	if block {
		var req struct {
			Reason string `json:"reason"`
		}
		if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
			return
		}
		reason = strings.TrimSpace(req.Reason)
		if reason == "" || utf8.RuneCountInString(reason) > 512 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "reason 必填且不能超过 512 个字符")
			return
		}
	} else if !emptyRequestBody(r) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "unblock 请求体必须为空")
		return
	}

	var updated *Identity
	var changed bool
	var err error
	if block {
		updated, changed, err = h.blockFn(r.Context(), id, reason, p.UserID)
	} else {
		updated, changed, err = h.unblockFn(r.Context(), id, "", p.UserID)
	}
	if err != nil {
		h.writeNotFound(w, r, err)
		return
	}
	if changed {
		beforeStatus, afterStatus, action := "NORMAL", "NORMAL", "unblock"
		if block {
			afterStatus, action = "BLOCKED", "block"
		}
		h.recordAudit(r, p, action, id, beforeStatus, afterStatus)
		if h.publish != nil {
			h.publish(r.Context(), p.UserID, response.RequestIDFrom(r))
		}
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"identity": updated, "changed": changed})
}

func emptyRequestBody(r *http.Request) bool {
	if r.Body == nil || r.Body == http.NoBody {
		return true
	}
	var buf [1]byte
	n, err := r.Body.Read(buf[:])
	return n == 0 && (err == nil || errors.Is(err, io.EOF))
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action string, id uuid.UUID, beforeStatus, afterStatus string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "security_identities",
		Action:        action,
		ObjectType:    "client_identity",
		ObjectID:      id.String(),
		ObjectName:    "客户身份",
		BeforeSummary: `{"status":"` + beforeStatus + `"}`,
		AfterSummary:  `{"status":"` + afterStatus + `"}`,
		Result:        audits.ResultSuccess,
		RiskLevel:     audits.RiskHigh,
		RequestID:     response.RequestIDFrom(r),
	})
}
