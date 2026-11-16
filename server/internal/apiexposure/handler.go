// handler.go 暴露面判定 HTTP 处理器：
//   - GET  /api/v1/api-security/endpoints/{id}/exposure          当前维度值 + 最近一次评估明细（权限 api_asset.read）
//   - POST /api/v1/api-security/endpoints/{id}/exposure/reassess 即时重评（权限 api_asset.edit + 操作审计）
package apiexposure

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 暴露面判定处理器。
type Handler struct {
	store   Repository
	audits  audits.Recorder // nil 时跳过审计（装配层恒注入 *audits.Service）
	sweeper *Sweeper        // nil 时重评接口 503（装配未接评估器）
}

// NewHandler 创建处理器（构造注入审计服务，语义同 apiassets/apiweakness；
// 显式判空防 typed-nil 进入接口）。
func NewHandler(store Repository, audit *audits.Service) *Handler {
	h := &Handler{store: store}
	if audit != nil {
		h.audits = audit
	}
	return h
}

// SetSweeper 注入评估器（重评接口用；装配层调用）。
func (h *Handler) SetSweeper(s *Sweeper) *Handler { h.sweeper = s; return h }

// dimensionView 当前 EXPOSURE 分类维度视图（无维度行时 value/source 为空串）。
type dimensionView struct {
	Value      string  `json:"value"`
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
}

// assessmentView 评估明细视图（评估时间为零值时整体不输出）。
type assessmentView struct {
	Verdict    string         `json:"verdict"`
	Source     string         `json:"source"`
	Confidence string         `json:"confidence"`
	Evidence   []EvidenceItem `json:"evidence"`
	AssessedAt time.Time      `json:"assessed_at"`
}

// exposureResponse GET 响应：当前维度 + 最近一次评估。
type exposureResponse struct {
	EndpointID  uuid.UUID       `json:"endpoint_id"`
	EndpointKey string          `json:"endpoint_key"`
	Locked      bool            `json:"locked"` // 分类锁定（锁定/人工来源时引擎不覆盖）
	Current     dimensionView   `json:"current"`
	Assessment  *assessmentView `json:"assessment"` // null = 从未评估
}

// GetExposure GET /api/v1/api-security/endpoints/{id}/exposure
// 当前 EXPOSURE 维度值（api_classification_dimensions 实时口径）+ 最近一次评估明细。
func (h *Handler) GetExposure(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	ectx, err := h.store.EndpointContext(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	resp := exposureResponse{
		EndpointID:  id,
		EndpointKey: ectx.EndpointKey,
		Locked:      ectx.Locked,
		Current: dimensionView{
			Value:      ectx.ExistingValue,
			Source:     ectx.ExistingSource,
			Confidence: ectx.ExistingConfidence,
		},
	}
	latest, err := h.store.LatestAssessment(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if latest != nil {
		resp.Assessment = &assessmentView{
			Verdict:    latest.Verdict,
			Source:     latest.Source,
			Confidence: latest.Confidence,
			Evidence:   latest.Evidence,
			AssessedAt: latest.AssessedAt,
		}
	}
	response.JSON(w, r, http.StatusOK, resp)
}

// reassessResponse POST 重评响应。
type reassessResponse struct {
	Assessment assessmentView `json:"assessment"`
	Applied    bool           `json:"applied"` // 维度是否被本次判定更新（人工/锁定不更新）
	Message    string         `json:"message"`
}

// Reassess POST /api/v1/api-security/endpoints/{id}/exposure/reassess
// 即时重评：重新装配证据评估、写评估明细、条件 upsert 维度（人工/锁定不覆盖），
// 写操作审计（RiskLow——判定可重入，不产生不可恢复变更）。
func (h *Handler) Reassess(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	p := authz.PrincipalFrom(r.Context())
	if h.sweeper == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "暴露面评估器未装配")
		return
	}
	if _, err := h.store.EndpointContext(r.Context(), id); errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	} else if err != nil {
		response.InternalError(w, r, err)
		return
	}
	a, applied, err := h.sweeper.AssessEndpoint(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	// 回读刚落库的评估明细（响应与持久化同一事实源）
	latest, err := h.store.LatestAssessment(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if latest == nil { // 防御：重评恒写明细，正常不会发生
		response.InternalError(w, r, errors.New("reassess wrote no assessment"))
		return
	}
	view := assessmentView{
		Verdict:    latest.Verdict,
		Source:     latest.Source,
		Confidence: latest.Confidence,
		Evidence:   latest.Evidence,
		AssessedAt: latest.AssessedAt,
	}
	h.recordAudit(r, p, id.String(), fmt.Sprintf("重评暴露面 → %s（%s/%s，维度更新=%t）",
		a.Verdict, a.Source, a.Confidence, applied))
	response.JSON(w, r, http.StatusOK, reassessResponse{
		Assessment: view,
		Applied:    applied,
		Message:    "已完成重新评估",
	})
}

// recordAudit 写操作审计（语义同 apiassets：操作者/对象/摘要/风险等级；
// 审计服务未注入或无操作者上下文时跳过，不影响主流程）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, objID, summary string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "api_exposure",
		Action:       "reassess",
		ObjectType:   "api_endpoint",
		ObjectID:     objID,
		AfterSummary: summary,
		Result:       audits.ResultSuccess,
		RiskLevel:    audits.RiskLow,
		RequestID:    response.RequestIDFrom(r),
	})
}

// parsePathID 解析路径参数 id（非法即写 400，语义同 apiassets）。
func parsePathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的接口ID")
		return uuid.Nil, false
	}
	return id, true
}
