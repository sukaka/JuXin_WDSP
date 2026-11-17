package apidataflow

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

const (
	PermDataFlowRead         = "api_data_flow.read"
	PermDataFlowEvidenceRead = "api_data_flow.evidence.read"
)

type auditRecorder interface {
	Record(context.Context, audits.RecordInput) error
}

type Handler struct {
	reader Reader
	audits auditRecorder
}

func NewHandler(reader Reader) *Handler { return &Handler{reader: reader} }

func (h *Handler) SetAudits(a auditRecorder) *Handler { h.audits = a; return h }

func RegisterRoutes(mux *http.ServeMux, authzFn func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/data-flow/graph", authzFn(middleware.RequirePermission(PermDataFlowRead)(http.HandlerFunc(h.Graph))))
	mux.Handle("GET /api/v1/api-security/data-flow/nodes/{node_id...}", authzFn(middleware.RequirePermission(PermDataFlowRead)(http.HandlerFunc(h.Node))))
	mux.Handle("GET /api/v1/api-security/data-flow/evidence", authzFn(middleware.RequirePermission(PermDataFlowEvidenceRead)(http.HandlerFunc(h.Evidence))))
	mux.Handle("GET /api/v1/api-security/data-flow/quality", authzFn(middleware.RequirePermission(PermDataFlowRead)(http.HandlerFunc(h.Quality))))
}

func (h *Handler) Graph(w http.ResponseWriter, r *http.Request) {
	filter, err := parseGraphFilter(r)
	if err != nil {
		badDataflowRequest(w, r, err)
		return
	}
	graph, err := h.reader.Graph(r.Context(), filter)
	if err != nil {
		writeDataflowError(w, r, err)
		return
	}
	quality, err := h.reader.Quality(r.Context(), filter)
	if err != nil {
		writeDataflowError(w, r, err)
		return
	}
	graph.Quality = quality
	if graph.RuntimeFieldsWarning != "" {
		graph.Quality.Partial = true
		graph.Quality.Message = graph.RuntimeFieldsWarning
	}
	response.JSON(w, r, http.StatusOK, graph)
}

func (h *Handler) Node(w http.ResponseWriter, r *http.Request) {
	filter, err := parseGraphFilter(r)
	if err != nil {
		badDataflowRequest(w, r, err)
		return
	}
	graph, err := h.reader.Graph(r.Context(), filter)
	if err != nil {
		writeDataflowError(w, r, err)
		return
	}
	nodeID := strings.TrimPrefix(r.PathValue("node_id"), "/")
	for _, node := range graph.Nodes {
		if node.ID != nodeID {
			continue
		}
		dependencies := []Edge{}
		calledBy := []Edge{}
		for _, edge := range graph.Edges {
			if edge.SourceID == nodeID {
				dependencies = append(dependencies, edge)
			}
			if edge.TargetID == nodeID {
				calledBy = append(calledBy, edge)
			}
		}
		response.JSON(w, r, http.StatusOK, map[string]interface{}{
			"node": node, "dependencies": dependencies, "called_by": calledBy,
		})
		return
	}
	response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "数据流节点不存在")
}

func (h *Handler) Evidence(w http.ResponseWriter, r *http.Request) {
	filter, err := parseGraphFilter(r)
	if err != nil {
		badDataflowRequest(w, r, err)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	edgeID := strings.TrimSpace(r.URL.Query().Get("edge_id"))
	records, err := h.reader.Evidence(r.Context(), edgeID, filter, limit)
	if err != nil {
		writeDataflowError(w, r, err)
		return
	}
	h.recordEvidenceAudit(r, edgeID)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": records, "total": len(records)})
}

func (h *Handler) Quality(w http.ResponseWriter, r *http.Request) {
	filter, err := parseGraphFilter(r)
	if err != nil {
		badDataflowRequest(w, r, err)
		return
	}
	quality, err := h.reader.Quality(r.Context(), filter)
	if err != nil {
		writeDataflowError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, quality)
}

func parseGraphFilter(r *http.Request) (GraphFilter, error) {
	filter := GraphFilter{MaxEdges: 50}
	query := r.URL.Query()
	start, err := parseDataflowTime(query.Get("start"), query.Get("start_time"))
	if err != nil {
		return filter, err
	}
	end, err := parseDataflowTime(query.Get("end"), query.Get("end_time"))
	if err != nil {
		return filter, err
	}
	now := time.Now().UTC()
	if start.IsZero() {
		start = now.Add(-time.Hour)
	}
	if end.IsZero() {
		end = now
	}
	filter.Start, filter.End = start, end
	if value := strings.TrimSpace(query.Get("application_id")); value != "" {
		id, err := uuid.Parse(value)
		if err != nil {
			return filter, errors.New("无效的 application_id")
		}
		filter.ApplicationID = &id
	}
	filter.Method = strings.ToUpper(strings.TrimSpace(query.Get("method")))
	if len(filter.Method) > 16 || len(query.Get("data_type")) > 64 {
		return filter, errors.New("无效的 method 或 data_type")
	}
	filter.DataType = strings.TrimSpace(query.Get("data_type"))
	if value := strings.TrimSpace(query.Get("max_edges")); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil {
			return filter, errors.New("无效的 max_edges")
		}
		filter.MaxEdges = n
	}
	filter.View = strings.ToLower(strings.TrimSpace(query.Get("view")))
	return filter, nil
}

func parseDataflowTime(values ...string) (time.Time, error) {
	for _, value := range values {
		if value == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return time.Time{}, errors.New("时间须为 RFC3339 格式")
		}
		return parsed.UTC(), nil
	}
	return time.Time{}, nil
}

func badDataflowRequest(w http.ResponseWriter, r *http.Request, err error) {
	response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
}

func writeDataflowError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrObservationDataPlane) {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "数据流存储暂不可用，请检查 ClickHouse 配置与状态")
		return
	}
	response.InternalError(w, r, err)
}

func (h *Handler) recordEvidenceAudit(r *http.Request, edgeID string) {
	if h.audits == nil {
		return
	}
	principal := authz.PrincipalFrom(r.Context())
	if principal == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID: &principal.UserID, Username: principal.Username,
		SourceIP: middleware.RemoteIP(r), ConnectionIP: middleware.ConnectionIP(r), UserAgent: r.UserAgent(),
		Module: "api_data_flow", Action: "read_evidence", ObjectType: "data_flow_edge", ObjectID: edgeID,
		Result: audits.ResultSuccess, RiskLevel: audits.RiskHigh, RequestID: response.RequestIDFrom(r),
	})
}
