package tlssessions

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 是 SSL/HTTPS 加密会话分析 HTTP 处理器。
type Handler struct {
	repo Repository
}

// NewHandler 创建加密会话分析处理器。
func NewHandler(repo Repository) *Handler {
	return &Handler{repo: repo}
}

// List 查询加密会话握手事件明细（分页 + 多维筛选）。
// GET /api/v1/tls-sessions
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f, err := parseListFilter(r)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	items, total, err := h.repo.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if items == nil {
		items = []SessionEvent{}
	}
	response.Page(w, r, items, total, f.Page, f.PageSize)
}

// Summary 查询加密会话握手汇总统计（总览、协议分布、密码套件分布）。
// GET /api/v1/tls-sessions/summary
func (h *Handler) Summary(w http.ResponseWriter, r *http.Request) {
	f, err := parseSummaryFilter(r)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	summary, err := h.repo.Summary(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if summary == nil {
		summary = &Summary{}
	}
	if summary.ByProtocol == nil {
		summary.ByProtocol = []ProtocolStat{}
	}
	if summary.ByCipherSuite == nil {
		summary.ByCipherSuite = []CipherSuiteStat{}
	}
	response.JSON(w, r, http.StatusOK, summary)
}

func parseListFilter(r *http.Request) (ListFilter, error) {
	q := r.URL.Query()
	page, err := parsePositiveInt(q.Get("page"), "page", 1)
	if err != nil {
		return ListFilter{}, err
	}
	pageSize, err := parsePositiveInt(q.Get("page_size"), "page_size", 20)
	if err != nil {
		return ListFilter{}, err
	}
	if pageSize > 100 {
		pageSize = 100
	}

	startTime, err := parseOptionalRFC3339(q.Get("start_time"), "start_time")
	if err != nil {
		return ListFilter{}, err
	}
	endTime, err := parseOptionalRFC3339(q.Get("end_time"), "end_time")
	if err != nil {
		return ListFilter{}, err
	}
	if startTime != nil && endTime != nil && endTime.Before(*startTime) {
		return ListFilter{}, fmt.Errorf("end_time 不能早于 start_time")
	}

	sni := strings.TrimSpace(q.Get("sni"))
	if len(sni) > maxSNILen {
		return ListFilter{}, fmt.Errorf("sni 长度不能超过%d字节", maxSNILen)
	}
	clientIP := strings.TrimSpace(q.Get("client_ip"))
	if len(clientIP) > maxClientIPLen {
		return ListFilter{}, fmt.Errorf("client_ip 长度不能超过%d字节", maxClientIPLen)
	}

	detectedProtocol := strings.TrimSpace(q.Get("detected_protocol"))
	if detectedProtocol != "" {
		if !IsValidDetectedProtocol(detectedProtocol) {
			return ListFilter{}, fmt.Errorf("detected_protocol 不合法，仅支持 SSLv2/SSLv2/v3/SSLv3/TLS1.0/TLS1.1/TLS1.2/TLS1.3/TLCP1.1/UNKNOWN")
		}
	}

	action := strings.ToUpper(strings.TrimSpace(q.Get("action")))
	if action != "" && !IsValidAction(action) {
		return ListFilter{}, fmt.Errorf("action 不合法，仅支持 ALLOWED/BLOCKED_LEGACY_SSL/BLOCKED_PROTOCOL_POLICY/HANDSHAKE_FAILED")
	}

	var isGM *bool
	if rawGM := strings.TrimSpace(q.Get("is_gm")); rawGM != "" {
		switch strings.ToLower(rawGM) {
		case "true":
			v := true
			isGM = &v
		case "false":
			v := false
			isGM = &v
		default:
			return ListFilter{}, fmt.Errorf("is_gm 必须为 true 或 false")
		}
	}

	appID, err := parseOptionalUUID(q.Get("application_id"), "application_id")
	if err != nil {
		return ListFilter{}, err
	}

	return ListFilter{
		StartTime:        startTime,
		EndTime:          endTime,
		SNI:              sni,
		ClientIP:         clientIP,
		DetectedProtocol: detectedProtocol,
		Action:           action,
		IsGM:             isGM,
		ApplicationID:    appID,
		Page:             page,
		PageSize:         pageSize,
	}, nil
}

func parseSummaryFilter(r *http.Request) (SummaryFilter, error) {
	q := r.URL.Query()
	startTime, err := parseOptionalRFC3339(q.Get("start_time"), "start_time")
	if err != nil {
		return SummaryFilter{}, err
	}
	endTime, err := parseOptionalRFC3339(q.Get("end_time"), "end_time")
	if err != nil {
		return SummaryFilter{}, err
	}
	if startTime != nil && endTime != nil && endTime.Before(*startTime) {
		return SummaryFilter{}, fmt.Errorf("end_time 不能早于 start_time")
	}
	appID, err := parseOptionalUUID(q.Get("application_id"), "application_id")
	if err != nil {
		return SummaryFilter{}, err
	}
	return SummaryFilter{
		StartTime:     startTime,
		EndTime:       endTime,
		ApplicationID: appID,
	}, nil
}

func parsePositiveInt(raw, name string, def int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s 必须是正整数", name)
	}
	return n, nil
}

func parseOptionalRFC3339(raw, name string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("%s 必须是 RFC3339 时间格式", name)
	}
	u := t.UTC()
	return &u, nil
}

func parseOptionalUUID(raw, name string) (*uuid.UUID, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s 必须是合法 UUID", name)
	}
	return &id, nil
}
