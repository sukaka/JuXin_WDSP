// handler.go 统一执行覆盖查询 HTTP 处理器（NG-COV-02 查询侧）：
//
//	GET /api/v1/api-security/protection/coverage  覆盖聚合（view=agg）/ 节点阶段计数（view=stages）
//
// 口径与纪律：
//   - agg 视图：窗口内 coverage_minute_agg 分钟桶按维度键汇总为 Metrics 行——
//     E=FULL+PARTIAL+SKIPPED+ERROR，NOT_APPLICABLE 另计不进 E；比率查询侧计算，
//     E=0 时 no_applicable_traffic=true 且比率为 0（绝不显示 100%）；
//   - data_incomplete：窗口内节点最新 cov_ingest 计数快照中 agg_overflow>0 或
//     agg_invalid>0 时为 true——统计输入不完整如实披露，不显示虚假完整；
//   - stages 视图：每节点最新一份 guard 链路阶段计数（total/rejected_*/intercepted_*/
//     reached_*，阶段集合与顺序跨仓冻结，见 gateway/modules/jiuzhang_guard/
//     coverage_counters.go covStageOrder），缺失阶段补零保序输出；
//   - 只读接口，权限点 api_protection.read（种子见迁移 000169）；
//     维度键即契约（应用/端点模板/检测器/方向/策略版本/节点），不新增敏感字段。
package coverage

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// PermProtectionRead 权限点（api_protection 模块只读；种子见迁移 000169）。
const PermProtectionRead = "api_protection.read"

// 查询窗口口径：默认 60 分钟，上限 7 天（10080 分钟）。
const (
	defaultWindowMinutes = 60
	maxWindowMinutes     = 7 * 24 * 60
	aggRowsLimit         = 1000
)

// guardStageOrder guard 链路阶段冻结顺序（跨仓契约：
// gateway/modules/jiuzhang_guard/coverage_counters.go covStageOrder；
// 标签冻结——进入聚合后不得改名，新增只准追加）。
var guardStageOrder = []string{
	"total",
	"rejected_manual_ban",
	"rejected_ip_blacklist",
	"rejected_auto_ban",
	"rejected_l7_acl",
	"rejected_cc",
	"rejected_license_quota",
	"intercepted_bot",
	"intercepted_waf",
	"reached_api_pipeline",
	"reached_upstream",
}

// Repository 查询侧仓储接口（*Store 直接满足；测试注入内存实现）。
type Repository interface {
	QueryAggView(ctx context.Context, aq AggQuery) ([]Metrics, error)
	LatestStageCounts(ctx context.Context, stageSet []string, nodeID string, from, to time.Time) ([]NodeStageSnapshot, error)
}

// Handler 统一执行覆盖查询处理器。
type Handler struct {
	store Repository
	// now 时间源（测试可注入固定时钟；nil 用 time.Now）
	now func() time.Time
}

// NewHandler 创建处理器。
func NewHandler(store Repository) *Handler {
	return &Handler{store: store}
}

// RegisterRoutes 注册路由（/api/v1/api-security 命名空间；权限点 api_protection.read）。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/protection/coverage",
		authz(middleware.RequirePermission(PermProtectionRead)(http.HandlerFunc(h.Coverage))))
}

// stageCountItem 单阶段计数（响应保序数组元素）。
type stageCountItem struct {
	Stage string `json:"stage"`
	Count int64  `json:"count"`
}

// nodeStagesView 单节点最新阶段计数（stages 视图响应元素）。
type nodeStagesView struct {
	NodeID     string           `json:"node_id"`
	CapturedAt time.Time        `json:"captured_at"`
	Counts     []stageCountItem `json:"counts"`
}

// aggViewData agg 视图响应 data。
type aggViewData struct {
	View           string    `json:"view"`
	WindowMinutes  int       `json:"window_minutes"`
	From           time.Time `json:"from"`
	To             time.Time `json:"to"`
	DataIncomplete bool      `json:"data_incomplete"`
	Rows           []Metrics `json:"rows"`
}

// stagesViewData stages 视图响应 data。
type stagesViewData struct {
	View          string           `json:"view"`
	WindowMinutes int              `json:"window_minutes"`
	From          time.Time        `json:"from"`
	To            time.Time        `json:"to"`
	Nodes         []nodeStagesView `json:"nodes"`
}

// coverageQuery 解析后的查询参数。
type coverageQuery struct {
	view          string
	applicationID string
	detector      string
	nodeID        string
	windowMinutes int
}

// Coverage GET /api/v1/api-security/protection/coverage
// 查询参数：application_id（UUID，非法 400）/detector/node_id（长度上限同列宽，
// 超长 400）/window_minutes（默认 60，非数字 400，非正数归一 60，越界夹紧 10080）/
// view（agg|stages，缺省 agg，其他取值 400）。
func (h *Handler) Coverage(w http.ResponseWriter, r *http.Request) {
	q, ok := parseCoverageQuery(w, r)
	if !ok {
		return
	}
	now := time.Now().UTC()
	if h.now != nil {
		now = h.now()
	}
	to := now
	from := now.Add(-time.Duration(q.windowMinutes) * time.Minute)

	switch q.view {
	case "stages":
		h.serveStages(w, r, q, from, to)
	default:
		h.serveAgg(w, r, q, from, to)
	}
}

// serveAgg agg 视图：窗口聚合 Metrics 行 + data_incomplete 披露。
func (h *Handler) serveAgg(w http.ResponseWriter, r *http.Request, q coverageQuery, from, to time.Time) {
	rows, err := h.store.QueryAggView(r.Context(), AggQuery{
		ApplicationID: q.applicationID,
		Detector:      q.detector,
		NodeID:        q.nodeID,
		From:          from,
		To:            to,
		Limit:         aggRowsLimit,
	})
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if rows == nil {
		rows = []Metrics{} // 空数据返回空数组不报错
	}
	incomplete, err := h.dataIncomplete(r, q.nodeID, from, to)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, aggViewData{
		View:           "agg",
		WindowMinutes:  q.windowMinutes,
		From:           from,
		To:             to,
		DataIncomplete: incomplete,
		Rows:           rows,
	})
}

// serveStages stages 视图：每节点最新一份 guard 阶段计数（冻结顺序，缺失补零）。
func (h *Handler) serveStages(w http.ResponseWriter, r *http.Request, q coverageQuery, from, to time.Time) {
	snaps, err := h.store.LatestStageCounts(r.Context(), guardStageOrder, q.nodeID, from, to)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	nodes := make([]nodeStagesView, 0, len(snaps))
	for _, snap := range snaps {
		counts := make([]stageCountItem, 0, len(guardStageOrder))
		for _, stage := range guardStageOrder {
			counts = append(counts, stageCountItem{Stage: stage, Count: snap.Counts[stage]})
		}
		nodes = append(nodes, nodeStagesView{
			NodeID:     snap.NodeID,
			CapturedAt: snap.CapturedAt,
			Counts:     counts,
		})
	}
	response.JSON(w, r, http.StatusOK, stagesViewData{
		View:          "stages",
		WindowMinutes: q.windowMinutes,
		From:          from,
		To:            to,
		Nodes:         nodes,
	})
}

// dataIncomplete 统计输入完整性披露：窗口内任一节点最新 cov_ingest 计数快照
// （agg_overflow / agg_invalid 累计口径）存在正计数即为 true。
func (h *Handler) dataIncomplete(r *http.Request, nodeID string, from, to time.Time) (bool, error) {
	snaps, err := h.store.LatestStageCounts(r.Context(),
		[]string{stageAggOverflow, stageAggInvalid}, nodeID, from, to)
	if err != nil {
		return false, err
	}
	for _, snap := range snaps {
		if snap.Counts[stageAggOverflow] > 0 || snap.Counts[stageAggInvalid] > 0 {
			return true, nil
		}
	}
	return false, nil
}

// parseCoverageQuery 解析并校验查询参数（失败已写 400 响应，ok=false）。
func parseCoverageQuery(w http.ResponseWriter, r *http.Request) (coverageQuery, bool) {
	q := r.URL.Query()
	out := coverageQuery{view: "agg", windowMinutes: defaultWindowMinutes}

	if raw := strings.TrimSpace(q.Get("view")); raw != "" {
		if raw != "agg" && raw != "stages" {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 view 取值（agg/stages）")
			return coverageQuery{}, false
		}
		out.view = raw
	}
	if raw := strings.TrimSpace(q.Get("application_id")); raw != "" {
		if _, err := uuid.Parse(raw); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 application_id（需 UUID）")
			return coverageQuery{}, false
		}
		out.applicationID = raw
	}
	out.detector = strings.TrimSpace(q.Get("detector"))
	if len(out.detector) > colDetector {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "detector 长度不能超过 96")
		return coverageQuery{}, false
	}
	out.nodeID = strings.TrimSpace(q.Get("node_id"))
	if len(out.nodeID) > colNodeID {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "node_id 长度不能超过 96")
		return coverageQuery{}, false
	}
	if raw := strings.TrimSpace(q.Get("window_minutes")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 window_minutes（需整数分钟）")
			return coverageQuery{}, false
		}
		if n <= 0 {
			n = defaultWindowMinutes // 非正数归一默认
		}
		if n > maxWindowMinutes {
			n = maxWindowMinutes // 越界夹紧上限（7 天）
		}
		out.windowMinutes = n
	}
	return out, true
}
