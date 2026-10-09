// admission.go API 准入防护 P1：覆盖率报告与准入拦截列表
// （docs/API_ADMISSION_CONTROL_DESIGN.md §5.2/§5.3；冻结契约见任务书）。
//
// 数据源与事件→应用归因口径（重要，改动前先读）：
//   - api_runtime_events 自建表（000016）起无 application_id 列（000029/000030/000035/
//     000127/000131/000149/000150 历次增补均未引入），事件→应用只能经 endpoint_key
//     关联 api_endpoints 的同应用行；
//   - 该关联成立的前提：采集器对全部网关事件按发现信息 upsert 端点资产
//     （apiruntime/collector.go「全部记录按 endpoint 发现信息 upsert 端点资产」），
//     故 PROTECT 拦截的未知端点也会落为该应用 DISCOVERED 行，拦截统计不漏；
//   - 迁移 000137 起 endpoint_key 非全局唯一（作用域=application+domain+binding+host），
//     同一 endpoint_key 出现在多应用基线时，窗口命中会分别归因到各应用——
//     这是事件schema 下可用的最准确口径，查询注释与汇报均如实标注；
//   - 同应用内同键多作用域行（不同 host/binding）按 endpoint_key 折叠聚合，
//     属性列取 min() 兜底（endpoint_key 已含 method+path，二者同键恒定）。
//
// 准入类事件判定：final_action='BLOCK' 且 details_json 检测明细或 final_decision.rule_refs
// 含 admission 类 finding（规则 ID admission.unknown_endpoint / admission.unconfirmed_endpoint，
// 或检测器名 api_admission；设计 §4.1）。
package apisecurity

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 命中统计窗口词表（hits_window 查询参数，单位小时）。
const (
	// AdmissionDefaultHitsWindowHours 缺省窗口（7 天）
	AdmissionDefaultHitsWindowHours = 168
	// AdmissionMaxHitsWindowHours 窗口上限（90 天；受 api_runtime_events 实际留存约束，
	// 超出留存的部分自然无数据，不另行标注）
	AdmissionMaxHitsWindowHours = 2160
	// admissionHotLimit 未确认命中榜上限（冻结契约：按 hits 降序，上限 50）
	admissionHotLimit = 50
	// admissionDeniedSampleIPCap 拦截样本 client_ip 单端点展示上限
	admissionDeniedSampleIPCap = 5
)

// admissionEventCond 准入类事件 SQL 判定片段（作用于 api_runtime_events 别名 ev）。
// details_json 可能为 JSON null（旧版网关），jsonb_array_elements 前以 jsonb_typeof 守卫
// （与 GetPostureTrends 敏感命中同一纪律）；final_decision 可空（迁移 000131），
// ->'rule_refs' 对 NULL 列返回 NULL，jsonb_typeof(NULL) 非 'array' 自然短路。
const admissionEventCond = `(
	jsonb_typeof(ev.details_json) = 'array' AND EXISTS (
	    SELECT 1 FROM jsonb_array_elements(ev.details_json) m
	    WHERE (m->>'rule_id') LIKE 'admission.%' OR m->>'detector' = 'api_admission')
	OR
	jsonb_typeof(ev.final_decision->'rule_refs') = 'array' AND EXISTS (
	    SELECT 1 FROM jsonb_array_elements(ev.final_decision->'rule_refs') rr
	    WHERE (rr->>'rule_id') LIKE 'admission.%')
)`

// AdmissionEndpointCounts 应用端点按资产状态计数（五态词表，与冻结契约键名一致）。
type AdmissionEndpointCounts struct {
	Confirmed  int64 `json:"confirmed"`
	Discovered int64 `json:"discovered"`
	Ignored    int64 `json:"ignored"`
	Deprecated int64 `json:"deprecated"`
	Zombie     int64 `json:"zombie"`
}

// AdmissionHotEndpoint 窗口内仍有命中的未确认端点（切 PROTECT 会误伤的对象）。
type AdmissionHotEndpoint struct {
	EndpointKey    string    `json:"endpoint_key"`
	HTTPMethod     string    `json:"http_method"`
	NormalizedPath string    `json:"normalized_path"`
	AssetStatus    string    `json:"asset_status"`
	Hits           int64     `json:"hits"`
	LastSeenAt     time.Time `json:"last_seen_at"`
}

// AdmissionCoverageReport 准入覆盖率报告（GET /api-security/admission/coverage 响应 data）。
type AdmissionCoverageReport struct {
	ApplicationID   uuid.UUID               `json:"application_id"`
	Mode            string                  `json:"mode"` // OFF / OBSERVE / PROTECT（应用当前准入模式）
	HitsWindowHours int                     `json:"hits_window_hours"`
	Endpoints       AdmissionEndpointCounts `json:"endpoints"`
	// ConfirmRate 确认覆盖率 = confirmed / (confirmed+discovered)（设计 §5.2 口径；
	// 分母为 0 时返回 0）
	ConfirmRate    float64                `json:"confirm_rate"`
	UnconfirmedHot []AdmissionHotEndpoint `json:"unconfirmed_hot"`
	// Blocked 窗口内准入拦截次数（OBSERVE 期自然为 0）
	Blocked int64 `json:"blocked"`
}

// AdmissionDeniedItem 准入拦截列表行（按端点聚合）。
type AdmissionDeniedItem struct {
	EndpointKey     string    `json:"endpoint_key"`
	HTTPMethod      string    `json:"http_method"`
	NormalizedPath  string    `json:"normalized_path"`
	AssetStatus     string    `json:"asset_status"`
	DeniedCount     int64     `json:"denied_count"`
	LastDeniedAt    time.Time `json:"last_denied_at"`
	SampleClientIPs []string  `json:"sample_client_ips"` // 窗口内去重样本，上限 admissionDeniedSampleIPCap
	FirstSeenAt     time.Time `json:"first_seen_at"`     // 端点首次发现时间（api_endpoints）
}

// AdmissionRepository 准入防护读接口（*Store 实现；单测注入内存假实现，
// 与 RiskRepository/SetRiskRepository 同一测试纪律）。
type AdmissionRepository interface {
	AdmissionCoverage(ctx context.Context, appID uuid.UUID, hitsWindowHours int) (*AdmissionCoverageReport, error)
	AdmissionDenied(ctx context.Context, appID uuid.UUID, hitsWindowHours, page, pageSize int) ([]AdmissionDeniedItem, int64, error)
}

// SetAdmissionRepository 覆盖准入仓储（测试注入内存实现；生产无需调用）。
func (h *Handler) SetAdmissionRepository(r AdmissionRepository) { h.admission = r }

// ---------- 仓储实现 ----------

// AdmissionCoverage 覆盖率报告：端点状态计数 + 窗口内未确认命中榜 + 窗口内准入拦截数。
// hitsWindowHours 由 HTTP 层校验（1-2160），此处防御性夹取不静默改语义。
func (s *Store) AdmissionCoverage(ctx context.Context, appID uuid.UUID, hitsWindowHours int) (*AdmissionCoverageReport, error) {
	rep := &AdmissionCoverageReport{
		ApplicationID:   appID,
		HitsWindowHours: hitsWindowHours,
		UnconfirmedHot:  []AdmissionHotEndpoint{},
	}
	// 应用存在性与当前准入模式（软删除应用视同不存在）
	if err := s.db.QueryRow(ctx,
		`SELECT api_admission_mode FROM applications WHERE id = $1 AND deleted_at IS NULL`, appID).
		Scan(&rep.Mode); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	// 端点状态计数（全量，不限窗口——覆盖率是存量概念）
	rows, err := s.db.Query(ctx,
		`SELECT asset_status, count(*) FROM api_endpoints WHERE application_id = $1 GROUP BY asset_status`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var n int64
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		switch status {
		case "CONFIRMED":
			rep.Endpoints.Confirmed = n
		case "DISCOVERED":
			rep.Endpoints.Discovered = n
		case "IGNORED":
			rep.Endpoints.Ignored = n
		case "DEPRECATED":
			rep.Endpoints.Deprecated = n
		case "ZOMBIE":
			rep.Endpoints.Zombie = n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if denom := rep.Endpoints.Confirmed + rep.Endpoints.Discovered; denom > 0 {
		rep.ConfirmRate = round4(float64(rep.Endpoints.Confirmed) / float64(denom))
	}

	since := time.Now().UTC().Add(-time.Duration(hitsWindowHours) * time.Hour)
	// 未确认命中榜：窗口内事件按 endpoint_key 聚合后回连本应用未确认端点
	// （先聚合事件再关联，避免同键多作用域行造成计数膨胀；按 hits 降序、键升序兜底，上限 50）。
	rows2, err := s.db.Query(ctx, `
SELECT g.endpoint_key, e.http_method, e.normalized_path, e.asset_status, g.hits, g.last_seen
FROM (
    SELECT endpoint_key, count(*) AS hits, max(occurred_at) AS last_seen
    FROM api_runtime_events
    WHERE occurred_at >= $2 AND endpoint_key <> ''
    GROUP BY endpoint_key
) g
JOIN (
    SELECT endpoint_key, min(http_method) AS http_method, min(normalized_path) AS normalized_path,
           min(asset_status) AS asset_status
    FROM api_endpoints
    WHERE application_id = $1 AND asset_status <> 'CONFIRMED'
    GROUP BY endpoint_key
) e ON e.endpoint_key = g.endpoint_key
ORDER BY g.hits DESC, g.endpoint_key
LIMIT `+strconv.Itoa(admissionHotLimit), appID, since)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var it AdmissionHotEndpoint
		if err := rows2.Scan(&it.EndpointKey, &it.HTTPMethod, &it.NormalizedPath, &it.AssetStatus,
			&it.Hits, &it.LastSeenAt); err != nil {
			return nil, err
		}
		rep.UnconfirmedHot = append(rep.UnconfirmedHot, it)
	}
	if err := rows2.Err(); err != nil {
		return nil, err
	}

	// 窗口内准入拦截次数（final_action=BLOCK 且含 admission 类 finding；
	// 事件→应用归因经 endpoint_key 关联本应用端点行，口径见文件头注释）
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM api_runtime_events ev
WHERE ev.occurred_at >= $2 AND ev.final_action = 'BLOCK'
  AND `+admissionEventCond+`
  AND EXISTS (SELECT 1 FROM api_endpoints e WHERE e.application_id = $1 AND e.endpoint_key = ev.endpoint_key)`,
		appID, since).Scan(&rep.Blocked); err != nil {
		return nil, err
	}
	return rep, nil
}

// AdmissionDenied 准入拦截列表：窗口内准入拦截事件按端点聚合（denied_count 降序、
// 键升序兜底，分页）。样本 IP 为窗口内去重 client_ip（空串/NULL 剔除，顺序不保证——
// 仅作样本展示，审计溯源走运行时事件明细）。
func (s *Store) AdmissionDenied(ctx context.Context, appID uuid.UUID, hitsWindowHours, page, pageSize int) ([]AdmissionDeniedItem, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	since := time.Now().UTC().Add(-time.Duration(hitsWindowHours) * time.Hour)
	// count(*) OVER () 在 LIMIT/OFFSET 前求值，单查询同时取页与总数（0 行时总数为 0）。
	rows, err := s.db.Query(ctx, `
WITH denied AS (
    SELECT ev.endpoint_key,
           count(*) AS denied_count,
           max(ev.occurred_at) AS last_denied_at,
           array_remove((array_agg(DISTINCT NULLIF(ev.client_ip, '')))[1:20], NULL) AS sample_ips
    FROM api_runtime_events ev
    WHERE ev.occurred_at >= $2 AND ev.final_action = 'BLOCK'
      AND `+admissionEventCond+`
    GROUP BY ev.endpoint_key
),
app_eps AS (
    SELECT endpoint_key, min(http_method) AS http_method, min(normalized_path) AS normalized_path,
           min(asset_status) AS asset_status, min(first_seen_at) AS first_seen_at
    FROM api_endpoints
    WHERE application_id = $1
    GROUP BY endpoint_key
)
SELECT d.endpoint_key, a.http_method, a.normalized_path, a.asset_status, a.first_seen_at,
       d.denied_count, d.last_denied_at, d.sample_ips,
       count(*) OVER () AS total
FROM denied d
JOIN app_eps a ON a.endpoint_key = d.endpoint_key
ORDER BY d.denied_count DESC, d.endpoint_key
LIMIT $3 OFFSET $4`, appID, since, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []AdmissionDeniedItem{}
	var total int64
	for rows.Next() {
		var it AdmissionDeniedItem
		if err := rows.Scan(&it.EndpointKey, &it.HTTPMethod, &it.NormalizedPath, &it.AssetStatus,
			&it.FirstSeenAt, &it.DeniedCount, &it.LastDeniedAt, &it.SampleClientIPs, &total); err != nil {
			return nil, 0, err
		}
		if len(it.SampleClientIPs) > admissionDeniedSampleIPCap {
			it.SampleClientIPs = it.SampleClientIPs[:admissionDeniedSampleIPCap]
		}
		if it.SampleClientIPs == nil {
			it.SampleClientIPs = []string{}
		}
		out = append(out, it)
	}
	return out, total, rows.Err()
}

// ---------- HTTP 处理 ----------

// parseAdmissionAppID 解析并校验 application_id 查询参数（必填 UUID；非法写 400 并返回 ok=false）。
func parseAdmissionAppID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("application_id"))
	id, err := uuid.Parse(raw)
	if raw == "" || err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效或缺失的 application_id（需 UUID）")
		return uuid.Nil, false
	}
	return id, true
}

// parseAdmissionWindow 解析 hits_window 查询参数：正整数小时，范围 1-2160，缺省 168；
// 非数字/越界一律 400（冻结契约），不静默回落。
func parseAdmissionWindow(w http.ResponseWriter, r *http.Request) (int, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("hits_window"))
	if raw == "" {
		return AdmissionDefaultHitsWindowHours, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > AdmissionMaxHitsWindowHours {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"无效的 hits_window 取值（1-2160 的整数小时，缺省 168）")
		return 0, false
	}
	return n, true
}

// AdmissionCoverage GET /api/v1/api-security/admission/coverage
// 覆盖率与影响面报告（切 PROTECT 前评估；权限 api_asset.read）。
func (h *Handler) AdmissionCoverage(w http.ResponseWriter, r *http.Request) {
	appID, ok := parseAdmissionAppID(w, r)
	if !ok {
		return
	}
	window, ok := parseAdmissionWindow(w, r)
	if !ok {
		return
	}
	rep, err := h.admission.AdmissionCoverage(r.Context(), appID, window)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, rep)
}

// AdmissionDenied GET /api/v1/api-security/admission/denied
// 准入拦截列表（PROTECT 期被 403 的端点聚合；权限 api_asset.read）。
func (h *Handler) AdmissionDenied(w http.ResponseWriter, r *http.Request) {
	appID, ok := parseAdmissionAppID(w, r)
	if !ok {
		return
	}
	window, ok := parseAdmissionWindow(w, r)
	if !ok {
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryPageSize(r, 20)
	items, total, err := h.admission.AdmissionDenied(r.Context(), appID, window, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, items, total, page, pageSize)
}
