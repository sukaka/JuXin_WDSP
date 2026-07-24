// noise_handler.go AI 自动降噪接口：簇列表/详情/统计、手动扫描、扫描历史、
// 降噪设置与簇状态流转（suppress/resolve 只改簇状态，不触碰事件处置/封禁/例外）。
// 全部端点走 authChain + RequirePermission；写操作落 ai_audit_records。
package aihandlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aiaudit"
	"github.com/jiuzhang-waf/server/internal/ainoise"
	"github.com/jiuzhang-waf/server/internal/aitools"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// NoiseClusterList 降噪簇分页查询（source/status/verdict/时间窗筛选）。
func (d *Deps) NoiseClusterList(w http.ResponseWriter, r *http.Request) {
	if d.Noise == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "AI 降噪模块未装配")
		return
	}
	q := r.URL.Query()
	f := ainoise.ListFilter{Page: queryInt(r, "page", 1), PageSize: queryInt(r, "page_size", 20)}
	if v := q.Get("source"); v != "" {
		if v != "WAF" && v != "API" {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 source（WAF/API）")
			return
		}
		f.Source = v
	}
	if v := q.Get("status"); v != "" {
		if v != "ACTIVE" && v != "SUPPRESSED" && v != "RESOLVED" {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 status")
			return
		}
		f.Status = v
	}
	if v := q.Get("verdict"); v != "" {
		if v != "TRUE_POSITIVE" && v != "LIKELY_FALSE_POSITIVE" && v != "UNKNOWN" {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 verdict")
			return
		}
		f.Verdict = v
	}
	if v := q.Get("start_time"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 start_time（RFC3339）")
			return
		}
		t = t.UTC()
		f.Since = &t
	}
	if v := q.Get("end_time"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 end_time（RFC3339）")
			return
		}
		t = t.UTC()
		f.Until = &t
	}
	items, total, err := d.Noise.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, response.PageData{Items: items, Page: f.Page, PageSize: f.PageSize, Total: total})
}

// loadNoiseCluster 解析路径 ID 并加载簇（非法 400 / 不存在 404）。
func (d *Deps) loadNoiseCluster(w http.ResponseWriter, r *http.Request) (*ainoise.Cluster, bool) {
	if d.Noise == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "AI 降噪模块未装配")
		return nil, false
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的簇ID")
		return nil, false
	}
	c, err := d.Noise.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, ainoise.ErrClusterNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "降噪簇不存在")
		} else {
			response.InternalError(w, r, err)
		}
		return nil, false
	}
	return c, true
}

// NoiseClusterGet 簇详情（含代表事件与计数）。
func (d *Deps) NoiseClusterGet(w http.ResponseWriter, r *http.Request) {
	c, ok := d.loadNoiseCluster(w, r)
	if !ok {
		return
	}
	events, err := d.Noise.ListEvents(r.Context(), c.ID, 20)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"cluster": c, "events": events,
	})
}

// NoiseStats 面板统计（活跃簇数/折叠事件总数/疑似误报簇数/已抑制簇数）。
func (d *Deps) NoiseStats(w http.ResponseWriter, r *http.Request) {
	if d.Noise == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "AI 降噪模块未装配")
		return
	}
	stats, err := d.Noise.Stats(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, stats)
}

// noiseTransition suppress/resolve 共用流转（只改簇状态，审计）。
func (d *Deps) noiseTransition(w http.ResponseWriter, r *http.Request, action string) {
	c, ok := d.loadNoiseCluster(w, r)
	if !ok {
		return
	}
	updated, err := d.Noise.Transition(r.Context(), c.ID, action)
	if err != nil {
		if errors.Is(err, ainoise.ErrClusterState) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "当前簇状态不允许该操作")
		} else {
			response.InternalError(w, r, err)
		}
		return
	}
	p := authz.PrincipalFrom(r.Context())
	d.recordAIAudit(p, aiaudit.Record{
		Action:         "noise_" + action,
		RequestSummary: "cluster_id=" + c.ID.String(),
		ResultSummary:  fmt.Sprintf("status %s -> %s", c.Status, updated.Status),
	})
	response.JSON(w, r, http.StatusOK, updated)
}

// NoiseClusterSuppress 抑制簇（ACTIVE → SUPPRESSED）。
func (d *Deps) NoiseClusterSuppress(w http.ResponseWriter, r *http.Request) {
	d.noiseTransition(w, r, "suppress")
}

// NoiseClusterResolve 解决簇（ACTIVE/SUPPRESSED → RESOLVED）。
func (d *Deps) NoiseClusterResolve(w http.ResponseWriter, r *http.Request) {
	d.noiseTransition(w, r, "resolve")
}

// NoiseSweepTrigger 手动触发一次降噪扫描（同步执行并返回统计；manage 权限）。
func (d *Deps) NoiseSweepTrigger(w http.ResponseWriter, r *http.Request) {
	if d.NoiseWorker == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "AI 降噪扫描器未装配")
		return
	}
	stats := d.NoiseWorker.SweepOnce(r.Context())
	p := authz.PrincipalFrom(r.Context())
	d.recordAIAudit(p, aiaudit.Record{
		Action:         "noise_sweep",
		RequestSummary: "manual trigger",
		ResultSummary: fmt.Sprintf("status=%s scanned=%d new=%d updated=%d llm=%d",
			stats.Status, stats.ScannedEvents, stats.NewClusters, stats.UpdatedClusters, stats.LLMCalls),
	})
	response.JSON(w, r, http.StatusOK, stats)
}

// NoiseSweepList 扫描历史。
func (d *Deps) NoiseSweepList(w http.ResponseWriter, r *http.Request) {
	if d.Noise == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "AI 降噪模块未装配")
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	items, total, err := d.Noise.ListSweepRuns(r.Context(), page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, response.PageData{Items: items, Page: page, PageSize: pageSize, Total: total})
}

// noiseSettingsPayload 降噪设置响应（生效值，含默认回退）。
func noiseSettingsPayload(cfg ainoise.Config) map[string]interface{} {
	return map[string]interface{}{
		"enabled":              cfg.Enabled,
		"interval_seconds":     int(cfg.Interval / time.Second),
		"sweep_window_minutes": int(cfg.Window / time.Minute),
		"min_events_threshold": cfg.MinEventsThreshold,
		"llm_verdict_enabled":  cfg.LLMVerdictEnabled,
	}
}

// NoiseSettingsGet 读取降噪设置（manage 权限；返回含默认值回退的生效配置）。
func (d *Deps) NoiseSettingsGet(w http.ResponseWriter, r *http.Request) {
	if d.Settings == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "系统设置服务未装配")
		return
	}
	cfg := ainoise.LoadConfig(r.Context(), d.Settings)
	response.JSON(w, r, http.StatusOK, noiseSettingsPayload(cfg))
}

// noiseSettingsRequest 降噪设置更新请求（指针字段区分未提供/零值）。
type noiseSettingsRequest struct {
	Enabled            *bool `json:"enabled"`
	IntervalSeconds    *int  `json:"interval_seconds"`
	SweepWindowMinutes *int  `json:"sweep_window_minutes"`
	MinEventsThreshold *int  `json:"min_events_threshold"`
	LLMVerdictEnabled  *bool `json:"llm_verdict_enabled"`
}

// NoiseSettingsPut 更新降噪设置（manage 权限；取值范围校验，非法 400）。
func (d *Deps) NoiseSettingsPut(w http.ResponseWriter, r *http.Request) {
	if d.Settings == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "系统设置服务未装配")
		return
	}
	var req noiseSettingsRequest
	if err := decodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	// 先校验全部取值，再落库（避免部分写入）
	if req.IntervalSeconds != nil &&
		(*req.IntervalSeconds < ainoise.MinIntervalSeconds || *req.IntervalSeconds > ainoise.MaxIntervalSeconds) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("interval_seconds 取值范围 %d-%d", ainoise.MinIntervalSeconds, ainoise.MaxIntervalSeconds))
		return
	}
	if req.SweepWindowMinutes != nil &&
		(*req.SweepWindowMinutes < ainoise.MinSweepWindowMinutes || *req.SweepWindowMinutes > ainoise.MaxSweepWindowMinutes) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("sweep_window_minutes 取值范围 %d-%d", ainoise.MinSweepWindowMinutes, ainoise.MaxSweepWindowMinutes))
		return
	}
	if req.MinEventsThreshold != nil &&
		(*req.MinEventsThreshold < ainoise.MinEventsThresholdFloor || *req.MinEventsThreshold > ainoise.MinEventsThresholdCeil) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("min_events_threshold 取值范围 %d-%d", ainoise.MinEventsThresholdFloor, ainoise.MinEventsThresholdCeil))
		return
	}
	p := authz.PrincipalFrom(r.Context())
	var operatorID uuid.UUID
	if p != nil {
		operatorID = p.UserID
	}
	upsert := func(key, value, desc string) bool {
		if err := d.Settings.UpsertString(r.Context(), ainoise.SettingsGroup, key, value, desc, operatorID); err != nil {
			response.InternalError(w, r, err)
			return false
		}
		return true
	}
	changed := []string{}
	if req.Enabled != nil {
		if !upsert("enabled", strconv.FormatBool(*req.Enabled), "AI自动降噪总开关") {
			return
		}
		changed = append(changed, "enabled="+strconv.FormatBool(*req.Enabled))
	}
	if req.IntervalSeconds != nil {
		if !upsert("interval_seconds", strconv.Itoa(*req.IntervalSeconds), "降噪扫描间隔（秒）") {
			return
		}
		changed = append(changed, "interval_seconds="+strconv.Itoa(*req.IntervalSeconds))
	}
	if req.SweepWindowMinutes != nil {
		if !upsert("sweep_window_minutes", strconv.Itoa(*req.SweepWindowMinutes), "降噪扫描窗口（分钟）") {
			return
		}
		changed = append(changed, "sweep_window_minutes="+strconv.Itoa(*req.SweepWindowMinutes))
	}
	if req.MinEventsThreshold != nil {
		if !upsert("min_events_threshold", strconv.Itoa(*req.MinEventsThreshold), "降噪簇最小事件数阈值") {
			return
		}
		changed = append(changed, "min_events_threshold="+strconv.Itoa(*req.MinEventsThreshold))
	}
	if req.LLMVerdictEnabled != nil {
		if !upsert("llm_verdict_enabled", strconv.FormatBool(*req.LLMVerdictEnabled), "降噪簇LLM误报评分开关") {
			return
		}
		changed = append(changed, "llm_verdict_enabled="+strconv.FormatBool(*req.LLMVerdictEnabled))
	}
	if len(changed) > 0 {
		d.recordAIAudit(p, aiaudit.Record{
			Action:         "noise_settings_update",
			RequestSummary: trunc(fmt.Sprintf("%v", changed), 400),
			ResultSummary:  "设置已更新",
		})
	}
	cfg := ainoise.LoadConfig(r.Context(), d.Settings)
	response.JSON(w, r, http.StatusOK, noiseSettingsPayload(cfg))
}

// NoiseClusterDraftRule 从降噪簇生成自定义规则草稿（闭环：事件→聚类→草稿→人工审核）。
// 产出为 DISABLED 自定义规则 + ai_recommendations 记录；AI 不自动启用/发布（draft.custom_rule.create 工具）。
func (d *Deps) NoiseClusterDraftRule(w http.ResponseWriter, r *http.Request) {
	c, ok := d.loadNoiseCluster(w, r)
	if !ok {
		return
	}
	if d.Tools == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "AI 工具注册表未装配")
		return
	}
	if c.NormalizedURI == "" || c.NormalizedURI == "/" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "该簇缺少可用 URI 模式，无法生成规则草稿")
		return
	}
	// 分配自定义规则 ID（7100000-7199999）
	var rid int
	if err := d.DB.QueryRow(r.Context(), `SELECT COALESCE(MAX(rule_id),7100000) FROM custom_rules`).Scan(&rid); err != nil {
		response.InternalError(w, r, err)
		return
	}
	rid++
	if rid > 7199999 {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "自定义规则 ID 段已满")
		return
	}
	severity := "WARNING"
	if c.AIVerdict == "TRUE_POSITIVE" {
		severity = "ERROR"
	}
	reason := fmt.Sprintf("由降噪簇生成（源 %s，命中 %d 次，客户端 %s，规则/检测器 %s）",
		c.Source, c.EventCount, c.ClientIP, detectorOrRule(c))
	input := map[string]interface{}{
		"name":             "降噪簇 " + c.NormalizedURI,
		"rule_id":          rid,
		"attack_type":      "OTHER",
		"severity":         severity,
		"phase":            2,
		"operator":         "beginsWith",
		"operator_value":   c.NormalizedURI,
		"target_variables": []string{"REQUEST_URI"},
		"action":           "OBSERVE",
		"reason":           reason,
		"evidence":         []string{"noise_cluster:" + c.ID.String()},
	}
	raw, _ := json.Marshal(input)
	p := authz.PrincipalFrom(r.Context())
	prin := &aitools.Principal{UserID: p.UserID, Username: p.Username, Permissions: p.PermsSet}
	out, _, err := d.Tools.Execute(r.Context(), prin, uuid.New(), nil, "draft.custom_rule.create", raw, nil)
	if err != nil {
		if errors.Is(err, aitools.ErrPermission) {
			response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "缺少 ai.draft.custom_rule 权限")
			return
		}
		if errors.Is(err, aitools.ErrInvalidInput) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
		response.InternalError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action:         "noise_draft_rule",
		RequestSummary: "cluster_id=" + c.ID.String(),
		ResultSummary:  fmt.Sprintf("draft custom rule %d (DISABLED)", rid),
	})
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"message": "规则草稿已生成（默认停用，请在「自定义规则」审核启用）",
		"rule_id": rid, "draft": out,
	})
}

// detectorOrRule 簇关联的规则/检测器标识（展示用）。
func detectorOrRule(c *ainoise.Cluster) string {
	if c.DetectorCode != "" {
		return c.DetectorCode
	}
	if c.RuleID != nil {
		return fmt.Sprint(*c.RuleID)
	}
	return "-"
}
