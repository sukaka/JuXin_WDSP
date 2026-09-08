// settings_handler.go APM 总开关与 ClickHouse DSN 专用设置接口
// （GET/PUT /api/v1/apm/settings，权限 system_settings.read/update，与系统设置一致）。
//
// 设计要点：
//   - 两键（apm:enabled / apm:clickhouse_dsn）不进 settings.AllowedSettingKeys
//     通用白名单——DSN 含口令，通用 Update 无掩码语义；任何接口不回显 DSN 原文
//     （GET 只回 clickhouse_dsn_set/source，写审计摘要只记 set/cleared）；
//   - 本接口不受 APM 关闭 503 门控影响（装配层直接注册在主 mux），否则关闭后
//     无法经界面重新开启；
//   - PUT 字段缺省 = 不变；clickhouse_dsn="" = 清除界面覆盖（删除 DB 行，
//     回退环境变量兜底）；非空先经 clickhouse.ParseDSN 校验，非法 400；
//   - 写操作高风险审计（module=apm）；写后立即触发 CHManager.Resolve 重建连接。
package apm

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// apmSettingsWriter 设置写入面（*settings.Service 实现；单测注入内存 fake）。
type apmSettingsWriter interface {
	UpsertBool(ctx context.Context, group, key string, value bool, description string, operatorID uuid.UUID) error
	UpsertSensitiveString(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) error
	Delete(ctx context.Context, group, key string) error
}

// SettingsHandler APM 开关/数据面设置处理器。
type SettingsHandler struct {
	cfg      *RuntimeConfig
	settings apmSettingsWriter
	ch       *CHManager
	audits   auditRecorder // nil 时写操作不记审计（仅测试便利；生产装配必须注入）
}

// NewSettingsHandler 创建 APM 设置处理器。
func NewSettingsHandler(cfg *RuntimeConfig, settings apmSettingsWriter, ch *CHManager) *SettingsHandler {
	return &SettingsHandler{cfg: cfg, settings: settings, ch: ch}
}

// SetAudits 注入操作审计记录器（生产由 app 装配 *audits.Service）。
func (h *SettingsHandler) SetAudits(a auditRecorder) *SettingsHandler { h.audits = a; return h }

// RegisterSettingsRoutes 注册 /api/v1/apm/settings 路由（不受 APM 503 门控，
// 由装配层直接注册在主 mux）。
func RegisterSettingsRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *SettingsHandler) {
	mux.Handle("GET /api/v1/apm/settings",
		authz(middleware.RequirePermission("system_settings.read")(http.HandlerFunc(h.Get))))
	mux.Handle("PUT /api/v1/apm/settings",
		authz(middleware.RequirePermission("system_settings.update")(http.HandlerFunc(h.Update))))
}

// state 当前生效状态（GET 响应与 PUT 成功后的回执共用；DSN 原文不回显）。
func (h *SettingsHandler) state(ctx context.Context) map[string]interface{} {
	enabled, enabledSource := h.cfg.EnabledWithSource(ctx)
	dsn, _, dsnSource := h.cfg.ClickHouseDSNWithSource(ctx)
	return map[string]interface{}{
		"enabled":               enabled,
		"enabled_source":        enabledSource,
		"clickhouse_dsn_set":    dsn != "",
		"clickhouse_dsn_source": dsnSource,
		"ch_connected":          h.ch.Connected(ctx),
	}
}

// Get 读取 APM 设置生效状态（权限 system_settings.read）。
func (h *SettingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	response.JSON(w, r, http.StatusOK, h.state(r.Context()))
}

// updateAPMSettingsRequest PUT 入参（指针字段区分"缺省=不变"与零值）。
type updateAPMSettingsRequest struct {
	Enabled       *bool   `json:"enabled"`
	ClickHouseDSN *string `json:"clickhouse_dsn"`
}

// Update 更新 APM 设置（权限 system_settings.update；高风险审计）。
func (h *SettingsHandler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req updateAPMSettingsRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.Enabled == nil && req.ClickHouseDSN == nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"请求缺少可更新字段（enabled / clickhouse_dsn）")
		return
	}
	// DSN 非空时先校验格式（clickhouse-go ParseDSN；非法 400，不落库不重建）
	if req.ClickHouseDSN != nil && *req.ClickHouseDSN != "" {
		if _, err := clickhouse.ParseDSN(*req.ClickHouseDSN); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				"ClickHouse 连接串格式错误")
			return
		}
	}

	// after 摘要：DSN 只记 set/cleared，不记值（含口令，审计不留明文）
	after := map[string]interface{}{}
	changedKeys := []string{}
	if req.Enabled != nil {
		if err := h.settings.UpsertBool(r.Context(), settingsGroupAPM, settingsKeyEnabled, *req.Enabled,
			"APM 业务性能监控总开关（界面设置优先于 APM_ENABLED 环境变量）", p.UserID); err != nil {
			response.InternalError(w, r, err)
			return
		}
		after["enabled"] = *req.Enabled
		changedKeys = append(changedKeys, settingsKeyEnabled)
	}
	if req.ClickHouseDSN != nil {
		if *req.ClickHouseDSN == "" {
			// 空串 = 清除界面覆盖（删除 DB 行，回退环境变量兜底）
			if err := h.settings.Delete(r.Context(), settingsGroupAPM, settingsKeyClickHouseDSN); err != nil {
				response.InternalError(w, r, err)
				return
			}
			after["clickhouse_dsn"] = "cleared"
		} else {
			if err := h.settings.UpsertSensitiveString(r.Context(), settingsGroupAPM, settingsKeyClickHouseDSN,
				*req.ClickHouseDSN,
				"APM 数据面 ClickHouse 连接串（界面设置优先于 APM_CLICKHOUSE_DSN 环境变量）", p.UserID); err != nil {
				response.InternalError(w, r, err)
				return
			}
			after["clickhouse_dsn"] = "set"
		}
		changedKeys = append(changedKeys, settingsKeyClickHouseDSN)
	}

	// 写后立即按新生效 DSN 重建连接（热生效，无需重启）
	h.ch.Resolve(r.Context())

	if h.audits != nil {
		afterJSON, _ := json.Marshal(after)
		audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
			UserID:       &p.UserID,
			Username:     p.Username,
			SourceIP:     middleware.RemoteIP(r),
			ConnectionIP: middleware.ConnectionIP(r),
			UserAgent:    r.UserAgent(),
			Module:       "apm",
			Action:       "update",
			ObjectType:   "setting",
			ObjectID:     settingsGroupAPM + ":" + strings.Join(changedKeys, ","),
			ObjectName:   "APM 总开关与数据面连接",
			AfterSummary: string(afterJSON),
			Result:       audits.ResultSuccess,
			RiskLevel:    audits.RiskHigh,
			RequestID:    response.RequestIDFrom(r),
		})
	}

	response.JSON(w, r, http.StatusOK, h.state(r.Context()))
}
