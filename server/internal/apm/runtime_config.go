// runtime_config.go APM 总开关与 ClickHouse DSN 的运行期配置解析（系统设置界面可配、
// 修改立即生效、无需重启）。
//
// 优先级：界面设置（system_settings 表 apm 组 DB 行）优先，环境变量（APM_ENABLED /
// APM_CLICKHOUSE_DSN）兜底——与 guardProvider.SetAPIModeOverride 的"DB 覆盖优先于
// 构造配置"先例一致。管理员从未在界面配置过时 DB 无行，行为与纯 env 部署完全一致
// （不做迁移种子，避免种子值覆盖存量 env 部署）。
//
// DB 读取错误：Warn 日志 + 回退 env（与 settings.GetBool 的容错口径一致，不 500）。
// 两键由专用接口 GET/PUT /api/v1/apm/settings 管理（settings_handler.go），不进
// settings.AllowedSettingKeys 通用白名单——DSN 含口令，通用 Update 无掩码语义。
package apm

import (
	"context"
	"log/slog"
)

const (
	// settingsGroupAPM APM 界面设置分组（行由专用接口 Upsert 按需创建，无迁移种子）。
	settingsGroupAPM = "apm"
	// settingsKeyEnabled 总开关键（boolean jsonb）。
	settingsKeyEnabled = "enabled"
	// settingsKeyClickHouseDSN 数据面连接串键（string jsonb，is_sensitive=true，
	// 任何接口不回显原文）。
	settingsKeyClickHouseDSN = "clickhouse_dsn"
)

// 覆盖来源标识（GET /api/v1/apm/settings 响应字段值）。
const (
	sourceUI  = "ui"  // 界面设置（DB 行）
	sourceEnv = "env" // 环境变量兜底
)

// runtimeSettingsReader 运行期配置所需的设置读取面（*settings.Service 实现；
// 单测注入内存 fake）。
type runtimeSettingsReader interface {
	GetBoolWithSource(ctx context.Context, group, key string) (value bool, found bool, err error)
	GetStringWithSource(ctx context.Context, group, key string) (value string, found bool, err error)
}

// RuntimeConfig APM 运行期配置：每次调用实时读 DB（设置表为低开销点查，
// 与登录限速等"动态读取系统设置"先例同口径），修改即时生效。
type RuntimeConfig struct {
	settings   runtimeSettingsReader
	envEnabled bool
	envDSN     string
}

// NewRuntimeConfig 创建运行期配置解析器（envEnabled/envDSN 为启动期 env 兜底值）。
func NewRuntimeConfig(s runtimeSettingsReader, envEnabled bool, envDSN string) *RuntimeConfig {
	return &RuntimeConfig{settings: s, envEnabled: envEnabled, envDSN: envDSN}
}

// EnabledWithSource 返回总开关生效值与来源（DB 行优先；DB 错误 Warn 回退 env）。
func (r *RuntimeConfig) EnabledWithSource(ctx context.Context) (enabled bool, source string) {
	v, found, err := r.settings.GetBoolWithSource(ctx, settingsGroupAPM, settingsKeyEnabled)
	if err != nil {
		slog.Warn("APM 总开关设置读取失败，回退环境变量兜底值", "error", err)
		return r.envEnabled, sourceEnv
	}
	if found {
		return v, sourceUI
	}
	return r.envEnabled, sourceEnv
}

// Enabled 总开关生效值（gate 门控 / capabilities / 后台评估空转判定共用）。
func (r *RuntimeConfig) Enabled(ctx context.Context) bool {
	enabled, _ := r.EnabledWithSource(ctx)
	return enabled
}

// ClickHouseDSNWithSource 返回数据面 DSN 生效值、是否命中 DB 行与来源。
// DB 行存在且值为空串 = 显式清空（不回退 env——管理员明确要求不接数据面）。
func (r *RuntimeConfig) ClickHouseDSNWithSource(ctx context.Context) (dsn string, found bool, source string) {
	v, foundRow, err := r.settings.GetStringWithSource(ctx, settingsGroupAPM, settingsKeyClickHouseDSN)
	if err != nil {
		slog.Warn("APM ClickHouse DSN 设置读取失败，回退环境变量兜底值", "error", err)
		return r.envDSN, false, sourceEnv
	}
	if foundRow {
		return v, true, sourceUI
	}
	if r.envDSN != "" {
		return r.envDSN, false, sourceEnv
	}
	return "", false, ""
}

// ClickHouseDSN 数据面 DSN 生效值（空串 = 未接入，纯无 Agent 模式）。
func (r *RuntimeConfig) ClickHouseDSN(ctx context.Context) string {
	dsn, _, _ := r.ClickHouseDSNWithSource(ctx)
	return dsn
}
