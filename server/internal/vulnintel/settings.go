package vulnintel

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// 订阅设置（system_settings 组 vuln_intel；界面热生效）。
const (
	SettingsGroup       = "vuln_intel"
	KeyWatchTechs       = "watch_techs"  // 逗号分隔技术名列表（字符串值）
	KeyMinSeverity      = "min_severity" // 最低提醒级别（字符串值）
	KeySyncEnabled      = "sync_enabled" // 在线每日同步开关（布尔值）
	DefaultWatchTechs   = "php"
	DefaultMinSeverity  = SeverityHigh
	maxWatchTechs       = 10
	minSeverityVocabTip = "LOW/MEDIUM/HIGH/CRITICAL"
)

// SettingsReader 是设置读取接口（*settings.Service 实现；单测用 fake）。
type SettingsReader interface {
	GetString(ctx context.Context, group, key, def string) string
	GetBool(ctx context.Context, group, key string, def bool) bool
}

// SettingsWriter 是设置写入接口（*settings.Service 实现）。
type SettingsWriter interface {
	UpsertString(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) error
	UpsertBool(ctx context.Context, group, key string, value bool, description string, operatorID uuid.UUID) error
}

// Subscription 是当前订阅配置。
type Subscription struct {
	WatchTechs  []string `json:"watch_techs"`
	MinSeverity string   `json:"min_severity"`
	SyncEnabled bool     `json:"sync_enabled"`
}

// LoadSubscription 读取订阅配置（DB 无行时回落默认值）。
func LoadSubscription(ctx context.Context, r SettingsReader) Subscription {
	watchTechs := ParseWatchTechs(r.GetString(ctx, SettingsGroup, KeyWatchTechs, DefaultWatchTechs))
	minSev := strings.ToUpper(strings.TrimSpace(r.GetString(ctx, SettingsGroup, KeyMinSeverity, DefaultMinSeverity)))
	if !IsValidSeverity(minSev) || minSev == SeverityNone {
		minSev = DefaultMinSeverity
	}
	return Subscription{
		WatchTechs:  watchTechs,
		MinSeverity: minSev,
		SyncEnabled: r.GetBool(ctx, SettingsGroup, KeySyncEnabled, false),
	}
}

// ParseWatchTechs 解析逗号分隔技术名列表（去空白、去重、保序）。
func ParseWatchTechs(s string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		tech := strings.ToLower(strings.TrimSpace(part))
		if tech == "" || seen[tech] {
			continue
		}
		seen[tech] = true
		out = append(out, tech)
	}
	return out
}

// JoinWatchTechs 序列化技术名列表（落库字符串形态）。
func JoinWatchTechs(techs []string) string {
	return strings.Join(techs, ",")
}

// ValidateSubscription 校验订阅配置（PUT settings 入口）。
func ValidateSubscription(sub *Subscription) error {
	if len(sub.WatchTechs) == 0 {
		return fmt.Errorf("%w: watch_techs 不能为空", ErrInvalidInput)
	}
	if len(sub.WatchTechs) > maxWatchTechs {
		return fmt.Errorf("%w: watch_techs 超过 %d 项上限", ErrInvalidInput, maxWatchTechs)
	}
	seen := map[string]bool{}
	techs := make([]string, 0, len(sub.WatchTechs))
	for _, tech := range sub.WatchTechs {
		tech = strings.ToLower(strings.TrimSpace(tech))
		if err := ValidateTechName(tech); err != nil {
			return err
		}
		if seen[tech] {
			continue
		}
		seen[tech] = true
		techs = append(techs, tech)
	}
	sub.WatchTechs = techs
	sub.MinSeverity = strings.ToUpper(strings.TrimSpace(sub.MinSeverity))
	if !IsValidSeverity(sub.MinSeverity) || sub.MinSeverity == SeverityNone {
		return fmt.Errorf("%w: min_severity 词表非法（%s）: %q", ErrInvalidInput, minSeverityVocabTip, sub.MinSeverity)
	}
	return nil
}

// SaveSubscription 覆盖写入订阅配置（三键各自 upsert，版本自增）。
func SaveSubscription(ctx context.Context, w SettingsWriter, sub Subscription, operator uuid.UUID) error {
	if err := w.UpsertString(ctx, SettingsGroup, KeyWatchTechs,
		JoinWatchTechs(sub.WatchTechs), "漏洞情报订阅技术栈（逗号分隔）", operator); err != nil {
		return err
	}
	if err := w.UpsertString(ctx, SettingsGroup, KeyMinSeverity,
		sub.MinSeverity, "漏洞情报最低提醒级别", operator); err != nil {
		return err
	}
	return w.UpsertBool(ctx, SettingsGroup, KeySyncEnabled,
		sub.SyncEnabled, "漏洞情报 NVD 每日在线同步开关", operator)
}
