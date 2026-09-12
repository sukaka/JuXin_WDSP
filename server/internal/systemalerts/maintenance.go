package systemalerts

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 维护窗口作用范围与周期（阶段6 §11.5，迁移 000142）
const (
	MaintScopeAll    = "ALL"    // 抑制全部告警
	MaintScopeCustom = "CUSTOM" // 按告警类型/组件过滤

	MaintRecurrenceOnce  = "ONCE"  // 一次性窗口 [starts_at, ends_at]
	MaintRecurrenceDaily = "DAILY" // 日期跨度内每日 UTC 时段
)

// 维护窗口输入上限
const (
	maintNameMaxLen   = 100
	maintDescMaxLen   = 500
	maintScopeMaxItem = 50
)

// MaintenanceWindow 是一条告警维护窗口。
type MaintenanceWindow struct {
	ID               uuid.UUID  `json:"id"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	Scope            string     `json:"scope"`
	AlertTypes       []string   `json:"alert_types"`
	Components       []string   `json:"components"`
	Recurrence       string     `json:"recurrence"`
	StartsAt         time.Time  `json:"starts_at"`
	EndsAt           time.Time  `json:"ends_at"`
	DailyStartMinute *int       `json:"daily_start_minute"`
	DailyEndMinute   *int       `json:"daily_end_minute"`
	Enabled          bool       `json:"enabled"`
	SuppressedCount  int64      `json:"suppressed_count"`
	LastSuppressedAt *time.Time `json:"last_suppressed_at"`
	CreatedBy        *uuid.UUID `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
}

// ActiveAt 判断窗口在给定时刻是否生效（含启停标志与周期时段）。
func (w MaintenanceWindow) ActiveAt(now time.Time) bool {
	if !w.Enabled {
		return false
	}
	if now.Before(w.StartsAt) || now.After(w.EndsAt) {
		return false
	}
	if w.Recurrence != MaintRecurrenceDaily {
		return true
	}
	// DAILY：比较 UTC 日内分钟；daily_end <= daily_start 表示跨零点时段
	if w.DailyStartMinute == nil || w.DailyEndMinute == nil {
		return false
	}
	utc := now.UTC()
	m := utc.Hour()*60 + utc.Minute()
	s, e := *w.DailyStartMinute, *w.DailyEndMinute
	if e > s {
		return m >= s && m < e
	}
	return m >= s || m < e
}

// Matches 判断窗口是否覆盖指定告警（ALL 全覆盖；CUSTOM 空维度视为通配）。
func (w MaintenanceWindow) Matches(alertType, component string) bool {
	if w.Scope == MaintScopeAll {
		return true
	}
	return containsOrWildcard(w.AlertTypes, alertType) && containsOrWildcard(w.Components, component)
}

func containsOrWildcard(list []string, v string) bool {
	if len(list) == 0 {
		return true
	}
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

// maintenanceWindowInput 是创建维护窗口的请求体。
type maintenanceWindowInput struct {
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	Scope            string    `json:"scope"`
	AlertTypes       []string  `json:"alert_types"`
	Components       []string  `json:"components"`
	Recurrence       string    `json:"recurrence"`
	StartsAt         time.Time `json:"starts_at"`
	EndsAt           time.Time `json:"ends_at"`
	DailyStartMinute *int      `json:"daily_start_minute"`
	DailyEndMinute   *int      `json:"daily_end_minute"`
}

// validate 校验并归一化维护窗口输入（大小写归一、空白裁剪），返回错误文案（空串=合法）。
func (in *maintenanceWindowInput) validate() string {
	in.Name = strings.TrimSpace(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	in.Scope = strings.ToUpper(strings.TrimSpace(in.Scope))
	in.Recurrence = strings.ToUpper(strings.TrimSpace(in.Recurrence))
	if in.Name == "" || len(in.Name) > maintNameMaxLen {
		return fmt.Sprintf("名称必填且不超过 %d 字符", maintNameMaxLen)
	}
	if len(in.Description) > maintDescMaxLen {
		return fmt.Sprintf("描述不超过 %d 字符", maintDescMaxLen)
	}
	if in.Scope == "" {
		in.Scope = MaintScopeAll
	}
	if in.Scope != MaintScopeAll && in.Scope != MaintScopeCustom {
		return "无效的作用范围（ALL/CUSTOM）"
	}
	if in.Recurrence == "" {
		in.Recurrence = MaintRecurrenceOnce
	}
	if in.Recurrence != MaintRecurrenceOnce && in.Recurrence != MaintRecurrenceDaily {
		return "无效的周期类型（ONCE/DAILY）"
	}
	if in.StartsAt.IsZero() || in.EndsAt.IsZero() {
		return "起止时间必填（RFC3339）"
	}
	if !in.EndsAt.After(in.StartsAt) {
		return "结束时间必须晚于开始时间"
	}
	if in.Recurrence == MaintRecurrenceDaily {
		if in.DailyStartMinute == nil || in.DailyEndMinute == nil {
			return "每日时段窗口必须提供 daily_start_minute/daily_end_minute"
		}
		if *in.DailyStartMinute < 0 || *in.DailyStartMinute > 1439 ||
			*in.DailyEndMinute < 0 || *in.DailyEndMinute > 1439 {
			return "每日时段分钟须在 0~1439 之间"
		}
		if *in.DailyStartMinute == *in.DailyEndMinute {
			return "每日时段起止分钟不能相同"
		}
	} else {
		in.DailyStartMinute = nil
		in.DailyEndMinute = nil
	}
	if in.Scope == MaintScopeCustom {
		if len(in.AlertTypes) == 0 && len(in.Components) == 0 {
			return "CUSTOM 范围须至少指定一类告警类型或组件"
		}
		if len(in.AlertTypes) > maintScopeMaxItem || len(in.Components) > maintScopeMaxItem {
			return fmt.Sprintf("告警类型/组件列表各不超过 %d 项", maintScopeMaxItem)
		}
		for i, t := range in.AlertTypes {
			t = strings.ToUpper(strings.TrimSpace(t))
			if !IsValidType(t) {
				return fmt.Sprintf("无效的告警类型：%s", in.AlertTypes[i])
			}
			in.AlertTypes[i] = t
		}
		for i, c := range in.Components {
			c = strings.ToUpper(strings.TrimSpace(c))
			if c == "" || len(c) > 50 {
				return "组件名不能为空且不超过 50 字符"
			}
			in.Components[i] = c
		}
	} else {
		in.AlertTypes = nil
		in.Components = nil
	}
	return ""
}

// toWindow 转换为持久化模型（未赋值 ID/审计字段）。
func (in *maintenanceWindowInput) toWindow(by uuid.UUID) *MaintenanceWindow {
	return &MaintenanceWindow{
		Name:             in.Name,
		Description:      in.Description,
		Scope:            in.Scope,
		AlertTypes:       in.AlertTypes,
		Components:       in.Components,
		Recurrence:       in.Recurrence,
		StartsAt:         in.StartsAt.UTC(),
		EndsAt:           in.EndsAt.UTC(),
		DailyStartMinute: in.DailyStartMinute,
		DailyEndMinute:   in.DailyEndMinute,
		Enabled:          true,
		CreatedBy:        &by,
	}
}

// ---------- Store ----------

const maintWindowColumns = `
id, name, description, scope, alert_types, components, recurrence,
starts_at, ends_at, daily_start_minute, daily_end_minute,
enabled, suppressed_count, last_suppressed_at, created_by, created_at`

func scanMaintenanceWindow(row interface{ Scan(...interface{}) error }) (*MaintenanceWindow, error) {
	var w MaintenanceWindow
	err := row.Scan(&w.ID, &w.Name, &w.Description, &w.Scope, &w.AlertTypes, &w.Components,
		&w.Recurrence, &w.StartsAt, &w.EndsAt, &w.DailyStartMinute, &w.DailyEndMinute,
		&w.Enabled, &w.SuppressedCount, &w.LastSuppressedAt, &w.CreatedBy, &w.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &w, nil
}

// CreateMaintenanceWindow 新建维护窗口。
func (s *Store) CreateMaintenanceWindow(ctx context.Context, w *MaintenanceWindow) error {
	return s.db.QueryRow(ctx, `
INSERT INTO system_alert_maintenance_windows
(name, description, scope, alert_types, components, recurrence,
 starts_at, ends_at, daily_start_minute, daily_end_minute, enabled, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id, created_at`,
		w.Name, w.Description, w.Scope, w.AlertTypes, w.Components, w.Recurrence,
		w.StartsAt, w.EndsAt, w.DailyStartMinute, w.DailyEndMinute, w.Enabled, w.CreatedBy,
	).Scan(&w.ID, &w.CreatedAt)
}

// ListMaintenanceWindows 列出全部维护窗口（按创建时间倒序）。
func (s *Store) ListMaintenanceWindows(ctx context.Context) ([]MaintenanceWindow, error) {
	rows, err := s.db.Query(ctx, `
SELECT `+maintWindowColumns+`
FROM system_alert_maintenance_windows
ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MaintenanceWindow{}
	for rows.Next() {
		w, err := scanMaintenanceWindow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *w)
	}
	return out, rows.Err()
}

// DeleteMaintenanceWindow 删除维护窗口；不存在返回 ErrNotFound。
func (s *Store) DeleteMaintenanceWindow(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.Exec(ctx, `DELETE FROM system_alert_maintenance_windows WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// FindActiveMaintenanceWindows 返回时刻 now 生效且覆盖 (alertType, component) 的窗口。
// 先按时间范围与启停过滤（窗口量级小），周期时段与 scope 匹配在内存判定。
func (s *Store) FindActiveMaintenanceWindows(ctx context.Context, now time.Time, alertType, component string) ([]MaintenanceWindow, error) {
	rows, err := s.db.Query(ctx, `
SELECT `+maintWindowColumns+`
FROM system_alert_maintenance_windows
WHERE enabled AND starts_at <= $1 AND ends_at >= $1`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MaintenanceWindow{}
	for rows.Next() {
		w, err := scanMaintenanceWindow(rows)
		if err != nil {
			return nil, err
		}
		if w.ActiveAt(now) && w.Matches(alertType, component) {
			out = append(out, *w)
		}
	}
	return out, rows.Err()
}

// RecordMaintenanceSuppression 记录抑制事实：命中窗口 suppressed_count+1 并刷新最近抑制时刻。
func (s *Store) RecordMaintenanceSuppression(ctx context.Context, ids []uuid.UUID, now time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.db.Exec(ctx, `
UPDATE system_alert_maintenance_windows
SET suppressed_count = suppressed_count + 1, last_suppressed_at = $2
WHERE id = ANY($1)`, ids, now)
	return err
}
