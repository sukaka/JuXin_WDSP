// types.go AI 定时运营任务核心类型：计划/执行记录、任务类型词表、任务入参与错误。
package apiops

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// 内置任务类型词表（v1 五种；与迁移 000062 chk_api_ai_schedules_task_type 一致，
// 新增类型须同步迁移 CHECK 与任务注册表）。
const (
	TaskAssetDigest     = "API_ASSET_DIGEST" // 资产变化摘要：新增/确认/Shadow/Zombie 计数与清单
	TaskShadowReview    = "SHADOW_REVIEW"    // Shadow API 运营：新 Shadow 清单 + 纳管建议
	TaskWeaknessFollow  = "WEAKNESS_FOLLOW"  // 弱点跟进：到期/超期弱点清单 + 催办建议
	TaskRiskDigest      = "RISK_DIGEST"      // 高风险 findings 摘要（HIGH/CRITICAL 未闭环）
	TaskSensitiveDigest = "SENSITIVE_DIGEST" // 涉敏概览变化：涉敏端点/字段计数与新增清单
)

// TaskTypes 返回任务类型词表（注册表键序固定，供校验与展示）。
func TaskTypes() []string {
	return []string{TaskAssetDigest, TaskShadowReview, TaskWeaknessFollow, TaskRiskDigest, TaskSensitiveDigest}
}

// ValidTaskType 校验任务类型词表。
func ValidTaskType(t string) bool {
	_, ok := taskRegistry[t]
	return ok
}

// TaskTypeInfo 任务类型展示元数据。
type TaskTypeInfo struct {
	TaskType    string `json:"task_type"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// TaskTypeInfos 任务类型展示清单（GET /task-types）。
func TaskTypeInfos() []TaskTypeInfo {
	return []TaskTypeInfo{
		{TaskAssetDigest, "资产变化摘要", "统计窗口内新增/确认端点与 Shadow/Zombie 未闭环计数，附新增端点清单"},
		{TaskShadowReview, "Shadow API 运营", "汇总未闭环 Shadow 发现与窗口内新增 Shadow 清单，给出纳管建议"},
		{TaskWeaknessFollow, "弱点整改跟进", "列出超期与临近到期弱点清单，给出催办建议"},
		{TaskRiskDigest, "高风险发现摘要", "汇总 HIGH/CRITICAL 未闭环发现的类型分布与重点清单"},
		{TaskSensitiveDigest, "涉敏概览变化", "统计涉敏端点/字段总量与类型分布，列出窗口内新增涉敏字段"},
	}
}

// 执行记录状态词表（与迁移 000062 chk_api_ai_schedule_runs_status 一致）。
const (
	RunStatusRunning = "RUNNING"
	RunStatusSuccess = "SUCCESS"
	RunStatusFailed  = "FAILED"
)

// 包内错误（handler 映射为 4xx/5xx，不静默吞错）。
var (
	ErrScheduleNotFound  = errors.New("计划不存在")
	ErrRunNotFound       = errors.New("执行记录不存在")
	ErrRunConflict       = errors.New("该计划已有正在执行中的运行")
	ErrSchedulesDisabled = errors.New("AI 运营定时任务总开关未启用")
	ErrInvalidTaskType   = errors.New("无效的任务类型")
	ErrInvalidCron       = errors.New("无效的 cron 表达式")
	ErrInvalidConfig     = errors.New("无效的任务配置")
	ErrInvalidName       = errors.New("名称必填且不超过 128 字符")
	ErrTaskTypeImmutable = errors.New("任务类型不可变更")
)

// Schedule AI 运营定时计划。
type Schedule struct {
	ID         uuid.UUID       `json:"id"`
	TaskType   string          `json:"task_type"`
	Name       string          `json:"name"`
	CronExpr   string          `json:"cron_expr"`
	Enabled    bool            `json:"enabled"`
	Config     json.RawMessage `json:"config"`
	NextRunAt  *time.Time      `json:"next_run_at"`
	LastRunAt  *time.Time      `json:"last_run_at"`
	LastStatus string          `json:"last_status"`
	LastError  string          `json:"last_error"`
	// 连续失败熔断（迁移 000187）：失败计数（成功清零）、熔断时间与原因；
	// 达阈同事务 enabled=false + 清空 next_run_at，手动启用时清零复位
	ConsecutiveFailures int        `json:"consecutive_failures"`
	CircuitOpenedAt     *time.Time `json:"circuit_opened_at"`
	CircuitReason       string     `json:"circuit_reason"`
	CreatedBy           *uuid.UUID `json:"created_by"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// Run 执行记录（每次触发一行，含手动立即执行）。
type Run struct {
	ID         uuid.UUID       `json:"id"`
	ScheduleID uuid.UUID       `json:"schedule_id"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt *time.Time      `json:"finished_at"`
	Status     string          `json:"status"`
	Summary    string          `json:"summary"`
	Report     json.RawMessage `json:"report"`
	CreatedAt  time.Time       `json:"created_at"`
}

// 任务入参边界（缺省值与夹取范围；越界拒绝而非静默夹取——入参校验纪律）。
const (
	defaultWindowHours   = 24
	maxWindowHours       = 720 // 30 天
	defaultLimit         = 20
	maxLimit             = 100
	defaultDueWithinDays = 3
	maxDueWithinDays     = 30
)

// TaskConfig 任务入参（config_json 白名单键；零值取缺省）。
type TaskConfig struct {
	WindowHours   int `json:"window_hours,omitempty"`    // 统计窗口（小时），缺省 24
	Limit         int `json:"limit,omitempty"`           // 清单条数上限，缺省 20
	DueWithinDays int `json:"due_within_days,omitempty"` // WEAKNESS_FOLLOW 临近到期窗口（天），缺省 3
}

// ParseTaskConfig 解析并校验任务入参：白名单键（未知键拒绝）、范围校验、缺省填充。
// raw 为空或 "{}" 时返回全缺省配置。
func ParseTaskConfig(raw json.RawMessage) (TaskConfig, error) {
	cfg := TaskConfig{
		WindowHours:   defaultWindowHours,
		Limit:         defaultLimit,
		DueWithinDays: defaultDueWithinDays,
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return cfg, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("%w：%v", ErrInvalidConfig, err)
	}
	if cfg.WindowHours < 0 || cfg.WindowHours > maxWindowHours {
		return cfg, fmt.Errorf("%w：window_hours 须在 1..%d 之间", ErrInvalidConfig, maxWindowHours)
	}
	if cfg.Limit < 0 || cfg.Limit > maxLimit {
		return cfg, fmt.Errorf("%w：limit 须在 1..%d 之间", ErrInvalidConfig, maxLimit)
	}
	if cfg.DueWithinDays < 0 || cfg.DueWithinDays > maxDueWithinDays {
		return cfg, fmt.Errorf("%w：due_within_days 须在 0..%d 之间", ErrInvalidConfig, maxDueWithinDays)
	}
	if cfg.WindowHours == 0 {
		cfg.WindowHours = defaultWindowHours
	}
	if cfg.Limit == 0 {
		cfg.Limit = defaultLimit
	}
	return cfg, nil
}

// ValidateScheduleInput 校验计划写入口径（创建/更新共用）：名称长度 + cron 可解析。
func ValidateScheduleInput(name, cronExpr string) error {
	if n := utf8.RuneCountInString(name); n == 0 || n > 128 {
		return ErrInvalidName
	}
	if _, err := ParseCron(cronExpr); err != nil {
		return err
	}
	return nil
}

// truncRunes 按字符截断（circuit_reason VARCHAR(500) 等定长列防溢出）。
func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
