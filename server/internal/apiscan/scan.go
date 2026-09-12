// scan.go 主动扫描领域类型与词表（纯逻辑，不依赖数据库）。
package apiscan

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound 记录不存在。
var ErrNotFound = errors.New("api scan record not found")

// ErrInvalidTransition 非法状态迁移（当前状态不允许该操作）。
var ErrInvalidTransition = errors.New("invalid api scan status transition")

// 目标状态（与迁移 000053 chk_api_scan_targets_status 一致）。
const (
	TargetStatusEnabled  = "ENABLED"
	TargetStatusDisabled = "DISABLED"
)

// 任务状态（与迁移 000053 chk_api_scan_jobs_status 一致）。
const (
	JobStatusPending   = "PENDING"   // 已排队，待调度
	JobStatusRunning   = "RUNNING"   // 执行中
	JobStatusPaused    = "PAUSED"    // 暂停（词表预留，v1 无暂停入口）
	JobStatusStopped   = "STOPPED"   // 人工停止 / 授权撤销 / 紧急停止
	JobStatusCompleted = "COMPLETED" // 正常完成
	JobStatusFailed    = "FAILED"    // 执行失败（原因落 progress.last_error）
)

// 扫描发现状态（与迁移 000054 chk_api_scan_findings_status 一致）。
const (
	FindingStatusNew           = "NEW"            // 引擎产出，待人工复核
	FindingStatusConfirmed     = "CONFIRMED"      // 人工确认为真实问题（可关联弱点）
	FindingStatusFalsePositive = "FALSE_POSITIVE" // 人工判定误报
	FindingStatusRetired       = "RETIRED"        // 失效（词表预留，复测未复现后可人工退役）
)

// 内置探针集词表（设计稿 §6.3；引擎只执行词表内探针，白名单外一律拒绝）。
const (
	ProbeAuthRequired      = "AUTH_REQUIRED"      // 未认证访问是否被拒（无凭据重放，判定 401/403 vs 2xx）
	ProbeDeprecatedAlive   = "DEPRECATED_ALIVE"   // 已下线端点是否仍在提供服务
	ProbeSensitiveExposure = "SENSITIVE_EXPOSURE" // 响应是否暴露敏感字段名（不落原文，只落字段名）
	ProbeSchemaConform     = "SCHEMA_CONFORM"     // 边界参数是否被校验（对照基线请求对比决策差异）
	ProbeBolaCompare       = "BOLA_COMPARE"       // 相邻对象标识响应差异（仅 OBSERVE 证据，不落原文）
	ProbeMethodEnum        = "METHOD_ENUM"        // OPTIONS 枚举允许方法集（不主动发送高风险方法）
)

// validProbeSets 探针集白名单。
var validProbeSets = map[string]bool{
	ProbeAuthRequired: true, ProbeDeprecatedAlive: true, ProbeSensitiveExposure: true,
	ProbeSchemaConform: true, ProbeBolaCompare: true, ProbeMethodEnum: true,
}

// IsValidProbeSet 校验探针集取值。
func IsValidProbeSet(s string) bool { return validProbeSets[s] }

// AllProbeSets 全部内置探针集（稳定顺序，授权画像为空时的默认全集）。
func AllProbeSets() []string {
	return []string{ProbeAuthRequired, ProbeDeprecatedAlive, ProbeSensitiveExposure,
		ProbeSchemaConform, ProbeBolaCompare, ProbeMethodEnum}
}

// 发现分类（category 列取值；与弱点中心分类口径对齐，AUTHZ 为越权类）。
const (
	CategoryAuthn     = "AUTHN"
	CategoryAuthz     = "AUTHZ"
	CategoryLifecycle = "LIFECYCLE"
	CategorySensitive = "SENSITIVE"
	CategorySchema    = "SCHEMA"
)

// 严重度（与 api_runtime_findings / api_weaknesses 口径一致）。
const (
	SeverityInfo     = "INFO"
	SeverityLow      = "LOW"
	SeverityMedium   = "MEDIUM"
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"
)

var validSeverities = map[string]bool{
	SeverityInfo: true, SeverityLow: true, SeverityMedium: true,
	SeverityHigh: true, SeverityCritical: true,
}

// IsValidSeverity 校验严重度取值。
func IsValidSeverity(s string) bool { return validSeverities[s] }

var validFindingStatuses = map[string]bool{
	FindingStatusNew: true, FindingStatusConfirmed: true,
	FindingStatusFalsePositive: true, FindingStatusRetired: true,
}

// IsValidFindingStatus 校验发现状态取值。
func IsValidFindingStatus(s string) bool { return validFindingStatuses[s] }

// ---------- 目标 ----------

// Target 扫描目标（api_scan_targets）。
type Target struct {
	ID            uuid.UUID  `json:"id"`
	ApplicationID uuid.UUID  `json:"application_id"`
	Name          string     `json:"name"`
	BaseURL       string     `json:"base_url"`
	AllowedPaths  []string   `json:"allowed_paths"`
	Status        string     `json:"status"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// ---------- 授权 ----------

// TimeWindow 授权时间窗（time_window JSONB；nil 端不限制）。
type TimeWindow struct {
	Start *time.Time `json:"start,omitempty"`
	End   *time.Time `json:"end,omitempty"`
}

// Authorization 扫描授权单（api_scan_authorizations）。
// 生效状态由 ExpiresAt/RevokedAt/TimeWindow 派生（Active），无独立状态列。
type Authorization struct {
	ID             uuid.UUID  `json:"id"`
	TargetID       uuid.UUID  `json:"target_id"`
	AuthorizedBy   uuid.UUID  `json:"authorized_by"`
	Allowlist      []string   `json:"allowlist"`
	TimeWindow     TimeWindow `json:"time_window"`
	MaxQPS         int        `json:"max_qps"`
	MaxConcurrency int        `json:"max_concurrency"`
	TestProfile    string     `json:"test_profile"`
	ExpiresAt      time.Time  `json:"expires_at"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// Active 授权当前是否有效：未撤销、未过期、处于时间窗内。
func (a *Authorization) Active(now time.Time) bool {
	return a.InactiveReason(now) == ""
}

// InactiveReason 授权失效原因（空串 = 有效）；执行侧按原因区分停止语义。
func (a *Authorization) InactiveReason(now time.Time) string {
	if a == nil {
		return "授权单不存在"
	}
	if a.RevokedAt != nil && !a.RevokedAt.After(now) {
		return "授权已撤销"
	}
	if !a.ExpiresAt.After(now) {
		return "授权已过期"
	}
	if a.TimeWindow.Start != nil && now.Before(*a.TimeWindow.Start) {
		return "未到授权时间窗起点"
	}
	if a.TimeWindow.End != nil && now.After(*a.TimeWindow.End) {
		return "已超出授权时间窗终点"
	}
	return ""
}

// ---------- 任务 ----------

// Progress 任务执行进度（progress JSONB；失败原因落 LastError，不静默吞错）。
type Progress struct {
	Total     int    `json:"total"`    // 解析出的待探测端点数
	Done      int    `json:"done"`     // 已完成端点数
	Requests  int    `json:"requests"` // 已发出请求数
	Findings  int    `json:"findings"` // 已产出发现数
	Errors    int    `json:"errors"`   // 探针执行错误数（单点错误不阻断任务）
	LastError string `json:"last_error,omitempty"`
}

// Job 扫描任务（api_scan_jobs）。
type Job struct {
	ID              uuid.UUID  `json:"id"`
	TargetID        uuid.UUID  `json:"target_id"`
	AuthorizationID uuid.UUID  `json:"authorization_id"`
	ProbeSet        string     `json:"probe_set"`
	Status          string     `json:"status"`
	Progress        Progress   `json:"progress"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	CreatedBy       *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// Terminal 任务是否终态（不可再流转）。
func (j *Job) Terminal() bool {
	switch j.Status {
	case JobStatusStopped, JobStatusCompleted, JobStatusFailed:
		return true
	}
	return false
}

// ---------- 发现 ----------

// Finding 扫描发现（api_scan_findings；样本均已脱敏截断）。
type Finding struct {
	ID             uuid.UUID  `json:"id"`
	JobID          uuid.UUID  `json:"job_id"`
	Engine         string     `json:"engine"`
	Template       string     `json:"template"`
	EndpointKey    string     `json:"endpoint_key"`
	Category       string     `json:"category"`
	Severity       string     `json:"severity"`
	Confidence     float64    `json:"confidence"`
	Evidence       any        `json:"evidence"`
	RequestSample  string     `json:"request_sample"`
	ResponseSample string     `json:"response_sample"`
	Status         string     `json:"status"`
	WeaknessID     *uuid.UUID `json:"weakness_id,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}
