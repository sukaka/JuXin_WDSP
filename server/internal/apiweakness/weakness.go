// weakness.go 弱点领域类型与生命周期状态机（纯逻辑，不依赖数据库）。
package apiweakness

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound 弱点不存在。
var ErrNotFound = errors.New("api weakness not found")

// ErrInvalidTransition 非法状态迁移（当前状态不允许该操作）。
var ErrInvalidTransition = errors.New("invalid weakness status transition")

// 弱点状态（与迁移 000039 chk_api_weaknesses_status 一致）。
const (
	StatusNew        = "NEW"        // 扫描派生，待确认
	StatusConfirmed  = "CONFIRMED"  // 已确认为真实弱点
	StatusToFix      = "TO_FIX"     // 已指派整改
	StatusFixed      = "FIXED"      // 整改完成，待复测
	StatusReproduced = "REPRODUCED" // 复测未通过 / FIXED 后再被扫描命中
	StatusIgnored    = "IGNORED"    // 接受风险或误报
	StatusArchived   = "ARCHIVED"   // 关闭（复测通过或人工归档），终态
)

// 操作（写 api_weakness_actions.action 的取值）。
const (
	ActionDerived    = "DERIVED"     // 派生扫描首次发现（actor=system）
	ActionConfirm    = "CONFIRM"     // 确认弱点
	ActionAssign     = "ASSIGN"      // 指派/改派整改
	ActionMarkFixed  = "MARK_FIXED"  // 标记整改完成
	ActionRetestPass = "RETEST_PASS" // 复测通过
	ActionRetestFail = "RETEST_FAIL" // 复测未通过
	ActionIgnore     = "IGNORE"      // 忽略（接受风险/误报）
	ActionArchive    = "ARCHIVE"     // 人工归档关闭
	ActionReproduced = "REPRODUCED"  // FIXED 后再被扫描命中（actor=system）
)

// 复测结果取值（POST /{id}/retest 请求体 result 字段）。
const (
	RetestPass = "PASS"
	RetestFail = "FAIL"
)

// 弱点分类（category 列取值；新弱点码可扩展）。
const (
	CategoryAuthn     = "AUTHN"     // 认证缺失
	CategoryAuthz     = "AUTHZ"     // 对象授权与业务滥用
	CategoryLifecycle = "LIFECYCLE" // 生命周期
	CategorySensitive = "SENSITIVE" // 敏感数据
	CategorySchema    = "SCHEMA"    // Schema 治理
)

// 严重度（与 api_runtime_findings 口径一致）。
const (
	SeverityInfo     = "INFO"
	SeverityLow      = "LOW"
	SeverityMedium   = "MEDIUM"
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"
)

// 派生规则的弱点码（SweepOnce 数据源见 sweep.go）。
const (
	CodeUnauthenticatedSensitiveAPI = "UNAUTHENTICATED_SENSITIVE_API"
	CodeDeprecatedStillCalled       = "DEPRECATED_STILL_CALLED"
	CodeSensitiveInQuery            = "SENSITIVE_IN_QUERY"
	CodeCredentialInURL             = "CREDENTIAL_IN_URL"
	CodeSensitiveCookie             = "SENSITIVE_COOKIE"
	CodeServerInfoDisclosure        = "SERVER_INFO_DISCLOSURE"
	CodeObjectEnumerationRisk       = "OBJECT_ENUMERATION_RISK"
	CodeFlowSequenceDeviation       = "FLOW_SEQUENCE_DEVIATION"
	CodeFlowReplayOrBurst           = "FLOW_REPLAY_OR_BURST"
	CodeFileContentTypeMismatch     = "FILE_CONTENT_TYPE_MISMATCH"
	CodeSensitiveFileContent        = "SENSITIVE_FILE_CONTENT"
	CodeSensitiveResponseUnmasked   = "SENSITIVE_RESPONSE_UNMASKED"
	CodeSchemaDriftPersistent       = "SCHEMA_DRIFT_PERSISTENT"
)

// 弱点码 → 展示名/分类/严重度（派生写入时取值）。
var weaknessMeta = map[string]struct {
	Name     string
	Category string
	Severity string
}{
	CodeUnauthenticatedSensitiveAPI: {"未认证敏感接口被调用", CategoryAuthn, SeverityHigh},
	CodeDeprecatedStillCalled:       {"已下线接口仍被调用", CategoryLifecycle, SeverityMedium},
	CodeSensitiveInQuery:            {"敏感数据出现在 URL 查询串", CategorySensitive, SeverityHigh},
	CodeCredentialInURL:             {"URL 携带明文密码或凭据", CategoryAuthn, SeverityHigh},
	CodeSensitiveCookie:             {"Cookie 包含敏感凭据信息", CategorySensitive, SeverityMedium},
	CodeServerInfoDisclosure:        {"服务器版本或错误信息泄露", CategorySensitive, SeverityMedium},
	CodeObjectEnumerationRisk:       {"对象标识批量遍历风险", CategoryAuthz, SeverityHigh},
	CodeFlowSequenceDeviation:       {"业务访问序列异常", CategoryAuthz, SeverityHigh},
	CodeFlowReplayOrBurst:           {"重复提交或短窗批量滥用", CategoryAuthz, SeverityMedium},
	CodeFileContentTypeMismatch:     {"文件真实类型与声明不符", CategorySensitive, SeverityMedium},
	CodeSensitiveFileContent:        {"文件中检出敏感内容", CategorySensitive, SeverityMedium},
	CodeSensitiveResponseUnmasked:   {"响应敏感信息未观察到成功脱敏", CategorySensitive, SeverityMedium},
	CodeSchemaDriftPersistent:       {"Schema 漂移长期存在", CategorySchema, SeverityMedium},
}

// WeaknessMeta 弱点码的展示元数据；未注册码返回 false（派生器忽略未知规则）。
func WeaknessMeta(code string) (name, category, severity string, ok bool) {
	m, ok := weaknessMeta[code]
	if !ok {
		return "", "", "", false
	}
	return m.Name, m.Category, m.Severity, true
}

// validStatuses / validSeverities 列表过滤与入参校验用白名单。
var validStatuses = map[string]bool{
	StatusNew: true, StatusConfirmed: true, StatusToFix: true, StatusFixed: true,
	StatusReproduced: true, StatusIgnored: true, StatusArchived: true,
}

var validSeverities = map[string]bool{
	SeverityInfo: true, SeverityLow: true, SeverityMedium: true,
	SeverityHigh: true, SeverityCritical: true,
}

// IsValidStatus / IsValidSeverity 校验枚举取值。
func IsValidStatus(s string) bool   { return validStatuses[s] }
func IsValidSeverity(s string) bool { return validSeverities[s] }

// transitions 状态机迁移表：action → 允许的源状态 → 目标状态。
// 表外组合一律非法（ErrInvalidTransition，HTTP 400）。
var transitions = map[string]map[string]string{
	ActionConfirm:    {StatusNew: StatusConfirmed},
	ActionAssign:     {StatusConfirmed: StatusToFix, StatusToFix: StatusToFix, StatusReproduced: StatusToFix},
	ActionMarkFixed:  {StatusToFix: StatusFixed},
	ActionRetestPass: {StatusFixed: StatusArchived},
	ActionRetestFail: {StatusFixed: StatusReproduced},
	ActionIgnore:     {StatusNew: StatusIgnored, StatusConfirmed: StatusIgnored, StatusToFix: StatusIgnored, StatusReproduced: StatusIgnored},
	ActionArchive:    {StatusConfirmed: StatusArchived, StatusToFix: StatusArchived, StatusFixed: StatusArchived, StatusReproduced: StatusArchived, StatusIgnored: StatusArchived},
}

// ResolveTransition 计算 (action, from) 的目标状态；非法组合返回 false。
func ResolveTransition(action, from string) (string, bool) {
	byFrom, ok := transitions[action]
	if !ok {
		return "", false
	}
	to, ok := byFrom[from]
	return to, ok
}

// Weakness API 弱点（api_weaknesses）。
type Weakness struct {
	ID           uuid.UUID       `json:"id"`
	EndpointID   *uuid.UUID      `json:"endpoint_id,omitempty"`
	EndpointKey  string          `json:"endpoint_key"` // LEFT JOIN api_endpoints 带出；端点已删除时为空
	WeaknessCode string          `json:"weakness_code"`
	WeaknessName string          `json:"weakness_name"`
	Category     string          `json:"category"`
	Severity     string          `json:"severity"`
	Status       string          `json:"status"`
	Evidence     json.RawMessage `json:"evidence"`
	FirstSeen    time.Time       `json:"first_seen"`
	LastSeen     time.Time       `json:"last_seen"`
	TriggerCount int             `json:"trigger_count"`
	Owner        string          `json:"owner"`
	DueDate      *time.Time      `json:"due_date,omitempty"`
	FixedAt      *time.Time      `json:"fixed_at,omitempty"`
	RetestedAt   *time.Time      `json:"retested_at,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// WeaknessAction 整改/复测历史条目（api_weakness_actions）。
type WeaknessAction struct {
	ID         uuid.UUID `json:"id"`
	WeaknessID uuid.UUID `json:"weakness_id"`
	Action     string    `json:"action"`
	Actor      string    `json:"actor"`
	Note       string    `json:"note"`
	CreatedAt  time.Time `json:"created_at"`
}

// TransitionInput 一次生命周期操作的输入（按动作取用相应字段）。
type TransitionInput struct {
	Actor   string     // 操作者用户名（派生扫描为 system）
	Note    string     // 备注/原因
	Owner   string     // ASSIGN：整改负责人
	DueDate *time.Time // ASSIGN：整改期限
	Now     time.Time  // 流转发生时间（测试可注入）
}
