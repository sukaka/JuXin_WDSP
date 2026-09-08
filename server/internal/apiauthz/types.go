// types.go 授权实体层实体、枚举常量与纯函数校验（handler 与 store 共用）。
package apiauthz

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound 资源不存在（角色基线 / 字段权限 / 评估端点）。
var ErrNotFound = errors.New("api authz resource not found")

// ErrBaselineConflict 角色基线冲突（endpoint_id+role+method+action 唯一）。
var ErrBaselineConflict = errors.New("api role baseline conflict")

// ErrFieldPermConflict 字段权限冲突（endpoint_id+field_path+direction+role+tenant 唯一）。
var ErrFieldPermConflict = errors.New("api field permission conflict")

// ErrEndpointNotFound 引用的端点资产不存在（FK 23503 映射）。
var ErrEndpointNotFound = errors.New("api endpoint not found")

// 权限点常量（种子迁移由集成方登记，本包只引用）。
const (
	PermAuthzRead   = "api_authorization.read"
	PermAuthzManage = "api_authorization.manage"
)

// 基线来源（api_role_baselines.source CHECK 对齐）。
const (
	SourceManual   = "MANUAL"   // 人工登记
	SourceSpec     = "SPEC"     // 规格（OpenAPI 等）导入
	SourceObserved = "OBSERVED" // 观测学习
	SourceImported = "IMPORTED" // 批量导入
)

// 字段方向（api_field_permissions.direction CHECK 对齐）。
const (
	DirectionRequest  = "REQUEST"  // 请求侧（防 Mass Assignment）
	DirectionResponse = "RESPONSE" // 响应侧（防越权读取）
)

// 字段属性（api_field_permissions.attribute CHECK 对齐）。
const (
	AttrReadable        = "READABLE"         // 可读
	AttrWritable        = "WRITABLE"         // 可写
	AttrReadOnly        = "READ_ONLY"        // 只读（写入即 Mass Assignment 嫌疑）
	AttrAdminWritable   = "ADMIN_WRITABLE"   // 仅管理员可写
	AttrServerGenerated = "SERVER_GENERATED" // 服务端生成（客户端提供即可疑）
	AttrSensitive       = "SENSITIVE"        // 敏感（读取需额外管控）
	AttrForbidden       = "FORBIDDEN"        // 禁止（出现即违规）
)

// BOLA 评估五档结论（evaluate.go 判定阶梯输出）。
const (
	// VerdictPolicyConfirmed 有权属记录且匹配：身份访问自己权属内的对象 → 允许。
	VerdictPolicyConfirmed = "POLICY_CONFIRMED"
	// VerdictHighConfidence 有权属记录且不匹配：对象已有属主，访问者不是属主 → 越权。
	VerdictHighConfidence = "HIGH_CONFIDENCE"
	// VerdictLikely 无该对象权属记录，但身份在本端点有权属基线或历史访问 → 倾向允许。
	VerdictLikely = "LIKELY"
	// VerdictPossible 端点已有权属画像，但该身份与对象均无记录（仅有对象枚举信号）→ 倾向可疑。
	VerdictPossible = "POSSIBLE"
	// VerdictInsufficientEvidence 无任何可用证据 → 无法判定。
	VerdictInsufficientEvidence = "INSUFFICIENT_EVIDENCE"
)

// 输入上限。
const (
	maxRoleLen    = 64
	maxActionLen  = 64
	maxTenantLen  = 64
	maxFieldPath  = 512
	maxObjectID   = 256
	maxObjectType = 128
	maxIdentity   = 128
)

// 合法 HTTP 方法白名单（与网关/资产侧大写方法口径一致）。
var validMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true,
}

// identifierPattern 角色/动作码字符白名单（字母数字下划线点短横，防注入式脏数据）。
var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9_.\-]+$`)

// RoleBaseline 角色功能级基线（api_role_baselines，BFLA）。
type RoleBaseline struct {
	ID         uuid.UUID `json:"id"`
	EndpointID uuid.UUID `json:"endpoint_id"`
	Role       string    `json:"role"`   // 角色码
	Method     string    `json:"method"` // HTTP 方法（大写）
	Action     string    `json:"action"` // 业务动作（大写归一）
	Allowed    bool      `json:"allowed"`
	Source     string    `json:"source"`     // MANUAL / SPEC / OBSERVED / IMPORTED
	Confidence float64   `json:"confidence"` // 0..1
	Confirmed  bool      `json:"confirmed"`  // 人工确认标记
	CreatedBy  *string   `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ObjectOwnership 对象权属基线（api_object_ownership，BOLA；SweepOnce 生产，只读查询）。
type ObjectOwnership struct {
	ID                  uuid.UUID `json:"id"`
	EndpointID          uuid.UUID `json:"endpoint_id"`
	IdentityFingerprint string    `json:"identity_fingerprint"`
	ObjectType          string    `json:"object_type"`
	ObjectID            string    `json:"object_id"`
	FirstSeen           time.Time `json:"first_seen"`
	LastSeen            time.Time `json:"last_seen"`
	AccessCount         int64     `json:"access_count"`
}

// ObjectModel 对象模型候选（api_object_models，BOLA 实体画像；
// SweepObjectModelsOnce 生产，见 objectmodels.go；object_type 不入列，
// 可由端点模板/段形表派生：path 段取前一静态段，query 段即参数名）。
type ObjectModel struct {
	ID              uuid.UUID `json:"id"`
	EndpointID      uuid.UUID `json:"endpoint_id"`
	ObjectSegment   string    `json:"object_segment"`  // path:<pos> / query:<参数名>
	IdentifierType  string    `json:"identifier_type"` // numeric / uuid / hash / mixed / unknown
	ExampleHash     string    `json:"example_hash"`    // 观测示例 SHA-256（不落明文）
	EntropyEstimate *float64  `json:"entropy_estimate,omitempty"`
	SampleCount     int64     `json:"sample_count"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
}

// FieldPermission 字段权限（api_field_permissions）。
// Role/Tenant 为可空列，Go 侧用指针表达 NULL 语义：nil = 默认行，非空 = 覆盖行。
type FieldPermission struct {
	ID         uuid.UUID `json:"id"`
	EndpointID uuid.UUID `json:"endpoint_id"`
	FieldPath  string    `json:"field_path"`
	Direction  string    `json:"direction"` // REQUEST / RESPONSE
	Attribute  string    `json:"attribute"` // 七值枚举
	Role       *string   `json:"role"`      // NULL = 默认，非空 = 角色覆盖
	Tenant     *string   `json:"tenant"`    // NULL = 默认，非空 = 租户覆盖
	CreatedBy  *string   `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ---------- 校验（纯函数） ----------

// validSource 基线来源枚举校验。
func validSource(s string) bool {
	switch s {
	case SourceManual, SourceSpec, SourceObserved, SourceImported:
		return true
	}
	return false
}

// validDirection 字段方向枚举校验。
func validDirection(s string) bool { return s == DirectionRequest || s == DirectionResponse }

// validAttribute 字段属性枚举校验。
func validAttribute(s string) bool {
	switch s {
	case AttrReadable, AttrWritable, AttrReadOnly, AttrAdminWritable,
		AttrServerGenerated, AttrSensitive, AttrForbidden:
		return true
	}
	return false
}

// checkIdentifier 角色/动作/租户码校验（非空、限长、字符白名单）。
func checkIdentifier(field, v string, maxLen int) error {
	if v == "" || len(v) > maxLen {
		return fmt.Errorf("%s 必填且长度不能超过 %d", field, maxLen)
	}
	if !identifierPattern.MatchString(v) {
		return fmt.Errorf("%s 仅允许字母、数字、下划线、点、短横", field)
	}
	return nil
}

// validateRoleBaseline 校验角色基线（创建/编辑共用；调用前已完成 trim 与归一）。
func validateRoleBaseline(b *RoleBaseline) error {
	if b.EndpointID == uuid.Nil {
		return errors.New("endpoint_id 必填")
	}
	if err := checkIdentifier("role", b.Role, maxRoleLen); err != nil {
		return err
	}
	if !validMethods[b.Method] {
		return errors.New("无效的 method 取值（GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS）")
	}
	if err := checkIdentifier("action", b.Action, maxActionLen); err != nil {
		return err
	}
	if !validSource(b.Source) {
		return errors.New("无效的 source 取值（MANUAL/SPEC/OBSERVED/IMPORTED）")
	}
	if b.Confidence < 0 || b.Confidence > 1 {
		return errors.New("confidence 取值范围 0..1")
	}
	return nil
}

// validateFieldPermission 校验字段权限（创建/编辑共用；与迁移 000044 CHECK 约束一致）。
func validateFieldPermission(p *FieldPermission) error {
	if p.EndpointID == uuid.Nil {
		return errors.New("endpoint_id 必填")
	}
	if strings.TrimSpace(p.FieldPath) == "" || len(p.FieldPath) > maxFieldPath {
		return fmt.Errorf("field_path 必填且长度不能超过 %d", maxFieldPath)
	}
	if !validDirection(p.Direction) {
		return errors.New("无效的 direction 取值（REQUEST/RESPONSE）")
	}
	if !validAttribute(p.Attribute) {
		return errors.New("无效的 attribute 取值（READABLE/WRITABLE/READ_ONLY/ADMIN_WRITABLE/SERVER_GENERATED/SENSITIVE/FORBIDDEN）")
	}
	if p.Role != nil {
		if err := checkIdentifier("role", *p.Role, maxRoleLen); err != nil {
			return err
		}
	}
	if p.Tenant != nil {
		if err := checkIdentifier("tenant", *p.Tenant, maxTenantLen); err != nil {
			return err
		}
	}
	return nil
}
