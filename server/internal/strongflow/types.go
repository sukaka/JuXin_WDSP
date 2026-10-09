// Package strongflow 强流程定义管理面（NG-FLOW-01，docs/nextgen/NG-FLOW-strong-flow.md）。
//
// 定义与版本冻结语义（D1）：POST 新建（version=1 DRAFT）或同名新草稿（version=max+1）；
// PUT 仅 DRAFT 原地编辑；activate 即冻结（同事务 RETIRED 同名义旧 ACTIVE）；
// RETIRED 单向终态。与既有流程观察（api_flow_baselines）物理隔离，无导入路径。
// 权限沿用 api_flow.read / api_flow.manage（迁移 000155 已种，零新增权限点）。
package strongflow

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// 权限点（种子见迁移 000155；与 apiflows 同域同点）。
const (
	PermFlowRead   = "api_flow.read"
	PermFlowManage = "api_flow.manage"
	// PermEvidenceRead 证据明细查看（复用授权域已种权限点——迁移 000136
	// api_authorization.evidence_read，授 SECURITY_ADMIN/AUDIT_ADMIN；D9「权限沿用
	// read/manage/evidence_read 零新增」承载：实例详情进门走 api_flow.read，
	// 证据明细（request_id/reason_code/fencing_token）仅持本权限点者带出，
	// 与 apiauthz 决策详情 evidence 裁剪同构）。
	PermEvidenceRead = "api_authorization.evidence_read"
)

// 词表（§1.1 冻结）。
const (
	StatusDraft   = "DRAFT"
	StatusActive  = "ACTIVE"
	StatusRetired = "RETIRED"

	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"

	RetryIdempotent     = "IDEMPOTENT"
	RetryNotRetryable   = "NOT_RETRYABLE"
	RetryRequiresReview = "REQUIRES_REVIEW"

	timeoutMinSeconds = 15
	timeoutMaxSeconds = 600
	leaseMinSeconds   = 15
	leaseMaxSeconds   = 300

	maxStepsPerDefinition = 64
	maxNameLen            = 255
	maxBindingPrefixLen   = 512
	maxInstanceParamLen   = 128
	maxStepKeyLen         = 128
	maxParallelGroupLen   = 128
	maxSuccessRuleBytes   = 4096
)

// 哨兵错误（handler 映射 400/404/409 精确区分）。
var (
	ErrNotFound          = errors.New("strong flow definition not found")
	ErrNotDraft          = errors.New("definition is not DRAFT（激活即冻结：ACTIVE/RETIRED 不可编辑不可再激活）")
	ErrInvalidTransition = errors.New("invalid status transition（RETIRED 单向终态）")
	ErrVersionConflict   = errors.New("strong flow instance version conflict（乐观锁不匹配：实例已被变更，请刷新后重试）")
	ErrNoSteps           = errors.New("定义至少包含一个步骤")
	// ErrInstanceNotFound 实例不存在（详情/resolve 404；与定义不存在显式区分消息）
	ErrInstanceNotFound = errors.New("strong flow instance not found")
	// ErrInstanceTerminal 终态实例拒绝恢复（409 幂等不误伤——CONFIRMED/CANCELLED/FAILED 已定案，
	// 重复恢复一律拒绝不推进；§1.5/D5）
	ErrInstanceTerminal = errors.New("instance already terminal（CONFIRMED/CANCELLED/FAILED 终态拒绝重复恢复）")
)

// resolve 动作词表（§1.5/D5 冻结；词表外 400 不降级猜义）。
const (
	// ResolveConfirmSucceeded 对账确认业务已执行 → 实例推 CONFIRMED（终态）
	ResolveConfirmSucceeded = "CONFIRM_SUCCEEDED"
	// ResolveConfirmNotExecuted 对账确认业务未执行 → 实例推 FAILED（终态；
	// FAILED=「明确业务失败——仅由明确证据进入」（§1.2），人工对账确认未执行即明确证据）
	ResolveConfirmNotExecuted = "CONFIRM_NOT_EXECUTED"
	// ResolveKeepUnknown 保持未知（不推进状态，仅留审计与 RESOLVE 事件——未知
	// 不显示安全通过，绝不美化成通过）
	ResolveKeepUnknown = "KEEP_UNKNOWN"

	// ReasonResolve 管理恢复事件原因码（CONFIRM_* 状态推进事件与 KEEP_UNKNOWN
	// RESOLVE 留痕共用——事件链可区分管理面对账与网关执行侧产出）。
	ReasonResolve = "FLOW-RESOLVE-001"
	// ActionResolve 管理恢复留痕动作（仅 KEEP_UNKNOWN 落行；迁移 000178 放宽
	// step_events action CHECK 加入——管理面专属词表，网关执行侧不产出）。
	ActionResolve = "RESOLVE"
)

// ValidationError 载荷校验错误（400；与存储错误显式区分）。
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalidf(format string, args ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, args...)}
}

// SuccessRule 成功判定式（§1.4 三形态可组合与；运行期解析属 FLOW-03，
// 本层只做受限子集词表与形态校验）。白名单键，未知键拒收不忽略。
type SuccessRule struct {
	// StatusCodes 响应状态码集合（100~599，非空时形态一成立）
	StatusCodes []int `json:"status_codes,omitempty"`
	// BodyJSONPathEquals body JSONPath 子集等值（仅点路径 $.a.b 形态；形态二）
	BodyJSONPathEquals *JSONPathEquals `json:"body_jsonpath_equals,omitempty"`
	// GraphQLErrorsEmpty GraphQL errors 为空（形态三）
	GraphQLErrorsEmpty bool `json:"graphql_errors_empty,omitempty"`
}

// JSONPathEquals 点路径等值（path 形态校验见 validate.go；value 为 JSON 标量）。
type JSONPathEquals struct {
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// StepInput 步骤写入载荷（activate 前全量校验的输入形态）。
type StepInput struct {
	StepKey        string       `json:"step_key"`
	EndpointKey    string       `json:"endpoint_key"`
	Sequence       int          `json:"sequence"`
	SuccessRule    *SuccessRule `json:"success_rule"`
	TimeoutSeconds int          `json:"timeout_seconds"`
	RetrySemantics string       `json:"retry_semantics"`
	ParallelGroup  string       `json:"parallel_group"`
	LeaseSeconds   int          `json:"lease_seconds"`
	Allows202      bool         `json:"allows_202"`
}

// Definition 定义行（读模型）。
type Definition struct {
	ID                uuid.UUID  `json:"id"`
	ApplicationID     uuid.UUID  `json:"application_id"`
	Name              string     `json:"name"`
	Version           int        `json:"version"`
	Status            string     `json:"status"`
	BindingPathPrefix string     `json:"binding_path_prefix"`
	InstanceKeyParam  string     `json:"instance_key_param"`
	Mode              string     `json:"mode"`
	CreatedByName     string     `json:"created_by_name"`
	CreatedAt         time.Time  `json:"created_at"`
	ActivatedAt       *time.Time `json:"activated_at"`
}

// DefinitionDetail 定义 + 步骤（详情出参）。
type DefinitionDetail struct {
	Definition
	Steps []StepInput `json:"steps"`
}

// DefinitionInput 新建/编辑载荷（编辑为整体替换语义：steps 全量给出）。
type DefinitionInput struct {
	ApplicationID     string      `json:"application_id"`
	Name              string      `json:"name"`
	BindingPathPrefix string      `json:"binding_path_prefix"`
	InstanceKeyParam  string      `json:"instance_key_param"`
	Mode              string      `json:"mode"`
	Steps             []StepInput `json:"steps"`
}
