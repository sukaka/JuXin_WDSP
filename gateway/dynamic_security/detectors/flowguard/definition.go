// Package flowguard 强流程（响应确认型业务流程防护）定义解析与校验
// （NG-FLOW-01 gateway 轨，docs/nextgen/NG-FLOW-strong-flow.md §1.1 冻结契约）。
//
// 本包只做强流程定义（发布通道下发 api_strong_flows 段：定义+步骤数组随快照
// 下发，仅 status=ACTIVE）的反序列化、§1.1 校验规则逐条校验与版本不可变装配
// （Registry）——校验失败即装配失败（fail-closed，与既有发布段解析同纪律）。
// 本批（FLOW-01）不含任何运行时判定：检测器执行体（原子预留/实断）属 FLOW-02，
// 成功判定式运行期解析属 FLOW-03，本批不接入 pipeline；段缺失/空数组 = 零行为
// （NG-T-C01：无定义时管线零行为、无新日志、无新状态）。
//
// 与既有流程观察（detectors/flow.go 七类 OBSERVE 信号，发布段
// api_flow_baselines）并行共存、互不消费：强流程实例热状态命名空间
// Valkey sflow:v1:（§1.2）与观察态会话键物理隔离，无任何导入路径。
//
// 校验口径与 server 侧管理面（server/internal/strongflow/validate.go）同词表
// 同边界双保险：管理面入库前已拒绝的非法配置，网关装配期永远不应再遇到；
// 遇到即快照异常，fail-closed 拒载，不夹紧猜义、不静默降级。
package flowguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// 词表（§1.1 冻结 + 联调裁决 §8.4-1 育龄窗；与 server 侧 strongflow 同词表，
// 发布数据为规范大写形态）。
const (
	// StatusActive 发布面 ACTIVE 定义：可创建新实例（INSTANCE_NEW）。
	StatusActive = "ACTIVE"
	// StatusRetired 育龄窗 RETIRED 定义（存在非终态实例随发布面下发）：
	// 仅存量实例续跑（既有实例键的后续步骤匹配），不得创建新实例
	// （reserve 层 definition_retired 拒绝；无非终态实例后自然掉出发布面）。
	StatusRetired = "RETIRED"

	// ModeObserve 缺省模式：只记录不实断（NG-T-C01 零变化承载）。
	ModeObserve = "OBSERVE"
	// ModeProtect PROTECT 违规实断（FLOW-02 接入请求链；本批仅解析不判定）。
	ModeProtect = "PROTECT"

	// RetryIdempotent 步骤可安全重试（幂等）。
	RetryIdempotent = "IDEMPOTENT"
	// RetryNotRetryable 步骤不可重试。
	RetryNotRetryable = "NOT_RETRYABLE"
	// RetryRequiresReview 重试需人工复核。
	RetryRequiresReview = "REQUIRES_REVIEW"
)

// 边界（§1.1 冻结；与 server 侧同边界——夹紧区间外拒收不夹紧猜义）。
const (
	TimeoutSecondsMin = 15  // timeout_seconds 夹紧下界
	TimeoutSecondsMax = 600 // timeout_seconds 夹紧上界
	LeaseSecondsMin   = 15  // lease_seconds 夹紧下界
	LeaseSecondsMax   = 300 // lease_seconds 夹紧上界

	// MaxStepsPerDefinition 单定义步骤数上限。
	MaxStepsPerDefinition = 64

	maxNameLen          = 255
	maxBindingPrefixLen = 512
	maxInstanceParamLen = 128
	maxStepKeyLen       = 128
	maxEndpointKeyLen   = 560
	maxParallelGroupLen = 128
	maxSuccessRuleBytes = 4096
)

// Definition 强流程定义（发布通道下发 api_strong_flows 段元素；字段名与 §1.1
// 定义表列名 snake_case 逐字段对应，线契约冻结不得改名）。
type Definition struct {
	ID                string `json:"id"`
	ApplicationID     string `json:"application_id"`
	Name              string `json:"name"`
	Version           int    `json:"version"` // 单调递增，激活即冻结（版本不可变承载）
	Status            string `json:"status,omitempty"`
	BindingPathPrefix string `json:"binding_path_prefix"`
	// InstanceKeyParam 实例引用来源（批准的参数提取器键，形态
	// "query:<参数名>" / "path:<段序>"——与对象模型 object_segment 同词表纪律）。
	InstanceKeyParam string     `json:"instance_key_param"`
	Mode             string     `json:"mode,omitempty"` // OBSERVE|PROTECT，缺省 OBSERVE
	CreatedBy        string     `json:"created_by,omitempty"`
	CreatedAt        *time.Time `json:"created_at,omitempty"`
	ActivatedAt      *time.Time `json:"activated_at,omitempty"`
	Steps            []Step     `json:"steps"`
}

// Step 强流程步骤（§1.1 步骤表列名 snake_case 逐字段对应）。
type Step struct {
	ID          string `json:"id,omitempty"`
	StepKey     string `json:"step_key"`
	EndpointKey string `json:"endpoint_key"` // METHOD + 空格 + 路径模板（同 normalizer.EndpointKey 口径）
	Sequence    int    `json:"sequence"`     // 定义内唯一（严格递增即首步唯一最小的承载）
	// SuccessRule 成功判定式原始 JSON（三形态可组合与；装配期经 ParseSuccessRule
	// 严格解码+词表形态校验，运行期解析求值属 FLOW-03）。
	SuccessRule    json.RawMessage `json:"success_rule,omitempty"`
	TimeoutSeconds int             `json:"timeout_seconds"` // 15~600 夹紧区间，越界拒收
	RetrySemantics string          `json:"retry_semantics"` // IDEMPOTENT|NOT_RETRYABLE|REQUIRES_REVIEW
	ParallelGroup  string          `json:"parallel_group,omitempty"`
	LeaseSeconds   int             `json:"lease_seconds"`        // 步骤预留租约 15~300 夹紧区间，越界拒收
	Allows202      bool            `json:"allows_202,omitempty"` // 异步受理：202=已受理待完成，不自动完成
}

// SuccessRule 成功判定式（§1.4/D4 三形态可组合与：全部配置的条件同时成立才判
// 成功）。白名单键——未知键拒收不忽略（管理面配置的条件被静默丢弃会弱化判定，
// fail-closed）。HTTP 2xx 不是通用成功证据（§9.3）：判定式必须显式配置。
type SuccessRule struct {
	// StatusCodes 响应状态码集合（形态一；元素须为合法 HTTP 状态码 100~599）。
	StatusCodes []int `json:"status_codes,omitempty"`
	// BodyJSONPathEquals body JSONPath 受限子集等值（形态二；仅点路径+等值）。
	BodyJSONPathEquals *JSONPathEquals `json:"body_jsonpath_equals,omitempty"`
	// GraphQLErrorsEmpty GraphQL errors 为空（形态三）。
	GraphQLErrorsEmpty bool `json:"graphql_errors_empty,omitempty"`
}

// JSONPathEquals 点路径等值（path 仅 $.a.b 点路径子集形态；value 为等值目标
// JSON 标量，标量语义的运行期求值属 FLOW-03）。
type JSONPathEquals struct {
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// ParseSuccessRule 严格解码成功判定式（DisallowUnknownFields：未知键拒绝；
// 体量上限 maxSuccessRuleBytes 与 server 侧同边界）。raw 缺失/空/null 返回
// (nil, nil)——「未配置」与「配置非法」显式区分（词表与形态校验见 validate.go）。
func ParseSuccessRule(raw json.RawMessage) (*SuccessRule, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	if len(trimmed) > maxSuccessRuleBytes {
		return nil, fmt.Errorf("success_rule 超 %d 字节", maxSuccessRuleBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	var rule SuccessRule
	if err := dec.Decode(&rule); err != nil {
		return nil, fmt.Errorf("success_rule 反序列化失败（白名单键，未知键拒收）: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("success_rule 含多余内容（单 JSON 对象）")
	}
	return &rule, nil
}
