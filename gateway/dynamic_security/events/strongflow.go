// strongflow.go 强流程（响应确认型业务流程防护）运行时事件形状
// （NG-FLOW-02，docs/nextgen/NG-FLOW-strong-flow.md §1.2/§1.3/§1.6）。
//
// StrongFlowAction 随 api_runtime_events 主事件行 strong_flow 数组内嵌落库
// （server 采集轨按冻结字段名消费写入 api_strong_flow_step_events——字段名
// 不得改；与 AuthzDecision/AuthzEnforcementEvidence 同纪律：不建新表、复用
// 既有留存/导出链）。冻结键全量恒在（无 omitempty——消费端按冻结键名取数），
// 无值字段以零值如实呈现（如 UNKNOWN 时 fencing_token=0）。
package events

import "time"

// 强流程动作词表（冻结）。
const (
	SFlowActionReserve               = "RESERVE"
	SFlowActionCommit                = "COMMIT"
	SFlowActionRelease               = "RELEASE"
	SFlowActionExpire                = "EXPIRE"
	SFlowActionInstanceNew           = "INSTANCE_NEW"
	SFlowActionInstanceConfirmed     = "INSTANCE_CONFIRMED"
	SFlowActionInstanceIndeterminate = "INSTANCE_INDETERMINATE"
	SFlowActionInstanceCancelled     = "INSTANCE_CANCELLED"
	SFlowActionInstanceFailed        = "INSTANCE_FAILED"
)

// 强流程动作结果词表（冻结）。
const (
	SFlowResultOK       = "OK"
	SFlowResultConflict = "CONFLICT"
	SFlowResultRejected = "REJECTED"
	SFlowResultUnknown  = "UNKNOWN"
)

// StrongFlowAction 一次强流程原子操作/状态迁移的事实条目（网关热路径产出：
// 本批 RESERVE/INSTANCE_NEW/EXPIRE；COMMIT/RELEASE 接口已冻结、响应回程判定
// 接线属 FLOW-03；INSTANCE_INDETERMINATE/CANCELLED/FAILED 由管理对账/恢复链
// 产出）。InstanceID 为 sfref: HMAC 引用（域隔离，不落实例引用明文）。
type StrongFlowAction struct {
	DefinitionID      string    `json:"definition_id"`
	DefinitionVersion int       `json:"definition_version"`
	InstanceID        string    `json:"instance_id"`
	StepKey           string    `json:"step_key"`
	Action            string    `json:"action"` // 词表见上
	FencingToken      int64     `json:"fencing_token"`
	LeaseSeconds      int       `json:"lease_seconds"`
	Result            string    `json:"result"` // OK|CONFLICT|REJECTED|UNKNOWN
	ReasonCode        string    `json:"reason_code"`
	OccurredAt        time.Time `json:"occurred_at"`
}
