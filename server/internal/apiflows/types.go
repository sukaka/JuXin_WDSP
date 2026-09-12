// types.go 流程基线实体与应用层校验（阶段8 §44 发布下发面）。
// 校验口径与网关 detectors.ValidateFlowBaselines 逐项对齐：管理面入库前拒绝的
// 非法配置，网关装配期永远不应再遇到（双保险，网关侧仍独立校验拒绝加载）。
package apiflows

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 权限点（种子见迁移 000155）。
const (
	PermFlowRead   = "api_flow.read"
	PermFlowManage = "api_flow.manage"
)

// 字段护栏（与迁移 000155/000158 列宽一致）。
const (
	maxFlowIDLen    = 128
	maxNameLen      = 255
	maxDescLen      = 1024
	maxStepIDLen    = 128
	maxStateLen     = 64
	maxStepsPerFlow = 64
	maxPredecessors = 16
	// maxRateWindowSeconds 短窗秒数上限 = 网关 FlowSessionTTL（10min）：
	// 有效窗口不得超会话生命（窗口长于会话即不可判定，属配置错误；
	// 与网关 detectors.checkFlowRateFields 同口径，库层 CHECK 恒约束）。
	maxRateWindowSeconds = 600
)

// ErrNotFound 流程基线不存在（404）。
var ErrNotFound = errors.New("flow baseline not found")

// ErrVersionConflict 乐观锁冲突（409；expected_version 与当前版本不一致）。
var ErrVersionConflict = errors.New("flow baseline version conflict")

// ErrDuplicateFlowID flow_id 已被占用（409；唯一索引兜底）。
var ErrDuplicateFlowID = errors.New("flow_id already exists")

// ErrUnknownEndpoint 步骤引用的 endpoint_id 不存在（400；外键违规映射）。
var ErrUnknownEndpoint = errors.New("endpoint_id does not exist")

// ValidationError 载荷校验错误（400；validateFlow 产物，与存储错误显式区分）。
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

func invalidf(format string, args ...any) error {
	return &ValidationError{msg: fmt.Sprintf(format, args...)}
}

// StepInput 步骤写入载荷（endpoint_id 引用 api_endpoints，发布时解析 endpoint_key）。
type StepInput struct {
	StepID       string   `json:"step_id"`
	EndpointID   string   `json:"endpoint_id"`
	Sequence     int      `json:"sequence"`
	Predecessors []string `json:"predecessors"`
	Terminal     bool     `json:"terminal"`
	StateFrom    string   `json:"state_from"`
	StateTo      string   `json:"state_to"`
	// MaxPerWindow 步骤级短窗调用上限（>0 启用 rapid_batch 步骤级判定；0 = 不判定）。
	MaxPerWindow int `json:"max_per_window"`
	// RateWindowSeconds 步骤级短窗秒数（>0 覆盖缺省 60s；上限 maxRateWindowSeconds）。
	RateWindowSeconds int `json:"rate_window_seconds"`
	// CancelsFlow 取消语义声明（post_cancel_operation 判定的唯一来源；无声明不判定）。
	CancelsFlow bool `json:"cancels_flow"`
}

// Step 步骤行（读模型，EndpointKey 经 api_endpoints 关联带出供管理面展示核对）。
type Step struct {
	ID                uuid.UUID `json:"id"`
	StepID            string    `json:"step_id"`
	EndpointID        uuid.UUID `json:"endpoint_id"`
	EndpointKey       string    `json:"endpoint_key"`
	Sequence          int       `json:"sequence"`
	Predecessors      []string  `json:"predecessors"`
	Terminal          bool      `json:"terminal"`
	StateFrom         string    `json:"state_from"`
	StateTo           string    `json:"state_to"`
	MaxPerWindow      int       `json:"max_per_window"`
	RateWindowSeconds int       `json:"rate_window_seconds"`
	CancelsFlow       bool      `json:"cancels_flow"`
}

// Flow 流程基线读模型（含步骤，按 sequence 稳定排序）。
type Flow struct {
	ID          uuid.UUID `json:"id"`
	FlowID      string    `json:"flow_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	Version     int       `json:"version"`
	// MaxPerWindow 流程级短窗调用上限（同主体对本流程任意步骤的合计调用；
	// >0 启用 rapid_batch 流程级判定；0 = 不判定）。
	MaxPerWindow int `json:"max_per_window"`
	// RateWindowSeconds 流程级短窗秒数（语义同步骤级）。
	RateWindowSeconds int       `json:"rate_window_seconds"`
	Steps             []Step    `json:"steps"`
	CreatedBy         string    `json:"created_by"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// Summary 列表行（不含步骤明细，带步骤数）。
type Summary struct {
	ID          uuid.UUID `json:"id"`
	FlowID      string    `json:"flow_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	Version     int       `json:"version"`
	StepCount   int       `json:"step_count"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// FlowInput 创建/整体替换写入载荷（Update 时 ExpectedVersion 必填做乐观锁）。
type FlowInput struct {
	FlowID            string
	Name              string
	Description       string
	Enabled           bool
	MaxPerWindow      int
	RateWindowSeconds int
	Steps             []StepInput
}

// validateFlow 入库前校验（与网关 detectors.ValidateFlowBaselines 同口径 +
// 管理面字段护栏；返回的 error 文案直接进 400 响应）。
func validateFlow(in *FlowInput) error {
	in.FlowID = strings.TrimSpace(in.FlowID)
	if in.FlowID == "" || len(in.FlowID) > maxFlowIDLen {
		return invalidf("flow_id 必填且不超过 %d 字符", maxFlowIDLen)
	}
	if len([]rune(in.Name)) > maxNameLen {
		return invalidf("name 不超过 %d 字符", maxNameLen)
	}
	if len([]rune(in.Description)) > maxDescLen {
		return invalidf("description 不超过 %d 字符", maxDescLen)
	}
	if len(in.Steps) == 0 {
		return invalidf("steps 至少 1 步")
	}
	if len(in.Steps) > maxStepsPerFlow {
		return invalidf("steps 超过单流程上限 %d", maxStepsPerFlow)
	}
	if err := checkRateFields(in.MaxPerWindow, in.RateWindowSeconds); err != nil {
		return invalidf("流程级 %v", err)
	}
	ids := make(map[string]bool, len(in.Steps))
	for i := range in.Steps {
		s := &in.Steps[i]
		s.StepID = strings.TrimSpace(s.StepID)
		s.StateFrom = strings.TrimSpace(s.StateFrom)
		s.StateTo = strings.TrimSpace(s.StateTo)
		if s.StepID == "" || len(s.StepID) > maxStepIDLen {
			return invalidf("steps[%d] step_id 必填且不超过 %d 字符", i, maxStepIDLen)
		}
		if strings.TrimSpace(s.EndpointID) == "" {
			return invalidf("steps[%d]（%s）endpoint_id 必填", i, s.StepID)
		}
		if _, err := uuid.Parse(strings.TrimSpace(s.EndpointID)); err != nil {
			return invalidf("steps[%d]（%s）endpoint_id 非法", i, s.StepID)
		}
		if ids[s.StepID] {
			return invalidf("steps[%d] step_id 重复: %s", i, s.StepID)
		}
		ids[s.StepID] = true
		if len(s.Predecessors) > maxPredecessors {
			return invalidf("steps[%d]（%s）前置步骤超过上限 %d", i, s.StepID, maxPredecessors)
		}
		if len(s.StateFrom) > maxStateLen || len(s.StateTo) > maxStateLen {
			return invalidf("steps[%d]（%s）state_from/state_to 不超过 %d 字符", i, s.StepID, maxStateLen)
		}
		if err := checkRateFields(s.MaxPerWindow, s.RateWindowSeconds); err != nil {
			return invalidf("steps[%d]（%s）%v", i, s.StepID, err)
		}
	}
	for i := range in.Steps {
		s := in.Steps[i]
		for _, p := range s.Predecessors {
			if p == s.StepID {
				return invalidf("step %s 前置步骤自引用", s.StepID)
			}
			if !ids[p] {
				return invalidf("step %s 前置步骤未声明: %s", s.StepID, p)
			}
		}
	}
	return nil
}

// checkRateFields 批量执行字段校验（与网关 detectors.checkFlowRateFields 同口径 +
// 库层 CHECK 上限）：上限/窗口不得为负；短窗秒数不得超 maxRateWindowSeconds
// （= 网关 FlowSessionTTL，窗口长于会话生命即不可判定；库层恒约束，管理面与库一致）。
func checkRateFields(maxPerWindow, windowSeconds int) error {
	if maxPerWindow < 0 {
		return fmt.Errorf("max_per_window 不得为负: %d", maxPerWindow)
	}
	if windowSeconds < 0 {
		return fmt.Errorf("rate_window_seconds 不得为负: %d", windowSeconds)
	}
	if windowSeconds > maxRateWindowSeconds {
		return fmt.Errorf("rate_window_seconds 超过会话 TTL 上限 %ds", maxRateWindowSeconds)
	}
	return nil
}
