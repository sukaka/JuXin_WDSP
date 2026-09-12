// flow.go 业务流程偏离运行时检测（阶段8 任务书 §44 七类）：
// 发布通道下发流程基线（端点 → 步骤序列/前置约束），网关在会话窗口内重建主体
// 的步骤轨迹，产出七类 OBSERVE 级信号：
//
//	flow.step_skip                跳过前置步骤（会话窗口内未见声明前置步骤即到达本步骤）
//	flow.duplicate_submit         重复提交（同会话同步骤同幂等键/对象短窗重复 POST）
//	flow.out_of_order             逆序调用（步骤序号相对窗口内已观测最大序号倒退）
//	flow.illegal_state_transition 未授权状态转换（对象状态机非法迁移）
//	flow.rapid_batch              短时间批量执行（步骤级 max_per_window 或流程级
//	                              max_per_window 短窗调用频率超基线阈值）
//	flow.post_cancel_operation    取消后继续操作（取消语义步骤之后仍有后续步骤执行）
//	flow.anonymous_late_entry     未登录直接调用后置 API（匿名主体直接命中非首步步骤）
//
// 取消语义口径（post_cancel_operation）：仅承认基线显式声明——步骤级
// cancels_flow=true。不内置取消词表、不从 state_to/端点路径猜测取消语义
// （网关无法解释业务状态名，编造词表必然误判）；无任何声明 = 不判定。
// 判定为粘性口径：会话窗口内一旦观测到取消步骤，其后本流程任意步骤（含再次
// 取消自身之外的步骤）均判「取消后继续操作」，直至会话空闲 TTL 重置——合法的
// 「取消后重开流程」在窗口内也会命中，OBSERVE 级提示可接受，宁可多报不误放。
//
// 匿名口径（anonymous_late_entry）与 flow.step_skip 去重策略：identity 为
// TrackingKey 口径，凭据指纹前缀 auth:/key:/sess: 之外（ip: 回退、unknown）
// 视为匿名。「后置步骤」= 流程内存在更小序号的步骤（首步=最小序号）。匿名直达
// 后置步骤是比「跳过前置」更强的信号且语义涵盖后者：同一请求同一步骤两者同时
// 成立时只产出 anonymous_late_entry，抑制 step_skip，避免语义重复明细；已登录
// 主体的 step_skip 判定不受影响。
//
// 批量执行口径（rapid_batch）：步骤未声明 max_per_window 且流程未声明
// max_per_window = 不判定（向后兼容，旧基线零行为）；短窗取声明的
// rate_window_seconds（>0），缺省 FlowRateWindow；有效窗口不得超会话 TTL，
// 校验期拒绝（窗口长于会话生命即不可判定，属配置错误如实报错）。
//
// 任务书口径：第一版作为观察和高风险提示，不默认阻断复杂业务流程——全部明细
// Category=OBSERVE，只 AddMatch 不定案，任何模式下不阻断；fail-open（存储实现
// 自行降级，见 store.go 契约；身份/端点/基线缺失直接跳过）。
//
// 基线来源纪律：仅消费发布通道下发的 FlowBaseline（pipeline.Config.FlowBaselines，
// 装配层按端点解析后传入）；nil/空 = 无端点流程基线，检测零行为，不编造基线。
//
// 状态来源与降级说明（未授权状态转换）：网关无业务库可查询对象当前状态，状态来源
// 限于请求内可观测信号——本实现对「对象当前状态」的重建口径为：同一主体在同一会话
// 窗口内、同一对象（§7 object_identifiers 值哈希）上先前已观测步骤声明的 state_to。
// 因此如实降级三种情形（均不判定、仅注释说明，不出 Finding）：
//  1. 步骤未声明 state_from/state_to（基线未建状态机）→ 该步骤不参与状态判定；
//  2. 请求未携带可识别对象标识 → 无法归属对象，跳过状态判定；
//  3. 会话窗口内该对象无先前观测状态（如流程从中段开始进入网关视野）→ 无法建立
//     「迁移前状态」，跳过不判——宁可漏判不误判。
//
// 计数有界：会话追踪器 LRU 定容（flowSessionMaxKeys）；单会话内步骤集合、对象状态槽、
// 幂等键槽分别定容（flowMaxSeenSteps/flowMaxObjects/flowMaxSubmitKeys），槽满拒绝新
// 成员不淘汰已记账状态（保守：超限后新维度不判定）；会话空闲超 flowSessionTTL 重置。
// 存储可插拔：StoreOverrides.FlowSession 注入（装配层 Valkey 实现消除多节点盲区），
// 默认进程内存实现与 windowTracker 同一单节点限制。
package detectors

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

const (
	// flowSessionMaxKeys 会话追踪器 LRU 容量上限（与既有检测器同一纪律）。
	flowSessionMaxKeys = 10000
	// FlowSessionTTL 会话空闲窗口：超时未活动即视为新会话（跨流程实例隔离）。
	FlowSessionTTL = 10 * time.Minute
	// FlowDuplicateWindow 重复提交判定短窗（同幂等键两次 POST 间隔在窗口内计为重复）。
	FlowDuplicateWindow = time.Minute
	// flowMaxSeenSteps 单会话已见步骤集合上限（超出后新步骤不参与前置判定，
	// 会话状态保守不淘汰——已记账前置关系优于新步骤可见性）。
	flowMaxSeenSteps = 64
	// flowMaxObjects 单会话对象状态槽上限（超出后新对象不参与状态机判定）。
	flowMaxObjects = 32
	// flowMaxSubmitKeys 单会话幂等键槽上限（超出后新键不参与重复提交判定）。
	flowMaxSubmitKeys = 32
	// FlowRateWindow 批量执行判定缺省短窗（步骤/流程声明 max_per_window 但未
	// 声明 rate_window_seconds 时使用）。
	FlowRateWindow = time.Minute
	// flowMaxStepEvents 单会话单步骤（及流程级）短窗时间戳环容量上限（超出
	// 淘汰最旧——批量执行为短窗信号，可重建）。
	flowMaxStepEvents = 128
)

// FlowStep 流程步骤（发布通道下发；server 侧 api_flow_baselines 镜像）。
type FlowStep struct {
	StepID       string   `json:"step_id"`              // 步骤标识（同一流程内唯一）
	EndpointKey  string   `json:"endpoint_key"`         // 绑定端点（METHOD + 空格 + 路径模板，同 normalizer.EndpointKey 口径）
	Sequence     int      `json:"sequence"`             // 流程内单调序号（逆序判定基准）
	Predecessors []string `json:"predecessors"`         // 期望前置步骤 StepID 列表（AND 语义：全部需在会话窗口内出现过；空 = 无前置约束）
	Terminal     bool     `json:"terminal"`             // 是否流程终点（描述性字段，供事件展示；判定不依赖）
	StateFrom    string   `json:"state_from,omitempty"` // 步骤要求的对象前置状态（空 = 不参与状态机判定）
	StateTo      string   `json:"state_to,omitempty"`   // 步骤完成后的对象状态（空 = 本步骤不推进状态记录）
	// MaxPerWindow 步骤级短窗调用上限（>0 启用 rapid_batch 步骤级判定；
	// 缺省 0 = 不判定，向后兼容）。
	MaxPerWindow int `json:"max_per_window,omitempty"`
	// RateWindowSeconds 步骤级短窗秒数（>0 覆盖缺省 FlowRateWindow；
	// 有效窗口不得超 FlowSessionTTL，校验期拒绝）。
	RateWindowSeconds int `json:"rate_window_seconds,omitempty"`
	// CancelsFlow 取消语义声明（true = 本步骤执行后流程视为已取消；
	// 取消后继续操作判定的唯一来源，不编造词表）。
	CancelsFlow bool `json:"cancels_flow,omitempty"`
}

// FlowBaseline 业务流程基线（发布通道下发）。
type FlowBaseline struct {
	FlowID string     `json:"flow_id"` // 流程标识（会话键组成部分）
	Steps  []FlowStep `json:"steps"`
	// MaxPerWindow 流程级短窗调用上限（同主体对本流程任意步骤的合计调用；
	// >0 启用 rapid_batch 流程级判定；缺省 0 = 不判定，向后兼容）。
	MaxPerWindow int `json:"max_per_window,omitempty"`
	// RateWindowSeconds 流程级短窗秒数（语义同步骤级）。
	RateWindowSeconds int `json:"rate_window_seconds,omitempty"`
}

// flowRateWindow 有效短窗：声明秒数 >0 用之，否则缺省 FlowRateWindow。
func flowRateWindow(seconds int) time.Duration {
	if seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return FlowRateWindow
}

// FlowConfigError 流程基线配置错误（装配层校验失败如实报错，拒绝加载，不静默吞错）。
type FlowConfigError struct {
	Index  int    // 基线在切片中的下标
	Reason string // 失败原因
}

func (e *FlowConfigError) Error() string {
	return fmt.Sprintf("flow baseline[%d]: %s", e.Index, e.Reason)
}

// ValidateFlowBaselines 配置校验（装配层调用）：流程标识/步骤引用非法如实报错。
// 校验项：flow_id 非空；步骤 step_id/endpoint_key 非空且流程内 step_id 唯一；
// 前置步骤引用须指向同流程已声明步骤且不得自引用（跨流程引用无意义）。
func ValidateFlowBaselines(baselines []FlowBaseline) error {
	for i := range baselines {
		b := baselines[i]
		if strings.TrimSpace(b.FlowID) == "" {
			return &FlowConfigError{Index: i, Reason: "flow_id 为空"}
		}
		if err := checkFlowRateFields(b.MaxPerWindow, b.RateWindowSeconds); err != nil {
			return &FlowConfigError{Index: i, Reason: "flow: " + err.Error()}
		}
		ids := make(map[string]bool, len(b.Steps))
		for _, s := range b.Steps {
			if strings.TrimSpace(s.StepID) == "" {
				return &FlowConfigError{Index: i, Reason: "step_id 为空"}
			}
			if strings.TrimSpace(s.EndpointKey) == "" {
				return &FlowConfigError{Index: i, Reason: "step " + s.StepID + " endpoint_key 为空"}
			}
			if ids[s.StepID] {
				return &FlowConfigError{Index: i, Reason: "step_id 重复: " + s.StepID}
			}
			if err := checkFlowRateFields(s.MaxPerWindow, s.RateWindowSeconds); err != nil {
				return &FlowConfigError{Index: i, Reason: "step " + s.StepID + ": " + err.Error()}
			}
			ids[s.StepID] = true
		}
		for _, s := range b.Steps {
			for _, p := range s.Predecessors {
				if p == s.StepID {
					return &FlowConfigError{Index: i, Reason: "step " + s.StepID + " 前置步骤自引用"}
				}
				if !ids[p] {
					return &FlowConfigError{Index: i, Reason: "step " + s.StepID + " 前置步骤未声明: " + p}
				}
			}
		}
	}
	return nil
}

// checkFlowRateFields 批量执行字段校验：上限/窗口不得为负；启用判定（max>0）
// 时有效窗口不得超会话 TTL（窗口长于会话生命即不可判定，属配置错误）。
func checkFlowRateFields(maxPerWindow, windowSeconds int) error {
	if maxPerWindow < 0 {
		return fmt.Errorf("max_per_window 为负: %d", maxPerWindow)
	}
	if windowSeconds < 0 {
		return fmt.Errorf("rate_window_seconds 为负: %d", windowSeconds)
	}
	if maxPerWindow > 0 && flowRateWindow(windowSeconds) > FlowSessionTTL {
		return fmt.Errorf("rate_window_seconds 有效窗口超过会话 TTL (%ds)", int(FlowSessionTTL/time.Second))
	}
	return nil
}

// GroupFlowBaselines 按步骤 endpoint_key 归组（装配层一次归组，运行期按命中端点
// O(1) 选取；同一流程跨多个端点各挂一份引用，与 GroupParamRelations 同一模式）。
func GroupFlowBaselines(baselines []FlowBaseline) map[string][]FlowBaseline {
	if len(baselines) == 0 {
		return nil
	}
	out := make(map[string][]FlowBaseline)
	for _, b := range baselines {
		seen := make(map[string]bool, len(b.Steps))
		for _, s := range b.Steps {
			if s.EndpointKey == "" || seen[s.EndpointKey] {
				continue
			}
			seen[s.EndpointKey] = true
			out[s.EndpointKey] = append(out[s.EndpointKey], b)
		}
	}
	return out
}

// FlowObservation 单次流程步骤观测（写入侧；均不含明文——幂等键已加盐哈希，
// 对象为 §7 object_identifiers 值哈希）。
type FlowObservation struct {
	StepID    string // 命中步骤标识
	Sequence  int    // 步骤序号
	SubmitKey string // 重复提交判定键（step 维度外的幂等键/对象哈希部分；空 = 本请求不参与重复提交判定）
	ObjectKey string // 对象状态归属键（空 = 无对象，不参与状态机判定）
	StateTo   string // 本步骤声明的后置状态（空 = 不推进状态记录）
	// StepRateWindow 步骤级批量判定短窗（0 = 本步骤未声明 max_per_window，
	// 不参与步骤级计数判定；快照 StepWindowCount 恒为 0）。
	StepRateWindow time.Duration
	// FlowRateWindow 流程级批量判定短窗（语义同上，快照 FlowWindowCount）。
	FlowRateWindow time.Duration
	// CancelsFlow 本步骤声明取消语义（true = 观测后本会话流程标记已取消）。
	CancelsFlow bool
}

// FlowSessionSnapshot 会话窗口内流程状态快照（Observe 记录本次观测后返回；
// Before 字段为「本次观测之前」的窗口状态，SeenSteps/DuplicateCount 含本次）。
type FlowSessionSnapshot struct {
	SeenSteps         map[string]bool // 窗口内已观测步骤集合（含本次）
	HasMaxSequence    bool            // 本次观测前窗口内是否已有序号记录
	MaxSequenceBefore int             // 本次观测前窗口内最大步骤序号
	ObjectStateBefore string          // 本次观测前该对象已观测状态（空 = 无记录）
	DuplicateCount    int             // 同步骤同幂等键短窗内累计提交数（含本次；无 SubmitKey 为 0）
	// StepWindowCount 本步骤在 StepRateWindow 短窗内累计调用数（含本次；
	// 观测未声明 StepRateWindow 或步骤时间戳槽满时恒为 0 = 不判定）。
	StepWindowCount int
	// FlowWindowCount 本流程在 FlowRateWindow 短窗内累计调用数（含本次；
	// 观测未声明 FlowRateWindow 时恒为 0）。
	FlowWindowCount int
	// CancelledBefore 本次观测前会话窗口内是否已观测到取消语义步骤。
	CancelledBefore bool
	// CancelledBy 最近一次取消语义步骤标识（CancelledBefore=false 时为空）。
	CancelledBy string
}

// flowSubmitState 单幂等键短窗状态。
type flowSubmitState struct {
	last  time.Time
	count int
}

// flowSessionEntry 单会话状态（步骤集合/对象状态/幂等键分别定容）。
type flowSessionEntry struct {
	lastActive time.Time
	maxSeq     int
	hasSeq     bool
	seen       map[string]struct{}
	objState   map[string]string
	objOrder   []string // 插入序（槽满按最旧淘汰对象状态——状态机维度可重建）
	submits    map[string]flowSubmitState
	subOrder   []string // 插入序（槽满按最旧淘汰）
	// stepEvents 步骤级短窗时间戳环（仅声明了步骤级批量判定的步骤建槽，
	// 键数沿用 flowMaxSeenSteps 上限；环长定容 flowMaxStepEvents）
	stepEvents map[string][]time.Time
	// flowEvents 流程级短窗时间戳环（恒记账，环长定容 flowMaxStepEvents）
	flowEvents []time.Time
	// cancelledBy 窗口内最近一次取消语义步骤（空 = 未取消；粘性至会话重置）
	cancelledBy string
}

func newFlowSessionEntry() *flowSessionEntry {
	return &flowSessionEntry{
		seen:       make(map[string]struct{}),
		objState:   make(map[string]string),
		submits:    make(map[string]flowSubmitState),
		stepEvents: make(map[string][]time.Time),
	}
}

func (e *flowSessionEntry) reset() {
	e.maxSeq = 0
	e.hasSeq = false
	e.seen = make(map[string]struct{})
	e.objState = make(map[string]string)
	e.objOrder = nil
	e.submits = make(map[string]flowSubmitState)
	e.subOrder = nil
	e.stepEvents = make(map[string][]time.Time)
	e.flowEvents = nil
	e.cancelledBy = ""
}

// flowRingPrune 剔除窗口外时间戳（同一时钟单调追加，前缀淘汰）。
func flowRingPrune(ring []time.Time, now time.Time, window time.Duration) []time.Time {
	cut := 0
	for cut < len(ring) && now.Sub(ring[cut]) > window {
		cut++
	}
	return ring[cut:]
}

// flowRingAppend 追加时间戳，环满淘汰最旧（批量执行为短窗信号，可重建）。
func flowRingAppend(ring []time.Time, now time.Time) []time.Time {
	if len(ring) >= flowMaxStepEvents {
		ring = ring[1:]
	}
	return append(ring, now)
}

// flowSessionTracker 进程内流程会话追踪器（LRU 定容；now 可注入供测试与
// 装配层时钟对齐，nil 用系统时钟）。
type flowSessionTracker struct {
	mu      sync.Mutex
	entries *lru
	now     func() time.Time
}

func newFlowSessionTracker(capacity int, now func() time.Time) *flowSessionTracker {
	if now == nil {
		now = time.Now
	}
	return &flowSessionTracker{entries: newLRU(capacity), now: now}
}

// Observe 记录一次步骤观测并返回快照（FlowSessionStore 语义实现；失败策略由
// 调用侧 store.go 契约约束，本实现无外部依赖不会失败）。
func (t *flowSessionTracker) Observe(key string, o FlowObservation) FlowSessionSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now().UTC()
	var e *flowSessionEntry
	if v, ok := t.entries.get(key); ok {
		e = v.(*flowSessionEntry)
	} else {
		e = newFlowSessionEntry()
		t.entries.set(key, e)
	}
	// 会话空闲超时重置：跨流程实例隔离（旧轨迹不污染新会话的前置/逆序判定）
	if !e.lastActive.IsZero() && now.Sub(e.lastActive) > FlowSessionTTL {
		e.reset()
	}
	e.lastActive = now

	snap := FlowSessionSnapshot{
		HasMaxSequence:    e.hasSeq,
		MaxSequenceBefore: e.maxSeq,
		CancelledBefore:   e.cancelledBy != "",
		CancelledBy:       e.cancelledBy,
	}
	if o.ObjectKey != "" {
		snap.ObjectStateBefore = e.objState[o.ObjectKey]
	}
	// 步骤级短窗批量计数（观测声明窗口才判定；未建槽且键槽满 = 新步骤不判定，保守）
	if o.StepRateWindow > 0 {
		if ring, ok := e.stepEvents[o.StepID]; ok {
			ring = flowRingPrune(ring, now, o.StepRateWindow)
			e.stepEvents[o.StepID] = ring
			snap.StepWindowCount = len(ring) + 1
		} else if len(e.stepEvents) < flowMaxSeenSteps {
			e.stepEvents[o.StepID] = nil
			snap.StepWindowCount = 1
		}
	}
	// 流程级短窗批量计数（观测声明窗口才判定；环恒记账）
	if o.FlowRateWindow > 0 {
		e.flowEvents = flowRingPrune(e.flowEvents, now, o.FlowRateWindow)
		snap.FlowWindowCount = len(e.flowEvents) + 1
	}
	e.flowEvents = flowRingAppend(e.flowEvents, now)
	if ring, ok := e.stepEvents[o.StepID]; ok {
		e.stepEvents[o.StepID] = flowRingAppend(ring, now)
	}
	// 重复提交短窗计数（窗口内连续累计；出窗即重置为 1）
	if o.SubmitKey != "" {
		st, ok := e.submits[o.SubmitKey]
		if !ok {
			if len(e.submits) >= flowMaxSubmitKeys {
				// 槽满淘汰最旧插入的键（重复提交为短窗信号，可重建）
				if len(e.subOrder) > 0 {
					delete(e.submits, e.subOrder[0])
					e.subOrder = e.subOrder[1:]
				}
			}
			e.subOrder = append(e.subOrder, o.SubmitKey)
			st = flowSubmitState{}
		}
		if ok && now.Sub(st.last) <= FlowDuplicateWindow {
			st.count++
		} else {
			st.count = 1
		}
		st.last = now
		e.submits[o.SubmitKey] = st
		snap.DuplicateCount = st.count
	}

	// 快照 seen 集合（含本次；步骤集合槽满时新步骤不入集——前置判定保守）
	if len(e.seen) < flowMaxSeenSteps {
		e.seen[o.StepID] = struct{}{}
	}
	snap.SeenSteps = make(map[string]bool, len(e.seen))
	for id := range e.seen {
		snap.SeenSteps[id] = true
	}
	if !e.hasSeq || o.Sequence > e.maxSeq {
		e.maxSeq = o.Sequence
	}
	e.hasSeq = true
	// 对象状态推进（仅本步骤声明了 state_to 时记账）
	if o.ObjectKey != "" && o.StateTo != "" {
		if _, ok := e.objState[o.ObjectKey]; !ok {
			if len(e.objState) >= flowMaxObjects && len(e.objOrder) > 0 {
				delete(e.objState, e.objOrder[0])
				e.objOrder = e.objOrder[1:]
			}
			e.objOrder = append(e.objOrder, o.ObjectKey)
		}
		e.objState[o.ObjectKey] = o.StateTo
	}
	// 取消语义记账（快照 CancelledBefore 为记录前状态——取消步骤自身不判
	// 「取消后继续操作」；重复取消以后到者为准，证据展示最近一次取消步骤）
	if o.CancelsFlow {
		e.cancelledBy = o.StepID
	}
	return snap
}

// defaultFlowSessionTracker 包级默认会话追踪器（单节点限制同 windowTracker；
// 配置重载不重置，进程重启清零）。
var defaultFlowSessionTracker = newFlowSessionTracker(flowSessionMaxKeys, nil)

// idempotencyKeyHeaders 幂等键请求头词表（按优先级序；值为客户端生成标识，
// 一律加盐哈希后使用，明文不出本函数作用域、永不入证据）。
var idempotencyKeyHeaders = []string{"Idempotency-Key", "X-Idempotency-Key"}

// CheckFlowDeviation 业务流程偏离检测（§44 七类，OBSERVE 级只 AddMatch）：
// baselines 为本请求命中端点适用的流程基线（装配层按端点解析；空 = 零行为）。
// identity 为会话主体键（pipeline 传 TrackingKey 口径：凭据指纹优先、回退来源 IP，
// 空 = 跳过）；endpointKey 为管线统一口径端点键（gRPC 为 Preserve 口径）。
// 证据只含流程/步骤标识、序号、计数与状态名（基线声明的配置字符串），
// 绝不含幂等键/对象明文。
func CheckFlowDeviation(ctx *dsctx.RequestContext, r *http.Request, identity, endpointKey, salt string, baselines []FlowBaseline) {
	if ctx == nil || identity == "" || endpointKey == "" || len(baselines) == 0 {
		return
	}
	anonymous := flowIdentityAnonymous(identity)
	for i := range baselines {
		b := baselines[i]
		step, ok := matchFlowStep(b, endpointKey)
		if !ok {
			continue
		}
		obs := FlowObservation{StepID: step.StepID, Sequence: step.Sequence, StateTo: step.StateTo, CancelsFlow: step.CancelsFlow}
		if step.MaxPerWindow > 0 {
			obs.StepRateWindow = flowRateWindow(step.RateWindowSeconds)
		}
		if b.MaxPerWindow > 0 {
			obs.FlowRateWindow = flowRateWindow(b.RateWindowSeconds)
		}
		// 对象归属键：§7 统一提取产物的值哈希（pipeline 在检测段前已落 ctx）；
		// 无对象标识时状态机判定按降级说明跳过
		if ids := ctx.CopyObjectIdentifiers(); len(ids) > 0 {
			obs.ObjectKey = ids[0].Source + ":" + ids[0].Param + "|" + ids[0].ValueHash
		}
		// 重复提交判定键：仅 POST（任务书口径「重复 POST」）；幂等键头优先，
		// 缺省回退对象哈希（无幂等键语义的重复提交近似）；两者皆无不参与判定。
		// 键以步骤标识命名空间隔离——不同步骤操作同一对象不算重复提交
		keySource := ""
		if r != nil && r.Method == http.MethodPost {
			for _, h := range idempotencyKeyHeaders {
				if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
					obs.SubmitKey = step.StepID + "|idem:" + Fingerprint(salt, v)
					keySource = "header"
					break
				}
			}
			if obs.SubmitKey == "" && obs.ObjectKey != "" {
				obs.SubmitKey = step.StepID + "|obj:" + obs.ObjectKey
				keySource = "object"
			}
		}

		snap := flowSessionObserve(ctx, identity+"|"+b.FlowID, obs)

		// 前置缺失集合（rule 1 与 rule 7 去重判定共用）
		var missing []string
		for _, p := range step.Predecessors {
			if !snap.SeenSteps[p] {
				missing = append(missing, p)
			}
		}

		// 7) 未登录直接调用后置 API：匿名主体（identity 无凭据指纹前缀，见
		// flowIdentityAnonymous）直接命中非首步步骤。与 flow.step_skip 去重：
		// 两者同时成立时匿名信号更强且语义涵盖「未按流程进入」，只产出本规则、
		// 抑制 step_skip（文件头注释口径）；已登录主体的 step_skip 不受影响。
		anonLate := anonymous && step.Sequence > flowMinSequence(b)
		if anonLate {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "api_flow",
				RuleID:   "flow.anonymous_late_entry",
				Category: "OBSERVE",
				Severity: "HIGH",
				Message:  "anonymous principal reached non-first flow step",
				Evidence: map[string]string{
					"flow_id":      b.FlowID,
					"step_id":      step.StepID,
					"sequence":     strconv.Itoa(step.Sequence),
					"min_sequence": strconv.Itoa(flowMinSequence(b)),
				},
				ScoreDelta: 30,
			})
		}
		// 1) 跳过前置步骤：声明前置（AND 语义）在会话窗口内未全部出现
		if len(missing) > 0 && !anonLate {
			sort.Strings(missing)
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "api_flow",
				RuleID:   "flow.step_skip",
				Category: "OBSERVE",
				Severity: "HIGH",
				Message:  "flow step reached without observed predecessors",
				Evidence: map[string]string{
					"flow_id":     b.FlowID,
					"step_id":     step.StepID,
					"missing":     strings.Join(missing, ","),
					"seen_window": strconv.Itoa(int(FlowSessionTTL/time.Minute)) + "m",
				},
				ScoreDelta: 25,
			})
		}
		// 2) 逆序调用：本次序号小于窗口内已观测最大序号（相等为重复访问，不判）
		if snap.HasMaxSequence && step.Sequence < snap.MaxSequenceBefore {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "api_flow",
				RuleID:   "flow.out_of_order",
				Category: "OBSERVE",
				Severity: "MEDIUM",
				Message:  "flow step sequence regression",
				Evidence: map[string]string{
					"flow_id":             b.FlowID,
					"step_id":             step.StepID,
					"sequence":            strconv.Itoa(step.Sequence),
					"max_sequence_before": strconv.Itoa(snap.MaxSequenceBefore),
				},
				ScoreDelta: 15,
			})
		}
		// 3) 重复提交：同会话同步骤同幂等键短窗内第 2 次起（含）判重
		if snap.DuplicateCount >= 2 {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "api_flow",
				RuleID:   "flow.duplicate_submit",
				Category: "OBSERVE",
				Severity: "MEDIUM",
				Message:  "duplicate submit within short window",
				Evidence: map[string]string{
					"flow_id":    b.FlowID,
					"step_id":    step.StepID,
					"count":      strconv.Itoa(snap.DuplicateCount),
					"window":     strconv.Itoa(int(FlowDuplicateWindow/time.Second)) + "s",
					"key_source": keySource,
				},
				ScoreDelta: 15,
			})
		}
		// 4) 未授权状态转换：步骤声明 state_from 且对象有先前观测状态、且不一致 → 非法迁移。
		// 先前无观测状态（ObjectStateBefore 空）不判——无法从请求内信号建立迁移前状态，
		// 宁可漏判不误判（降级说明见文件头注释）。
		if step.StateFrom != "" && obs.ObjectKey != "" && snap.ObjectStateBefore != "" && snap.ObjectStateBefore != step.StateFrom {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "api_flow",
				RuleID:   "flow.illegal_state_transition",
				Category: "OBSERVE",
				Severity: "HIGH",
				Message:  "object state transition violates declared flow",
				Evidence: map[string]string{
					"flow_id":        b.FlowID,
					"step_id":        step.StepID,
					"expected_state": step.StateFrom,
					"observed_state": snap.ObjectStateBefore,
				},
				ScoreDelta: 25,
			})
		}
		// 5) 短时间批量执行：步骤级/流程级短窗计数超声明上限（未声明上限
		// max_per_window 时不判定——向后兼容，计数快照恒 0；步骤级与流程级
		// 为两个独立阈值，同一请求可同时成立，证据 scope 区分语义不重复）
		if step.MaxPerWindow > 0 && snap.StepWindowCount > step.MaxPerWindow {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "api_flow",
				RuleID:   "flow.rapid_batch",
				Category: "OBSERVE",
				Severity: "MEDIUM",
				Message:  "flow step call rate exceeds baseline within short window",
				Evidence: map[string]string{
					"flow_id": b.FlowID,
					"step_id": step.StepID,
					"scope":   "step",
					"count":   strconv.Itoa(snap.StepWindowCount),
					"limit":   strconv.Itoa(step.MaxPerWindow),
					"window":  strconv.Itoa(int(obs.StepRateWindow/time.Second)) + "s",
				},
				ScoreDelta: 15,
			})
		}
		if b.MaxPerWindow > 0 && snap.FlowWindowCount > b.MaxPerWindow {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "api_flow",
				RuleID:   "flow.rapid_batch",
				Category: "OBSERVE",
				Severity: "MEDIUM",
				Message:  "flow call rate exceeds baseline within short window",
				Evidence: map[string]string{
					"flow_id": b.FlowID,
					"step_id": step.StepID,
					"scope":   "flow",
					"count":   strconv.Itoa(snap.FlowWindowCount),
					"limit":   strconv.Itoa(b.MaxPerWindow),
					"window":  strconv.Itoa(int(obs.FlowRateWindow/time.Second)) + "s",
				},
				ScoreDelta: 15,
			})
		}
		// 6) 取消后继续操作：会话窗口内已观测取消语义步骤（基线 cancels_flow
		// 显式声明，无声明不判定），其后本流程任意步骤均判；取消步骤自身
		// 不判（CancelledBefore 为记录前状态）。
		if snap.CancelledBefore {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "api_flow",
				RuleID:   "flow.post_cancel_operation",
				Category: "OBSERVE",
				Severity: "HIGH",
				Message:  "flow step executed after cancellation",
				Evidence: map[string]string{
					"flow_id":      b.FlowID,
					"step_id":      step.StepID,
					"cancelled_by": snap.CancelledBy,
					"seen_window":  strconv.Itoa(int(FlowSessionTTL/time.Minute)) + "m",
				},
				ScoreDelta: 25,
			})
		}
	}
}

// flowIdentityAnonymous 匿名主体判定：identity 为 TrackingKey 口径
// （authentication.go），凭据指纹前缀 auth:/key:/sess: 之外——ip: 回退与
// unknown——均无凭据指纹，视为匿名。
func flowIdentityAnonymous(identity string) bool {
	return !strings.HasPrefix(identity, "auth:") &&
		!strings.HasPrefix(identity, "key:") &&
		!strings.HasPrefix(identity, "sess:")
}

// flowMinSequence 流程内最小步骤序号（首步基准；空流程返回 0——此时
// matchFlowStep 不会命中，本函数不会被用于判定）。
func flowMinSequence(b FlowBaseline) int {
	min := 0
	for i, s := range b.Steps {
		if i == 0 || s.Sequence < min {
			min = s.Sequence
		}
	}
	return min
}

// matchFlowStep 在流程基线内按端点键定位步骤（同端点多步骤取首个——
// 配置面上同流程同端点多步骤语义不明，校验不禁止但运行期只取首个，保守）。
func matchFlowStep(b FlowBaseline, endpointKey string) (FlowStep, bool) {
	for _, s := range b.Steps {
		if s.EndpointKey == endpointKey {
			return s, true
		}
	}
	return FlowStep{}, false
}
