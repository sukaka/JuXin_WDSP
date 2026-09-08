// 请求最终处置上下文（WDSP P0-04 工作流 C；契约冻结
// docs/tasks/wdsp-p0/S4_DESIGN_BASELINE.md §2/§7/§10，任务书
// docs/tasks/wdsp-p0/P0-04_DECISION_SCOPED_EXCEPTIONS.md）：
// 每个进入 guard 的请求在 ServeHTTP 入口创建 Disposition 并挂入请求上下文，
// 各终止分支/观测点/例外命中实时记录事实，请求结束（ServeHTTP defer Finalize）
// 补全 completion_status/findings 计数/终止后 SKIPPED 步骤，最终序列化为
// final_decision JSON（schema_version=1）随事件落库（guard 事件 →
// access_control_events.details.final_decision；API 事件 →
// api_runtime_events.final_decision；WAF 事件经 eventparser 落
// security_events.final_decision）。
//
// 纪律（契约 §2）：
//   - 只记录已执行事实：观察命中不进 security_action；上游断连/超时/流中断
//     不硬映射 BLOCK；终止分支之后的模块标 SKIPPED，白名单/L7 allow 只记录
//     实际绕过的步骤（SKIPPED + detail）。
//   - 先到先得 + 终止动作优先：终止记录仅首次生效；Finalize 幂等。
//   - 容量上限：steps ≤ 32、rule_refs ≤ 64；截断时 steps 追加
//     {"module":"TRUNCATED","result":"SKIPPED","detail":"dropped=N"}；
//     最终动作与关键规则引用不可被截断丢弃。
//   - 不落原始 Token/明文声明；identity_verification 仅引用 P0-03 状态与指纹。
package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// dispositionSchemaVersion final_decision JSON 结构版本（契约 §2 冻结 schema_version=1）。
const dispositionSchemaVersion = 1

// completion_status 枚举（契约 §2）。
const (
	CompletionCompleted          = "COMPLETED"
	CompletionAborted            = "ABORTED"
	CompletionError              = "ERROR"
	CompletionPendingCorrelation = "PENDING_CORRELATION"
	CompletionUnknown            = "UNKNOWN"
)

// security_action 枚举（契约 §2；观察命中不进入——仅实断/实改写动作）。
const (
	DisActionNone         = "NONE"
	DisActionBlock        = "BLOCK"
	DisActionTempBlock    = "TEMP_BLOCK"
	DisActionRateLimit    = "RATE_LIMIT"
	DisActionMaskResponse = "MASK_RESPONSE"
)

// executor_module 枚举（契约 §2 冻结 13 值）。白名单不产生终止动作（命中即放行），
// 不在 executor 词表；其步骤模块词见 StepModuleIPAllowlist。
const (
	ExecutorProtectedAddress = "PROTECTED_ADDRESS"
	ExecutorManualBan        = "MANUAL_BAN"
	ExecutorIPBlacklist      = "IP_BLACKLIST"
	ExecutorL7ACL            = "L7_ACL"
	ExecutorAutoBan          = "AUTO_BAN"
	ExecutorRiskPolicy       = "RISK_POLICY"
	ExecutorLicenseQuota     = "LICENSE_QUOTA"
	ExecutorCC               = "CC"
	ExecutorJWT              = "JWT"
	ExecutorAPI              = "API"
	ExecutorWAF              = "WAF"
	ExecutorNone             = "NONE"
	ExecutorUnknown          = "UNKNOWN"
)

// StepModuleIPAllowlist 白名单步骤模块词（非 executor——白名单命中是放行而非终止，
// 只记录实际绕过的后续步骤 SKIPPED + detail）。
const StepModuleIPAllowlist = "IP_ALLOWLIST"

// response_source 枚举（契约 §2）。
const (
	ResponseSourceGateway = "GATEWAY"
	ResponseSourceOrigin  = "ORIGIN"
	ResponseSourceUnknown = "UNKNOWN"
)

// 步骤 result 枚举（契约 §2/§10 冻结四值）。
const (
	StepExecuted = "EXECUTED"
	StepObserved = "OBSERVED"
	StepExcepted = "EXCEPTED"
	StepSkipped  = "SKIPPED"
)

// dispositionModuleOrder guard 请求链模块执行序（与 module.go serveGuard 分支顺序一致），
// Finalize 据终止位置为终止之后未执行的模块补记 SKIPPED 步骤。
var dispositionModuleOrder = []string{
	ExecutorJWT,
	ExecutorManualBan,
	StepModuleIPAllowlist,
	ExecutorIPBlacklist,
	ExecutorL7ACL,
	ExecutorAutoBan,
	ExecutorRiskPolicy,
	ExecutorLicenseQuota,
	ExecutorCC,
	ExecutorAPI,
	ExecutorWAF,
}

// 容量上限（契约 §2：steps ≤ 32、rule_refs ≤ 64；其余为同纪律的防御性上限）。
const (
	maxDispositionSteps       = 32
	maxDispositionRuleRefs    = 64
	maxDispositionReasons     = 16
	maxMatchedExceptions      = 16
	maxDispositionEvidenceRef = 32
)

var disValidExecutors = map[string]bool{
	ExecutorProtectedAddress: true,
	ExecutorManualBan:        true,
	ExecutorIPBlacklist:      true,
	ExecutorL7ACL:            true,
	ExecutorAutoBan:          true,
	ExecutorRiskPolicy:       true,
	ExecutorLicenseQuota:     true,
	ExecutorCC:               true,
	ExecutorJWT:              true,
	ExecutorAPI:              true,
	ExecutorWAF:              true,
	ExecutorNone:             true,
	ExecutorUnknown:          true,
}

// disValidTerminalActions 终止分支动作合法集。NONE 用于非安全动作的网关终止
// （L7 redirect/custom_page——请求不到源站但不是安全阻断）；阻断类为
// BLOCK/TEMP_BLOCK/RATE_LIMIT；MASK_RESPONSE 是放行+响应改写，不是终止动作。
var disValidTerminalActions = map[string]bool{
	DisActionNone:      true,
	DisActionBlock:     true,
	DisActionTempBlock: true,
	DisActionRateLimit: true,
}

var disValidStepResults = map[string]bool{
	StepExecuted: true,
	StepObserved: true,
	StepExcepted: true,
	StepSkipped:  true,
}

// DispositionStep 单步执行事实。
type DispositionStep struct {
	Module string `json:"module"`
	Result string `json:"result"`
	Detail string `json:"detail,omitempty"`
}

// DispositionRuleRef 规则引用（terminal 记录的字符串引用按终止模块填充 module）。
type DispositionRuleRef struct {
	Module  string `json:"module"`
	RuleID  string `json:"rule_id"`
	Version string `json:"version,omitempty"`
}

// DispositionEffectiveConfig 生效配置引用（字段均可空）。
type DispositionEffectiveConfig struct {
	ConfigFingerprint string         `json:"config_fingerprint,omitempty"`
	APIPolicyVersion  string         `json:"api_policy_version,omitempty"`
	ExceptionVersions map[string]int `json:"exception_versions,omitempty"`
}

// DispositionFindings findings 计数（Finalize 从 steps/终止/例外派生）。
type DispositionFindings struct {
	Observed int `json:"observed"`
	Enforced int `json:"enforced"`
	Excepted int `json:"excepted"`
	Skipped  int `json:"skipped"`
}

// DispositionMatchedException 命中的受限例外（脱敏摘要，不含完整范围配置）。
type DispositionMatchedException struct {
	ExceptionID    string     `json:"exception_id"`
	Version        int        `json:"version"`
	Target         string     `json:"target"` // WAF|API
	RuleRefs       []string   `json:"rule_refs,omitempty"`
	ScopeSummary   string     `json:"scope_summary,omitempty"`
	EffectiveFrom  *time.Time `json:"effective_from,omitempty"`
	EffectiveUntil *time.Time `json:"effective_until,omitempty"`
}

// DispositionIdentityVerification P0-03 身份验证引用（不落原始 Token/明文声明）。
type DispositionIdentityVerification struct {
	Status              string `json:"status,omitempty"`
	VerifiedPrincipalID string `json:"verified_principal_id,omitempty"`
}

// terminalRecord 终止分支事实（内部态，Finalize 时投影到导出字段）。
type terminalRecord struct {
	module    string
	action    string
	status    int
	committed bool
	reasons   []string
	ruleRefs  []string
}

// originRecord 源站完成事实（内部态）。
type originRecord struct {
	status    int
	committed bool
}

// Disposition 请求最终处置上下文（与 final_decision JSON 同构，契约 §2）。
// 并发安全（同一请求内多模块串行记录，互斥锁兜底防御并发写）。
type Disposition struct {
	mu sync.Mutex

	SchemaVersion        int                              `json:"schema_version"`
	RequestID            string                           `json:"request_id"`
	ApplicationID        string                           `json:"application_id,omitempty"`
	GatewayNode          string                           `json:"gateway_node"`
	CompletionStatus     string                           `json:"completion_status"`
	SecurityAction       string                           `json:"security_action"`
	ExecutorModule       string                           `json:"executor_module"`
	ResponseSource       string                           `json:"response_source"`
	HTTPStatus           int                              `json:"http_status,omitempty"`
	ResponseCommitted    bool                             `json:"response_committed"`
	ReasonCodes          []string                         `json:"reason_codes,omitempty"`
	RuleRefs             []DispositionRuleRef             `json:"rule_refs,omitempty"`
	EffectiveConfig      DispositionEffectiveConfig       `json:"effective_config"`
	Findings             DispositionFindings              `json:"findings"`
	Steps                []DispositionStep                `json:"steps,omitempty"`
	MatchedExceptions    []DispositionMatchedException    `json:"matched_exceptions,omitempty"`
	IdentityVerification *DispositionIdentityVerification `json:"identity_verification,omitempty"`
	EvidenceRefs         []string                         `json:"evidence_refs,omitempty"`
	FinalizedAt          *time.Time                       `json:"finalized_at,omitempty"`

	finalized          bool
	terminal           *terminalRecord
	origin             *originRecord
	errored            bool
	pendingCorrelation bool
	maskEnforced       bool
	stepsDropped       int
	recorded           map[string]bool
	applicableExcVers  map[string]int
}

// dispositionCtxKey 请求上下文键（未导出，唯一存取入口为 With/From）。
type dispositionCtxKey struct{}

// WithDisposition 创建处置上下文并挂入 ctx（ServeHTTP 入口调用，不依赖访问日志开关）。
func WithDisposition(ctx context.Context, node string) (context.Context, *Disposition) {
	d := &Disposition{
		SchemaVersion:     dispositionSchemaVersion,
		GatewayNode:       node,
		CompletionStatus:  CompletionUnknown,
		SecurityAction:    DisActionNone,
		ExecutorModule:    ExecutorUnknown,
		ResponseSource:    ResponseSourceUnknown,
		recorded:          make(map[string]bool),
		applicableExcVers: make(map[string]int),
	}
	return context.WithValue(ctx, dispositionCtxKey{}, d), d
}

// DispositionFrom 从 ctx 取处置上下文（未创建返回 nil；所有记录方法容忍 nil 接收者）。
func DispositionFrom(ctx context.Context) *Disposition {
	if ctx == nil {
		return nil
	}
	d, _ := ctx.Value(dispositionCtxKey{}).(*Disposition)
	return d
}

// SetRequest 绑定请求标识（先到先得——RequestID 网关生成后只应设置一次）。
func (d *Disposition) SetRequest(requestID, appID string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.finalized {
		return
	}
	if d.RequestID == "" {
		d.RequestID = requestID
	}
	if d.ApplicationID == "" {
		d.ApplicationID = appID
	}
}

// SetIdentityVerification 记录 P0-03 身份验证引用（状态与主体指纹，不落原始 Token）。
func (d *Disposition) SetIdentityVerification(status, principalID string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.finalized {
		return
	}
	d.IdentityVerification = &DispositionIdentityVerification{Status: status, VerifiedPrincipalID: principalID}
}

// SetAPIPolicyVersion 记录生效 API 策略版本戳（先到先得）。
func (d *Disposition) SetAPIPolicyVersion(v string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.finalized {
		return
	}
	if d.EffectiveConfig.APIPolicyVersion == "" {
		d.EffectiveConfig.APIPolicyVersion = v
	}
}

// NoteExceptionVersion 登记本请求适用例外的版本（effective_config.exception_versions；
// 适用≠命中——命中另经 RecordMatchedException 记录，二者在 Finalize 合并）。
func (d *Disposition) NoteExceptionVersion(exceptionID string, version int) {
	if d == nil || exceptionID == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.finalized {
		return
	}
	d.applicableExcVers[exceptionID] = version
}

// AddEvidenceRef 追加关联证据标识（如 Coraza 事务 ID）。
func (d *Disposition) AddEvidenceRef(ref string) {
	if d == nil || ref == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.finalized || len(d.EvidenceRefs) >= maxDispositionEvidenceRef {
		return
	}
	d.EvidenceRefs = append(d.EvidenceRefs, ref)
}

// RecordTerminal 记录终止分支事实（先到先得——重复调用忽略；契约 §10 冻结签名）。
// module 非法归一 UNKNOWN；action 非法值归一 BLOCK（终止即阻断语义；NONE 合法——
// 非安全动作的网关终止）。
// ruleRefs 超上限截断并追加 TRUNCATED 步骤；同时留一条 EXECUTED 步痕。
func (d *Disposition) RecordTerminal(module, action string, status int, committed bool, reasons, ruleRefs []string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.finalized || d.terminal != nil {
		return
	}
	if !disValidExecutors[module] {
		module = ExecutorUnknown
	}
	if !disValidTerminalActions[action] {
		action = DisActionBlock
	}
	if len(reasons) > maxDispositionReasons {
		reasons = reasons[:maxDispositionReasons]
	}
	if len(ruleRefs) > maxDispositionRuleRefs {
		dropped := len(ruleRefs) - maxDispositionRuleRefs
		ruleRefs = ruleRefs[:maxDispositionRuleRefs]
		d.appendStepLocked(DispositionStep{
			Module: "TRUNCATED", Result: StepSkipped,
			Detail: fmt.Sprintf("rule_refs dropped=%d", dropped),
		})
	}
	d.terminal = &terminalRecord{
		module: module, action: action, status: status,
		committed: committed, reasons: reasons, ruleRefs: ruleRefs,
	}
	d.appendStepLocked(DispositionStep{
		Module: module, Result: StepExecuted,
		Detail: fmt.Sprintf("terminated action=%s status=%d", action, status),
	})
}

// RecordStep 记录单步执行事实（契约 §10 冻结签名；result 非法归一 EXECUTED）。
// result ∈ EXECUTED/OBSERVED/EXCEPTED/SKIPPED。
func (d *Disposition) RecordStep(module, result, detail string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.finalized {
		return
	}
	if !disValidStepResults[result] {
		result = StepExecuted
	}
	d.appendStepLocked(DispositionStep{Module: module, Result: result, Detail: detail})
	d.recorded[module] = true
}

// RecordMatchedException 记录受限例外命中（契约 §10 冻结签名）。同一例外同一目标
// 多次命中合并 ruleRefs（决策侧每条例外可豁免多条 Finding）；上限 16 条。
func (d *Disposition) RecordMatchedException(id string, version int, target string, ruleRefs []string, scopeSummary string, from, until *time.Time) {
	if d == nil || id == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.finalized {
		return
	}
	for i := range d.MatchedExceptions {
		me := &d.MatchedExceptions[i]
		if me.ExceptionID == id && me.Target == target {
			me.RuleRefs = mergeStringSet(me.RuleRefs, ruleRefs, maxDispositionRuleRefs)
			return
		}
	}
	if len(d.MatchedExceptions) >= maxMatchedExceptions {
		return
	}
	d.MatchedExceptions = append(d.MatchedExceptions, DispositionMatchedException{
		ExceptionID:    id,
		Version:        version,
		Target:         target,
		RuleRefs:       mergeStringSet(nil, ruleRefs, maxDispositionRuleRefs),
		ScopeSummary:   scopeSummary,
		EffectiveFrom:  utcSecondPtr(from),
		EffectiveUntil: utcSecondPtr(until),
	})
	d.applicableExcVers[id] = version
}

// RecordOrigin 记录源站完成事实（response_source=ORIGIN；契约 §10 冻结签名）。
// 先到先得——finishAPIResponse 的真实状态码记录早于 serveGuard 返回后的兜底补记；
// status=0 表示写出码不可得（序列化时省略 http_status）。
func (d *Disposition) RecordOrigin(status int, committed bool) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.finalized || d.terminal != nil || d.origin != nil {
		return
	}
	d.origin = &originRecord{status: status, committed: committed}
}

// RecordMaskResponse 标记响应脱敏已实改写（仅无终止时生效；security_action=
// MASK_RESPONSE，response_source 仍由 RecordOrigin 落 ORIGIN——契约 §7）。
func (d *Disposition) RecordMaskResponse() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.finalized || d.terminal != nil {
		return
	}
	d.maskEnforced = true
}

// RecordError 标记处理错误（completion_status=ERROR，response_source=UNKNOWN；
// 用于 API 管线 next 返回非 WAF 归因错误等路径）。
func (d *Disposition) RecordError(module, detail string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.finalized || d.terminal != nil {
		return
	}
	d.errored = true
	if detail != "" {
		d.appendStepLocked(DispositionStep{Module: module, Result: StepExecuted, Detail: "error: " + detail})
	}
}

// NotePendingCorrelation 标记终止动作的规则明细待 eventparser 异步补全
// （WAF 中断归因路径：同步仅知 executor+status；Finalize 时 completion_status
// 落 PENDING_CORRELATION 而非 ABORTED）。
func (d *Disposition) NotePendingCorrelation() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.finalized {
		return
	}
	d.pendingCorrelation = true
}

// Finalize 补全 completion_status/SKIPPED/findings 计数/finalized_at（幂等，契约 §10）。
// 优先级：terminal > error > origin > 皆无（客户端取消/panic 路径落 UNKNOWN）。
func (d *Disposition) Finalize() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.finalized {
		return
	}
	d.finalized = true
	now := time.Now().UTC()
	d.FinalizedAt = &now

	switch {
	case d.terminal != nil:
		d.CompletionStatus = CompletionAborted
		if d.pendingCorrelation {
			d.CompletionStatus = CompletionPendingCorrelation
		}
		d.SecurityAction = d.terminal.action
		d.ExecutorModule = d.terminal.module
		d.ResponseSource = ResponseSourceGateway
		d.HTTPStatus = d.terminal.status
		d.ResponseCommitted = d.terminal.committed
		d.ReasonCodes = d.terminal.reasons
		for _, ref := range d.terminal.ruleRefs {
			d.RuleRefs = append(d.RuleRefs, DispositionRuleRef{Module: d.terminal.module, RuleID: ref})
		}
		d.appendSkippedAfterLocked(d.terminal.module)
	case d.errored:
		d.CompletionStatus = CompletionError
		d.ExecutorModule = ExecutorNone
		d.ResponseSource = ResponseSourceUnknown
	case d.origin != nil:
		d.CompletionStatus = CompletionCompleted
		d.ExecutorModule = ExecutorNone
		d.ResponseSource = ResponseSourceOrigin
		d.HTTPStatus = d.origin.status
		d.ResponseCommitted = d.origin.committed
		if d.maskEnforced {
			d.SecurityAction = DisActionMaskResponse
		}
	default:
		d.CompletionStatus = CompletionUnknown
		d.ExecutorModule = ExecutorUnknown
		d.ResponseSource = ResponseSourceUnknown
	}

	// findings 计数：enforced=有实断/实改写动作（NONE 动作的非安全终止不计）；
	// observed/excepted/skipped 从事实派生。
	if (d.terminal != nil && d.terminal.action != DisActionNone) || d.maskEnforced {
		d.Findings.Enforced = 1
	}
	d.Findings.Excepted = len(d.MatchedExceptions)
	for _, s := range d.Steps {
		switch s.Result {
		case StepObserved:
			d.Findings.Observed++
		case StepSkipped:
			if s.Module != "TRUNCATED" {
				d.Findings.Skipped++
			}
		}
	}

	// exception_versions：适用例外与命中例外合并。
	if len(d.applicableExcVers) > 0 {
		d.EffectiveConfig.ExceptionVersions = d.applicableExcVers
	}

	// steps 截断标记：满额时替换末位（被替换条目计入 dropped），否则追加。
	if d.stepsDropped > 0 {
		truncated := DispositionStep{
			Module: "TRUNCATED", Result: StepSkipped,
			Detail: fmt.Sprintf("dropped=%d", d.stepsDropped),
		}
		if len(d.Steps) >= maxDispositionSteps {
			truncated.Detail = fmt.Sprintf("dropped=%d", d.stepsDropped+1)
			d.Steps[maxDispositionSteps-1] = truncated
		} else {
			d.Steps = append(d.Steps, truncated)
		}
	}
}

// Settled 处置事实是否已确定（终止/源站完成/错误任一已记录）。事件挂载
// final_decision 的门禁：仅 settled 后 JSON() 的提前 Finalize 才不锁死后续记录——
// 终止/完成后本就不会再产生新事实；放行途中（非终止观察事件）为 false 不挂。
func (d *Disposition) Settled() bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.terminal != nil || d.origin != nil || d.errored
}

// JSON 序列化为 final_decision JSON（内部先 Finalize；重复调用结果稳定）。
func (d *Disposition) JSON() json.RawMessage {
	if d == nil {
		return nil
	}
	d.Finalize()
	d.mu.Lock()
	defer d.mu.Unlock()
	data, err := json.Marshal(d)
	if err != nil {
		return nil
	}
	return data
}

// appendStepLocked 追加大步骤（满额丢弃并计数，Finalize 统一补 TRUNCATED 条目）。
func (d *Disposition) appendStepLocked(step DispositionStep) {
	if len(d.Steps) >= maxDispositionSteps {
		d.stepsDropped++
		return
	}
	d.Steps = append(d.Steps, step)
}

// appendSkippedAfterLocked 为终止之后未记录事实的模块补 SKIPPED 步骤（契约 §7：
// 终止分支之后的模块标 SKIPPED）。终止模块本身已在 RecordTerminal 留 EXECUTED 步痕。
func (d *Disposition) appendSkippedAfterLocked(terminalModule string) {
	idx := -1
	for i, m := range dispositionModuleOrder {
		if m == terminalModule {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	for _, m := range dispositionModuleOrder[idx+1:] {
		if d.recorded[m] {
			continue
		}
		d.appendStepLocked(DispositionStep{
			Module: m, Result: StepSkipped,
			Detail: "not reached: terminated by " + terminalModule,
		})
		d.recorded[m] = true
	}
}

// mergeStringSet 合并字符串集（去重、保持先入序、上限截断）。
func mergeStringSet(base, add []string, max int) []string {
	out := base
	for _, s := range add {
		if s == "" || len(out) >= max {
			continue
		}
		dup := false
		for _, e := range out {
			if e == s {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, s)
		}
	}
	return out
}

// utcSecondPtr 时间指针归一（UTC、秒精度；nil 透传）。
func utcSecondPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC().Truncate(time.Second)
	return &v
}

// recordBypassedSteps 记录白名单/L7 allow/保护地址实际绕过的步骤（契约 §7：
// 只记录实际绕过的步骤，SKIPPED + detail）。调用点按请求链顺序传入被绕过模块。
func recordBypassedSteps(d *Disposition, bypasser string, modules ...string) {
	if d == nil {
		return
	}
	for _, m := range modules {
		d.RecordStep(m, StepSkipped, "bypassed by "+bypasser)
	}
}
