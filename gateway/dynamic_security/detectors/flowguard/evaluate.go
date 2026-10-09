// evaluate.go 强流程运行时判定（NG-FLOW-02 §1.6/D6）：检测器 flowguard 在 API
// 管线内、授权评估之后挂接，对命中步骤执行原子预留并产决策组
// （ALLOW/VIOLATION/UNKNOWN + reason code 词表）。
//
// 实断语义（D6）：定义级 mode OBSERVE（缺省，NG-T-C01 零变化）/PROTECT；
// 违规（无有效预留执行依赖步骤 / 重复执行已 CONFIRMED 步骤 / 非法并行 /
// fencing 过期提交 / 幂等冲突）产出 flowguard.violation 明细——定义 PROTECT 且
// 决策引擎 PROTECT 双闸全真时 Category=BLOCK 可定案 403（统一 JSON 不泄露实例
// 细节，防探测——AZ-03 同纪律），否则 OBSERVE 只记录。
// UNKNOWN 恒不阻断（红线）：Valkey 故障/密钥缺席/实例引用缺失/INDETERMINATE →
// 放行 + flowguard.unknown OBSERVE 明细 + 事件如实披露（infra 故障附
// dependency_unavailable=true，同 AZ-02 先例）；任何形态不把 UNKNOWN 映射为 403。
//
// 动作事实（含 ALLOW）经请求上下文扩展 sflow.actions 留存
// （[]*dsevents.StrongFlowAction 冻结形状），由装配层挂到运行时主事件
// strong_flow 数组随既有采集链落 PG（不建新表）；成功预留同时经
// sflow.reservation 留存（FLOW-03 响应回程 commit 的消费点，本批不消费）。
//
// 与既有流程观察（detectors/flow.go 七类 OBSERVE 信号）并行共存互不消费：
// 强流程只读 Valkey sflow:v1: 命名空间，不读观察态会话，反之亦然。
package flowguard

import (
	"net/http"
	"sort"
	"strconv"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// 请求上下文扩展键（装配层 emitAPIEvent 读取；FLOW-03 消费 sflow.reservation）。
const (
	extActions     = "sflow.actions"
	extReservation = "sflow.reservation"
)

// BoundStep 端点命中的强流程步骤绑定（装配层按 endpoint_key 归组产物；
// 同一端点可被多个定义/版本绑定——逐绑定独立判定，实例键含定义版本维度天然隔离）。
type BoundStep struct {
	Definition Definition
	Step       Step
}

// IndexByEndpoint 按步骤 endpoint_key 归组已装配定义（装配层一次归组，运行期
// 按命中端点 O(1) 选取；与 detectors.GroupFlowBaselines 同一模式）。
// nil Registry = 零行为（NG-T-C01）。
func IndexByEndpoint(reg *Registry) map[string][]BoundStep {
	if reg == nil {
		return nil
	}
	out := make(map[string][]BoundStep)
	for _, d := range reg.All() {
		for _, s := range d.Steps {
			if s.EndpointKey == "" {
				continue
			}
			out[s.EndpointKey] = append(out[s.EndpointKey], BoundStep{Definition: d, Step: s})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Runtime 强流程运行时（装配层构建；Provision 后只读，热加载经实例整体替换）。
type Runtime struct {
	// Store 原子操作存储（nil 或 Valkey 故障 → 恒 UNKNOWN 放行+披露，D8 不切本地内存）。
	Store *Store
	// HMACKey 实例引用 HMAC 密钥（快照下发 object HMAC key，32B；缺席 → 恒 UNKNOWN
	// 放行+披露，不阻断——登记偏差）。
	HMACKey []byte
	// Now 事件发生时刻源（nil = time.Now；测试注入）。
	Now func() time.Time
}

// Reservation 成功预留（FLOW-03 响应回程 commit 的消费点）。
type Reservation struct {
	DefinitionID      string
	DefinitionVersion int
	InstanceID        string
	StepKey           string
	FencingToken      int64
	LeaseSeconds      int
	Allows202         bool
	RetrySemantics    string
	// SuccessRule 成功判定式（reserve 时已解析——装配校验保证形态合法，解析
	// 失败防御性置 nil → 响应回程恒 UNKNOWN 如实处理，D4）
	SuccessRule *SuccessRule
	// AllStepKeys 定义全部步骤（sequence 升序）——commit 实例完成判定的原子域键集
	AllStepKeys []string
	// IdemHash/Digest 幂等键哈希与参数摘要（与 reserve 同值——commit 幂等重放判定）
	IdemHash string
	Digest   string
}

// ActionsFromContext 取本请求已记录的强流程动作条目（装配层事件挂载用）。
func ActionsFromContext(ctx *dsctx.RequestContext) []*dsevents.StrongFlowAction {
	if ctx == nil {
		return nil
	}
	v, ok := ctx.GetExtension(extActions)
	if !ok {
		return nil
	}
	actions, _ := v.([]*dsevents.StrongFlowAction)
	return actions
}

// ReservationFromContext 取本请求成功预留（FLOW-03 消费点）。
func ReservationFromContext(ctx *dsctx.RequestContext) *Reservation {
	if ctx == nil {
		return nil
	}
	v, ok := ctx.GetExtension(extReservation)
	if !ok {
		return nil
	}
	res, _ := v.(*Reservation)
	return res
}

// Evaluate 强流程检测器入口（pipeline 在授权评估之后调用；bound 为本请求命中端点
// 的步骤绑定，nil/空 = 零行为）。tracking 为管线统一主体追踪键（凭据指纹优先、
// 回退来源 IP）；jwt 为信任链验证结果（VERIFIED 时主体/租户取可信声明）。
// engineProtect 为决策引擎 PROTECT 语义（定义级 mode 与其构成双闸，AZ-03 同纪律）。
func Evaluate(ctx *dsctx.RequestContext, r *http.Request, parsed *parser.Parsed, endpointKey string, bound []BoundStep, rt *Runtime, jwt *jwtverify.VerificationResult, tracking string, engineProtect bool) {
	if ctx == nil || rt == nil || len(bound) == 0 {
		return
	}
	now := time.Now().UTC()
	if rt.Now != nil {
		now = rt.Now().UTC()
	}
	for i := range bound {
		evaluateOne(ctx, r, parsed, endpointKey, bound[i], rt, jwt, tracking, engineProtect, now)
	}
}

// evaluateOne 单绑定判定：提取实例引用 → 构造实例键 → 原子预留 → 决策组+事件条目。
func evaluateOne(ctx *dsctx.RequestContext, r *http.Request, parsed *parser.Parsed, endpointKey string, bs BoundStep, rt *Runtime, jwt *jwtverify.VerificationResult, tracking string, engineProtect bool, now time.Time) {
	def, step := bs.Definition, bs.Step
	// 可信租户/主体（§1.2 实例键分量）：JWT VERIFIED 取可信声明，否则回退管线
	// 追踪键（凭据指纹/来源 IP——网关派生非客户端断言，不冒充已验证身份）。
	principal, tenant := resolvePrincipal(jwt, tracking)
	if principal == "" {
		recordUnknownAction(ctx, def, step, "", now, "missing_principal")
		addUnknownFinding(ctx, def, step, endpointKey, "missing_principal", false)
		return
	}
	// 实例引用提取（批准的参数提取器键；缺失 = 证据不足 UNKNOWN 放行，不编造归属）
	ref := ExtractInstanceRef(def.InstanceKeyParam, parsed)
	if ref == "" {
		recordUnknownAction(ctx, def, step, "", now, "missing_instance_ref")
		addUnknownFinding(ctx, def, step, endpointKey, "missing_instance_ref", false)
		return
	}
	// 实例键（域隔离 HMAC；密钥缺席 → UNKNOWN 放行+披露，登记偏差不阻断）
	iid := InstanceID(rt.HMACKey, def.ApplicationID, tenant, principal, def.Version, ref)
	if iid == "" {
		recordUnknownAction(ctx, def, step, "", now, "hmac_key_unavailable")
		addUnknownFinding(ctx, def, step, endpointKey, "hmac_key_unavailable", true)
		return
	}

	idemHash := IdempotencyKeyHash(r.Header.Get)
	digest := ParamDigest(parsed)
	// 育龄窗闸（§8.4-1 裁决）：RETIRED 下发版本仅存量实例续跑——Reserve 原子域内
	// 判实例状态键存在性，全新实例键 definition_retired 拒入（新实例必须按
	// ACTIVE 版本键，多版本并存由 registry (id,version) 索引天然分流）
	res := rt.Store.Reserve(iid, step.StepKey, predecessorStepKeys(def, step), step.LeaseSeconds, idemHash, digest,
		def.Status != StatusRetired)
	recordActions(ctx, def, step, iid, res, now)

	switch res.Outcome {
	case "OK":
		// 成功预留留存（FLOW-03 commit 消费点；幂等重放返回的即既有 token，
		// 重复写入等价幂等——先到先得，不覆盖既有留存）
		if ReservationFromContext(ctx) == nil {
			ctx.SetExtension(extReservation, &Reservation{
				DefinitionID:      def.ID,
				DefinitionVersion: def.Version,
				InstanceID:        iid,
				StepKey:           step.StepKey,
				FencingToken:      res.Token,
				LeaseSeconds:      step.LeaseSeconds,
				Allows202:         step.Allows202,
				RetrySemantics:    step.RetrySemantics,
				SuccessRule:       parsedSuccessRule(step),
				AllStepKeys:       sortedStepKeys(def),
				IdemHash:          idemHash,
				Digest:            digest,
			})
		}
	case "CONFLICT", "REJECTED":
		// 违规（D6 形态集合）：双闸全真 → BLOCK 可定案；否则 OBSERVE 只记录
		category := "OBSERVE"
		if def.Mode == ModeProtect && engineProtect {
			category = "BLOCK"
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "flowguard",
			RuleID:     "flowguard.violation",
			Category:   category,
			Severity:   "HIGH",
			Message:    "strong flow step violates reservation state",
			Confidence: 1.0,
			Evidence: map[string]string{
				"definition_id":      def.ID,
				"definition_version": strconv.Itoa(def.Version),
				"endpoint_key":       endpointKey,
				"step_key":           step.StepKey,
				"reason_code":        res.Reason,
				"detail":             res.Detail,
				"instance_id":        iid,
				"fencing_token":      strconv.FormatInt(res.Token, 10),
				"mode":               def.Mode,
			},
		})
	default: // UNKNOWN（动作条目已在上方 recordActions 记录，此处只补明细）
		infra := res.Detail == "valkey_error" || res.Detail == "valkey_unconfigured" || res.Detail == "eval_protocol_error"
		addUnknownFinding(ctx, def, step, endpointKey, res.Detail, infra)
	}
}

// resolvePrincipal 可信主体/租户解析：JWT VERIFIED → 可信声明（jwt: 前缀区别于
// 追踪键形态）；否则回退管线追踪键（凭据指纹优先、来源 IP 兜底），租户无声明置 "-"。
func resolvePrincipal(jwt *jwtverify.VerificationResult, tracking string) (principal, tenant string) {
	if jwt != nil && jwt.Status == jwtverify.StatusVerified && jwt.VerifiedPrincipalID != "" {
		t := jwt.VerifiedTenantID
		if t == "" {
			t = "-"
		}
		return "jwt:" + jwt.VerifiedPrincipalID, t
	}
	return tracking, "-"
}

// predecessorStepKeys 前置步骤（sequence 小于本步并行组起点；首步为空）：
// 并行组同组成员互不为前置（同组可合法并行），组外更小序列步骤全部须先 CONFIRMED。
func predecessorStepKeys(def Definition, step Step) []string {
	groupStart := step.Sequence
	if step.ParallelGroup != "" {
		for _, s := range def.Steps {
			if s.ParallelGroup == step.ParallelGroup && s.Sequence < groupStart {
				groupStart = s.Sequence
			}
		}
	}
	var out []string
	for _, s := range def.Steps {
		if s.Sequence < groupStart {
			out = append(out, s.StepKey)
		}
	}
	return out
}

// parsedSuccessRule reserve 时解析成功判定式（装配校验保证形态合法；
// 解析失败防御性置 nil——响应回程按 rule_missing 恒 UNKNOWN 如实处理，不 panic）。
func parsedSuccessRule(step Step) *SuccessRule {
	rule, err := ParseSuccessRule(step.SuccessRule)
	if err != nil {
		return nil
	}
	return rule
}

// sortedStepKeys 定义全部步骤键（sequence 升序；commit 实例完成判定原子域键集）。
func sortedStepKeys(def Definition) []string {
	steps := make([]Step, len(def.Steps))
	copy(steps, def.Steps)
	sort.Slice(steps, func(i, j int) bool { return steps[i].Sequence < steps[j].Sequence })
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		out = append(out, s.StepKey)
	}
	return out
}

// recordActions 动作事实留存（RESERVE 为主条目；实例首建/过期接管补
// INSTANCE_NEW/EXPIRE 条目——事件链含两次 fencing 值，F05 审计可核对）。
func recordActions(ctx *dsctx.RequestContext, def Definition, step Step, instanceID string, res OpResult, now time.Time) {
	base := dsevents.StrongFlowAction{
		DefinitionID:      def.ID,
		DefinitionVersion: def.Version,
		InstanceID:        instanceID,
		StepKey:           step.StepKey,
		LeaseSeconds:      step.LeaseSeconds,
		OccurredAt:        now,
	}
	var entries []*dsevents.StrongFlowAction
	if res.InstanceNew {
		e := base
		e.Action = dsevents.SFlowActionInstanceNew
		e.Result = dsevents.SFlowResultOK
		e.FencingToken = res.Token
		entries = append(entries, &e)
	}
	if res.ExpiredTakeover {
		e := base
		e.Action = dsevents.SFlowActionExpire
		e.Result = dsevents.SFlowResultOK
		e.FencingToken = res.ExpiredToken
		entries = append(entries, &e)
	}
	e := base
	e.Action = dsevents.SFlowActionReserve
	e.Result = res.Outcome
	e.ReasonCode = res.Reason
	e.FencingToken = res.Token
	entries = append(entries, &e)

	appendActions(ctx, entries...)
}

func appendActions(ctx *dsctx.RequestContext, entries ...*dsevents.StrongFlowAction) {
	existing := ActionsFromContext(ctx)
	existing = append(existing, entries...)
	ctx.SetExtension(extActions, existing)
}

// recordUnknownAction UNKNOWN 动作条目留存（result=UNKNOWN, reason UNKNOWN-001；
// 实例键不可得时 instance_id 空串如实呈现）。
func recordUnknownAction(ctx *dsctx.RequestContext, def Definition, step Step, instanceID string, now time.Time, detail string) {
	recordActions(ctx, def, step, instanceID, OpResult{
		Outcome: dsevents.SFlowResultUnknown,
		Reason:  ReasonUnknown,
		Detail:  detail,
	}, now)
}

// addUnknownFinding UNKNOWN 明细（flowguard.unknown OBSERVE——恒不阻断红线；
// infra 故障附 dependency_unavailable=true，同 AZ-02 披露先例）。
func addUnknownFinding(ctx *dsctx.RequestContext, def Definition, step Step, endpointKey, detail string, infra bool) {
	evidence := map[string]string{
		"definition_id":      def.ID,
		"definition_version": strconv.Itoa(def.Version),
		"endpoint_key":       endpointKey,
		"step_key":           step.StepKey,
		"reason_code":        ReasonUnknown,
		"detail":             detail,
		"mode":               def.Mode,
	}
	if infra {
		evidence["dependency_unavailable"] = "true"
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "flowguard",
		RuleID:     "flowguard.unknown",
		Category:   "OBSERVE",
		Severity:   "MEDIUM",
		Message:    "strong flow evaluation unknown (fail-open, disclosed)",
		Confidence: 1.0,
		Evidence:   evidence,
	})
}
