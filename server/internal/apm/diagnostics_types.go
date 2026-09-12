// diagnostics_types.go APM 阶段4 深度诊断会话：模型、生命周期状态机、入参校验/夹紧
// 与开销护栏（纯函数层，不触库；设计 §6.3 深度诊断流程 / §11 诊断能力 / §21.2 性能预算）。
//
// 会话状态机存态（apm_diagnostic_sessions.status，CHECK 约束兜底）：
//
//	ACTIVE ──到期──► EXPIRED（终态）
//	ACTIVE ──人工停止──► STOPPED（终态）
//	ACTIVE ──kill switch──► KILLED（终态）
//
// 终态不可再迁移；所有迁移经仓储条件 UPDATE（WHERE status='ACTIVE'）原子落库。
//
// 开销护栏（§21.2；handler 映射 HTTP 422，与参数形态错误 400 区分）：
//   - 函数探针为最高开销能力：要求 scope.instance_ids 非空或 service 精确指定
//     （防大范围高开销），且采样率 ≤ 0.5；其余能力采样率 ≤ 1.0；
//   - 时长上限 120 分钟（防忘记关闭——§12.3）；
//   - 下界不拒绝只做夹紧：采样率 <0.1 夹紧到 0.1，时长 <15 分钟夹紧到 15
//     （缺省 15）；夹紧后的生效值随响应回显（dry_run effective / 会话行）。
package apm

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 诊断会话状态词表（apm_diagnostic_sessions.status）。
const (
	DiagnosticStatusActive  = "ACTIVE"
	DiagnosticStatusExpired = "EXPIRED"
	DiagnosticStatusStopped = "STOPPED"
	DiagnosticStatusKilled  = "KILLED"
)

// canTransitionDiagnostic 会话状态机合法迁移表（from → 允许的 to 集合；终态为空集）。
var canTransitionDiagnostic = map[string]map[string]bool{
	DiagnosticStatusActive: {
		DiagnosticStatusExpired: true,
		DiagnosticStatusStopped: true,
		DiagnosticStatusKilled:  true,
	},
	DiagnosticStatusExpired: {},
	DiagnosticStatusStopped: {},
	DiagnosticStatusKilled:  {},
}

// CanTransitionDiagnosticSession 判断会话状态迁移是否合法（终态任何转出均非法）。
func CanTransitionDiagnosticSession(from, to string) bool {
	return canTransitionDiagnostic[from][to]
}

// 诊断能力词表（§11 五类深度诊断能力）。
const (
	DiagCapSQLDetail     = "sql_detail"     // SQL 慢查询细节（指纹+脱敏口径展开）
	DiagCapFunctionProbe = "function_probe" // 目标函数探针（最高开销）
	DiagCapThreadBlock   = "thread_block"   // 线程/协程阻塞诊断
	DiagCapGCDetail      = "gc_detail"      // GC 明细
	DiagCapMQWait        = "mq_wait"        // 消息队列等待明细
)

// allowedDiagnosticCapabilities 能力白名单（fail-closed：未知能力一律拒绝）。
var allowedDiagnosticCapabilities = map[string]bool{
	DiagCapSQLDetail: true, DiagCapFunctionProbe: true, DiagCapThreadBlock: true,
	DiagCapGCDetail: true, DiagCapMQWait: true,
}

// 采样率/时长边界与夹紧口径（合同：sampling_rate 0.1~1.0、duration_minutes 15~120 缺省 15）。
const (
	minDiagnosticSamplingRate        = 0.1
	maxDiagnosticSamplingRate        = 1.0
	maxFunctionProbeSamplingRate     = 0.5 // 函数探针分级上限（§21.2 开销预算）
	defaultDiagnosticDurationMinutes = 15
	minDiagnosticDurationMinutes     = 15
	maxDiagnosticDurationMinutes     = 120
	maxDiagnosticScopeInstanceIDs    = 64 // scope.instance_ids 基数上限（防异常放大）
	diagnosticStopReasonManual       = "manual"
	diagnosticStopReasonExpired      = "expired"
	diagnosticStopReasonKillSwitch   = "kill switch"
)

// 诊断会话错误（handler 按 errors.Is 映射状态码）。
var (
	// ErrDiagnosticInvalid 入参形态非法（HTTP 400）。
	ErrDiagnosticInvalid = errors.New("诊断会话参数非法")
	// ErrDiagnosticGuard 开销护栏拦截（HTTP 422）。
	ErrDiagnosticGuard = errors.New("诊断开销护栏拦截")
	// ErrDiagnosticNoAgents scope 未匹配到在线 Agent（HTTP 422）。
	ErrDiagnosticNoAgents = errors.New("scope 未匹配到在线 Agent")
	// ErrDiagnosticKillSwitch kill switch 开启中，拒绝新建（HTTP 422）。
	ErrDiagnosticKillSwitch = errors.New("诊断 kill switch 已开启，拒绝新建诊断会话")
	// ErrDiagnosticNotFound 会话不存在（HTTP 404）。
	ErrDiagnosticNotFound = errors.New("诊断会话不存在")
	// ErrDiagnosticTerminal 会话已处于终态（HTTP 409）。
	ErrDiagnosticTerminal = errors.New("诊断会话已处于终态")
	// ErrDiagnosticScopeBusy 同应用存在进行中的诊断会话（HTTP 409；部分唯一索引兜底）。
	ErrDiagnosticScopeBusy = errors.New("该应用存在进行中的诊断会话，请先停止或等待到期")
)

// DiagnosticScope 诊断会话范围（落库 scope jsonb；application_id 必填，
// 诊断叠加策略按 application:<uuid> 作用域发布，故范围必须收敛到单应用）。
type DiagnosticScope struct {
	ApplicationID uuid.UUID `json:"application_id"`
	Service       string    `json:"service,omitempty"`
	Environment   string    `json:"environment,omitempty"`
	InstanceIDs   []string  `json:"instance_ids,omitempty"`
}

// DiagnosticSession apm_diagnostic_sessions 行。
type DiagnosticSession struct {
	ID               uuid.UUID       `json:"id"`
	Scope            DiagnosticScope `json:"scope"`
	Capabilities     []string        `json:"capabilities"`
	SamplingRate     float64         `json:"sampling_rate"`
	DurationMinutes  int             `json:"duration_minutes"`
	Status           string          `json:"status"` // ACTIVE/EXPIRED/STOPPED/KILLED
	CreatedBy        *uuid.UUID      `json:"created_by"`
	CreatedAt        time.Time       `json:"created_at"`
	ExpiresAt        time.Time       `json:"expires_at"`
	StoppedAt        *time.Time      `json:"stopped_at"`
	StoppedBy        *uuid.UUID      `json:"stopped_by"`
	StopReason       string          `json:"stop_reason"`
	PolicyVersion    int64           `json:"policy_version"`    // 创建时下发的诊断叠加策略版本
	BaselineRestored bool            `json:"baseline_restored"` // 终态后是否已下发基线恢复策略
}

// diagnosticScopeInput 创建入参的 scope 形态（application_id 以字符串承载，解析后入库）。
type diagnosticScopeInput struct {
	ApplicationID string   `json:"application_id"`
	Service       string   `json:"service"`
	Environment   string   `json:"environment"`
	InstanceIDs   []string `json:"instance_ids"`
}

// normalizeDiagnosticScope 校验并规范化 scope（fail-closed：形态非法即 ErrDiagnosticInvalid）：
// application_id 必填且为合法 UUID；service 复用 Agent 面 service_name 字符集；
// environment 复用注册令牌环境标识格式；instance_ids 去重、逐元素校验、上限 64。
func normalizeDiagnosticScope(in diagnosticScopeInput) (DiagnosticScope, error) {
	appID, err := uuid.Parse(strings.TrimSpace(in.ApplicationID))
	if err != nil {
		return DiagnosticScope{}, fmt.Errorf("%w：scope.application_id 须为合法 UUID", ErrDiagnosticInvalid)
	}
	scope := DiagnosticScope{ApplicationID: appID}
	scope.Service = strings.TrimSpace(in.Service)
	if scope.Service != "" && !serviceNamePattern.MatchString(scope.Service) {
		return DiagnosticScope{}, fmt.Errorf("%w：scope.service 须为 1~128 位字母数字或 . _ : -", ErrDiagnosticInvalid)
	}
	scope.Environment = strings.TrimSpace(in.Environment)
	if scope.Environment != "" && !environmentSlug.MatchString(scope.Environment) {
		return DiagnosticScope{}, fmt.Errorf("%w：scope.environment 格式非法（小写字母/数字/中划线，不超过 64 字符）", ErrDiagnosticInvalid)
	}
	seen := map[string]bool{}
	for _, raw := range in.InstanceIDs {
		id := strings.TrimSpace(raw)
		if !instanceIDPattern.MatchString(id) {
			return DiagnosticScope{}, fmt.Errorf("%w：scope.instance_ids 元素 %q 非法（1~128 位字母数字或 . _ : -）", ErrDiagnosticInvalid, raw)
		}
		if !seen[id] {
			seen[id] = true
			scope.InstanceIDs = append(scope.InstanceIDs, id)
		}
	}
	if len(scope.InstanceIDs) > maxDiagnosticScopeInstanceIDs {
		return DiagnosticScope{}, fmt.Errorf("%w：scope.instance_ids 不能超过 %d 个", ErrDiagnosticInvalid, maxDiagnosticScopeInstanceIDs)
	}
	return scope, nil
}

// normalizeDiagnosticCapabilities 能力白名单校验 + 去重（非空；未知能力拒绝）。
func normalizeDiagnosticCapabilities(in []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, raw := range in {
		c := strings.ToLower(strings.TrimSpace(raw))
		if !allowedDiagnosticCapabilities[c] {
			return nil, fmt.Errorf("%w：不支持的诊断能力 %q（支持 sql_detail/function_probe/thread_block/gc_detail/mq_wait）", ErrDiagnosticInvalid, raw)
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w：capabilities 不能为空", ErrDiagnosticInvalid)
	}
	return out, nil
}

// clampDiagnosticSamplingRate 采样率下界夹紧（<0.1 含缺省 0 → 0.1；上界由护栏校验拒绝）。
func clampDiagnosticSamplingRate(rate float64) float64 {
	if rate < minDiagnosticSamplingRate {
		return minDiagnosticSamplingRate
	}
	return rate
}

// clampDiagnosticDurationMinutes 时长下界夹紧（缺省/<15 → 15；上界由护栏校验拒绝）。
func clampDiagnosticDurationMinutes(d int) int {
	if d <= 0 {
		return defaultDiagnosticDurationMinutes
	}
	if d < minDiagnosticDurationMinutes {
		return minDiagnosticDurationMinutes
	}
	return d
}

// hasCapability 能力集合判定。
func hasCapability(caps []string, cap string) bool {
	for _, c := range caps {
		if c == cap {
			return true
		}
	}
	return false
}

// checkDiagnosticOverheadGuards 开销护栏（§21.2；违反即 ErrDiagnosticGuard，HTTP 422）：
// 时长上限 120；采样率上限按能力分级（function_probe ≤0.5、其余 ≤1.0）；
// 函数探针要求范围精确（instance_ids 非空或 service 精确），防大范围高开销。
func checkDiagnosticOverheadGuards(caps []string, scope DiagnosticScope, rate float64, durationMin int) error {
	if durationMin > maxDiagnosticDurationMinutes {
		return fmt.Errorf("%w：duration_minutes 不能超过 %d 分钟", ErrDiagnosticGuard, maxDiagnosticDurationMinutes)
	}
	if rate > maxDiagnosticSamplingRate {
		return fmt.Errorf("%w：sampling_rate 不能超过 %.1f", ErrDiagnosticGuard, maxDiagnosticSamplingRate)
	}
	if hasCapability(caps, DiagCapFunctionProbe) {
		if rate > maxFunctionProbeSamplingRate {
			return fmt.Errorf("%w：function_probe 能力 sampling_rate 不能超过 %.1f", ErrDiagnosticGuard, maxFunctionProbeSamplingRate)
		}
		if len(scope.InstanceIDs) == 0 && scope.Service == "" {
			return fmt.Errorf("%w：function_probe 能力要求 scope.instance_ids 非空或精确指定 scope.service（防大范围高开销）", ErrDiagnosticGuard)
		}
	}
	return nil
}

// ---------- 开销预估（dry_run；确定性启发式，响应标注为估算口径） ----------

// OverheadEstimate dry_run 预估输出（合同字段：cpu_hint/spans_per_s_hint/data_volume_hint/risk_notes）。
type OverheadEstimate struct {
	CPUHint        string   `json:"cpu_hint"`
	SpansPerSHint  string   `json:"spans_per_s_hint"`
	DataVolumeHint string   `json:"data_volume_hint"`
	RiskNotes      []string `json:"risk_notes"`
}

// 估算基数（单实例、采样率 1.0 口径的经验上限；仅用于创建前提示，不作为性能承诺——
// §21"不是未经测试的承诺"）。
var diagnosticCPUPercentPerCap = map[string]float64{
	DiagCapSQLDetail: 2, DiagCapFunctionProbe: 8, DiagCapThreadBlock: 3,
	DiagCapGCDetail: 1, DiagCapMQWait: 1,
}
var diagnosticSpansPerSecPerCap = map[string]float64{
	DiagCapSQLDetail: 40, DiagCapFunctionProbe: 200, DiagCapThreadBlock: 10,
	DiagCapGCDetail: 5, DiagCapMQWait: 20,
}

// spanAvgKB 单 span 平均体积估算（KB，含属性上限截断后的经验值）。
const spanAvgKB = 1.2

// steadyStateCPUBudgetPct 稳态额外 CPU 预算线（§21.1：不超过 5%）。
const steadyStateCPUBudgetPct = 5.0

// EstimateDiagnosticOverhead 估算诊断开销（caps/rate/duration 为夹紧后的生效值；
// matchedInstances 为当前匹配的在线 Agent 数，0 时如实提示正式创建将被拒绝）。
func EstimateDiagnosticOverhead(caps []string, rate float64, durationMin, matchedInstances int) OverheadEstimate {
	var cpuPct, spansPerS float64
	for _, c := range caps {
		cpuPct += diagnosticCPUPercentPerCap[c]
		spansPerS += diagnosticSpansPerSecPerCap[c]
	}
	cpuPct *= rate
	spansPerS *= rate * float64(max(matchedInstances, 0))
	totalMB := spansPerS * float64(durationMin) * 60 * spanAvgKB / 1024

	est := OverheadEstimate{
		CPUHint: fmt.Sprintf("约 %.1f%% 额外 CPU（单实例估算上限；§21.1 稳态预算线 %.0f%%）", cpuPct, steadyStateCPUBudgetPct),
		SpansPerSHint: fmt.Sprintf("约 %.0f spans/s（%d 个匹配实例合计，采样率 %.2f）",
			spansPerS, matchedInstances, rate),
		DataVolumeHint: fmt.Sprintf("约 %.1f MB 诊断数据（%d 分钟会话期估算）", totalMB, durationMin),
		RiskNotes:      []string{},
	}
	if cpuPct > steadyStateCPUBudgetPct {
		est.RiskNotes = append(est.RiskNotes,
			fmt.Sprintf("估算额外 CPU %.1f%% 超出稳态预算线 %.0f%%：会话达到阈值时 Agent 侧自动降采样或停止（§21.2）", cpuPct, steadyStateCPUBudgetPct))
	}
	for _, c := range caps {
		switch c {
		case DiagCapSQLDetail:
			est.RiskNotes = append(est.RiskNotes, "SQL 细节在指纹+脱敏口径下展开，默认仍不采集 bind values（§11.1）")
		case DiagCapFunctionProbe:
			est.RiskNotes = append(est.RiskNotes, "函数探针为最高开销能力：仅限白名单函数，禁止捕获入参/返回值/局部变量（§11.2）")
		case DiagCapThreadBlock:
			est.RiskNotes = append(est.RiskNotes, "线程栈可能包含类名/路径等业务信息，按敏感数据处理（§11.3）")
		case DiagCapGCDetail:
			est.RiskNotes = append(est.RiskNotes, "GC 明细提高运行时采样频率，需关联堆/吞吐/版本解读（§11.3）")
		case DiagCapMQWait:
			est.RiskNotes = append(est.RiskNotes, "消息等待明细不记录消息正文与业务主键（§11.4）")
		}
	}
	est.RiskNotes = append(est.RiskNotes, "诊断数据全部携带 diagnostic_session_id，可定位到会话、发起人与有效期（§21.2）")
	if matchedInstances == 0 {
		est.RiskNotes = append(est.RiskNotes, "当前无匹配在线 Agent：正式创建将被拒绝（422）")
	}
	return est
}
