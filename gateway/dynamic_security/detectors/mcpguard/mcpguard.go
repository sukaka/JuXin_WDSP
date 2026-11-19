// Package mcpguard MCP 工具调用安全执行器（NG-MCP G1 批次 B2，
// docs/nextgen/NG-MCP-g1-toolcall.md §1.2~§1.12 + §5 批次 B2 线契约）。
//
// 识别形态（D2 绑定驱动）：命中本应用 api_mcp_bindings 登记 endpoint_path
// （精确匹配、大小写敏感）且方法 POST 且 Content-Type JSON 族 → 候选；
// 绑定缺失 = 零行为（NG-T-C01；现状启发式 llm.mcp_* 观测并行不动）。
//
// 转发前检查链（tools/call，§1.4 固定序——前一项失败即短路，逐项独立 Finding）：
//  1. 可信主体（PROTECT 绑定要求 JWT VERIFIED；jwt 未覆盖端点=依赖缺席
//     SKIPPED(COV_NO_TRUSTED_SUBJECT) 放行+披露；UNVERIFIED → mcp.subject_untrusted）；
//  2. 工具白名单（目录 APPROVED 集按名查 tool_hash → mcp.tool_not_in_catalog）；
//     2b. 目录 ACL（allowed_principals/roles/tenants 逐维 AND，仅消费 VERIFIED
//     信号 → mcp.caller_not_authorized——§1.5 授权点，插位登记：工具在册后、
//     Schema 前，工具存在才谈谁可调）；
//  3. 参数 Schema 校验（§1.6 冻结子集+结构预算+重复键 → mcp.arg_schema_violation /
//     mcp.json_duplicate_key / mcp.budget_exceeded）；
//  4. 路径/域名范围（arg_constraints path_prefix/domain_suffix → mcp.arg_scope_violation）；
//  5. 调用预算（max_calls_per_minute>0 按（工具，主体）滑窗 → mcp.call_budget_exceeded，
//     429 语义——进程内默认内存，behavior_store Valkey 时共享，存储缺席如实披露）；
//  6. 高风险默认拒绝（risk_level=HIGH 或 approval_required → mcp.high_risk_denied）。
//
// 定案语义（grpcguard/flowguard 同纪律双闸）：违规 Finding 仅当 绑定 mode=PROTECT
// 且引擎 PROTECT 全真时 Category=BLOCK 可定案（apiprotect 按 mcp_error_code/
// mcp_http_status 证据分流 writeMCPErrorResponse——JSON-RPC 错误对象 committed
// 直写）；否则 OBSERVE 拟动作。UNKNOWN 恒不阻断（目录缺失/解析失败/Schema 降级/
// jwt 未覆盖全 SKIPPED 五态如实+mcp.coverage_v1，§1.9）。
//
// 证据纪律（§1.4/§14.3 红线）：只落工具名/规则名/字段点路径/类型/长度/受控摘要
// （identity_salt 加盐 HMAC 指纹）/request_id——不落参数原值、不落 Token、
// 不落提示词原文。
package mcpguard

import (
	"net/http"
	"strconv"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser/mcprpc"
)

// 模式词表（绑定 mode；缺省 OBSERVE——NG-T-C01 零变化承载）。
const (
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"
)

// 错误码表（§1.11 冻结：产品扩展 JSON-RPC 保留段 -32000~-32099 注册；
// 标准码 -32700/-32600/-32601/-32602/-32603 网关一律不使用（源站语义不冒用））。
const (
	CodeSubjectUntrusted   = -32010 // MCP_SUBJECT_UNTRUSTED    403 准入式拒绝（§1.4-1）
	CodeToolDenied         = -32011 // MCP_TOOL_DENIED          403 不在册/未授权/范围/高风险
	CodeArgumentRejected   = -32012 // MCP_ARGUMENT_REJECTED    403 Schema/重复键/参数范围
	CodeBudgetExceeded     = -32013 // MCP_BUDGET_EXCEEDED      413 消息预算 / 429 调用预算
	CodeResultBlocked      = -32014 // MCP_RESULT_BLOCKED       403 结果检查（仅未外发可干净返回）
	codeDependencyReserved = -32015 // MCP_DEPENDENCY_UNAVAILABLE 预留（G1 不产出——UNKNOWN 恒不阻断）
)

// 风险与分类词表（目录行；缺省值由 server 导入语义保证，网关消费侧防御归一）。
const (
	RiskHigh                   = "HIGH"
	ClassificationConfidential = "CONFIDENTIAL"
)

// 约束种类词表（arg_constraints.kind；G1 两种确定性约束）。
const (
	ConstraintPathPrefix   = "path_prefix"
	ConstraintDomainSuffix = "domain_suffix"
)

// Tool 目录工具行（发布段 api_mcp_tool_catalogs[].tools[] 消费形态）。
type Tool struct {
	Name               string
	Version            string
	Hash               string // tool_hash（审批绑定不可变摘要）
	RiskLevel          string
	DataClassification string
	CapabilityTags     []string
	AllowedPrincipals  []string
	AllowedRoles       []string
	AllowedTenants     []string
	ApprovalRequired   bool
	MaxCallsPerMinute  int
	// InputSchema/OutputSchema 冻结子集编译产物（nil = 缺席——Schema 校验 SKIPPED，
	// 结构预算与重复键在协议层照判）。
	InputSchema  *Schema
	OutputSchema *Schema
	// InputDegraded/OutputDegraded 含不支持关键字（登记降级——不冒充完整校验，
	// 覆盖 PARTIAL 如实；键名证据 ≤8）。
	InputDegraded        bool
	OutputDegraded       bool
	InputUnsupportedKeys []string
	// ArgConstraints 路径/域名约束（G1 两种；逐条 AND）。
	ArgConstraints []ArgConstraint
}

// ArgConstraint 一条参数范围约束（证据不落原值）。
type ArgConstraint struct {
	Field string   // arguments 顶层字段名（一级；嵌套点路径列后续增强点如实标注）
	Kind  string   // path_prefix|domain_suffix
	Allow []string // 允许前缀/后缀集（空=该条不约束）
}

// Catalog 工具目录（装配期 catalog_hash 重算比对通过——不消费未验证摘要的目录）。
type Catalog struct {
	Name            string
	ServiceIdentity string
	ProtocolVersion string
	Hash            string // catalog_hash（已验证）
	Tools           map[string]*Tool
}

// Endpoint 绑定端点（per-app endpoint_path → 目录+mode）。
type Endpoint struct {
	Catalog *Catalog // nil = 目录缺失/摘要不符（运行期 SKIPPED(COV_NO_CATALOG) 放行不误断）
	Mode    string   // OBSERVE|PROTECT（装配归一）
}

// Config mcpguard 装配产物（Provision 后只读，热加载经实例整体替换）。
type Config struct {
	// Apps application_id → endpoint_path → Endpoint（绑定驱动识别的全量映射）。
	Apps map[string]map[string]Endpoint
	// IdentitySalt 受控摘要 HMAC 盐（identity_salt 同源；空 = 固定域分隔前缀代替）。
	IdentitySalt string
	// resolved ForEndpoint 作用域解析产物（Evaluate/EvaluateResult 消费——
	// 线契约签名不含 endpoint_path，绑定解析由 ForEndpoint 在调用侧完成）。
	resolved *Endpoint
}

// ForEndpoint 端点解析（规范化路径后精确匹配、大小写敏感——消除 '//' 与 '.'/'..' 差异）；
// 命中返回单端点作用域 Config（resolved 承载），未命中 nil（零行为）。
func (c *Config) ForEndpoint(appID, endpointPath string) *Config {
	if c == nil {
		return nil
	}
	eps, ok := c.Apps[appID]
	if !ok {
		return nil
	}
	canon := normalizer.CanonicalPath(endpointPath)
	ep, ok := eps[canon]
	if !ok {
		for k, v := range eps {
			if normalizer.CanonicalPath(k) == canon {
				ep = v
				ok = true
				break
			}
		}
		if !ok {
			return nil
		}
	}
	e := ep
	return &Config{IdentitySalt: c.IdentitySalt, resolved: &e}
}

// resolvedEndpoint Evaluate/EvaluateResult 内部解析（ForEndpoint 作用域防御：
// 未按作用域传入时按 appID 单值兜底——装配与挂点恒经 ForEndpoint，防御分支
// 仅为契约稳固）。
func (c *Config) resolvedEndpoint(appID string) *Endpoint {
	if c == nil {
		return nil
	}
	if c.resolved != nil {
		return c.resolved
	}
	eps := c.Apps[appID]
	if len(eps) != 1 {
		return nil
	}
	for _, ep := range eps {
		e := ep
		return &e
	}
	return nil
}

// CallContext tools/call 调用上下文（请求相位检查链产物——响应相位结果检查
// （EvaluateResult）与错误对象 id 回显的消费点；经请求上下文扩展传递，
// 装配侧（pipeline/response/SSE 捕获）按 CallFromContext 读取）。
type CallContext struct {
	Config  *Config         // 单端点作用域配置（ForEndpoint 产物引用）
	Message *mcprpc.Message // 请求消息（工具名提取与 id 回显源）
	Mode    string          // 绑定 mode
	Tool    *Tool           // 命中工具行（结果检查 output_schema 与 data_classification 源）
	Catalog *Catalog        // 命中目录（覆盖读数 catalog/catalog_hash 前 8）
}

// CallFromContext 取本请求 MCP 调用上下文（无调用为零值 nil——响应侧零行为）。
func CallFromContext(ctx *dsctx.RequestContext) *CallContext {
	if ctx == nil {
		return nil
	}
	v, ok := ctx.GetExtension("mcp.call")
	if !ok {
		return nil
	}
	call, _ := v.(*CallContext)
	return call
}

func setCallContext(ctx *dsctx.RequestContext, call *CallContext) {
	ctx.SetExtension("mcp.call", call)
}

// ---------- 候选判定（方法/Content-Type 门） ----------

// EvaluateCandidate 候选判定（pipeline 挂点调用；绑定已命中（ForEndpoint 非 nil）
// 为前提）。返回 true = POST+JSON 族候选（调用侧继续 ParseMessage+Evaluate）；
// 否则产出对应覆盖并返回 false：
//   - GET：观测（会话头存在性——原值类凭据不落事件，只记存在性）+ 覆盖
//     NOT_APPLICABLE(MCP-NA-METHOD-001)（结果检查不承诺覆盖该流，§1.2/§1.7）；
//   - 非 POST 其他方法：SKIPPED(COV_NOT_MCP)（非候选形态）；
//   - POST 非 JSON 族 Content-Type：SKIPPED(COV_NOT_MCP)。
func EvaluateCandidate(ctx *dsctx.RequestContext, p *parser.Parsed, r *http.Request, cfg *Config, appID string) (bool, *coverage.Observation) {
	ep := cfg.resolvedEndpoint(appID)
	if ep == nil {
		return false, nil // 未绑定（防御——调用侧已过滤）
	}
	cov := baseCoverage(ctx)
	method := strings.ToUpper(p.Method)
	switch {
	case method == "GET":
		// 会话头观测（存在性+盐指纹纪律：原值类凭据不落事件——§1.2/§14.3）
		evidence := map[string]string{}
		if hdr := headerOf(r, "Mcp-Session-Id"); hdr != "" {
			evidence["session_id_present"] = "true"
			evidence["session_id_fp"] = fingerprint(cfg.IdentitySalt, hdr)
		}
		if v := headerOf(r, "MCP-Protocol-Version"); v != "" {
			evidence["protocol_version"] = truncateString(v, 64)
		}
		emitCoverageMatch(ctx, cov, evidence, "not_applicable", "")
		cov.Status = coverage.StatusNotApplicable
		cov.ReasonCode = coverage.ReasonNAFrozenRule
		cov.NARuleID = "MCP-NA-METHOD-001"
		return false, cov
	case method != "POST":
		emitCoverageMatch(ctx, cov, map[string]string{}, "skipped", skipReasonNotMCP)
		cov.Status = coverage.StatusSkipped
		cov.ReasonCode = coverage.ReasonNotMCP
		return false, cov
	default:
		if !isJSONFamily(p.ContentType) {
			emitCoverageMatch(ctx, cov, map[string]string{}, "skipped", skipReasonNotMCP)
			cov.Status = coverage.StatusSkipped
			cov.ReasonCode = coverage.ReasonNotMCP
			return false, cov
		}
		return true, nil
	}
}

// ---------- ParseMessage 错误分派 ----------

// HandleParseError ParseMessage 错误分派（pipeline 挂点调用；§1.2/§1.6/§1.9）：
//   - ErrShape（批处理数组）：mcp.unsupported_shape OBSERVE 记录 + 覆盖
//     NOT_APPLICABLE(COV_NA_FROZEN_RULE/NARuleID=MCP-NA-SHAPE-001) 放行不判攻击
//     （合法旧生态形态）；
//   - ErrMalformed（解析失败/形态不符）：SKIPPED(COV_PARSE_ERROR) 放行不误断
//     （UNKNOWN 红线；非绑定端点普通 JSON 不受影响）；
//   - ErrBudget（协议预算触顶）：mcp.budget_exceeded 违规（预算类——
//     双闸 BLOCK → -32013/413，否则 OBSERVE 拟动作），覆盖 PARTIAL 如实。
func HandleParseError(ctx *dsctx.RequestContext, perr error, cfg *Config, appID string, engineProtect bool, msgBytes int) *coverage.Observation {
	ep := cfg.resolvedEndpoint(appID)
	if ep == nil {
		return nil
	}
	cov := baseCoverage(ctx)
	cov.Scope.Bytes = int64(msgBytes)
	switch {
	case errorsIsShape(perr):
		rc := &chainRecorder{ctx: ctx, cov: cov, cfg: cfg, ep: ep, engineProtect: engineProtect}
		if rc.doubleGate() {
			rc.violation("mcp.unsupported_shape", CodeArgumentRejected, http.StatusForbidden,
				map[string]string{"shape": "batch_array", "reason_code": "MCP_UNSUPPORTED_SHAPE"})
			emitCoverageMatch(ctx, cov, map[string]string{"shape": "batch_array"}, "partial", "")
			cov.Status = coverage.StatusPartial
			return cov
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "mcpguard",
			RuleID:   "mcp.unsupported_shape",
			Category: "OBSERVE",
			Severity: "LOW",
			Message:  "mcp batch shape (removed in frozen protocol revision): pass through in OBSERVE mode",
			Evidence: map[string]string{"shape": "batch_array"},
		})
		emitCoverageMatch(ctx, cov, map[string]string{"shape": "batch_array"}, "not_applicable", "")
		cov.Status = coverage.StatusNotApplicable
		cov.ReasonCode = coverage.ReasonNAFrozenRule
		cov.NARuleID = "MCP-NA-SHAPE-001"
		return cov
	case errorsIsBudget(perr):
		be := budgetErrorOf(perr)
		rc := &chainRecorder{ctx: ctx, cov: cov, cfg: cfg, ep: ep, engineProtect: engineProtect}
		rc.violation("mcp.budget_exceeded", CodeBudgetExceeded, 413,
			map[string]string{"rule": be.Rule, "actual": strconv.Itoa(be.Actual), "limit": strconv.Itoa(be.Limit)})
		cov.Status = coverage.StatusPartial
		cov.Truncated = true
		emitCoverageMatch(ctx, cov, map[string]string{"rule": be.Rule}, "partial", "")
		return cov
	default: // ErrMalformed
		emitCoverageMatch(ctx, cov, map[string]string{}, "skipped", skipReasonParseError)
		cov.Status = coverage.StatusSkipped
		cov.ReasonCode = coverage.ReasonParseError
		return cov
	}
}
