// evaluate.go 转发前检查链（§1.4 固定序；Evaluate 线契约逐字冻结——
// B2 直接消费，签名不得改名改形）。
package mcpguard

import (
	"encoding/json"
	"strconv"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser/mcprpc"
)

// chainRecorder 检查链记录器（逐项独立 Finding + 覆盖读数收集）。
type chainRecorder struct {
	ctx           *dsctx.RequestContext
	cov           *coverage.Observation
	cfg           *Config
	ep            *Endpoint
	engineProtect bool

	tool    *Tool
	subject string // VERIFIED 主体（未验证为空串——ACL/预算维度如实）
	tenant  string
	roles   []string
}

// doubleGate 双闸（绑定 PROTECT × 引擎 PROTECT）。
func (rc *chainRecorder) doubleGate() bool {
	return rc.ep.Mode == ModeProtect && rc.engineProtect
}

// violation 违规定案（双闸全真 Category=BLOCK 可定案，否则 OBSERVE 拟动作；
// 证据注入 mcp_error_code/mcp_http_status 供 apiprotect 协议化分流）。
func (rc *chainRecorder) violation(ruleID string, code, httpStatus int, evidence map[string]string) {
	category := "OBSERVE"
	if rc.doubleGate() {
		category = "BLOCK"
	}
	if evidence == nil {
		evidence = map[string]string{}
	}
	evidence["mcp_error_code"] = strconv.Itoa(code)
	evidence["mcp_http_status"] = strconv.Itoa(httpStatus)
	rc.ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "mcpguard",
		RuleID:     ruleID,
		Category:   category,
		Severity:   "HIGH",
		Confidence: 1.0,
		Evidence:   evidence,
	})
}

// Evaluate tools/call 转发前检查链（线契约逐字冻结，§5 批次 B2）：
// 绑定命中且内容为 tools/call 时按固定顺序检查（前一项失败即短路，逐项独立
// Finding；全链在统一决策前完成，转发前阻断语义成立）；非 tools/call 方法 →
// 覆盖 NOT_APPLICABLE(MCP-NA-METHOD-001) 转发不动（词表外方法由存量
// llm.mcp_unknown_method 单源记录，mcpguard 不重复产出）。
func Evaluate(ctx *dsctx.RequestContext, msg *mcprpc.Message, cfg *Config, jwtRes *jwtverify.VerificationResult, appID string, engineProtect bool) *coverage.Observation {
	if ctx == nil || msg == nil || cfg == nil {
		return nil
	}
	ep := cfg.resolvedEndpoint(appID)
	if ep == nil {
		return nil
	}
	rc := &chainRecorder{ctx: ctx, cov: baseCoverage(ctx), cfg: cfg, ep: ep, engineProtect: engineProtect}
	rc.cov.Scope.Bytes = int64(msg.Stats.Bytes)

	// 方法门：tools/call 以外方法转发不动（覆盖 NOT_APPLICABLE——G1 深检只对
	// tools/call；词表外方法=llm.mcp_unknown_method 单源，mcpguard 不重复产出）
	if msg.Method != "tools/call" {
		rc.cov.Status = coverage.StatusNotApplicable
		rc.cov.ReasonCode = coverage.ReasonNAFrozenRule
		rc.cov.NARuleID = "MCP-NA-METHOD-001"
		rc.emitMethodCoverage("not_applicable", "", msg, nil)
		return rc.cov
	}

	// 工具名提取（params.name 字符串；缺失/非串 → 形态不可判定 SKIPPED(COV_PARSE_ERROR)
	// 放行不误断——不冒充工具判定）
	toolName, ok := toolNameFromParams(msg.Params)
	if !ok {
		rc.cov.Status = coverage.StatusSkipped
		rc.cov.ReasonCode = coverage.ReasonParseError
		rc.emitMethodCoverage("skipped", skipReasonParseError, msg, nil)
		return rc.cov
	}
	// 最小调用上下文先行留存（§1.11 id 回显的消费点——错误对象 id 回显请求 id
	// （可解析时）；白名单后的完整上下文（Tool/Catalog）在步骤 2 命中后覆盖，
	// 响应相位结果检查只认完整上下文（Tool+Catalog 非空））
	setCallContext(ctx, &CallContext{Config: cfg, Message: msg, Mode: ep.Mode})

	// 目录门：缺失/摘要不符（装配已拒装）→ SKIPPED(COV_NO_CATALOG) 放行不误断
	// （不消费未验证摘要的目录；管理面差集可见，Warn 已在装配期留痕）
	catalog := ep.Catalog
	if catalog == nil {
		rc.cov.Status = coverage.StatusSkipped
		rc.cov.ReasonCode = coverage.ReasonNoCatalog
		rc.emitMethodCoverage("skipped", skipReasonNoCatalog, msg, nil)
		return rc.cov
	}

	// 步骤 1：可信主体（§1.4-1/§1.5：PROTECT 绑定要求 JWT VERIFIED）
	rc.subject, rc.tenant, rc.roles = verifiedTriple(jwtRes)
	if ep.Mode == ModeProtect {
		if jwtRes == nil {
			// jwt 未覆盖端点 → 依赖缺席 SKIPPED 放行+披露（UNKNOWN 恒不阻断；
			// 发布侧校验警示（§1.14），运行期只如实披露不升级为断）
			rc.ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "mcpguard",
				RuleID:   "mcpguard.dependency_unavailable",
				Category: "OBSERVE",
				Severity: "MEDIUM",
				Message:  "mcp protect binding endpoint not covered by jwt trust chain (fail-open, disclosed)",
				Evidence: map[string]string{"dependency_unavailable": "true", "dependency": "jwt_trust"},
			})
			rc.cov.Status = coverage.StatusSkipped
			rc.cov.ReasonCode = coverage.ReasonNoTrustedSubject
			rc.emitMethodCoverage("skipped", skipReasonNoTrustedSubject, msg, nil)
			return rc.cov
		}
		if jwtRes.Status != jwtverify.StatusVerified {
			rc.violation("mcp.subject_untrusted", CodeSubjectUntrusted, 403,
				map[string]string{"reason_code": "MCP_SUBJECT_UNTRUSTED"})
			rc.cov.Status = coverage.StatusPartial
			rc.cov.Truncated = true
			rc.emitMethodCoverage("partial", "", msg, nil)
			return rc.cov
		}
	}

	// 步骤 2：工具白名单（目录 APPROVED 集按名查——发布段只含 APPROVED，
	// 不在册与未审核同一不可调用语义）
	tool, found := catalog.Tools[toolName]
	if !found {
		rc.violation("mcp.tool_not_in_catalog", CodeToolDenied, 403,
			map[string]string{"tool": truncateString(toolName, 128), "catalog": catalog.Name,
				"reason_code": "MCP_TOOL_DENIED"})
		rc.cov.Status = coverage.StatusPartial
		rc.cov.Truncated = true
		rc.emitMethodCoverage("partial", "", msg, nil)
		return rc.cov
	}
	rc.tool = tool

	// 完整调用上下文覆盖（响应相位结果检查消费点——Tool+Catalog 非空才认；
	// 后续步骤成败不回收：OBSERVE 拟动作流响应侧照检）
	setCallContext(ctx, &CallContext{Config: cfg, Message: msg, Mode: ep.Mode, Tool: tool, Catalog: catalog})

	// 步骤 2b：目录 ACL（§1.5：allowed_principals/roles/tenants 逐维 AND——
	// 空=该维度不约束；仅消费 VERIFIED 信号，请求体/普通头/提示词文本中的
	// 角色声明一律不可信（§4.2-2 不变量））
	if !callerAuthorized(tool, jwtRes, rc.subject, rc.tenant, rc.roles) {
		rc.violation("mcp.caller_not_authorized", CodeToolDenied, 403,
			map[string]string{"tool": truncateString(toolName, 128), "reason_code": "MCP_TOOL_DENIED"})
		rc.cov.Status = coverage.StatusPartial
		rc.cov.Truncated = true
		rc.emitMethodCoverage("partial", "", msg, tool)
		return rc.cov
	}

	// arguments 解码一次（步骤 3/4 共用；msg.Params 已经 ParseMessage 全量校验为
	// 合法 JSON，解码理论不可失败——防御分支仍按形态不可判定 SKIPPED 放行）
	var argDoc struct {
		Arguments any `json:"arguments"`
	}
	if err := json.Unmarshal(msg.Params, &argDoc); err != nil {
		rc.cov.Status = coverage.StatusSkipped
		rc.cov.ReasonCode = coverage.ReasonParseError
		rc.emitMethodCoverage("skipped", skipReasonParseError, msg, tool)
		return rc.cov
	}

	// 步骤 3：参数 Schema 校验（§1.6；重复键先行——Schema 语义歧义与白名单互斥）
	if len(msg.Stats.DuplicatePaths) > 0 {
		rc.violation("mcp.json_duplicate_key", CodeArgumentRejected, 403,
			map[string]string{"tool": truncateString(toolName, 128), "paths": strings.Join(msg.Stats.DuplicatePaths, ","),
				"reason_code": "MCP_ARGUMENT_REJECTED"})
		rc.cov.Status = coverage.StatusPartial
		rc.cov.Truncated = true
		rc.emitMethodCoverage("partial", "", msg, tool)
		return rc.cov
	}
	schemaNote := ""
	if tool.InputSchema == nil {
		schemaNote = skipReasonSchemaAbsent // input_schema 缺席 → Schema 校验 SKIPPED（结构预算照判）
	} else if tool.InputDegraded {
		schemaNote = skipReasonSchemaUnsupported // 不支持关键字降级 PARTIAL 如实（不冒充完整校验）
	} else {
		if violations := ValidateSchema(tool.InputSchema, argDoc.Arguments); len(violations) > 0 {
			first := violations[0]
			rc.violation("mcp.arg_schema_violation", CodeArgumentRejected, 403,
				map[string]string{"tool": truncateString(toolName, 128), "rule": first.Rule, "path": first.Path,
					"count": strconv.Itoa(len(violations)), "reason_code": "MCP_ARGUMENT_REJECTED"})
			rc.cov.Status = coverage.StatusPartial
			rc.cov.Truncated = true
			rc.emitMethodCoverage("partial", "", msg, tool)
			return rc.cov
		}
	}

	// 步骤 4：路径/域名范围（arg_constraints 逐条 AND；证据不落原值——
	// 字段路径+约束种类+值长度+受控摘要）
	if bad := rc.checkArgConstraints(tool, argDoc.Arguments); bad != nil {
		rc.violation("mcp.arg_scope_violation", CodeArgumentRejected, 403, *bad)
		rc.cov.Status = coverage.StatusPartial
		rc.cov.Truncated = true
		rc.emitMethodCoverage("partial", "", msg, tool)
		return rc.cov
	}

	// 步骤 5：调用预算（max_calls_per_minute>0；滑窗（工具，主体）——
	// 进程内默认内存，behavior_store Valkey 时共享，多节点一致性以存储为准，
	// 存储缺席按进程内如实披露不冒充一致）
	if tool.MaxCallsPerMinute > 0 {
		count, _ := detectors.MCPCallCounts(ctx, "mcpcall|"+tool.Hash+"|"+rc.subject)
		if count > tool.MaxCallsPerMinute {
			rc.ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "mcpguard",
				RuleID:   "mcp.call_budget_exceeded",
				Category: callBudgetCategory(rc.doubleGate()),
				Severity: "HIGH",
				Message:  "mcp tool call budget exceeded",
				Evidence: map[string]string{
					"tool": truncateString(toolName, 128), "window_count": strconv.Itoa(count),
					"limit": strconv.Itoa(tool.MaxCallsPerMinute), "window": "1m",
					"mcp_error_code": strconv.Itoa(CodeBudgetExceeded), "mcp_http_status": "429",
				},
				Confidence: 1.0,
			})
			rc.cov.Status = coverage.StatusPartial
			rc.cov.Truncated = true
			rc.emitMethodCoverage("partial", "", msg, tool)
			return rc.cov
		}
	}

	// 步骤 6：高风险默认拒绝（§1.8：risk_level=HIGH 或 approval_required=true →
	// 默认拒绝+可关联安全事件；OBSERVE 记录拟动作——审批闭环后续子阶段不冒充）
	if tool.RiskLevel == RiskHigh || tool.ApprovalRequired {
		rc.violation("mcp.high_risk_denied", CodeToolDenied, 403,
			map[string]string{"tool": truncateString(toolName, 128), "tool_hash": tool.Hash,
				"risk_level": tool.RiskLevel, "approval_required": strconv.FormatBool(tool.ApprovalRequired),
				"reason_code": "MCP_TOOL_DENIED"})
		rc.cov.Status = coverage.StatusPartial
		rc.cov.Truncated = true
		rc.emitMethodCoverage("partial", "", msg, tool)
		return rc.cov
	}

	// 全链通过：FULL（tools/call 全链检查完成）
	rc.cov.Status = coverage.StatusFull
	rc.emitMethodCoverage("full", schemaNote, msg, tool)
	return rc.cov
}

// callBudgetCategory 调用预算定案类别（RATE_LIMIT 语义——决策引擎 429 定案链；
// 双闸全真才升级，否则 OBSERVE 拟动作）。
func callBudgetCategory(doubleGate bool) string {
	if doubleGate {
		return "RATE_LIMIT"
	}
	return "OBSERVE"
}

// emitMethodCoverage 检查链覆盖记录（每候选请求一条；method(≤128)/tool/catalog/
// catalog_hash 前 8/schema 降级注记读数与实际一致）。
func (rc *chainRecorder) emitMethodCoverage(completion, note string, msg *mcprpc.Message, tool *Tool) {
	evidence := map[string]string{
		"method":         truncateString(msg.Method, 128),
		"bytes_examined": strconv.Itoa(msg.Stats.Bytes),
	}
	if tool != nil {
		evidence["tool"] = truncateString(tool.Name, 128)
	}
	if rc.ep.Catalog != nil {
		evidence["catalog"] = rc.ep.Catalog.Name
		// catalog_hash 前 8 取 hex 摘要段（域前缀 "mcp-catalog-sha256:v1:" 为常量，
		// 前 8 取域前缀则无信息量——与 grpc descriptor_hash=sha256(content)[:8] 同语义）
		if h := strings.TrimPrefix(rc.ep.Catalog.Hash, "mcp-catalog-sha256:v1:"); h != "" {
			if len(h) > 8 {
				h = h[:8]
			}
			evidence["catalog_hash"] = h
		}
	}
	if note != "" {
		evidence["skip_reason"] = note
	}
	mergeHeadObs(rc.ctx, evidence)
	emitCoverageMatch(rc.ctx, rc.cov, evidence, completion, note)
}

// verifiedTriple VERIFIED 三字段提取（未 VERIFIED 全空——不冒充已验证身份）。
func verifiedTriple(jwtRes *jwtverify.VerificationResult) (subject, tenant string, roles []string) {
	if jwtRes == nil || jwtRes.Status != jwtverify.StatusVerified {
		return "", "", nil
	}
	return jwtRes.VerifiedPrincipalID, jwtRes.VerifiedTenantID, jwtRes.VerifiedRoles
}

// toolNameFromParams 工具名提取（params.name 字符串；缺失/非串/空 → false）。
func toolNameFromParams(params json.RawMessage) (string, bool) {
	if len(params) == 0 {
		return "", false
	}
	var doc struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &doc); err != nil {
		return "", false
	}
	name := strings.TrimSpace(doc.Name)
	return name, name != ""
}

// callerAuthorized 目录 ACL 逐维 AND（空=该维度不约束；仅 VERIFIED 信号）。
func callerAuthorized(tool *Tool, jwtRes *jwtverify.VerificationResult, subject, tenant string, roles []string) bool {
	verified := jwtRes != nil && jwtRes.Status == jwtverify.StatusVerified
	if len(tool.AllowedPrincipals) > 0 {
		if !verified || !containsString(tool.AllowedPrincipals, subject) {
			return false
		}
	}
	if len(tool.AllowedRoles) > 0 {
		if !verified || !intersects(tool.AllowedRoles, roles) {
			return false
		}
	}
	if len(tool.AllowedTenants) > 0 {
		if !verified || !containsString(tool.AllowedTenants, tenant) {
			return false
		}
	}
	return true
}

func containsString(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}
