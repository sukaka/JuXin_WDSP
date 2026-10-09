// helpers.go mcpguard 内部辅助（错误分类/指纹/头取值/覆盖记录底座/JSON 族判定）。
package mcpguard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser/mcprpc"
)

// 跳过原因词表（mcp.coverage_v1 evidence.skip_reason；与 §1.2/§1.9/§1.12 命名一致）。
const (
	skipReasonNotMCP            = "not_mcp"
	skipReasonParseError        = "parse_error"
	skipReasonNoCatalog         = "no_catalog"
	skipReasonNoTrustedSubject  = "no_trusted_subject"
	skipReasonSchemaAbsent      = "schema_absent"
	skipReasonSchemaUnsupported = "schema_unsupported_keywords"
)

// errorsIsShape/errorsIsBudget/errorsIsMalformed ParseMessage 三分类判定。
func errorsIsShape(err error) bool { return errors.Is(err, mcprpc.ErrShape) }

func errorsIsBudget(err error) bool { return errors.Is(err, mcprpc.ErrBudget) }

// budgetErrorOf 取预算明细（ParseMessage ErrBudget 链恒为 *mcprpc.BudgetError）。
func budgetErrorOf(err error) *mcprpc.BudgetError {
	var be *mcprpc.BudgetError
	if errors.As(err, &be) {
		return be
	}
	return &mcprpc.BudgetError{Rule: "unknown"}
}

// fingerprint 受控摘要（identity_salt 加盐 HMAC-SHA256 截断 16 字节 hex；
// 空盐走固定域分隔前缀——detectors.Fingerprint 同纪律）。原值不出本函数。
func fingerprint(salt, value string) string {
	if salt == "" {
		salt = "jiuzhang-wdsp-fp-default\x00"
	}
	m := hmac.New(sha256.New, []byte(salt))
	_, _ = m.Write([]byte("mcpguard\x00"))
	_, _ = m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// headerOf 请求头取值（nil 安全）。
func headerOf(r *http.Request, name string) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get(name))
}

// truncateString 截断辅助（观测字段限长）。
func truncateString(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

// isJSONFamily JSON 族 Content-Type 判定（application/json 与 +json 后缀族；
// 容忍参数——绑定候选判定形态（§1.2））。
func isJSONFamily(contentType string) bool {
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	return mt == "application/json" || strings.HasSuffix(mt, "+json")
}

// baseCoverage 覆盖观测底座（detector=mcpguard、phase=request、
// 方向 request、声明消息 1——响应侧读数由响应链另行发射）。
func baseCoverage(ctx *dsctx.RequestContext) *coverage.Observation {
	return &coverage.Observation{
		RequestID: ctx.RequestID,
		Detector:  "mcpguard",
		Phase:     coverage.PhaseRequest,
		Scope:     coverage.ScopeDeclared{Messages: 1, Direction: "request"},
	}
}

// emitCoverageMatch mcp.coverage_v1 INFO 记录（§1.12：每候选请求一条——
// direction/method(≤128)/tool/catalog/catalog_hash 前 8/bytes_examined/completion/
// skip_reason 读数与实际一致；INFO 零分值永不贡献攻击分）。
func emitCoverageMatch(ctx *dsctx.RequestContext, cov *coverage.Observation, evidence map[string]string, completion, skipReason string) {
	if evidence == nil {
		evidence = map[string]string{}
	}
	evidence["direction"] = "request"
	evidence["completion"] = completion
	if skipReason != "" {
		evidence["skip_reason"] = skipReason
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "mcpguard",
		RuleID:   "mcp.coverage_v1",
		Category: "INFO",
		Severity: "INFO",
		Message:  "mcp candidate coverage",
		Evidence: evidence,
	})
}
