// graphql.go GraphQL 成本预算链路（NG-GQL-03 pipeline 执行段）：
// 识别 → gqlast.ParseBounded（五道硬边界）→ SelectOperation（NG-T-G01 只算选定者）
// → trusted 文档直通 → CostOfCached（LRU，键含策略版本）→ 单请求预算 → 时间窗预算。
//
// 纪律（契约，不可偏离）：
//   - 默认关闭：策略段 nil/Enabled=false 时管线零行为变化（仅覆盖观测按契约记账）；
//   - 挂点在 Admission 短路之后、统一决策之前，不移动 AGENTS.md 请求处理顺序；
//   - 失败分流（NG-T-G06）：结构准入失败 reason=GQL_ADMISSION_REJECTED，
//     成本超限 reason=GQL_COST_EXCEEDED，时间窗超限 reason=GQL_WINDOW_EXCEEDED；
//     PROTECT 记 category=BLOCK（取得决策阻断资格），OBSERVE 全量只记录不实断；
//   - 阻断资格：graphql 检测器一律用 category=BLOCK（PROTECT）——category=BLOCK 即
//     决策引擎阻断资格（engine.go §115），不依赖可信源名单；
//   - 证据脱敏：evidence 只含 cost/budget/reason/operation_kind/error_kind，
//     绝不含查询文本/变量值；
//   - 覆盖观测（NG-COV-01）：每个 GraphQL 分类请求一条 detector="graphql.cost_v1"
//     （SKIPPED=策略未启用 COV_DISABLED；FULL=完成；PARTIAL=超硬边界 COV_INPUT_TRUNCATED
//     或语法类失败 COV_PARSE_ERROR）；非 GraphQL 请求不产生该检测器记录（避免噪音洪流）；
//   - 时间窗预算为可降级限速类：WindowStore 未注入时用进程内定窗（本批默认形态；
//     Valkey 注入点保留——detectors StoreOverrides 窗口原语为计数型不适配 token 型，
//     接入后续批次，docs/nextgen/NG-GQL-03-wiring.md 注明边界）。
package pipeline

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/gqlast"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// GraphQL 失败分流 reason code（NG-T-G06 冻结枚举；响应 extensions.code 与 evidence.reason 共用）。
const (
	GQLReasonAdmissionRejected = "GQL_ADMISSION_REJECTED" // 结构准入失败（语法/多操作/超硬边界）
	GQLReasonCostExceeded      = "GQL_COST_EXCEEDED"      // 单请求成本超预算
	GQLReasonWindowExceeded    = "GQL_WINDOW_EXCEEDED"    // 时间窗预算超限
	GQLReasonTrustedDoc        = "GQL_TRUSTED_DOC"        // 可信文档直通（免成本判定）
)

// graphqlDetector 决策 Finding 的 detector 名（网关 GraphQL 协议错误 JSON 渲染分支按此识别）。
const graphqlDetector = "graphql"

// graphqlCovDetector 覆盖观测 detector 名（契约 §6）。
const graphqlCovDetector = "graphql.cost_v1"

// GraphQLPolicy GraphQL 成本预算策略（发布通道下发 api_graphql 段，按应用；
// nil/Enabled=false = 关闭，管线零行为变化）。
type GraphQLPolicy struct {
	Enabled           bool
	Limits            gqlast.Limits        // 解析硬边界覆盖（零值字段取 gqlast 默认）
	Weights           gqlast.WeightsConfig // 权重三层覆盖（Type.field > *.field > 默认/内省特判）
	Budget            gqlast.BudgetConfig  // 单请求 + 时间窗预算
	TrustedDocDigests []string             // 可信文档摘要白名单（gqlast.DigestDocument 口径；
	// APQ 摘要不自动可信——白名单即全部可信依据）
	WindowStore WindowBudgetStore // 时间窗状态（nil = 进程内定窗默认形态）
}

// WindowBudgetStore GraphQL 时间窗成本状态（app+tenant 键定窗累计）。
type WindowBudgetStore interface {
	// AddAndSum 本窗累计加 cost 并返回加后总额（窗口按 windowSeconds 对齐自然边界滚动）。
	AddAndSum(key string, cost, windowSeconds int64, now time.Time) int64
}

// graphQLCostCache 管线级成本缓存单例（D9：变量不求值故成本与变量值无关；
// 键含文档摘要+schema 版本+策略版本——策略变更自动失效）。
var graphQLCostCache = gqlast.NewCostCache(1000)

// memWindowBudgetStore 进程内定窗预算存储（LRU 定容；本批默认形态）。
type memWindowBudgetStore struct {
	mu      sync.Mutex
	max     int
	buckets map[string]*windowBucket
	order   []string
}

type windowBucket struct {
	windowStart int64
	sum         int64
}

// NewMemoryWindowBudgetStore 构造进程内定窗预算存储（maxKeys≤0 取 10000）。
func NewMemoryWindowBudgetStore(maxKeys int) WindowBudgetStore {
	if maxKeys <= 0 {
		maxKeys = 10000
	}
	return &memWindowBudgetStore{max: maxKeys, buckets: map[string]*windowBucket{}}
}

func (m *memWindowBudgetStore) AddAndSum(key string, cost, windowSeconds int64, now time.Time) int64 {
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	ws := now.Unix() / windowSeconds * windowSeconds
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.buckets[key]
	if !ok {
		if len(m.order) >= m.max {
			delete(m.buckets, m.order[0])
			m.order = m.order[1:]
		}
		b = &windowBucket{windowStart: ws}
		m.buckets[key] = b
		m.order = append(m.order, key)
	}
	if b.windowStart != ws {
		b.windowStart = ws
		b.sum = 0
	}
	b.sum += cost
	return b.sum
}

func isGraphQLCandidate(parsed *parser.Parsed) bool {
	if parsed == nil {
		return false
	}
	if parsed.GraphQLQuery != "" {
		return true
	}
	ct := strings.ToLower(parsed.ContentType)
	if strings.Contains(ct, "application/graphql") {
		return true
	}
	p := strings.ToLower(normalizer.CanonicalPath(parsed.RawPath))
	if strings.Contains(p, "/graphql") && (parsed.Method == http.MethodPost || parsed.Method == http.MethodPut || parsed.Method == http.MethodPatch) {
		return true
	}
	return false
}

// checkGraphQL GraphQL 判定（Admission 短路之后、统一决策之前调用）。
// 非 GraphQL 请求直返（零记录零开销）；GraphQL 分类请求按策略执行并记覆盖观测。
// 当请求体因超解析上限（>1MiB）或超保全上限（>4MiB）被截断时，GraphQL 候选端点按
// ErrDocTooLarge 走结构准入失败（PROTECT 下阻断，禁止借大请求体绕过 GraphQL 防护）。
func (cfg *Config) checkGraphQL(ctx *dsctx.RequestContext, r *http.Request, parsed *parser.Parsed, mode decision.Mode, ek string) {
	if parsed == nil {
		return
	}
	pol := cfg.GraphQL
	if parsed.GraphQLQuery == "" {
		if parsed.BodyTruncated && isGraphQLCandidate(parsed) {
			if pol == nil || !pol.Enabled {
				cfg.emitGraphQLCov(ctx, ek, int64(parsed.BodySize), int64(parsed.BodySize), coverage.StatusSkipped, coverage.ReasonDisabled, true)
				return
			}
			docBytes := int64(parsed.BodySize)
			if r != nil && r.ContentLength > docBytes {
				docBytes = r.ContentLength
			}
			cfg.graphQLAdmissionFail(ctx, ek, &gqlast.Error{
				Kind:    gqlast.ErrDocTooLarge,
				Message: "graphql request body exceeds inspection limit",
			}, docBytes, mode)
		}
		return // 非 GraphQL：不产生该检测器任何记录
	}
	docBytes := int64(len(parsed.GraphQLQuery))
	if pol == nil || !pol.Enabled {
		cfg.emitGraphQLCov(ctx, ek, docBytes, docBytes, coverage.StatusSkipped, coverage.ReasonDisabled, false)
		return
	}

	query := parsed.GraphQLQuery
	// 1) 有界解析（五道硬边界；错误分类 ErrorKind）
	doc, err := gqlast.ParseBounded(query, pol.Limits)
	if err != nil {
		cfg.graphQLAdmissionFail(ctx, ek, err, docBytes, mode)
		return
	}
	// 2) 操作选择（NG-T-G01：多 operation 只执行被选定者，其余不展开不计成本；
	// 按客户端协议字段显式指定的 operationName 选择——推断名不得冒充指定）
	op, err := gqlast.SelectOperation(doc, parsed.GraphQLOperationNameSpecified)
	if err != nil {
		cfg.graphQLAdmissionFail(ctx, ek, err, docBytes, mode)
		return
	}
	// 3) 可信文档直通（免成本判定但照常解析与操作选择——上两步已完成；
	// APQ 摘要不自动可信，白名单即全部可信依据）
	digest := gqlast.DigestDocument(query)
	for _, d := range pol.TrustedDocDigests {
		if d == digest {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector: graphqlDetector, RuleID: "gql.trusted_doc",
				Category: "OBSERVE", Severity: "INFO",
				Message:  "trusted graphql document (digest allowlisted), cost check bypassed",
				Evidence: map[string]string{"reason": GQLReasonTrustedDoc, "doc_digest": digest, "operation_kind": op.Kind},
			})
			cfg.emitGraphQLCov(ctx, ek, docBytes, docBytes, coverage.StatusFull, "", false)
			return
		}
	}
	// 4) 成本计算（缓存键：文档摘要 + schema 版本（无 schema 常量）+ 策略版本）
	out := gqlast.CostOfCached(graphQLCostCache, doc, op, pol.Weights, pol.Budget, "noschema-v1", cfg.PolicyVersion)
	// 5) 单请求预算判定
	if out.Exceeded {
		cfg.graphQLBudgetFail(ctx, ek, "gql.cost_v1", GQLReasonCostExceeded, op.Kind, out.Cost, out.Budget, docBytes, mode)
		return
	}
	// 6) 时间窗预算（app+tenant 定窗累计；匿名独立桶）
	budget := pol.Budget
	if budget.WindowSeconds <= 0 {
		budget.WindowSeconds = 60
	}
	if budget.WindowBudget <= 0 {
		budget.WindowBudget = 100000
	}
	if budget.AnonymousBudget <= 0 {
		budget.AnonymousBudget = 20000
	}
	tenant := graphQLTenantKey(r, cfg.IdentitySalt)
	limit := budget.WindowBudget
	if tenant == "anonymous" {
		limit = budget.AnonymousBudget
	}
	store := pol.WindowStore
	if store == nil {
		store = defaultGraphQLWindowStore()
	}
	sum := store.AddAndSum(cfg.ApplicationID+"|"+tenant, out.Cost, budget.WindowSeconds, time.Now().UTC())
	if sum > limit {
		cfg.graphQLBudgetFail(ctx, ek, "gql.window", GQLReasonWindowExceeded, op.Kind, sum, limit, docBytes, mode)
		return
	}
	cfg.emitGraphQLCov(ctx, ek, docBytes, docBytes, coverage.StatusFull, "", false)
}

// graphQLAdmissionFail 结构准入失败分流（NG-T-G06）：语法/多操作/超硬边界。
// OBSERVE 只记录；PROTECT category=BLOCK + reason=GQL_ADMISSION_REJECTED。
// 覆盖：超硬边界 PARTIAL+COV_INPUT_TRUNCATED；语法/选择类 PARTIAL+COV_PARSE_ERROR。
func (cfg *Config) graphQLAdmissionFail(ctx *dsctx.RequestContext, ek string, err error, docBytes int64, mode decision.Mode) {
	kind := "SYNTAX"
	if ge, ok := err.(*gqlast.Error); ok {
		kind = string(ge.Kind)
	}
	category, severity := "OBSERVE", "MEDIUM"
	if mode == decision.ModeProtect {
		category, severity = "BLOCK", "HIGH"
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: graphqlDetector, RuleID: "gql.admission",
		Category: category, Severity: severity,
		Message:  fmt.Sprintf("graphql admission rejected: %s", kind),
		Evidence: map[string]string{"reason": GQLReasonAdmissionRejected, "error_kind": kind},
	})
	covReason := coverage.ReasonParseError
	truncated := false
	switch kind {
	case string(gqlast.ErrDocTooLarge), string(gqlast.ErrTooDeep), string(gqlast.ErrTooManyNodes),
		string(gqlast.ErrTooManyAliases), string(gqlast.ErrFragmentCycle):
		covReason = coverage.ReasonInputTruncated
		truncated = true
	}
	cfg.emitGraphQLCov(ctx, ek, docBytes, docBytes, coverage.StatusPartial, covReason, truncated)
}

// graphQLBudgetFail 预算超限分流（单请求成本/时间窗）：PROTECT category=BLOCK 拒绝，
// OBSERVE 只记录拟动作；evidence 脱敏（cost/budget/reason/operation_kind，无查询内容）。
func (cfg *Config) graphQLBudgetFail(ctx *dsctx.RequestContext, ek, ruleID, reason, opKind string, cost, budget, docBytes int64, mode decision.Mode) {
	category, severity := "OBSERVE", "HIGH"
	if mode == decision.ModeProtect {
		category, severity = "BLOCK", "CRITICAL"
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: graphqlDetector, RuleID: ruleID,
		Category: category, Severity: severity,
		Message: fmt.Sprintf("graphql budget exceeded: %s (cost=%d budget=%d)", reason, cost, budget),
		Evidence: map[string]string{
			"reason": reason, "cost": fmt.Sprintf("%d", cost),
			"budget": fmt.Sprintf("%d", budget), "operation_kind": opKind,
		},
	})
	cfg.emitGraphQLCov(ctx, ek, docBytes, docBytes, coverage.StatusFull, "", false)
}

// graphQLTenantKey 时间窗主体键：凭据指纹（HMAC 已脱敏）或 anonymous（无凭据独立桶）。
// 与 detectors.CredentialKey 同口径——不引入新身份语义，不落原始凭据。
func graphQLTenantKey(r *http.Request, salt string) string {
	if r == nil {
		return "anonymous"
	}
	if k := detectors.CredentialKey(r, salt); k != "" {
		return k
	}
	return "anonymous"
}

// defaultGraphQLWindowStore 进程内默认窗存储（单例；Valkey 注入点见 GraphQLPolicy.WindowStore）。
var defaultWindowStore = NewMemoryWindowBudgetStore(10000)

func defaultGraphQLWindowStore() WindowBudgetStore { return defaultWindowStore }

// emitGraphQLCov GraphQL 覆盖观测（契约 §6：detector=graphql.cost_v1，scope.bytes=文档字节）。
func (cfg *Config) emitGraphQLCov(ctx *dsctx.RequestContext, ek string, scopeBytes, examined int64, status coverage.Status, reason coverage.ReasonCode, truncated bool) {
	cfg.emitCov(coverage.Observation{
		RequestID:     ctx.RequestID,
		Detector:      graphqlCovDetector,
		EndpointKey:   ek,
		Phase:         coverage.PhaseRequest,
		Scope:         coverage.ScopeDeclared{Bytes: scopeBytes, Messages: 1, Direction: "request"},
		Status:        status,
		ReasonCode:    reason,
		BytesExamined: examined,
		Truncated:     truncated,
	})
}
