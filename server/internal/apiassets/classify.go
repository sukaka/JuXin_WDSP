package apiassets

import (
	"slices"
	"strings"
	"unicode"
)

// 任务书 §34 用途多维识别：在既有 PURPOSE/EXPOSURE/ACCESS 三维启发式基础上扩展
//   - ACTION：§34.2 操作动作 43 项词表（方法映射兜底 + 路径 token 规则命中）；
//   - BUSINESS_DOMAIN：§34.1 业务领域 16 项内置种子（api_classifications，迁移 000073），
//     关键词命中才打标，多领域并列低置信时不打标。
// 其余维度（业务对象/交互模式/身份要求/数据敏感等级/业务流程阶段/风险标签）
// 需要参数、响应、认证与调用顺序等观测数据，路径启发式不足以支撑，不在此编造。

// actionRule 操作动作识别规则：路径静态段 token 命中 + 可选方法约束。
// keywords 任一命中且 andTokens 全部命中时规则命中；规则有序，先中先生效。
type actionRule struct {
	action    string
	conf      float64
	methods   []string // 空 = 不限方法（大写）
	keywords  []string // 路径 token 任一精确命中（小写）
	andTokens []string // 路径 token 全部命中（小写）
}

// actionRules §34.2 操作动作词表识别规则（集中维护处）。
// 顺序即优先级：刷新/吊销必须先于 TOKEN_ISSUE，UNPUBLISH/UNLOCK 先于 PUBLISH/LOCK
// （token 精确匹配已天然区分，顺序仅作语义兜底）。
var actionRules = []actionRule{
	{action: "TOKEN_REFRESH", conf: 0.75, keywords: []string{"refresh"}, andTokens: []string{"token"}},
	{action: "TOKEN_REVOKE", conf: 0.75, keywords: []string{"revoke"}},
	{action: "TOKEN_ISSUE", conf: 0.75, methods: []string{"POST"}, keywords: []string{"token"}},
	{action: "LOGIN", conf: 0.85, keywords: []string{"login", "signin"}},
	{action: "LOGOUT", conf: 0.85, keywords: []string{"logout", "signout"}},
	{action: "REGISTER", conf: 0.85, keywords: []string{"register", "signup"}},
	{action: "VERIFY", conf: 0.8, keywords: []string{"verify", "verification", "captcha"}},
	{action: "SUBMIT", conf: 0.85, methods: []string{"POST"}, keywords: []string{"submit"}},
	{action: "BATCH_CREATE", conf: 0.8, methods: []string{"POST"}, keywords: []string{"batch", "bulk"}},
	{action: "BATCH_UPDATE", conf: 0.8, methods: []string{"PUT", "PATCH"}, keywords: []string{"batch", "bulk"}},
	{action: "BATCH_DELETE", conf: 0.8, methods: []string{"DELETE"}, keywords: []string{"batch", "bulk"}},
	{action: "APPROVE", conf: 0.85, methods: []string{"POST", "PUT", "PATCH"}, keywords: []string{"approve"}},
	{action: "REJECT", conf: 0.85, methods: []string{"POST", "PUT", "PATCH"}, keywords: []string{"reject"}},
	{action: "WITHDRAW", conf: 0.8, methods: []string{"POST", "PUT"}, keywords: []string{"withdraw"}},
	{action: "ASSIGN", conf: 0.8, methods: []string{"POST", "PUT", "PATCH"}, keywords: []string{"assign", "allocate"}},
	{action: "TRANSFER", conf: 0.8, methods: []string{"POST", "PUT"}, keywords: []string{"transfer"}},
	{action: "UNPUBLISH", conf: 0.85, methods: []string{"POST", "PUT", "PATCH"}, keywords: []string{"unpublish"}},
	{action: "PUBLISH", conf: 0.85, methods: []string{"POST", "PUT", "PATCH"}, keywords: []string{"publish"}},
	{action: "ENABLE", conf: 0.85, methods: []string{"POST", "PUT", "PATCH"}, keywords: []string{"enable"}},
	{action: "DISABLE", conf: 0.85, methods: []string{"POST", "PUT", "PATCH"}, keywords: []string{"disable"}},
	{action: "UNLOCK", conf: 0.85, methods: []string{"POST", "PUT", "PATCH"}, keywords: []string{"unlock"}},
	{action: "LOCK", conf: 0.85, methods: []string{"POST", "PUT", "PATCH"}, keywords: []string{"lock"}},
	{action: "IMPORT", conf: 0.85, methods: []string{"POST"}, keywords: []string{"import"}},
	{action: "EXPORT", conf: 0.85, methods: []string{"POST", "GET"}, keywords: []string{"export"}},
	{action: "UPLOAD", conf: 0.85, methods: []string{"POST", "PUT"}, keywords: []string{"upload"}},
	{action: "DOWNLOAD", conf: 0.85, methods: []string{"GET"}, keywords: []string{"download"}},
	{action: "PREVIEW", conf: 0.8, methods: []string{"GET", "POST"}, keywords: []string{"preview"}},
	{action: "SYNC", conf: 0.8, methods: []string{"POST", "PUT"}, keywords: []string{"sync"}},
	{action: "CALLBACK", conf: 0.8, keywords: []string{"callback", "webhook"}},
	{action: "START", conf: 0.8, methods: []string{"POST", "PUT"}, keywords: []string{"start"}},
	{action: "STOP", conf: 0.8, methods: []string{"POST", "PUT"}, keywords: []string{"stop"}},
	{action: "RETRY", conf: 0.8, methods: []string{"POST"}, keywords: []string{"retry"}},
	{action: "BACKUP", conf: 0.75, keywords: []string{"backup"}},
	{action: "RESTORE", conf: 0.75, keywords: []string{"restore"}},
	{action: "EXECUTE", conf: 0.75, methods: []string{"POST"}, keywords: []string{"execute", "exec", "invoke", "run"}},
	{action: "SEARCH", conf: 0.8, methods: []string{"GET", "POST"}, keywords: []string{"search", "query"}},
	{action: "COUNT", conf: 0.8, methods: []string{"GET"}, keywords: []string{"count"}},
	{action: "READ_LIST", conf: 0.8, methods: []string{"GET"}, keywords: []string{"list"}},
}

// domainRule 业务领域识别规则：code 对应 api_classifications 内置种子编码（迁移 000073）。
type domainRule struct {
	code     string
	keywords []string // 路径 token 精确命中（小写）
}

// domainRules §34.1 业务领域 16 项种子关键词映射（集中维护处）。
var domainRules = []domainRule{
	{code: "IDENTITY_AUTH", keywords: []string{"auth", "login", "signin", "logout", "signout", "sso", "oauth", "oauth2", "token", "captcha", "mfa", "otp", "session"}},
	{code: "USER_ACCOUNT", keywords: []string{"user", "users", "account", "accounts", "profile", "password", "register", "signup", "member", "members"}},
	{code: "ORG_PERMISSION", keywords: []string{"org", "orgs", "organization", "organizations", "department", "departments", "dept", "role", "roles", "permission", "permissions", "rbac", "acl"}},
	{code: "DATA_RESOURCE", keywords: []string{"resource", "resources", "dataset", "datasets"}},
	{code: "PROCESS_APPROVAL", keywords: []string{"approval", "approvals", "approve", "workflow", "workflows", "ticket", "tickets"}},
	{code: "TRANSACTION_FUND", keywords: []string{"pay", "payment", "payments", "order", "orders", "trade", "billing", "invoice", "invoices", "recharge", "fund", "funds", "wallet", "transaction", "transactions", "settlement"}},
	{code: "FILE_CONTENT", keywords: []string{"file", "files", "attachment", "attachments", "document", "documents", "upload", "download"}},
	{code: "QUERY_ANALYTICS", keywords: []string{"search", "query", "analytics", "statistics", "stats", "report", "reports", "dashboard", "metric", "metrics", "aggregation"}},
	{code: "IMPORT_EXPORT", keywords: []string{"import", "export"}},
	{code: "MESSAGE_NOTIFICATION", keywords: []string{"message", "messages", "notification", "notifications", "sms", "email", "mail", "push", "inbox", "subscribe", "subscription"}},
	{code: "EXTERNAL_INTEGRATION", keywords: []string{"webhook", "webhooks", "callback", "callbacks", "openapi", "sdk", "integration", "integrations", "thirdparty"}},
	{code: "SYSTEM_CONFIG", keywords: []string{"config", "configs", "configuration", "settings", "setting", "dict", "dictionary", "preference", "preferences"}},
	{code: "SYSTEM_OPS", keywords: []string{"monitor", "monitoring", "log", "logs", "job", "jobs", "schedule", "scheduler", "backup", "restore", "health", "ops", "maintenance"}},
	{code: "DEVICE_IOT", keywords: []string{"device", "devices", "iot", "shadow", "telemetry", "firmware", "sensor", "sensors", "ota"}},
	{code: "AI_INTELLIGENCE", keywords: []string{"ai", "model", "models", "llm", "agent", "agents", "prompt", "prompts", "embedding", "embeddings", "inference", "completion", "completions", "rag"}},
	{code: "PRIVACY_COMPLIANCE", keywords: []string{"privacy", "compliance", "consent", "consents", "pii", "gdpr"}},
}

// classifyByPath 路径/方法启发式自动分类（AUTO 来源，供 SQL 与内存实现共用）。
// 输出 PURPOSE/EXPOSURE/ACCESS/ACTION 四维，BUSINESS_DOMAIN 仅在领域关键词置信达标时附带。
func classifyByPath(method, path string) []ClassificationDimension {
	p := strings.ToLower(path)
	purpose, pconf := "GENERAL", 0.5
	switch {
	case strings.Contains(p, "/login"), strings.Contains(p, "/signin"),
		strings.Contains(p, "/auth"), strings.Contains(p, "/token"), strings.Contains(p, "/captcha"):
		purpose, pconf = "AUTH", 0.7
	case strings.Contains(p, "/pay"), strings.Contains(p, "/order"),
		strings.Contains(p, "/trade"), strings.Contains(p, "/billing"):
		purpose, pconf = "TRADE", 0.7
	case strings.Contains(p, "/upload"), strings.Contains(p, "/file"),
		strings.Contains(p, "/download"), strings.Contains(p, "/export"):
		purpose, pconf = "FILE", 0.7
	case strings.Contains(p, "/admin"), strings.Contains(p, "/manage"):
		purpose, pconf = "ADMIN", 0.7
	case strings.Contains(p, "/user"), strings.Contains(p, "/account"), strings.Contains(p, "/profile"):
		purpose, pconf = "USER_MGMT", 0.6
	case strings.Contains(p, "/search"), strings.Contains(p, "/query"), strings.Contains(p, "/list"):
		purpose, pconf = "QUERY", 0.6
	}
	exposure, econf := "INTERNAL", 0.5
	if strings.Contains(p, "/public") || strings.Contains(p, "/openapi") ||
		strings.Contains(p, "/webhook") || strings.Contains(p, "/callback") {
		exposure, econf = "PUBLIC", 0.7
	}
	access := "WRITE"
	if strings.EqualFold(method, "GET") || strings.EqualFold(method, "HEAD") {
		access = "READ"
	}
	action, aconf := classifyAction(method, path)
	dims := []ClassificationDimension{
		{Dimension: "PURPOSE", Value: purpose, Source: "AUTO", Confidence: pconf},
		{Dimension: "EXPOSURE", Value: exposure, Source: "AUTO", Confidence: econf},
		{Dimension: "ACCESS", Value: access, Source: "AUTO", Confidence: 0.9},
		{Dimension: "ACTION", Value: action, Source: "AUTO", Confidence: aconf},
	}
	if domain, dconf, ok := classifyBusinessDomain(path); ok {
		dims = append(dims, ClassificationDimension{Dimension: "BUSINESS_DOMAIN", Value: domain, Source: "AUTO", Confidence: dconf})
	}
	return dims
}

// classifyAction §34.2 操作动作识别：先按规则表命中，未命中按方法映射兜底。
func classifyAction(method, path string) (string, float64) {
	m := strings.ToUpper(strings.TrimSpace(method))
	tokenSet := make(map[string]struct{})
	for _, t := range pathTokens(path) {
		tokenSet[t] = struct{}{}
	}
	for _, r := range actionRules {
		if len(r.methods) > 0 && !slices.Contains(r.methods, m) {
			continue
		}
		if len(r.keywords) > 0 {
			hit := false
			for _, k := range r.keywords {
				if _, ok := tokenSet[k]; ok {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		allHit := true
		for _, k := range r.andTokens {
			if _, ok := tokenSet[k]; !ok {
				allHit = false
				break
			}
		}
		if !allHit {
			continue
		}
		return r.action, r.conf
	}
	// 方法映射兜底：GET 末段为变量段按详情读，否则按列表读。
	switch m {
	case "GET", "HEAD":
		segs := strings.Split(strings.Trim(path, "/"), "/")
		if len(segs) > 0 && isPathVariableSegment(segs[len(segs)-1]) {
			return "READ_DETAIL", 0.65
		}
		return "READ_LIST", 0.6
	case "POST":
		return "CREATE", 0.55
	case "PUT":
		return "UPDATE", 0.6
	case "PATCH":
		return "PATCH", 0.7
	case "DELETE":
		return "DELETE", 0.6
	default:
		return "CUSTOM", 0.3
	}
}

// classifyBusinessDomain §34.1 业务领域识别：命中数最多的领域胜出；
// 多领域命中数并列视为低置信不打标。
func classifyBusinessDomain(path string) (string, float64, bool) {
	tokenSet := make(map[string]struct{})
	for _, t := range pathTokens(path) {
		tokenSet[t] = struct{}{}
	}
	best, bestHits, tied := "", 0, false
	for _, r := range domainRules {
		hits := 0
		for _, k := range r.keywords {
			if _, ok := tokenSet[k]; ok {
				hits++
			}
		}
		if hits == 0 {
			continue
		}
		switch {
		case hits > bestHits:
			best, bestHits, tied = r.code, hits, false
		case hits == bestHits:
			tied = true
		}
	}
	if best == "" || tied {
		return "", 0, false
	}
	if bestHits >= 2 {
		return best, 0.75, true
	}
	return best, 0.6, true
}

// pathTokens 提取路径静态段 token：变量段（{id}、:id、纯数字）跳过；
// 驼峰边界先拆分，再统一小写按非字母数字切分。
func pathTokens(path string) []string {
	var tokens []string
	for _, seg := range strings.Split(path, "/") {
		if seg == "" || isPathVariableSegment(seg) {
			continue
		}
		var b strings.Builder
		var prev rune
		for i, r := range seg {
			if i > 0 && unicode.IsUpper(r) && (unicode.IsLower(prev) || unicode.IsDigit(prev)) {
				b.WriteRune('_')
			}
			b.WriteRune(unicode.ToLower(r))
			prev = r
		}
		tokens = append(tokens, strings.FieldsFunc(b.String(), func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		})...)
	}
	return tokens
}

// isPathVariableSegment 分类口径的变量段：{name} 占位（复用 segments.go 判据）、
// :name 占位或纯数字 ID。
func isPathVariableSegment(seg string) bool {
	if seg == "" {
		return false
	}
	if isVariableSegment(seg) {
		return true
	}
	if strings.HasPrefix(seg, ":") && len(seg) > 1 {
		return true
	}
	for _, r := range seg {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
