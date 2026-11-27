// i18n.go 系统告警文案中文化：把 API 风险发现类型代码（finding_type）、英文级别与
// 存量历史告警消息中的英文枚举映射为中文，供新告警生成与 CSV 导出复用。
// 词表与前端 web/src/utils/stage8.ts 的 API_FINDING_TYPE_META 保持一致。
package systemalerts

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// apiFindingTypeLabels 覆盖网关全量检测器、API 准入、授权决策、流程防护、文件安全、
// LLM/MCP、gRPC/GraphQL 与 WAF 规则的中文名称（与前端 API_FINDING_TYPE_META 对齐）。
var apiFindingTypeLabels = map[string]string{
	// 生命周期与 API 准入
	"SHADOW":                         "影子 API",
	"ZOMBIE":                         "僵尸 API",
	"DEPRECATED":                     "已下线 API",
	"ADMISSION_UNCONFIRMED":          "未确认 API 准入命中",
	"ADMISSION_UNKNOWN_ENDPOINT":     "未发现 API 准入命中",
	"ADMISSION_UNCONFIRMED_ENDPOINT": "未确认 API 准入命中",

	// 越权与授权（BOLA / BFLA / 字段权限 / 多租户）
	"BOLA":                               "对象级越权",
	"BFLA":                               "功能级越权",
	"BOLA_UNAUTHENTICATED_OBJECT_ACCESS": "未认证对象越权访问",
	"MASS_ASSIGNMENT":                    "批量赋值",
	"AUTHZ_BFLA_ANONYMOUS":               "匿名功能级越权",
	"AUTHZ_BFLA_ROLE_MISMATCH":           "角色功能级越权",
	"AUTHZ_FORBIDDEN_FIELD":              "请求含禁止字段（批量赋值）",
	"AUTHZ_SERVER_GENERATED_WRITE":       "篡改服务端生成字段",
	"AUTHZ_READONLY_WRITE":               "写入只读或管理员字段",
	"AUTHZ_RESPONSE_FORBIDDEN_FIELD":     "响应含禁止字段（过度暴露）",
	"AUTHZ_RESPONSE_SENSITIVE_FIELD":     "响应含已确认敏感字段",
	"AUTHZ_WATERMARK_REGRESSION":         "授权快照水位回退",
	"AUTHZ_BOLA_001":                     "对象级越权（BOLA）",
	"AUTHZ_BOLA_002":                     "对象授权证据不足",
	"AUTHZ_BFLA_001":                     "功能级越权（BFLA）",
	"AUTHZ_TENANT_001":                   "跨租户越权访问",
	"AUTHZ_TENANT_002":                   "租户授权上下文异常",
	"AUTHZ_IDENTITY_001":                 "缺少可信身份（授权未知）",
	"AUTHZ_ROLE_001":                     "缺少可信角色（授权未知）",
	"AUTHZ_POLICY_001":                   "授权策略基线冲突",
	"AUTHZ_POLICY_002":                   "授权快照已过期",
	"AUTHZ_CLOCK_001":                    "授权节点时钟漂移",
	"AUTHZ_LEASE_001":                    "授权租约过期（严格拒绝）",
	"AUTHZ_LEASE_002":                    "授权租约过期（降级观察）",
	"AUTHZ_CONFLICT_001":                 "对象授权关系冲突",
	"AUTHZ_RELATION_001":                 "缺少对象归属关系",
	"AUTHZ_OBJECT_001":                   "对象标识缺失或非法",
	"AUTHZ_OBJECT_002":                   "对象标识不唯一",
	"AUTHZ_OBJECT_003":                   "对象签名密钥缺失",

	// 请求/响应模型与参数约束
	"SCHEMA_DEVIATION":                "模型偏离",
	"SCHEMA_TYPE_MISMATCH":            "参数类型不匹配",
	"SCHEMA_EXTRA_FIELD":              "未定义多余字段",
	"SCHEMA_UNDEFINED_FIELD":          "未定义请求字段",
	"SCHEMA_MISSING_FIELD":            "必填字段缺失",
	"SCHEMA_PARAM_REQUIRED":           "必填参数缺失",
	"SCHEMA_PARAM_TYPE":               "参数类型不匹配",
	"SCHEMA_PARAM_LENGTH":             "参数长度超限",
	"SCHEMA_PARAM_RANGE":              "参数数值越界",
	"SCHEMA_PARAM_ENUM":               "参数不在枚举范围",
	"SCHEMA_PARAM_REGEX":              "参数格式不匹配",
	"SCHEMA_PARAM_NULLABLE":           "参数不允许为空",
	"SCHEMA_PARAM_EMPTY":              "参数不允许空值",
	"SCHEMA_PARAM_CONSTRAINT_INVALID": "参数约束不可执行",
	"SCHEMA_RELATION_REQUIRES":        "关联必填参数缺失",
	"SCHEMA_RELATION_MUTEX":           "互斥参数同时出现",
	"SCHEMA_RELATION_COOCCURS":        "共现参数关系偏离",
	"SCHEMA_RELATION_EQUALS":          "参数相等约束违例",
	"SCHEMA_RELATION_NOT_EQUALS":      "参数不等约束违例",
	"SCHEMA_RELATION_GREATER_THAN":    "参数大于约束违例",
	"SCHEMA_RELATION_LESS_THAN":       "参数小于约束违例",
	"SCHEMA_RELATION_TIME_BEFORE":     "时间先后约束违例（早于）",
	"SCHEMA_RELATION_TIME_AFTER":      "时间先后约束违例（晚于）",
	"SCHEMA_RELATION_COUNT_MATCHES":   "数组数量约束违例",
	"SCHEMA_RELATION_SUM_MATCHES":     "参数求和约束违例",
	"RESPONSE_SCHEMA_NEW_STATUS":      "响应出现未学习状态码",
	"RESPONSE_SCHEMA_NEW_FIELD":       "响应出现未学习字段",
	"RESPONSE_SCHEMA_MISSING_FIELD":   "响应缺少基线字段",

	// 敏感数据、响应与服务端泄露
	"SENSITIVE_LEAK":                     "敏感数据泄露",
	"SENSITIVE_IN_QUERY":                 "URL 查询含敏感字段",
	"SENSITIVE_VALUE_IN_QUERY":           "URL 查询含敏感数据",
	"SENSITIVE_FIELD":                    "请求含敏感字段名",
	"SENSITIVE_VALUE":                    "请求含敏感数据值",
	"SENSITIVE_RESPONSE_FIELD":           "响应含敏感字段名",
	"SENSITIVE_RESPONSE_VALUE":           "响应包含敏感数据",
	"SENSITIVE_RESPONSE_BODY_UNCHECKED":  "响应敏感检测未完成",
	"SERVER_VERSION_DISCLOSURE":          "服务端版本信息泄露",
	"SERVER_ERROR_DISCLOSURE":            "服务端错误详情泄露",
	"RESPONSE_MASK_FAILED":               "响应脱敏失败",
	"RESPONSE_MASK_SKIPPED":              "响应脱敏已跳过",
	"RESPONSE_MASK_APPLIED":              "已执行响应脱敏",
	"RESPONSE_MASK_PLAN":                 "已生成响应脱敏计划",
	"RESPONSE_FAIL_CLOSED":               "响应安全抑制（故障关闭）",
	"RESPONSE_ERROR_SIGNATURE":           "响应异常错误特征",
	"REQUEST_BODY_PRESERVE_SKIPPED":      "请求体超限跳过检测",
	"REQUEST_BODY_TOO_LARGE_FAIL_CLOSED": "请求体超限触发保护",

	// 行为、频率、配额与业务流程
	"BEHAVIOR_ANOMALY":              "行为异常",
	"BEHAVIOR_RATE_SPIKE":           "访问速率突增",
	"SHARED_DEVICE_ACCOUNTS":        "同设备多账号",
	"RATELIMIT_API_WRITE_RATE":      "API 写入频率超限",
	"RATELIMIT_CREDENTIAL_RATE":     "单凭据请求速率超限",
	"RATELIMIT_TENANT_RATE":         "租户请求速率超限",
	"RATELIMIT_ACTION_RATE":         "操作请求速率超限",
	"RATELIMIT_GROUP_RATE":          "接口分组速率超限",
	"RATELIMIT_API_HOURLY_QUOTA":    "API 每小时配额超限",
	"RATELIMIT_API_DAILY_QUOTA":     "API 每日配额超限",
	"RATELIMIT_OBJECT_RATE":         "单对象访问频率超限",
	"RATELIMIT_PAGE_SIZE_EXCEEDED":  "分页拉取大小超限",
	"RATELIMIT_BATCH_SIZE_EXCEEDED": "批量请求数量超限",
	"FLOW_ANONYMOUS_LATE_ENTRY":     "匿名进入非首步流程",
	"FLOW_STEP_SKIP":                "业务流程跳步执行",
	"FLOW_OUT_OF_ORDER":             "业务流程顺序异常",
	"FLOW_DUPLICATE_SUBMIT":         "业务请求短时重复提交",
	"FLOW_ILLEGAL_STATE_TRANSITION": "对象状态非法流转",
	"FLOW_RAPID_BATCH":              "业务流程高频批量调用",
	"FLOW_POST_CANCEL_OPERATION":    "取消后继续操作流程",
	"FLOWGUARD_VIOLATION":           "强流程状态违例",
	"FLOWGUARD_UNKNOWN":             "强流程评估未知",
	"FLOWGUARD_STEP_CONFIRMED":      "强流程步骤已确认",
	"FLOWGUARD_COMMIT_REJECTED":     "强流程令牌过期拒提交",
	"FLOWGUARD_STEP_ACCEPTED_202":   "强流程异步受理待完成",
	"FLOWGUARD_STEP_UNKNOWN":        "强流程结果未知待对账",

	// 认证、凭据与机器身份
	"WEAK_AUTH":                        "弱认证风险",
	"AUTH_UNAUTHENTICATED_API":         "未携带认证凭据",
	"AUTH_WEAK_CREDENTIAL":             "弱认证凭据",
	"AUTH_MALFORMED_CREDENTIAL":        "认证头格式异常",
	"AUTH_JWT_MALFORMED_HEADER":        "JWT 头部格式异常",
	"AUTH_JWT_ALG_NONE":                "JWT 空算法（alg=none）",
	"AUTH_JWT_KID_TRAVERSAL":           "JWT kid 路径遍历风险",
	"AUTH_JWT_EMPTY_SIGNATURE":         "JWT 缺少签名段",
	"AUTH_JWT_EXPIRED":                 "JWT 令牌已过期",
	"AUTH_CREDENTIAL_IN_URL":           "URL 明文传递凭据",
	"CREDENTIAL_URL_PASSWORD":          "URL 明文传递密码",
	"AUTH_CREDENTIAL_CROSS_APP":        "凭据跨应用复用",
	"AUTH_CREDENTIAL_DEVICE_SPREAD":    "凭据多设备扩散",
	"AUTH_CREDENTIAL_REVOKED":          "已吊销凭据复用",
	"AUTH_CREDENTIAL_IP_SPREAD":        "凭据多来源 IP 使用",
	"AUTH_CREDENTIAL_CONCURRENCY":      "凭据异常并发使用",
	"AUTH_CREDENTIAL_UNUSUAL_HOUR":     "凭据非常规时段活跃",
	"AUTH_CREDENTIAL_UA_CHANGE":        "凭据客户端类型变更",
	"AUTH_ENV_ANOMALY_STACK":           "凭据多项环境异常叠加",
	"CREDENTIAL_COOKIE_SENSITIVE":      "Cookie 携带敏感凭据",
	"IDENTITY_TOKEN_PRESENT":           "携带认证请求头",
	"IDENTITY_COOKIE_PRESENT":          "携带 Cookie 会话头",
	"IDENTITY_HMAC_SIGNATURE_PRESENT":  "携带 HMAC 签名凭据",
	"MACHINEID_FAILED":                 "机器身份验证失败",
	"MACHINEID_DEPENDENCY_UNAVAILABLE": "机器身份校验依赖不可用",
	"MACHINEID_BODY_UNAVAILABLE":       "机器身份内容摘要不可用",
	"ID_COVERAGE_V1":                   "机器身份校验覆盖观测",

	// 文件安全
	"FILE_DOUBLE_EXTENSION":                "文件双扩展名风险",
	"FILE_COMPLIANCE_VIOLATION":            "文件合规违规",
	"FILE_SENSITIVE_CONTENT":               "文件含敏感内容",
	"FILE_SENSITIVE_CONTENT_NOT_INSPECTED": "文件敏感检测未完成",
	"FILE_CONTENT_TYPE_MISMATCH":           "文件签名与声明类型不符",
	"FILE_CONTENT_UNRECOGNIZED":            "文件签名无法识别",
	"FILE_CONTENT_NOT_INSPECTED":           "文件内容签名未检测",
	"FILE_BULK_DOWNLOAD":                   "同身份文件批量下载",
	"FILE_DOWNLOAD_BLOCK_UNAVAILABLE":      "文件下载阻断未生效",
	"FILE_WATERMARK_APPLIED":               "已添加文件水印",
	"FILE_SIGNATURE_EMBEDDED":              "已嵌入文件签名",

	// 扫描器、WebShell、镜像、资源与报文解析
	"SCANNER_PRESENCE_ONLY":        "主动扫描流量标记",
	"SCANNER_SIGNATURE_VALID":      "已验签主动扫描流量",
	"SCANNER_SIGNATURE_FORGED":     "伪造扫描器签名",
	"WEBSHELL_C2_SUSPECTED":        "疑似 WebShell/远控通信",
	"RESOURCE_OBJECT_ENUMERATION":  "对象资源枚举探测",
	"MIRROR_CAPTURE":               "镜像流量旁路观测",
	"WAF_DOWNSTREAM_INTERCEPT":     "WAF 下游阻断",
	"PARSER_DUPLICATE_JSON_KEY":    "JSON 重复键解析异常",
	"PARSER_DUPLICATE_QUERY_PARAM": "查询参数重复解析异常",
	"PARSER_DUPLICATE_HEADER":      "请求头重复解析异常",
	"PARSER_DUPLICATE_FORM_PARAM":  "表单参数重复解析异常",
	"PARSER_FIELD_COUNT_CAPPED":    "请求字段数量超解析上限",

	// gRPC 与 GraphQL
	"GRPC_OBSERVED":                    "gRPC 报文帧观测",
	"GRPC_MALFORMED_FRAME":             "gRPC 异常报文帧",
	"GRPC_UNEXPECTED_COMPRESSION":      "gRPC 未允许压缩帧",
	"GRPC_DECODE_ERROR":                "gRPC 消息解码失败",
	"GRPC_SENSITIVE_FIELD":             "gRPC 消息含敏感字段",
	"GRPC_COVERAGE_V1":                 "gRPC 一元调用覆盖观测",
	"GRPC_NO_UNARY_MESSAGE":            "gRPC 请求无消息帧",
	"GRPC_READ_ERROR":                  "gRPC 报文帧读取失败",
	"GRPC_STREAMING_OBSERVED":          "gRPC 流式调用检测降级",
	"GRPC_UNSUPPORTED_ENCODING":        "gRPC 不支持的压缩编码",
	"GRPC_COMPRESSION_BUDGET_EXCEEDED": "gRPC 解压预算超限",
	"GRPC_FIELD_VIOLATION":             "gRPC 消息结构违规",
	"GRPC_ENUM_OUT_OF_RANGE":           "gRPC 枚举值越界",
	"GRPC_FIELD_VIOLATION_SUMMARY":     "gRPC 结构违例已截断",
	"GRPCGUARD_MALFORMED_FRAME":        "gRPC 报文帧畸形",
	"GRPCGUARD_BUDGET_EXCEEDED":        "gRPC 报文帧预算超限",
	"GQL_ADMISSION":                    "GraphQL 准入拒绝",
	"GQL_COST_V1":                      "GraphQL 单请求复杂度超限",
	"GQL_WINDOW":                       "GraphQL 时间窗预算超限",
	"GQL_TRUSTED_DOC":                  "GraphQL 可信文档直通",

	// LLM 与 MCP
	"LLM_PROMPT_INJECTION":             "LLM 提示词注入",
	"LLM_UNAUTHORIZED_MODEL":           "LLM 未授权模型调用",
	"LLM_INPUT_CONTENT_VIOLATION":      "LLM 输入内容违规",
	"LLM_TOPIC_VIOLATION":              "LLM 提示词命中禁止主题",
	"LLM_PII_DETECTED":                 "LLM 提示词含敏感信息",
	"LLM_PROMPT_SIZE_EXCEEDED":         "LLM 提示词长度超限",
	"LLM_OUTPUT_TOKEN_BUDGET_EXCEEDED": "LLM 输出 Token 超预算",
	"LLM_OUTPUT_CONTENT_VIOLATION":     "LLM 输出内容违规",
	"LLM_OUTPUT_PII_DETECTED":          "LLM 输出含敏感信息",
	"LLM_OUTPUT_NOT_INSPECTED":         "LLM 输出未完整检测",
	"LLM_OUTPUT_PARTIALLY_INSPECTED":   "LLM 输出部分检测",
	"LLM_MCP_UNKNOWN_METHOD":           "MCP 未知扩展方法",
	"LLM_MCP_SENSITIVE_ARG":            "MCP 参数含敏感信息",
	"MCP_SUBJECT_UNTRUSTED":            "MCP 调用主体未通过可信认证",
	"MCP_TOOL_NOT_IN_CATALOG":          "MCP 调用未审核目录外工具",
	"MCP_CALLER_NOT_AUTHORIZED":        "MCP 调用方无工具授权",
	"MCP_JSON_DUPLICATE_KEY":           "MCP 参数含 JSON 重复键",
	"MCP_ARG_SCHEMA_VIOLATION":         "MCP 工具参数 Schema 违规",
	"MCP_ARG_SCOPE_VIOLATION":          "MCP 工具参数越出允许范围",
	"MCP_CALL_BUDGET_EXCEEDED":         "MCP 工具调用频率超限",
	"MCP_HIGH_RISK_DENIED":             "MCP 高风险工具默认拒绝",
	"MCP_UNSUPPORTED_SHAPE":            "MCP 不支持的批处理格式",
	"MCP_BUDGET_EXCEEDED":              "MCP 消息结构超预算",
	"MCP_RESULT_SCHEMA_VIOLATION":      "MCP 工具返回 Schema 违规",
	"MCP_RESULT_SENSITIVE_VALUE":       "MCP 工具返回含敏感数据",
	"MCP_RESULT_BLOCKED_MIDSTREAM":     "MCP 流式返回中途阻断",
	"MCP_COVERAGE_V1":                  "MCP 工具调用覆盖观测",
	"MCPGUARD_DEPENDENCY_UNAVAILABLE":  "MCP 防护依赖不可用",
}

var findingTypePrefixFallbacks = []struct {
	prefix string
	label  string
}{
	{"RESPONSE_SCHEMA_", "响应模型偏离"},
	{"RESPONSE_", "响应安全异常"},
	{"REQUEST_", "请求安全异常"},
	{"SCHEMA_", "请求模型偏离"},
	{"PARSER_", "报文解析异常"},
	{"RATELIMIT_", "频率限速触发"},
	{"SENSITIVE_", "敏感数据风险"},
	{"SERVER_", "服务端信息泄露"},
	{"ADMISSION_", "API 准入告警"},
	{"LIFECYCLE_", "API 生命周期风险"},
	{"AUTHZ_", "授权安全异常"},
	{"AUTH_", "认证凭据异常"},
	{"CREDENTIAL_", "凭据安全风险"},
	{"JWT_", "JWT 认证异常"},
	{"MACHINEID_", "机器身份异常"},
	{"IDENTITY_", "身份信号异常"},
	{"BOLA_", "对象级越权风险"},
	{"BFLA_", "功能级越权风险"},
	{"FLOWGUARD_", "强流程防护异常"},
	{"FLOW_", "业务流程异常"},
	{"LLM_", "LLM 安全告警"},
	{"MCPGUARD_", "MCP 安全防护告警"},
	{"MCP_", "MCP 工具安全告警"},
	{"FILE_", "文件安全告警"},
	{"GRPCGUARD_", "gRPC 安全防护告警"},
	{"GRPC_", "gRPC 协议异常"},
	{"GRAPHQL_", "GraphQL 安全告警"},
	{"GQL_", "GraphQL 安全告警"},
	{"RESOURCE_", "资源访问异常"},
	{"SCANNER_", "扫描器异常"},
	{"BEHAVIOR_", "异常行为检测"},
	{"WEBSHELL_", "WebShell 通信风险"},
	{"MIRROR_", "镜像旁路观测"},
	{"WAF_", "WAF 安全检测"},
}

var wafRuleCategoryRanges = []struct {
	min, max int
	label    string
}{
	{200000, 200999, "WAF 报文解析异常"},
	{911000, 911999, "WAF HTTP 方法限制"},
	{913000, 913999, "WAF 扫描器检测"},
	{920000, 920999, "WAF 协议合规"},
	{921000, 921999, "WAF 协议攻击"},
	{922000, 922999, "WAF Multipart 攻击"},
	{930000, 930999, "WAF 本地文件包含"},
	{931000, 931999, "WAF 远程文件包含"},
	{932000, 932999, "WAF 命令执行"},
	{933000, 933999, "WAF PHP 注入"},
	{934000, 934999, "WAF 通用应用攻击"},
	{941000, 941999, "WAF XSS 攻击"},
	{942000, 942999, "WAF SQL 注入"},
	{943000, 943999, "WAF 会话固定"},
	{944000, 944999, "WAF Java 攻击"},
	{949000, 949999, "WAF 入站异常阻断"},
	{950000, 954999, "WAF 数据泄露"},
	{955000, 955999, "WAF WebShell 检测"},
	{956000, 956999, "WAF 数据泄露"},
	{959000, 959999, "WAF 出站异常阻断"},
	{980000, 980999, "WAF 关联评分"},
	{1000000, 1000099, "WAF 高危 CVE 防护"},
	{1000100, 1000199, "WAF WebShell 检测"},
	{1000200, 1000299, "WAF 扫描器指纹"},
	{1000300, 1000399, "WAF 云原生滥用"},
	{1000400, 1000499, "WAF API 滥用防护"},
	{1000500, 1000599, "WAF 敏感路径暴露"},
	{1000600, 1000699, "WAF 反序列化/RCE"},
	{1000700, 1000799, "WAF 自动化异常"},
	{1000800, 1000999, "WAF 漏洞利用防护"},
	{1001000, 1001099, "WAF WebShell 混淆"},
	{1001100, 1001299, "WAF 攻击变种检测"},
	{1001300, 1001499, "WAF WebShell 检测"},
	{1001500, 1001599, "WAF SSRF 防护"},
	{1001600, 1001699, "WAF XXE/文件包含"},
	{1001700, 1001799, "WAF 注入变种检测"},
	{1001800, 1001899, "WAF 模板注入"},
	{1001900, 1001999, "WAF 未授权探测"},
	{1002000, 1003999, "WAF 扩展爬虫指纹"},
	{1010000, 1010199, "WAF AI 爬虫管控"},
	{1010200, 1010299, "WAF 伪造爬虫检测"},
	{9000000, 9000999, "WAF 九章内置规则"},
}

// findingTypeLabel 返回 API 风险发现类型的中文名称；支持精确词表、WAF_<规则号>
// 与检测域前缀兜底，未识别类型原样返回。
func findingTypeLabel(t string) string {
	trimmed := strings.TrimSpace(t)
	if trimmed == "" {
		return ""
	}
	upper := strings.ToUpper(trimmed)
	if label, ok := apiFindingTypeLabels[upper]; ok {
		return label
	}
	normalized := strings.NewReplacer(".", "_", "-", "_", " ", "_").Replace(upper)
	if label, ok := apiFindingTypeLabels[normalized]; ok {
		return label
	}
	if strings.HasPrefix(normalized, "WAF_") {
		if id, err := strconv.Atoi(strings.TrimPrefix(normalized, "WAF_")); err == nil && id > 0 {
			for _, r := range wafRuleCategoryRanges {
				if id >= r.min && id <= r.max {
					return fmt.Sprintf("%s（%d）", r.label, id)
				}
			}
			return fmt.Sprintf("WAF 规则命中（%d）", id)
		}
	}
	for _, p := range findingTypePrefixFallbacks {
		if strings.HasPrefix(normalized, p.prefix) {
			return p.label
		}
	}
	return trimmed
}

var (
	reAlertFindingCode     = regexp.MustCompile(`\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b`)
	reAlertAnyFindingCode  = regexp.MustCompile(`\b(?:[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|SHADOW|ZOMBIE|DEPRECATED|BOLA|BFLA)\b`)
	reAlertDupCodeParen    = regexp.MustCompile(`\b([A-Z][A-Z0-9_]+)[（(]([A-Z][A-Z0-9_]+)[）)]`)
	reAlertHighestSev      = regexp.MustCompile(`最高级别[:：]\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b`)
	reAlertHighCrit        = regexp.MustCompile(`\s*HIGH/CRITICAL\s*级`)
	reAlertCriticalLevel   = regexp.MustCompile(`\s*CRITICAL\s*级`)
	reAlertMaskParen       = regexp.MustCompile(`[（(]MASK_RESPONSE[）)]`)
	reAlertCheckpoint      = regexp.MustCompile(`事件采集\s+checkpoint\s+滞后`)
)

// localizeAlertMessage 将存量历史告警详情中遗留的英文风险发现码与级别枚举中文化，
// 用于 API 展示与 CSV 导出（幂等，已是中文的文本原样保留）。
func localizeAlertMessage(msg string) string {
	if msg == "" {
		return ""
	}
	out := reAlertMaskParen.ReplaceAllString(msg, "")
	out = reAlertHighCrit.ReplaceAllString(out, "高危/严重级")
	out = reAlertCriticalLevel.ReplaceAllString(out, "严重级")
	out = reAlertCheckpoint.ReplaceAllString(out, "事件采集位点滞后")
	out = reAlertHighestSev.ReplaceAllStringFunc(out, func(m string) string {
		sub := reAlertHighestSev.FindStringSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		sep := "："
		if strings.Contains(m, ":") {
			sep = ":"
		}
		return "最高级别" + sep + exportAlertSeverityLabel(sub[1])
	})
	isFindingAlert := strings.Contains(out, "风险发现")
	if isFindingAlert {
		out = reAlertDupCodeParen.ReplaceAllStringFunc(out, func(m string) string {
			sub := reAlertDupCodeParen.FindStringSubmatch(m)
			if len(sub) == 3 && sub[1] == sub[2] {
				return sub[1]
			}
			return m
		})
	}
	re := reAlertFindingCode
	if isFindingAlert {
		re = reAlertAnyFindingCode
	}
	out = replaceBoundedTokens(out, re, func(tok string, wrappedInParens bool) string {
		if wrappedInParens && !strings.Contains(tok, "_") {
			return tok
		}
		if label := findingTypeLabel(tok); label != tok {
			return label
		}
		return tok
	})
	return out
}

// replaceBoundedTokens 仅替换前后不紧贴路径/域名/连字符分隔符的独立英文码，
// 避免误改 URL、文件路径或 CVE 编号中的片段；同时标记是否被括号包裹（避免误译“对象级越权（BOLA）”）。
func replaceBoundedTokens(s string, re *regexp.Regexp, fn func(tok string, wrappedInParens bool) string) string {
	locs := re.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return s
	}
	var b strings.Builder
	prev := 0
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		if (start > 0 && isTokenJoiner(s[start-1])) || (end < len(s) && isTokenJoiner(s[end])) {
			continue
		}
		wrapped := hasOpenParenBefore(s[:start]) && hasCloseParenAfter(s[end:])
		b.WriteString(s[prev:start])
		b.WriteString(fn(s[start:end], wrapped))
		prev = end
	}
	b.WriteString(s[prev:])
	return b.String()
}

func hasOpenParenBefore(prefix string) bool {
	return strings.HasSuffix(prefix, "(") || strings.HasSuffix(prefix, "（")
}

func hasCloseParenAfter(suffix string) bool {
	return strings.HasPrefix(suffix, ")") || strings.HasPrefix(suffix, "）")
}

func isTokenJoiner(ch byte) bool {
	return ch == '/' || ch == '.' || ch == '-' || ch == '_'
}
