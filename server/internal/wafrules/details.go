package wafrules

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed rule_specs_zh.json
var ruleSpecsZhJSON []byte

type ruleSpec struct {
	Kind       string   `json:"k"`
	Targets    []string `json:"t,omitempty"`
	Op         string   `json:"op,omitempty"`
	Arg        string   `json:"arg,omitempty"`
	Transforms []string `json:"tf,omitempty"`
	PL         int      `json:"pl,omitempty"`
	Action     string   `json:"act,omitempty"`
	SkipAfter  string   `json:"skip,omitempty"`
	CtlSummary string   `json:"ctl,omitempty"`
	Chained    bool     `json:"ch,omitempty"`
	Summary    string   `json:"s,omitempty"`
	Risk       string   `json:"r,omitempty"`
	Tuning     string   `json:"a,omitempty"`
}

var (
	ruleSpecsZh map[int]ruleSpec

	cveInTextPattern   = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)
	cnnvdInTextPattern = regexp.MustCompile(`(?i)\bCNNVD-\d{6}-\d{3,}\b`)
)

func init() {
	var raw map[string]ruleSpec
	if err := json.Unmarshal(ruleSpecsZhJSON, &raw); err != nil {
		panic(fmt.Sprintf("wafrules: decode rule_specs_zh.json: %v", err))
	}
	ruleSpecsZh = make(map[int]ruleSpec, len(raw))
	for k, v := range raw {
		id, err := strconv.Atoi(k)
		if err != nil {
			panic(fmt.Sprintf("wafrules: invalid rule id %q in rule_specs_zh.json: %v", k, err))
		}
		ruleSpecsZh[id] = v
	}
}

// RuleDescriptionOverride 是管理员在界面手工维护的规则中文说明覆盖项（方案 B）。
// 任意字段留空时自动沿用系统内置或规则文件自动解析的说明。
type RuleDescriptionOverride struct {
	Summary        string     `json:"summary"`
	DetectionLogic string     `json:"detection_logic"`
	RiskImpact     string     `json:"risk_impact"`
	TuningAdvice   string     `json:"tuning_advice"`
	UpdatedByName  string     `json:"updated_by_name,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
}

// HasAnyContent 判断覆盖记录是否包含至少一项非空中文说明。
func (o *RuleDescriptionOverride) HasAnyContent() bool {
	if o == nil {
		return false
	}
	return strings.TrimSpace(o.Summary) != "" ||
		strings.TrimSpace(o.DetectionLogic) != "" ||
		strings.TrimSpace(o.RiskImpact) != "" ||
		strings.TrimSpace(o.TuningAdvice) != ""
}

// RuleDescribeInput 是生成中文规则详细说明的输入元数据。
type RuleDescribeInput struct {
	RuleID         int
	RuleSource     string
	FileName       string
	Name           string
	Message        string
	Severity       string
	Phase          int
	AttackType     string
	DefaultState   string
	CRSVersion     string
	Tags           []string
	ParsedSpec     json.RawMessage
	CustomOverride *RuleDescriptionOverride
}

// RuleDetail 是面向管理端详情抽屉与 API 消费的结构化中文规则说明。
type RuleDetail struct {
	RuleType         string                   `json:"rule_type"`
	RuleTypeLabel    string                   `json:"rule_type_label"`
	Source           string                   `json:"source"`
	SourceLabel      string                   `json:"source_label"`
	Customized       bool                     `json:"customized"`
	Summary          string                   `json:"summary"`
	DetectionLogic   string                   `json:"detection_logic"`
	RiskImpact       string                   `json:"risk_impact"`
	TuningAdvice     string                   `json:"tuning_advice"`
	PhaseDescription string                   `json:"phase_description"`
	ParanoiaLevel    string                   `json:"paranoia_level"`
	ActionBehavior   string                   `json:"action_behavior"`
	Targets          []string                 `json:"targets"`
	References       []string                 `json:"references"`
	CustomFields     *RuleDescriptionOverride `json:"custom_fields,omitempty"`
}

var ruleTypeMeta = map[string]struct {
	code  string
	label string
}{
	"det": {code: "DETECTION", label: "安全检测规则"},
	"obs": {code: "OBSERVE", label: "观测告警规则"},
	"blk": {code: "BLOCKING_EVALUATION", label: "阻断评估规则"},
	"exc": {code: "EXCLUSION", label: "误报排除规则"},
	"pre": {code: "PREPROCESSING", label: "预处理规则"},
	"int": {code: "INTERNAL", label: "引擎内部控制规则"},
}

var phaseDescriptionsZh = map[int]string{
	1: "阶段 1（请求头检查）：在接收完整 HTTP 请求头后执行，可在读取请求体前及早判定",
	2: "阶段 2（请求体与参数检查）：在解析查询参数、表单、JSON/XML 及上传文件后执行",
	3: "阶段 3（响应头检查）：在接收源站返回响应头后执行",
	4: "阶段 4（响应体检查）：在接收源站响应正文后执行，用于识别敏感报错、源码泄露与 WebShell 回显",
	5: "阶段 5（日志与关联分析）：在响应完成后执行异常评分汇总与审计关联，不阻断流量",
}

var severityScoreMeta = map[string]struct {
	label string
	score int
}{
	"CRITICAL": {label: "严重", score: 5},
	"ERROR":    {label: "高", score: 4},
	"WARNING":  {label: "中", score: 3},
	"NOTICE":   {label: "低", score: 2},
}

var transformLabelsZh = map[string]string{
	"base64Decode":       "Base64 解码",
	"base64DecodeExt":    "扩展 Base64 解码",
	"cmdLine":            "命令行混淆归一化",
	"compressWhitespace": "空白字符压缩",
	"cssDecode":          "CSS 转义解码",
	"escapeSeqDecode":    "转义序列解码",
	"hexDecode":          "十六进制解码",
	"hexEncode":          "十六进制编码",
	"htmlEntityDecode":   "HTML 实体解码",
	"jsDecode":           "JavaScript 转义解码",
	"length":             "长度计算",
	"lowercase":          "转小写归一化",
	"normalizePath":      "Unix 路径规范化",
	"normalizePathWin":   "Windows 路径规范化",
	"removeComments":     "移除注释块",
	"removeCommentsChar": "移除注释定界符",
	"removeNulls":        "移除空字节",
	"removeWhitespace":   "移除空白字符",
	"replaceComments":    "注释替换为空格",
	"replaceNulls":       "空字节替换为空格",
	"sha1":               "SHA-1 摘要计算",
	"trim":               "首尾空白裁剪",
	"uppercase":          "转大写归一化",
	"urlDecode":          "URL 解码",
	"urlDecodeUni":       "Unicode URL 解码",
	"utf8toUnicode":      "UTF-8 转 Unicode 归一化",
}

var targetBaseLabelsZh = map[string]string{
	"ARGS":                   "请求参数值（ARGS）",
	"ARGS_GET":               "GET 查询参数值（ARGS_GET）",
	"ARGS_GET_NAMES":         "GET 查询参数名（ARGS_GET_NAMES）",
	"ARGS_NAMES":             "请求参数名（ARGS_NAMES）",
	"FILES":                  "上传文件名（FILES）",
	"FILES_NAMES":            "上传表单字段名（FILES_NAMES）",
	"MULTIPART_PART_HEADERS": "Multipart 分段请求头（MULTIPART_PART_HEADERS）",
	"QUERY_STRING":           "原始查询字符串（QUERY_STRING）",
	"REMOTE_ADDR":            "客户端连接地址（REMOTE_ADDR）",
	"REQBODY_PROCESSOR":      "请求体解析器类型（REQBODY_PROCESSOR）",
	"REQUEST_BASENAME":       "请求路径文件名（REQUEST_BASENAME）",
	"REQUEST_BODY":           "HTTP 请求体（REQUEST_BODY）",
	"REQUEST_BODY_LENGTH":    "HTTP 请求体字节长度（REQUEST_BODY_LENGTH）",
	"REQUEST_COOKIES":        "Cookie 值（REQUEST_COOKIES）",
	"REQUEST_COOKIES_NAMES":  "Cookie 名称（REQUEST_COOKIES_NAMES）",
	"REQUEST_FILENAME":       "请求路径（REQUEST_FILENAME）",
	"REQUEST_HEADERS":        "HTTP 请求头（REQUEST_HEADERS）",
	"REQUEST_HEADERS_NAMES":  "HTTP 请求头名称（REQUEST_HEADERS_NAMES）",
	"REQUEST_LINE":           "HTTP 请求行（REQUEST_LINE）",
	"REQUEST_METHOD":         "HTTP 请求方法（REQUEST_METHOD）",
	"REQUEST_PROTOCOL":       "HTTP 协议版本（REQUEST_PROTOCOL）",
	"REQUEST_URI":            "请求 URI（REQUEST_URI）",
	"REQUEST_URI_RAW":        "原始未规范化 URI（REQUEST_URI_RAW）",
	"RESPONSE_BODY":          "HTTP 响应正文（RESPONSE_BODY）",
	"RESPONSE_HEADERS":       "HTTP 响应头（RESPONSE_HEADERS）",
	"RESPONSE_STATUS":        "HTTP 响应状态码（RESPONSE_STATUS）",
	"TX":                     "引擎事务变量（TX）",
	"UNIQUE_ID":              "请求唯一标识（UNIQUE_ID）",
	"XML":                    "XML 文档节点与属性（XML）",
}

var txVarLabelsZh = map[string]string{
	"DETECTION_PARANOIA_LEVEL":               "策略检测偏执级别（TX:DETECTION_PARANOIA_LEVEL）",
	"BLOCKING_PARANOIA_LEVEL":                "策略阻断偏执级别（TX:BLOCKING_PARANOIA_LEVEL）",
	"BLOCKING_INBOUND_ANOMALY_SCORE":         "入站阻断异常总分（TX:BLOCKING_INBOUND_ANOMALY_SCORE）",
	"BLOCKING_OUTBOUND_ANOMALY_SCORE":        "出站阻断异常总分（TX:BLOCKING_OUTBOUND_ANOMALY_SCORE）",
	"DETECTION_INBOUND_ANOMALY_SCORE":        "入站检测异常总分（TX:DETECTION_INBOUND_ANOMALY_SCORE）",
	"DETECTION_OUTBOUND_ANOMALY_SCORE":       "出站检测异常总分（TX:DETECTION_OUTBOUND_ANOMALY_SCORE）",
	"BLOCKING_ANOMALY_SCORE":                 "汇总阻断异常分（TX:BLOCKING_ANOMALY_SCORE）",
	"DETECTION_ANOMALY_SCORE":                "汇总检测异常分（TX:DETECTION_ANOMALY_SCORE）",
	"JZ_BLOCKING_INBOUND_SCORE":              "九章二次阻断汇总分（TX:JZ_BLOCKING_INBOUND_SCORE）",
	"REPORTING_LEVEL":                        "关联报告级别（TX:REPORTING_LEVEL）",
	"CRS_VALIDATE_UTF8_ENCODING":             "UTF-8 编码校验开关（TX:CRS_VALIDATE_UTF8_ENCODING）",
	"MAX_NUM_ARGS":                           "最大参数数量限制（TX:MAX_NUM_ARGS）",
	"ARG_NAME_LENGTH":                        "单个参数名长度限制（TX:ARG_NAME_LENGTH）",
	"ARG_LENGTH":                             "单个参数值长度限制（TX:ARG_LENGTH）",
	"TOTAL_ARG_LENGTH":                       "参数总长度限制（TX:TOTAL_ARG_LENGTH）",
	"MAX_FILE_SIZE":                          "单文件大小限制（TX:MAX_FILE_SIZE）",
	"COMBINED_FILE_SIZES":                    "上传文件总大小限制（TX:COMBINED_FILE_SIZES）",
	"ENABLE_DEFAULT_COLLECTIONS":             "默认会话集合开关（TX:ENABLE_DEFAULT_COLLECTIONS）",
	"AUTO-DECODING-PLUGIN_DOUBLE_DECODING":   "自动解码双轮开关（TX:AUTO-DECODING-PLUGIN_DOUBLE_DECODING）",
	"crs_setup_version":                      "CRS 初始化配置版本（TX:crs_setup_version）",
	"crs_skip_response_analysis":             "跳过响应分析开关（TX:crs_skip_response_analysis）",
	"sampling_percentage":                    "流量采样率（TX:sampling_percentage）",
	"sampling_rnd100":                        "采样随机值（TX:sampling_rnd100）",
	"enforce_bodyproc_urlencoded":            "强制 URLENCODED 解析开关（TX:enforce_bodyproc_urlencoded）",
	"detection_paranoia_level":               "策略检测偏执级别（TX:detection_paranoia_level）",
	"blocking_paranoia_level":                "策略阻断偏执级别（TX:blocking_paranoia_level）",
	"inbound_anomaly_score_threshold":        "入站异常阻断阈值（TX:inbound_anomaly_score_threshold）",
	"outbound_anomaly_score_threshold":       "出站异常阻断阈值（TX:outbound_anomaly_score_threshold）",
	"reporting_level":                        "关联报告级别（TX:reporting_level）",
	"early_blocking":                         "提前阻断开关（TX:early_blocking）",
	"critical_anomaly_score":                 "严重级分值配置（TX:critical_anomaly_score）",
	"error_anomaly_score":                    "高危级分值配置（TX:error_anomaly_score）",
	"warning_anomaly_score":                  "中危级分值配置（TX:warning_anomaly_score）",
	"notice_anomaly_score":                   "低危级分值配置（TX:notice_anomaly_score）",
	"allowed_methods":                        "允许 HTTP 方法配置（TX:allowed_methods）",
	"allowed_request_content_type":           "允许 Content-Type 配置（TX:allowed_request_content_type）",
	"allowed_request_content_type_charset":   "允许请求字符集配置（TX:allowed_request_content_type_charset）",
	"allowed_http_versions":                  "允许 HTTP 版本配置（TX:allowed_http_versions）",
	"restricted_extensions":                  "受限文件扩展名配置（TX:restricted_extensions）",
	"restricted_headers_basic":               "基础受限请求头配置（TX:restricted_headers_basic）",
	"restricted_headers_extended":            "扩展受限请求头配置（TX:restricted_headers_extended）",
	"allow_method_override_parameter":        "允许 _method 覆盖开关（TX:allow_method_override_parameter）",
	"auto-decoding-plugin_enabled":           "自动解码插件开关（TX:auto-decoding-plugin_enabled）",
	"incubator-plugin_enabled":               "孵化器插件开关（TX:incubator-plugin_enabled）",
	"wordpress-rule-exclusions-plugin_enabled":  "WordPress 排除插件开关",
	"nextcloud-rule-exclusions-plugin_enabled":  "Nextcloud 排除插件开关",
	"drupal-rule-exclusions-plugin_enabled":     "Drupal 排除插件开关",
	"phpmyadmin-rule-exclusions-plugin_enabled": "phpMyAdmin 排除插件开关",
	"dokuwiki-rule-exclusions-plugin_enabled":   "DokuWiki 排除插件开关",
	"xenforo-rule-exclusions-plugin_enabled":    "XenForo 排除插件开关",
}

var capecLabelsZh = map[string]string{
	"capec/1/180/77":              "CAPEC-77：操纵用户可控变量",
	"capec/1000/118/116":          "CAPEC-116：敏感信息发掘",
	"capec/1000/118/116/54":       "CAPEC-54：查询系统与报错信息泄露",
	"capec/1000/118/116/54/127":   "CAPEC-127：目录索引泄露",
	"capec/1000/118/224/541/310":  "CAPEC-310：自动化扫描探测",
	"capec/1000/152":              "CAPEC-152：注入攻击",
	"capec/1000/152/137/15/460":   "CAPEC-460：HTTP 参数污染",
	"capec/1000/152/137/6":        "CAPEC-6：参数注入",
	"capec/1000/152/175/253":      "CAPEC-253：远程文件包含（RFI）",
	"capec/1000/152/242":          "CAPEC-242：代码注入",
	"capec/1000/152/242/63":       "CAPEC-63：跨站脚本（XSS）",
	"capec/1000/152/248":          "CAPEC-248：命令注入",
	"capec/1000/152/248/136":      "CAPEC-136：LDAP 注入",
	"capec/1000/152/248/66":       "CAPEC-66：SQL 注入",
	"capec/1000/152/248/66/109":   "CAPEC-109：对象关系映射（ORM）注入",
	"capec/1000/152/248/88":       "CAPEC-88：操作系统命令注入",
	"capec/1000/153/267":          "CAPEC-267：编码混淆绕过",
	"capec/1000/210/272":          "CAPEC-272：协议操纵",
	"capec/1000/210/272/220":      "CAPEC-220：HTTP 协议操纵",
	"capec/1000/210/272/220/273":  "CAPEC-273：HTTP 响应拆分",
	"capec/1000/210/272/220/274":  "CAPEC-274：HTTP 方法篡改",
	"capec/1000/210/272/220/33":   "CAPEC-33：HTTP 请求走私",
	"capec/1000/210/272/220/34":   "CAPEC-34：HTTP 响应拆分/头注入",
	"capec/1000/225/122/17/650":   "CAPEC-650：上传 WebShell 后门",
	"capec/1000/225/21/593/61":    "CAPEC-61：会话固定攻击",
	"capec/1000/225/664":          "CAPEC-664：服务端请求伪造（SSRF）",
	"capec/1000/255/153":          "CAPEC-153：输入数据操纵",
	"capec/1000/255/153/126":      "CAPEC-126：路径遍历",
	"capec/1000/255/153/267":      "CAPEC-267：多形态编码绕过",
	"capec/1000/255/153/267/120":  "CAPEC-120：双重编码绕过",
	"capec/1000/255/153/267/72":   "CAPEC-72：URL 编码滥用",
	"capec/137/134":               "CAPEC-134：CRLF 注入",
	"capec/272/220":               "CAPEC-220：HTTP 协议操纵",
}

type attackAdvice struct {
	risk   string
	tuning string
}

var attackTypeAdviceZh = map[string]attackAdvice{
	"SQL_INJECTION": {
		risk:   "SQL 注入攻击可导致攻击者绕过身份认证、批量窃取数据库敏感记录、篡改或删除业务数据，严重时甚至借助数据库扩展（UDF、xp_cmdshell 等）控制操作系统。",
		tuning: "若富文本、报表检索条件、代码编辑器或含复杂数学/逻辑表达式的字段触发误报，建议针对具体接口路径与参数名配置「移除变量检测」例外，切勿对整站关闭 SQL 注入检测。",
	},
	"XSS": {
		risk:   "跨站脚本（XSS）攻击可在受害者浏览器中执行恶意 JavaScript，导致会话 Cookie/Token 窃取、账号劫持、钓鱼页面篡改及内部管理操作越权执行。",
		tuning: "CMS 富文本编辑、HTML 邮件模板、Markdown/代码片段提交接口较易命中 XSS 规则；建议仅对对应路径的特定富文本字段配置精细例外，并配合后端输出编码与 CSP 策略纵深防御。",
	},
	"COMMAND_INJECTION": {
		risk:   "远程命令注入可使攻击者在应用服务器直接执行任意操作系统指令，进而窃取凭据、植入持久化后门、横向渗透内网或勒索加密主机。",
		tuning: "运维脚本平台、终端工具接口或含大量技术命令行文本的文档系统可能产生误报；建议限定路径与参数名配置例外，非 Windows 源站可按需评估是否停用 Windows 专属命令规则。",
	},
	"REMOTE_CODE_EXECUTION": {
		risk:   "远程代码执行（RCE）属于最高危漏洞利用类型，攻击者可直接以应用进程权限运行任意代码，导致服务器被完全接管及核心业务与数据泄露。",
		tuning: "本类规则通常针对高置信度漏洞利用载荷，误报率较低；如开发文档、安全测试工具或特定业务表达式接口误报，请严格限定路径和参数做最小粒度例外。",
	},
	"LOCAL_FILE_INCLUSION": {
		risk:   "本地文件包含与路径遍历可导致服务器配置文件、环境变量、数据库密钥、应用源码乃至系统口令文件被未授权读取，结合日志投毒或临时文件还可升级为远程代码执行。",
		tuning: "若业务接口参数确实需要传递相对路径或文件名，建议校验路径规范后仅对该接口参数做精细例外，切勿放宽全局目录穿越检测。",
	},
	"REMOTE_FILE_INCLUSION": {
		risk:   "远程文件包含（RFI）允许攻击者诱使源站加载并执行外部恶意服务器上的脚本代码，直接导致远程代码执行或敏感信息外带。",
		tuning: "若业务存在合法的外部回调 URL、跳转地址（redirect_uri）或外链图片参数，建议针对具体参数名配置变量级例外并在后端严格校验目标域名白名单。",
	},
	"PHP_INJECTION": {
		risk:   "PHP 代码注入、伪协议滥用及反序列化攻击可直接在 PHP 进程内执行任意代码或读写服务器文件，导致站点被植入 WebShell 并完全失陷。",
		tuning: "若站点后端完全不使用 PHP 技术栈（例如纯 Go/Java/Node.js 服务）且出现文本误报，可评估按应用停用 PHP 专属规则；PHP 站点请仅针对具体误报参数做精细例外。",
	},
	"JAVA_INJECTION": {
		risk:   "Java 表达式注入（OGNL/SpEL/EL）、JNDI 注入（Log4Shell）与反序列化利用链可直接触发远程代码执行，威胁等级极高。",
		tuning: "若后端为非 Java 应用且特定文本触发误报，可按应用评估是否停用部分 Java 专属规则；Java/Spring/Tomcat 应用强烈建议保持启用，误报时仅对具体路径做最小例外。",
	},
	"PROTOCOL_VIOLATION": {
		risk:   "HTTP 协议违规与走私攻击利用网关、代理与源站对畸形报文解析的细微差异，可实现缓存投毒、请求劫持、身份校验绕过或绕过 WAF 检测。",
		tuning: "部分老旧客户端、非标物联网设备或定制 API（如使用非常规 Content-Type、IP 直连 Host、自定义扩展方法）可能触发协议合规规则；建议结合抓包核实后按应用或路径调整策略或添加精确例外。",
	},
	"SESSION_FIXATION": {
		risk:   "会话固定攻击通过诱使受害者使用攻击者预先指定的 SessionID 完成登录，从而直接劫持受害者已认证会话。",
		tuning: "若遗留系统确实通过 URL 参数传递会话标识且存在跨域名正常跳转，建议优先改造为 HttpOnly Cookie 承载会话；过渡期可针对特定来源域名与路径配置临时例外。",
	},
	"SCANNER_DETECTION": {
		risk:   "自动化漏洞扫描器与恶意爬虫常用于规模化资产测绘、目录爆破与批量漏洞探测，既会暴露系统弱点也会带来额外源站负载。",
		tuning: "内部授权安全巡检、监控探针或合作爬虫触发本规则时，可按固定出口 IP 配置白名单或局部例外；观测类爬虫规则默认不阻断，可根据业务需要决定是否联动 L7 规则拦截。",
	},
	"INFORMATION_DISCLOSURE": {
		risk:   "敏感路径暴露、备份文件下载及数据库/框架报错堆栈泄露会向攻击者直接暴露源码、配置密钥、表结构与组件版本，大幅降低定向攻击门槛。",
		tuning: "若技术博客、在线 IDE 或 API 调试页面正常输出包含代码/SQL 示例导致出站误报，可针对对应路径配置例外；对于真正的敏感文件暴露与报错回显，应优先在源站关闭调试模式并清理备份文件。",
	},
	"SSRF": {
		risk:   "服务端请求伪造（SSRF）可使攻击者借应用服务器作为跳板访问内网管理接口、扫描内网端口或窃取云主机元数据服务（IMDS）中的临时访问凭证。",
		tuning: "若业务支持 Webhook、远程拉图或 URL 预览功能且需传入合法外网地址，建议针对特定参数做精细放行并确保后端已禁用内网与元数据网段访问。",
	},
	"XXE_INJECTION": {
		risk:   "XML 外部实体注入（XXE）可导致服务器任意本地文件读取、内网 SSRF 探测以及实体扩展拒绝服务（Billion Laughs 攻击）。",
		tuning: "若业务使用标准 XML/SOAP 接口且包含合法 DTD 声明，可针对具体接口路径做精细例外，同时务必在后端 XML 解析器层面禁用外部实体解析。",
	},
	"WEBSHELL": {
		risk:   "WebShell 后门木马意味着攻击者正在尝试上传、植入或远程操控持久化后门，一旦得手可长期窃取数据、篡改网页或作为内网渗透跳板。",
		tuning: "此类规则风险极高，正常业务极少命中；若命中请第一时间排查源站是否已被入侵并核查上传目录，确认安全测试或代码平台误报后再做路径级精细例外。",
	},
	"FILE_UPLOAD": {
		risk:   "恶意文件上传与双扩展名/空字节/图片马绕过可导致攻击者向服务器写入可执行脚本或配置文件（如 .htaccess/.user.ini），进而获取服务器控制权。",
		tuning: "若业务上传接口允许特定压缩包或特殊命名文件导致误报，请在确认源站上传目录已禁执行权限后，针对特定上传路径配置精细例外。",
	},
	"DESERIALIZATION": {
		risk:   "不安全反序列化（Java/PHP/Python/.NET 等）允许攻击者构造恶意对象流，在服务端反序列化阶段直接触发利用链执行任意代码。",
		tuning: "若应用正常通过 Cookie 或表单传递合法序列化数据结构（如 ViewState 或签名 Token）引发误报，请核实数据完整性签名机制后针对该特定字段配置变量级例外。",
	},
	"SSTI": {
		risk:   "服务端模板注入（SSTI）可使攻击者在 Jinja2、FreeMarker、Velocity、Twig、Thymeleaf 等模板引擎中逃逸沙箱并直接执行任意服务端代码。",
		tuning: "邮件/短信模板编辑后台、低代码公式配置或 Vue/Angular 前端源码提交页面可能出现 {{...}} / ${...} 语法误报；建议仅对对应管理后台路径配置精确例外。",
	},
	"DOS": {
		risk:   "应用层拒绝服务载荷（如死循环表达式、Fork 炸弹、超长参数或畸形 Range 分片）可迅速耗尽应用线程、CPU 或内存资源，导致正常用户无法访问。",
		tuning: "若业务存在合理的大文件分片下载（如 PDF 预览）或超大数据表单提交，请优先在防护策略中适当放宽请求体/参数上限，而非直接关闭防护规则。",
	},
	"MASS_ASSIGNMENT": {
		risk:   "批量赋值与原型链污染攻击通过提交未预期的权限或内部字段（如 isAdmin、role、__proto__），诱导后端自动绑定并实现越权提权或逻辑篡改。",
		tuning: "管理后台修改用户角色或切换调试开关的合法接口可能携带同名参数；建议仅针对已做好严格服务端鉴权的管理接口路径配置精细例外。",
	},
	"EXCLUSION": {
		risk:   "该规则属于应用级白名单误报排除规则，本身不阻断任何请求，仅在匹配指定开源应用路径与表单字段时放行已知误报，避免正常业务受阻。",
		tuning: "仅当站点运行对应开源应用时发挥降噪作用；若业务未部署该应用，可保持默认或通过规则覆盖按需停用以精简规则链。",
	},
	"OTHER": {
		risk:   "用于补充校验请求合规性、控制规则引擎执行流程或拦截通用高危异常特征，保障 Web 防护链路稳定、准确运行。",
		tuning: "如需针对特定业务路径调整本规则行为，请先在安全事件中心核实命中上下文，再通过规则覆盖或精细例外策略进行放行。",
	},
}

// ParseTagsJSON 解析数据库或接口中的 JSON 数组格式标签字节。
func ParseTagsJSON(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// DescribeRule 为任意 WAF 规则生成完整、结构化的中文详细说明。
// 说明来源优先级：人工维护覆盖（CUSTOM） > 内置中文规则库/模板规则（BUILTIN）
// > 同步时 .conf 自动解析元数据（PARSED） > 元数据自动推导（AUTO）。
func DescribeRule(in RuleDescribeInput) RuleDetail {
	// 1. 优先处理 1,694 条模板型扩展规则（爬虫 UA / AI 爬虫 / 搜索引擎爬虫声称）
	if tmpl, ok := describeTemplateRule(in); ok {
		tmpl.Source = "BUILTIN"
		tmpl.SourceLabel = "内置中文规则库"
		applyCustomOverride(&tmpl, in.CustomOverride)
		return tmpl
	}

	spec, hasSpec := ruleSpecsZh[in.RuleID]
	detailSource := "BUILTIN"
	detailSourceLabel := "内置中文规则库"
	if !hasSpec {
		if parsed, ok := parseStoredRuleSpec(in.ParsedSpec); ok {
			spec = parsed
			hasSpec = true
			detailSource = "PARSED"
			detailSourceLabel = "规则文件自动解析"
		} else {
			detailSource = "AUTO"
			detailSourceLabel = "元数据自动生成"
		}
	}

	kind := "det"
	if hasSpec && spec.Kind != "" {
		kind = spec.Kind
	} else {
		kind = inferKindFallback(in)
	}
	tm, ok := ruleTypeMeta[kind]
	if !ok {
		tm = ruleTypeMeta["det"]
	}

	pl := 0
	if hasSpec && spec.PL > 0 {
		pl = spec.PL
	} else {
		pl = extractPLFromTags(in.Tags)
	}

	targets := formatTargetsZh(spec.Targets)
	summary := ""
	if hasSpec && spec.Summary != "" {
		summary = spec.Summary
	} else {
		summary = buildFallbackSummary(in, kind)
	}

	detectionLogic := buildDetectionLogic(in, spec, hasSpec, kind, targets)
	riskImpact, tuningAdvice := buildRiskAndTuning(in, spec, hasSpec, kind, pl)
	phaseDesc := formatPhaseZh(in.Phase)
	plDesc := formatParanoiaLevelZh(in, kind, pl)
	actionDesc := formatActionBehaviorZh(in, spec, hasSpec, kind)
	refs := buildReferencesZh(in)

	if targets == nil {
		targets = []string{}
	}
	if refs == nil {
		refs = []string{}
	}

	detail := RuleDetail{
		RuleType:         tm.code,
		RuleTypeLabel:    tm.label,
		Source:           detailSource,
		SourceLabel:      detailSourceLabel,
		Summary:          summary,
		DetectionLogic:   detectionLogic,
		RiskImpact:       riskImpact,
		TuningAdvice:     tuningAdvice,
		PhaseDescription: phaseDesc,
		ParanoiaLevel:    plDesc,
		ActionBehavior:   actionDesc,
		Targets:          targets,
		References:       refs,
	}
	applyCustomOverride(&detail, in.CustomOverride)
	return detail
}

func applyCustomOverride(detail *RuleDetail, ov *RuleDescriptionOverride) {
	if detail == nil || !ov.HasAnyContent() {
		return
	}
	cp := *ov
	cp.Summary = strings.TrimSpace(cp.Summary)
	cp.DetectionLogic = strings.TrimSpace(cp.DetectionLogic)
	cp.RiskImpact = strings.TrimSpace(cp.RiskImpact)
	cp.TuningAdvice = strings.TrimSpace(cp.TuningAdvice)
	if cp.Summary != "" {
		detail.Summary = cp.Summary
	}
	if cp.DetectionLogic != "" {
		detail.DetectionLogic = cp.DetectionLogic
	}
	if cp.RiskImpact != "" {
		detail.RiskImpact = cp.RiskImpact
	}
	if cp.TuningAdvice != "" {
		detail.TuningAdvice = cp.TuningAdvice
	}
	detail.Customized = true
	detail.Source = "CUSTOM"
	detail.SourceLabel = "人工维护说明"
	detail.CustomFields = &cp
}

// RuleDescription 返回单段式中文详细说明（供列表与概要字段使用）。
func RuleDescription(in RuleDescribeInput) string {
	return DescribeRule(in).Summary
}

func describeTemplateRule(in RuleDescribeInput) (RuleDetail, bool) {
	base := strings.TrimSuffix(filepath.Base(in.FileName), filepath.Ext(in.FileName))
	rawName := strings.TrimSpace(in.Name)
	rawMsg := strings.TrimSpace(in.Message)

	// 1) scanner-fingerprints-ext（爬虫 UA 扩展指纹，1501 条）
	if base == "scanner-fingerprints-ext" || strings.HasPrefix(rawName, "扫描器指纹：爬虫 UA（") || strings.HasPrefix(rawMsg, "Scanner fingerprint: crawler UA (") {
		pat := extractInner(rawName, "扫描器指纹：爬虫 UA（", "）")
		if pat == "" {
			pat = extractInner(rawMsg, "Scanner fingerprint: crawler UA (", ")")
		}
		if pat == "" {
			pat = rawName
		}
		return RuleDetail{
			RuleType:         "OBSERVE",
			RuleTypeLabel:    "观测告警规则",
			Summary:          fmt.Sprintf("属于九章「扩展爬虫指纹检测」观测规则包（源自开源 crawler-user-agents 指纹库）。专门识别客户端 User-Agent 请求头匹配模式「%s」的已知自动化爬虫或抓取客户端，用于全站爬虫流量测绘与审计观测。", pat),
			DetectionLogic:   fmt.Sprintf("在阶段 1（请求头检查）读取 User-Agent 请求头（REQUEST_HEADERS:User-Agent），使用正则表达式匹配爬虫特征「%s」；采用 pass + log 仅记录策略，不累加异常评分也不阻断请求。", pat),
			RiskImpact:       "自动化爬虫与抓取脚本可能消耗源站带宽、抓取公开业务数据或掩护批量扫描行为；本规则以低干扰观测方式记录命中线索，便于安全运营统计爬虫分布与交叉研判异常请求。",
			TuningAdvice:     "本规则默认仅观测记录，不会拦截正常业务流量。如需主动封禁该爬虫，可在 L7 访问控制或自定义规则中配置阻断；若为业务合作抓取产生过多告警噪音，可按来源 IP 或规则覆盖停用该条观测规则。",
			PhaseDescription: formatPhaseZh(1),
			ParanoiaLevel:    "默认观测生效（不随偏执级别屏蔽）",
			ActionBehavior:   "仅观测记录（pass + log，命中后生成安全日志但不阻断、不累加异常评分）",
			Targets:          []string{"User-Agent 请求头（REQUEST_HEADERS:User-Agent）"},
			References:       buildReferencesZh(in),
		}, true
	}

	// 2) ai-crawler-control（AI 爬虫管控，180 条）
	if base == "ai-crawler-control" || strings.HasPrefix(rawName, "AI 爬虫 UA：") || strings.HasPrefix(rawMsg, "AI crawler UA: ") {
		bot := strings.TrimPrefix(rawName, "AI 爬虫 UA：")
		if bot == rawName {
			bot = strings.TrimPrefix(rawMsg, "AI crawler UA: ")
		}
		bot = strings.TrimSpace(bot)
		return RuleDetail{
			RuleType:         "OBSERVE",
			RuleTypeLabel:    "观测告警规则",
			Summary:          fmt.Sprintf("属于九章「AI 爬虫管控」观测规则包（源自开源 ai.robots.txt 清单）。专门识别客户端 User-Agent 包含「%s」标识的大模型训练或 AI 检索抓取爬虫，帮助站点掌握 AI 抓取来源与频次。", bot),
			DetectionLogic:   fmt.Sprintf("在阶段 1（请求头检查）读取 User-Agent 请求头（REQUEST_HEADERS:User-Agent），使用子串精确包含匹配「%s」；采用 pass + log 仅记录方式，不累加异常评分、不直接拦截请求。", bot),
			RiskImpact:       "高频 AI 抓取爬虫可能导致站点原创内容被未经授权采集用于模型训练，同时增加源站带宽与接口负载；观测记录可为制定反爬与版权防护策略提供数据依据。",
			TuningAdvice:     "本规则默认仅观测记录，不影响业务可用性。如业务策略禁止该 AI 爬虫访问，可通过 L7 访问控制、Bot 防护或自定义阻断规则实施拦截；若允许其收录抓取，可保留观测或停用本条减少日志。",
			PhaseDescription: formatPhaseZh(1),
			ParanoiaLevel:    "默认观测生效（不随偏执级别屏蔽）",
			ActionBehavior:   "仅观测记录（pass + log，命中后生成安全日志但不阻断、不累加异常评分）",
			Targets:          []string{"User-Agent 请求头（REQUEST_HEADERS:User-Agent）"},
			References:       buildReferencesZh(in),
		}, true
	}

	// 3) fake-bot-claims（搜索引擎爬虫 UA 声称标记，13 条）
	if base == "fake-bot-claims" || strings.HasPrefix(rawName, "搜索引擎爬虫 UA 声明：") || strings.HasPrefix(rawMsg, "Search engine bot UA claim: ") {
		bot := strings.TrimPrefix(rawName, "搜索引擎爬虫 UA 声明：")
		if bot == rawName {
			bot = strings.TrimPrefix(rawMsg, "Search engine bot UA claim: ")
		}
		bot = strings.TrimSpace(bot)
		return RuleDetail{
			RuleType:         "OBSERVE",
			RuleTypeLabel:    "观测告警规则",
			Summary:          fmt.Sprintf("属于九章「搜索引擎爬虫声称检测」观测规则包。当请求的 User-Agent 自称为主流搜索引擎爬虫「%s」时打标记录；本规则仅做声称标记、不做在线真伪反查，供安全运营结合攻击命中交叉识别伪造爬虫。", bot),
			DetectionLogic:   fmt.Sprintf("在阶段 1（请求头检查）读取 User-Agent 请求头（REQUEST_HEADERS:User-Agent），检查是否包含「%s」标识；采用 pass + log 仅标记策略，不累加异常评分也不阻断真实搜索引擎抓取。", bot),
			RiskImpact:       "攻击者和恶意扫描器常将 User-Agent 伪装为知名搜索引擎爬虫以企图绕过基础访问限制。真实搜索引擎极少触发攻击检测规则，因此「命中本声称标记 + 同时触发攻击规则」是高置信度的假冒爬虫入侵线索。",
			TuningAdvice:     "本规则不会阻断真实搜索引擎收录，无需担心影响 SEO。若无需记录此类观测标签，可通过规则覆盖停用；排查疑似假冒爬虫时建议在事件中心结合源 IP 归属与 rDNS 反查核验。",
			PhaseDescription: formatPhaseZh(1),
			ParanoiaLevel:    "默认观测生效（不随偏执级别屏蔽）",
			ActionBehavior:   "仅观测记录（pass + log，打标记录但不阻断、不累加异常评分）",
			Targets:          []string{"User-Agent 请求头（REQUEST_HEADERS:User-Agent）"},
			References:       buildReferencesZh(in),
		}, true
	}

	return RuleDetail{}, false
}

func extractInner(s, prefix, suffix string) string {
	if strings.HasPrefix(s, prefix) && strings.HasSuffix(s, suffix) && len(s) > len(prefix)+len(suffix) {
		return s[len(prefix) : len(s)-len(suffix)]
	}
	return ""
}

func inferKindFallback(in RuleDescribeInput) string {
	if in.RuleSource == SourceThirdParty || in.AttackType == "EXCLUSION" {
		return "exc"
	}
	if in.RuleSource == SourceCRSPlugin {
		return "pre"
	}
	if in.RuleID == 949110 || in.RuleID == 949111 || in.RuleID == 959100 || in.RuleID == 959101 || in.RuleID == 9000102 || in.RuleID == 9000104 {
		return "blk"
	}
	if strings.Contains(in.Name, "内部规则") {
		return "int"
	}
	return "det"
}

func extractPLFromTags(tags []string) int {
	for _, t := range tags {
		if strings.HasPrefix(t, "paranoia-level/") {
			if n, err := strconv.Atoi(strings.TrimPrefix(t, "paranoia-level/")); err == nil && n >= 1 && n <= 4 {
				return n
			}
		}
	}
	return 0
}

func formatPhaseZh(phase int) string {
	if desc, ok := phaseDescriptionsZh[phase]; ok {
		return desc
	}
	if phase > 0 {
		return fmt.Sprintf("阶段 %d：在对应 WAF 网关处理阶段执行", phase)
	}
	return "阶段 2（请求体与参数检查）：默认请求检测阶段"
}

func formatParanoiaLevelZh(in RuleDescribeInput, kind string, pl int) string {
	switch pl {
	case 1:
		return "PL1（默认启用，低误报基线防护）"
	case 2:
		return "PL2（增强防护，策略偏执级别 ≥ 2 时生效）"
	case 3:
		return "PL3（严格防护，策略偏执级别 ≥ 3 时生效）"
	case 4:
		return "PL4（极严防护，策略偏执级别 = 4 时生效，误报风险较高）"
	}
	switch kind {
	case "int":
		return "无条件执行（引擎内部流程控制）"
	case "blk":
		return "无条件执行（异常评分阻断评估）"
	case "exc":
		return "随对应应用排除插件生效"
	case "pre":
		return "随对应 CRS 插件开关生效"
	case "obs":
		return "默认观测生效（不随偏执级别屏蔽）"
	}
	if in.RuleSource == SourceCustomPack || in.RuleSource == SourceJiuzhang || in.RuleSource == SourceCustom {
		return "全偏执级别生效（独立于 CRS PL 分级）"
	}
	return "默认基线生效"
}

func formatActionBehaviorZh(in RuleDescribeInput, spec ruleSpec, hasSpec bool, kind string) string {
	sev := severityScoreMeta[strings.ToUpper(strings.TrimSpace(in.Severity))]
	if sev.label == "" {
		sev = severityScoreMeta["NOTICE"]
	}
	if hasSpec {
		switch spec.Action {
		case "score_in":
			return fmt.Sprintf("异常评分（入站，%s级别 +%d 分；累计达到策略入站阈值后在防护模式阻断，观察模式仅记录）", sev.label, sev.score)
		case "score_out":
			return fmt.Sprintf("异常评分（出站，%s级别 +%d 分；累计达到策略出站阈值后在防护模式阻断，观察模式仅记录）", sev.label, sev.score)
		case "deny_403":
			if kind == "blk" {
				return "阈值达标阻断（防护模式返回 403 拦截，观察模式自动降级为仅记录安全事件）"
			}
			return "直接阻断（防护模式返回 403 拦截，观察模式仅记录安全事件）"
		case "deny_500":
			return "配置校验强制中断（返回 500 状态码并记录严重告警日志）"
		case "pass_log":
			return "仅观测记录（pass + log，命中后生成安全日志但不阻断、不累加异常评分）"
		case "skip":
			return "内部流程跳转（满足条件跳过后续规则段，不阻断、不记录日志）"
		case "ctl":
			return "动态规则放行（通过控制指令移除指定误报检测，不阻断请求）"
		case "setvar":
			if kind == "pre" {
				return "解码预处理（写入事务变量供下游检测规则一并检查，不阻断、不记日志）"
			}
			return "内部变量赋值（初始化或汇总引擎事务变量，不阻断、不记日志）"
		case "pass_nolog":
			return "内部静默控制（不阻断、不记录日志）"
		case "block":
			return fmt.Sprintf("安全拦截/计分（%s级别，防护模式下阻断，观察模式下仅记录）", sev.label)
		}
	}
	switch kind {
	case "int":
		return "内部流程控制（不阻断、不记录日志）"
	case "exc":
		return "动态规则放行（降低误报，不阻断请求）"
	case "pre":
		return "预处理变换（辅助下游检测，不直接阻断）"
	case "obs":
		return "仅观测记录（命中后记录日志，不直接阻断）"
	case "blk":
		return "阈值达标阻断（防护模式返回 403，观察模式仅记录）"
	default:
		return fmt.Sprintf("异常评分/拦截（%s级别 +%d 分，达到策略阈值后在防护模式下阻断）", sev.label, sev.score)
	}
}

func formatTargetsZh(rawTargets []string) []string {
	if len(rawTargets) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(rawTargets))
	out := make([]string, 0, len(rawTargets))
	for _, raw := range rawTargets {
		label := formatOneTargetZh(raw)
		if label == "" || seen[label] {
			continue
		}
		seen[label] = true
		out = append(out, label)
	}
	return out
}

func formatOneTargetZh(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	neg := false
	if strings.HasPrefix(s, "!") {
		neg = true
		s = strings.TrimPrefix(s, "!")
	}
	count := false
	if strings.HasPrefix(s, "&") {
		count = true
		s = strings.TrimPrefix(s, "&")
	}

	var label string
	if idx := strings.Index(s, ":"); idx > 0 {
		base := s[:idx]
		sub := s[idx+1:]
		switch base {
		case "TX":
			if v, ok := txVarLabelsZh[sub]; ok {
				label = v
			} else if strings.HasPrefix(sub, "/^tf_1_") {
				label = "第一轮自动解码变量集合（TX:/^tf_1_*/）"
			} else {
				label = fmt.Sprintf("引擎事务变量（TX:%s）", sub)
			}
		case "REQUEST_HEADERS":
			label = fmt.Sprintf("%s 请求头（REQUEST_HEADERS:%s）", sub, sub)
		case "RESPONSE_HEADERS":
			label = fmt.Sprintf("%s 响应头（RESPONSE_HEADERS:%s）", sub, sub)
		case "ARGS":
			label = fmt.Sprintf("请求参数 %s（ARGS:%s）", sub, sub)
		case "ARGS_GET":
			label = fmt.Sprintf("GET 查询参数 %s（ARGS_GET:%s）", sub, sub)
		case "ARGS_NAMES":
			label = "特定格式请求参数名（ARGS_NAMES）"
		case "REQUEST_COOKIES":
			if strings.HasPrefix(sub, "/") {
				label = "特定格式 Cookie（REQUEST_COOKIES）"
			} else {
				label = fmt.Sprintf("Cookie 字段 %s（REQUEST_COOKIES:%s）", sub, sub)
			}
		case "MULTIPART_PART_HEADERS":
			label = fmt.Sprintf("Multipart 分段头 %s（MULTIPART_PART_HEADERS:%s）", sub, sub)
		case "XML":
			label = "XML 文档节点与属性（XML）"
		default:
			if b, ok := targetBaseLabelsZh[base]; ok {
				label = b
			} else {
				label = s
			}
		}
	} else {
		if b, ok := targetBaseLabelsZh[s]; ok {
			label = b
		} else {
			label = s
		}
	}

	if count {
		label = "数量统计：" + label
	}
	if neg {
		label = "排除：" + label
	}
	return label
}

func buildDetectionLogic(in RuleDescribeInput, spec ruleSpec, hasSpec bool, kind string, targets []string) string {
	phaseLabel := fmt.Sprintf("阶段 %d", in.Phase)
	switch in.Phase {
	case 1:
		phaseLabel = "阶段 1（请求头阶段）"
	case 2:
		phaseLabel = "阶段 2（请求体与参数阶段）"
	case 3:
		phaseLabel = "阶段 3（响应头阶段）"
	case 4:
		phaseLabel = "阶段 4（响应体阶段）"
	case 5:
		phaseLabel = "阶段 5（日志关联阶段）"
	}

	if !hasSpec {
		atLabel := attackTypeLabelZh(in.AttackType)
		return fmt.Sprintf("在%s执行规则检测，围绕「%s」攻击面检查对应 HTTP 流量字段特征；命中后按规则严重级别计入异常评分或记录安全事件。", phaseLabel, atLabel)
	}

	var parts []string
	// 1. 阶段 + 检查目标
	if len(targets) > 0 {
		shown := targets
		suffix := ""
		if len(shown) > 5 {
			shown = shown[:5]
			suffix = fmt.Sprintf("等 %d 项检查目标", len(targets))
		}
		parts = append(parts, fmt.Sprintf("在%s检查%s%s", phaseLabel, strings.Join(shown, "、"), suffix))
	} else {
		parts = append(parts, fmt.Sprintf("在%s执行规则判定", phaseLabel))
	}

	// 2. 数据归一化/解码变换
	if len(spec.Transforms) > 0 {
		tfs := make([]string, 0, len(spec.Transforms))
		for _, tf := range spec.Transforms {
			if zh, ok := transformLabelsZh[tf]; ok {
				tfs = append(tfs, zh)
			} else {
				tfs = append(tfs, tf)
			}
		}
		parts = append(parts, fmt.Sprintf("匹配前先执行%s预处理以对抗混淆绕过", strings.Join(tfs, "、")))
	}

	// 3. 匹配算子说明
	opClause := describeOperatorZh(spec.Op, spec.Arg, spec.Chained)
	if opClause != "" {
		parts = append(parts, opClause)
	}

	// 4. 特殊控制行为（skipAfter / ctl）
	if spec.SkipAfter != "" {
		parts = append(parts, fmt.Sprintf("条件满足时通过 skipAfter 跳转至标记 %s，跳过中间规则执行", spec.SkipAfter))
	}
	if spec.CtlSummary != "" {
		parts = append(parts, "命中后执行控制动作："+spec.CtlSummary)
	}

	return strings.Join(parts, "；") + "。"
}

func describeOperatorZh(op, arg string, chained bool) string {
	base := ""
	switch op {
	case "@rx":
		base = "使用正则表达式匹配特征模式"
	case "!@rx":
		base = "使用正则表达式反向校验（不符合允许格式即命中）"
	case "@pmFromFile":
		if arg != "" {
			base = fmt.Sprintf("使用多模式特征字典文件 %s 进行高速匹配", arg)
		} else {
			base = "使用内置多模式特征字典文件进行高速匹配"
		}
	case "!@pmFromFile":
		if arg != "" {
			base = fmt.Sprintf("使用字典文件 %s 做快速预筛（未命中任何关键词时触发跳过）", arg)
		} else {
			base = "使用特征字典做反向预筛"
		}
	case "@pm":
		base = "使用多关键字短语集合匹配特征"
	case "@detectSQLi":
		base = "调用 libinjection SQL 注入词法与语法指纹引擎执行深度识别"
	case "@detectXSS":
		base = "调用 libinjection XSS 上下文词法分析引擎执行深度识别"
	case "@within":
		if arg != "" {
			base = fmt.Sprintf("校验取值是否位于集合 %s 内", arg)
		} else {
			base = "校验取值是否位于指定集合内"
		}
	case "!@within":
		if arg != "" {
			base = fmt.Sprintf("校验取值是否超出白名单集合 %s", arg)
		} else {
			base = "校验取值是否超出白名单集合"
		}
	case "@validateByteRange":
		if arg != "" {
			base = fmt.Sprintf("校验字节范围是否超出允许集合（%s）", arg)
		} else {
			base = "校验输入字符是否全部落入允许字节范围"
		}
	case "!@validateByteRange":
		base = "检查输入是否包含允许字节范围之外的特殊字符"
	case "@contains":
		if arg != "" {
			base = fmt.Sprintf("检查是否包含特征子串「%s」", arg)
		} else {
			base = "检查是否包含指定特征子串"
		}
	case "!@contains":
		base = "检查是否不包含指定子串"
	case "@streq":
		if arg != "" {
			base = fmt.Sprintf("执行精确字符串相等比对（%s）", arg)
		} else {
			base = "执行精确字符串相等比对"
		}
	case "!@streq":
		if arg != "" {
			base = fmt.Sprintf("比较变换结果是否与原值 %s 不同（变化则表示存在编码内容）", arg)
		} else {
			base = "执行字符串不等比对"
		}
	case "@endsWith":
		if arg != "" {
			base = fmt.Sprintf("匹配路径或值是否以「%s」结尾", arg)
		} else {
			base = "匹配后缀特征"
		}
	case "!@endsWith":
		base = "反向校验后缀特征"
	case "@beginsWith":
		if arg != "" {
			base = fmt.Sprintf("匹配路径或值是否以「%s」开头", arg)
		} else {
			base = "匹配前缀特征"
		}
	case "@lt":
		if arg != "" {
			base = fmt.Sprintf("数值比较是否小于 %s", arg)
		} else {
			base = "执行小于阈值数值比较"
		}
	case "!@lt":
		if arg != "" {
			base = fmt.Sprintf("数值比较是否不小于 %s", arg)
		} else {
			base = "执行不小于阈值数值比较"
		}
	case "@ge":
		if arg != "" {
			base = fmt.Sprintf("数值比较是否大于等于 %s", arg)
		} else {
			base = "执行大于等于阈值数值比较"
		}
	case "@gt":
		if arg != "" {
			base = fmt.Sprintf("数值比较是否大于 %s", arg)
		} else {
			base = "执行大于阈值数值比较"
		}
	case "@eq":
		if arg != "" {
			base = fmt.Sprintf("数值比较是否等于 %s", arg)
		} else {
			base = "执行精确数值相等判断"
		}
	case "!@eq":
		if arg != "" {
			base = fmt.Sprintf("数值比较是否不等于 %s", arg)
		} else {
			base = "执行数值不等判断"
		}
	case "@ipMatch":
		if arg != "" {
			base = fmt.Sprintf("比对来源地址是否匹配 IP/网段（%s）", arg)
		} else {
			base = "比对来源 IP 地址范围"
		}
	case "@unconditionalMatch":
		base = "在规则生效范围内无条件匹配并应用控制动作"
	default:
		if op != "" {
			base = fmt.Sprintf("通过 %s 条件算子执行规则匹配", op)
		}
	}
	if chained && base != "" {
		base += "，并结合链式子规则（chain）进行多条件联合判定以降低误报"
	}
	return base
}

func buildRiskAndTuning(in RuleDescribeInput, spec ruleSpec, hasSpec bool, kind string, pl int) (string, string) {
	risk := ""
	tuning := ""
	if hasSpec {
		risk = spec.Risk
		tuning = spec.Tuning
	}

	if risk == "" {
		switch kind {
		case "int":
			risk = "属于 WAF 引擎内部流程控制或变量初始化规则，不直接检测恶意攻击载荷、不阻断业务请求，也不产生业务安全告警；用于确保偏执级别分级、异常评分汇总与默认策略参数按预期工作。"
		case "exc":
			risk = attackTypeAdviceZh["EXCLUSION"].risk
		case "pre":
			risk = "属于请求预处理与多轮解码插件规则，本身不直接拦截请求，而是将经过编码混淆的载荷还原为明文副本供后续 WAF 检测规则审查，显著提升对抗编码逃逸的检出率。"
		case "obs":
			risk = "属于低干扰观测线索规则，命中后仅在安全事件中心留存日志供安全运营关联分析，不直接阻断用户请求；适合识别侦察探测、爬虫行为或弱攻击信号。"
		case "blk":
			risk = "作为异常评分模型的最终阻断评估闸门，根据前置全部规则累积的异常总分与策略阈值统一裁决是否阻断，避免单条弱特征误拦同时保证组合攻击与高危攻击被可靠拦截。"
		default:
			if adv, ok := attackTypeAdviceZh[in.AttackType]; ok {
				risk = adv.risk
			} else {
				risk = attackTypeAdviceZh["OTHER"].risk
			}
		}
	}

	if tuning == "" {
		switch kind {
		case "int":
			tuning = "此类引擎内部控制规则不会造成业务误报，通常不应手动停用或添加覆盖；误停用可能破坏偏执级别分层跳过或异常分汇总逻辑。如需调整防护强度，请直接修改防护策略的「偏执级别」或「异常评分阈值」。"
		case "exc":
			tuning = attackTypeAdviceZh["EXCLUSION"].tuning
		case "pre":
			tuning = "默认仅在启用对应 CRS 插件时生效；若特定接口参数本身承载合法 Base64/编码数据并在解码后触发下游检测规则误报，建议对该参数配置精细例外，而非关闭整个解码链路。"
		case "obs":
			tuning = "本规则不直接阻断流量，不会影响业务可用性；如确认属于授权扫描或正常业务客户端导致日志噪音偏多，可按来源 IP 配置白名单或通过规则覆盖停用。"
		case "blk":
			tuning = "切勿直接停用阻断评估规则；如遇到业务误拦，请在安全事件详情中查明具体加分的上游规则 ID，并对上游规则配置精细例外或调整防护策略的阻断阈值。"
		default:
			if adv, ok := attackTypeAdviceZh[in.AttackType]; ok {
				tuning = adv.tuning
			} else {
				tuning = attackTypeAdviceZh["OTHER"].tuning
			}
			if pl >= 3 {
				tuning += fmt.Sprintf(" 注意：本规则属于 PL%d 高严格度规则，在常规业务中误报概率相对较高，建议先在观察模式下充分验证后再切入防护。", pl)
			} else if pl == 2 {
				tuning += " 提示：本规则在偏执级别 ≥ PL2 时启用，如遇误报可通过精细例外放行具体参数。"
			}
		}
	}

	return risk, tuning
}

func buildFallbackSummary(in RuleDescribeInput, kind string) string {
	zhName := LocalizeRule(in.RuleID, in.FileName, in.Name)
	if zhName == "" {
		zhName = fmt.Sprintf("规则 %d", in.RuleID)
	}
	srcLabel := ruleSourceLabelZh(in.RuleSource)
	atLabel := attackTypeLabelZh(in.AttackType)
	switch kind {
	case "int":
		return fmt.Sprintf("属于%s的内部流程控制规则（%s），负责引擎状态控制与策略分级调度，不直接拦截正常业务请求。", srcLabel, zhName)
	case "exc":
		return fmt.Sprintf("属于%s的误报排除规则（%s），用于在特定业务路径或参数场景下放行已知误报，保障正常业务通行。", srcLabel, zhName)
	default:
		return fmt.Sprintf("属于%s的「%s」安全防护规则，用于识别并防范「%s」相关的异常请求特征与潜在攻击利用。", srcLabel, atLabel, zhName)
	}
}

func buildReferencesZh(in RuleDescribeInput) []string {
	seen := map[string]bool{}
	var refs []string
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			refs = append(refs, v)
		}
	}

	// 1. 提取 CVE / CNNVD 编号（从 tags 与规则名称）
	cves := map[string]bool{}
	cnnvds := map[string]bool{}
	for _, t := range in.Tags {
		low := strings.ToLower(t)
		if strings.HasPrefix(low, "cve/") {
			cves[strings.ToUpper(strings.TrimPrefix(t, t[:4]))] = true
		} else if cveInTextPattern.MatchString(t) {
			for _, m := range cveInTextPattern.FindAllString(t, -1) {
				cves[strings.ToUpper(m)] = true
			}
		}
		if strings.HasPrefix(low, "cnnvd/") {
			cnnvds[strings.ToUpper(strings.TrimPrefix(t, t[:6]))] = true
		} else if cnnvdInTextPattern.MatchString(t) {
			for _, m := range cnnvdInTextPattern.FindAllString(t, -1) {
				cnnvds[strings.ToUpper(m)] = true
			}
		}
	}
	for _, m := range cveInTextPattern.FindAllString(in.Name+" "+in.Message, -1) {
		cves[strings.ToUpper(m)] = true
	}
	for _, m := range cnnvdInTextPattern.FindAllString(in.Name+" "+in.Message, -1) {
		cnnvds[strings.ToUpper(m)] = true
	}

	sortedCVEs := make([]string, 0, len(cves))
	for c := range cves {
		sortedCVEs = append(sortedCVEs, c)
	}
	sort.Strings(sortedCVEs)
	for _, c := range sortedCVEs {
		add("漏洞编号：" + c)
	}

	sortedCNNVDs := make([]string, 0, len(cnnvds))
	for c := range cnnvds {
		sortedCNNVDs = append(sortedCNNVDs, c)
	}
	sort.Strings(sortedCNNVDs)
	for _, c := range sortedCNNVDs {
		add("CNNVD 编号：" + c)
	}

	// 2. 提取 CAPEC 攻击模式中文说明
	for _, t := range in.Tags {
		if strings.HasPrefix(t, "capec/") {
			if zh, ok := capecLabelsZh[t]; ok {
				add(zh)
			} else {
				parts := strings.Split(t, "/")
				add("CAPEC-" + parts[len(parts)-1] + " 攻击模式")
			}
		}
	}

	// 3. 规则族/来源归属说明
	if in.FileName != "" {
		base := strings.TrimSuffix(filepath.Base(in.FileName), filepath.Ext(in.FileName))
		if fam, ok := familyNamesZh[base]; ok {
			src := ruleSourceLabelZh(in.RuleSource)
			if in.RuleSource == SourceCRS && in.CRSVersion != "" {
				add(fmt.Sprintf("%s %s · %s规则族", src, in.CRSVersion, fam))
			} else {
				add(fmt.Sprintf("%s · %s", src, fam))
			}
		}
	}

	return refs
}

func ruleSourceLabelZh(source string) string {
	switch source {
	case SourceCRS:
		return "OWASP 核心规则集"
	case SourceCRSPlugin:
		return "OWASP CRS 插件"
	case SourceThirdParty:
		return "第三方应用排除规则"
	case SourceCustomPack:
		return "九章扩展规则包"
	case SourceJiuzhang:
		return "九章内置规则"
	case SourceCustom:
		return "用户自定义规则"
	default:
		return "WAF 防护规则库"
	}
}

func attackTypeLabelZh(at string) string {
	switch at {
	case "SQL_INJECTION":
		return "SQL 注入"
	case "XSS":
		return "XSS 跨站脚本"
	case "COMMAND_INJECTION":
		return "命令注入"
	case "LOCAL_FILE_INCLUSION":
		return "本地文件包含"
	case "REMOTE_FILE_INCLUSION":
		return "远程文件包含"
	case "PHP_INJECTION":
		return "PHP 注入"
	case "JAVA_INJECTION":
		return "Java 注入"
	case "PROTOCOL_VIOLATION":
		return "协议违规"
	case "SESSION_FIXATION":
		return "会话固定"
	case "SCANNER_DETECTION":
		return "扫描器探测"
	case "INFORMATION_DISCLOSURE":
		return "信息泄露"
	case "REMOTE_CODE_EXECUTION":
		return "远程代码执行"
	case "SSRF":
		return "SSRF 服务端请求伪造"
	case "XXE_INJECTION":
		return "XXE 外部实体注入"
	case "WEBSHELL":
		return "WebShell 后门"
	case "FILE_UPLOAD":
		return "恶意文件上传"
	case "DESERIALIZATION":
		return "不安全反序列化"
	case "SSTI":
		return "服务端模板注入"
	case "DOS":
		return "拒绝服务"
	case "MASS_ASSIGNMENT":
		return "批量赋值"
	case "EXCLUSION":
		return "应用白名单排除"
	default:
		return "通用安全防护"
	}
}

// LookupRuleSpecCount 返回内置规则详述元数据条目数（供测试校验同步完整性）。
func LookupRuleSpecCount() int {
	return len(ruleSpecsZh)
}

// HasRuleSpec 判断给定 rule_id 是否已收录于内置详述元数据表（供测试校验）。
func HasRuleSpec(ruleID int) bool {
	_, ok := ruleSpecsZh[ruleID]
	return ok
}
