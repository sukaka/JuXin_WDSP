package securityevents

// Remediation 是针对某类攻击的处置知识（分析步骤 / 修复建议 / 加固建议）。
type Remediation struct {
	AttackType     string   `json:"attack_type"`
	AttackLabel    string   `json:"attack_label"`
	AnalyzeSteps   []string `json:"analyze_steps"`
	FixSuggestions []string `json:"fix_suggestions"`
	Hardening      []string `json:"hardening"`
}

// remediationKB 按攻击类型组织的处置知识库。
// 内容面向安全运营与开发人员：先研判真伪，再修复代码，最后加固防线。
var remediationKB = map[string]Remediation{
	"SQL_INJECTION": {
		AttackType:  "SQL_INJECTION",
		AttackLabel: "SQL 注入",
		AnalyzeSteps: []string{
			"查看匹配数据（matched_data）定位注入点参数，确认载荷是否包含 UNION SELECT、OR '1'='1、SLEEP/BENCHMARK 等典型特征",
			"核对请求路径对应的代码：该参数是否拼接进 SQL 语句（字符串拼接、ORDER BY/LIMIT 动态拼接是高危点）",
			"用相同载荷在测试环境重放，观察是否返回异常数据量或数据库报错信息，以确认是否真实可利用",
			"检查同时段同 IP 的其他请求：是否存在枚举表名/字段名的序列行为（信息_schema 查询）",
			"确认 WAF 动作：若为 OBSERVE（未阻断），按真实攻击处理并立即排查数据泄露痕迹（慢日志、异常导出）",
		},
		FixSuggestions: []string{
			"所有 SQL 访问改用参数化查询（预编译语句），禁止字符串拼接 SQL，包括 ORDER BY 字段名也要走白名单映射",
			"ORM 场景避免使用原生 SQL 拼接 API（如 GORM 的 Raw/Exec 拼接、MyBatis 的 ${}），改用占位符（? / #{}）",
			"对输入做类型与格式校验：ID 类参数强制转整型，枚举类参数走白名单",
			"数据库账号最小权限：业务账号禁止 DDL、禁止读 information_schema 以外的系统库，按库分离账号",
			"开启数据库错误统一处理，生产环境不向客户端返回 SQL 错误详情",
		},
		Hardening: []string{
			"确认 CRS SQLi 规则族（942xxx）处于阻断模式且未被例外放行",
			"对该接口调低异常评分阈值或提高 paranoia level，观察误报情况后固化",
			"对登录、查询类接口增加频率限制，拖慢盲注枚举速度",
		},
	},
	"XSS": {
		AttackType:  "XSS",
		AttackLabel: "跨站脚本（XSS）",
		AnalyzeSteps: []string{
			"查看匹配变量与匹配数据，判断注入点是 URL 参数（反射型）、表单提交（存储型）还是 DOM 渲染（DOM 型）",
			"在页面实际渲染位置确认输出上下文：HTML 文本、HTML 属性、JavaScript 字符串、URL，不同上下文利用难度不同",
			"检查响应中载荷是否原样回显（响应体留痕可直接查看），确认 Content-Type 是否为 text/html",
			"若为存储型，排查该数据的所有展示页面（后台、列表、详情、导出）",
			"结合来源 IP 与 UA 判断是扫描器批量探测还是针对性攻击",
		},
		FixSuggestions: []string{
			"输出编码按上下文处理：HTML 文本转义 <>&\"'，属性值加引号并转义，JS 上下文用 \\x 转义，URL 参数做 encodeURIComponent",
			"前端框架（React/Vue）禁止 dangerouslySetInnerHTML / v-html 渲染未净化的用户输入",
			"富文本场景使用成熟净化库（如 DOMPurify），并配置标签/属性白名单",
			"设置 Content-Security-Policy 响应头（至少 default-src 'self'，禁止 unsafe-inline 脚本）作为纵深防御",
			"Cookie 设置 HttpOnly + Secure + SameSite，降低会话窃取影响",
		},
		Hardening: []string{
			"确认 CRS XSS 规则族（941xxx）处于阻断模式",
			"对回显型参数（搜索词、昵称、评论）建立重点监控",
			"添加 X-Content-Type-Options: nosniff 响应头",
		},
	},
	"COMMAND_INJECTION": {
		AttackType:  "COMMAND_INJECTION",
		AttackLabel: "命令注入",
		AnalyzeSteps: []string{
			"查看匹配数据确认注入特征：; | & $() ` 等命令分隔符或 bash/powershell 关键字",
			"定位代码中调用系统命令的位置（exec/system/popen/ProcessBuilder/Runtime.exec），确认参数是否来自用户输入",
			"检查服务器侧是否有命令执行痕迹：异常进程、临时目录新文件、出站连接日志",
			"评估影响面：执行命令的运行账号权限、是否能出网、是否容器隔离",
		},
		FixSuggestions: []string{
			"能用语言 API 就不用系统命令（如压缩、网络请求、文件操作均有标准库）",
			"必须调用命令时：参数数组传参（不经过 shell），禁止 shell 拼接；对参数做白名单校验（如 IP/域名正则）",
			"运行账号降权 + 容器/seccomp 限制可执行命令集合",
			"禁止命令执行类功能直连用户输入，增加审批或二次确认",
		},
		Hardening: []string{
			"确认 CRS RCE 规则族（932xxx）处于阻断模式",
			"对该类接口（ping、备份、诊断）增加访问控制（仅内网/管理员）与操作审计",
			"部署 egress 出网管控，阻断反弹 shell 外联",
		},
	},
	"PATH_TRAVERSAL": {
		AttackType:  "PATH_TRAVERSAL",
		AttackLabel: "路径穿越 / 本地文件包含",
		AnalyzeSteps: []string{
			"查看匹配数据确认穿越特征：../、..%2f、....// 或绝对路径 /etc/passwd、win.ini",
			"定位文件读取代码：下载、预览、日志查看、模板包含等功能是否直接拼接用户输入路径",
			"确认目标文件是否真实存在且可读（测试环境重放验证），评估泄露内容敏感度",
			"检查是否伴随 URL 编码/双重编码绕过尝试，确认解码链路（网关、框架、应用各自解码一次）",
		},
		FixSuggestions: []string{
			"文件访问改为 ID 映射（数据库记录 ID → 存储路径），不直接接受路径参数",
			"必须接受文件名时：校验规范化后的路径必须位于指定基目录之下（filepath.Clean + 前缀比较），并拒绝符号链接",
			"过滤 null 字节（%00），文件名仅允许 [A-Za-z0-9._-] 白名单字符",
			"Web 服务账号对敏感目录（/etc、应用配置、密钥）不可读",
		},
		Hardening: []string{
			"确认 CRS LFI 规则族（930xxx）处于阻断模式",
			"静态资源与下载功能走独立域名/目录，与应用代码隔离",
		},
	},
	"RCE": {
		AttackType:  "RCE",
		AttackLabel: "远程代码执行",
		AnalyzeSteps: []string{
			"确认载荷类型：表达式注入（OGNL/SpEL/EL）、反序列化（Java/PHP）、调试组件滥用（如 Laravel Ignition）",
			"核对应用框架与组件版本是否存在对应 CVE（载荷特征通常指向特定漏洞）",
			"检查主机侧痕迹：异常子进程、临时文件、计划任务、出站连接",
			"该类型告警一律按高优先级处理，即使已阻断也要确认是否为已知 CVE 的针对性扫描",
		},
		FixSuggestions: []string{
			"升级存在漏洞的框架/组件到安全版本（对照 CVE 公告），无法升级时按官方建议配置缓解措施",
			"关闭生产环境的调试/点火（debug/ignition/actuator 敏感端点）功能",
			"反序列化场景：配置类白名单（如 Jackson 的 activateDefaultTyping 白名单、fastjson safemode）",
			"表达式求值功能（规则引擎、模板）使用沙箱模式并限制可用类与方法",
		},
		Hardening: []string{
			"对该路径添加虚拟补丁（自定义规则精准拦截载荷特征），为升级争取时间",
			"容器化运行 + 只读文件系统 + 禁止出网，压缩利用后影响",
			"建立组件资产清单（SBOM），订阅所用组件的安全通告",
		},
	},
	"SSRF": {
		AttackType:  "SSRF",
		AttackLabel: "服务端请求伪造",
		AnalyzeSteps: []string{
			"查看匹配数据确认目标地址：云元数据（169.254.169.254）、内网地址（127.0.0.1、10/172.16/192.168 段）或协议跳转（gopher/file/dict）",
			"定位发起请求的功能：URL 抓取、Webhook 回调、图片代理、文档导入",
			"检查响应是否回显内网资源内容（响应体留痕可直接确认是否已被利用成功）",
			"排查内网侧访问日志，确认是否有来自该应用服务器的异常请求",
		},
		FixSuggestions: []string{
			"目标 URL 做白名单：仅允许业务必需的域名/协议（http/https），其余拒绝",
			"解析后校验 IP：拒绝内网、回环、链路本地地址，且要防 DNS rebinding（解析后固定 IP 再请求）",
			"禁用重定向跟随或逐跳校验重定向目标",
			"云环境元数据接口启用 IMDSv2（需 token 访问）",
		},
		Hardening: []string{
			"对外发请求功能做独立出口代理 + 访问控制（egress 网关白名单）",
			"Webhook 类功能改为异步投递且不回显响应内容",
		},
	},
	"SCANNER_DETECTION": {
		AttackType:  "SCANNER_DETECTION",
		AttackLabel: "扫描器探测",
		AnalyzeSteps: []string{
			"确认扫描特征：sqlmap/nikto/nuclei 等工具 UA、对 .git/.env/wp-admin 等已知路径的批量探测",
			"统计该 IP 的探测广度（路径数、时间跨度），区分互联网背景噪声扫描与针对性踩点",
			"检查探测路径中是否有真实存在的敏感文件（.git 泄露、备份文件）——扫描本身不可怕，可怕的是扫到了东西",
			"关注扫描后是否紧随针对性攻击（同一 IP 换用手工载荷）",
		},
		FixSuggestions: []string{
			"清理暴露的敏感路径：.git/.env/备份文件/调试端点不得发布到生产",
			"确认目录列表（autoindex）已关闭，错误页面不泄露框架与路径信息",
		},
		Hardening: []string{
			"对高频扫描 IP 启用临时封禁或频率限制",
			"扫描器规则保持观察模式即可，避免误伤正常爬虫（SEO 需要时放行搜索引擎 UA）",
		},
	},
	"SCANNER": {
		AttackType:  "SCANNER",
		AttackLabel: "扫描器探测",
		AnalyzeSteps: []string{
			"确认扫描特征：sqlmap/nikto/nuclei 等工具 UA、对 .git/.env/wp-admin 等已知路径的批量探测",
			"统计该 IP 的探测广度（路径数、时间跨度），区分互联网背景噪声扫描与针对性踩点",
			"检查探测路径中是否有真实存在的敏感文件（.git 泄露、备份文件）",
			"关注扫描后是否紧随针对性攻击（同一 IP 换用手工载荷）",
		},
		FixSuggestions: []string{
			"清理暴露的敏感路径：.git/.env/备份文件/调试端点不得发布到生产",
			"确认目录列表（autoindex）已关闭，错误页面不泄露框架与路径信息",
		},
		Hardening: []string{
			"对高频扫描 IP 启用临时封禁或频率限制",
			"扫描器规则保持观察模式即可，避免误伤正常爬虫",
		},
	},
	"FILE_UPLOAD": {
		AttackType:  "FILE_UPLOAD",
		AttackLabel: "危险文件上传",
		AnalyzeSteps: []string{
			"确认上传文件类型与内容是否匹配（伪装 Content-Type、双扩展名 shell.php.jpg）",
			"检查上传目录是否可被 Web 访问且是否会解析执行（最危险组合）",
			"核对该功能的上传校验逻辑：扩展名、MIME、内容魔数、图片重渲染",
		},
		FixSuggestions: []string{
			"上传文件重命名为随机 ID 存储，扩展名白名单校验 + 内容魔数校验",
			"上传目录禁止脚本解析执行（独立静态域或对象存储），与代码目录隔离",
			"图片类强制重渲染（压缩转码），清除嵌入的可执行内容",
			"限制单文件大小与上传频率",
		},
		Hardening: []string{
			"确认上传接口仅对认证用户开放且记录操作审计",
			"对上传目录部署文件完整性监控（Webshell 检测）",
		},
	},
	"PROTOCOL_VIOLATION": {
		AttackType:  "PROTOCOL_VIOLATION",
		AttackLabel: "HTTP 协议违规",
		AnalyzeSteps: []string{
			"确认违规类型：请求走私（CL/TE 冲突）、缺少必需头、畸形请求行",
			"请求走私类（921xxx）要重点排查：中间链路（CDN、LB、反代）对 CL/TE 的解析是否一致",
			"缺少 Accept 头等低级违规多为脚本/爬虫，结合 UA 与频率判断",
		},
		FixSuggestions: []string{
			"请求走私：全链路统一 HTTP 解析行为，前端代理直接拒绝 CL+TE 双头请求",
			"客户端 SDK/脚本补齐标准请求头",
		},
		Hardening: []string{
			"走私类规则保持阻断；普通协议违规可保持观察，避免误伤老旧客户端",
		},
	},
	"SESSION_FIXATION": {
		AttackType:  "SESSION_FIXATION",
		AttackLabel: "会话固定",
		AnalyzeSteps: []string{
			"确认会话 ID 是否在登录前后保持不变，URL 中是否携带会话标识",
		},
		FixSuggestions: []string{
			"登录成功后强制轮换会话 ID",
			"会话 ID 仅通过 Cookie 传输（HttpOnly+Secure），禁止 URL 传会话",
		},
		Hardening: []string{"启用会话超时与异地登录检测"},
	},
	"INFORMATION_DISCLOSURE": {
		AttackType:  "INFORMATION_DISCLOSURE",
		AttackLabel: "信息泄露",
		AnalyzeSteps: []string{
			"确认泄露内容：错误堆栈、源码、配置、目录列表还是业务数据",
			"检查响应体留痕，评估泄露敏感度与影响范围",
		},
		FixSuggestions: []string{
			"生产环境关闭调试信息与详细错误页，统一错误处理",
			"敏感配置从代码库移除并轮换已泄露凭据",
		},
		Hardening: []string{"对响应做敏感数据扫描（身份证号、密钥正则）并告警"},
	},
}

func init() {
	// LFI/RFI 复用路径穿越的处置知识（标签微调）
	lfi := remediationKB["PATH_TRAVERSAL"]
	lfi.AttackType, lfi.AttackLabel = "LOCAL_FILE_INCLUSION", "本地文件包含（LFI）"
	remediationKB["LOCAL_FILE_INCLUSION"] = lfi
	rfi := remediationKB["PATH_TRAVERSAL"]
	rfi.AttackType, rfi.AttackLabel = "REMOTE_FILE_INCLUSION", "远程文件包含（RFI）"
	remediationKB["REMOTE_FILE_INCLUSION"] = rfi
}

// genericRemediation 是未知攻击类型的通用处置建议。
var genericRemediation = Remediation{
	AttackType:  "OTHER",
	AttackLabel: "其他/未知攻击",
	AnalyzeSteps: []string{
		"查看规则匹配明细与匹配数据，确认触发的是哪类检测规则",
		"结合请求/响应留痕判断载荷是否到达应用并产生影响",
		"检索规则 ID 对应文档，理解规则意图后判断真伪",
	},
	FixSuggestions: []string{
		"按匹配数据定位输入点，对该参数做类型/格式/白名单校验",
		"确认服务端对异常输入有统一拒绝与记录",
	},
	Hardening: []string{
		"保持 CRS 规则更新，定期评审误报并收敛为例外策略",
	},
}

// RemediationFor 返回指定攻击类型的处置知识；未知类型返回通用建议。
func RemediationFor(attackType string) Remediation {
	if r, ok := remediationKB[attackType]; ok && len(r.AnalyzeSteps) > 0 {
		return r
	}
	g := genericRemediation
	g.AttackType = attackType
	if g.AttackType == "" {
		g.AttackType = "OTHER"
	}
	return g
}
