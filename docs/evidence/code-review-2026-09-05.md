# WDSP 全库代码审查报告（2026-09-05）

> **2026-09-05 复核修订**：本文已经过独立复核（见 `docs/evidence/code-review-validation-2026-09-05.md`）。复核确认：部分发现在复核时的工作区已有修复及回归测试（当时未提交/未发布）；MED-16、MED-23、MED-31、HIGH-14 的定性或修复建议已按复核结论修订；严重级别统计已修正。**实际条目数：严重 1、高 14、中 32、低 59，合计 106 条。**
>
> **2026-09-05 修复完成**：106 条发现已全部处置完毕（6 个批次，详见文末「修复完成记录」）。批次 6 已闭环全部 5 项设计级遗留/残留（MED-11 高成本配额、LOW-S10 token 上限、MED-23 离线包验签、HIGH-14 hostctl 签名、LOW-G3 XFF 默认值）及 LOW-W12 服务端分页，全部附回归测试。文末「设计级遗留」一节仅余 3 项已知限制/发布注意/跟进项（非漏洞）。所有改动均未提交，提交/发布前需经编排方验收。
>
> 状态图例：**已修复** = 工作区已有实现与回归测试（含复核时已有的修复与本次批次修复）；**已文档化** = 设计限制，已补文档/注释声明；**待立项/后续增强** = 设计级遗留，见文末清单。

## 概述

- **范围**：防护网关（`gateway/modules/jiuzhang_guard` 全部子包 + `gateway/` 周边组件 tproxyd/mirrorcap/netmgrd/havipd/eventparser）、管理后端（`server/internal` 93 个包）、流量采集组件（`wdsp-agent`）、管理前端（`web/src` 全部 96 个页面 + 基础设施）、运维脚本与部署清单（`ops/`、`deployment/`、`docker-compose.yml`）。
- **方法**：13 路并行只读审查，逐文件精读真实代码；每条发现均在代码中核实并排除了已有防护（中间件、上游校验、DB 约束、测试）；`go vet` 各模块通过。审查时工作区包含未提交修改，审查未记录基线 commit，复核基线 HEAD 为 `3c73774da8bed0a36764a4eed29e511a7de85b4a`。
- **分类定义**：【A】安全漏洞/安全语义缺陷；【B】功能 Bug/可靠性缺陷；【C】UI/UX 问题。

### 审查确认健康的重点面（摘要）

- 网关请求处理顺序与 AGENTS.md 声明严格一致；白名单/L7 allow/保护地址命中后仍经 `serveNext` 过 API 动态防护与 WAF；真实客户端 IP 识别无绕过（可信代理校验 + 伪造检测 + 长度/链长护栏）。
- 管理后端：Argon2id + 常量时间比较；会话 256bit 随机 ID + DB 吊销对账；CSRF 三重校验；RBAC 路由覆盖完整；SQL 全部参数化；发布扇出 SSRF「登记校验 + 拨号时 DNS 重解析复检」真实闭环；证书私钥加密落库；License Ed25519 验签 fail-closed。
- 备份/恢复/升级：tar 条目白名单防 slip、三层哈希校验、标识符 Sanitize、恢复二次确认 + 事务整组替换、升级包执行前复核哈希 fail-closed。
- 前端：无 `dangerouslySetInnerHTML`/`innerHTML`/`javascript:` 用法；CSRF Token 仅内存；报告预览 iframe `sandbox=""`。
- 部署：无 `latest` 镜像标签，第三方镜像 tag+digest 双锁；生产 compose 的 API/DB/缓存绑 127.0.0.1；Caddy Admin 仅 Unix Socket。

---

## 严重（1 条）

### CRIT-1 自定义规则 TargetVariables 可注入任意 SecLang（可关停整个 WAF）【A】
- 位置：`server/internal/customrules/customrules.go:129-134, 156-190`
- 问题：变量校验只看 `strings.Split(v, ":")[0]` 前缀白名单；`GenerateSecLang` 把变量用 `|` 原样拼进 `SecRule %s "%s" ...`，不转义、不剥控制字符。持 `custom_rules.manage` 的账号可构造含换行的值（如 `ARGS:x\nSecAction "id:...,ctl:ruleEngine=Off"`）插入独立指令行，全局关停 Coraza 引擎；`dangerousPatterns` 检查不覆盖 TargetVariables；管理面/审计中仍显示为合法结构化规则。
- 修复方向：变量整体须匹配 `^[A-Z_]+(:[A-Za-z0-9_.-]+)?$`，拒绝一切控制字符；`dangerousPatterns` 覆盖全部注入面。
- 修复状态：**已修复**（复核确认工作区已有修复：变量整体正则校验 + 危险内容检查覆盖 TargetVariables + 注入回归测试）

## 高（14 条）

### HIGH-1 例外 URI 字段未校验控制字符，换行注入任意 SecLang【A】
- 位置：`server/internal/exceptions/exceptions.go:112-158, 225-229`
- 问题：`ValidateInput` 只校验正则语法/域名/IP；`URIExact/URIPrefix/URIRegex` 无控制字符检查；`escapeArg` 仅转义 `\` 和 `"`，换行即可在 before-crs 指令段插入新指令行，效果同 CRIT-1 且绕过「宽泛例外」审计标记。
- 修复方向：三个 URI 字段加控制字符与长度校验（对齐 l7rules/validate.go 的 hasControlChar 纪律）。
- 修复状态：**已修复**（复核确认：三字段已增加 2048 字符上限与控制字符校验，已有回归测试）

### HIGH-2 例外的应用/策略作用域在下发 SecLang 中丢失，「单应用例外」实际全局摘除规则【A】
- 位置：`server/internal/exceptions/exceptions.go:162-189` + `server/internal/gatewayconfig/generator.go:435-437`
- 问题：`GenerateSecLang` 条件只编码 URIExact/URIPrefix/URIRegex/Domain，从不使用 ApplicationID/PolicyID；无 URI 与域名时落到 `SecRule REQUEST_URI "@rx .*"` 兜底；生成器把同一份全局例外列表注入每个应用的 WAF 指令。ScopeType=APPLICATION 的例外无需风险确认即可创建，发布后对全部应用移除对应规则。
- 修复方向：按例外归属应用过滤下发列表，或将 Host 条件强制绑定该应用域名。
- 修复状态：**已修复**（复核确认：生成器已通过 `exceptionAppliesToApp` 按 ScopeType 和 ApplicationID 过滤，未知作用域 fail-closed，已有作用域回归测试）

### HIGH-3 源站 scheme=https 被静默降级为明文 HTTP 回源【A/B】
- 位置：`server/internal/gatewayconfig/generator.go:475-551`；关联 `server/internal/applications/store.go:610-640`（UpdateUpstream 不校验 Scheme）
- 问题：`buildReverseProxy` 不读 `Upstream.Scheme/TLSServerName/TLSVerify`，transport 恒为 `"protocol":"http"`；管理面允许配置 HTTPS 源站，实际回源明文且不校验证书，回源链路可被窃听/篡改；管理面显示与网关行为不一致。
- 修复方向：https 源站生成带 `tls`（server_name、InsecureSkipVerify 取反于 tls_verify）的 transport；UpdateUpstream 补 Scheme 校验。
- 修复状态：**已修复**（复核确认：Scheme=="https" 时生成器已设置 TLS transport、SNI 与证书校验策略；批次 3-B 确认 UpdateUpstream 已补 Scheme 校验）

### HIGH-4 TLS 证书从未被加载进配置，any_tag 类型错误，HTTPS 应用无法真正发布【B】
- 位置：`server/internal/gatewayconfig/generator.go:366-394`
- 问题：`buildTLSPolicies` 里 `certFiles` map 赋值后从未被读取；生成的配置没有 `apps.tls.certificates.load_files` 段；`certificate_selection.any_tag` 输出字符串 `policyDomains[0]`，而 Caddy v2.11.4 该字段为 `[]string`——含 HTTPS 应用的发布在 /load 直接失败；即便改数组，所有 SNI 也只匹配同一标签。
- 修复方向：生成 load_files 段（按 CertFileName + 证书 ID 作 tag），any_tag 用 `[]string{...}` 并按 SNI 分组生成策略。
- 修复状态：**已修复**（复核确认：已生成 `apps.tls.certificates.load_files`，any_tag 使用字符串数组并按证书标签关联 SNI）

### HIGH-5 网关引擎重建「先拆旧、后建新」，失败的配置重载摧毁在线防护【B】
- 位置：`gateway/modules/jiuzhang_guard/module.go:415-435`
- 问题：`getEngine` 在新引擎 `init` 成功之前就 `cancelPoll()` 并 `valkey.Close()` 旧引擎；Valkey 地址改为不可达时 init 必失败，Caddy 拒绝新配置、旧配置继续服务但引擎已死：封禁轮询停止、过期封禁残留、CC/配额限速 fail-open 整体旁路，仅每分钟一条节流事件。
- 修复方向：在不修改全局旧实例的情况下完整构建并 init 新引擎 → 验证必需组件就绪 → 原子替换共享指针 → 替换成功后再停止并关闭旧实例。
- 修复状态：**已修复**（批次 1-A：getEngine 重排为先建后拆原子替换，init 失败旧实例完整存活；新增 `TestGetEngineFailedRebuildKeepsOldEngine` 失败重载回归测试）

### HIGH-6 文件合规规则被超长文件名/截断 Content-Disposition 绕过（上传下载双向）【A】
- 位置：`gateway/dynamic_security/context/fileobs.go:57-59` + `gateway/dynamic_security/parser/fileobs.go:20-28`；关联 `gateway/modules/jiuzhang_guard/apiresponse.go:288-292`、`gateway/dynamic_security/response/fileobs.go:30-33`、`detectors/filecomp.go:223,177`
- 问题：合规评估用先截断（128 字符）后提取的文件名，`A×200.exe` 扩展名被截掉 → EXT 规则与双扩展名信号静默不命中；下载方向观测取自已脱敏截断的响应头快照，超长 Content-Disposition 解析失败 → 完全不产观测，下载 BLOCK 与 OOXML 水印门禁一并失效且无日志。
- 修复方向：扩展名与规则匹配基于未截断原始名计算，截断只用于证据落库；下载观测改用原始 Content-Disposition/Content-Type。
- 修复状态：**已修复**（批次 1-C 确认 dynamic_security 侧生产修复已在工作区并补齐回归测试——MatchName 不截断匹配口径 + ResponseInput.ContentDisposition 原始值通道；批次 2-A 完成 jiuzhang_guard 侧接线并新增超长 Content-Disposition 下载观测回归测试）

### HIGH-7 请求体 >1MiB 时整条 API 动态防护管线静默跳过（零日志零事件）【A】
- 位置：`gateway/modules/jiuzhang_guard/apiprotect.go:588-592, 677-706`
- 问题：`preserveRequestBody` 对 ContentLength>1MiB 直接返回 nil，`runAPIProtection` 据此直接放行——无 Warn、无 DetectorMatch、不产事件；文件上传合规（真实上传普遍 >1MiB）、gRPC 畸形帧 BLOCK、Prompt 注入、参数约束等全部请求侧检测对大体完全失效且不可见；parser 的截断+采样路径因此成为死代码。
- **复核限定**：该结论限定为「API 动态防护请求相位被跳过」，不能扩大为所有 Coraza/CRS WAF 防护均被绕过。
- 修复方向：跳过时落 OBSERVE 明细/事件标记并 Warn；或把 guard 上限提高到大于 MaxBodyParseBytes 让截断采样路径生效。
- 修复状态：**已修复**（批次 1-B：guard 上限 1MiB→4MiB 使截断采样路径生效；跳过分支落 OBSERVE 明细事件 `request.body_preserve_skipped` + 节流 Warn；新增 1.5MiB 进管线、超限跳过可见、spill 双计 3 个回归测试）

### HIGH-8 修改密码后「当前会话」未在服务端吊销【A】
- 位置：`server/internal/users/store.go:418-425`；关联 `server/internal/auth/service.go:347`、`server/internal/auth/handler.go:383-389`、`server/tests/security_regression_test.go:221`
- 问题：事务只撤销其他会话；handler 注释与 `relogin_required: true` 响应自相矛盾。改密恰是会话被盗后的标准处置动作：攻击者持有当前会话副本时改密后访问不受影响。
- 修复方向：改密成功路径吊销含当前会话在内的全部会话；同步更新回归测试预期。
- 修复状态：**已修复**（复核确认：ChangePassword 在启用撤销策略时撤销该用户全部持久化会话含当前会话，服务层同步清理缓存）

### HIGH-9 分钟聚合 SQL 引用不存在的表别名，WAF 事件指标永久为空【B】
- 位置：`server/internal/aggregations/jobs.go:51`
- 问题：FROM 中只有别名 `e`/`a`，WHERE 用 `m.event_occurred_at`（下方规则命中查询残留），PostgreSQL 报 42P01；`aggregateEventsMinute` 每分钟必失败，首页态势与统计分析的 WAF 事件数据持续为空。
- 修复方向：改为 `e.occurred_at`；补带真实/仿真 DB 的聚合回归测试。
- 修复状态：**已修复**（复核确认：当前查询使用 `e.occurred_at`）

### HIGH-10 CSV 导出缺公式注入防护（3 处）【A】
- 位置：`server/internal/accesslogs/handler.go:113`、`server/internal/securityevents/handler.go:388`、`server/internal/audits/audits.go:510`
- 问题：csvEscape 仅做分隔符转义，不处理以 `= + - @` 开头的单元格；domain（Host 头）与 request_uri 攻击者可控，导出文件可携带 `=HYPERLINK(...)`/DDE 公式。仓库内 accessrules/csv.go:299、systemalerts/handler.go:296 已有正确实现（`'` 前缀），属遗漏。
- 修复方向：统一替换为带公式防护的 csvCell。
- 修复状态：**已修复**（复核确认：三处 csvEscape 已对 `= + - @` 开头的值增加单引号前缀，并存在测试）

### HIGH-11 API 安全图谱 ECharts tooltip 存储型 XSS【A】
- 位置：`web/src/pages/api-graph/ApiGraphPage.tsx:124-129`；次级 `web/src/utils/apmCharts.ts:119`
- 问题：`tooltip.formatter` 原样返回 `p.data.name`（= endpoint_key），ECharts html 渲染模式将其作为 HTML 插入 DOM；网关侧 sanitize 只剔控制字符不处理 `<>`，攻击者请求 `/%3Cimg onerror=...%3E` 路径即入资产库，管理员悬停节点时在控制台上下文执行脚本。
- 修复方向：formatter 内 HTML 转义或改 richText/文本节点；apmCharts 同类处理。
- 修复状态：**已修复**（复核确认：ApiGraphPage.tsx 与 apmCharts.ts 已调用 `escapeHtml`）

### HIGH-12 wdsp-agent TLS 加密流被送入 HTTP 重组器，goroutine 无界泄漏致采集致盲【B】
- 位置：`wdsp-agent/internal/agent/agent.go:481-486`；关联 `httpsensor/conn.go:198,270,61`
- 问题：`onPacket` 不做 TLS 可见性门控；TLS 字节 parseRequest 立即失败后两个半流 goroutine 执行 `io.Copy(io.Discard, buf)` 排空到 EOF；HTTPS 长连接每条钉住 2 个 goroutine；连接表满后被拒连接照样起 Discard goroutine——goroutine 数实际无上限，最终触发自我保护停抓。
- 修复方向：flow 层把 visibility 透传进 FlowState，ENCRYPTED 流不进 sensor；或 sensor 首包判定非 HTTP 后立即删除并停止重组。
- 修复状态：**已修复**（批次 5-A：FlowState 新增 Visibility 透传，ENCRYPTED 流不进 sensor 并以 L0 终止释放连接；新增 TLS 流跳过 sensor 的回归测试）

### HIGH-13 tproxyd relay 透传无空闲/读超时，空闲连接耗尽并发上限整体 DoS【A】
- 位置：`gateway/tproxyd/server.go:201`（关联 :138 清除 deadline、:64 sem 上限 1024、:91 拒连）
- 问题：relay 双向 `io.Copy` 裸跑，嗅探阶段 deadline 被清除后全程无 deadline；每条连接占一个令牌，攻击者保持 1024 条空闲连接即让透明串接模式拒连正常业务。
- 修复方向：relay 期间设滚动空闲超时（搬运 N 字节续期）或连接总时长上限。
- 修复状态：**已修复**（复核确认：relay 已设置滚动 RelayIdleTimeout，双向活动续期 deadline，并有超时回归测试；批次 3-E 修复该修复残留的编译错误并复跑测试确认语义不回退）

### HIGH-14 hostctl root 系统控制通道不校验标志文件属主（已修订攻击前置条件）【A】
- 位置：`ops/system/hostctl-exec.sh:70-116`；配合 `ops/install/install.sh:271-277`、`deployment/systemd/jiuzhang-hostctl.service:14-18`
- 问题（**已按复核修订**）：执行脚本不校验标志文件属主、目录权限或请求真实性。正常安装时 `runtime/hostctl` 为 UID 1000 所有、权限 755，并非所有本地用户可写；**当 hostctl 目录所有权错误（UID 1000 对应非预期本地用户）或 chown 失败退化为 1777 时，能够写入该目录的本地用户可构造合法 JSON 标志文件，由 root 执行 reboot、shutdown 或 factory_reset**（factory_reset 会 `compose down -v` + `rm -rf` 全部数据）。
- 修复方向：执行前 stat 校验标志文件属主与目录非 other-writable；改用专用属主/组或对标志做共享密钥签名。
- 修复状态：**已修复**（批次 5-B：执行前 fail-closed 校验目录属主/权限/标志文件属主，install.sh 退化场景输出醒目安全警告；ops harness 4 场景覆盖）。**后续增强已完成**（批次 6：hostctl 标志共享密钥 HMAC-SHA256 签名验真——server 写入方 `systemops.SignCommand` 对规范化载荷（含 requestedAt 时间戳/requestID nonce）签名，hostctl-exec.sh 验签 + ±300s 防重放窗口，密钥 `.hostctl-secret` 双端先到先生成自举（0600），未签名/验签失败/超窗一律 fail-closed 拒绝并归档；harness 39 项全 PASS，systemops 单测含 openssl 黄金向量比对）

## 中（32 条）

### MED-1 枚举检测可用一个分页参数一键绕过【A】
- 位置：`gateway/modules/jiuzhang_guard/identitybehavior/enumeration.go:24`（engine.go:141 调用点）
- 问题：query 含 page/limit/offset/cursor 任一分页字段、或路径段含 batch/sync/export 即整体跳过账号/对象标识提取；攻击者每请求附带 `&page=1` 即让 RECON-ACCOUNT-001/RECON-OBJECT-001 永不触发。
- 修复方向：命中分页字段时降级为「不计分页字段本身的变化」而非整请求跳过，或对「带分页参数但账号值高频变化」单独记账。
- 修复状态：**已修复**（批次 1-A：query 侧改为剔除分页字段后照常提取标识，路径段排除保留并注释依据；enumeration 测试重写 + 引擎级回归）

### MED-2 访问日志查询串脱敏不做参数名 URL 解码，编码键绕过掩码【A】
- 位置：`gateway/modules/jiuzhang_guard/accesslog.go:727`；同样缺陷 `server/internal/securityevents/normalize.go:339`
- 问题：maskAccessLogQuery 直接比较低分参数名不 QueryUnescape；`GET /login?pass%77ord=Secret123` 的密码明文落访问日志入库（同文件表单体掩码已解码，作者已知该形态但查询串路径漏了）。
- 修复方向：比对前先 url.QueryUnescape 参数名（失败保持原样不过掩）；两侧同步修。
- 修复状态：**已修复**（批次 2-B 确认两侧均已修复且有回归测试；批次 3-C 顺带修复同根因的 normalize.go maskQuery 查询摘要路径）

### MED-3 访问日志 client_ip 记录连接源 IP 而非真实客户端 IP【B】
- 位置：`gateway/modules/jiuzhang_guard/accesslog.go:362-373`（rec 在 478 行 handler 调用前构建，真实 IP 改写在其内 serveGuard）
- 问题：网关在可信 LB 之后时 access_logs.client_ip 全部记成 LB 地址，与安全事件 ClientIP/ConnectionIP 双字段口径矛盾，留痕失去溯源价值。
- 修复方向：rec 构建移到 defer 收口处，或从请求上下文 clientIPResultKey 取识别结果。
- 修复状态：**已修复**（批次 2-B 确认：defer 收口处优先从上下文取真实 IP 识别结果，缺失时回落改写后的 RemoteAddr；有可信 LB 场景回归测试）

### MED-4 Query 参数洪泛耗尽共享 FieldCount 预算，请求体内容检测整体失效且不可见【A】
- 位置：`gateway/dynamic_security/parser/parse.go:128-141, 430-433`；关联 classifier/llm.go:90-97、events/event.go
- 问题：Query 键与 JSON 字段共用 MaxFieldCount=2048 且 Query 先消费；≥2048 个 query 键（约 12KB URL）即让 LLM 形态确认、敏感字段、schema 偏离、BODY 参数约束全部跳过；FieldCountCapped 无任何 detector 消费，攻击在事件流中不可见。
- 修复方向：Query/Body 各自独立配额；FieldCapped 产一条 OBSERVE 明细。
- 修复状态：**已修复**（批次 1-C 确认：Query/Body 独立配额 + `parser.field_count_capped` OBSERVE 明细已在工作区，本批补齐回归测试）

### MED-5 多 Guard 实例共存时 SetStoreOverrides(nil) 全局清除其他实例的 Valkey 行为存储【A】
- 位置：`gateway/modules/jiuzhang_guard/module.go:733`（绕过 pipeline.ApplyStoreOverrides 契约，pipeline/pipeline.go:89-99 明确多实例不得互相清除）
- 问题：behaviorStores 为 nil（memory/缺省）时把进程级全局指针清掉；一个 memory 站点装配/重载会把另一 valkey 站点的 behavior/apiwrite/resource/envanomaly 计数静默降级为进程内存，无任何告警。
- 修复方向：仅在非 nil 时注入；摘除语义改为按实例引用计数或由最后一个 valkey 实例退出时复位。
- 修复状态：**已修复**（批次 1-A：仅非 nil 时注入 + 回归测试；已知限制——单实例摘除 behavior_store 后进程级注入残留至下次非 nil 装配或重启，代码注释已声明）

### MED-6 API 事件输出为请求路径内全局互斥锁下的同步磁盘写【A】
- 位置：`gateway/modules/jiuzhang_guard/apievents/apievents.go:136-167` + `apiprotect.go:824`
- 问题：每条 API 请求同步 Emit（mutex + os.File.Write，无队列无超时无丢弃策略）；磁盘卡顿/满时所有在飞 API 请求在同一互斥锁上排队，形成无界头阻塞（心跳 runner 同锁停摆）。
- 修复方向：有界内存队列 + 后台落盘 goroutine（满则丢新记 Warn），或写路径加超时。
- 修复状态：**已修复**（批次 1-B 确认工作区已有修复：有界队列 4096 + 后台落盘 + 满则丢新并节流汇总上报 + Close 排空，包测试全绿）

### MED-7 临时封禁条目无过期清理，内存与 Valkey 双端单调增长【B】
- 位置：`gateway/modules/jiuzhang_guard/temporaryblock/temporaryblock.go:181-199,119-153`；`server/internal/temporaryblocks/store.go:410-435`；`server/internal/guardjanitor/janitor.go:38-63`
- 问题：纯内存模式过期条目仅被跳过而永不删除（IPv6 /64 轮换源 IP 可无界撑大 map）；Valkey 模式网关 Refresh 只在本地副本剔除从不 HDel，管理面 janitor 只置 DB EXPIRED 也不 HDel——Valkey 哈希永久膨胀而网关每秒 HGETALL 全量拉取。
- 修复方向：网关 Refresh 时对过期 field HDel；janitor 到期标记后同步 cacheDel。
- 修复状态：**已修复**（批次 2-C 确认网关侧已修：内存模式写入时惰性清扫 + Valkey 模式 PruneIfUnchanged 条件 HDel；批次 3-B 确认 server 侧 MarkExpiredReturning 已同步 cacheDel 并在 stage5 集成测试补 HDel 断言）

### MED-8 MaxCounterKeys 无上限校验，异常值可在配置 Provision 阶段 OOM 杀网关进程【B】
- 位置：`gateway/modules/jiuzhang_guard/counters/counters.go:53` + `module.go:743-862`（Validate 漏校验该项）
- 问题：NewMemoryMap 按该值预分配 map；管理面误下发如 2^30 的值时新配置 Provision 即巨量分配，可直接 OOM 杀掉正在服务的网关进程。
- 修复方向：Validate 加合理上限（如 ≤10^7），预分配 hint 另设封顶。
- 修复状态：**已修复**（批次 1-A：Validate 新增 10^7 上限校验 + 边界测试）

### MED-9 登录限速窗口 Expire 失败被吞，可导致来源 IP 永久 429【B】
- 位置：`server/internal/middleware/ratelimit.go:51`（另 :62-63 输出 `Retry-After: -1` 非法头）
- 问题：count==1 时 `_ = Expire(...)` 静默忽略失败；Valkey 抖动时计数键无 TTL，固定窗口永不过期，该 IP 登录/改密/TOTP 接口永久 429。
- 修复方向：Expire 失败时删除该键或按错误处理；TTL 为 -1 时不输出 Retry-After 或给默认值。
- 修复状态：**已修复**（批次 3-A 确认修复已在工作区：Expire 失败删键 + 503 fail-closed、TTL≤0 退化为窗口长度；本批补故障注入回归测试 4 例）

### MED-10 登录存在用户名枚举时间侧信道【A】
- 位置：`server/internal/auth/service.go:175-197`
- 问题：用户不存在时立即返回，存在时执行 Argon2id（数百毫秒级）校验，响应时间差数个数量级，无等时补偿。
- 修复方向：用户不存在时对预设假哈希执行一次 VerifyPassword 拉平耗时。
- 修复状态：**已修复**（批次 3-A 确认：用户不存在时执行预设 dummyPasswordHash 的真实 VerifyPassword；已有回归测试）

### MED-11 AI 配额检查在 DB 错误时静默放行（fail-open）【A】
- 位置：`server/internal/aicost/aicost.go:62-77`（另 ConcurrentTasks/HighCostTaskDaily 字段定义未执行）
- 问题：两处 `_ = r.db.QueryRow(...).Scan(...)` 丢弃错误，DB 抖动时配额检查必通过——本地 LLM 资源滥用与成本的唯一服务端闸门失效。
- 修复方向：Scan 出错返回错误（拒绝或显式记日志降级）；补齐并发/高成本任务维度。
- 修复状态：**已修复**（批次 3-D 确认：CheckQuota 已 fail-closed、ConcurrentTasks 已接线执行并有测试）。**遗留已闭环**（批次 6：高成本任务口径落地为「任务类型命中 Quotas.HighCostTaskTypes（默认 7 类多 Agent 重分析/模拟/报告类）或 Token 估算 ≥ HighCostTaskTokens（默认 20000）」，强制点在意图分类后、任务登记前（Orchestrator.Run），计数基于持久化的 ai_audit_records，超限 fail-closed 拒绝（chat 走 SSE error、analyze 走 429，均记审计）；13 个新单测全过）

### MED-12 Agent「允许 Tool 集」（allowed_tool_ids）是可写但从不执行的死开关【A】
- 位置：`server/internal/aihandlers/agents_tools_handler.go:170-182`；执行路径 `aiorchestrator/orchestrator.go` ToolContext.CallTool → Registry.Execute 从不读取
- 问题：管理员在 UI 上做的工具收敛不产生任何效果，虚假安全边界（实际越权靠每个 Tool 的 RequiredPermission 兜底）。
- 修复方向：CallTool 增加 Agent→Tool 白名单校验，或下架该配置项。
- 修复状态：**已修复**（批次 3-D 确认：CallTool 已先校 Agent→Tool 白名单再执行，DB 实现 fail-closed，app.go 已接线并有测试）

### MED-13 主动扫描引擎缺少拨号时 IP 复检（SSRF 防护强度不一致）【A】
- 位置：`server/internal/apiscan/engine.go:92-102,285-316` + `worker.go:517-539`
- 问题：仅 hostAllowed 字符串白名单比对后用默认 http.Client 拨号，无「DialContext 内重解析 + 逐 IP 校验」（对比 apisecurity/spec_version.go:711-738 的完整实现）；DNS 重绑定到云元数据等地址时探针会把响应样本落库。
- 修复方向：注入与 specFetchTransport 同构的 DialContext 复检。
- 修复状态：**已修复**（批次 3-D：新增 dial_guard.go——授权时刻解析快照 + 拨号时重解析比对，任一结果落快照外即拒绝；引擎恒注入复检客户端；含重绑定拒绝端到端测试）

### MED-14 系统设置更新审计把 setting_value 原文落审计并外发 syslog，秘密材料泄漏【A】
- 位置：`server/internal/settings/handler.go:74-79`；关联 settings.go:375 白名单含 `gateway_runtime:identity_salt`、`tls_session_ticket_key`；settings.go:264 List 不脱敏；运行期 UpsertString 写入 is_sensitive=false
- 问题：MaskSensitiveJSON 只按字段名脱敏，setting_value 不在列；这两类秘密材料一经系统设置 API 更新即明文写入 operation_audits.after_summary 并随审计 syslog 外发。
- 修复方向：Update 审计按 is_sensitive 或敏感键清单脱敏；秘密材料行统一用 UpsertSensitiveString 写入。
- 修复状态：**已修复**（批次 3-C 确认：SensitiveSettingKeys 清单 + upsertString 兜底强制敏感行 + List 脱敏 + Update 审计按 sensitive 标记写 `"********"`；回归测试已存在）

### MED-15 报表 Preview 缺归属校验，绕过 Download 的「仅本人」边界【A】
- 位置：`server/internal/reports/handler.go:396`（Download 在 434-437 强制仅创建者本人或 download_audit）
- 问题：Preview 只经路由层权限，无归属判断，返回同一份报告全文 HTML——下载侧保密设计被架空。
- 修复方向：Preview 增加与 Download 一致的 isOwner/download_audit 校验。
- 修复状态：**已修复**（批次 3-C：新增 canAccessReportFile 共用归属判定，Preview/Download 同口径；5 用例回归测试）

### MED-16 通知渠道邮箱地址格式校验不足（已修订，删除 SMTP 注入结论）【A→B，等级调整为低】
- 位置：`server/internal/notify/store.go:356-366` + `sender.go:264-283`
- 原报告问题描述（**已被复核推翻**）：原报告称 net/smtp 的 Mail/Rcpt 不校验 CRLF，可注入 `\r\nBcc:` 致邮件外泄。复核确认：Go 标准库 `Mail`/`Rcpt` 在发送命令前均调用 `validateLine`，地址含 `\r`/`\n` 立即报错；且项目在 Mail/Rcpt 全部成功后才调 `client.Data()` 写正文——含换行的地址在信封阶段即失败，邮件头拼接 Bcc 也不会增加 SMTP 信封收件人，**邮件外泄闭环不成立**。
- 修订后定性：配置保存层邮箱格式校验过弱（仅校验包含 `@`），允许保存无效地址导致发送失败。
- 修复方向：复用 reports/schedule.go:56 的严格 emailRe 校验 From/To，并显式拒绝控制字符。
- 修复状态：**已修复**（批次 3-C：新增 isValidEmail（严格正则 + 逐字节拒绝控制字符 + 长度上限），From/To 改走该校验；含 CRLF/换行/缺 TLD/空格 4 反例测试）

### MED-17 应用 Update 不校验 protection_mode，非法值发布后静默回落 DetectionOnly【B】
- 位置：`server/internal/applications/store.go:297-314`；关联 generator.go:271-273 modeToRuleEngine 回落
- 问题：写入非法 mode 后管理员以为处于 PROTECT，实际仅观测不拦截（fail-open 且无任何提示）。
- 修复方向：Update 同步校验防护模式与名称长度。
- 修复状态：**已修复**（批次 3-B 确认：Update 已校验名称长度 + validProtectionMode + validDeploymentMode，已有回归测试）

### MED-18 checkDomainConflict 的 excludeID 参数从未使用，活动域名上线即无法编辑【B】
- 位置：`server/internal/applications/store.go:400-429`（UpdateDomain 在 481 行传入 d.ID 但 SQL/循环均未引用）
- 问题：更新 hostname/端口不变的 ACTIVE 域名会命中自身记录，报「端口已被应用 X 使用」（X 就是自己）。
- 修复方向：查询加 `AND ad.id <> $2`（或循环内跳过自身）。
- 修复状态：**已修复**（批次 3-B 确认查询已含 `ad.id <> $2`；本批在 stage3 集成测试补「更新自身 ACTIVE 域名不冲突 + 跨应用仍 409」用例，需在 CI 环境重跑）

### MED-19 wdsp-agent 控制面地址允许 http://，Bearer credential 明文传输【A】
- 位置：`wdsp-agent/internal/transport/transport.go:188`；关联 cmd/agent/main.go:148-151 固化进 agent.json
- 问题：`--server http://...` 不拒绝不警告；后续所有心跳/事件上报的 Authorization: Bearer <credential> 走明文，中间人可窃取长期 credential 冒充 Agent。
- 修复方向：非 https 直接报错（或仅允许 loopback http 并 WARN）。
- 修复状态：**已修复**（批次 5-A：非 loopback 的 http:// 直接报错（先于 agent.json 固化），loopback 允许但 WARN；含正反例测试。**发布注意**：已固化非 loopback http:// 的存量 agent.json 升级后启动将报错，需写入发布说明）

### MED-20 磁盘缓存补传的限速等待失效，超时后不限速照发【B】
- 位置：`wdsp-agent/internal/agent/agent.go:799-802`
- 问题：注释写「仍不满足则暂停补传」，但 50 次 Allow 失败后直接落入正常发送；断线恢复补传高峰可突破 outbound_mbps 上限挤占业务带宽。
- 修复方向：循环结束后检查最后一次 Allow 结果，失败则 return 等下轮。
- 修复状态：**已修复**（批次 5-A：循环结束后复查，仍不获令牌则返回 errReplayThrottled 保留该段下轮重试；含饱和/放开两场景测试）

### MED-21 诊断打包 .env 脱敏正则遗漏 DSN 类键，APM ClickHouse 口令原样外发【A】
- 位置：`ops/diagnostics/collect.sh:75-76`
- 问题：只匹配键名含 PASSWORD|SECRET|KEY|TOKEN 的行，`APM_CLICKHOUSE_DSN=clickhouse://user:password@host:9000/apm` 这类内嵌口令原样写入对外发送的诊断包。
- 修复方向：补充 DSN|URL|URI 键名或对值中 user:pass@ 段单独掩码。
- 修复状态：**已修复**（批次 5-B：键名正则补 DSN|URL|URI + 值内 `scheme://user:pass@` 通用掩码双道防线；harness 真实产包验证敏感值零泄漏、非敏感行不误伤）

### MED-22 ha-lab compose 硬编码真实强度默认管理员口令【A】
- 位置：`deployment/ha-lab/docker-compose.ha-lab.yml:207`（另 :54、:78、:201、:204 弱默认库/缓存口令）
- 问题：`${INITIAL_ADMIN_PASSWORD:-SysAdmin@S5!2026}` 是外观可投产的真实强度口令，违反「不得保留默认密码」红线且文件易被复制为部署基线（端口虽绑 127.0.0.1 且声明 lab 用途）。
- 修复方向：改为 `:?` 必填或由服务生成一次性随机口令（stage2 已有此写法）。
- 修复状态：**已修复**（批次 5-B：5 处默认口令 + JIUZHANG_MASTER_KEY 空默认全部改为 `:?` 必填注入，文件头更新启动前置说明；test/ha/ha-lab-verify.sh 同步改为要求 export 同源 VALKEY_PASSWORD）

### MED-23 离线交付包安装链无有效完整性校验（已修订修复方案）【A】
- 位置：`ops/install/install.sh:80-116` + `ops/install/install-gateway-baremetal.sh:195-207`
- 问题：install.sh 只用 awk 抠 arch/edition 从不校验文件哈希；裸机包校验的 sha256sums 来自包内自证且 `tar -xzf` 解压发生在校验之前——被篡改的离线包可静默安装 root 级 systemd 服务。
- **复核修订**：原修复建议（校验包内 manifest.files 或旁车 SHA-256）不能证明真实性——若安装包与哈希文件来自同一不可信渠道，校验只能发现偶发损坏，无法抵御主动篡改。可信链路应三选一：① 发布私钥对清单/制品签名，安装端内置可信公钥并在解压、执行前验签；② 从独立且经过认证的渠道获取期望哈希；③ 使用具备签名与身份验证能力的制品分发系统。
- 修复方向：按修订后方案实施（短期先做「先校验后解压」的顺序修正 + 旁车哈希校验防偶发损坏，并在脚本与交付文档中明确说明该校验不抵御主动篡改；真实性验签作为后续增强）。
- 修复状态：**已修复（含后续增强）**（批次 5-B：install.sh 旁车整包哈希 + manifest 逐文件校验、失败即中止；裸机包先校验后解压；build.sh 补齐旁车 .sha256 产出。批次 6：真实性验签体系落地——OpenSSL Ed25519 发布私钥签名（`WDSP_SIGNING_KEY` 指定，未配置跳过并告警、路径无效 fail-closed），安装端两个脚本内嵌可信公钥并在解压/执行任何包内容**之前**验签，未签名默认中止（`--allow-unsigned` 显式逃生开关），验签通过后 sha256/manifest 校验保留为纵深；密钥保管与轮换流程见 docs/DEPLOYMENT.md「离线交付包签名与验签」；offline-signing-harness 25 项 + baremetal harness 45 项全 PASS）

### MED-24 mirrorcap 检测流 http.ReadRequest 对请求头大小/条数无上限【A】
- 位置：`gateway/mirrorcap/stream.go:150`（发现路径 discovery.go:313 有 16KB LimitReader 护栏，检测路径没有）
- 问题：旁路流量天然攻击者可控；textproto 读头对单行长度与头部总数无上限，超长头行使内部缓冲持续增长。
- 修复方向：对读取包一层单请求上限（LimitReader 或头大小护栏，超限终止该流）。
- 修复状态：**已修复**（批次 2-D：新增 64KB headerGuardReader + 读后精确复核，超限终止该流；顺带修复终止分支不排空导致重组器反压死锁的既有缺陷；3 个回归测试）

### MED-25 mirrorcap 站点发现聚合器键基数无上限【A】
- 位置：`gateway/mirrorcap/discovery.go:152`（仅单键客户端集合上限 1000，键总数无上限）
- 问题：聚合键含攻击者可控的 Host/SNI；30s 窗口内每条流换随机域名即新增一键，窗口内内存与落盘量无界。
- 修复方向：加窗口键总数护栏（超限丢弃或归入 other 桶）。
- 修复状态：**已修复**（批次 2-D：maxDiscoveryKeys=10000 上限 + 丢弃计数器纳入周期日志；回归测试覆盖）

### MED-26 eventparser maskMatchedData 只遮蔽每个敏感名的第一次出现，敏感头命中值不遮蔽【A】
- 位置：`gateway/internal/eventparser/parser.go:393`（ParseLine 产出 MatchInfo.MatchedData，:325-327）
- 问题：strings.Index 只找首个 password=/token= 模式，重复出现的同名参数值从第二次起原样进事件；REQUEST_HEADERS:Authorization 命中的 Matched Data 值段没有任何遮蔽，经采集链路入库后事件中心可见。
- 修复方向：循环遮蔽全部出现位置；命中变量为敏感头（Authorization/Cookie 等）时整段遮蔽。
- 修复状态：**已修复**（批次 2-D：循环遮蔽全部出现 + 敏感头命中整段遮蔽 + 顺带修复「token: 值」带空格形式遮不住的既有漏洞；3 个回归测试含事件 JSON 全文零泄漏断言）

### MED-27 退出登录不清 TanStack Query 缓存，共享浏览器跨账号数据残留【A】
- 位置：`web/src/layouts/AdminLayout.tsx:267-281`（queryClient 为 App.tsx:13 模块级单例，全库无 clear/removeQueries 调用）
- 问题：A（如 SYSTEM_ADMIN）退出、B（如 AUDIT_ADMIN）登录后打开同名页面会立即渲染 A 留下的缓存数据，查询 403 时旧数据仍保留显示；401 被动失效路径因整页刷新恰好清缓存，唯独主动登出有缺口。
- 修复方向：session 失效/登出统一入口调用 queryClient.clear()。
- 修复状态：**已修复**（批次 4-A 确认：登出统一入口 finally 中 queryClient.clear()；本批补 2 个回归测试——登出清缓存/登出接口异常仍清缓存）

### MED-28 ai.ts 三处自制 fetch 封装绕过全局 401/423 处理且不校验业务信封【B】
- 位置：`web/src/api/ai.ts:59-127, 165-187, 414-436`
- 问题：streamPostSSE/renameAiSession/patchJSON 裸用 fetch：401 不触发 sessionExpiredHandler、423 不触发 licenseInvalidHandler；resp.ok 时不检查信封 code!=='SUCCESS'；注释称「client.request 不支持 PATCH」已过时（client.ts:49 已支持）。
- 修复方向：删除重复封装统一走 request()（SSE 除外但需补 401/423 回调）。
- 修复状态：**已修复**（批次 4-A 确认：renameAiSession/patchJSON 已收敛回 request()，SSE 补 401/423 回调触发全局处理器；已有回归测试）

### MED-29 HA 回切按钮永远以低优先级节点为目标，故障转移后无法把 VIP 切回原主【B】
- 位置：`web/src/pages/ha-groups/HaGroupsPage.tsx:248-258`；关联 `server/internal/hagroups/handler.go:240-252`
- 问题：nopreempt 自动故障转移后 VIP 在备节点 B，点「回切」前端发 B 的 node_id，后端随之把 B 置为高优先级，把 VIP 永久钉在备节点——与回切意图完全相反；若改发 A，后端又以「已是高优先级无需回切」提前返回。
- 修复方向：前端以实际持有 VIP 的节点为参照选择目标；后端解耦「优先级」与「VIP 实际持有」判定。
- 修复状态：**已修复**（批次 4-D 全栈修复：后端幂等条件改为「目标已持有 VIP」（基于 havipd 回写运行态，过期状态不信任），nopreempt 下已高优先级未持有 VIP 的目标可执行回切（微调对端优先级强制让位）；前端以未持有 VIP 的一方为目标并展示当前持有节点；OpenAPI 文案批次 5-C 已同步；前后端回归测试齐备）

### MED-30 网络配置保存无二次确认，可直接下发网桥/路由到网关节点【C】
- 位置：`web/src/pages/network-config/NetworkConfigPage.tsx:468`
- 问题：页面自身 Alert 写明「高危操作……错误配置可能导致业务流量中断」，同类高危操作（CC 发布、升级执行）都有 modal.confirm，此处标准不一致。
- 修复方向：保存前加 modal.confirm（脏数据存在时提示影响面）。
- 修复状态：**已修复**（批次 4-C 确认 confirmSave 弹窗已在工作区；本批修复其配套回归测试的时序 bug 与 antd 双渲染断言）

### MED-31 License 导入授权无二次确认（已修订后果描述）【C】
- 位置：`web/src/pages/license/LicensePage.tsx:328-341`
- 原报告问题描述（**已被复核部分推翻**）：原报告称「误选过期授权会立即替换有效授权并导致全系统 423 锁定」。复核确认：授权导入服务在写库前依次执行文件解析、Ed25519 验签、Payload 解析、到期检查、主机指纹检查、产品形态绑定检查——已到期授权在到期检查即返回错误，不会替换当前有效授权（有 `TestServiceImportExpiredRejected` 回归测试）。
- 修订后定性：纯前端交互风险——高危操作（导入即生效替换当前授权）缺少二次确认，误选错/他机授权文件仍会造成服务中断。
- 修复方向：选文件后先弹确认框（显示文件名与「将取代当前授权」后果）。
- 修复状态：**已修复**（批次 4-B 确认：beforeUpload 已先弹 modal.confirm（含文件名与后果、okType danger），确认后才提交；回归测试已存在并通过）

### MED-32 主动扫描「启动」无二次确认，单击即向目标发送真实攻击探针【C】
- 位置：`web/src/pages/api-scan/JobsTab.tsx:273-280`（同页停止/紧急停止均有确认）
- 修复方向：启动前加确认（目标名、授权单、探针集与限流参数）。
- 修复状态：**已修复**（批次 4-B 确认：confirmStart 弹窗展示目标名/授权单号/探针集并拉取授权单详情展示限流参数；回归测试已存在并通过）

## 低（59 条，按组件归并）

### 网关 jiuzhang_guard
- LOW-G1【A】`ratelimit/ratelimit.go:247`：Valkey 滑动窗口 member 为「毫秒+进程内自增序号」，多节点同毫秒同序号时 ZADD 互相覆盖，限速向放宽方向偏差。状态：**已修复**（批次 2-C 确认：member 加启动时生成的实例级随机前缀，跨节点不碰撞；回归测试已存在）
- LOW-G2【A】`riskengine/valkey.go:138-170`：Valkey 故障窗口内存回退的风险信号恢复后不被 State 合并，抖动窗口内风险分被整体遗忘。状态：**已修复**（批次 2-C 确认：State 合并内存回退窗口内条目，幂等不重复计数；回归测试已存在）
- LOW-G3【A】`module.go:1147-1148` + `server/internal/gatewayconfig/headers.go:162-164`：默认不重写 X-Forwarded-For，源站若信任 XFF 左端可被伪造（网关自身防护无绕过）。状态：**已修复**（批次 1-A：生成器在无头合规配置记录时默认开启 XFF 覆盖为真实 IP，显式配置仍尊重；有默认开/显式关/显式开三态测试。**残留已闭环**（批次 6）：新迁移 000123 将 `app_header_configs.xff_overwrite` 列默认翻转为 TRUE（存量显式 false 记录语义保留）、`appconfigs.DefaultHeaderConfig()` 置 true（该默认值才是驱动前端表单的无记录回源）、web HeaderProxyTab 表单默认 true——三处与生成器完全对齐；vitest 7 用例全绿）
- LOW-G4【B】`identitybehavior/engine.go:260-275` + `riskengine/engine.go:162-167` + `module.go:872-884` + `accesslog.go:472`：配置重载 Cleanup 裸写字段与在途请求数据竞争，可 nil 解引用 panic。状态：**已修复**（批次 1-A：Close/Cleanup 只关闭资源不置 nil 且幂等；-race 专项通过）
- LOW-G5【A】`identitybehavior/identity.go:121-129`：identity_key 凭据优先且不验签，轮换伪造凭据即重置全部按身份风险累计。状态：**已文档化**（批次 1-A：docs/ADR_IDENTITY_BEHAVIOR_V1_1.md 新增「已知限制」节声明该限制与 IP 维度兜底）
- LOW-G6【B】`identitybehavior/engine.go:172-182`：所有 caddyhttp.Error 拦截分支在行为快照中状态码记 0（403/429 桶漏计）。状态：**已修复**（批次 1-A：End 增加错误链兜底（caddyhttp.HandlerError.StatusCode），已采集状态码优先；3 例回归测试）
- LOW-G7【B】`accesslog.go:247-256`：captureResponseWriter 不排除 1xx，Early Hints 被记为最终状态码且 TTFB/采体决策提前落定。状态：**已修复**（批次 2-B 确认：code<100||>=200 才落定；103 场景回归测试已存在）
- LOW-G8【B】`redirect_rewrite.go:82-108`：只改端口不改 host，内部主机名仍随 302 泄漏（文件头注释已声明定位是修可用性非防泄漏）。状态：**已文档化**（文件头注释已声明，批次 1-A 核实无需代码改动）
- LOW-G9【B】`netcollector.go:54-98`：采集器替换窗口内 cancel 尚未赋值，可泄漏 goroutine。状态：**已修复**（批次 2-B 确认：先建 ctx/cancel 再一次性发布；并发 Provision 回归测试已存在）
- LOW-G10【B】`apiprotect.go:224` + `apiresponse.go:179-184`：spill 响应 BodySize 双重计数缓冲前缀（最多高估 1MiB），污染文件资产 Size 与统计。状态：**已修复**（批次 1-B：body.Len() 仅在未 spill 时计入；回归测试断言 spill 下载 Size 等于实际外发字节数）
- LOW-G11【B】`dynamic_security/response/transform.go:41-46`、`watermark.go:214-221`：JSON 改写静默丢弃首个 JSON 值之后的尾随字节。状态：**已修复**（批次 1-C 确认：ensureSingleJSONValue 尾随数据探测走 FAIL_OPEN；本批补尾随数据/空白尾随回归测试）
- LOW-G12【A】`dynamic_security/detectors/scanner.go:116-127`：扫描识别签名仅 HMAC(job_id) 无时效，泄漏后可无限重放污染学习样本。状态：**已修复**（批次 1-C 确认网关侧三段式时效契约已在工作区并更新契约测试；批次 2-A 把 server 侧 apiscan/sign.go 对齐为 job_id|unix_ts ±5 分钟时窗，jiuzhang_guard 端到端测试复跑通过）
- LOW-G13【A】`havipd/keepalived.go:48` + `config.go:163-165`：auth_pass 仅校验长度未拒绝换行，可注入 keepalived 配置行。状态：**已修复**（批次 2-D：逐字符校验仅允许可打印非空白 ASCII；4 反例测试）
- LOW-G14【A】`stek-lab/config-a.json:22`（b/c 同）：STEK 密钥以固定已知值提交进仓库（lab 有意设计，但有被复制到生产的风险）。状态：**已文档化**（批次 2-D：stek-lab compose 文件头加「密钥仅为 lab 占位、视为已泄漏、生产必须由密钥管理下发」警告）
- LOW-G15【A】`rules/coraza.conf:59`：SecAuditEngine On + 部件含 C（全量请求体落盘）为 POC 默认，且经核实会原样进入生产（generator Include + 离线包携带）。状态：**已修复**（批次 3-E：生成器在 Include 后内联写入 SecAuditEngine RelevantOnly + Parts 去 C 的生产覆盖（Coraza 后写覆盖语义已在 v3.7.0 源码核实），POC 文件保持实验室/FTW 用途不动；新增生成产物回归测试）

### 管理后端
- LOW-S1【A】`auth/totp.go:66-99`：TOTP 挑战令牌不绑定来源 IP/UA，5 分钟 TTL 内可跨机完成第二步。状态：**已修复**（批次 3-A 确认：挑战令牌存 IP/UA，验证不一致拒绝且不消费令牌；回归测试已存在）
- LOW-S2【A】`security/totp.go:127-131`：恢复码 8 字符≈40bit 熵 + 无盐 SHA-256，DB 泄漏后可离线暴破。状态：**已修复**（批次 3-A 确认：恢复码改 Argon2id 每码随机盐，旧无盐 SHA-256 仅校验兼容命中即消费迁移；回归测试已存在）
- LOW-S3【B】`auth/service.go:372-396` + `loginlogs/loginlogs.go:87-94`：登录日志写库失败完全静默（无日志）。状态：**已修复**（批次 3-A 确认：Record 失败路径补 Warn（不含敏感字段）；DB 故障路径建议后续集成测试覆盖）
- LOW-S4【B】`users/handler.go:201-205`：管理员 Update 未校验 DisplayName 长度，超长输入 500 而非 400。状态：**已修复**（批次 3-A 确认：与 Create/profile 同一 128 上限 400 校验）
- LOW-S5【B】`users/store.go:430-444`：管理员重置密码不写入密码历史，历史策略可被回退绕过。状态：**已修复**（复核确认：UpdatePasswordForceChange 已在事务中写入旧密码历史）
- LOW-S6【B】`security/captcha.go:159-162`：randInt 吞 crypto/rand 错误，极端情况 nil 解引用。状态：**已修复**（批次 3-A 确认：randInt 返回 error 逐级上抛；本批补正常路径回归测试）
- LOW-S7【B】`auth/handler.go:310-311`：Me 接口吞角色/权限查询错误，DB 抖动时返回空权限引发前端误踢出。状态：**已修复**（批次 3-A 确认：两者失败均返回 500）
- LOW-S8【A】`aihandlers/agents_tools_handler.go:69-91`：Tool/Agent 启停检查 DB 出错时 fail-open（视为启用）。状态：**已修复**（批次 3-D 确认：仅 ErrNoRows 放行，其余 DB 错误记 Warn 并拒绝）
- LOW-S9【A】`apiscan/apiops/apisecurity/apiauthz/apidata` 列表接口 page_size 无上限（兄弟包均夹取 ≤100）。状态：**已修复**（批次 3-D：五包统一 queryPageSize 夹取 ≤100 + store 层 normPage 同步；顺带修复 apidata ListAllTypes 借分页取全量被截断的问题；各包新增分页测试）
- LOW-S10【B】`aiorchestrator/orchestrator.go:93-105` + `aicost`：TaskLimits 三个字段与 Quotas.MaxToolCalls 定义后无强制点。状态：**已修复（MaxToolCalls）**（批次 3-D 确认：CallTool 内按任务共享计数器强制上限，跨 Agent 共享，超限报错）。**遗留已闭环**（批次 6）：输入侧单一权威为 aicost `PerRequestTokens`（handler CheckQuota 强制），`TaskLimits.MaxInputTokens` 重定义为单次 LLM 调用输入上限并由装配层从权威值映射，`llmCompose` 发起 Chat 前估算校验、超限拒绝并走既有确定性降级；输出侧硬编码 256 替换为 `MaxOutputTokens`（≤0 回退 256，注意 DefaultLimits 声明默认 4096，生产装配下 compose max_tokens 由 256 变 4096）
- LOW-S11【B】`aimodel/store.go:45-54` + `gateway.go:114-123`：供应商密钥两处静默降级（enc 缺失时密钥被丢弃且非事务；解密失败静默切备用模型掩盖配置故障）。状态：**已修复**（批次 3-D：enc 缺失直接报错 + 建行与密钥同事务回滚；解密失败记 Warn 且该候选直接判失败不发起呼叫不计熔断；测试更新）
- LOW-S12【B】`securityevents/handler.go:135-137`：事件详情静默吞三类子查询错误。状态：**已修复**（批次 3-C：三处改 slog.Warn 记录 event_id + error）
- LOW-S13【B】`settings/settings.go:306`：数值类安全策略（password:min_length 等）无取值范围校验，可写 0/负数。状态：**已修复**（批次 3-C 确认：settingValueRanges 逐键范围校验已挂入 Update，回归测试已存在）
- LOW-S14【B】`upgrades/upload.go:120-138`：同名并发上传 TOCTOU 小竞态（预检复核哈希兜底，不会执行错误包）。状态：**已修复**（批次 3-C：按文件名互斥锁 + finalizeUpload 临界区内冲突判定与 rename；8 并发测试恰 1 成功）
- LOW-S15【B】`customrules/customrules.go:431-461` + `exceptions/exceptions.go:444-489`：手写 JSON 序列化/解析不对称，含反斜杠或逗号的值损坏数据。状态：**已修复**（批次 3-B 确认：两处均已改用 encoding/json，存量数据兼容，round-trip 回归测试已存在）
- LOW-S16【B】`gatewayconfig/publish_store.go:351-362,179-180`：GetCurrentVersion 把扫描错误一律吞成 (nil,nil)。状态：**已修复**（批次 3-B：仅 ErrNoRows 返回 (nil,nil) 其余上抛；批次 4-E 配套修复 CurrentConfig handler 对非空 err 返回 500 并补 500 回归测试）
- LOW-S17【B】`apiscan/worker.go:201-222`：手动 StartJob 全局并发上限 check-then-act 竞态。状态：**已修复**（批次 3-D：占槽+检查同锁原子完成，失败回滚；顺带闭合 RunOnce 调度任务不登记 running 的同源缺口；8 并发 -race 测试通过）

### wdsp-agent
- LOW-A1【B】`agent/agent.go:931-949` vs `capture/eth_linux.go:197-204`：内核丢包统计口径自相矛盾（读后清零 vs 累计差分），kernel_drops 系统性失真。状态：**已修复**（批次 5-A：统一差值语义——AF_PACKET 直接累加每次读数，eBPF 后端内部差分化；接口注释写明契约）
- LOW-A2【B】`agent/agent.go:552-561,516-526`：内存队列 64MB 字节硬上限为 check-then-act，并发生产者可突破。状态：**已修复**（批次 5-A：reserveQBytes CAS 原子预留 + 入队失败回滚；32 并发 -race 测试）
- LOW-A3【B】`buffer/buffer.go:29` + `agent.go:605`：磁盘缓存单记录上限 1MB 与 Body 硬上限 10MB 不匹配，断网期静默丢大 Body 记录。状态：**已修复**（批次 5-A：上限提至 21MB（10MB×2+开销），段写路径支持超段长大记录；12MB 记录写入回读测试）
- LOW-A4【B】`cert/manager.go:129-136`：证书轮换回滚静默吞错，可留下钥/证不匹配死状态。状态：**已修复**（批次 5-A：回滚失败返回 ErrRollbackFailed 哨兵错误并升级 Error 日志提示重新注册；测试覆盖）
- LOW-A5【B】`k8smeta/k8smeta.go:86-98,216-238`：ServiceAccount token 仅启动时读取，投射卷轮换后永久 401 停滞。状态：**已修复**（批次 5-A：每轮 sync 重读 token（失败 fail-open 沿用旧值并 WARN），401 时重读重试一次；跨轮轮换恢复测试）
- LOW-A6【B】`httpparse/httpparse.go:35-71` + `flow/flow.go:288`：Sniffer.buf 决策后不释放，单流最高常驻 16KB（65536 流≈1GB）。状态：**已修复**（批次 5-A：决策后即释放 buf 与 sniffer；测试覆盖）
- LOW-A7【B】`filter/filter.go:77-88` + `flow/flow.go:271-278`：双采集端口互访时同一连接被拆成两条单向流，HTTP 配对全灭。状态：**已修复**（批次 5-A：Packet 新增 BothHit，flow 与 sensor 两层按五元组排序固定 canonical；配对回归测试）
- LOW-A8【B】`flow/flow.go:282-284,304-322`：满驱逐路径在全局锁内同步调 onEvent（可写磁盘），且驱逐 O(n) 全表扫描。状态：**已修复**（批次 5-A：驱逐事件锁外发送 + 采样 8 条取最旧 O(1) 化；重入不死锁测试）
- LOW-A9【B】`capture/capture_linux.go:80-98`：AF_PACKET 崩溃退避 sleep 不可中断，停止后仍重建句柄泄漏 fd。状态：**已修复**（批次 5-A：退避改 select stopCh、重建前再查 stopCh、竞态句柄补关闭；GOOS=linux 编译/vet 验证）

### 前端
- LOW-W1【C】`pages/login-logs/LoginLogsPage.tsx:16-41`：硬编码枚举缺 LOGIN_TOTP_CHALLENGE 与 TOTP 失败码，无法筛选且裸码显示。状态：**已修复**（批次 4-B 确认：两项映射已补齐，后端码值已 grep 核实一致）
- LOW-W2【C】`pages/access-control-versions/AccessControlVersionsPage.tsx:101-103`：回滚按钮未做权限门控（只读用户点了必收 403）。状态：**已修复**（批次 4-B 确认：按 access_control_versions.rollback 控制显隐；权限测试已存在）
- LOW-W3【C】`pages/api-specs/ApiSpecsPage.tsx:426-428`：URL 导入认证头值用明文 Input（同类字段均 Input.Password）。状态：**已修复**（批次 4-B 确认：Input.Password + autoComplete="new-password"；回归测试已存在）
- LOW-W4【C】`pages/apm-agents/ApmAgentsPage.tsx:175-186`：基线策略作用域仅取前 100 条 Agent，超出的服务不可选。状态：**已修复**（批次 4-B 确认：Select 远程搜索 + 300ms 防抖透传 keyword，后端 ILIKE 匹配已核实；回归测试已存在）
- LOW-W5【C】`pages/big-screen/TrafficAccessScreen.tsx:99-158`、`AttackMonitorScreen.tsx:94-225`：真实数据全零时大屏展示虚构攻击数据（与「不得用 Mock 数据」红线相悖）。状态：**已修复**（批次 4-B 确认：KPI 全部取真实值（注释明确 KPI 不得引用演示序列），演示兜底仅限趋势图/TOP 榜/事件流并保留角标；查询失败展示降级条+真实空态）
- LOW-W6【C】`hooks/useBatchDelete.tsx:100`：无 getCheckboxProps 行级禁用——系统保护地址/他人报告可勾选批量删（后端 409/403）、可勾选当前会话把自己踢下线（3 处使用点）。状态：**已修复**（批次 4-C 确认：useBatchDelete 新增 rowDisabled 透传 getCheckboxProps，三个使用点已按行禁用；回归测试已存在）
- LOW-W7【C】`pages/security-events/SecurityEventsPage.tsx:144-153`：导出只透传 5 个筛选参数，其余 6 项静默丢弃且无提示。状态：**已修复**（批次 4-C 确认：导出按钮 Tooltip 明确说明生效的筛选维度）
- LOW-W8【B】`pages/system-upgrade/SystemUpgradePage.tsx:386`、`traffic-agents/PolicyPanel.tsx:465`、`CaptureOverridesPanel.tsx:266`：表单校验失败产生未捕获 Promise rejection。状态：**已修复**（批次 4-C 确认：三处均已 try/catch 并附注释）
- LOW-W9【C】`pages/waf-rules/WafRulesPage.tsx:284`：规则 ID 筛选逐字符触发查询无防抖。状态：**已修复**（批次 4-C 确认：本地输入态 + 回车/失焦才提交查询，与 Input.Search 纪律一致）
- LOW-W10【C】`pages/traffic-agents/CaptureOverridesPanel.tsx:284-295`：dst_ip/host/uri_prefix 无格式校验，错误值到后端才 400。状态：**已修复**（批次 4-C 确认：dst_ip/uri_prefix 已补与后端同口径 validator；host 后端本就只限长度，前端 maxLength 已对齐，维持现状有依据）
- LOW-W11【C】`pages/risk-policy/RiskPolicyPage.tsx:94-99`：信号分值表允许重复 signal_type 行，提交时静默覆盖。状态：**已修复**（批次 4-C：提交前检测重复键，行级错误定位 + message.error，不发起 PUT；回归测试新增）
- LOW-W12【C】`pages/trusted-proxies/TrustedProxiesPage.tsx:783`：保护地址列表全量拉取纯前端分页。状态：**已修复**（批次 6：后端补齐分页——Store.ListPaged（count + LIMIT/OFFSET）+ Handler.List 解析 page/page_size（默认 1/20，page_size 夹取 ≤100）返回 `{items,page,page_size,total}`；原全量 List 保留供 IsProtected 封禁前保护检查；OpenAPI 04 分片与 wdsp-api.yaml 已同步；前端切服务端分页，筛选变更重置第 1 页；不带分页参数的旧调用得到第一页（语义变化已在台账声明），后端 4 个分页单测 + 前端 3 个用例全绿）
- LOW-W13【C】`api/client.ts:97-99` + `App.tsx:22-29`：401 全局回调无 /auth/* 白名单；整页刷新丢 from 回跳。状态：**已修复**（批次 4-A 确认：/auth/* 端点跳过全局 401 回调；已有回归测试）
- LOW-W14【B】`api/client.ts:108,165-206`：resp.text() 全量读入无大小上限，fetch 无超时（挂起永不 settle）。状态：**已修复**（批次 4-A 确认：60s 超时 + 10MiB 响应上限（超限给可读错误码），长耗时端点可显式放宽；已有回归测试）
- LOW-W15【C】`constants.ts:3`：SYSTEM_VERSION 硬编码 V1.0.1，与发版流程脱节。状态：**已修复**（批次 4-A 确认：vite 构建期从 package.json version 注入，展示格式不变）

### 运维
- LOW-O1【B】`ops/lib/common.sh:118`：api_login 硬编码读 CWD 下 .env，未用 -e/--env-file 传入的 $JZ_ENV_FILE。状态：**已修复**（批次 5-B 确认：已优先读 $JZ_ENV_FILE）
- LOW-O2【A】`ops/lib/common.sh:120`：`valkey-cli -a` 口令暴露在进程命令行（check.sh:124 已有 REDISCLI_AUTH 安全写法）。状态：**已修复**（批次 5-B 确认：已统一为 REDISCLI_AUTH 环境变量方式）
- LOW-O3【A】`ops/install/install.sh:256-258`、`install-gateway-baremetal.sh:369-371`：firewalld 默认放行 1024-65535/tcp 全高位端口。状态：**已修复**（批次 5-B：默认仅放行 80/443 + 新增 --site-ports 精确放行（含端口清单校验函数与醒目警告）；docs/DEPLOYMENT.md 端口表已同步）

---

## 修复完成记录（2026-09-05）

### 批次执行摘要

| 批次 | 范围 | 结果 |
|------|------|------|
| 批次 1 | 网关核心（module.go+identitybehavior / apiprotect+apiresponse+apievents / dynamic_security） | HIGH-5、HIGH-7、MED-1、MED-5、MED-8、LOW-G3/G4/G6/G10 新修；HIGH-6、MED-4、MED-6、LOW-G11/G12 确认工作区已有生产修复并补齐/更新回归测试；LOW-G5/G8 文档化 |
| 批次 2 | 跨模块接线收尾 + accesslog/netcollector + riskengine/temporaryblock/ratelimit + 网关周边 | scanner 签名契约 server/网关两端对齐；HIGH-6 下载方向接线闭环；TestRiskPolicyProtectRateLimit 修正；MED-2/MED-3/LOW-G7/G9、LOW-G1/G2、MED-7 网关侧确认已修；MED-24/25/26、LOW-G13/G14/G15 新修 |
| 批次 3 | server 认证安全 / 配置规则 / 运维包 / WDSP·AI 包 / 编译与 coraza 生产覆盖 | MED-13、MED-15、MED-16、LOW-S9/S11/S12/S14/S16/S17、maskQuery 新修；tproxyd 编译修复；LOW-G15 生产覆盖方案实施；其余确认工作区已修并补回归测试 |
| 批次 4 | web 基础设施 / 页面 A / 页面 B / HA 回切全栈 / server 收尾 | MED-29 全栈新修；MED-27/28/30/31/32、LOW-W1~W15 确认已修，补缺失回归测试并修绿 4 个既有坏测试；settings_integration_test.go 编译修复；CurrentConfig 吞错修复 |
| 批次 5 | wdsp-agent 全部 / ops 脚本 / 全仓收尾 | HIGH-12、MED-19/20、LOW-A1~A9 全部新修；HIGH-14、MED-21/22/23、LOW-O3 新修（LOW-O1/O2 确认已修）；OpenAPI failback 文案同步；web typecheck 收尾全绿；新增 ops-security-harness.sh（35 项） |
| 批次 6 | 设计级遗留全量闭环（5 个并行任务） | MED-11 高成本任务配额口径+强制点落地；LOW-S10 token 上下限穿入 LLM 调用链；MED-23 Ed25519 离线包签名验真体系（含 ops/lib/signing.sh、--allow-unsigned 逃生开关、DEPLOYMENT.md 密钥流程）；HIGH-14 hostctl 标志 HMAC 签名+防重放；LOW-G3 XFF 默认值三处对齐（迁移 000123+DefaultHeaderConfig+前端表单）；LOW-W12 保护地址服务端分页全栈 |

### 最终验证结果（批次 5-C 全量复跑 + 批次 6 收尾后确认）

- `server`：`go build ./...`、`go vet ./...` 通过；`go test -short ./...` 全部通过（需 PostgreSQL/Valkey/ClickHouse 的集成测试按仓库 testing.Short() 约定跳过，未在真实外部依赖下运行）。批次 6 后复跑：aicost / aiorchestrator / aimodel / protectedaddresses / systemops / appconfigs / notify / outboundhttp 八包 `-count=1` 全 ok。
- `gateway` 根模块 + `gateway/modules/jiuzhang_guard` + `gateway/dynamic_security`：build / vet / 全量 test 全部通过。
- `wdsp-agent`：`go test ./...` 20 个包全部通过；改动核心 8 包 `-race` 通过；`GOOS=linux` 跨平台 build/vet 通过（Linux-only 代码未在真内核上 smoke）。
- `web`：`tsc --noEmit` 全绿；批次 6 前 `npx vitest run` 全量 99 个测试文件 / 690 个用例全部通过，批次 6 新增 HeaderProxyTab（7 用例）与 TrustedProxiesPage 分页（3 用例）实跑全绿。
- `ops`：全部改动脚本 `bash -n` 通过；`ops-security-harness.sh` 39 项全 PASS（含 HIGH-14 签名验真 4 新用例）；新增 `offline-signing-harness.sh` 25 项全 PASS；`baremetal-gateway-harness.sh` 45 项全 PASS（已适配验签 fail-closed 新默认）。
- 全仓 `gofmt -l server/ gateway/ wdsp-agent/` 干净。

### 设计级遗留（原 5 项已于批次 6 全部闭环，仅余已知限制与跟进项）

1. ~~MED-11 遗留~~ → **批次 6 已闭环**（见 MED-11 条目状态）。
2. ~~LOW-S10 遗留~~ → **批次 6 已闭环**（见 LOW-S10 条目状态；行为变化提示：DefaultLimits 下 compose max_tokens 256→4096，如本地 CPU 推理偏慢可在装配层调小）。
3. ~~MED-23 后续增强~~ → **批次 6 已闭环**（见 MED-23 条目状态；发布私钥已生成于 `runtime/license/offline-package-signing.key`（0600，gitignore 双重排除），需移交发布负责人保险库保管）。
4. ~~HIGH-14 后续增强~~ → **批次 6 已闭环**（见 HIGH-14 条目状态；发布注意：升级后旧版未签名 hostctl 标志将被拒绝，属预期行为；5 分钟窗口内重放的彻底防御需持久化已用 requestID 集合，留作后续增强）。
5. ~~LOW-G3 残留~~ → **批次 6 已闭环**（见 LOW-G3 条目状态；迁移 000123 未在真实 PostgreSQL 上执行过，仅一条 ALTER COLUMN SET DEFAULT，需 CI 验证）。
6. **MED-5 已知限制**：单实例摘除 behavior_store 后进程级 Valkey 注入残留至下次非 nil 装配或进程重启（代码注释已声明）。
7. **MED-19 发布注意**：已固化非 loopback http:// 控制面地址的存量 agent.json，升级后 agent 启动将直接报错（修复的预期行为），需写入发布说明。
8. 其他小型跟进项：tproxyd supervisor 测试固定端口偶发冲突（flaky，建议改动态端口）；gatewayconfig handler.go:200/253 的 `current, _ :=` 尽力渲染语义未改；批次 3-B 新增的两条集成测试（stage3 域名自更新 / stage5 janitor HDel）需在 CI 真实依赖环境重跑。

## 复核验证记录

2026-09-05 复核执行（详见 `code-review-validation-2026-09-05.md` 第 7 节）：

```text
GOCACHE=/private/tmp/wdsp-review-go-cache GOPROXY=off \
  go test ./internal/customrules ./internal/exceptions ./internal/gatewayconfig ./internal/license
```

customrules/exceptions/license 通过；gatewayconfig 全包测试在沙箱中因 httptest 无法监听本地 IPv6 端口中断（非断言失败），随后 `-run '^TestGenerate'` 专项测试通过。
