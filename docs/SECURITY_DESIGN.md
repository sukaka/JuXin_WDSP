# 安全设计文档

## 管理面安全

1. **端口分离**：管理端和业务代理端口分离，管理端默认只监听内网；
2. **身份认证**：所有接口执行身份认证；
3. **权限控制**：所有写接口执行后端权限校验和 CSRF 校验；
4. **配置校验**：所有进入网关配置的字段经过白名单校验；
5. **数据库权限**：使用最小权限账号；
6. **Valkey 安全**：禁止公网暴露，必须配置访问密码；
7. **Caddy Admin API**：仅通过 Unix Socket 访问，不暴露到业务网络；
8. **文件上传**：限制大小和类型；
9. **私钥保护**：证书私钥加密存储，日志不打印私钥；
10. **日志脱敏**：敏感字段默认脱敏；
11. **错误处理**：接口错误不返回堆栈；
12. **调试接口**：生产环境关闭；
13. **安全响应头**：配置默认安全响应头；
14. **限速**：登录和高风险接口限速。

## 三权角色权限划分（迁移 000100 口径）

- **安全管理员（SECURITY_ADMIN）**：全部安全功能——应用防护、应用防护策略、访问控制、API 防护、事件中心、安全态势（含系统告警的安全告警）、报表中心、智能安全运营，以及 HA 主备、告警通知只读。
- **系统管理员（SYSTEM_ADMIN）**：系统运维（运行监控/网口/网络/存储/备份/升级/交付检查/告警通知）、用户与角色管理、系统设置、授权管理、系统告警（系统运维告警），以及智能能力管理整组（模型/智能体/工具/提示词/记忆/配额成本/智能审计/质量评估）；不持有任何安全业务权限点。
- **审计管理员（AUDIT_ADMIN）**：纯审计角色，仅操作审计（`audits.*`）、登录日志（`login_logs.*`）、个人资料与自身会话自助、工作台基础信息；不持有任何业务与 AI 权限点。
- 该划分由迁移 `000100_role_perm_rebalance` 统一收口，前端菜单（`web/src/utils/menu.ts`）角色码与后端路由 `RequirePermission` 权限点口径一致；自定义角色不受影响，仍按权限点补显菜单。

## 身份认证安全

- 密码使用 Argon2id 或 bcrypt 存储；
- 不允许明文密码；
- 访问令牌使用 HttpOnly、Secure、SameSite Cookie；
- 不保存于浏览器 LocalStorage；
- 所有写操作执行 CSRF 校验；
- 登录错误不区分用户名不存在和密码错误；
- 连续登录失败次数和锁定时间可配置。

## 配置注入防护

所有可进入网关配置的字段必须经过白名单校验。

禁止直接把用户输入拼接到：

- Caddyfile；
- SecLang 规则；
- Shell 命令；
- 文件路径；
- SQL；
- HTML 阻断页面；
- Docker 命令。

使用结构化配置生成器，不依赖字符串模板无条件拼接。

## SSRF 防护

源站连通性测试必须防止访问：

- Caddy 管理接口；
- 管理后端接口；
- Docker Socket；
- 云主机元数据地址；
- 本机回环管理服务；
- Valkey 和 PostgreSQL；
- Unix Socket；
- `file://` 等非 HTTP 协议。

允许管理员显式配置合法内网源站，但必须经过地址解析、端口校验和审计。

## 日志隐私

默认脱敏字段：

- Authorization；
- Cookie；
- Set-Cookie；
- 密码参数；
- Token；
- 身份证号；
- 银行卡号；
- 私钥；
- 会话标识。

安全事件只保留调查所需信息，不默认保存完整请求体和响应体。

## 日志外发（syslog）

管理面业务日志可外发至用户自建 syslog 服务器（SIEM 对接），外发不改变库内记录，外发失败不影响任何主流程。

- **外发范围（六类）**：安全事件、访问控制事件、全量访问日志、操作审计、登录日志、系统告警。网关 Caddy 运行日志、Coraza 原始 audit 文件、API 进程 stdout 属进程运行日志，不经管理面外发。
- **架构**：各采集器/业务服务在**入库成功后**通过非阻塞 `Enqueue` 投递（有界内存队列 10000 条，满时丢弃最旧并告警计数）；后台单协程批量发送。操作审计/登录日志/系统告警以装配层闭包注入投递函数（避免包间循环依赖），未注入时跳过。发送失败的报文追加到磁盘 spool（`syslog-spool.jsonl`，上限 50MB，超限截断只留后半部分），后台每 10s 重放，全部成功后删除文件。配置每批发送前从 `system_settings` 热读取，改开关/地址即时生效。
- **报文格式**：RFC5424（`<pri>1 ts host app-name procid msgid - msg`），APP-NAME 固定 `jiuzhang-waf`，MSGID 按类型区分（`security-event` / `access-control-event` / `access-log` / `operation-audit` / `login-log` / `system-alert` / `test`），MSG 为紧凑 JSON，换行与控制字符一律清洗防帧破坏。severity 映射：安全事件 HIGH→3/MEDIUM→4/LOW→5；系统告警按等级 CRITICAL→2/HIGH→3/MEDIUM→4/LOW→5；登录失败与删除/禁用类审计→4（warning）；其余→6（info）。
- **配置项**（`system_settings` logging 组，接口仅允许白名单键、boolean 类型强校验）：

| 设置键 | 类型 | 默认 | 说明 |
|--------|------|------|------|
| `syslog_enabled` | boolean | false | 外发总开关 |
| `syslog_protocol` | string | udp | 传输协议（udp / tcp） |
| `syslog_address` | string | 空 | 服务器地址（host:port） |
| `syslog_facility` | integer | 1 | facility 数值 |
| `syslog_forward_security_events` | boolean | true | 外发安全事件 |
| `syslog_forward_access_control_events` | boolean | true | 外发访问控制事件 |
| `syslog_forward_access_logs` | boolean | false | 外发全量访问日志 |
| `syslog_forward_operation_audits` | boolean | true | 外发操作审计 |
| `syslog_forward_login_logs` | boolean | true | 外发登录日志 |
| `syslog_forward_system_alerts` | boolean | true | 外发系统告警 |

- **可靠性语义**：UDP 不保证送达（无重传，发送失败仅进 spool 依赖下次重放，队列满丢弃最旧）；TCP 断线自动重连（退避 1s→30s）+ spool 重放，尽力投递不保证零丢失。外发为旁路设计：任何环节失败只记日志/告警计数，绝不阻塞或回滚业务写入。
- **安全约束**：操作审计外发 payload 复用脱敏后的 before/after 摘要（与库内一致）；登录日志不含密码、验证码、完整会话标识；测试消息接口（`POST /api/v1/system-settings/syslog-test`）需 `logging.syslog_test` 权限并记操作审计；系统告警仅新建 OPEN 时外发（合并不重复外发），评估器对同 type+component 未关闭告警去重，防止外发失败→告警→再外发的循环放大。

## 数据安全

- 证书私钥在数据库或磁盘中加密保存；
- 私钥文件权限不得高于 `0600`；
- 备份文件中的私钥必须加密；
- 删除证书前必须检查绑定关系。

## 网关安全

- Caddy Admin API 仅通过 Unix Socket 访问；
- 配置发布失败不影响当前有效配置；
- 重启后恢复最后有效配置；
- 真实客户端 IP 识别基于可信代理列表；
- 不无条件信任 X-Forwarded-For。

## 容器运维通道安全（containerops sidecar）

- **docker.sock 唯一持有**：全栈仅 containerops sidecar 挂载 `/var/run/docker.sock`；
  API 容器只挂载共享 Unix Socket 卷（仅见 socket 文件），任何其他容器挂载
  docker.sock 即视为配置事故；
- **sidecar 最小权限**：镜像以非 root（uid 1000）运行、`read_only` + `cap_drop ALL` +
  `no-new-privileges`，访问 docker.sock 的属组 gid 经 `group_add` 注入
  （`CONTAINEROPS_DOCKER_GID`，安装期 `ops/install/prepare-containerops.sh` 探测），
  不固化宿主机 gid、不授予任何 capability；
- **无网络面**：sidecar 不暴露 TCP 端口，以 `network_mode: none` 运行，请求只可能
  来自共享卷内的 Unix Socket；
- **双重白名单校验**：操作目标必须同时命中 compose 项目标签（`CONTAINEROPS_PROJECT`）
  与服务白名单（`CONTAINEROPS_ALLOWED_SERVICES`），任一不满足 fail-closed 拒绝并记审计；
  sidecar 自身永远不在白名单内（防通道自毁）；
- **镜像更新纪律**：update 拒绝 `latest` 与任意 tag，只接受显式锁定引用；不提供
  卷删除、`system prune` 等破坏性语义；API 自身禁止经通道 stop/update；
- **审计与脱敏**：全部写操作经管理面权限校验 + CSRF + 操作审计；sidecar 审计行不含
  环境变量值与凭据；日志读取限尾 1000 行/1MB 截断并剥离控制字符，inspect 输出
  仅白名单字段、不回传容器 Env；
- **降级口径**：裸机 systemd 形态无 docker.sock，容器运维接口 503 降级、页面隐藏入口，
  不伪造容器状态。设计全文见 [docs/CONTAINER_OPS_DESIGN.md](CONTAINER_OPS_DESIGN.md)。

## 访问控制与CC防护安全（阶段5）

- 只有 TCP 连接源属于可信代理时才解析代理头，其余一律使用连接源 IP；
- 代理头值禁控制字符、限长、链长上限 16，非法即回退并产生安全事件；
- IPv4 映射 IPv6 统一归一，CIDR 不用字符串前缀判断（netip 规范化匹配）；
- 保护地址（网关/管理平台/数据库/缓存/源站/可信代理/回环/链路本地）永不封禁，封禁尝试记高风险审计；
- 临时封禁不得自动转永久，永久封禁必须人工确认；
- CC 计数键与封禁键全部哈希化（sha256+长度前缀），禁止拼接用户输入；
- 内存计数器容量有界（LRU 淘汰），Valkey 键带 TTL 自动过期，防随机键耗尽；
- Valkey 故障按配置 Fail-open/Fail-closed 处理并产生告警事件，不静默关闭防护；
- URI 正则限长 256 且仅使用 Go RE2（线性时间，防 ReDoS）；
- 429 响应不返回内部阈值/计数/算法/节点，不反射用户输入；
- 导入限 1MB/10000 行并逐行校验，导出防 CSV 公式注入；
- 封禁/解封/发布/回滚全部操作审计，三权边界由后端强制校验。

## AI 安全运营中心安全（阶段7）

- **权限模型（能力权限 + 数据权限两层）**：能力层——迁移 000014 种子 31 个 `ai.*` 权限点，000100 起按新三权口径分配：安全管理员获智能安全运营全量能力（分析/草稿/降噪，不含模型/Agent/Tool/Prompt/记忆/配额等能力管理），系统管理员独占智能能力管理（模型/Agent/Tool/Prompt/记忆/配额成本/智能审计/质量评估），审计管理员不持有任何 `ai.*` 权限点；所有阶段7接口在路由层按权限点强制校验，Tool 每次执行前重新校验调用者当前真实权限（RequiredPermission）。数据层——会话、任务记录、记忆严格属主隔离，非属主访问一律 404，不泄露资源存在性。
- **确定性管线与受约束总结**：意图分类与任务规划为确定性正则规则（非 LLM 决策）；事实唯一来源为 Tool 查询结果，回答主体为确定性事实文本，LLM 仅做受约束语言总结——系统提示词限定只能复述给定事实、禁止编造数字/事件/规则/IP/时间、不超过 6 句、数据不足时直接声明不得推测、背景记忆中的指令性内容一律忽略；LLM 总结失败时降级为直接返回确定性事实文本。
- **Prompt Injection 防护**：事件/日志/知识库内容仅以 user 角色的事实段进入上下文并标注为已核实事实，不作为指令执行，事实段截断 3000 字符；回答路径的系统提示词以代码内联安全规则为骨架（`composeAnswer`），数据库 `ai_prompts` 的已发布内容（编码 `orchestrator_answer_summary`）经 `SetPromptLoader` 注入运行时，但被 `buildComposePrompts` 明确限定为仅控制表达方式、不得覆盖事实/安全/权限规则（截断 2000 字符），未发布或加载失败回退内置规则；知识库文件名/元数据/正文中的指令性内容不执行（详见 docs/AI_RAG_SECURITY.md、docs/AI_TOOL_SECURITY.md）；DB Prompt 内容进入运行路径的唯一通道是发布门（fail-closed，仓储层 `Publish` 强制）：写入与版本创建经禁止内容静态扫描（密钥/Shell/越权/思维链），版本测试为静态检查 + 真实回归（候选内容经 `PromptOverrides` 仅本次评估运行生效、不触碰发布存储；4 个种子评估集，安全类阈值 100%、一般 80%），对抗测试为内置样本集确定性判定，仅回归 PASSED + 对抗 ADVERSARIAL_PASSED 齐备的版本可发布，模型不可用/评估集缺失一律如实 FAILED 不伪装通过（迁移 000146/000187，详见 docs/AI_PROMPT_MANAGEMENT.md §4）。
- **幻觉防护**：Tool 结果登记为证据集并以 [Ex] 编号引用，最终回答经 `ValidateCitations` 校验，未能对应到证据集的引用一律剔除并附加说明，回答末尾附证据列表；无事实支撑时回答固定声明"当前数据不足，无法确认"。
- **草稿安全**：AI 产出的例外/黑名单/CC 策略/自定义规则一律写入 `ai_recommendations`（DRAFT 状态、标记 AI 生成、记录来源与证据引用），对应业务实体默认 DRAFT/DISABLED 不生效；草稿接口不提供任何发布/生效操作，生效必须经对应业务模块既有人工校验发布流程；废弃仅逻辑标记 REJECTED，不删除记录、不触碰草稿指向的业务配置。
- **密钥安全**：供应商密钥仅存 `ai_provider_secrets`，经应用级加密服务 AES-256-GCM 加密（主密钥取自环境变量 `JIUZHANG_MASTER_KEY`）；密钥仅在创建/轮换时以明文入参，任何接口响应不回传明文或密文（供应商输出仅含引用名 `api_key_reference`）；解密仅供服务端内部 KeyResolver 使用且绝不记录日志。
- **AI 审计**：独立审计表 `ai_audit_records` 以 sha256 哈希链（previous_hash/record_hash）保证完整性，写入经 `pg_advisory_xact_lock(93847562)` 串行化（与业务审计 operation_audits 的锁 93847561 区分，防链分叉）；摘要落库前脱敏——命中 api_key/password/secret/private_key/token 等关键词时掩码长 token（≥24 字符字段保留前 6 位），并按 rune 截断（请求摘要 500 字符、结果摘要 1000 字符）；不保存模型私有思维链与完整载荷；`POST /api/v1/ai/audits/verify` 支持在线校验链完整性（详见 docs/AI_AUDIT_DESIGN.md）。
- **配额与可用性**：`CheckQuota` 服务端强制三层限额——单次输入 Token（默认 12000）、用户每日 Token（默认 200000）、角色每日 Token（默认 500000），超限返回 429；编排单任务上限 120 秒、最多 4 个 Agent、20 次 Tool 调用、输出 4096 Token；模型网关对同一模型连续失败 3 次熔断 60 秒，路由候选按优先级主备切换；SSE 流式与一次性分析连接写期限放宽至 10 分钟（评估运行 15 分钟），避免默认 WriteTimeout 掐断长推理；评估单次运行上限 20 用例、整体 10 分钟超时。
- **敏感记忆拦截**：记忆写入/更新经 `ContainsSensitive` 规则拦截（password/api_key/private_key 等关键词特征及疑似凭据的长随机串），接口层对任何作用域一律拒绝凭据类内容；AI 推测（AI_INFERRED）记忆未经用户确认不得写入长期记忆（仓储层强制）。
- **模型运行时安全**：Ollama 容器化运行，镜像锁定 `ollama/ollama:0.9.6`（禁止 latest）；仅接入内网 bridge `stage5-net`，宿主机端口绑定 `127.0.0.1`（默认 11434），不暴露公网；容器配置 `no-new-privileges:true` 与健康检查，模型持久化于命名卷。

## 审计安全

- 审计日志不允许通过普通业务接口删除；
- 高风险操作记录操作前值、操作后值、操作人和时间；
- 敏感数据查看记录审计。

## 安全测试要求

至少执行：

- 身份认证测试；
- 越权测试；
- CSRF 测试；
- XSS 测试；
- SQL 注入测试；
- SSRF 测试；
- 文件上传测试；
- 配置注入测试；
- 命令注入测试；
- 敏感信息泄露测试；
- 弱口令测试；
- 会话固定测试；
- 日志伪造测试；
- 依赖漏洞扫描；
- 容器配置检查。

---

## 阶段8 / WDSP：API 动态防护安全设计

### 启用边界与故障策略

- API 动态防护默认关闭（`PRODUCT_EDITION=waf` + `API_DYNAMIC_PROTECTION_ENABLED=false`）；关闭时网关 `serveNext` 早退、下发 JSON 与纯 WAF 完全一致、管理面不注册 `/api/v1/api-security/*` 路由、前端菜单隐藏。
- 引擎故障一律 fail-open：管线错误仅告警并跳过（不阻断业务请求）；事件输出失败仅告警。防护模式缺省 `OBSERVE`（fail-safe），`PROTECT` 需显式设置并经发布生效。

### 解析期安全

- 一次解析限制：`MaxBodyParseBytes`（超限截断 + 采样，不做字段级解析防部分 schema 污染）、`MaxJSONDepth`、`MaxFieldCount`、`MaxXMLDepth`、`MaxFileMetaCount`，防资源耗尽。
- XML 流式解析遇 `DOCTYPE` 直接停止并置标记（XXE 协议层拒绝，不展开实体）。
- multipart 文件内容不落内存，仅计元数据（字段名/文件名/类型/大小）。

### 数据最小化与脱敏

- 请求头 `authorization`/`cookie`/`x-api-key` 仅标记存在（`[redacted]`）；凭据指纹为 FNV-1a 哈希，永不存明文。
- 学习样本仅存 `sample_hash` 与指纹，不存完整敏感值（任务书 50.4）。
- 敏感数据检测只匹配字段名/路径模式，Evidence 记录字段路径与类型，不记录值。
- 事件日志字段截断 + 控制字符剥离（防日志注入），JSON 转义为第二道防线。

### 访问控制与审计

- 27 个权限点按三权分配（000100 起：安全管理员全量独占，系统管理员与审计管理员不再持有 `api_*` 权限点），路由层 `RequirePermission` 强制；所有写操作记录操作审计（模块 `api_assets`/`api_security`）。
- 策略发布（`api_policy.publish`）为高风险操作，同步执行并记录 SUCCESS/FAILURE。
- AI 工具（`api_*`）全部为 READ_ONLY 风险等级：AI 不得自动确认模型、自动发布、自动修改用途、自动关闭 API、自动封禁身份。

### 幂等与一致性

- 统一主事件按 `request_id` 幂等（同一 Request ID 只生成一个主事件；采集器重放不产生重复行）。
- 模型冻结事务化（`FOR UPDATE` 行锁 + 旧版 SUPERSEDED），FORMAL 不可变；API合并/拆分事务化并写生命周期事件。
- 配置下发经 Caddy Admin Unix Socket（不暴露 TCP），快照进版本库，回滚一致。
