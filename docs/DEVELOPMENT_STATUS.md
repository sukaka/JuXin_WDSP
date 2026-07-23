# 开发状态

## 当前阶段

**阶段5：IP访问控制、真实客户端IP识别与CC防护** — 已完成
**阶段6：安全态势、统计报表、运行监控与正式交付** — 已完成（遗留项见文末）
**阶段7：AI 智能安全运营中心** — 已完成

## 阶段进度总览

| 阶段 | 内容 | 状态 | 完成时间 |
|------|------|------|---------|
| 阶段0 | 项目初始化 | 已完成 | 2026-07-20 |
| 阶段0.1 | 工程基线修正 | 已完成 | 2026-07-20 |
| 阶段1 | 网关技术验证 | 已完成 | 2026-07-20 |
| 阶段2 | 身份认证、三权权限与系统基础 | 已完成 | 2026-07-21 |
| 阶段3 | Web应用接入、源站、证书与网关配置发布 | 已完成 | 2026-07-21 |
| 阶段4 | WAF策略和事件中心 | 已完成 | 2026-07-21 |
| 阶段5 | IP访问控制、真实客户端IP识别与CC防护 | 已完成 | 2026-07-21 |
| 阶段6 | 安全态势、统计报表、运行监控与正式交付 | 已完成 | 2026-07-22 |
| 阶段7 | AI 安全运营 + 阶段4–6 合并修复 | 已完成 | 2026-07-22 |

## 阶段0完成内容

- 标准仓库目录结构；
- AGENTS.md、README.md、THIRD_PARTY_NOTICES.md、LICENSE、CHANGELOG.md；
- 产品/架构/数据库/接口/安全/部署/测试/合规/状态九份设计文档；
- Docker Compose 基础环境；
- server / gateway Go 空项目（构建与测试通过）；
- web React + TypeScript 空项目（构建、测试、Lint 通过）；
- GitHub Actions CI 配置。

## 阶段0.1完成内容

### 1. 统一 npm 包管理器

- [x] 新增 `.nvmrc` 与 `.node-version`（Node.js 24.13.0）；
- [x] `web/package.json` 声明 `engines.node >=24.0.0 <25.0.0`、`engines.npm >=11.0.0`；
- [x] 确认仓库无 `pnpm-lock.yaml` / `yarn.lock`；
- [x] Makefile、README、CI 全部统一为 npm 命令，CI 使用 `npm ci`；
- [x] CI Node 版本通过 `node-version-file: '.nvmrc'` 与本地一致；
- [x] 验证 `npm ci`、`npm run typecheck`、`npm run lint`、`npm test`、`npm run build` 全部通过。

### 2. Vite 结构检查

- [x] 确认 `web/` 结构完整（index.html、package.json、package-lock.json、tsconfig 三件套、vite.config.ts、src/main.tsx、src/App.tsx、src/vite-env.d.ts、public/）；
- [x] 脚本齐全：dev / build / lint / test（vitest run）/ typecheck / format / preview；
- [x] 存在真实测试用例 `src/App.test.tsx`，未使用 `--passWithNoTests` 掩盖。

### 3. Redis 替换为 Valkey

- [x] Docker Compose：`redis:7.4-alpine` → `valkey/valkey:8.1.8-alpine@sha256:94365b275456ae14621001c03556c732b1d93a0cdeacc317d1bdd52eba680885`；
- [x] PostgreSQL 镜像同样锁定摘要：`postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c`；
- [x] Valkey 配置：密码认证、AOF 持久化、maxmemory 256mb + allkeys-lru、健康检查、命名卷、no-new-privileges；
- [x] `.env.example`：`REDIS_*` → `VALKEY_*`；
- [x] Valkey 8.1.8 BSD-3-Clause 许可证归档至 `licenses/valkey/LICENSE`；
- [x] README / AGENTS.md / ARCHITECTURE / DEPLOYMENT / SECURITY_DESIGN / TEST_PLAN / OPEN_SOURCE_COMPLIANCE / THIRD_PARTY_NOTICES 全部从 Redis 更新为 Valkey；
- [x] 删除 `licenses/redis/`。

### 4. Docker Compose 安全检查

- [x] PostgreSQL / Valkey 仅绑定 127.0.0.1（`docker port` 实测确认）；
- [x] 无写死密码，密码来自 `.env`（`${VAR:?required}` 强制校验）；
- [x] `.env` 已在 `.gitignore` 中；
- [x] 健康检查、重启策略、命名卷、bridge 网络隔离齐全；
- [x] 无 `privileged`、无 Docker Socket 挂载、无 `network_mode: host`；
- [x] 两个服务均配置 `no-new-privileges:true`；
- [x] 镜像全部锁定版本+摘要，无 `latest`。

### 5. 阶段0.1退出条件验证

- [x] `docker compose config` 通过；
- [x] `docker compose up -d` 启动成功；
- [x] `docker compose ps`：postgres healthy、valkey healthy；
- [x] `valkey-cli ping` 返回 PONG，`info server` 显示 valkey_version:8.1.8；
- [x] 后端空项目构建通过（server + gateway）；
- [x] 前端构建通过；
- [x] Git 中无密钥和实际密码（仅 .env.example 占位符）；
- [x] 文档已从 Redis 更新为 Valkey；
- [x] 不存在混用 npm / pnpm / yarn 的命令。

## 阶段1完成内容

详见 [GATEWAY_POC.md](GATEWAY_POC.md)、[GATEWAY_ARCHITECTURE.md](GATEWAY_ARCHITECTURE.md)、
[GATEWAY_SECURITY.md](GATEWAY_SECURITY.md)、[GATEWAY_TEST_REPORT.md](GATEWAY_TEST_REPORT.md)。

- [x] 依赖核查与版本锁定（docs/DEPENDENCIES.md，全部 Apache-2.0，许可证归档 licenses/）
- [x] xcaddy 多阶段构建自定义 Caddy v2.11.4 + coraza-caddy v2.5.0（镜像 21.4MB）
- [x] 独立测试源站（7 类接口，独立镜像，非 root）
- [x] CRS 4.28.0 按官方顺序加载（coraza.conf → crs-setup → before-crs → CRS → after-crs → 九章规则）
- [x] 三种防护模式实测（Off 转发 / DetectionOnly 检测不阻断 / On 403 阻断）
- [x] 正常流量 11 用例、攻击 21 用例（SQLi/XSS/CMDi/路径/扫描器）全部通过
- [x] 协议异常 5 用例（走私特征/超大头/非法方法/类型不匹配/重复TE头）全部通过
- [x] go-ftw CRS 回归 94 用例全部通过（942100/941160/932230）
- [x] 九章阻断页面（Request ID + 时间，无敏感信息，无 XSS 面）
- [x] Request ID 全链路关联（uuid ↔ x-request-id ↔ 审计日志 ↔ 阻断页 ↔ 源站）
- [x] 事件解析器（8 单元测试，脱敏，错误队列不静默丢弃）
- [x] Admin API 仅 Unix Socket（0200 权限，TCP 2019 未暴露实测）
- [x] 配置失败保护（3 类非法配置拒绝且服务无损）
- [x] 配置发布/回滚（版本A/B 切换，哈希一致，无中断）
- [x] 容器安全（非 root/只读根文件系统/cap_drop ALL/no-new-privileges/无 docker socket）
- [x] 构建与测试证据归档（docs/evidence/stage1/）

## 阶段2完成内容

详见 [STAGE2_TEST_REPORT.md](STAGE2_TEST_REPORT.md)、[AUTHENTICATION_DESIGN.md](AUTHENTICATION_DESIGN.md)、
[RBAC_DESIGN.md](RBAC_DESIGN.md)、[AUDIT_DESIGN.md](AUDIT_DESIGN.md)、[server/openapi/openapi.yaml](../server/openapi/openapi.yaml)。

**测试：后端单元 13 + 接口集成 28 + 前端单元 23 + E2E 16 + 安全测试 16 = 96 用例全部通过。**

- [x] 数据库迁移（users/roles/permissions/user_roles/role_permissions/login_sessions/login_logs/operation_audits/system_settings/password_histories，含 up/down）
- [x] 三权内置角色 + 24 项权限 + 角色权限映射种子数据
- [x] Argon2id 密码哈希（独立随机盐）、密码策略（长度/复杂度/历史/弱口令/有效期）
- [x] 初始管理员安全初始化（一次性随机密码 stdout 打印或环境变量注入，首次登录强制改密）
- [x] 图形验证码（自绘 PNG，Valkey 短期 TTL，一次性使用）
- [x] 服务端会话（Valkey，空闲 30 分钟/绝对 8 小时，PostgreSQL 仅存哈希摘要）
- [x] 登录失败锁定（5 次/15 分钟）、统一错误提示防枚举
- [x] CSRF 三重防护（SameSite Cookie + Token + Origin 校验）
- [x] 三权互斥 RBAC（一账号一角色，后端强制校验，最后一个系统管理员保护）
- [x] 用户管理（创建/编辑/启停/解锁/重置密码/删除/强制下线，乐观锁）
- [x] 个人中心（资料/改密/会话管理/登录记录）
- [x] 登录日志（16 类事件，不记录密码/验证码/完整会话）
- [x] 操作审计（风险分级、敏感字段脱敏、哈希链、数据库 RULE 禁改删、verify-chain 校验）
- [x] 系统设置（密码/登录/会话/展示四组，乐观锁，敏感值脱敏，白名单）
- [x] 接口限速（登录/验证码/改密/重置/导出，动态配置热更新）
- [x] 统一 API 规范（响应信封/错误码/Request ID/分页）
- [x] 管理前端（登录页/工作台/用户管理/角色权限/登录日志/操作审计/系统设置/个人中心/错误页，按角色过滤菜单与路由守卫）
- [x] server/web Dockerfile（多阶段、非 root）+ docker-compose.stage2 一键启停
- [x] 关键修复：中间件顺序、INET 扫描（netip.Addr）、IPv6 地址解析、CSRF Origin、动态限速

## 阶段3后端完成内容

详见 [STAGE3_TEST_REPORT.md](STAGE3_TEST_REPORT.md)、[GATEWAY_CONFIG_GENERATION.md](GATEWAY_CONFIG_GENERATION.md)、[CONFIG_PUBLISH_DESIGN.md](CONFIG_PUBLISH_DESIGN.md)。

- [x] 数据库迁移（applications/domains/upstreams/health_records/certificates/app_certs/config_versions/publish_tasks/validation_results）+ 三权权限种子（安全管理员全量/系统管理员只读/审计管理员只读）
- [x] 校验模块（应用编码/域名规范化/泛域名/源站地址/SSRF 地址校验）
- [x] AES-256-GCM 私钥加密（主密钥环境注入）
- [x] 证书解析（X.509/私钥匹配/域名匹配/到期状态/密钥强度）
- [x] 应用/域名/源站/证书 store 与 handler（CRUD/冲突检测/乐观锁/审计）
- [x] 确定性配置生成器（Caddy JSON，三种模式/加权轮询/健康检查/HTTPS 跳转）
- [x] 源站 SSRF 测试器（DNS 校验/防重绑定/协议限制/超时限制）
- [x] 发布控制器（任务状态机/Valkey 分布式锁/Unix Socket/失败保护/自动回滚）
- [x] 配置版本管理与回滚（不可变版本/幂等键/差异）
- [x] 关键修复：admin socket unix 前缀、reverse_proxy 字段（retries/weight）、ListTasks 参数索引、权重 0 掩盖
- [x] stage3 整合编排（postgres/valkey/api/gateway/testorigin 共享 admin socket 卷）
- [x] 真实发布闭环：应用接入→发布→网关转发→WAF 阻断→回滚→幂等→失败保护

## 阶段3前端完成内容

- [x] Web应用列表（/applications）：关键词/状态/防护模式筛选，新建（编码格式前端校验与后端一致）、编辑（乐观锁 version 回传）、复制、启停、删除二次确认
- [x] 应用详情（/applications/:id）：基本信息卡 + 域名/源站/证书三个 Tab
- [x] 域名管理：hostname 前端校验（禁协议/路径/端口、泛域名仅 *. 前缀）、HTTP/HTTPS 端口联动、跳转开关、增删改
- [x] 源站管理：增删改/启停、健康检查与 TLS 参数、连通性测试（DNS/TCP/TLS/HTTP 分阶段展示，SSRF 私网需显式允许）
- [x] 证书绑定 Tab：展示已绑定证书（证书列表 + 绑定关系反查）
- [x] HTTPS证书（/certificates）：列表（剩余天数分级）、PEM 粘贴上传（前端格式校验）、详情抽屉（不含私钥）、删除（使用中禁删）
- [x] 配置发布（/config-publish）：当前版本卡、预览、校验、发布（二次确认 + 幂等键 + 任务进度轮询）、发布任务记录
- [x] 配置版本（/config-versions）：列表、差异对比抽屉、回滚（二次确认 + 任务进度）
- [x] 网关状态（/gateway-status）：在线状态、版本/哈希、应用/域名/源站计数、最后发布结果
- [x] 菜单「应用防护」分组 + 路由守卫，按角色过滤
- [x] 前端单测 33 用例全部通过

## 阶段4后端完成内容

详见 [STAGE4_TEST_REPORT.md](STAGE4_TEST_REPORT.md)、[WAF_POLICY_DESIGN.md](WAF_POLICY_DESIGN.md)。

- [x] 数据库迁移（12 表，security_events 按月分区）+ 三套内置策略模板（relaxed/standard/strict）+ 阶段4权限种子（安全管理员全量/审计管理员只读）
- [x] 防护策略 store/handler（CRUD/复制/绑定应用查询/内置保护/乐观锁/审计）
- [x] CRS 规则元数据同步（622 条入库，SecLang 解析，攻击类型标签映射，内容哈希变更检测）
- [x] 规则覆盖（策略级/应用级启停，优先级 应用 > 策略 > 默认）
- [x] 自定义规则（结构化编辑 → SecLang 生成，操作符/变量/动作白名单，exec/命令替换/文件读取等危险内容拦截，正则预编译，ID 段 7100000+ 控制）
- [x] 例外策略（精确/临时/宽泛受控，宽泛例外强制风险确认，临时例外到期自动失效）
- [x] 安全事件标准化 + 脱敏（Coraza 审计日志解析，攻击类型/评分/动作映射，敏感参数遮蔽）
- [x] 事件采集器（断点续传/文件轮转检测/批量入库/错误队列/后台 goroutine）
- [x] 事件中心（列表/详情/处置/备注/相关事件/CSV 导出/从事件一键建例外草稿）
- [x] 策略发布下发网关（buildSnapshot 注入 900001 PL/阈值指令，启用例外生成 ctl 规则置于 CRS 前，精确例外实测消除误报）
- [x] 关键修复：INET 扫描（netip.Addr）、MatchInfo JSON tag、宽泛例外误判、config 测试补环境变量
- [x] stage3 编排补充：api 只读挂载 CRS 规则目录（元数据同步）

## 阶段4前端完成内容

- [x] 防护策略（/protection-policies）：列表/筛选/新建/编辑（乐观锁）/复制/删除二次确认/绑定应用查询/内置策略保护提示
- [x] WAF规则（/waf-rules）：多条件筛选/详情/手动同步/tags base64 兼容解析
- [x] 自定义规则（/custom-rules）：结构化表单/在线校验/启停
- [x] 例外策略（/exceptions）：精确/临时/宽泛实时风险提示与强制确认
- [x] 安全事件（/security-events）：列表/详情抽屉/处置/备注/相关事件/CSV 导出/一键建例外
- [x] 事件统计（/event-statistics）：今日/未处置/阻断计数 + 攻击类型/动作/处置状态分布
- [x] 菜单「WAF策略」「事件中心」分组 + 路由权限守卫（审计管理员只读可见，系统管理员不可见）
- [x] 前端单测 stage4 工具 12 用例全部通过

## 阶段5完成内容

详见 [STAGE5_TEST_REPORT.md](STAGE5_TEST_REPORT.md)、[JIUZHANG_GUARD_MODULE.md](JIUZHANG_GUARD_MODULE.md)、
[REAL_CLIENT_IP_DESIGN.md](REAL_CLIENT_IP_DESIGN.md)、[TRUSTED_PROXY_DESIGN.md](TRUSTED_PROXY_DESIGN.md)、
[IP_ACCESS_CONTROL_DESIGN.md](IP_ACCESS_CONTROL_DESIGN.md)、[RATE_LIMIT_DESIGN.md](RATE_LIMIT_DESIGN.md)、
[ACCESS_CONTROL_EVENT_DESIGN.md](ACCESS_CONTROL_EVENT_DESIGN.md)。

### jiuzhang_guard 自主 Caddy 模块（独立 go.mod，xcaddy 真实构建加载）

- [x] cidr：IPv4/IPv6/CIDR 解析规范化（映射归一、掩码化），精确 map + CIDR 扫描匹配器
- [x] clientip：真实IP识别（仅可信代理才信代理头；XFF/X-Real-IP/Forwarded/自定义头；链遍历；超长链16；非法回退连接源；伪造检测事件）
- [x] trustedproxy：优先级匹配、头类型绑定（自定义头仅对配置代理生效）
- [x] accesscontrol：全局白→应用白→全局黑→应用黑分层评估，同层显式优先级，时间窗生效
- [x] ratelimit：令牌桶（实时）+ 滑动窗口（封禁判断），内存（有界LRU）与 Valkey（Lua原子）双后端
- [x] temporaryblock：Valkey HASH 存储 + 网关 1s 轮询内存缓存，到期本地失效
- [x] events：JSONL 事件输出（字段截断、控制字符剥离、单行）
- [x] Guard 模块：保护地址永不封禁、白名单绕过黑名单与CC（不绕WAF）、429+Retry-After+X-Jiuzhang-Request-ID、不泄露内部信息、Fail-open/Fail-closed + 告警节流
- [x] 单元测试 41 测试函数 9 包全绿

### 后端（7 个新服务包 + 发布集成）

- [x] 迁移 000008（8 表：trusted_proxies/protected_addresses/ip_access_rules/rate_limit_policies/temporary_blocks/access_control_events(月分区)/access_control_versions/rate_limit_runtime_summaries）+ 000009 权限种子（安全管理员全量/审计只读/系统管理员可信代理+保护地址）
- [x] trustedproxies/protectedaddresses/accessrules/ratelimitpolicies/temporaryblocks/accesscontrolevents/accesscontrolversions 七个包（CRUD/乐观锁/审计/校验）
- [x] 批量导入导出（≤1MB/10000行、行级错误定位、dry_run 预览、ALL_OR_NOTHING/SKIP_ERRORS、公式注入转义）
- [x] 保护地址（系统自动登记 refresh、封禁保护地址 400 + 高风险审计）
- [x] 临时封禁（Valkey 键协议与网关一致、解封/延期/转永久、采集器 upsert）
- [x] guardconfig 组装器 + 发布器集成（guard 配置注入、access_control_versions 快照、失败保护、历史版本回滚重发布）
- [x] 访问控制事件采集器（断点续传、轮转检测、封禁/命中联动、运行汇总）
- [x] 关键修复：采集器 checkpoint 改可写数据目录（曾误放只读卷导致全量重放）、api 镜像 /app/runtime 属主、空列表 items 归一
- [x] 集成测试 16 例（含到期标记调度、证书绑定独立接口）+ 修复既有 TestRateLimitLogin 框架缺陷（captcha 限速容错）
- [x] 收尾增强：`GUARD_FAIL_OPEN` 故障策略可配（随发布下发逐实例生效，Fail-closed 真实验证 5 用例）；
  guardjanitor 到期自动失效调度（临时规则/封禁标记 EXPIRED + 系统审计）；
  证书绑定/解绑独立接口（阶段3遗留补齐，POST /certificates/{id}/bind|unbind）

### 前端（5 页面 + 菜单「访问控制」）

- [x] 可信代理（含保护地址 Tab、命中测试）/ IP黑白名单（导入预览行级错误、导出、发布进度）/ CC防护（分步表单、干跑模拟、发布）/ 临时封禁（解封/延期/转永久）/ 访问控制事件（筛选/详情/导出）
- [x] 菜单「访问控制」分组 + 路由权限守卫（系统管理员仅可信代理，审计管理员只读）
- [x] stage5 工具元数据与校验 14 单测

## 阶段6完成内容（进行中）

详见 [SECURITY_DASHBOARD_DESIGN.md](SECURITY_DASHBOARD_DESIGN.md)、[METRICS_DATA_DICTIONARY.md](METRICS_DATA_DICTIONARY.md)、
[REPORTING_DESIGN.md](REPORTING_DESIGN.md)、[MONITORING_ALERTING_DESIGN.md](MONITORING_ALERTING_DESIGN.md)、
[BACKUP_RESTORE_DESIGN.md](BACKUP_RESTORE_DESIGN.md)、[UPGRADE_ROLLBACK_DESIGN.md](UPGRADE_ROLLBACK_DESIGN.md)、
[DISASTER_RECOVERY_GUIDE.md](DISASTER_RECOVERY_GUIDE.md)、[INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md)、
[OFFLINE_DEPLOYMENT_GUIDE.md](OFFLINE_DEPLOYMENT_GUIDE.md)、[OPERATIONS_MANUAL.md](OPERATIONS_MANUAL.md)。

- [x] 统一指标模型与三级聚合（分钟/小时/天，幂等 upsert + 迟到修正，访问日志断点续传采集）
- [x] 安全态势首页（总览卡片/趋势/排行/风险提示，三权视图）与统计分析 11 接口
- [x] 报告系统（日报/周报/月报/自定义，21 章节，确定性结论规则，HTML + PDF(gofpdf+内嵌中文字体)，异步 worker，哈希/权限/审计）
- [x] 运行监控（10 类组件快照）与系统告警（18 类，合并/冷却/抖动抑制/上限保护/自动恢复/确认处置）
- [x] 备份（.jzbk 自定义格式，分块 AES-256-GCM，尾部清单，五级验证，保留策略）与恢复（隔离 schema 预览→确认→维护模式正式恢复）+ 备份文件导入（全新环境恢复入口）
- [x] 升级包登记/预检（9 项）/执行（强制升级前备份/迁移 up-down 成对校验）/失败自动回滚
- [x] 交付检查（22 项，关键 FAIL 阻止交付）与离线部署包（镜像+清单+SBOM+安装向导）
- [x] 前端 11 页面（安全态势/统计分析/系统告警/报告任务/模板/归档/运行监控/存储/备份恢复/系统升级/交付检查，三权菜单）
- [x] SBOM（SPDX+CycloneDX，557 组件）与许可证审计、ops 运维脚本 9 个
- [x] 关键修复：审计哈希链时间精度截断（纳秒/微秒失配）与并发分叉（advisory lock）、restore_jobs.status 列宽、采集滞后语义（积压驱动）、报告模板 sections 默认、恢复建表保留默认值、空列表归一

## 测试

**阶段3新增：后端单元 28 + 接口集成 9 + 前端 33 + E2E 1 + 真实网关验证 6 = 77 用例全部通过（阶段2回归 41 用例同步通过）。**

**阶段4新增：后端单元 32 + 接口集成 10 + 前端 45 + E2E 5 + 真实WAF 22 + 安全 14 = 128 用例全部通过（阶段3 E2E 回归冒烟 8 用例同步通过）。**

**阶段5新增：guard 模块单测 41 + 后端单元 283 + 接口集成 16 + 前端 59 + 真实网关 40 + 安全 25 + Fail-closed 5 + 性能 9 + E2E 6 = 484 用例全部通过（阶段4 E2E 回归 5 用例同步通过）。**

**阶段6：接口集成 9 + 前端 81 + E2E 6 + 冒烟 26/27 + 安全 18/18 + 性能容量 10/10 + 全新环境恢复 18/18 + 离线安装验证通过 + 升级回滚实测通过。详见 [STAGE6_TEST_REPORT.md](STAGE6_TEST_REPORT.md)。**

## 阶段4–7 合并修复（2026-07-22）

详见 [STAGE_4_7_REMEDIATION_PLAN.md](tasks/STAGE_4_7_REMEDIATION_PLAN.md)。

- [x] M-01 访问控制版本快照/API 脱敏 Valkey 密码，回滚时注入运行时密钥
- [x] M-02 防护策略绑定/解绑 API + 前端详情绑定
- [x] M-03 启用自定义规则写入发布生成的 WAF directives
- [x] M-04 保护地址仅按客户端 IP 早放行（不再用 ConnectionIP 旁路）
- [x] M-05 TEMP_BLOCK：Valkey Put 失败保留 localOnly，Refresh 不冲掉；人工解封仍以远程为准
- [x] M-06/M-07 共享 engine 去掉错误 Once 半初始化，配置指纹变化可重建
- [x] M-09 临时例外纳入 guardjanitor 到期调度
- [x] M-10 发布加载例外失败则任务失败
- [x] M-11 429 Content-Type 在 WriteHeader 之前设置
- [x] M-12 生产默认 GUARD_FAIL_OPEN=false
- [x] M-14 全局 CC TEMP_BLOCK 使用空 AppID
- [x] M-15 维护模式中间件拦截写操作
- [x] M-16 报告僵尸任务 WORKER_LOST 回收
- [x] M-17 访问控制版本前端页面
- [x] M-18 事件统计标明样本占比
- [x] M-19 版本 List 仅元数据
- [x] M-20 人工临时封禁优先于白名单；自动封禁仍可被白名单绕过
- [x] M-21 令牌桶拒绝时 current_count 不为 0
- [x] M-08 rule_overrides 完整 CRUD + 发布 DISABLE 注入（优先级 应用>策略>全局）
- [x] M-22 例外策略 PUT 更新（乐观锁 version）
- [x] M-23 AI draft 全量 ValidateInput / Store.Create 对齐（created_by 取自 Principal）
- [x] M-24 CC 到期/解封事件（CC_TEMP_BLOCK_EXPIRED / RELEASED）

## 阶段7完成内容

详见 [STAGE7_TEST_REPORT.md](STAGE7_TEST_REPORT.md)、[AI_SECURITY_TEST_GUIDE.md](AI_SECURITY_TEST_GUIDE.md) 及 `docs/AI_*.md`。

- [x] 模型网关（供应商/密钥加密/路由档位/健康测试/流式）
- [x] Orchestrator（意图、计划摘要、多 Agent、证据、压缩、配额）
- [x] 受控 Tool 体系（事件/日志/资产/统计/草稿；执行前权限重检）
- [x] Chat SSE + 停止/重试/继续/反馈
- [x] 一次性分析：事件/误报/画像/攻击链/策略/What-If/根因/报告
- [x] 草稿与推荐 accept/reject；HTTP 草稿创建入口
- [x] Prompt 版本/测试/发布/回滚/Diff；Memory；AI 审计哈希链
- [x] 用量 overview/by-user/by-agent/by-task；评估集 API + 管理 UI
- [x] AI 模块 `AI_ENABLED` 独立启停；事件详情一键 AI
- [x] 前端：助手/分析/画像/链/策略/报告/任务 + 管理面 + 质量评估页

## 遗留问题

1. 开发环境管理面使用 HTTP，生产必须启用 HTTPS 且 `COOKIE_SECURE=true`（配置已强制 prod 校验）；
2. 审计哈希链为基础防篡改（数据库 RULE 禁改删 + 哈希链），未含可信时间戳/外部存证（后续可选）；
3. 前端 antd 全量引入单 chunk 较大（阶段6已做 ECharts 按需引入，antd 分割后续优化）；
4. 源站主动健康检查由 Caddy reverse_proxy health_checks 承担，独立健康检查调度与历史展示在后续增强；
5. 发布验证为基础检查（Caddy admin 可用 + 配置加载），源站级发布后健康验证在后续增强；
6. macOS 开发环境后端需容器化访问网关 socket（bind mount 不支持 unix socket），生产 Linux 部署通过共享卷正常；
7. 阶段4 `policy_versions` 表与 `policy_versions.read` 权限已预留，策略版本快照/差异/回滚的 store 与路由在后续补充（当前策略下发走配置发布闭环，回滚由配置版本承担）；
8. 开发库早期 693 条审计记录因阶段6修复前的哈希链时间精度缺陷失配（根因已修复，新记录链完整；全新环境部署链自始完整）；
9. 72 小时连续稳定性未在会话内完成（墙钟限制）：已交付 `make stage6-test-stability`（HOURS 可配）浸泡框架并通过短浸泡 5 项检查，正式交付前建议 HOURS=72 执行一次并归档结果；
10. 审计归档按设计不恢复写回（仅保存于备份文件）；如需恢复审计数据需专门流程；
11. 多节点分布式 CC 全局一致性按任务书暂不开发（当前单节点 Valkey 共享计数已支持横向扩展）；
12. 规则覆盖 SEVERITY_OVERRIDE/ACTION_OVERRIDE 可入库，发布侧当前仅落实 DISABLE/ENABLE 优先级解析；
13. AI 知识库为规则元数据检索（完整 embedding RAG 可后续增强）；What-If 非全量离线回放引擎。

## 下一步

### WDSP / 阶段8（统一 Web 与 API 动态防护）

- 分支：`develop` + `feature/stage8-*`（见 [BRANCHING_AND_PRODUCT_LINES.md](BRANCHING_AND_PRODUCT_LINES.md)）
- 开工说明：[STAGE_8_WDSP_KICKOFF.md](tasks/STAGE_8_WDSP_KICKOFF.md)
- 任务书：[STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md](tasks/STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md)
- 核查基线：[STAGE8_IMPLEMENTATION_REVIEW.md](STAGE8_IMPLEMENTATION_REVIEW.md)（2026-07-22，其 §7.1 第 1–3 项已全部落地）
- **已交付**：
  - 统一引擎挂接 `jiuzhang_guard` 请求链（`serveNext` 唯一挂点；一次解析→分类→归一→检测→统一决策；`api_dynamic_protection=false` 时零行为变化，下发 JSON 与纯 WAF 一致）
  - 一次解析多协议：JSON / form / XML（流式、DOCTYPE 拒绝）/ multipart（文件不落内存）/ GraphQL；解析限制真实生效
  - 检测器：schema 偏离、身份信号、认证有效性、敏感数据（Query 明文升 BLOCK）、BOLA 辅助、生命周期（已知端点基线随发布下发）、行为滑窗、API 限速
  - 统一事件流：网关 `api-runtime-events.log` → 采集器（断点续传/轮转/错误文件）→ `api_runtime_events`（request_id 幂等）；端点发现由流量自动驱动
  - 数据库 27 表（`000016`-`000018`）+ 27 权限点（`000019`，三权分配与既有口径一致）
  - 接口：`/api/v1/api-security/*` 43 条（端点/学习/模型生命周期/参数/分类/图谱/规范/风险/运行时/策略），全量权限校验 + 操作审计，openapi.yaml 收录
  - 模型生命周期：CANDIDATE→IN_REVIEW→FORMAL/REJECTED/SUPERSEDED/ARCHIVED，版本号自增、diff、activate、FORMAL 不可变；冻结模型经发布通道下发网关
  - 策略接口：模式 OFF/OBSERVE/PROTECT（settings 表覆盖优先于 env）+ 同步发布到网关
  - AI 工具（48 章）：10 个 `api_*` 工具全部 READ_ONLY（AI 不得确认/发布/修改），仅 WDSP 形态注册并同步 `ai_tools` 表
  - 前端：12 个阶段8 页面（端点/模型/学习中心/参数/分类/敏感数据/规范/图谱/拓扑/风险/影子僵尸/策略），产品形态 + 权限双层门控，全部符合前端风格指南
  - 测试：`make stage8-test-*` 全量命令；接口集成 9/9、全链路 15/15、回放 10/10、安全 11/11、性能 5/5、纯 WAF 回归 40/40，详见 [STAGE8_TEST_REPORT.md](STAGE8_TEST_REPORT.md)
- **诚实遗留（任务书超集部分）**：
  - 学习自动化：样本达阈值自动生成候选模型未实现（候选靠手工/接口创建）；参数统计画像（字符串/数值/条件关系）仅有表结构
  - 响应侧解析与 MASK_RESPONSE 未实现（响应字段存在但无写入点）
  - 行为基线为单节点进程内滑窗（多节点共享需 Valkey 化）；图谱调用边仅 caller→target 形态；BOLA/BFLA 为辅助信号而非全量规则库
  - Coraza 命中未同步进 RequestContext（经 request_id 在管理面关联；coraza-caddy 为第三方模块，不 fork）
  - 网关→管理面方向仍为单向日志采集（与既有架构一致）；WAF 纯形态回归以 stage5 既有测试套件为准

### 其他

阶段7 收尾优先合 `main` 再同步 `develop`；可选增强：完整 RAG、策略版本快照、多租户 AI 计费、更深度的 What-If 回放与压测归档。
