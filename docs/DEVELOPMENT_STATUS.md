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
- [x] 管理面无 `privileged`、无 Docker Socket 挂载、无 `network_mode: host`；生产离线包
      网关为业务端口直绑例外使用 host 网络，并限制为 `CAP_NET_BIND_SERVICE`；
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

## 阶段6完成内容

详见 [SECURITY_DASHBOARD_DESIGN.md](SECURITY_DASHBOARD_DESIGN.md)、[METRICS_DATA_DICTIONARY.md](METRICS_DATA_DICTIONARY.md)、
[REPORTING_DESIGN.md](REPORTING_DESIGN.md)、[MONITORING_ALERTING_DESIGN.md](MONITORING_ALERTING_DESIGN.md)、
[BACKUP_RESTORE_DESIGN.md](BACKUP_RESTORE_DESIGN.md)、[UPGRADE_ROLLBACK_DESIGN.md](UPGRADE_ROLLBACK_DESIGN.md)、
[DISASTER_RECOVERY_GUIDE.md](DISASTER_RECOVERY_GUIDE.md)、[INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md)、
[OFFLINE_DEPLOYMENT_GUIDE.md](OFFLINE_DEPLOYMENT_GUIDE.md)、[OPERATIONS_MANUAL.md](OPERATIONS_MANUAL.md)。

- [x] 统一指标模型与三级聚合（分钟/小时/天，幂等 upsert + 迟到修正，访问日志断点续传采集）
- [x] 安全态势首页（总览卡片/趋势/排行/风险提示，三权视图）与统计分析 11 接口
- [x] 报告系统（日报/周报/月报/自定义，21 章节，确定性结论规则，HTML + PDF(gofpdf+内嵌中文字体)，异步 worker，哈希/权限/审计）
- [x] 报告导出增强（2026-08-27）：新增 Word（docx）格式（godocx，主报告与 API 域报告全覆盖）；报告内嵌图表（go-charts 服务端渲染，HTML 内联 SVG / PDF 与 Word 嵌入 PNG：流量与攻击趋势折线、攻击类型与严重度饼图、源IP/应用 TOP 条形；图表标签消毒防 SVG 注入；字体缺失自动降级为无图表、解析失败归 FONT_UNAVAILABLE）
- [x] 报告内容丰富化与定时化（2026-08-29）：26+11 节（上篇 Web 26 节 + 下篇 API 动态防护 11 节，含环比/攻击时段/源地区 GeoIP/被攻击路径/高危事件明细）；内容范围 WAF/API/WAF_API 独立可选（报告类型固定 日/周/月/自定义，迁移 000082）；英文全面中文化、关注项红色高亮、图表大字纯黑、PDF 双描伪加粗；定时报告计划（迁移 000083，每天/每周/每月 UTC 固定时刻，FOR UPDATE SKIP LOCKED 认领防重）+ 生成后邮件发送（复用通知渠道 SMTP，notify.SendMail 附件邮件，失败只记录不回滚）
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
- [x] M-26 可信代理链全 trusted 时回落连接源 IP（复用 TRUSTED_PROXY_INVALID 事件，action=CONNECTION_FALLBACK）；CSRF Origin 默认端口归一化（https→443/http→80）（2026-09-10）

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

### AI 自动降噪（阶段7 增量，WAF + WDSP）

详见 [AI_NOISE_REDUCTION_DESIGN.md](AI_NOISE_REDUCTION_DESIGN.md)。

- [x] 确定性指纹聚类（sha256(source|host|normalized_uri|rule_id或detector_code|client_ip)；URI 归一化 数字→{n}、UUID→{uuid}、≥16位hex→{h}）：`server/internal/ainoise/`（fingerprint/source/store/mem_store/verdict/recommend/worker）
- [x] 后台 worker（照搬 guardjanitor 模式：ticker + `SweepOnce` 可测；设置存 `system_settings` 组 `ai_noise`，每 tick 热读；仅 `cfg.AI.Enabled` 时启动，`StartStage6Workers` 中 `go Run`）
- [x] 双事件源：WAF 读 `security_events`（窗口内 UNPROCESSED/ANALYZING）；WDSP（`APIDynamicProtectionEnabled()`）追加 `api_runtime_events`
- [x] 可选 LLM 误报评分（standard 档、JSON 输出；失败降级 UNKNOWN 不致命；`llm_verdict_enabled` 默认 false 零 LLM 成本）
- [x] DRAFT 降噪推荐（`ai_recommendations` 类型 NOISE_REDUCTION，同簇 DRAFT/PENDING_REVIEW 去重；不自动改事件处置、不自动封禁、不自动启用例外）
- [x] 幂等 upsert（关联表 ON CONFLICT，窗口重叠重复扫描不重复计数）
- [x] 接口 9 个API `/api/v1/ai/noise/*`（簇/统计/扫描历史/状态流转/设置；权限 `ai.noise_reduction.use` / `ai.noise_reduction.manage`；写操作落 ai_audit_records）：`server/internal/aihandlers/noise_handler.go`
- [x] AI Tool 2 个（`noise_cluster.search` / `noise_cluster.get`，全部 READ_ONLY）：`server/internal/aitools/noise_tools.go`
- [x] 迁移 `server/migrations/000021_ai_noise_reduction.up.sql`（3 张表 ai_noise_clusters / ai_noise_cluster_events / ai_noise_sweep_runs + 2 个权限点种子）
- [x] 前端：自动降噪页 `web/src/pages/ai/noise-reduction/NoiseReductionPage.tsx`、`aiNoiseApi`（`web/src/api/ai.ts`）、路由 `/ai/noise-reduction`、菜单「智能安全运营→自动降噪」、事件详情抽屉「查看降噪簇」入口
- [x] 测试：ainoise 5 个测试文件（fingerprint/store/worker/verdict/recommend）、aitools/noise_tools_test.go、aihandlers/noise_handler_test.go、前端 NoiseReductionPage.test.tsx + api/__tests__/ai-noise.test.ts
- 遗留：迁移 000021 未在真实 PostgreSQL 实例执行过（仅经单元测试验证）；设置以字符串形式存 `system_settings`；API 源无处置状态过滤（`api_runtime_events` 无该列）

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
14. AI 自动降噪迁移 000021 未在真实 PostgreSQL 实例执行过（建表与权限种子仅经单元测试验证，首次部署需观察迁移执行结果）；降噪设置以字符串形式存 `system_settings`（组 `ai_noise`）。

## 下一步

### WDSP / 阶段8（统一 Web 与 API 动态防护）

- 分支：`develop` + `feature/stage8-*`（见 [BRANCHING_AND_PRODUCT_LINES.md](BRANCHING_AND_PRODUCT_LINES.md)）
- 开工说明：[STAGE_8_WDSP_KICKOFF.md](tasks/STAGE_8_WDSP_KICKOFF.md)
- 任务书：[STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md](tasks/STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md)
- 核查基线：[STAGE8_IMPLEMENTATION_REVIEW.md](STAGE8_IMPLEMENTATION_REVIEW.md)（2026-07-22，其 §7.1 第 1–3 项已全部落地）
- **已交付**：
  - 统一引擎挂接 `jiuzhang_guard` 请求链（`serveNext` 唯一挂点；一次解析→分类→归一→检测→统一决策；`api_dynamic_protection=false` 时零行为变化，下发 JSON 与纯 WAF 一致）
  - 一次解析多协议：JSON / form / XML（流式、DOCTYPE 拒绝）/ multipart（文件不落内存）/ GraphQL；解析限制真实生效
  - 检测器：schema 偏离、身份信号、认证有效性、敏感数据（Query 明文升 BLOCK）、BOLA 辅助、生命周期（已知API基线随发布下发）、行为滑窗、API 限速
  - 统一事件流：网关 `api-runtime-events.log` → 采集器（断点续传/轮转/错误文件）→ `api_runtime_events`（request_id 幂等）；API发现由流量自动驱动
  - 站点资产自动发现（2026-08-22，迁移 000077）：mirrorcap 全端口被动嗅探（HTTP Host + TLS ClientHello SNI）学习站点域名/IP/端口，覆盖 MIRROR/ROUTED/TRANSPARENT 三模式（按接口 role 经 sidecar 下发发现接口与来源模式，发现与检测独立启停、共享抓包句柄）；`site-discovery.jsonl` → sitediscovery 采集器断点续传 → `site_asset_discoveries`（domain+ip+port 幂等 upsert，人工处置字段不被采集覆盖）；管理端 `/api/v1/site-discoveries` 列表 + 确认/忽略/恢复（权限 `site_discovery.read/manage`，仅 SECURITY_ADMIN，写操作记审计）；前端「站点发现」页（应用防护组，确认后引导手动接入应用）；部署接线 `WAF_SITE_DISCOVERY_LOG`（deployment/docker-compose.stage5.yml、.env.example）；设计见 [SITE_DISCOVERY_DESIGN.md](SITE_DISCOVERY_DESIGN.md)
  - 协议识别补全（2026-08-29）：`protocol_type` 词表由 REST/GRPC 扩为五值 REST/GRPC/GRAPHQL/SOAP/WEBSOCKET；网关 `classifier/protocol.go` 三检测器（GraphQL=application/graphql 或 /graphql+JSON query 字段（解析层双重确认）；SOAP=application/soap+xml 或 text/xml|application/xml+SOAPAction 头；WebSocket=Upgrade: websocket+Connection 含 upgrade 令牌，仅标注握手）经管线 `api.protocol` 扩展打标（GRPC→WS→GraphQL→SOAP 互斥优先级），事件→采集→发现链路既有透传零改动；模型编译 GRAPHQL→application/json（`apimodels/compiler.go`）；前端协议列 `API_PROTOCOL_META` 标签展示；遗留：GraphQL 不按 operationName 拆API、WS 帧内容检测不做
  - 数据库 28 表（`000016` 三表 + `000018` 二十五表，2026-08-30 按迁移实数核实）+ 27 权限点（`000019`，三权分配与既有口径一致）
  - 接口：`/api/v1/api-security/*`（API/学习/模型生命周期/参数/分类/图谱/规范/风险/运行时/策略），全量权限校验 + 操作审计；openapi.yaml 收录 api-security 前缀 40 个路径 / 45 个 operation（2026-08-30 按 server/openapi/openapi.yaml 实数核实；全量 504 路由对账见第十七批条目）
  - 模型生命周期：CANDIDATE→IN_REVIEW→FORMAL/REJECTED/SUPERSEDED/ARCHIVED，版本号自增、diff、activate、FORMAL 不可变；冻结模型经发布通道下发网关
  - 策略接口：模式 OFF/OBSERVE/PROTECT（settings 表覆盖优先于 env）+ 同步发布到网关
  - AI 工具（48 章）：10 个 `api_*` 工具全部 READ_ONLY（AI 不得确认/发布/修改），仅 WDSP 形态注册并同步 `ai_tools` 表
  - 前端：30 个 api-* 页面（API/模型/学习中心/参数/分类/敏感数据/规范/图谱/拓扑/风险/影子僵尸/策略等，2026-08-30 按 web/src/pages/api-* 目录实数核实），产品形态 + 权限双层门控，全部符合前端风格指南
  - 学习自动化闭环（P0-1，迁移 000027）：启动学习可设样本目标（缺省 100，[10,100000]）；采集器按学习任务落样（§25 可得子集过滤 + `(endpoint, request_id)` 幂等 + 计数同事务回填 + 来源占比上限 `source_ratio_cap`）；`learningjobs` 周期判定（默认 30s，`system_settings/api_learning.sweep_interval_seconds` 可调）达阈值任务 → COMPLETED + API LEARNED + 生命周期事件 + 自动生成空 Schema 候选（`created_reason=learning_threshold`）+ 操作审计；确认与冻结仍为人工
  - 身份微模型第一批（2026-08，迁移 000029）：统一指纹 `detectors.Fingerprint`（HMAC-SHA256 截断 16 字节 hex，盐取自 `identity_salt` 配置，缺盐走固定域分隔前缀并启动 Warn）；`CredentialKey`（仅凭据派生 auth:/key:/sess:，匿名为空串）与 `TrackingKey`（无凭据回退 ip:，仅供滑窗计数）分离；新增 `identity.cookie_present` 信号与 `cookie_session` 认证类型；`api_runtime_events` 落库 `identity_fingerprint`/`auth_type`（部分索引），运行时事件列表响应携带两字段并支持 `identity_fingerprint` 精确过滤
  - 三微模型第二/三批（2026-08，迁移 000029/000030）：参数画像生产线（learningjobs 每轮 Sweep 后 `RefreshParameterStatistics` UPSERT `api_parameter_statistics`，observed/recommended 按样本量分级自动生成、enum 护栏）与行为画像生产线（aggregations 小时级 UPSERT `api_behavior_profiles` 含 `hour_dist` 时段分布，`GET behavior-profiles` 只读）；访问环境异常检测（envanomaly.go：同凭据跨 IP / 同凭据并发 OBSERVE 信号，阈值可配）；对象标识扩展（多对象段逐段评估 + Query 参数值形态识别）；滑窗/游标 Valkey 可插拔存储（detectors/store.go 接口 + jiuzhang_guard/behaviorstore，Lua 原子计数、Fail-open 降级，`behavior_store` 默认 memory）；模型成熟度状态机（`GET model-maturity` 四模型 LEARNING→CANDIDATE→CONFIRMED→ENFORCING + 管理面页面 /api-model-maturity）
  - 三微模型增强批（2026-08，迁移 000031）：参数值脱敏观测通路（网关 `param_observations` → `api_parameter_value_obs` → statistics 回填长度/值域/基数 + semantic_type 推断 + CO_OCCURS 关系候选 + 批量确认）；身份画像生产线（`RunIdentityProfiles` → `api_identity_profiles` + `GET identity-profiles` 质量分 + 管理面 `/api-identity-profiles`）；JWT 结构级 OBSERVE；环境异常扩展（非常规小时 / UA 族突变 / 多信号叠加）；BODY 对象标识经 semantic_type 联动
  - 测试：`make stage8-test-*` 全量命令；接口集成 9/9、全链路 15/15、回放 10/10、安全 11/11、性能 5/5、纯 WAF 回归 40/40，详见 [STAGE8_TEST_REPORT.md](STAGE8_TEST_REPORT.md)。口径注记（2026-08-30 核实）：STAGE8_TEST_REPORT 原文为 2026-07-23 快照，「接口集成 9/9」为当时口径，当前 server/tests 下 TestStage8* 函数实数 103 个；「纯 WAF 回归 40/40」对应 test/waf/scripts/stage5-gateway-tests.sh 全部 42 个断言点中 40 个恒执行项全过（其余 2 个为仅发布失败时记录的条件分支，当次未触发不计入 TOTAL）
  - API 安全补全第一批（2026-08-16 第一波 + 2026-08-17 第二波，迁移 000035-000042；现状盘点口径见 [API_SECURITY_CURRENT_STATE.md](API_SECURITY_CURRENT_STATE.md)）：
    - 学习闭环加深（P0-01/02，迁移 000038）：学习达标多条件判定（`learningjobs/conditions.go`：min_valid_samples/min_unique_ips/min_unique_identities/min|max_learning_duration/minimum_success_ratio，`system_settings` 组 `api_learning` 可调，默认值不改变既有"仅 sample_target"行为）；达标自动候选改为**非空 Schema**（`apimodels/candidate_builder.go`：以API级脱敏观测为权威源推断 string/number/bool 类型、出现率 ≥95% 判 required、长度/值域随 observed_constraints 落库；无观测回退空 Schema）并**自动提交 IN_REVIEW**；超期未达标任务置 FAILED + last_error；QUERY/PATH 参数行 Confirm 时按观测物化（孤儿观测断链修复，HEADER/COOKIE 两侧无数据源暂不物化）
    - Runtime Model Compiler（P0-03/21，迁移 000037）：Confirm 事务内编译 FORMAL 版本为API级运行时策略（`CompiledEndpointPolicy`，compiler_version=v1，content_hash=规范序列化 sha256，runtime_version API内自增 vN）；状态机 DRAFT→（Activate）VALIDATED→（整站发布成功回写）ACTIVE，同API旧 ACTIVE→ROLLED_BACK，发布失败→FAILED；回滚接口克隆上一已知良好版本为新 DRAFT 重发布；`GET runtime-policies` 列表、`GET models/{id}/runtime` 溯源、`POST runtime-policies/{id}/rollback` 回滚
    - 响应侧（P0-05/07）：`ResponseContext` + 统一引擎响应相位 `ProcessResponse`（JSON 解析/响应敏感字段检测/错误签名/transform plan）+ Response Transformer（MASK/HASH/REMOVE 字段级脱敏、重编码、Content-Length 修正、ETag/Content-MD5 失效）；决策引擎 MASK_RESPONSE 分支（计划非空且 PROTECT）；`api_mask_rules` 随发布下发；失败策略 `api_response_fail_policy`（FAIL_OPEN 默认，FAIL_CLOSED 抑制为 500 空明细）；捕获上限 `api_response_capture_max_bytes`（默认 1MiB，硬上限 16MiB）；流式/SSE/非 identity 编码直通不缓冲
    - 事件审计列与响应后输出（P0-20，迁移 000035）：`api_runtime_events` 新增 client_ip/method/raw_path/latency_ms/model_version/policy_version（可空；旧版网关缺字段落 NULL，不伪造 0 值）；API 放行流量事件改为响应完成后输出（真实 response_status + latency_ms + 响应侧明细）
    - Findings 生产化（P0-13/P0-11，迁移 000036）：采集器按物化规则 v1（severity≥MEDIUM 或 final_action 非 ALLOW）把检测明细 upsert 进 `api_runtime_findings`（dedup_fingerprint 幂等，命中 count+1 不覆盖首次证据；证据白名单脱敏，主体只落指纹）；Shadow/Zombie 页与风险列表自此有真实数据源
    - 弱点中心（P0-13，迁移 000039）：`api_weaknesses` + `api_weakness_actions`（只增不改）；状态机 NEW→CONFIRMED→TO_FIX→FIXED→（RETEST_PASS→ARCHIVED / RETEST_FAIL→REPRODUCED）+ IGNORE/ARCHIVE；Sweeper 四规则派生（未认证敏感接口/已下线仍调用/敏感数据在查询串/Schema 漂移持续，5 分钟周期）；FIXED 再命中自动回 REPRODUCED；8 条处置接口全量权限校验 + 操作审计
    - 敏感数据管理面（P0-19，迁移 000040）：`api_sensitive_data_types`（五级分级 + 7 内置类型种子，is_builtin 禁删且名称不可改）+ `api_masking_rules`（GLOBAL<APPLICATION<ENDPOINT 优先级合并与排除求值，`MaskPlanForEndpoint` 纯函数）+ `api_sensitive_fields` SweepOnce 写入方（水位幂等，detection_source=RUNTIME）+ 敏感态势 overview
    - 发布通道扩展（P0-03/04/18/21）：`gateway_runtime` 组六键（behavior_store/identity_salt/behavior_store_ttl_seconds/credential_ip_spread_limit/credential_concurrency_limit/api_write_rate_per_minute）+ api_formal_model_versions + api_mask_rules + api_policy_version（发布内容哈希）随整站发布下发；读取失败或取值非法中止发布（脱敏规则段缺失容忍 Warn 跳过）
    - 权限（迁移 000041）：api_weakness.read/handle、api_data.read/manage 四权限点，三权口径与 000019 一致（SECURITY_ADMIN 全量、AUDIT_ADMIN 只读、SYSTEM_ADMIN 仅弱点只读）
    - 风险处置接口（P0-13，迁移 000042）：`api_runtime_findings` status 词表由注释约定四态升级为七态 CHECK 约束（NEW/CONFIRMED/IN_PROGRESS/FALSE_POSITIVE/IGNORED/RESOLVED/ARCHIVED，存量 OPEN→NEW、ACKNOWLEDGED→IN_PROGRESS，列默认值同步）；`api_risk.read`/`api_risk.handle` 权限点（SECURITY_ADMIN 全量、AUDIT_ADMIN 只读、SYSTEM_ADMIN 不授权——风险主体含身份/来源指纹）；8 条处置接口（summary/detail/confirm/start/resolve/false-positive/ignore/archive）：迁移表即代码事实（非法迁移 400）、行锁事务内状态机校验、处置记录 JSONB 浅合并进 `detail.handling`（保留首次命中上下文）、逐次操作审计；降噪聚合主体/API/类型三视图；关联请求为"同API（同身份）近期请求"近似关联（dedup 只留首次 request_id，如实标注非精确回放）；前端 findings/weaknesses 操作界面随第二波前端分片接通。（原两处待对齐——sweep.go 旧词表取数与测试种子——已在第三波收口，见下块）
  - API 安全补全第二/三批（2026-08-17/18，迁移 000042-000046/000048；000047 空缺为并发改号所致）：
    - 风险处置接口与七态状态机（P0-13，迁移 000042）：八接口 + 七态 CHECK + `api_risk` 权限 + 降噪三视图，已随上块末项记述；本批收口其两处待对齐——`apiweakness/sweep.go` SchemaDriftPersistent 已按七态词表（NEW/CONFIRMED/IN_PROGRESS）取数、测试种子同步，docs/API_RISK_WEAKNESS.md 集成注意解除
    - Coraza 合流（P0-08，G2 落地）：不 fork coraza-caddy 的折中——`jiuzhang_guard/apicoraza.go` 以下游返回错误中 coraza-caddy v2.5.0 的未导出哨兵（"interruption triggered"，caddyhttp.HandlerError 携带中断码与事务 ID）识别 Coraza 阻断；统一管线未判阻断而下游中断时补记 detector="waf" 明细（waf.downstream_intercept，BLOCK/HIGH，证据 attribution=downstream_intercept + coraza_tx_id + uncertainty=message_matched_no_rule_detail），final_action/response_status 按实记 BLOCK/中断码（事实记录而非引擎决策）；局限如实声明：归因与哨兵消息串耦合（升级 coraza-caddy 须复核）、取不到命中规则明细（仍经 request_id 事后关联审计日志）、phase 3 响应头相位中断不归因（与源站自返 403 不可区分）、非 API 流量事件不回填
    - 约束词汇升级（P0-04）：发布通道 confirmed_constraints 原样透传新增 regex（RE2，≤512 字符，编译失败/超长保守产 OBSERVE 明细不阻断）/nullable（仅 BODY JSON 有 null 语义，显式 false 才违例）/empty_allowed（空串各位置 + 空数组仅 BODY，显式 false 才违例）三词汇；required 缺失在 PROTECT 模式由 OBSERVE 升级为 BLOCK 类（可定案阻断），其余模式维持 OBSERVE
    - 规范中心增强（P0-12，迁移 000046）：`api_import_specs` 版本状态机（name/version_no/status：DRAFT/ACTIVE/HISTORICAL/INVALID/ARCHIVED + parent_id/activated_at；存量回填同名编版本号、仅最新版 ACTIVE，单 ACTIVE 部分唯一索引；`api_spec.manage` 权限仅 SECURITY_ADMIN）；URL 导入 `POST specs/import-url`（SSRF 防护：仅 http/https + 拒绝内网/保留地址，抓取函数可注入测试）；Swagger 2.0 识别并最小映射转换为 OpenAPI 3（YAML 仍 400 拒绝，go.mod 无 yaml 依赖）；跨版本 CHANGED 级 diff（同 path+method 的参数/类型/required 变化）与任意两版本只读对比 `GET specs/{id}/version-diff`；导入回写资产——仅登记运行时缺失的规范API（MISSING_IN_RUNTIME）进 api_endpoints，冲突不动已有资产；`POST specs/{id}/activate` 切换 ACTIVE（同名旧版降 HISTORICAL + 操作审计）
    - AuthZ 实体层（P0-15/16/17，迁移 000043/000044/000048）：`api_role_baselines`（BFLA 角色×API×方法×动作基线，source MANUAL/SPEC/OBSERVED/IMPORTED，confirmed 候选→人工确认）+ `api_object_ownership`（BOLA 权属：身份指纹×对象类型×对象标识，access_count/last_seen）+ `api_field_permissions`（字段权限七属性 READABLE/WRITABLE/READ_ONLY/ADMIN_WRITABLE/SERVER_GENERATED/SENSITIVE/FORBIDDEN，direction + role/tenant 覆盖行）；`apiauthz` 包：权属 SweepOnce（从事件 raw_path 按API路径模板提取占位符段值 upsert，HasMore 排空，与弱点/敏感 Sweep 同 5 分钟周期装配）+ 五档 BOLA 评估（POLICY_CONFIRMED/HIGH_CONFIDENCE/LIKELY/POSSIBLE/INSUFFICIENT_EVIDENCE，证据而非定罪）+ 13 条接口（角色基线 CRUD+confirm / 权属查询 / 字段权限 CRUD / evaluate）；权限 `api_authorization.read/manage`（SECURITY_ADMIN 全量、AUDIT_ADMIN 只读、SYSTEM_ADMIN 不授权）；**运行时消费已落地（第四波 W4-GW）**：confirmed 角色基线与字段权限经发布通道 `api_role_baselines`/`api_field_permissions` 下发（`guardconfig/authz_rules.go`，失败 Warn 跳过同脱敏规则模式）并纳入 api_policy_version 哈希；网关 `detectors/authzcheck.go`——BFLA（API有 confirmed 基线时：匿名访问 `authz.bfla_anonymous` OBSERVE/HIGH、角色无 allowed 基线 `authz.bfla_role_mismatch` OBSERVE/MEDIUM；角色取自未验签 JWT claims role/roles，仅作为 legacy 观察信号；无API基线零行为）+ 字段权限/Mass Assignment（`authz.forbidden_field` BLOCK 类 PROTECT 可阻断；`authz.server_generated_write`/`authz.readonly_write` OBSERVE；仅判定 REQUEST 方向 json. 前缀行，RESPONSE 方向与 tenant 覆盖行透传不判定）；**AUTHZ-01 核心 OBSERVE 链路已接线（迁移 000136）**：历史权属迁为不可直接确认的候选，新候选仅接收 VERIFIED HUMAN 身份；可发布对象模型、CONFIRMED OWNER 关系及 VERIFIED 角色基线经独立签名快照进入现有发布链；网关按可信主体、可信角色、应用、单层租户与关系有效期实时产生 BOLA/BFLA `authz_decision`，带 decision_id、原因码和脱敏证据且一律放行；候选/关系/决策/覆盖率接口、对象授权页面和 OpenAPI 已同步；关系确认、候选拒绝和决策详情采用独立权限门禁，已覆盖 `relation_manage`/`evidence_read` 交叉权限、脱敏及跨应用隔离测试，且 candidates、relations、coverage 查询均验证 `application_id` 隔离。关系确认与手工 CONFIRMED 关系创建均进入既有发布任务回调，内存覆盖率统计仅计算当前有效关系；真实 PostgreSQL 已验证全量迁移、000136 幂等重放、AZ-01 legacy 业务数据迁移、候选 sweep 恰好一次消费、迁移级并发锁和数据库事务失败后的重试；进程/机器/网络中断恢复、跨节点失败/回退、全流程 E2E 与性能基准仍待完成；真实跨进程发布仍待集成验收
    - 资产生命周期（P0-10/11，迁移 000045）：`api_endpoints` + asset_value/asset_value_explain/zombie_since 三列；ZOMBIE 入 asset_status 词表（注释口径，状态机由代码保证）——DEPRECATED 近 N 天仍有流量周期判 ZOMBIE（zombie_since 落时 + 生命周期事件 actor=system），ZOMBIE 无流量不自动归档（归档须人工）；`POST endpoints/{id}/deprecate|restore` 入口（api_asset.edit + 审计，restore 清 zombie_since）；资产价值评分九维（业务/数据敏感度、暴露面、权限、写/管理/交易能力、依赖度、流量规模）→ LOW/MEDIUM/HIGH/CRITICAL + 可解释明细周期回填；服务资产聚合视图（upstream host:port 粒度：应用数/API数/7 天流量/涉敏API数/未闭环风险数）`GET service-assets`
    - API 专项指标与探针（任务书 §158/§159 口径）：15 项有真实数据源的 DB 聚合 gauge 落地（`metrics/metrics.go`：资产/学习/候选/模型/编译/五类 findings/MASK_RESPONSE 计数），APICollector 周期采集并随 WDSP 形态装配；无数据源的指标（api_discovery_qps/api_parse_latency/学习延迟/事件积压/图谱边数/AI 工具调用量）如实不实现、不造假；runtimehealth 新增 API_SECURITY 组件探针（API 安全采集链路存活：最近事件时间/停滞秒数/事件总量，默认停滞 10 分钟降级）
    - 值级敏感检测下发与执行（P0-19 深化）：`api_sensitive_data_types` 增加值级 regex（长度与可编译校验）；status=ENABLED 且 regex 非空的类型经发布通道 `api_sensitive_value_rules` 下发（GuardSensitiveValueRule：data_type/regex/locations/level）并纳入 api_policy_version 哈希；网关 CompileSensitiveValueRules 启动期编译（条数≤256、正则≤512、非法规则拒绝加载不静默），CheckSensitiveData 追加值级参数——QUERY 值命中升级 BLOCK（sensitive.value_in_query，与键名命中同一语义）、JSON/FORM 值 OBSERVE（sensitive.value）、HEADER/PATH 位置扩展（cookie 整头脱敏跳过、脱敏头仅存在性、PATH 字面段名匹配 + 原始段值级匹配，证据用段序号绝不落值）；单值 4096 字符截断 + 单请求 512 次求值预算防 CPU 放大；无规则下发时零行为变化
    - 前端：弱点/敏感数据类型/脱敏规则/违例/运行时事件/运行时策略 6 个新页面注册路由（本批后累计 20 个 api-* 页面；2026-08-30 实数 30 个），授权基线管理页随前端分片在途
  - API 安全补全第四~六批（2026-08-18，迁移 000049-000056；其中 000049 网口管理、000050 syslog 外发扩展、000052 应用部署模式为并行网络模式/运维分片，非 API 安全项）：
    - 响应 Schema 学习闭环（P0-06，迁移 000051）：网关响应相位对合法 JSON 响应生成 ResponseObservation（一级字段路径→类型 + status_code/content_type/body_size/truncated，只含字段路径与类型标签不落值，`dynamic_security/response/observe.go` + `pipeline/response.go`），随主事件 `response_observations` 上报（apievents）；采集器 `apiruntime/respschema.go` 按 API×状态码 合并 UPSERT `api_response_schemas` 运行时学习行（字段并集、同路径类型冲突首次优先、sample_count 累计，`model_version_id IS NULL` 部分唯一索引承载运行时行）；`GET /api/v1/api-security/endpoints/{id}/response-schemas` 只读查询（api_model.read，按状态码升序，apimodels/response_schemas.go）；模型 Confirm 时 snapshotResponseSchemas 按版本物化快照行（快照不参与运行时合并）；TABLE_ONLY 状态解除
    - 调用边派生与图谱增强（P1-09/10）：`aggregations/call_edges.go` RunCallEdges 随分钟级周期作业运行（aggregations/jobs.go:326）——同一 identity_fingerprint 相邻调用间隔 ≤10 分钟成边（自环不成边、API未解析为序列截断点、匿名事件 SQL 层整体排除防伪拓扑）；水位取 aggregation_jobs 最近 SUCCESS 的 CALL_EDGES window_end，查询向前回看一个会话窗口配对、仅计入 to 时刻严格晚于水位的边，水位推进与边 upsert 同事务提交（崩溃重跑不重复计数），单批 5000 条防长事务；`GET /api-security/graph`/`topology` 新增 start/end（RFC3339 边活跃窗口）/min_count（最小调用次数）过滤参数（仅作用于边，节点始终全量返回），节点附 open_findings_count（未闭环风险计数）；`api_call_edges` 自此有生产写入方
    - API 安全告警（P1-08，迁移 000055）：systemalerts 新增三类型——API_CRITICAL_FINDING（窗口内新增未处置 CRITICAL findings，等级 CRITICAL）/API_FINDING_SPIKE（同 finding_type 窗口内新增数超阈，HIGH）/API_MASK_FAILURE（MASK_RESPONSE 脱敏执行失败，HIGH；网关 mask 失败产 response.mask_failed 明细，采集器物化为 RESPONSE_MASK_FAILED finding）；评估引擎 EvaluateAPIFindings 周期评估（复用 Raise 合并/冷却/抖动与 AutoRecover 自动恢复，开关关闭的类型跳过评估不清动既有告警）；`system_settings` 组 `api_alert` 六键可调（critical_finding_enabled/mask_failure_enabled/spike_enabled 默认开，spike_threshold=20、spike_window_minutes=60、scan_window_minutes=10，非法值回退默认）；告警静默能力：`system_alerts.silenced_until` 列 + `POST /api/v1/system-alerts/{id}/silence`（duration_minutes 1~43200，重复静默视为延长）与 `/resume`（解除）接口，静默期间告警照常合并记录、同指纹新建告警跳过 syslog 外发不重复通知（HasActiveSilence），列表新增 view 三态视图参数（ACTIVE/SILENCED/HISTORY，与 status 互斥，两者同传 400）
    - AI 工具第一批（P1-02）：aitools 新增 5 个 READ_ONLY 工具（api_ops_tools.go）——api_weakness.search（弱点搜索，证据经脱敏）、api_sensitive.search（敏感数据类型搜索）、api_runtime_policy.get（编译策略按 ID 取完整内容/按接口列版本摘要）、api_spec.get（规范版本详情与 diff，不含原文）、api_posture.get（安全态势聚合）；输入枚举白名单校验（与各域迁移 CHECK 口径一致），仅 WDSP 形态注册并经 SyncRegistry upsert 进 ai_tools 表；全部只读（弱点流转/策略发布/规范导入等写路径不暴露）；AI 自动运营定时任务仍未做（见诚实遗留）
    - 主动扫描 v1（P1-07，迁移 000053/000054/000056）：apiscan 包落地经授权有限主动验证（非 DAST）——`api_scan_targets`（靶标仅来自已纳管应用 FK applications + base_url + allowed_paths 路径白名单）/ `api_scan_authorizations`（授权先于一切执行：allowlist 主机白名单、time_window 时间窗、max_qps 1~100、max_concurrency 1~16、test_profile 探针画像、expires_at 必未来；双人分离——建目标 api_scan.manage 与授权签发/撤销 api_scan.execute 权限点分离且建标人不得自授权 403；撤销即停——撤销/紧急停止联动停止该授权下全部在跑任务，执行侧每批发包前 Guard 重查授权）/ `api_scan_jobs`（PENDING/RUNNING/PAUSED/STOPPED/COMPLETED/FAILED，progress 落 last_error 不吞错）/ `api_scan_findings`（evidence 只落判定规则/状态码/命中字段名/响应哈希，request/response 样本脱敏截断、凭据头值 [redacted]，SENSITIVE_EXPOSURE/BOLA_COMPARE 不落响应原文）；6 内置探针集词表（AUTH_REQUIRED/DEPRECATED_ALIVE/SENSITIVE_EXPOSURE/SCHEMA_CONFORM/BOLA_COMPARE/METHOD_ENUM，词表外一律拒绝）；扫描流量隔离签名头 X-JiuZhang-Scan（HMAC(job_id)，LoadOrCreateSigner 经 settings+加密服务落钥）；复测桥接弱点中心（finding confirm 可携带 weakness_id 关联，retest 真实重探该API并回写 apiweakness 状态机 RETEST_PASS/RETEST_FAIL，弱点非 FIXED/授权失效/执行器未装配如实报错不伪造结论）；学习样本扫描排除规则（apiruntime/samples.go：details 含 detector=scanner 明细即排除——网关侧识别上线前该规则处于待命态，如实声明）；17 条接口（/api-security/scans/*）全部路由层权限点 + 操作审计（建标/授权/撤销/紧急停止等中高风险留痕）；settings 组 `api_scan`：`enabled` 默认关（关闭时 CreateJob/Retest 403）、max_concurrent_jobs=1、sweep_interval_seconds=10；权限点 api_scan.read/execute/manage（000056，SECURITY_ADMIN 全量、AUDIT_ADMIN 只读、SYSTEM_ADMIN 不授权）；扫描前端页未建（当前 API_ONLY，如实声明）
  - API 安全补全第七/八批（2026-08-18，迁移 000057-000063；其中 000057 通知渠道、000060 通知二期为并行运维分片，非 API 安全项）：
    - 数据出境基础（P1-03，迁移 000058）：apigeo 包——自研纯 Go 只读 MMDB 解析器（零新依赖，复用仓库已授权的 geo-whois-asn-country 库 country.mmdb，服务端使用已在 THIRD_PARTY_NOTICES 登记署名）；出境判定五档（HOME/FOREIGN/INTERNAL/UNKNOWN/INVALID，内网/保留地址与未收录一律不记跨境，宁漏勿误）；生产方 SweepOnce 从 api_runtime_events 涉敏事件增量判定落 `api_cross_border_events`（独立水位表 + (source_event_id,direction) 唯一约束双保险幂等；风险等级经 api_sensitive_data_types.level 动态推导）；`GET /api/v1/api-security/cross-border` 看板（国家×敏感类型×API聚合+趋势+明细分页，geo_enabled 降级标识）；`api_data:home_regions`（默认 CN）进设置白名单；数据文件缺失 nil 降级（Sweep 空转、看板如实标注）
    - API 专项报告（P1-06，迁移 000059）：reports 包扩展四类型——API 资产周报（新增/确认率/Shadow/Zombie/Deprecated 计数与清单）/API 风险周报（findings 新增/关闭/类型分布/Top API与主体，七态口径对齐 000042）/弱点整改报告（状态分布/超期未修/复测记录）/敏感数据报告（类型分布/涉敏API Top/按天趋势）；全部真实 SQL 采集 + 确定性结论/建议模板 + HTML/PDF 渲染，复用既有报告管线（创建→生成→预览→下载→权限继承）；零新表（report_type 词表扩展）；调度器未做（手动触发或 cron 外驱，装配片段见报告）
    - 敏感文件资产（P1-04，迁移 000061）：网关 multipart 上传/Content-Disposition 下载文件观测（文件名 basename 归一化截断 128、扩展名/mime/大小/方向，不落内容；无 filename 的 octet-stream 不判定为下载，如实声明漏报口径）经 `file_observations` 事件字段上报；采集器 UPSERT `api_file_assets`（去重键 endpoint×方向×文件名×身份指纹，transfer_count 累计、IP 脱敏存储）；`GET /file-assets` 与 `/file-assets/stats`（§106 双口径统计与五个 TOP）；文件风险 v1：同身份 1h 批量下载超阈（`api_data:file_bulk_download_threshold` 默认 50，已进设置白名单）→ FILE_BULK_DOWNLOAD 风险发现（dedup upsert）
    - AI 定时运营任务（P1-02 续，迁移 000062/000063）：apiops 包——自研五段 cron 解析器（零新依赖）+ next_run_at 游标 claim 先行防重入；五种内置运营任务（API_ASSET_DIGEST/SHADOW_REVIEW/WEAKNESS_FOLLOW/RISK_DIGEST/SENSITIVE_DIGEST）纯确定性查询+模板化中文摘要，**只产报告不做任何变更**（安全边界：无自动确认/发布/封禁代码路径）；LLM 润色 Summarizer 小接口（nil/失败一律回退模板，降级不失败）；全局开关 `api_ai_ops.schedules_enabled`（默认关）门控调度与立即执行；`/api-security/ai-ops` 下 CRUD/启停/立即执行/runs 查询接口；权限点 api_ai.read/execute（000063，SECURITY_ADMIN 全量、AUDIT_ADMIN 只读）
    - 主动扫描前端（P1-07 残余收口）：ApiScanPage 四 Tab（目标 CRUD+启停/授权签发双人分离提示与吊销/任务启动停止紧急停止+进行中轮询/发现详情确认误报复测），路由菜单注册，权限 api_scan.read/execute/manage 显隐
    - Playwright E2E 扩充（§217）：新增 stage8-api-security-ops.spec.ts 8 场景（风险处置/弱点整改/脱敏规则/敏感类型/规范中心/授权基线/主动扫描/运行时策略），真实环境全量实跑 8/8 通过；发现并修复服务端缺陷 `runtime_policy.go` policySelect 列歧义（JOIN 后 42702 恒 500，逐列 p. 前缀修复）；Makefile stage8-test-e2e 与 api-security-test-e2e 目标纳入新 spec
  - API 安全补全第九批（2026-08-19，零新迁移）：
    - 扫描流量识别闭环（P1-07 隔离链收尾）：网关识别 X-JiuZhang-Scan 签名头——发布通道下发 `api_scan_verification.key_hex`（guardconfig 经 settings+加密服务解密 apiscan 密钥，快照脱敏、不入版本哈希）；签名校验有效产 `scanner.signature_valid`（OBSERVE/INFO）明细、无效不打标防伪造并产 `scanner.signature_forged`（OBSERVE/MEDIUM）、未配密钥按存在性产 `scanner.presence_only`；`detector=scanner` 明细即被学习样本排除规则（apiruntime/samples.go）消费——扫描流量不进学习/不进行为基线由待命转为生效
    - 响应偏离检测（P0-06 运行时消费）：`api_response_schemas` 学习行（sample_count≥20）经发布通道 `api_response_baselines` 下发；网关响应相位比对一级字段——基线外新字段 response.schema_new_field（OBSERVE/MEDIUM）、基线字段缺失 response.schema_missing_field（OBSERVE/LOW）、未知状态码 response.schema_new_status（INFO）；证据不落值；无基线零行为
    - API 态势（P1-01 补齐）：`GET /api-security/posture/overview` 12 项核心指标（访问量/防护量/资产/新增/Shadow/Zombie/Deprecated/涉敏/高风险/无认证/待确认模型/24h Schema 偏离，全部真实 SQL 口径注释）+ `GET /posture/trends?days=N` 六条按天趋势（访问/防护/风险/新增/Schema 偏离/敏感命中，UTC 日界补零）；前端 ApiPosturePage（指标卡+ECharts 趋势+钻取）注册为 API 防护组首屏
  - API 安全补全第十批（2026-08-19，迁移 000066）：
    - 态势访问维度（P1-01 残余收口）：`GET /posture/sources`（client_ip Top 脱敏/Geo 分桶与国家 Top（复用 apigeo，mmdb 缺失 geo_enabled=false 降级）/身份指纹 Top 截断/auth_type 分布；`api_runtime_events` 无 UA 列故 UA 维度如实不做）+ `GET /posture/targets`（API 请求量/findings 双口径、应用、涉敏、高风险五榜单）；前端态势页两区块
    - LLM API 安全 v1（P2-04 首批，迁移 000066）：网关 LLM API识别（OpenAI 兼容路径词表+POST+内容形态双重确认，保守精确）；请求侧观测（model/messages 存在性/prompt 长度分桶，不落原文）+ 响应侧补全（model/usage.total_tokens，SSE 置 stream）；Prompt Injection 词表 v1（8 条中英规则，仅 OBSERVE/LOW，证据只含规则名与消息序号不落原文）与未授权模型检测（`gateway_runtime.api_llm_allowed_models` 下发名单非空时判定，OBSERVE/MEDIUM 参与不了阻断）；事件 `llm_observation` 字段上报 → 采集落 `api_llm_observations`（request_id 派生 UUID 幂等）；`GET /llm/observations` 与 `/llm/stats`（模型分布/token 趋势/findings 计数）；MCP 形态本波仅识别落观测（内容级检测后续）
  - API 安全补全第十一批（2026-08-19，迁移 000067/000068）：
    - 参数条件关系闭环（P0-02 残余）：api_parameter_relations 补 confirmed 列与词表 CHECK（000068）；手工新建 REQUIRES/MUTEX + confirm/reject 接口（api_parameter.edit + 审计）；confirmed 关系经发布通道 `api_parameter_relations` 下发并纳入 api_policy_version 哈希；网关运行时检测——REQUIRES 缺失/MUTEX 同现（PROTECT 升级 BLOCK、OBSERVE 仅观察）、CO_OCCURS 仅 INFO；证据不落值
    - 响应方向字段权限运行时判定（P0-17 残余）：响应相位消费 RESPONSE 方向字段权限——FORBIDDEN 命中产 authz.response_forbidden_field（OBSERVE/MEDIUM，响应侧不定案阻断）、SENSITIVE 命中产 authz.response_sensitive_field（OBSERVE/LOW）；已被 REMOVE/MASK 治理的字段不重复判定（HASH 不去重）、与敏感检测器去重；role 覆盖行按未验签请求角色判定（仅观察信号）；tenant 行仍不判定（无租户上下文）
    - 调用边身份计数持久化（迁移 000067）：api_call_edges 加 identity_count（近似下界口径）+ NULLS NOT DISTINCT 唯一索引（含存量重复行合并去重）；派生 upsert 切 ON CONFLICT 去掉 advisory lock 依赖；graph/topology 边响应带 identity_count
  - API 安全补全第十二批（2026-08-20，迁移 000069/000070）：
    - 多节点版本校验 v1（§201 遥测路径，迁移 000069）：api_gateway_nodes 表 + SweepOnce 从 api_runtime_events 按 gateway_node 增量聚合（最近事件/最新非空 policy_version/model_version/计数，绝对值覆盖幂等）；状态判定 ACTIVE/STALE/SILENT（5min/1h 边界）；版本一致性比对（非 SILENT 且已上报版本节点参与，SILENT 离线不参与防升级期误报；未上报单列不参与）→ 不一致产 CONFIG_HASH_MISMATCH 告警（恢复自动 AutoRecover）；`GET /api-security/nodes` 与 `/nodes/consistency`（明确回答所有节点版本是否一致）；配套补齐 api_runtime_events.gateway_node 落列（事件透传字段此前未持久化）；如实声明：这是遥测校验而非同步协议，全量协议（节点注册/心跳/主动同步）为后续工程
    - MCP 内容级检测（P2-04 续）：MCP JSON-RPC 方法词表核对（词表外 llm.mcp_unknown_method OBSERVE/LOW）与 tools/call 参数值级敏感检测（复用 SensitiveValueRules → llm.mcp_sensitive_arg OBSERVE/MEDIUM，证据只含工具名/规则名不落参数与值）；mcp_method 入观测与 api_llm_observations（迁移 000070）
    - 文件水印 v1（P2-01 最小子集）：文本族下载（text/plain/csv/markdown、application/json）不可见水印——文本尾注释行 / JSON 顶层 _wm 字段（{ip}/{identity}/{time}/{domain} 占位）；经 `gateway_runtime.api_file_watermark_*` 四键下发（默认关闭零行为）；仅 identity 编码完整捕获体改写并修正 Content-Length，206 分段跳过，失败恒 FAIL_OPEN；先 mask 后水印顺序固定；docx/pdf/xlsx 需媒体库本波显式拒绝（配置期报错不静默）；命中产 file.watermark_applied INFO 明细
  - API 安全补全第十三批（2026-08-20，迁移 000071）：
    - 文件合规管控 v1（P2-03）：api_file_compliance_rules 表（direction/match_type(EXT|MIME|FILENAME_REGEX)/action(OBSERVE|BLOCK)，内置种子 exe/bat/sh 上传阻断与 sql/bak 下载观察）+ CRUD 接口；规则经发布通道下发并纳入版本戳；网关双相位执行——上传（multipart 观测点）与下载（Content-Disposition 观测点），BLOCK 在 PROTECT 上传 403/下载缓冲抑制 403（已直通诚实降级 file.download_block_unavailable，不冒充已阻断）；双扩展名 file.double_extension OBSERVE/LOW
    - 文件签名 v1（P2-02）：文本族下载嵌入 `jzsig1.{kid}.{unixts}.{hmac_hex}`（HMAC-SHA256(key, kid|filename|content_sha256_hex|unixts|identity_fp)，内容哈希取脱敏/水印后最终交付体）；密钥密文存 settings 经加密服务解密下发（Redact 脱敏覆盖）；`POST /file-signature/verify` 复算校验（max_age_days 默认 30 可配；kid 不符/伪造/过期如实结论；密钥未配置 503）；`GET /file-signature/key` 仅 kid + `POST /key/rotate` 轮换（递增 kid，旧 token 即失效，预期收紧）；验证/轮换均审计不含密钥与完整 token
  - API 安全补全第十四批（2026-08-20，迁移 000072）：
    - gRPC v1（P2-05）：识别 application/grpc(+proto) 与 /package.Service/Method 路径形态（服务/方法名全保留不归一化）；5 字节前缀帧结构校验——声明长度>剩余体或单帧超上限（`api_grpc_max_frame_bytes` 默认 4MiB 经发布下发）→ grpc.malformed_frame（PROTECT 定案 403）、压缩标志位（默认不允许）→ grpc.unexpected_compression OBSERVE；消息计数/声明体量入观测（不落内容）；API protocol_type 标注 GRPC（发现链路 DiscoveryInput 透传，仅首写不覆盖）；>1MiB 大体积随既有采样护栏跳过（注释声明）
    - OOXML 水印扩展（P2-01 补全子集）：docx/xlsx/pptx 下载经 Go 标准库 archive/zip（零新依赖）注入 docProps/custom.xml 自定义属性水印（幂等锚点跳过、OPC 三处合规登记、保留条目顺序/压缩方法；32MiB 护栏、加密/损坏 FAIL_OPEN）；与文本族水印共用配置（三 MIME 需显式 opt-in）
    - 协议版本可见性：事件新增 proto（HTTP/1.1/2/3）与 protocol（GRPC 标注）字段（omitempty，采集容忍缺失）
    - 源码 API 发现 v1（P2-07，迁移 000072）：tools/apisrc 独立工具（go/ast 零依赖）扫描 Go 源码路由注册（ServeMux/chi/echo/gin 字面量形态），输出 OpenAPI3 骨架（source=SOURCE_CODE 标记）→ 规范中心导入流水线天然兼容；api_import_specs 加 source 列（UPLOAD/URL/SOURCE_CODE 词表），导入记录来源落库
  - API 安全补全第十五/十六批（2026-08-20，迁移 000073）：
    - 前端收口：AI 运营（计划/运行记录）、LLM 观测、数据出境看板、服务资产、节点校验、文件合规 6 页注册路由菜单；Playwright 新增 stage8-api-security-ops2.spec.ts 6 场景（一次性容器环境 6/6 实跑通过；Makefile e2e 目标已纳入）
    - 残余空表生产方（迁移 000073）：api_object_models 补 first_seen/last_seen/sample_count 观测列并由 apiauthz SweepObjectModelsOnce 生产（路径占位段/Query 对象参数形态，仅落 SHA-256 示例哈希）；api_endpoint_path_segments 由发现链路首插/拆分派生（xmax=0 判插入，存量迁移回填）；api_classifications 内置业务领域 16 项种子（幂等）；api_request_schemas 表注释标注「保留不用：请求 schema 以 api_model_versions.schema_json 为权威来源」——TABLE_ONLY 表自此清零
  - API 安全补全第十七批（2026-08-20，零新迁移）：
    - 网关节点心跳（§201 活性+版本上报升级）：新配置 `api_node_heartbeat_seconds`（默认 0=关闭，校验范围；WDSP 关闭时拒载）——网关 Provision 起后台 goroutine 周期向 API 事件日志写合成心跳记录（heartbeat:true + gateway_node + policy_version + 正式模型版本摘要数 + uptime + guard_start_time；Caddy 重载优雅退出不泄漏），沿用单向日志采集通道架构零变化；采集端识别 heartbeat 仅透传 HeartbeatRecorder（不落 api_runtime_events、不产任何业务数据）；apinodes 活性判定不再依赖业务流量（有心跳无流量=ACTIVE），policy_version 以心跳上报为准（UpsertNode 合并不回退语义）
    - OpenAPI 全量对账收口：补录 l7-rules×7、notification-channels×5+meta、analytics/site-access-trends×2 共 15 个 operation（ai/drafts 同名异参为既有有意合并）；全后端 504 条 /api/v1 路由 vs 文档 504 operations 真实差集为 0
  - API 安全补全第十八批（2026-08-21，迁移 000074）：
    - 多节点发布扇出（§200 配置面主动同步 v2，迁移 000074）：api_gateway_nodes 增 admin_addr/sync_enabled/last_sync_* 六列；`PATCH /api-security/nodes/{id}` 登记节点 Caddy Admin 通道（仅内网地址校验+拨号时 DNS 重解析复检防重绑定，防 SSRF 镜像方向；api_policy.publish 权限+审计）；Publisher.PublishSync 主节点全链路成功后把**本次构建的同一份配置**扇出到全部 sync_enabled 次要节点（/load + 规范化哈希比对），逐节点回填 last_sync_*——次要节点失败不阻断主发布（记录+告警），主节点失败按既有回滚语义；http(s) 目标支持 caddyclient 最小扩展
    - 性能基线实测（§202-203 最小矩阵，真实数据）：Baseline Proxy 5337 QPS（p95 9ms）vs Full API Security（OBSERVE）3540 QPS（p95 13ms）——API 动态防护开销 QPS -33.7%、p95 +4ms、0 失败；事件洪峰 11.5 万条采集器约 6.5 分钟全量追平零丢失（分钟级时延如实记录）；环境/参数/原始数据见 docs/evidence/api-security-performance-baseline.md（含 harness 三次事故修复记录）；全矩阵其余档位（WAF Only/PROTECT/单项检测器/大 body 等）列入文档 §8 缺口
  - API 安全补全第十九/二十批（2026-08-21，零新迁移）：
    - 性能矩阵扩展（§202 真实数据）：Baseline 5499/OBSERVE 3211/PROTECT 4405（阻断比透传快 60%）/1KiB POST 3133/64KiB POST 961（0.22µs/字节）；WAF Only 1465 QPS——**关键结论：Coraza 全量 CRS 开销（-72% QPS、CPU 631%）≈ API 动态防护管线开销（-26%、CPU 226%）的 2.7 倍，网关水平扩展首要驱动是 WAF 规则评估而非 API 管线**；Multipart（体长主导 ~68ns/字节）与 c=100 高并发观察（零失败、吞吐饱和软拐点）补测；检测器无独立开关的 §202 分档已诚实声明不可测（不造假）；全部实测见 docs/evidence/api-security-performance-baseline.md（§10/§11，含环境终态自动核验）
    - HTTP/3（P2-06 诚实子集闭环）：Caddy 2.11 对 TLS 监听默认开启 h1/h2/h3（发布通道零改动）；编排侧补 UDP 端口注释可选块（deployment/docker-compose.wdsp.yml，默认关闭）；旁路实测（deployment/http3-lab/）：h3 请求经 Caddy → guard 管线 → 源站正常，proto=HTTP/3.0 在 Caddy 访问日志/guard 全量日志/API 运行时事件三面正确记录，路径归一化/检测器/真实 IP 在 h3 下全部正常（docs/HTTP3_SUPPORT.md 含证据与启用方式）；边界：QUIC 层 0-RTT/连接迁移/QPACK 帧解析与治理未做（引擎仅见 QUIC 终止后的 http.Request）；访问控制/CC 事件无协议版本字段（跨分片契约，未动）
  - API 安全补全第二十一批（2026-08-21，迁移 000075）：
    - 采集器 flush 批量化（性能实测发现的真实缺陷修复）：api 运行时事件与全量访问日志两采集器由「EOF 才唯一 flush、断点仅 flush 时落盘」改为批量（默认 2000 行）/周期（默认 2s）flush 且断点同节奏落盘——崩溃重扫量有界（≤2000 行+≤2s）、api 重建不再 GB 级全量重扫；中途 flush 失败断点不前移（下轮从最近成功断点重读，幂等语义不变）；`WAF_COLLECTOR_FLUSH_BATCH`/`WAF_COLLECTOR_FLUSH_INTERVAL` env 可配；顺带修复 accesslogs 断点按完整行累计错位与 EOF 落盘失败静默两处同域缺陷；§11.8 问题记录已标注修复
    - 访问控制/CC 事件协议版本字段（迁移 000075）：guard 事件 Record 单点填充 proto（omitempty）→ access_control_events 加 proto TEXT NULL 列 → 采集落列（缺失容忍）→ 读接口带出 → 前端事件页协议列（HTTP/1.x/2/3 Tag 色）；全链新旧版本互通不破坏
  - API 安全补全第二十二批（2026-08-21，零新迁移）：
    - 采集器事务批量化（W22）：每个 flush 批次的副作用与主事件并入单个 DB 事务整批 COMMIT（`apiruntime/batchtx.go`；副作用错误经记录级 SAVEPOINT 容忍、失败整体回滚且断点不前移、重放幂等；`SetBatchTxFactory(db.Begin)` 装配，未接线保持 autocommit 零行为变化；accesslogs 采集器同手法）——消除逐语句 commit 的中间态（不再有"副作用已提交、主事件未落"）；机制级基准实测：逐行 autocommit 143.6 rows/s → 每 2000 行单事务 272.2 rows/s（≈1.9 倍，共享负载机比值有效）；真实 PG 集成 4 用例（端到端一致/重放安全/毒记录回滚/死事务回滚）与单元测试 6 项全过；证据已追加 docs/evidence/api-security-performance-baseline.md §11.8（端到端生产复测留待后续）
  - API 安全补全第二十三批（2026-08-21，迁移 000076）：
    - gRPC 描述符级解析 v1（P2-05 深化，迁移 000076）：api_grpc_descriptors 表 + protoset 上传 CRUD（1MiB 护栏、线格式校验、api_spec.manage 权限）→ 发布通道下发 → 网关装配期 protodesc.NewFiles+dynamicpb 动态注册表（编译失败逐集 Warn 跳过不拖垮配置）；按 /package.Service/Method 查找方法描述符动态解码请求消息（仅未压缩首帧，解码失败降级 v1 行为）→ 字段路径级敏感值检测（grpc.sensitive_field OBSERVE，证据只含字段路径+规则名不落值）与 grpc.decode_error（与 malformed_frame 严格区分）；事件观测带 decoded/descriptor；无描述符下发行为与 v1 完全一致（专项测试锚定）；protobuf v1.36.11 由间接依赖转直接启用（既有锁定版本，零新增外部库）
    - W22 生产复测（诚实结论）：机制级 1.9 倍未在端到端体现（归一化后 ≈0.8-1.0 倍噪声内持平）——每行成本由 10+ 条副作用语句主导（追平期 postgres CPU ~390% vs api ~43%），事务批量化每行仅省 ≤1 次 COMMIT 且 SAVEPOINT/RELEASE 每行 2 次往返；确定性收益在正确性与重放结构（批次原子可见、"已提交未记断点"重放 503→0 行、杀死在途批次失败语义按设计工作）；吞吐进一步提升须副作用批量化（多行 VALUES/COPY，已记录为后续方向）；复测数据与独立复核见 docs/evidence/api-security-performance-baseline.md §11.8
  - 双节点 HA lab 落地（2026-08-22，零新迁移）：docs/HA_TWO_NODE_DESIGN.md §5/§6 工程化——编排 `deployment/ha-lab/`（Caddy 前置 LB least_conn + gw-a/gw-b 双网关 + 共享 PG/Valkey + api + nodepatch 身份补丁工具，端口绑 127.0.0.1）+ 一键验证 `test/ha/ha-lab-verify.sh`（S1 配置一致性 / S2 共享 Valkey 计数跨节点统一限速 / S3 故障摘除-STALE-恢复追平 / S4 发布中故障-FAILED-告警-漂移-重发对齐 / S5 管理面中断防护持续与事件追平，支持 `--scenario` 单跑）。**整跑实测 28/28 通过**。实测暴露并修复真实装配缺陷：`apiruntime.Collector.SetHeartbeatRecorder` 此前未在 `server/cmd/api/main.go` 接线（第十七批心跳已产出已采集但不落 api_gateway_nodes，节点活性/版本视图在无业务流量时失真），补接线后双节点 ACTIVE、版本哈希一致、S3/S4 活性与漂移断言全通；验证脚本三处断言按实测行为修正（硬停在途请求 LB 直返 502 不产事件的 ≥11/12 口径、告警同指纹合并改为清场后断言新建 OPEN、S4 版本标记跨轮残留的幂等复位基线）
  - 全流程走查修复批（2026-08-27，迁移 000079）：经「建站→发布→正常访问→攻击拦截→日志核验」真实走查暴露并修复 5+1 个缺陷——
    - 安全事件不写 application_id（按站点过滤恒空、站点维度报表失效）：securityevents 采集器新增 appResolver（application_domains JOIN applications 全量映射 60s 惰性缓存，Host 小写去端口精确+泛域名后缀匹配），InsertEvent 补 application_id/application_name_snapshot 两列；迁移 000079 回填存量（284→283 条有主，anything.local 无对应应用如实不归）
    - attack_type 误分类（首 tag 命中即定，notice 级扫描器提示规则 1000712 总先于 critical 级 CRS 攻击规则执行，71% 事件误标 SCANNER_DETECTION）：normalize 改严重度优先（同级取先出现者，纯扫描器事件仍判 SCANNER_DETECTION）；迁移 000079 从 security_event_matches(tags+severity) 同口径重算存量 47 条
    - 动态发布配置无错误路由（Coraza 拦截返回空 body 403、无阻断页、无请求 ID 头，BlockPagePath 字段定义后从未使用）：generator 新增 buildErrorRoutes 挂 server 级 errors（镜像 caddy adapt 实测形态；403 分支 headers→rewrite→templates+file_server，CEL 匹配器 expr/name 必须成对否则 UnmarshalJSON panic——实网发布首测即踩此坑并补上），链首 headers handler 增加 response.set X-Jiuzhang-Request-ID（正常/透传响应全覆盖）
    - access-full.jsonl 被拦请求 response_status=0：guard captureAccessLog 在下游返回 caddyhttp.HandlerError 时从错误链兜底取 StatusCode（403 记 BLOCK），普通错误不误推断（专项测试锚定两种形态）
    - 网关日志无轮转（coraza-audit.log 1.4GB / api-runtime-events.log 1.5GB）：新增纯 busybox logrotator sidecar（gateway/images/logrotator，alpine digest 锁定、零 apk），copytruncate 轮转 5 个无自轮转日志（阈值 100MB/保留 7 份/间隔 10min 可 env 配），stage5 编排挂载共享日志卷；实网强制轮转 2.9GB 验证写入方 fd 不中断、采集器断点自动重置无丢失
    - 附带修复（轮转实测暴露）：5 个日志采集器（securityevents/accesscontrolevents/apiruntime/accesslogs/sitediscovery）轮转检测后置断点不前进，空文件期间每 2s 重复刷 rotated 日志——统一改为轮转判定即落断点（空前缀指纹），实测 30s 内每采集器仅 1 条
    - 验证：复验脚本 7/7（发布/200+请求ID头/4 类攻击 403+拦截页+请求ID头/事件 application_id 非空且类型正确/access-full 403+BLOCK/存量回填 299/300/轮转实测）；回归 stage5-test-gateway 40/40、guard -race 全量通过；server ./internal/... 除 internal/product 外全量通过——product 失败为工作区既有未提交 WIP（grpcdesc 等 stage-8 未完批次）缺 go.sum protobuf 条目所致，与本批改动无关，未代为修整他人 WIP 依赖文件
  - 迁移记载补齐（2026-08-30 评审补登，均为已存在迁移的文档补记，非本批新迁移）：
    - 000064 镜像/透明部署模式产品化：applications.deployment_mode 词表扩为四值（REVERSE_PROXY/ROUTED/MIRROR/TRANSPARENT）；MIRROR 应用发布不生成内联站点路由、改写 mirrorcap 边车配置，TRANSPARENT 保留内联路由并写出 tproxyd 边车配置（设计见 [NETWORK_MODES_DESIGN.md](NETWORK_MODES_DESIGN.md) §4.2/§4.3）
    - 000078 产品侧离线授权：`licenses` 表 + `license.*` 权限点——.lic 由厂家授权中心 Ed25519 离线签发、产品侧验签导入，唯一 ACTIVE 部分唯一索引保证单行生效，导入新授权同事务将旧行置 SUPERSEDED；raw_file 经应用层 AES-256-GCM 加密落库；到期/指纹失配回锁定态（网关透传），运维流程见 [DEPLOYMENT.md](DEPLOYMENT.md)「授权导入与管理」、机制见 [LICENSE_DESIGN.md](LICENSE_DESIGN.md)
    - 000080 HA 主备高可用：`ha_groups` / `ha_group_members` + `ha.*` 权限点（VIP 漂移 + 网桥端口联动 + 会话保持，M2 范围；ha-vip.json 由管理面原子写共享卷 sidecars 供 havipd 执行，设计见 [HA_ACTIVE_STANDBY_DESIGN.md](HA_ACTIVE_STANDBY_DESIGN.md) §8.3）
    - 000081 API 文件合规 webshell 扩展名种子：`api_file_compliance_rules` 追加 JSP/ASP/PHP 系等可执行脚本后缀上传 BLOCK 种子（ON CONFLICT 幂等，不覆盖人工修订；BAS 覆盖基线补强）
    - 000084-000086 报表域：`reports.delete_all` 权限点（仅 SECURITY_ADMIN，删除任意用户报告）；报告/定时计划新增 `include_api_assets`（全量 API 资产清单可选项）与 `page_orientation`（PDF/Word 纸张方向 P/L）
    - 000087 API 分类词表扩充：`api_classifications` 追加商品目录/库存物流/客户服务/营销增长/内容社区/音视频媒体/位置服务等业务领域内置分类（ON CONFLICT 幂等，不覆盖既有同编码分类）
  - 评审收口（2026-08-30）：阶段8 整体评审发现的各项修复随本批评审修复批处理并落地，覆盖统一决策引擎判定一致性、运行时策略回滚链、CI 门禁与范围检查、离线包交付完整性、检测与分类词表扩充、发布内容哈希覆盖面等类别；逐条明细以本批各修复提交的 Git 差异为准，此处不重复罗列。文档侧同步刷新：本小节头部口径（表数/接口数/页面数/测试计数）经实数核实改写，DEPENDENCIES 补登 coraza-caddy 哨兵耦合点与 protobuf、THIRD_PARTY_NOTICES 补登 protobuf 与关键间接依赖并统一 SBOM 口径、HA_TWO_NODE_DESIGN 与 DEPLOYMENT 补次要节点 Caddy Admin API 暴露面风险与加固纪律。
- **诚实遗留（任务书超集部分）**：
  - 参数微模型覆盖面仍低于任务书 §4.2 字段清单：presence_rate/null_rate/p50~p99/format_candidate 等列不存在。（已闭环：观测→统计回填长度/值域/基数、QUERY/PATH 参数行物化、自动候选非空 Schema + 自动提交评审，见"API 安全补全第一批"；**参数条件关系已闭环**——confirmed 列 + confirm/reject 接口 + 发布下发 + 网关 relationcheck 运行时检测，见"API 安全补全第十一批"）
  - 响应侧已落地 JSON 族完整捕获体的解析/检测/字段级脱敏与响应 Schema 学习（P0-06 已闭环，见"API 安全补全第四~六批"；**响应偏离检测已落地**——api_response_baselines 下发 + 网关比对，见"API 安全补全第九批"）；遗留：gzip/br 等非 identity 编码与流式/SSE 直通不脱敏（FAIL_OPEN；FAIL_CLOSED 可抑制为 500 空明细），ENCRYPT/MAP 算法与还原审计未实现，§48 响应模型全字段（status_distribution 等维度）无数据源
  - 行为滑窗/对象游标默认单节点进程内存：Valkey 可插拔存储已实现，现可经发布通道 `gateway_runtime.behavior_store=valkey` 下发启用（默认仍 memory）；hourHist/UA 族两追踪器未抽象进 StoreOverrides；调用边派生已落地（P1-09/10，见"API 安全补全第四~六批"；匿名事件排除、跨节点身份序列依赖事件汇流）；**多节点版本遥测校验已落地**（api_gateway_nodes + 一致性比对 + CONFIG_HASH_MISMATCH 告警，见"API 安全补全第十二批"），**心跳活性与配置面主动同步 v2 已落地**（第十七批网关心跳、第十八批发布扇出 + last_sync_* 逐节点回填 + 失败告警），残余为节点注册握手协议与发布配置之外的产物（规则库/证书/GeoIP 等）分发；AUTHZ-01 已将 confirmed OWNER 关系和 VERIFIED 角色基线下发到网关执行实时 OBSERVE 判定，legacy BOLA 五档评估和未验签角色信号继续作为独立观察证据；完整 E2E、跨节点故障矩阵与性能验收仍缺
  - Coraza 合流已落地（下游哨兵归因，见"API 安全补全第二/三批"）；残余如实声明：归因与 coraza-caddy v2.5.0 未导出哨兵消息串耦合（升级须复核）、命中规则明细仍只能经 request_id 事后关联审计日志、phase 3 响应头相位中断不归因（与源站自返 403 不可区分）、非 API 流量事件不回填；管线外部明细入口 externalMatches 仍恒 nil（合流走下游错误归因，非管线注入）
  - AuthZ 残余：AUTHZ-01 的 OWNER-only BOLA 与 VERIFIED 角色 BFLA 已进入网关实时 OBSERVE 链路，且只消费 JWT 信任链产出的 VERIFIED 主体与角色；Guard→API 管线→事件出口的 BOLA 组合验收已覆盖 OBSERVE 放行与 HMAC 脱敏；候选 sweep 的事件查询、候选写入与 receipt 已统一在事务中并使用 `FOR UPDATE OF e SKIP LOCKED`，避免并发 worker 重复消费；迁移执行器现按版本使用 PostgreSQL 事务级 advisory lock，并在加锁后重检 `schema_migrations`，新增两个独立 runner 的并发迁移契约测试，且已在锁定的 PostgreSQL 16.4 实例运行通过；旧 `authzcheck.go` 未验签角色提取仍保留为隔离的 legacy 观察信号，不进入 `authz_decision`；当前关系类型只开放 OWNER，租户仅支持 verified tenant 与对象租户的单层完整性/一致性判断（双方为空允许、单侧缺失 UNKNOWN、双方不一致 OBSERVE），共享/委托/客服代查及复杂租户层级未实现；legacy 业务数据迁移、候选 sweep 业务并发和数据库事务失败后重试已有真实 PostgreSQL 契约证据，独立测试进程间 JSON 交接、PreviousValid 恢复和 PostgreSQL 持久化版本选择已有可复现契约（`TestPersistedSnapshotSelectionAfterProcessRestart` 通过 `AUTHZ_TEST_PG_DSN` 显式启用，未配置时跳过），机器/网络中断恢复及真实跨进程连续事件流仍缺；新增授权快照编译契约单测，锁定模型存在时关系/角色/HMAC 缺失即拒绝发布；Provider 已按最近一次 SUCCESS 快照选择并具备终态保护，新增版本级 `RetryNodeSyncForVersion` 恢复入口（仅接受 `SUCCESS` 快照，使用当前密钥重注入后复用节点同步/水位/告警路径；持久化仓储支持时仅重试该版本最近一次 `FAILED`/`HASH_MISMATCH` 节点，旧实现回退到全部启用节点），PreviousValid 配置渲染单测进一步锁定模型、关系、角色、版本、过期时间和 stale 标记下发且历史 HMAC 只替换为当前运行时密钥，Guard Provision 还会对历史模型缺失/非法 HMAC fail-closed；新增本地 AUTHZ-01 证据链测试，覆盖候选→确认→CONFIRMED OWNER→网关 BOLA 评估，owner 放行、其他主体 OBSERVE 及请求上下文记录；新增跨 module live HTTP 契约测试，注入 `/load` 瞬时 500 后以相同 JSON 重试，由 Guard 恢复 PreviousValid 并完成 BOLA OBSERVE 放行与事件落盘；新增可复现 `test/waf/scripts/authz-cross-module-contract.sh`，先执行 `apiauthz` 管理层候选确认/发布回调回归，再串联 server Provider 快照生成与 gateway Guard 快照消费，并在第二个独立 Gateway 进程验证 `PreviousValid` 恢复，覆盖 BOLA/BFLA 决策、PreviousValid/HMAC 和事件脱敏；新增双节点部分失败/定向重试的真实 HTTP 发布测试、旧版本节点未知授权分片 400 的快照保真/失败节点重试测试与 `authz_disabled`/`authz_enabled` 配对 benchmark，新增 `test/performance/p0/run-authz-01.sh` 的决策矩阵、`p0bench/go_bench.py` 的 P50/P95/P99、吞吐和分配 JSON 报告及正式环境缺失时的 `BLOCKED` 门禁，并通过本机 `-race`；这些证据仍不等同 Provider 真实常驻服务、多节点编排、真实旧二进制、机器/网络故障、完整跨进程连续事件流或 P0-02 的正式 P95/吞吐/RSS/长稳验收；事件存储中断路径已具备有界队列、限量错误账本和关闭汇总；显式回滚已在主节点恢复配置后继续向次节点扇出，且有授权快照配置保真测试，但部分节点发布失败/完整回退矩阵、Provider 真实进程参与的跨进程快照注入、真实 Guard HTTP 流量、全流程 E2E、跨应用完整接口矩阵，以及正式 P0-02 的 P95/吞吐/RSS/长稳与 20 万关系集端到端指标仍缺；确认与手工关系创建均已有进入既有发布任务链的单测证据，关系撤销接口、到期自动过期、原因审计、幂等行为及状态变化后的发布回调已实现，真实跨进程发布仍待集成验收；决策详情的 `evidence_read` 双权限门禁、脱敏边界和应用隔离 404 已由接口单测覆盖；**字段权限响应方向已落地运行时判定**（response_forbidden_field/response_sensitive_field，OBSERVE 级，见"API 安全补全第十一批"），旧字段权限 tenant 覆盖行仍透传不判定；字段权限除 `authz.forbidden_field` 外均 OBSERVE 级；规范中心 YAML/Postman/GraphQL 导入仍缺、Spec/Observed/Confirmed 三方视图仍无；值级敏感检测仅请求侧（响应侧值级与 xml/cookie/response_body 位置未消费）
  - AuthZ-01 收口补充：发布器显式回滚在恢复配置后仅在所有目标节点完成扇出时记为成功；部分节点失败与回滚状态持久化失败分别记录 `ROLLBACK_NODE_SYNC_FAILED` / `ROLLBACK_NODE_SYNC_STATE_PERSIST_FAILED`，并由 `RetryNodeSyncForVersion` 支持按版本失败目标定向恢复，相关不完整状态测试已通过。新增 `server/internal/gatewayconfig/authz_http_boundary_test.go` 与 `test/waf/scripts/authz-cross-module-contract.sh`，在独立测试进程间经生产 `CaddyClient` HTTP 交接并校验 JSON、哈希、Content-Type、PreviousValid、BOLA/BFLA 事件脱敏和源站放行；P0 runner 增加正式环境门禁，缺少匹配环境时返回退出码 3 并输出 `BLOCKED/ENVIRONMENT_UNAVAILABLE`，不启动 Docker。上述证据仍不等同 Provider 常驻服务、多节点编排、真实旧二进制、机器/网络故障、完整连续 E2E 或正式 P0-02 性能数据。
  - AUTHZ-01 恢复与环境门禁补充：`TestRetryNodeSyncVersionRecoversAfterNodeProcessRestart` 覆盖节点停止、同地址重启、新 Publisher 进程读取失败水位并定向重放完整授权快照；`test/waf/scripts/authz-cross-module-contract-gate.sh` 验证无效 Provider 地址和误用 `control:` 协议时只返回 `BLOCKED/ENVIRONMENT_UNAVAILABLE`（退出码 3），避免把测试进程交接误报为 Provider E2E。真实 Provider 常驻进程、多主机网络故障、完整连续流量和正式 P0-02 数据仍待部署环境。
  - AUTHZ-01 AZ-11 本地回归已验证：短窗口内同一对象出现超过 8 个不同主体时，候选冻结且确认路径保持拒绝，confirmed 关系不会被扇出投毒；迁移级 PostgreSQL 并发锁和候选 sweep 业务级恰好一次消费均已有锁定版本真实实例结果，跨进程连续事件流仍待集成验收。
  - AUTHZ-01 AZ-12 生效时间回归已补齐：`AuthzSnapshotStore` 保留未来 `valid_from` 的 `CONFIRMED/OWNER` 关系，`validateConfirmedAuthzRelations` 仅拒绝已过期关系，网关按本地时间过滤并在生效时刻激活；`TestLoadAPIAuthzSnapshotRetainsFutureRelationsForGatewayFiltering` 与 `internal/guardconfig` 全量测试通过。正式跨主机发布与故障恢复验收仍按任务书遗留项执行。
  - AUTHZ-01 事件落库安全边界已补齐：`SavePrimary` 在主事件 SQL 前校验授权决策，拒绝原始对象引用、原始角色声明和非法决策值，显式处理 `Details` 序列化错误，并仅持久化脱敏后的 HMAC 对象引用与角色；`TestSavePrimaryRejectsUnsanitizedAuthorizationBeforeInsert`、`TestSavePrimaryRejectsRawAuthorizationRoleBeforeInsert`、`TestSavePrimaryPersistsRedactedAuthorizationDecision`、`TestSavePrimaryRejectsUnencodableDetails` 普通与 `-race` 定向测试通过。真实跨进程事件流和正式环境验收仍待完成。
  - AUTHZ-01 发布扇出恢复语义补充：`SyncConfigToNodes` 支持取消后停止后续节点访问、对可识别瞬时 5xx/连接中断/超时/EOF 做一次重试并保留逐节点结果；显式回滚使用独立后台上下文扇出已验证恢复 JSON，仅在节点同步和状态落库均完整时报告成功，部分节点失败与状态落库失败分别记录 `ROLLBACK_NODE_SYNC_FAILED` / `ROLLBACK_NODE_SYNC_STATE_PERSIST_FAILED`。回滚保真、部分失败、记录失败、瞬时重试和节点进程重启恢复测试已通过；真实跨主机网络中断、机器重启和独立发布器编排仍待正式环境。
  - AUTHZ-01 Provider 兼容边界补充：`decodeGuardConfigSnapshot` 统一处理旧快照缺失可选字段和新快照未知授权分片，独立 Provider 测试进程通过 HTTP/受限 `control:` 协议返回归一化授权快照，跨模块控制协议门禁已通过；正式 Provider 服务、真实旧二进制节点组合和跨主机发布链路仍待集成环境。
  - 网关→管理面方向仍为单向日志采集（与既有架构一致）；**多节点遥测校验 v1 已落地**（事件携带 gateway_node/policy_version/model_version 落列聚合，见"API 安全补全第十二批"），**心跳活性（第十七批）与配置面主动同步 v2（第十八批发布扇出）已落地**，节点注册握手与全量产物分发未启动；WAF 纯形态回归以 stage5 既有测试套件为准
  - P1 残余如实声明：P1-01 态势已补齐（第九批：overview 12 指标 + trends 六曲线；**第十批：sources/targets 访问维度五榜单**，UA 族维度因 api_runtime_events 无 UA 列如实不做；Shadow 趋势未做）；AI 定时运营已落地五种任务（见第七/八批）但工作流框架/连续失败熔断/ai_recommendations 流转未做；P1-03/04/06/07/08/09/10 已落地（见第七~十一批，文件下载观测仅覆盖带 filename 的 Content-Disposition 响应、出境数据源无 ASN、报告调度器未做、通知渠道以 syslog 外发为主）
  - P2 终态如实声明：六项已按最小可行子集交付 v1——P2-01 文件水印（文本族 + OOXML 子集，pdf 显式拒绝）、P2-02 文件签名（文本族 + OOXML ZIP 注释 jzsig1，见 WP2-L）、P2-03 文件合规（双相位，下载直通诚实降级）、P2-04 LLM API 安全（观测不落原文 + MCP 内容级）、P2-05 gRPC（帧结构校验，**描述符级消息解析未做**）、P2-07 源码 API 发现（Go 四字面量形态）；**P2-06 HTTP/3 深度解析未做**（第十四批已落地协议版本可见性：事件 proto 字段）；性能最小矩阵已实测（第十八批：Baseline Proxy 5337 QPS/p95 9ms vs Full OBSERVE 3540 QPS/p95 13ms、0 失败，11.5 万事件约 6.5 分钟追平零丢失，见 docs/evidence/api-security-performance-baseline.md），多节点/大流量全矩阵仍缺，现有 stage8-test-performance 5/5 为基准测试

### APM / 业务性能监控 阶段0+阶段1（2026-08-30，迁移 000088）

设计与决策：`docs/BUSINESS_PERFORMANCE_APM_DESIGN.md`（双模式总设计）+ `docs/APM_STAGE0_ADR.md`（阶段0 ADR，含对设计文档 §2.2 过期论断的代码级核实修正：`api_call_edges` 生产写入链路在阶段8 已存在，本阶段仅复用）。

- **阶段0 出口物**：OTel/ClickHouse/首批语言（Java+Go）/W3C 信任策略等 12 项决策落 ADR；阶段1 零新增基础设施（ClickHouse 随阶段2 Agent 数据面再引入）。
- **网关（WP2）**：W3C traceparent 严格校验 + 默认新建内部 trace_id/span_id（`trace_trust_external` 默认 false 可配续接；tracestate 一律不续传、不向客户端返回、默认不向上游注入；阶段2 起新增 `trace_inject_upstream` 开关（默认关，开启后放行链路向上游注入内部 trace 上下文 `traceparent: 00-<trace_id>-<新span_id>-01`、覆盖外部伪造值、清除 tracestate；发布侧下发已就位、取值来源待管理面接线））；RequestContext 死字段桥接（TraceID/SpanID/ApplicationID/Domain/ClientIP 等）；访问日志采集点上移至 `ServeHTTP` 入口——人工封禁/黑名单/L7/CC 等前置拦截 403/429 也产生记录；记录新增 `trace_id/span_id/endpoint_key/path_template/ttfb_ms`，`waf_action` 收口 ALLOW/OBSERVE/BLOCK 三态；API 运行时事件补 `trace_id` 关联键。
- **服务端数据层（WP3）**：迁移 000088（access_logs 加 5 列 + trace_id 部分索引 + `apm.overview.read`/`apm.services.read`/`apm.traces.read` 权限种子，SECURITY_ADMIN/AUDIT_ADMIN 只读三权口径）；`RunEndpointRED` 分钟级端点聚合（`http_endpoint_requests_total`/`http_endpoint_duration_ms`/`http_endpoint_ttfb_ms`，labels app/endpoint/status_class/action，Top-200 + `__OTHER__`/`__UNCLASSIFIED__` 基数护栏，delete+insert 同事务幂等重算）。
- **服务端接口（WP4）**：`server/internal/apm/` 五接口（overview/services/services/{id}/endpoints/traces/{trace_id}——访问记录 + 按 request_id 关联 WAF 事件）；`APM_ENABLED` env 开关（默认关，关闭挂 503 降级 stub）；edition 接口下发 `apm_enabled`；OpenAPI 片段 12-apm.yaml，对账 534 路由双向零差集。
- **告警（WP5）**：`ENDPOINT_LATENCY_HIGH`/`ENDPOINT_ERROR_RATE_HIGH`（最小请求量 + 连续桶持续窗口双护栏防误报，伪端点跳过，`apm_alert` 组阈值带默认值无迁移种子，仅 APM 开启时评估）；runtimehealth 补 accesslog-01 采集链路新鲜度探针（`logging.access_log_enabled` 关闭时不判停滞）。
- **前端（WP6）**：业务性能菜单组三页面（apm-overview/apm-services/apm-endpoints）+ RequireApm 能力守卫 + product store `apmEnabled`（fail-safe 默认关）；全部图表标注"数据来源：无 Agent"，`access_log_enabled=false` 时如实降级提示，`__UNCLASSIFIED__`/`__OTHER__` 特殊标注；47 个 vitest 用例。
- **验证**：server `go test -race ./internal/...` 全绿；APM 集成测试（真实 Postgres/Valkey）通过，000088 迁移实测应用；gateway 三模块构建+测试全绿；web typecheck/lint/build 通过；openapi-reconcile 双向零差集。
- **诚实遗留**：上游分段耗时无数据源，仅总耗时 + TTFB（页面如实标注，ADR D8）；端点级数据依赖既有 `logging.access_log_enabled` 开关（默认关，不翻转存量部署）；~~`apm_alert` 阈值无种子行~~（已于阶段2 迁移 000089 补种子并可经系统设置 Update API 热更）；W3C 端到端传播实测与 ClickHouse 容量压测列为阶段2 入口门禁；全量 `npm test` 基线含他人未提交改动的既有红用例（与本次无关）。

### APM / 业务性能监控 阶段2–5（2026-08-31，迁移 000089–000094）

设计与决策同前（`docs/BUSINESS_PERFORMANCE_APM_DESIGN.md`、`docs/APM_STAGE0_ADR.md`）；部署手册 `docs/APM_DATA_PLANE_DEPLOYMENT.md`，运维/排障/接入三手册 `docs/APM_OPERATIONS_GUIDE.md`/`docs/APM_TROUBLESHOOTING.md`/`docs/APM_ONBOARDING_GUIDE.md`。

- **阶段2 Agent 数据面（WP8–WP13）**：Agent 控制面（000089：apm_services/apm_agents/apm_enrollment_tokens/apm_agent_policies 四表 + `apm.agents.manage`/`apm.settings.manage` 权限；内置 Ed25519 CA 材料经 JIUZHANG_MASTER_KEY 加密入库；一次性令牌+CSR 注册、PoP 签名心跳/策略拉取/证书轮换、签名策略版本单调递增、撤销指纹列表；管理 API 全高风险审计）；ClickHouse 数据面交付物（deployment/apm/：001 otel_traces 标准表+分层 TTL、002 服务/端点/SQL/异常分钟聚合物化视图、003 metrics 五表；本地/中央双层 Collector 配置——脱敏双清单、tail_sampling 错误/慢/高风险优先、clickhouse exporter；镜像 digest 双架构锁定并登记 DEPENDENCIES/THIRD_PARTY）；ClickHouse 查询接口（clickhouse-go v2.48.0：`/apm/trace-search` + `/apm/traces/{trace_id}` 瀑布 otel_spans 白名单属性 + services 行 Agent 覆盖列）；网关 `trace_inject_upstream` 开关（默认关，放行链路注入内部 traceparent，覆盖伪造值、清除 tracestate；发布侧下发已就位、取值来源待管理面接线）；Go 自埋点（APM_SELF_TELEMETRY_ENABLED：otelhttp 包裹管理 API + runtime metrics 30s 导出，fail-open；Caddy 原生 tracing handler 下发开关 GATEWAY_TRACING_ENABLED，经源码核实为 http.handlers.tracing 中间件形态）。
- **阶段3 诊断下钻（WP15–WP18）**：SQL 指纹（000090 `apm.sql.read`；聚合表+原始表双源，p95 全局排序；只出指纹不出 statement）、异常指纹（两级聚合，首末出现分钟桶精度）、依赖边（CLIENT/PRODUCER span 单视角派生如实标注）；运行时指标全链路（contrib runtime 9 指标实测清单、CH 五表 DDL 对齐 exporter 官方模板、三阶段查询降采样）；SLO（000092 apm_slos；availability=1−5xx/总数、latency_p95 直方图估算；错误预算公式与 OK/AT_RISK/BREACHED 状态机；`APM_SLO_BREACH` 告警每分钟评估自动恢复）；前端五页（SQL/异常/运行时/依赖/SLO，EChart 追加 GraphChart 注册）。
- **阶段4 深度诊断（WP19/WP20）**：诊断会话控制面（000093：apm_diagnostic_sessions + `apm.diagnostics.manage` 仅 SECURITY_ADMIN + kill switch 设置种子；dry_run 预估→confirm 二次确认创建；策略叠加=基线深拷贝+diagnostics 子树、信封 expires_at 硬截止（Agent 失联本地失效兜底）；到期扫描每分钟 EXPIRED+基线恢复（baseline_restored 对账重试）；kill switch 全局终止+拒绝新建+Critical 审计；开销护栏——function_probe 需精确范围且采样率 ≤0.5）；前端诊断中心（四步创建向导、倒计时、审计关联、kill switch 危险操作二次确认）。
- **阶段5 规模化加固（WP21–WP24）**：HA 交付物（中央 router+sampler×2 双层拓扑、loadbalancing 按 traceID 路由尾采样、K8s DaemonSet/Deployment/PDB/反亲和清单、ClickHouse ReplicatedMergeTree 双副本变体、backup.md 备份恢复演练；otelcol validate 四配置实测、compose config 通过）；交付合规（SBOM 638 组件重生成、license-audit exit 0、licenses/ 六组件归档逐字节核验、ops/offline-package 纳入 APM 镜像与 apm profile 自检打包通过）；容量告警（`APM_CLICKHOUSE` 健康探针刻意不进 AllComponents 防默认部署恒 UNKNOWN、`APM_INGEST_LAG` MEDIUM 采集滞后评估、000094 `apm_alert.ingest_lag_seconds` 可热更）；notify 类别扩第九类 `apm`（ENDPOINT_LATENCY_HIGH/ENDPOINT_ERROR_RATE_HIGH/APM_SLO_BREACH）+ APM_INGEST_LAG 入 collection。
- **测试口径**：服务端单测全绿（-race）；APM 集成测试 11 套件真实 PG/Valkey 全 PASS（阶段1 回归+控制面+SLO+诊断+ingest lag）；ClickHouse 真实容器实测（DDL/物化视图/写入/三阶段查询/端到端 OTLP 冒烟）；前端 APM 范围 160+ vitest 用例全绿、typecheck/lint/build 通过；openapi-reconcile 双向零差集（558 路由）。
- **诚实遗留**：mTLS 数据面 PKI 为部署侧占位（控制面用 CA+应用层 PoP 等价认证已声明）；`trace_inject_upstream` 取值来源待管理面接线（当前恒 false 下发）；OTel 官方零代码 Agent 不内置九章注册客户端（分语言开箱 Agent 包为路线图项）；Java/.NET/Node/Python 端到端接入与 W3C 传播实测、性能预算实测（≤3% 开销）、10 倍突发/网络分区演练需部署环境，列为下一阶段入口门禁，未实测不承诺性能数字；全量 `npm test` 基线含他人未提交改动的既有红用例（与 APM 无关）；`docs/OPEN_SOURCE_COMPLIANCE.md` 现状节停在阶段6 待补记。

### AI 自动化渗透防护增强（WDSP）阶段1：Identity + Behavior + Recon（2026-09-01，迁移 000097–000099）

实施文档 `docs/WDSP_AI_PENTEST_PROTECTION_ENHANCEMENT.md`（四阶段路线，本小节为阶段1：先解决 AI 自动化侦察与低慢扫描）。配置缺省零行为变化；行为统计故障 fail-open；本阶段全部检测信号仅 OBSERVE 不拦截；LLM 不进入实时请求路径。

- **网关 `identitybehavior` 包**（jiuzhang_guard 内，`identity_behavior` 配置段 nil=零行为）：凭据（JWT/API Key/会话 Cookie，未验签仅关联）> 浏览器指纹（UA+Accept 系头 HMAC）> IP 三级派生确定性 identity_key，同一浏览器多 IP 关联同一身份；1m/5m/30m/24h 四窗双桶行为统计（请求量/状态码族/认证失败/参数变异签名 HLL/敏感路径命中/唯一 URI HLL/新 URI），Valkey 单 Lua 原子更新（`jiuzhang:guard:ibh`），故障回退进程内存（LRU 有界）；身份写入请求上下文并桥接进 WDSP RequestContext.IdentityFingerprint。
- **Recon 检测七规则**（默认 OBSERVE、规则版本 1.0.0、阈值/分值/白名单全配置化）：URI 枚举、404 枚举、敏感路径探测、方法枚举、参数变异、认证探测、低慢侦察（30m/24h 长窗）；检测器只产信号不阻断，统一待阶段3 Risk Engine 聚合处置。
- **事件通道**：`identity-events.log` JSONL（identity_observation/behavior_snapshot/recon_signal，进程内节流：观测 5min+新 IP/凭据立即、快照 60s+桶轮转、信号 60s）→ server `identityevents` 采集器断点续传批量入库 → `client_identity`/`identity_ip_history`/`identity_credential`/`behavior_statistics`/`identity_behavior_events` 五表；风险分=24h 信号加分求和（截断 [0,100]，等级 0-19/20-39/40-69/70+）；请求量按快照 1m 窗计数估算累加（估算语义）；logrotator 纳入轮转。
- **管理面**：`security_behavior_policy` 单行策略（000098，version 乐观锁、全量校验、审计、PUT 触发发布经 `identity_behavior` 段下发网关，policy_version 随行溯源）；`GET/PUT /api/v1/security/behavior-policy`、`GET /api/v1/security/identities[/{id}[/{behavior,events}]]` 六接口；权限点 `security_identities.read`、`behavior_policy.read/.edit`（000099 种子，经 000100 重划归 SECURITY_ADMIN）；OpenAPI 片段 13-identity-security.yaml，对账 564 路由双向零差集。
- **前端**：「安全风险」新分组—风险身份列表/详情（IP 历史、关联凭据、行为趋势、行为事件）；「应用防护策略」—行为策略页（阈值/敏感路径/分值/白名单，409 冲突提示、字段级错误回显、按权限禁用）。
- **验证**：gateway 两模块 `go test -race ./...` 全绿（含新包 9 个模块级测试）；server 单测全绿 + 集成测试（真实 PG/Valkey，迁移 000001→000100 全链、采集器幂等/风险重算、策略 API 全路径）PASS；web typecheck/lint/build + 10 新增用例全绿；stage5 环境实况验收——同 UA 五 IP 扫描敏感路径关联为单一身份（ip_count=5）、风险 30/MEDIUM、SENSITIVE_PATH_PROBE 与 LOW_SLOW_RECON 信号经采集入库可查，策略 PUT v2 发布下发网关生效。
- **诚实遗留**：短突发计数经 1m 桶轮转补发快照后已接近真实值，残余低估仅限全程不跨 1m 桶边界且无后续请求触发轮转快照的尾部不足一分钟量（快照节流语义，已在代码注释注明）；TLS 指纹为 ConnectionState 弱指纹（HTTP 层拿不到 ClientHello，不做 JA3/JA4）；identity_type 仅 UA 启发式；身份手工封禁/解封与 CHALLENGE 动作为阶段3+ 范围。

### AI 自动化渗透防护增强（WDSP）阶段1 强化 + 阶段2：Parser 歧义检测（2026-09-01，无新迁移）

- **阶段1 两项强化**（gateway identitybehavior，同日补做）：① identity_observation 洪泛修复——观测节流从单条目改为 16 容量已知 IP 集，扫描身份轮换 IP 时观测记录从 105 条/150 请求降到 5 条（语义测试 `TestObservationRotatingIPs`）；② 轮转快照携带完成桶计数（`Snapshot.CompletedWindow`，memory 与 Valkey Lua 同步实现，`TestSnapshotRotationEmitsCompletedBucket`），短突发请求量估算失真收敛。
- **阶段2 Parser 歧义检测**（gateway `dynamic_security/parser` + `detectors` + `pipeline`）：重复参数/键歧义识别——重复 JSON 键、重复查询参数、重复 Header、重复表单参数四类，detector=`api_parser`、统一 OBSERVE、ScoreDelta=20、Severity=MEDIUM（仅过物化门槛，不单独处置）；规则版本化（PARSER-DUP-JSON-001 等 1.0.0）。
- **服务端归集**：四类歧义经统一 Finding 通道落 `api_runtime_findings`（finding_type=PARSER_DUPLICATE_JSON_KEY/QUERY_PARAM/HEADER/FORM_PARAM）；`findings.go` safeEvidenceKeys 白名单扩 parameter_name/value_count/rule_code/path（证据去敏纪律不变）。
- **验证**：gateway/server 单测全绿；stage5 实况验收四类 finding 全部落库且 evidence 仅含白名单键。

### AI 自动化渗透防护增强（WDSP）阶段3：Risk Engine + Enforcement（2026-09-01，迁移 000101–000102）

实施文档同一（阶段3：跨信号风险累计与统一处置，设计 §15）。策略缺省 OBSERVE 零拦截；评估/存储故障 fail-open 放行；处置原因固定 `identity_risk_policy`（不伪装成规则阻断）。

- **网关 `riskengine` 包**（jiuzhang_guard 内，`risk_policy` 配置段 nil=零行为）：身份滑窗信号累加（默认窗 24h，信号=类型/分值/原因/时间），内存实现为 Valkey 故障回退与缺省路径，Valkey ZSET 单 Lua 原子入账（键前缀 `jiuzhang:guard:risk`，清窗+ZADD+容量裁剪+TTL）；信号三入口——identitybehavior 侦察信号（含 HEADLESS-001）经 SignalSink、apiprotect 统一管线 DetectorMatch（ScoreDelta>0）经 feedRiskSignals、身份键与 identitybehavior 同算法同盐；阈值双档（block_threshold 80 / rate_limit_threshold 40+rps），OBSERVE 记 would_block/would_rate_limit 不实断、PROTECT 实断 403/429；执行点 serveGuard 步骤5.4（自动临时封禁之后、授权限速与 CC 之前），身份白名单命中零记账；RISK_POLICY_BLOCK/RATE_LIMIT 事件 60s identity+action 节流、嵌套 `risk` 证据对象（identity_key/score/risk_level/threshold/mode/policy_version/action_taken/signals 全量——可解释「为什么得 N 分」）。
- **服务端**：`security_risk_policy` 单行策略（000101，version 乐观锁、全量校验、审计、PUT 触发发布经 `risk_policy` 段下发）；`access_control_events` 加 `details` JSONB 列（同迁移）；权限 `risk_policy.read` 授 SYSTEM_ADMIN/SECURITY_ADMIN/AUDIT_ADMIN、`risk_policy.edit` 仅 SECURITY_ADMIN（000102）；`GET/PUT /api/v1/security/risk-policy`；事件采集落 details（RISK_POLICY_* 独立 event_type，action 映射 REJECT/OBSERVE，不产生 temporary_blocks、不计入 CC 统计）；OpenAPI 片段 14-risk-policy.yaml。
- **前端**：「应用防护策略」—风险策略页（模式/双阈值/信号分值覆盖/风险等级档位编辑）。
- **实况验收修复两缺陷**（stage5 实测抓出，单测均未覆盖到）：① `gatewayconfig/guard.go` buildGuardHandler 漏注入 `risk_policy` 段——快照有、网关收不到（补注入 + `risk_policy_test.go` 三用例）；② 采集解析器按扁平字段解析风险证据而网关实际嵌套 `risk` 对象——RISK_POLICY_* 事件全部解析失败被丢弃（改 `rawRiskDetail` 嵌套解析、动作列无条件映射 REJECT/OBSERVE，fixture 改为网关真实线格式）。
- **验证**：gateway `go test -race ./...` 全绿（riskengine 含 Valkey fake 测试）；server 单测+集成测试（策略 API 全路径、事件采集 details、CC 统计零污染断言 temporary_blocks=0）PASS；openapi-reconcile 零差集；stage5 实况——同身份跨请求累计（敏感路径×4+Parser 歧义+未认证=90 分）OBSERVE 记 would_block、PROTECT 后续请求实断 403 且 RISK_POLICY_BLOCK/REJECT 落库 details 完整（含 8 条信号明细）。

### AI 自动化渗透防护增强（WDSP）阶段4：Attack Session + Business Security（2026-09-01，迁移 000103–000105）

实施文档同一（阶段4：攻击链聚合与敏感业务流滥用识别，设计 §16/§12/§13）。聚合只读不改写源事件；未归属事件（降级链穷尽/NAT 歧义）跳过并计数，不建 NULL 会话；PERSISTENCE 仅占位枚举。

- **聚合器**：`attack_session`（session_key 唯一、identity_id 可空外键、risk_score/level、attack_stage 八值、OPEN/CLOSED）+ `attack_session_event`（`UNIQUE(source_table,source_id)` 幂等键）两表（000103）；60s Sweep + 30min 不活跃滑窗关会话；三类来源水位线增量拉取（security_events/api_runtime_events/identity_behavior_events + access_control_events 风险处置），request_id 首选关联、IP 反查兜底；request_count 跨源去重、security/api_runtime 双落同请求不互去（语义不同，`TestSweepOnceCrossSourceSameRequestNotDeduped`）；risk 累计截断 [0,100]。
- **阶段推断**（规则表纯函数，设计允许第一阶段规则简单推断）：行为事件 RECON-*/AUTH-FAIL-*/BIZ-* 前缀映射；运行时事件按 detector/rule 映射（waf/api_schema/api_parser→EXPLOIT、resource_access.unauthenticated_object_access→AUTHORIZATION_PROBE、authentication→AUTH_PROBE、lifecycle→DISCOVERY、sensitive.value 实值→DATA_ACCESS）；安全事件 attack_type 命中即 EXPLOIT；会话阶段取最高秩（UNKNOWN<RECON<DISCOVERY<AUTH_PROBE<AUTHORIZATION_PROBE<EXPLOIT<DATA_ACCESS<PERSISTENCE）。
- **Business 滥用三判定器**（写 identity_behavior_events event_kind=BUSINESS_ABUSE，1.0.0，OBSERVE）：BIZ-LOGIN 登录滥用（同身份多凭据哈希失败，归 AUTH_PROBE；identity_credential 无 account_id 列，以 distinct credential_hash 作多账号代理已注释高估风险）、BIZ-EXPORT 导出滥用（归 DATA_ACCESS）、BIZ-OBJENUM 对象枚举（归 AUTHORIZATION_PROBE）；冷却重跑零产出。
- **管理面**：`api_assets.business_type`（000105，13 枚举应用层校验无 DB CHECK，与 exposure 同纪律）全链路（Upsert/List 筛选/PATCH 校验，前端 EndpointDetailDrawer 可编辑）；`GET /api/v1/security/attack-sessions[/{id}]`（stage/risk_level/status/时间窗/分页，非法枚举 400、不存在 404；`attack_sessions.read` 授三角色只读，000104）；OpenAPI 片段 15-attack-sessions.yaml，对账 568 路由双向零差集；api-security 路由仅 WDSP 形态注册，attack-sessions 路由不门控。
- **前端**：「安全风险」—攻击活动列表+详情两页（阶段/等级/状态筛选、会话时间线事件分级展示、ATTACK_STAGE_META 中文元信息）。
- **实况验收修复两处**（stage5 实测）：① 阶段推断检测器名对齐网关实名（authentication/resource_access，原 auth/resource 永不命中致 AUTH/AUTHORIZATION_PROBE 丢为 UNKNOWN）；② `sensitive_data` 字段名命中（sensitive.field/in_query——正常登录携带 password 字段即触发）不再抬升 DATA_ACCESS，仅 sensitive.value 实值命中保留（文档 §44 演示链含登录失败步骤，原映射会使会话阶段永远停在 DATA_ACCESS）。
- **疑似自动化攻击标注（阶段4 补充，迁移 000106）**：`attack_session.automation_suspected` + `automation_basis` 两列——会话内有效阶段（非 UNKNOWN）≥3 且命中自动化指示信号（HEADLESS/URI枚举/404枚举/敏感路径/方法枚举/参数变异/低慢/对象枚举；AUTH_FAIL_PROBE 刻意不收防误标）即派生标注，单调 false→true 且 basis 冻结于判定时刻（`stages=命中阶段集;indicator=首个指示信号`，跨 Sweep 增量状态载体兼前端 tooltip 展示）；事件挂载路径随行维护（行为事件 signal 列驱动），历史会话不追溯；列表/详情 API 带字段，前端攻击活动两页红色徽标「疑似自动化攻击」+ 判定依据展示。stage5 实况：§44 链新会话 suspected=true、basis 含 SENSITIVE_PATH_PROBE。
- **验证（含文档 §44 最终验收场景）**：server 单测+集成测试 4 套件 PASS（验收链六类事件跨源单会话 event_count=9/EXPLOIT、迁移种子、business_type 全链路、Business 三判定器）；前端 171 用例绿；stage5 实况——/swagger+/.git+/.env+/admin → 系统判 RECON；3 次登录失败 → AUTH_PROBE；/api/user/1001~1003 枚举 → AUTHORIZATION_PROBE；SQLi（Coraza 403）→ EXPLOIT；四阶段跨源事件聚成**单一 Attack Session**（9 请求 10 事件、CRITICAL、阶段 EXPLOIT、事件时间线逐级推进可查）；配套风险引擎 OBSERVE would_block（score=100/8 信号）与 PROTECT blocked（403+REJECT 落库）同链可复现。

### 阶段4–8 任务书审计清单补齐（2026-09-10，三波并行开发）

审计清单与逐条证据见 [STAGE_4_8_PENDING_ITEMS.md](tasks/STAGE_4_8_PENDING_ITEMS.md)；以下为本会话实际落地项（迁移编号对应 `server/migrations/`）：

- **阶段5**：事件→黑名单（§十一：accessrules 预填接口 8 字段 + Create 支持 source_type=SECURITY_EVENT + 前端确认 Modal，实库集成测试 18 用例通过）；访问控制日志三字段（§6.5，迁移 000144：`client_ip_source`/`trusted_proxy_used`/`forwarded_chain_summary` 经网关事件与访问日志全链落库读回；遗留：JWT_*/BOT_* 事件发射点不经 eventBase 未携带）；CC 配置分步向导（§二十一：RateLimitPage 四步 Steps，分步校验 + 末步摘要 + 编辑回填）；规则关联事件（§8.5：`GET /api/v1/access-rules/{id}/events` + 前端规则页抽屉）。
- **阶段6**：文件句柄监控（§10.2：API 组件 `fd_open_files`/`fd_max_open_files`/`fd_usage_percent` 三指标，阈值 80% 可配，FD_USAGE_HIGH 告警 DEGRADED→raise/UP→recover 已挂接）；告警维护窗口（§11.5，迁移 000142：`system_alert_maintenance_windows`，Raise 前抑制且 suppressed_count/last_suppressed_at 可观测，异常不放行）；请求统计补方法/Content-Type 分布（§7.1）与可信代理来源分布（§7.3；保护地址拦截统计待网关事件）；告警导出接线（§11.4：`GET /api/v1/system-alerts/export` 挂载，读权限 + 导出限流）；交付检查新增漏洞扫描项（§十六：`vulnerability_scan` 关键项，检查项 22→23，详见 [DELIVERY_ACCEPTANCE_GUIDE.md](DELIVERY_ACCEPTANCE_GUIDE.md)）；依赖许可证清单 [DEPENDENCY_LICENSES.md](DEPENDENCY_LICENSES.md)（§十七）+ license-audit 强制 licenses/ 双向同步。
- **阶段7**：AI 数据保留清理（§26.4，迁移 000141：guardjanitor 分表保留配置 + 分批限量 sweep + 引用保护，审计表因哈希链约束只归档不删）；AI 工具 `rate_limit_statistics.get`（§10.5，READ_ONLY，Tool 总数 61）；Makefile 五自动化目标（§37：ai-model-test/ai-tool-test/ai-agent-test/ai-prompt-test/stage7-test-rag）；输出截断自动续写（§11.4：finish_reason 透传 + 自动续写默认上限 2 次可配）；事件分析结构化入参（§12.1：时间/应用/IP/URI/规则/Request ID 等 7 个可选维度逐一校验）与画像结构化分支（§15.2/15.3：ip>uri>application_id 优先级真实 SQL 聚合，零数据如实"数据不足"）；What-If 扩至 3 场景（§19：disable_rule + cc_threshold/block_duration 离线统计估算，全矩阵回放引擎仍为遗留）；评估集种子（§34.1，迁移 000143：12 类×3 用例幂等，实库迁移与首轮评估运行待有库/有模型环境终验）。
- **阶段8**：规范导入五格式（§33：OpenAPI3/Swagger2/JSON Schema/Postman v2.1/GraphQL SDL，JSON/YAML 双编码，YAML 安全解码 + 外部 $ref 拒绝 + 深度/大小限制）；参数微模型统计服务端层（§16/§17，迁移 000145：观测 6 列 + 画像 14 列，蓄水池分位数/字符直方图熵/前后缀 TopN/IQR 离群 + P95 画像读回；待挂接：网关 ParamObservation 上报扩展与 apiruntime 合并写入）。

### 网络诊断工具 + NTP/DNS 网络设置（2026-09-13，迁移 000160–000162）

设计文档 [NETWORK_TOOLS_DESIGN.md](NETWORK_TOOLS_DESIGN.md)。

- **网络诊断工具**（前台「系统运维 → 网络工具」）：五种动作 ping / tcp_probe / traceroute / dns_query / capture（按需抓包 pcap 下载）。server 新模块 `server/internal/netdiag/`（handler/store/worker/types）→ 共享卷 `<GATEWAY_SIDECAR_DIR>/diag/` 文件契约（request/result/stop/capture，0600 原子写）→ `gateway/netmgrd/` diag 消费端（diag.go，1s tick 串行）执行 → server Worker（2s tick）消费落库。API：POST/GET `/api/v1/network-tools/jobs`、POST `/jobs/{id}/stop`、GET `/jobs/{id}/download`；权限 `network_tools.execute`/`network_tools.download`（000161 种子仅授 SYSTEM_ADMIN）；任务表 `netdiag_jobs`（000160，状态机 PENDING/RUNNING/SUCCESS/FAILED/STOPPED/TIMEOUT）。
- **安全模型**：目标两端校验（server + netmgrd，仅 IP/合法主机名）；tcp_probe/dns_query Go 原生，ping/traceroute/capture 系统二进制参数数组不经 shell；capture 过滤仅 proto/host/port 三元素固定模板（不开放自由 BPF）；超时硬上限（ping 30s / traceroute 60s / capture 5–300s）；pcap ≤100MB；stdout/stderr 截断 64KB；pcap 搬入 NETDIAG_DATA_DIR 并 sha256 入库，下载校验一致才放行；execute/download/stop 全量审计。
- **NTP/DNS 网络设置**（前台「系统设置 → 网络」分组）：设置键 `network.ntp_servers`（默认 pool.ntp.org）/ `network.dns_servers`（默认空=继承宿主机），逗号分隔、各 ≤4 个、逐项 IP/主机名校验（000162 种子 + settings.go 白名单）；保存网络配置时 server 合并进 network.json 新可选字段 `dns_servers`/`ntp_servers`（omitempty 向后兼容）→ netmgrd apply 落地（DNS：resolvectl → 原子重写 resolv.conf → UNSUPPORTED；NTP：timesyncd drop-in → chronyd drop-in → UNSUPPORTED）；结果回报 network-status.json 的 `dns_status`/`ntp_status`（APPLIED/UNSUPPORTED/FAILED，FAILED 计入整体失败触发周期重试，UNSUPPORTED 不计），server 原样透传前端。
- **部署**：`deployment/docker-compose.stage5.yml` 新增 netmgrd 服务（`network_mode: service:gateway` 同网络命名空间、cap_add NET_RAW/NET_ADMIN、挂同一 /var/run/caddy 卷、NODE_NAME 与 GATEWAY_NODE_NAME 一致）；镜像 `gateway/images/netmgrd/Dockerfile`（alpine digest 锁定 + iproute2/iputils/tcpdump/traceroute）；裸机额外需系统包 iputils/tcpdump/traceroute；根 docker-compose.yml 仅基座不含网关栈故未接入。
- **验证**：gateway netmgrd diag 22 例 + dns_ntp 17 例；server netdiag 集成 + settings/netconfig 校验合并；前端 NetworkToolsPage 10 例 + 系统设置 3 例（全量 945 例绿）；stage5 实测——ping/traceroute SUCCESS、tcp_probe 8081 SUCCESS / 80 正确报 connection refused、dns_query 正常、10s 抓包 50 包 pcap 下载 sha256 一致、60s 抓包手动停止 STOPPED、DNS/NTP 全链路 UNSUPPORTED 回报正确、非法 DNS 值 400 拒绝、审计风险级别正确；OpenAPI `server/openapi/fragments/20-network-tools.yaml`，openapi-reconcile 661 路由零差集。
- **诚实遗留**：diag 单节点认领（按 NODE_NAME 匹配，无跨节点编排）；capture 串行执行阻塞后续任务；容器环境 NTP/DNS 如实回报 UNSUPPORTED（该设置项面向裸机）；根 compose 未接入 netmgrd。

### AI 能力增强第一波（2026-10-21，无新迁移）

- **API_SECURITY_ANALYSIS 意图与 api_security Agent**（`server/internal/aiorchestrator/intent.go`、`server/internal/aiagents/api_agent.go`）：新增第 13 类任务类型 `API_SECURITY_ANALYSIS`——高信号词（shadow/zombie/BOLA/BFLA/越权/参数偏离/涉敏/敏感数据/影子/僵尸/弱点）直接命中，泛词（资产/态势/模型/风险/统计等）须与 api/接口/端点/字段 共现才路由（规则位置在事件分析/统计/日志之前，避免劫持普通 WAF 问题）；`CapabilityIntro` 能力介绍同步追加 API 安全条目与示例问法。Agent 事实全部来自 API 域 READ_ONLY Tool（api_posture.get / api_runtime.statistics / api_asset.search / api_risk.search / api_weakness.search / api_sensitive.search / api_learning.status / api_model.diff / api_parameter.get），经 `ToolCtx.CallTool` 调用并登记证据，不直查数据库；权限不足/Tool 停用/查询失败如实写入事实并降级继续，缺业务 ID 明确提示补充、不用猜测值顶替；尾部固定声明变更须走既有人工审核发布流程。
- **动态 Agent SyncRegistry**（`server/internal/aihandlers/agents_tools_handler.go`、`app/app.go`）：`AgentCatalog` 静态 8 个 + 装配侧 extraAgents 经 `mergeAgentCatalog` 合并（同 code 覆盖、新 code 追加），`SyncRegistry` 按 code 唯一 upsert 入 `ai_agents`（保留既有启停状态）；`api_security` 仅 `APIDynamicProtectionEnabled()` 时注册装配——纯 WAF 形态编排器与 `ai_agents` 目录均不出现，意图命中未注册 Agent 编排器跳过不产伪造事实；启停（`AgentEnabledChecker`）与 `allowed_tool_ids` 白名单（`AgentToolChecker`）管理面口径与既有 Agent 完全一致。
- **AI 定时运营任务 LLM 润色接入**（`server/internal/app/aiops_summarizer.go`）：实现 `apiops.Summarizer`，五种定时任务（API_ASSET_DIGEST/SHADOW_REVIEW/WEAKNESS_FOLLOW/RISK_DIGEST/SENSITIVE_DIGEST）摘要经模型网关低复杂度档位（`aimodel.ComplexitySimple`）润色，仅 `cfg.AI.Enabled` 时由 app.go 装配；润色只复述报告与模板草稿中的事实、输出仅展示不回灌入参；nil/失败/空输出回退模板草稿（`apiops polishSummary` 降级语义不变）。工作流框架、连续失败熔断、属主权限模型与第二批 Tool 仍为未实现缺口（docs/API_AI_OPERATIONS.md 已同步口径）。
- **前端**（web/src/）：AI 状态横幅（`layouts/AdminLayout.tsx`——任一 AI 菜单可见时 5 分钟轮询 `GET /ai/status`，停用/降级顶部 banner 明示，登出期间停轮询）；助手页 `?session_id=` 深链定位会话（`pages/ai/assistant/AssistantPage.tsx`，未找到显式报错提示归档过滤）+ 任务详情会话 ID 跳转链接（`pages/ai/tasks/AiTasksPage.tsx` → `/ai/assistant?session_id=...`）；草稿采纳/拒绝与跳转（`pages/ai/policy-recommendation/PolicyRecommendationPage.tsx`——采纳仅标记 ACCEPTED 不落配置，成功弹层按草稿类型给出 `AI_DRAFT_TARGET_ROUTES` 对应业务页跳转按钮，拒绝标记 REJECTED；`?draft_id=` 深链直接开草稿详情）；智能审计页（`pages/ai/admin/audits/AiAuditsPage.tsx`）session_id 过滤 + 草稿引用深链至策略建议页。
- **测试（本地实跑通过，2026-10-21）**：服务端 `go test`——aiagents `TestAPISecurityAgent*` 7 例、aiorchestrator `TestClassifyAPI*`/`TestCapabilityIntroMentionsAPI` 3 例、app `TestAIOpsSummarizer*` 4 例、apiops `TestPolishSummaryDegrade`/`TestRunNowWithSummarizer`、aihandlers `TestMergeAgentCatalog*` 3 例；前端 `vitest run`——AssistantPage/PolicyRecommendationPage/AiTasksPage/AiAuditsPage/AdminLayout 五文件 18 例（含会话深链用例）。
- **诚实遗留**：LLM 润色仅经假网关/降级单测验证，未在真实模型环境实测润色质量（不写成已验收）；api_security Agent 已完成 stage5 真实 API/SSE 联调（意图命中、4 个 Tool 证据、无权限 fail-closed），但未做真实模型质量评估；`AI_TASK_TYPE_META`/Agent 中文名已补齐 `API_SECURITY_ANALYSIS`/`api_security`。

### AI 能力增强第二波（2026-10-21，迁移000187）

- **Prompt 发布门真实回归**（`server/internal/aihandlers/evaluation_runner.go`、`prompts_handler.go`；迁移 000187 新增 `ai_prompt_versions.test_detail`）：版本测试由纯静态检查升级为「静态检查 + 真实回归」两段——静态检查（非空/长度 + `ValidateContent` 禁止内容扫描）不通过则 FAILED 并跳过回归（候选内容不安全不进模型）；静态通过后将候选版本内容经 `RunInput.PromptOverrides` 覆盖编排器消费点 `orchestrator_answer_summary` 的已发布 Prompt（**仅本次评估运行有效，不读写发布存储**，正常对话入口不携带），逐集串行运行 4 个种子评估集（与 `POST /api/v1/ai/evaluations/run` 共用运行器 `executeEvalSet`，真实编排链路计分）：`eval_prompt_injection`/`eval_privilege_denial`（安全类阈值 100%，000143 种子）、`eval_insufficient_data`/`eval_api_security_analysis`（一般阈值 80%，后者为 000187 新种子，固定 UUID 幂等）。单集通过判据 `case_errors==0 && score>=阈值`；模型不可用/评估集缺失/执行失败一律如实 FAILED（失败摘要 + 逐集分数/阈值/模型/run_id 落 `test_detail`），发布门 fail-closed 不伪装通过；每集回归运行落 `ai_evaluation_runs` 并关联 `prompt_version_id` 可追溯。回归整体超时 15 分钟、接口写期限放宽至 20 分钟。
- **发布门双门槛**：`aiprompts.Store.Publish` 经 `CheckPublishable` 强制 `test_result=PASSED` + `adversarial_result=ADVERSARIAL_PASSED` 齐备（对抗测试门槛为 000146 既有能力，本波补齐回归真实性），未过门返回 `PublishGateError` 携两门槛当前状态（接口层 400 友好文案，未执行显示"未执行"）。
- **AI 运营计划连续失败熔断**（`server/internal/apiops/`、`server/internal/systemalerts/rules.go`；迁移 000187 新增 `consecutive_failures`/`circuit_opened_at`/`circuit_reason` 三列）：执行结局统一经 `RecordRunOutcome` 单事务记账（成功清零、失败 +1），连续失败达 `api_ai_ops.circuit_threshold`（settings，默认 3，夹取 1-10，运行期生效）且计划仍启用时同事务熔断——`enabled=false` + 清空 `next_run_at` + 记录熔断原因（500 字符截断）；仅首次触发上报（重复失败不重复告警），触发系统告警 `AI_OPS_SCHEDULE_CIRCUIT_OPEN`（HIGH，组件 AI_OPS，事件驱动 Raise）与操作审计（`ai_schedule_circuit_open`，系统动作、高风险）；手动启用为唯一恢复入口（复位计数与熔断现场，审计如实标注熔断复位）；cron 被旁路改写不可解析的执行前失败同样走熔断记账。docs/API_AI_OPERATIONS.md 缺口口径已同步（工作流框架/计划级配额/属主权限快照/第二批 Tool/监控探针仍为规划）。
- **反馈质量聚合**（`server/internal/aihandlers/feedback_handler.go`，无新表）：`GET /api/v1/ai/feedback/summary?days=7`（权限 `ai.usage.read`，days 夹取 ≤90）按 feedback_type × task_type 聚合反馈总量/负反馈量/负反馈率（百分制两位小数）；task_type 经 LEFT JOIN LATERAL 关联反馈时刻之前最近一次 `ai_tasks`，无法关联归 UNKNOWN；聚合面不返回 comment 原文（不落用户输入明文）。
- **OpenAPI**：`server/openapi/fragments/09-ai-admin.yaml`（版本测试接口真实回归语义 + `test_detail`/回归明细 schema + `/ai/feedback/summary`）、`07-api-security.yaml`（AI 运营计划熔断三字段 + 启用接口熔断复位语义）已同步。
- **前端**（web/src/）：Prompt 管理页（`AiPromptsPage.tsx`）版本测试结果按 `test_detail` 分区展示「模型回归测试」（逐集卡片：分数/阈值/通过数/模型/失败原因 + 逐用例摘要折叠）与「静态检查」，旧版响应仅展示静态检查不冒充回归；发布门错误结构化解析展示两门槛当前状态；AI 运营计划页（`api-ai-ops/SchedulesTab.tsx`）列表新增连续失败计数与已熔断标记（Tooltip 展示熔断时间/原因），熔断计划启用前弹「重新启用（重置熔断计数）」确认，运行记录抽屉顶部展示熔断告警；质量评估页（`AiEvaluationsPage.tsx`）新增反馈质量卡片（近 7/30 天切换，任务类型 × 反馈类型聚合表，无 comment 列）。
- **测试（2026-10-21 实跑）**：服务端单测 `go test` 实跑通过——aihandlers（evaluation_runner_test.go 门径聚合/词表阈值冻结/run_id 链接 5 例 + feedback_handler_test.go 未认证/越权/days 夹取 3 例）、aiorchestrator（promptoverride_test.go：PromptOverrides 仅本次运行生效）、apiops（circuit_test.go 7 例：计数/达阈熔断/阈值夹取/端到端告警审计/默认阈值/cron 失败熔断/DTO 字段）、aiprompts（test_detail JSON 校验等）；前端 `vitest run` 实跑通过 3 文件 19 例（AiPromptTestDetail 4 + ApiAIOpsPage 12 含熔断 3 例 + AiEvaluationsPage 反馈质量 3 例）。集成测试 `server/tests/ai_quality_wave2_test.go` 6 例（000187 up/down 往返与幂等重放、熔断 SQL 语义全链、test_detail 回写、反馈聚合 UNKNOWN 兜底、回归门 mock 模型 PASSED 路径、模型不可用 FAILED fail-closed 路径）与 stage7 发布门双门槛用例**本地因无 POSTGRES_PASSWORD/VALKEY_PASSWORD 按惯例 SKIP，未经本地实跑**（CI 全量执行）。
- **诚实遗留**：回归门径语义以 mock 模型服务确定性验证，stage5 仅实测了模型不可用/回归不达标的 fail-closed 与发布 400 阻断，**未在真实可用模型（本地 Ollama/qwen2.5）环境实测**回归质量与端到端耗时（4 集串行耗时取决于模型速度）；评估集未部署的环境发布门按 fail-closed 处理（缺种子即不可发布），`eval_api_security_analysis` 种子用例未经真实模型首轮实测；熔断告警/审计接线已另经 stage5 手动 RunNow 三连失败实测（停用 + HIGH 告警 + 重新启用复位），但未做长周期真实调度运行观测；反馈质量百分制负向率已完成前后端契约修正并实机验证。

### 漏洞情报提醒 MVP（2026-10-22，迁移000189）

- **漏洞情报提醒闭环（PHP 场景）**（`server/internal/vulnintel/`：vulnintel.go 类型校验 / store.go 仓储 / nvd.go 同步器 / alert.go 提醒引擎 / settings.go 订阅设置 / handler.go 接口；设计 docs/VULN_INTEL_DESIGN.md 第一部分）：NVD 每日同步 PHP 相关漏洞——在线**纯下行**，目标地址硬编码 NVD API 2.0 `https://services.nvd.nist.gov/rest/json/cves/2.0`（不接受自定义 URL，无 SSRF 面）；`keywordSearch=php` 固定，首窗 48h、增量自上次窗口终点回拨 1h、2000 条/页、页间 7s 限速（无 API key）、单次 50 页保护上限；技术标签确定性提取（描述含 php 或 CPE `cpe:2.3:a:php:php`），severity 取全部 CVSS 指标最高分值派生、无指标 NONE。每日循环由 app.go 装配 `Syncer.RunDaily`（启动 1 分钟首轮、其后 24h 一轮），`vuln_intel.sync_enabled`（默认 false）热读，关闭空转、默认部署零行为变化；失败如实落 `vuln_intel_sync_state`（FAILED + failure_message，不刷新窗口终点下轮重试）。
- **手动同步与 JSON 导入**：`POST /api/v1/vuln-intel/sync`（5 分钟超时、并发互斥 409、失败 502，不受 sync_enabled 约束）；`POST /api/v1/vuln-intel/import`（明文 JSON 数组，body ≤4MB、单批 ≤500 条逐条校验进 invalid_entries，severity 缺省按 cvss_score 派生，source 固定 MANUAL）；两者共用 cve_id 幂等 upsert 与同一提醒引擎。
- **聚合提醒与去重**：本批新建情报按订阅过滤（settings 组 `vuln_intel`：watch_techs 默认 `["php"]` ≤10、min_severity 默认 HIGH、sync_enabled 默认 false），每技术栈合并一条 `VULN_INTEL_NEW` 系统告警（component=`vuln_intel:<tech>`，默认 HIGH、批次含 CRITICAL 升 CRITICAL；文案含最高级别/CVE 列表≤10/发布日期范围/受影响应用≤5/参考链接，1000 字符预算）；`vuln_alerted (advisory_id, tech_name)` 唯一键保证同一漏洞同一技术栈只提醒一次，提醒失败不记账、下轮重评估不漏。通知渠道固定类别 `threat_intel`（"漏洞情报"）按类别订阅接收。
- **应用技术栈手动映射**：`application_technologies` 表 + `GET/PUT /api/v1/vuln-intel/tech-assets`（整组替换语义、单事务、≤1000 应用/单应用 ≤20 标签、应用删除级联清理）；无指纹自动识别，不维护则提醒文案如实显示"未标记使用 X 的应用"。
- **权限与审计**：000189 种子 `vuln_intel.read`（SYSTEM_ADMIN+SECURITY_ADMIN）/ `vuln_intel.manage`（仅 SYSTEM_ADMIN）；写操作 CSRF + 操作审计（module=vuln_intel，sync/import/replace_tech_assets/update_settings，RiskMedium，同步失败 ResultFailure）。边界：只提醒，不自动创建 WAF 规则/虚拟补丁/阻断；无 KEV/EPSS/SBOM/签名情报包/license 门控（后续迭代）。
- **API 与前端**：9 条路由（overview/advisories 列表与详情/sync/import/tech-assets GET+PUT/settings GET+PUT），OpenAPI `server/openapi/fragments/21-vuln-intel.yaml`；前端 `/vuln-intel`（菜单「安全运营 → 漏洞情报」，`web/src/pages/vuln-intel/VulnIntelPage.tsx`）概览卡（含同步状态与失败原因）/列表过滤/详情抽屉（受影响应用）/订阅设置/技术资产/导入/手动同步，写入口按 vuln_intel.manage 隐藏。
- **测试（2026-10-23 本地实跑通过）**：服务端单测 `go test ./internal/vulnintel/`——14 个测试函数（vulnintel_test.go 校验/解析 7 例 + nvd_test.go fake NVD httptest 4 例：解析映射/首窗+增量回拨/失败落 FAILED 保留上次成功现场/并发互斥 + alert_test.go 3 例：聚合提醒/级别门槛订阅过滤/失败路径不记账）；前端 `vitest run` VulnIntelPage 13 例全绿。集成测试 `server/tests/vuln_intel_api_test.go` 5 例（TestVulnIntelAPI/APIPermissions/ImportValidation/TechAssetsReplace/Migration000189Replay）**本地因无 POSTGRES_PASSWORD/VALKEY_PASSWORD 按惯例 SKIP，未经本地实跑**（CI 全量执行）。
- **诚实遗留**：**真实 NVD 联机同步未实测**——从未对真实 services.nvd.nist.gov 发起同步，真实出站可达性/限速表现/真实响应解析均以 fake 服务端单测代替；每日定时循环仅逻辑级单测，无长周期真实调度运行观测；技术栈映射全靠手动维护；完整能力（NVD 全量库/KEV/EPSS/SBOM 匹配/ed25519 签名情报包与防回滚/license 门控）仍后续迭代。

### AI 大模型输入保护 MVP（WP3-A，迁移000195）

- **策略管理**：`api_llm_security_policies` 按应用唯一配置，`api_llm_security_policy_versions` 保存每次创建/更新的不可变快照；支持 OBSERVE/PROTECT、Prompt 注入开关、PII 开关、受限话题关键词、提示词体量上限与启停；读写权限 `api_llm_security.read/manage`，安全管理员可读写、审计管理员只读，全部写操作审计。
- **发布与网关**：启用策略经 `GuardConfig.api_llm_security_policies` 随整站发布并纳入 API 版本哈希；网关按当前 application_id 选取策略。PROTECT 下高置信注入与受限话题进入 BLOCK、超体量进入 RATE_LIMIT；OBSERVE 只记录。PII 支持邮箱/身份证号/手机号，证据只含策略 ID/版本、字段路径与数据类型，不落 Prompt 原文。
- **接口与前端**：`apillm` 新增策略 CRUD、启停和版本列表；`/api-llm` 页面升级为「AI 大模型安全」，新增安全策略页签，保留原调用观测；保存/删除明确提示需经配置发布生效。
- **验证**：`apillm`、guardconfig、gatewayconfig、dynamic_security detectors/pipeline 与 jiuzhang_guard 定向测试通过；前端策略页真实 API 桩覆盖列表、新建提交与既有观测回归，类型检查、ESLint、生产构建通过；OpenAPI 757 操作双向零差。真实 stage5 已确认 000195 迁移记录、两表和两权限落库，策略未认证路由返回 401。
- **边界**：本波话题控制为关键词匹配，不冒充语义小模型；公共 parser 的多消息/数组覆盖限制仍沿用现有披露；输出内容深检、RAG 投毒防护、幻觉检测、安全代答、脱敏还原与自定义业务风险模型不在本波完成范围。

### AI 大模型输出保护（WP3-B，迁移000196）

- **策略扩展**：既有 LLM 安全策略新增 `output_content_enabled` / `output_pii_enabled`；迁移默认 false，已有策略需显式开启，新策略表单默认开启。版本快照、发布哈希和前端列表/表单同步覆盖两个开关。
- **输出检测**：`llm_output.go` 复用响应相位首次 JSON 解析产物，覆盖 OpenAI 兼容 choices/output 等文本字段；有害内容采用高置信规则，PII 复用邮箱/身份证/手机号模式。OBSERVE 只记录，PROTECT 产生 BLOCK 并由独立出口返回 403 `llm_output_protection`，不携带上游原文。流式、截断或不可解析响应产 `llm.output_not_inspected` 披露，不冒充已检测。
- **验证与边界**：detector/pipeline 覆盖正常文本、混合候选、PII、有害内容、流式披露及 PROTECT；jiuzhang_guard 真实 `serveNext` 验证 403 与事件脱敏。真实 stage5 已确认 `196|llm_output_protection` 迁移记录及两个输出开关默认 false，API/网关/ClickHouse healthy，策略未认证路由返回 401。当前为规则级输出保护，不包含语义审核模型、幻觉检测、安全代答或可逆脱敏。

### AI 单次输出 Token 预算（WP3-C，迁移000197）

- **策略与配置**：既有按应用 AI 安全策略新增 `max_output_tokens`，0=关闭预算检查，其他取值 1～1000000；迁移默认 0，既有策略行为不变。创建、部分更新、不可变版本快照、`GuardConfig.api_llm_security_policies` 发布与版本哈希均携带该值，沿用 `api_llm_security.read/manage` 权限及写操作审计；`/api-llm` 安全策略页提供列表展示、编辑和新建输入，保存后仍需整站发布。
- **运行时判定**：仅检查请求显式声明的 `max_tokens`、`max_completion_tokens`、`max_output_tokens` 正整数值，超过应用预算产 `llm.output_token_budget_exceeded`。OBSERVE 记录 OBSERVE/HIGH，PROTECT 进入既有 RATE_LIMIT 决策并由 Guard 返回 HTTP 429；证据只含策略 ID/版本、字段名、声明值和预算，不包含 Prompt。字段缺失、非数值或不大于预算时不产生该明细。
- **验证**：detectors 覆盖观察/防护、三个兼容字段、正常值、非数值、零预算与非法策略范围，定向 `-race` 通过；pipeline 验证 PROTECT 定案 RATE_LIMIT，Guard 真实 `serveNext` 验证 OBSERVE 转发及 PROTECT 429、上游未调用和事件证据；Guard 全量测试通过。`apillm`、guardconfig、gatewayconfig 测试覆盖新建、部分更新保留、版本快照和非法值；前端 5 项测试、改动文件 ESLint、typecheck 与生产构建通过，OpenAPI 758 操作双向零差。真实 PostgreSQL 回滚事务完成 000197 重复应用、down、再次 up 及默认值/非空校验，未留下字段或测试数据。
- **边界与部署状态**：这是单次请求声明的输出 Token 预算，不是模型实际消耗量、累计配额、计费或跨会话防滥用；不宣称覆盖全部模型私有字段。RAG 按用户要求保持暂停。新增 `server/tests/llm_token_budget_live_verification_test.go`，显式启用时通过本地 Unix Admin Socket 建立隔离站点，验证超限 429、观察放行、正常值和应用隔离后清理；默认跳过且尚未实际执行。两次标准镜像构建均被 Docker 内部元数据/内容存储 I/O 错误阻断，未执行部署替换；stage5 尚未应用 000197 或重建运行节点，不将处理器级验收写成已部署生效。

### AI 输入恶意内容过滤（WP3-D，迁移000198）

- **策略与检测**：既有按应用 AI 安全策略新增 `input_content_enabled`，迁移默认 false，既有策略需显式开启，新策略表单默认开启。复用输出侧高置信有害内容规则，对 `messages[].content`、结构化 content、`prompt`、`input`、`system`、`instructions` 等明确 Prompt 字段检测；命中产 `llm.input_content_violation`，证据只含策略 ID/版本、字段路径与规则名，不落 Prompt 原文。
- **处置与界面**：OBSERVE 记录 OBSERVE/MEDIUM，PROTECT 进入统一 BLOCK 决策并返回 HTTP 403，不调用上游。策略创建、部分更新、不可变快照、GuardConfig 发布及 `/api-llm` 列表/表单同步覆盖该开关，沿用 `api_llm_security.read/manage` 权限与写操作审计。
- **验证与边界**：detectors 覆盖观察/防护、六种字段、正常防御性提问、关闭开关及旧行为，detectors 全量 `-race`、pipeline、Guard 全量与真实 `serveNext` 阻断/脱敏测试通过；apillm/guardconfig/gatewayconfig 测试、前端 5 项测试、改动文件 ESLint、typecheck、生产构建及 OpenAPI 758 操作双向零差通过。000198 迁移集成测试因未设置测试环境变量跳过，未做真实数据库回放；未进行 Docker 构建或节点部署。
- **范围边界**：这是确定性高置信规则过滤，不冒充语义分类、完整内容合规审核或安全小模型；沿用公共 parser 的标量截断与数组覆盖边界。RAG、输入改写、幻觉检测、安全代答与可逆脱敏不在本次实现范围。

### 业务弱点检测（WP1-A：凭据传输与服务器泄露）

- **凭据传输**：新增 `credential_transport.go`，对 URL 中凭据字段名生成 `credential.url_password`（PROTECT 可阻断）与 `credential.cookie_sensitive`（仅 OBSERVE）；Cookie 只在请求内存中读取名称，不读取或记录 Cookie 值。既有 sensitive.in_query 规则保留，未改变历史语义。
- **服务器泄露**：新增 `server_disclosure.go`，对 Server/X-Powered-By 等响应头产 `server.version_disclosure`，对 Java/Go/Python 堆栈及 SQLSTATE/Oracle 错误产 `server.error_disclosure`；证据不含版本原文、堆栈正文或敏感参数值。
- **弱点闭环**：新增 CREDENTIAL_IN_URL、SENSITIVE_COOKIE、SERVER_INFO_DISCLOSURE 三类派生弱点及 PostgreSQL 聚合查询，复用 apiweakness 状态机、主动验证与整改复测。
- **验证与边界**：detector/pipeline 覆盖正常与攻击请求，jiuzhang_guard 真实请求验证 URL 密码阻断和服务器泄露事件；弱点派生七类信号全部通过。参数遍历/BOLA 语义分析未在本切片扩大，避免仅凭数字 ID 误判攻击。

### 对象枚举检测（WP1-B 首个切片）

- **证据门槛**：新增 `resource.object_enumeration`，仅接受 JWT `VERIFIED` 且主体指纹非空的请求，按应用、主体、接口和对象来源/位置统计 60 秒窗口。至少 8 个不同对象且有 3 个连续递增步进，或达到 16 个不同对象时产生一次 OBSERVE 信号；正常单对象重复访问、普通列表/分页及未达到证据门槛的非连续 ID 不命中。
- **隐私与容量**：路径模板与参数语义约束之外的普通数字查询不参与统计；原始 ID 仅用于当次规范化/HMAC，状态和证据只保留 HMAC 与计数。数字前导零、UUID/hex 大小写归一，窗口键 LRU 上限 10000、每键对象集合上限 32，超时重置，同一窗口只告警一次。
- **弱点闭环**：新增 AUTHZ 分类和 OBJECT_ENUMERATION_RISK 派生弱点，复用 apiweakness 确认、整改、复测和归档；后端、AI 只读工具及前端分类筛选/OpenAPI 枚举同步扩展。
- **验证与边界**：detectors/pipeline、apiweakness/aitools/app、jiuzhang_guard 全量与对象窗口并发 `-race` 测试通过；真实 `serveNext` 验证连续对象只观察、事件 HMAC、合法列表/单对象不误报。前端 5 项测试、typecheck、lint、生产构建通过；OpenAPI 757 个操作双向零差。stage5 API/网关已按现有本地环境重建，五个核心节点均 healthy，网关 HTTP 200、新分类接口未认证 HTTP 401。对象集合窗口默认单节点内存，Valkey 共享实现见下节；对象权属判定或自动阻断不在本切片完成。

### 对象枚举多节点共享窗口（WP1-B 续）

- **共享状态**：复用 `behavior_store=valkey` 与共享引擎连接，无新增配置项，默认 `memory` 行为不变。`objenum` 命名空间对主体/应用/接口键材料再次哈希；单个 Hash 的 Lua 原子操作完成窗口重置、HMAC 引用去重、连续步进、每窗告警去重和 TTL 刷新，键和字段均不含原始对象 ID。
- **一致边界**：窗口仍为首次访问起 60 秒、最多 32 个对象引用，TTL 下限 2 分钟；内存与 Valkey 达阈规则一致。Valkey 故障按既有契约告警并降级到本地内存，恢复后不回灌故障期计数，降级期不冒充集群视图。
- **验证**：两个 Store 共享真实 Valkey 完成跨节点阈值累计，64 个并发请求只告警一次；真实 API 管线跨节点检测保持 OBSERVE。覆盖窗口过期、时钟回退、容量上限、Fail-open 和 Guard 装配；behaviorstore 全量 `-race`、Guard 全量、detectors/pipeline 回归均通过。未据此宣称端到端吞吐或海量数据容量已完成验收。

### 业务序列与重复提交弱点闭环（WP1-B 续）

- **复用实际检测**：不另建序列检测器。既有流程基线已覆盖 `flow.step_skip`、`flow.out_of_order`、`flow.illegal_state_transition`、`flow.post_cancel_operation`、`flow.anonymous_late_entry`、`flow.duplicate_submit` 和 `flow.rapid_batch`；强流程实际违规使用 `flowguard.violation`。
- **派生边界**：新增 `FLOW_SEQUENCE_DEVIATION`（HIGH）与 `FLOW_REPLAY_OR_BURST`（MEDIUM），均归入 AUTHZ。只有事件 Details 中存在上述有效检测明细才聚合；正常流程、未配置基线的零行为以及 `flowguard.unknown` 均不生成弱点，不把依赖缺失或证据不足当成业务攻击。
- **验证**：覆盖同端点多信号合并、正常流程零产出、UNKNOWN 排除及既有列表 HTTP 与生命周期复用；流程检测器回归通过。真实 PostgreSQL 会话内临时表验证序列违规 2 次、批量滥用 1 次，正常流程与 UNKNOWN 不计入，事务已回滚。OpenAPI 弱点码同步扩展，保持 757 个操作双向零差；stage5 管理 API 已重建，五个核心节点 healthy，网关 HTTP 200、弱点接口未认证 HTTP 401。

### 下载文件真实类型检测（WP2-A）

- **签名检测**：`filecontent.go` 在已有下载合规策略启用时，对完整缓冲的下载文件进行魔数检查，覆盖 PE/ELF 可执行文件、PHP/shell 脚本、PDF、常见图片与 ZIP/OOXML/tar/gzip 等压缩格式。`file.content_type_mismatch` 仅 OBSERVE/MEDIUM，不凭签名差异自动阻断；普通文本与合法同类型文件零行为，无下载规则时也不新增行为。
- **诚实降级**：`file.content_unrecognized` 仅 LOW 观察，不把未知格式称为明确冲突；流式、溢出无字节或截断无法识别时产 `file.content_not_inspected` INFO。截断但前缀可识别时证据限定 PREFIX_ONLY。检测只保留文件元数据、声明类别和签名类型，不落文件正文。
- **弱点闭环**：新增 `FILE_CONTENT_TYPE_MISMATCH`（SENSITIVE/MEDIUM）及 PostgreSQL 聚合，接入既有弱点整改复测；未检查与未知签名不派生该弱点。detectors/pipeline、apiweakness/app、Guard 全量及真实 `serveNext` 下载/溢出测试通过；真实数据库临时表验证冲突计数 1，其他形态不计入，事务回滚；检测器 `-race` 通过，OpenAPI 757 个操作双向零差；stage5 API/网关已重建，五个核心节点 healthy，网关 HTTP 200、弱点接口未认证 HTTP 401。
- **范围边界**：WP2-A 为下载侧固定魔数检查，上传有界前缀检测见 WP2-B；不解压审计、不查杀病毒，也不等同于完整文件格式校验或恶意文件定性。敏感内容文件画像、文件溯源和更多格式治理仍需后续工作包。

### 上传文件前缀检测（WP2-B）

- **有界采集**：multipart 保持流式解析，每个文件最多保留 512 字节前缀，按 part 记录是否完整读取；其余内容仍丢弃。前缀为 PartMeta 非导出字段，只在请求内存活，事件 JSON 不包含正文；默认单请求文件数上限 64，前缀总内存最多 32KiB，未增加整文件缓冲。
- **检测与披露**：复用 WP2-A 的签名与声明类别比对，在上传合规策略启用时产生同一 `file.content_type_mismatch`（仅 OBSERVE），并统一进入 `FILE_CONTENT_TYPE_MISMATCH` 弱点。大文件/截断仅标 PREFIX_ONLY；总请求限额提前耗尽、未知截断签名或 part 数超限时以 `file.content_not_inspected` 如实披露，不冒充完整检查。
- **验证**：覆盖正常 PNG/文本/可执行文件、伪装图片、512 字节边界、小文件完整读取、截断前缀可得与不可得、part 数与总前缀容量、事件脱敏及真实 `serveNext` 上传放行。parser/detectors `-race` 与 Guard 全量通过；真实 PostgreSQL 临时表验证上传与下载各 1 条冲突均聚合，未知/未检查不计入，事务回滚。
- **范围边界**：这是文件头魔数检测，不是全文件病毒扫描、解压审计或完整内容审核；不改变既有 EXT/MIME/文件名的 OBSERVE/BLOCK 处置语义。

### 文件敏感内容识别与资产标签（WP2-C）

- **规则与检测**：值级敏感规则新增显式 `file` 位置，未配置该位置时零行为。`filesensitive.go` 对 CSV/TSV 字段及普通文本行/键值做规则匹配；只检查完整行，支持完整小文件与上传前缀/下载缓冲的有限覆盖。`file.sensitive_content` 仅 OBSERVE，记录数据类型、等级、计数和覆盖范围，不记录匹配值。
- **预算与降级**：跨文件共享最多 512 次规则求值和 20 类命中明细；预算耗尽、非文本格式/编码、截断不完整行及 part 数溢出以 `file.sensitive_content_not_inspected` INFO 披露，不把未检查当作无敏感内容。
- **资产与弱点**：`FileObservation`/`PartMeta` 增加 `sensitive_types` 标签，采集端与扩展名高置信分类合并后写入既有 `api_file_assets.sensitive_types`，无需迁移。新增 `SENSITIVE_FILE_CONTENT`（SENSITIVE/MEDIUM）弱点并复用整改复测；管理面/API/OpenAPI/前端配置均支持 `file` 位置。
- **验证**：CSV 多字段、正常文件、截断不完整行、非法编码、跨文件预算及事件脱敏通过；真实 `serveNext` 上传/下载确认标签写入且原始值不入事件。Guard 全量与 detectors `-race`、apidata/guardconfig/apiruntime/apifiles/apiweakness 回归通过；前端 7 项测试、typecheck、lint、生产构建通过；OpenAPI 757 个操作双向零差。真实 PostgreSQL 临时表验证历史标签与新标签合并、后续未命中仍保留证据且传输次数递增，事务已回滚。
- **范围边界**：JSON/JSONL 结构化识别见 WP2-D；当前不解析 XML/OOXML 结构、不解压、不做全文语义分类。前缀或缓冲之外的文件内容不能据此宣称无敏感信息，后续需扩展结构化文件解析和溯源。

### JSON/JSONL 结构化敏感字段识别（WP2-D）

- **结构化解析**：`filesensitive_json.go` 复用现有 JSON 解析器，支持嵌套对象、数组和数字/字符串标量。JSON 文档必须完整且合法；JSONL/NDJSON 仅分析完整记录。命中证据包含字段路径、数据类型、等级、计数和覆盖范围，不包含原始值；资产标签继续复用既有 `sensitive_types` 与历史并集。
- **安全边界**：非法 JSON、重复键歧义、截断 JSON 文档及无完整 JSONL 记录时，以 `file.sensitive_content_not_inspected` 披露，不把不完整或歧义输入当作正常内容。其余 `file` 位置规则、跨文件 512 次求值/20 类明细预算及 OBSERVE 语义保持不变。
- **验证**：嵌套对象/数组、JSONL 部分截断、非法/重复键、正常 JSON、上传/下载标签与字段路径测试通过；真实 `serveNext` 上传/下载链与 Guard 全量、detectors `-race` 通过。无新增管理 API 或数据库字段，OpenAPI 契约不变。
- **范围边界**：XML 结构化识别见 WP2-E，DOCX 主文档识别见 WP2-F；其余 OOXML 格式、压缩包内容遍历或全文语义分析未覆盖。结构化路径证据用于定位，不等同于完整文件溯源或恶意文件定性。

### XML 结构化敏感字段识别（WP2-E）

- **安全解析**：`filesensitive_xml.go` 使用 Go 标准库流式 XML 解码，支持嵌套元素文本与属性值。证据采用 `contacts.contact.phone` 元素路径和 `contact.@phone` 属性路径，不保留原始文本、属性值或文件正文。资产继续写入既有 `sensitive_types` 与历史并集。
- **安全边界**：XML 必须完整合法；DTD/自定义实体、非声明处理指令、非法/截断文档、超过 32 层嵌套、2048 个 token 或 512 字符路径均不冒充完整检查。沿用显式 `file` 规则、跨文件 512 次求值/20 类明细预算及 OBSERVE 语义。
- **验证**：嵌套元素、属性、正常 XML、DTD、非法/超深文档、上传/下载标签与真实 `serveNext` 链通过；Guard 全量与 detectors `-race` 通过。无新增管理 API 或数据库字段，OpenAPI 契约不变。
- **范围边界**：DOCX 主文档识别见 WP2-F；其他 OOXML 格式、压缩包内容遍历、XSLT 转换、外部实体或全文语义分析未覆盖；XML 路径用于证据定位，不等同于完整文件溯源。

### DOCX 主文档敏感识别（WP2-F）

- **有限结构覆盖**：`filesensitive_docx.go` 使用 Go 标准库 ZIP 读取 `word/document.xml`，复用 XML 流式检测。命中证据范围为 `DOCX_MAIN_DOCUMENT`，保留 XML 字段路径、数据类型、等级和计数，不落正文；资产标签继续复用 `sensitive_types` 与历史并集。
- **ZIP 安全边界**：仅完整包可解析，包体最多 32 MiB、最多 64 个条目、单部件 XML 最多 8 MiB。截断包、加密包、缺主文档、异常 ZIP/XML、超限均以 `file.sensitive_content_not_inspected` 披露，不读取媒体、不解压到磁盘；WP2-I 新增的页眉页脚及聚合限制见后文，未覆盖部件不视为已检查。
- **验证**：真实 ZIP 样本、正常文档、截断、加密标志、缺失主文档、非法包、过多条目、声明超大主文档及上传/下载标签均通过；detectors `-race` 通过。无新增管理 API 或数据库字段，OpenAPI 契约不变。
- **范围边界**：WP2-F 为主文档基线，XLSX 单元格识别见 WP2-G，页眉页脚扩展见 WP2-I，批注/脚注/尾注扩展见 WP2-J；媒体遍历或完整文件溯源未覆盖，不把主文档命中描述为整个压缩包均已完成检测。

### XLSX 共享字符串与单元格敏感识别（WP2-G）

- **单元格证据**：`filesensitive_xlsx.go` 读取 `xl/workbook.xml`、工作簿关系、`xl/sharedStrings.xml` 与工作表 XML，支持共享字符串索引、富文本拼接和内联文本。命中定位到 `工作表!单元格`，只保留字段路径、类型、等级和计数，不落原始值；资产标签继续复用 `sensitive_types` 与历史并集。
- **安全边界**：仅完整 ZIP 可解析，包体最多 32 MiB、最多 64 个条目、16 个工作表、4096 条共享字符串，单部件最多 8 MiB，相关工作表文本最多 16 MiB。非法索引、加密包、截断包、异常 XML 和超限均披露，不执行公式、不扫描媒体。
- **验证**：共享索引、富文本、内联文本、正常单元格、无效索引、加密包、缺失工作簿、上传/下载标签及真实 `serveNext` 链通过；detectors `-race` 通过。stage5 网关已重建，五个核心节点 healthy；`server/tests/ooxml_live_verification_test.go` 通过 Caddy Unix Admin 建立隔离临时站点，真实 multipart 上传与文件下载均为 HTTP 200，双向事件包含 `Demo!B2`、观察级类型标签且不含原始标记，下载字节保持一致，临时站点已删除。该测试默认跳过，仅在显式开启时连接本地管理 Socket；无新增管理 API 或数据库字段，OpenAPI 契约不变。
- **范围边界**：PPTX 正式幻灯片文本识别见 WP2-H；当前不支持图表/图片、批注、外部链接或完整文件溯源，仅覆盖工作簿关系可定位的工作表，不把单元格命中描述为整个压缩包已完成检测。

### PPTX 幻灯片段落敏感识别（WP2-H）

- **正式页与段落证据**：`filesensitive_pptx.go` 读取 `ppt/presentation.xml` 和实际 `ppt/slides/slideN.xml`，校验 `presentation`/`sld` 根元素，拼接每个 `a:p` 段落内跨文本运行的 `a:t` 文本。命中定位到 `slide页码!p段落序号`，只保留路径、类型、等级和计数，不落文本；资产继续复用 `sensitive_types` 与历史并集。
- **解析边界**：仅完整 ZIP 可解析，包体最多 32 MiB、64 个条目，单部件最多 8 MiB，演示文稿与幻灯片 XML 合计最多 16 MiB。每份 XML 最多 32 层、2048 个 token；截断、加密、重复幻灯片/演示文稿、非法 XML、DTD 和超限均披露未检查。WP2-H 仅覆盖正式幻灯片文本，备注页见 WP2-K；不读取批注、图表、媒体、嵌入对象或外部链接。
- **验证**：跨文本运行拼接、多幻灯片定位、正常文档、截断/加密/非法包、缺失部件、非法根元素、DTD、重复幻灯片、聚合文本超限及上传/下载标签通过；detectors/pipeline、Guard 全量与 detectors `-race` 通过。stage5 网关已重建，五个核心节点 healthy；`server/tests/ooxml_live_verification_test.go` 的 PPTX 真实上传/下载均为 HTTP 200，跨文本运行命中定位 `slide1!p1`，双向 API 事件与资产标签、脱敏证据和下载字节一致性均通过断言，临时站点已删除；XLSX 共用链路回归同时通过。测试默认跳过，仅在显式开启时连接本地管理 Socket；无新增管理 API 或数据库字段，OpenAPI 契约不变。
- **范围边界**：WP2-H 支持 PPTX 正式幻灯片文本，备注页见 WP2-K；不支持 PPTM、图表/图片、媒体遍历、宏分析或完整文件溯源，段落命中不表示整个压缩包已完成检测。

### DOCX 页眉页脚敏感识别（WP2-I）

- **来源与兼容语义**：`filesensitive_docx_parts.go` 在主文档之外读取实际 `word/headerN.xml`/`footerN.xml`，沿用流式 XML 检测。主文档继续使用 `DOCX_MAIN_DOCUMENT`，页眉页脚使用 `DOCX_HEADER_FOOTER`；证据增加 `source_part`，同类敏感数据在不同部件中保留独立来源。单文件标签取各部件并集，数据库仍沿用历史标签并集。
- **资源与完整性边界**：仅完整 ZIP 可解析，包体最多 32 MiB、64 个条目，单部件最多 8 MiB，主文档与页眉页脚 XML 合计最多 16 MiB，并在读取每个部件时执行聚合限额。重复部件、非法 XML、截断、加密和超限均披露未检查；扫描全部目标部件成功后才发出命中，不把部分 XML 解析成功冒充完整覆盖。
- **验证**：主文档回归、页眉页脚独立来源、跨部件标签并集、仅页眉上传、非法页眉、重复主文档/页眉、部件选择、聚合超限及下载 `serveNext` 事件通过；detectors/pipeline、Guard 全量与 detectors `-race` 通过。stage5 网关已重建，五个核心节点 healthy；`server/tests/docx_live_verification_test.go` 的真实上传/下载均为 HTTP 200，事件包含 `source_part=word/header1.xml`、`DOCX_HEADER_FOOTER`、`hdr.p.r.t`、观察级类型标签且不含原始标记，下载字节一致，临时站点已删除；XLSX/PPTX 共用链路回归同时通过。测试默认跳过，无新增管理 API、数据库字段或迁移，OpenAPI 契约不变。
- **范围边界**：WP2-I 提供主文档和页眉页脚基线，批注/脚注/尾注见 WP2-J；不扫描媒体、嵌入对象或外部链接，不执行宏，不把文本部件命中描述为整包审计或完整文件溯源。

### DOCX 批注脚注尾注敏感识别（WP2-J）

- **固定文本部件**：在 WP2-I 基础上增加 `word/comments.xml`、`word/footnotes.xml`、`word/endnotes.xml`，命中范围为 `DOCX_ANNOTATIONS`，并继续记录具体 `source_part` 和 XML 字段路径。不同部件的同类敏感数据保留独立证据，资产标签仍按单文件并集与历史并集处理。
- **完整性边界**：目标文本部件共享既有 32 MiB 包体、64 条目、单部件 8 MiB、聚合 16 MiB 限额。重复注释部件、非法 XML、截断、加密和超限均披露未检查；全部目标部件扫描成功后才发出命中。只选择三个固定路径，不读取 `commentsExtended.xml`、`people.xml`、媒体、嵌入对象或宏，不推断批注作者身份。
- **验证**：批注/脚注/尾注独立字段路径、标签并集、仅批注上传、非法批注、重复脚注、固定部件选择及下载 `serveNext` 来源证据通过；detectors/pipeline、Guard 全量与 detectors `-race` 通过。stage5 网关已重建，五个核心节点 healthy；`server/tests/docx_annotations_live_verification_test.go` 的真实上传/下载均为 HTTP 200，事件包含 `source_part=word/comments.xml`、`DOCX_ANNOTATIONS`、`comments.comment.p.r.t`、观察级类型标签且不含原始标记，下载字节一致，临时站点已删除；页眉、XLSX/PPTX 共用链路回归同时通过。测试默认跳过，无新增管理 API、数据库字段或迁移，OpenAPI 契约不变。
- **范围边界**：只覆盖上述三类文本内容，不包含扩展评论元数据、修订语义还原、媒体遍历或完整文件溯源；不将注释命中描述为整包检测。

### PPTX 备注页敏感识别（WP2-K）

- **独立备注证据**：在正式幻灯片基础上读取实际 `ppt/notesSlides/notesSlideN.xml`，校验 `notes` 根元素并复用 `a:p` 内跨 `a:t` 拼接。备注命中范围为 `PPTX_NOTES`，字段为 `notesSlideN!pN`，并记录具体 `source_part`；主幻灯片继续使用 `PPTX_SLIDES` 和 `slideN!pN`，同类数据在不同备注页中保留独立来源，资产标签取并集。
- **资源与完整性边界**：主文档、正式幻灯片与备注页共享 32 MiB 包体、64 条目、单部件 8 MiB、聚合 16 MiB 限额，读取每个部件时即检查。非法根元素、重复备注页、非法 XML、DTD、截断、加密和超限均披露未检查；全部目标文本扫描成功后才发出命中。只选择编号备注页，不读取备注母版、图表、媒体、嵌入对象、外部链接或宏。
- **验证**：多备注页来源、跨文本运行拼接、主幻灯片回归、仅备注上传、非法根元素、非法 XML、重复备注页及下载 `serveNext` 来源证据通过；detectors/pipeline、Guard 全量与 detectors `-race` 通过。stage5 网关已重建，五个核心节点 healthy；`server/tests/pptx_notes_live_verification_test.go` 的真实上传/下载均为 HTTP 200，事件包含 `source_part=ppt/notesSlides/notesSlide1.xml`、`PPTX_NOTES`、`notesSlide1!p1`、观察级类型标签且不含原始标记，下载字节一致，临时站点已删除；主幻灯片、DOCX 批注/页眉和 XLSX 共用链路回归同时通过。测试默认跳过，无新增管理 API、数据库字段或迁移，OpenAPI 契约不变。
- **范围边界**：只增加备注页文本，不支持备注母版语义还原、媒体遍历、宏分析或完整文件溯源；不将主幻灯片或备注命中描述为整包审计。

### OOXML 文件签名与原始内容验证（WP2-L）

- **同源签名与可恢复性**：`response/signature_ooxml.go` 复用 `jzsig1.{kid}.{unixts}.{hmac_hex}`，支持 DOCX/XLSX/PPTX（MIME 与扩展名一致）。仅修改 ZIP EOCD 注释长度和注释，不重压缩或改写文档部件；封装内含原注释长度、token 长度及 Base64 原注释，`RecoverOOXMLSignedContent` 可恢复签名前精确字节。签名继续覆盖脱敏/水印后的最终交付内容，密钥、轮换和身份指纹语义不变。
- **验证与边界**：原 `/api-security/file-signature/verify` 保持哈希+token 方式，新增 `content_format=ooxml_zip` + `content_base64` 文件载荷（原始文件 ≤2 MiB，请求 ≤3 MiB），提取 token、恢复原文并复用现有 HMAC/过期/kid 校验；两种来源不得混用，文件内容不进入审计或响应。仅完整缓冲且包体 ≤32 MiB 的下载，须具备 OOXML 登记锚点，已签名幂等跳过；加密、ZIP64、异常包及注释超限返回错误并 FAIL_OPEN 直通。
- **验证**：三种格式及原注释（含 EOCD 字样）往返恢复、重复签名、内容篡改、非法包、注释超限、ZIP64、下载 `serveNext` 与 Content-Length 修正通过；response 全量与 `-race`、Guard 全量、apifiles 真实 HTTP 正反面与输入校验通过。OpenAPI 新增可选请求字段，无新增路由/数据库迁移；Python 3.12 合并与 757 操作双向零差对账通过。stage5 网关与管理面均已重建，五个核心节点 healthy；`server/tests/ooxml_signature_live_verification_test.go` 通过 Caddy Unix Admin 隔离站点完成实际 DOCX 下载签名，HTTP 200、Content-Length 修正、ZIP 可读、签名前原始字节恢复及 `apifiles.VerifyFileToken` HMAC 校验均通过，事件含 `file.signature_embedded` 且不含 token/密钥，临时站点已删除。测试默认跳过，仅在显式开启时连接本地管理 Socket；未修改现有业务签名配置。文件合规页新增 `SignatureVerificationCard`，支持 DOCX/XLSX/PPTX 文件选择、2 MiB 限制、可选身份指纹及成功/失败元数据展示，使用原验证 API 与 `api_data.read` 权限；组件与页面共 10 项测试、改动文件 lint、typecheck 和生产构建通过。
- **范围边界**：这是 ZIP 容器注释中的完整性/来源签名，不是 Office 原生数字签名、加密或访问控制；不支持 PDF、ZIP64、加密包及超出 API 文件载荷上限的直接验证，不声称覆盖文件全生命周期溯源。

### 文件内容指纹与资产关联（WP2-M）

- **完整内容指纹**：文件观测新增 `content_sha256`，仅对完整读取的文件生成小写 SHA-256，不把前缀哈希冒充完整文件。上传侧在 multipart 流式解析中同步计算，不增加正文留存；下载侧仅对完整缓冲计算，截断、溢出和流式直通保持为空。若下载发生脱敏、水印或签名改写，Guard 在最终交付内容写出前更新指纹，保证与实际交付文件一致。
- **资产关联**：采集端将 `content_sha256` 映射到既有 `api_file_assets.sha256`，不新增表或迁移。UPSERT 使用 `COALESCE(EXCLUDED.sha256, api_file_assets.sha256)`，新观测没有完整内容时不抹除历史指纹；有完整内容时更新为最新交付文件。`GET /api-security/file-assets` 新增 `sha256` 精确过滤（64 位 hex，大小写不敏感，非法输入 400），权限与既有 `api_data.read` 不变。新增 `GET /file-assets/lineage` 按同一指纹聚合上传/下载、端点、文件名与传输时间，最多 100 条并以 `truncated` 披露超出；不包含正文，不推断所有者或业务来源。文件验证卡片在签名有效后计算所选文件 SHA-256，调用同一关联接口并由 `FileLineagePanel` 展示方向、端点、文件名、传输次数与最近观测；空结果、错误与截断如实展示，关联失败不改变签名结论。
- **文件资产台账**：新增 `ApiFileAssetsPage` 与 `/api-file-assets` 路由，归入“API 防护 / 数据安全”，沿用 `api_data.read` 权限与 WDSP 能力门控。页面真实查询 `/file-assets` 与 `/file-assets/stats`，展示上传/下载资产与传输统计，支持方向、扩展名、敏感标签、观测天数和完整内容 SHA-256 筛选；无完整指纹的资产明确标注“未完整观测”并禁用关联入口，有指纹时可打开抽屉复用 `FileLineagePanel` 查询实际上传/下载关联，不以演示数据替代真实观测。页面、关联卡片及菜单共 26 项测试、改动文件 ESLint、typecheck 与生产构建通过；尚未进行登录态浏览器交互验收。
- **验证**：覆盖小文件、超过 512 字节前缀的完整流式内容、请求截断、下载完整/截断/流式、最终签名内容指纹、入库参数与历史保留 SQL、资产过滤和输入校验；parser/pipeline/response、Guard 全量、apiruntime/apifiles 测试通过，关联查询权限/参数/截断用例通过，OpenAPI 758 操作双向零差；真实 PostgreSQL 回滚事务验证同指纹上传/下载聚合。stage5 网关与管理面均已重建，五个核心节点 healthy；共用 OOXML 隔离验收覆盖 DOCX 批注/页眉、XLSX、PPTX 正式页/备注的上传下载，均验证 HTTP 200、原始字节保持及 `content_sha256` 与完整内容一致；签名 DOCX 场景验证最终交付体指纹、原始内容恢复与 HMAC。真实 PostgreSQL 回滚事务验证空指纹不覆盖历史值，未留下测试资产。临时站点、样本、测试二进制与事件文件已清理。
- **范围边界**：内容指纹用于同一字节内容的关联与检索，不证明业务所有者、创建者或文件来源真实性，也不能替代签名、权限控制或恶意文件检测；正文仍不进入文件观测或资产表。低熵文件可能受字典猜测，指纹按敏感元数据保护，不作为公开标识。

### 响应 Schema 运行时观测面板（非 AI）

- **真实查询与入口**：`apiModelsApi.listResponseSchemas` 消费已有 `GET /api-security/endpoints/{id}/response-schemas`，在接口详情抽屉新增 `ResponseSchemaPanel`，不新增后端路由、数据库迁移或静态演示资产。按状态码展示 Content-Type、字段数、学习样本数、最近观测、完整性与结构哈希，可展开查看字段路径和类型。
- **权限与边界**：读取受 `api_model.read` 控制，无权限不发起请求；空结果与查询错误如实展示。仅显示运行时学习行，不包含响应值或模型版本快照，截断历史以“曾截断”标识，不把一级字段观测冒充完整响应审计。
- **验证**：面板真实查询、字段展开、无权限零请求、空结果和错误测试通过；接口详情集成及既有回归合计 22 项测试通过，改动文件 ESLint、typecheck 与生产构建通过。本次未进行登录态浏览器验收或节点部署；大模型相关工作保持暂停。

### API 专项报告定时调度（迁移000199，非 AI）

- **复用既有调度**：报告计划已有每日/每周/每月 UTC 执行、到期认领、任务生成、邮件与前端 CRUD，不重复开发调度器。新增可选 `api_report_type`（`API_ASSET`/`API_RISK`/`API_WEAK`/`API_SENS`），`JobReportType` 仅在明确选择时覆盖任务内容类型；周期字段仍独立用于下次执行和统计时间范围，空值保持原普通报告行为。
- **校验与管理面**：专项类型仅允许内容范围 API，未知值及 WAF/WAF_API 混配返回参数错误；存储创建、更新、列表和认领读取该字段，沿用既有 `reports.read`/`reports.create` 权限与操作审计。前端在内容范围为 API 时展示可选专项类型，列表同时显示周期和专项类型，编辑、启停保留该值，无专项配置时提交空串。
- **验证与边界**：`go test ./internal/reports` 通过，覆盖四类专项、普通计划回退、非法类型和范围；前端专项提交及既有页面 5 项测试、改动文件 ESLint、typecheck、生产构建通过；OpenAPI 758 操作双向零差。000199 迁移集成测试因测试环境变量缺失跳过，未做真实数据库回放，未在运行节点部署或实际触发专项计划。大模型相关工作保持暂停。

### 应用级资产价值聚合接口（非 AI，后端切片）

- **真实聚合**：`Store.ApplicationAssetValue` 按应用读取非忽略接口的既有 `asset_value_explain`，返回平均分、最高分、等级分布与各评分维度平均分。只消费已回填评分；无评分时 `level` 为空，`unscored_count` 如实披露，不生成虚构应用分数。应用不存在返回 404，不查询已软删除应用。
- **接口与权限**：新增 `GET /api/v1/api-security/applications/{id}/asset-value`，权限 `api_asset.read`；支持非法 ID 400、无权限 403、应用不存在 404、读取实现未装配 503 和存储失败 500。无需新增表、字段或迁移，不改变既有接口评分计算。
- **前端接线**：`ApplicationDetailPage` 新增 `ApplicationAssetValueCard`，展示平均分、最高分、接口数、评分覆盖率、综合等级、等级分布及维度均值；无评分明确显示“未评分”，无 `api_asset.read` 权限时不发起查询。覆盖率展示前四舍五入至两位小数，避免浮点格式化偏差。
- **当前边界与验证**：`go test ./internal/apiassets` 通过，覆盖 HTTP 契约、权限、异常与字段回传；前端面板、详情集成及既有应用页合计 15 项测试、改动文件 ESLint、typecheck 与生产构建通过。真实 PostgreSQL 聚合验证尚未执行（本地 PostgreSQL 容器当前未运行），未进行登录态浏览器验收或节点部署；本切片不宣称完整应用评分模型或跨应用资产治理已完成。大模型相关工作保持暂停。

### 按应用风险策略覆盖（迁移000200，非大模型）

- **策略与兼容**：既有 `risk_policy` 全局策略保留不变，新增 `security_risk_policy_overrides` 按应用保存完整的信号权重、风险等级、窗口、阻断/限速阈值与模式。无覆盖继承全局；显式禁用覆盖不继承全局处置。应用删除经外键级联删除覆盖，无新增权限点或外部依赖。
- **管理与运行时**：新增 `GET/PUT/DELETE /security/risk-policy/applications/{id}`，沿用 `risk_policy.read/edit`、全字段校验、版本乐观锁、写操作审计和现有发布回调。`risk_policy_overrides` 随 GuardConfig 进入处理器；网关复用同一风险引擎，按应用选择配置并隔离计数键，未改变原执行顺序、403/429 决策或事件证据语义。
- **前端配置**：`RiskPolicyPage` 新增 `ApplicationRiskOverridesPanel`，可选择应用、查看继承状态、按全局值新建、编辑和删除回退；新建默认观察模式，保存/删除携带版本并展示冲突与服务端校验错误。`RiskPolicyFields` 与 `riskPolicyForm` 共用输入组件、数据映射与重复信号检查，不改变原全局页面的权限、审计或提交语义。
- **验证**：覆盖接口的未认证/越权、空继承、创建、版本冲突、更新、删除与非法 scope 测试通过；发布可选读取、失败保留全局及处理器注入测试通过；Guard 覆盖阈值、事件版本、默认继承与显式停用通过，Guard 全量回归通过。前端应用覆盖创建、编辑、删除回退和无编辑权限测试，以及原全局页面回归共 9 项通过；改动文件 ESLint、typecheck 与生产构建通过。OpenAPI 762 操作双向零差。
- **未完成边界**：000200 的真实数据库回放因测试环境变量缺失跳过，未做节点部署、登录态浏览器验收或真实多节点集群验收。本次只提供按应用的确定性风险参数覆盖，不冒充通用语义风险建模或自定义业务规则编排。大模型相关工作保持暂停。

### 同设备多账号群控观察（非大模型）

- **可信输入**：`group_control.go` 只消费已完成本地信任链验证的 `JWT_VERIFIED` 主体、非空应用 ID 和被动设备指纹；缺少任一条件或 Token 未通过验证均不计数。指纹来自既有 UA/Accept 族请求头 HMAC，不新增客户端采集。
- **观察信号**：按应用与设备指纹在自然分钟窗口内统计不同可信主体，默认达到 3 个时产生 `behavior.shared_device_accounts`，类别为 `OBSERVE`、严重度 `MEDIUM`、`ScoreDelta=10`、置信度 0.55。证据仅包含账号数量、窗口、身份可信级别与设备指纹，不包含账号标识。
- **有界去重**：复用 `StoreOverrides.IPSpread` 的有界 distinct 集合和 `BehaviorWindow` 的自然分钟计数；同一窗口只观察一次，重复账号或超过阈值后的其他账号不重复告警，新窗口可重新观察。没有新增数据库表、管理 API、权限点或前端静态演示。
- **验证**：`go test ./detectors ./pipeline`、群控检测器 `-race` 和 Guard 全量回归通过；覆盖前两个账号不报、阈值观察、重复去重、窗口重置、应用隔离、缺少可信输入跳过、64 并发只报一次，以及真实管线在 PROTECT 模式下不直接阻断。
- **未完成边界**：默认内存为单节点有界近似；配置 `behavior_store=valkey` 时可复用现有共享通道，但故障降级为节点本地状态，不承诺跨节点恰好一次或全局完整群控视图。被动指纹不是唯一设备标识，共享设备不等于群控定罪，本信号不直接阻断，也不替代设备关联图谱、自定义业务风险模型或协同行为判定。尚未进行真实 Valkey、节点部署、容量压测或登录态浏览器验收，不宣称海量数据实时处理已完成。大模型与 RAG 相关工作保持暂停。

### 群控共享设备只读聚合（迁移000201，非大模型）

- **应用归属**：`api_runtime_events` 新增可空 `application_id` 与按应用/设备/时间的部分索引。采集端从已完成归属识别的主事件写入 UUID，非法值在落库前拒绝；旧版事件及未识别应用保持 NULL，不按同名端点猜测或回填。
- **真实只读接口**：新增 `GET /api/v1/api-security/group-control/shared-devices`，沿用 `api_runtime.read`，支持 RFC3339 时间窗、应用、设备指纹、最少账号数和分页。默认最近 24 小时、至少 3 个账号，单次最多 31 天、每页最多 100 组；非法参数 400，未装配读取器返回 503。
- **聚合与隐私**：按应用和被动设备指纹分组，仅统计 JWT VERIFIED 且含可信主体指纹的已采集事件，返回不同账号数、事件数、群控信号数、接口与网关覆盖和首末观测时间；不返回主体标识或原始账号。
- **验证**：`apisecurity`/`apiruntime`/`app` 测试通过，覆盖应用 ID 写入、旧事件 NULL、非法值拒收、真实 HTTP 权限、筛选校验、默认值、分页、响应脱敏与仓储错误；000201 静态 up/down 对账通过，OpenAPI 763 操作双向零差。
- **未完成边界**：真实 PostgreSQL 集成测试已编写，但本轮因测试环境凭据未配置而跳过，尚未完成迁移回放和聚合 SQL 实库验收。接口固定披露 `data_scope=NOTABLE_SECURITY_EVENTS`、`partial=true`，只代表已采集安全事件，不是全量流量或实际活跃账号总数；主体关联边、自定义群控规则或协同判定尚未提供，管理页面见下节。大模型与 RAG 相关工作保持暂停。

### 群控分析管理页面（非大模型）

- **入口与权限**：新增 `/api-group-control` 页面，归入“API 防护 / 关系与运行”；菜单同时接受安全管理员角色或 `api_runtime.read`，路由由 WDSP 能力门控与同一权限点保护，未新增权限点。
- **真实查询**：`ApiGroupControlPage` 经 `apiGroupControlApi` 调用共享设备聚合接口，支持时间范围、应用、设备指纹、最少可信账号数、重置和服务端分页；默认近 24 小时、3 个账号。设备指纹在前端校验 32 位十六进制并归一为小写，不使用演示数据。
- **展示与边界**：表格展示应用、设备指纹、观察账号数、群控信号、关联事件、接口与节点覆盖及首末观测。空态说明所需 JWT 信任验证与安全事件条件，接口错误显示后端消息；页面明确提示安全事件不是全量流量、被动指纹不是唯一设备标识、结果不自动封禁。
- **验证与未完成**：页面 7 项测试与菜单 18 项测试通过，覆盖真实数据、筛选、非法指纹零新增查询、重置、分页、空态、主体关联和 503；布局与阶段8元数据回归 31 项通过，改动文件 ESLint、新增页面与 API 文件 Prettier、typecheck 和生产构建通过。尚未进行登录态浏览器或真实后端联调；真实 PostgreSQL 迁移/聚合验收仍受上节环境限制。大模型与 RAG 相关工作保持暂停。

### 群控主体关联明细（非大模型）

- **限定范围读取**：新增 `GET /api/v1/api-security/group-control/shared-devices/accounts`，沿用 `api_runtime.read`。应用 UUID 与设备指纹均为必填，时间窗和分页约束与分组接口一致，防止跨应用或无范围枚举；按可信主体聚合事件、群控信号、接口数与首末观测。
- **隐私边界**：只查询 JWT VERIFIED 且主体为 32 位小写 HMAC 的记录，异常或原始账号形态不参与且不返回。响应使用 `principal_ref`，不包含原始账号、Token 或 JWT payload；主体关联列表不证明协同行为。
- **前端抽屉**：共享设备分组新增“主体关联”入口，`SharedDeviceAccountsDrawer` 沿用当前分组的时间范围并强制携带应用与设备条件，支持分页、空态和后端错误提示。切换筛选条件或重置会关闭旧抽屉，避免混看不同范围的数据。
- **验证与未完成**：`apisecurity`/`apiruntime`/`app` 测试通过，覆盖必填范围、权限、分页、响应和仓储错误；页面 7 项测试、改动文件 ESLint、typecheck 和生产构建通过，OpenAPI 764 操作双向零差。实库集成用例已扩展主体聚合断言，但仍因测试环境凭据未配置而跳过；未做登录态浏览器验收。当前是分组与主体明细，不是完整关系边图谱、自定义群控模型或协同行为判定。大模型与 RAG 相关工作保持暂停。

### 按应用群控观察阈值（迁移000202，非大模型）

- **配置与存储**：应用风险覆盖新增 `shared_device_account_limit`，0 表示默认 3 个可信账号，自定义范围 2-1000。管理接口沿用 `risk_policy.read/edit`、版本乐观锁与操作审计；全局策略不接受非零值，数据库以 CHECK 防止非法阈值。
- **发布与网关**：字段位于 `risk_policy_overrides` 的应用覆盖项、嵌套 `policy` 之外，不修改冻结的风险引擎参数。既有发布链原样携带并纳入处理器快照；Guard 按应用解析到 `pipeline.Config.SharedDeviceAccountLimit`，无覆盖保持默认，非法值告警并回退默认。
- **管理前端**：按应用覆盖表单新增“同设备账号观察阈值”，显示默认 0 的继承语义并拦截 1；全局表单不展示。该字段只调整 `behavior.shared_device_accounts` 的观察灵敏度，不改变风险模式，不直接阻断，也不提供通用自定义业务模型。
- **验证**：风险策略、发布读取、迁移管理和 Guard 测试通过；检测器与真实管线覆盖自定义 2、默认回退、应用隔离、不阻断及竞态，Guard 全量回归通过。前端覆盖与全局页面 10 项测试、改动文件 ESLint、typecheck 和生产构建通过；OpenAPI 764 操作双向零差，无新增路由。
- **未完成边界**：000202 静态 up/down 检查通过，真实 PostgreSQL 集成用例覆盖迁移重放、存储、发布读取及数据库非法值拒绝，但因测试环境凭据未配置而跳过；未做节点部署、真实发布或登录态浏览器验收。大模型与 RAG 相关工作保持暂停。

### 群控观察趋势（非大模型）

- **只读聚合**：新增 `GET /api/v1/api-security/group-control/trends`，沿用 `api_runtime.read`。按 UTC 小时或天返回达到账号阈值的共享设备分组数、群控信号数和关联安全事件数；支持时间窗、应用、设备指纹和账号阈值筛选，每个时间桶独立应用阈值。
- **时间桶边界**：范围不超过 48 小时默认按小时，否则按天；最大 31 天，非法 bucket 返回 400。仅返回真实观测桶，不补零，不把未采集时段表示为已确认无风险；数据源仍固定披露为 `NOTABLE_SECURITY_EVENTS`、`partial=true`。
- **前端趋势图**：群控分析页新增 `GroupControlTrend`，复用当前筛选条件，以两条折线展示共享设备分组与观察信号；提供加载、空态、错误和可访问文字摘要，不以 Mock 图表代替接口数据。
- **验证**：趋势参数、权限、默认时间桶、聚合错误及应用装配测试通过；页面与趋势组件 10 项测试通过，覆盖实际序列映射、无观测不生成零值及失败不绘制。改动文件 ESLint、typecheck、生产构建通过，OpenAPI 765 操作双向零差。
- **未完成边界**：实库集成用例已增加趋势断言，但因测试环境凭据未配置而跳过，尚未验证 PostgreSQL 聚合执行、容量表现或登录态浏览器展示；本功能不提供全量流量趋势或群控协同判定。大模型与 RAG 相关工作保持暂停。

### 内联 HTML 网页溯源水印（迁移000203，非大模型）

- **复用现有引擎**：`api_file_watermark` 新增可选 `include_inline_html`，沿用模板 `{ip}/{identity}/{time}/{domain}`、Content-Type 白名单、完整响应缓冲及 FAIL_OPEN 纪律，不新增媒体处理依赖。网页尾部追加渲染不可见的 HTML 溯源注释，不是可见浮层。
- **默认与发布**：迁移 000203 在 `gateway_runtime` 组新增同名布尔设置，默认 false；设置键进入更新白名单，经既有 guardconfig 校验与发布链下发。需同时启用文件水印、配置模板并把 `text/html` 加入白名单；不改变既有下载水印的默认行为。
- **处理边界**：仅处理 API 响应处理链内 2xx、无 Content-Disposition、完整可缓冲的 `text/html`；压缩、SSE、WebSocket、Range 分段、错误状态和超限均直通原文。命中仍记 `file.watermark_applied`，新增 `delivery=INLINE_HTML/DOWNLOAD` 区分，不落实际水印文本；Content-Length 按最终体修正。
- **验证**：响应引擎、guardconfig/gatewayconfig/settings/database 测试通过；真实 Guard `serveNext` 覆盖内联命中、默认关闭、下载兼容、非 HTML、错误/压缩/分段/SSE/超限直通，Guard 全量回归通过。无新增 API 路由，OpenAPI 操作数不变。
- **未完成边界**：000203 的 PostgreSQL 迁移回放用例已编写，但因测试环境凭据未配置而跳过；未做真实配置发布、节点部署或浏览器渲染验收。本切片不支持可见水印、可视化模板编辑器、非 API 链全站网页或加密/压缩内容；通用设置管理入口见下节。大模型与 RAG 相关工作保持暂停。

### 群控 Finding 证据与类型映射（非大模型）

- **物化语义**：`behavior.shared_device_accounts` 显式映射为 `SHARED_DEVICE_ACCOUNTS`，按既有 MEDIUM 规则进入风险发现。脱敏白名单补充账号数、窗口、固定可信级别与 HMAC 设备指纹，避免物化后只剩规则名。
- **隐私与展示**：原始账号标识不进入白名单，测试注入的原始账号值仍被剥除；设备指纹冗余列继续沿既有服务端形态校验。前端风险类型增加“同设备多账号”中文标签，筛选、汇总与详情复用既有映射。
- **验证与边界**：`apiruntime` 全量测试及前端元数据/阶段8共 18 项测试通过，typecheck、改动文件 ESLint 和生产构建通过。无数据库迁移、接口路径或权限变更；尚未做真实数据库风险列表与登录态浏览器验收。大模型与 RAG 相关工作保持暂停。

### 文件与水印设置入口（迁移000204，非大模型）

- **完整设置种子**：为既有 `api_file_watermark_enabled/template/content_types/json_key` 补齐默认行，分别为关闭、空模板、文本/JSON 默认白名单和 `_wm`。up 使用 `ON CONFLICT DO NOTHING` 保留用户已有值；down 只删除这四项，不误删 000203 的内联 HTML 开关。
- **管理入口**：系统设置新增“文件与水印”页签，复用 `system_settings.read/update`、逐行保存、原生布尔/字符串值和版本冲突处理；只展示 `api_file_watermark_` 前缀，不暴露无关网关运行项。页面提示逐项保存后需通过既有配置发布生效。
- **生效校验**：启用总开关时模板不能为空；开启内联 HTML 时白名单必须含 `text/html`，否则前端拦截且不发送 PUT。水印仍默认关闭，不引入可见浮层或新的接口路径。
- **验证与边界**：页面 6 项测试通过，覆盖默认关闭、非水印键过滤、模板/HTML 前置校验、原生 boolean 保存及只读权限；Prettier、ESLint、typecheck、生产构建通过。000204 静态检查及 settings/database 回归通过；真实 PostgreSQL 的幂等、保留已有值和回滚用例因测试环境凭据未配置而跳过，未做登录态浏览器或真实发布验收。大模型与 RAG 相关工作保持暂停。

### 群控设备主体关系图（非大模型）

- **真实关系投影**：新增 `SharedDeviceRelationshipGraph`，复用现有 EChart GraphChart，以共享设备为中心节点、当前主体明细页的可信账号为关联节点；节点和边保留真实事件数、群控信号与接口覆盖，不生成演示节点。HMAC 标签与可访问摘要只显示缩短前缀。
- **抽屉交互**：主体关联抽屉新增“明细列表 / 关系图”切换，默认明细列表。关系图仅消费当前页 `accountsQuery.data.items`，翻页后使用新页真实结果，不自动拼接其他页；加载、错误和空态均不绘制假关系。
- **验证**：相关页面、抽屉和关系图共 13 项测试通过，覆盖真实节点/边映射、当前页传递、HMAC 缩短、空态与错误；Prettier、ESLint、typecheck 和生产构建通过。无新增 API、数据库结构或依赖。
- **边界**：这是当前明细页的只读投影，不是全量设备关联图谱、跨页历史关系或协同行为定罪；未进行真实浏览器 Canvas 渲染、缩放或布局验收。大模型与 RAG 相关工作保持暂停。

### 文件关联身份与来源证据（非大模型）

- **补全既有字段**：文件关联接口的 `FileAsset` 本就返回 `identity_fingerprint` 与 `client_ip_masked`；前端 `ApiFileLineageItem` 已补齐类型，`FileLineagePanel` 新增“身份指纹”和“来源 IP（脱敏）”列。空身份显示“匿名”，空来源显示“未知”，不伪造用户姓名或来源。
- **溯源边界**：仍按完整 SHA-256 关联实际的上传/下载资产，并展示端点、传输次数和观测时间；身份指纹是凭据派生值，同内容关联不代表业务所有者、创建者或真实人物身份。
- **验证**：新增面板 3 项测试及关联既有回归共 11 项通过，Prettier、ESLint、typecheck 和生产构建通过。新增服务端完整 HTTP 用例覆盖上传/下载/匿名资产的身份、脱敏 IP、方向和时间，但因测试环境凭据未配置而跳过，未实际执行数据库或 HTTP 断言；未做登录态浏览器验收。无新增接口、迁移或依赖。大模型与 RAG 相关工作保持暂停。

### 文件资产身份精确过滤（非大模型）

- **真实查询条件**：`GET /api-security/file-assets` 新增可选 `identity_fingerprint`，trim 后空串不过滤、最长 128 字符，超长返回 400。PostgreSQL 使用参数化 `identity_fingerprint = $n`，count/list 共用条件；MemStore 同样使用大小写敏感等值匹配，不使用模糊/前缀匹配。
- **前端检索闭环**：文件资产台账新增“身份指纹”输入，与 SHA-256、扩展名、方向和敏感筛选共同提交；查询回到第一页，重置清除该参数，空白不发送。身份保持凭据派生指纹，不解析或拼接明文账号。
- **验证与边界**：apifiles 测试及页面 5 项测试通过，覆盖精确/前缀负例、大小写、匿名、组合过滤、分页、trim、重置和空值；Prettier、ESLint、typecheck、生产构建及 OpenAPI 765 操作双向对账通过。无新增路由、迁移、权限或依赖；真实 PostgreSQL 查询与登录态浏览器验收尚未执行。大模型与 RAG 相关工作保持暂停。

### API 路径与参数规范审计（非大模型）

- **按需真实审计**：新增 `GET /api-security/specs/{id}/audit`，权限 `api_spec.read`。读取当前版本的既有 `spec_json`，复用安全解析与操作模型，不落新表、不把审计写入导入主流程。覆盖路径占位缺声明、PATH 未必填、PATH 未出现在占位，以及 GET/DELETE 的保守敏感 QUERY 参数词表；只返回参数名和定位元数据。
- **确定性结果**：按接口/规则/参数稳定排序，返回操作数、完整问题数和 HIGH/MEDIUM 分布；items 最多 500 并以 `truncated` 披露，空结果保持 `[]`。非法 ID 400、不存在 404、已存内容解析失败 500，不返回参数值或完整规范。
- **前端管理入口**：规范列表新增“规范审计”抽屉，展示统计、中文规则标签和明细，支持空态、截断与错误提示；按版本 ID 隔离查询并校验响应，关闭清理选择，避免跨版本复用旧结果。
- **验证**：规则、排序、敏感名归一、边界截断、解析失败及 apisecurity/app 回归通过；前端新增 5 项及既有页面共 14 项测试通过，Prettier、ESLint、typecheck、生产构建通过，OpenAPI 766 操作双向零差。真实导入后 HTTP 审计用例因测试环境凭据未配置而跳过，未做登录态浏览器验收。
- **范围边界**：这是路径与参数的确定性审计，不是完整 OAS 合规检查、语义安全审计或运行时漏洞证明；未覆盖响应质量、认证设计、示例真实性或业务规范。大模型与 RAG 相关工作保持暂停。

### 规范响应声明审计扩展（非大模型）

- **新增确定性规则**：`SUCCESS_RESPONSE_MISSING`（HIGH）检查没有明确 2xx 成功响应；`ERROR_RESPONSE_MISSING`（MEDIUM）检查没有 default、4xx 或 5xx 错误响应。支持具体状态码及 2XX/4XX/5XX 类别声明；default 不计作明确成功，空 204/205 仍算成功。
- **未知语义不误报**：`SpecOperation` 新增响应状态集合与语义已知标记；只有 responses 为对象才判定，显式空对象表示已解析但无响应。缺失、null、非对象及 Postman/JSON Schema/GraphQL 等不具备此语义的格式不产生响应规则误报。
- **展示与边界**：审计抽屉新增“成功响应未声明 / 错误响应未声明”中文标签，继续展示真实严重级别、接口和说明。只评价响应声明完整性，不检查响应 Schema、示例真实性或实际运行时状态，不把它当作漏洞证明。
- **验证**：覆盖成功/错误正负例、default、空响应、204/205、类别声明、未知语义、Swagger、扩展格式、排序及截断前计数；apisecurity/app 回归通过。前端新增响应规则用例后共 15 项测试通过，Prettier、ESLint、typecheck 和生产构建通过；OpenAPI 766 操作双向零差。真实导入审计用例因测试环境凭据未配置而跳过，未做浏览器验收。大模型与 RAG 相关工作保持暂停。

### 规范审计 CSV 导出（非大模型）

- **真实结果导出**：审计抽屉新增“导出当前结果”，`specAuditCSV` 生成带 UTF-8 BOM 和标准 CRLF 行尾的 CSV，包含规范/格式、操作数、问题数、HIGH/MEDIUM、截断标记及实际返回明细。无数据、加载、错误或版本不匹配时禁用；截断时明确仅导出当前已返回部分。
- **文件与表格安全**：逗号、双引号、换行和中文按 CSV 规则转义；危险公式开头字符前置单引号。下载文件名对规范名/版本做有界清理，Blob 使用 `text/csv;charset=utf-8`，点击后移除链接并释放 Object URL，不读取规范原文或参数值。
- **验证与边界**：CSV 纯函数 12 项测试及页面/抽屉相关共 30 项测试通过，覆盖公式注入、中文/引号/CRLF、空态、截断、文件名、URL 释放和版本切换；Prettier、ESLint、typecheck 和生产构建通过。无新增接口、数据库结构或依赖；尚未进行真实浏览器下载及办公软件打开验收。大模型与 RAG 相关工作保持暂停。

### 规范鉴权安全审计（非大模型）

- **新增确定性规则**：`SECURITY_SCHEME_UNDEFINED`（HIGH）检查操作实际引用但未在 `components.securitySchemes` 定义的认证方案；`API_KEY_IN_QUERY`（HIGH）检查实际使用且定义为 `in=query` 的 `apiKey` 方案。只返回接口、规则和方案/参数定位元数据，不返回 Key 值、凭据或完整规范。
- **继承与未知边界**：支持全局 `security` 继承及操作级 `security: []` 公开覆盖；公开操作、未配置安全要求和未使用方案不误报。Swagger 最小转换、Postman、GraphQL、JSON Schema 等目录未知或语义不适用的格式跳过鉴权规则，不把空目录当成无认证的事实。
- **契约与展示**：沿用按需审计接口、稳定排序、完整计数和最多 500 条截断契约；前端新增“认证方案未定义 / 查询参数传递 API Key”中文标签。无新增路由、权限、数据表、迁移或依赖。
- **验证与边界**：apisecurity/app 回归通过；规范相关前端 3 个文件共 31 项测试通过，Prettier、ESLint、typecheck 和生产构建通过；OpenAPI 601 路径、766 操作、1011 Schema 合并及双向对账零差。真实导入后 HTTP 审计用例因测试环境凭据未配置而跳过，未实际执行数据库及 HTTP 断言；未做登录态浏览器验收。大模型与 RAG 相关工作保持暂停。

### 响应体采样比例下发（迁移000205，非大模型）

- **管理配置到网关闭环**：新增 `gateway_runtime:api_response_sample_ratio`，默认 `1`；管理面保存、发布解析和网关装配均校验 0~1，拒绝非数字、负数、超范围、NaN 与正负 Inf。使用可空指针区分未配置与显式 `0`，避免 `omitempty` 吞掉零值。
- **真实生效语义**：统一从 `DefaultParseLimits` 生成请求/响应相位限制；`1` 保持全量解析，`0` 不解析响应体，`(0,1)` 仅对超过 `MaxBodyParseBytes` 的超大响应进行确定性前缀采样。截断落在 JSON 中间时不产出部分 Schema，原始响应体不被修改。该比例只控制 API 引擎解析，不改变访问日志捕获、gzip/br/流式响应边界。
- **发布一致性**：比例进入 handler 映射和 `api_policy_version`，WDSP 关闭时剥除；快照、回滚重放按当前设置恢复显式 `0`。000205 种子使用 `ON CONFLICT DO NOTHING` 保留既有值，无新增路由、权限或前端依赖。
- **验证与边界**：guardconfig/gatewayconfig/settings/app 回归通过；网关 Guard 全包及 dynamic_security context/pipeline 测试通过，覆盖默认、0、0.5、非法拒载、真实 serveNext 请求/响应与事件链路。OpenAPI 766 操作双向零差。两项 PostgreSQL/Valkey 集成用例因测试凭据未配置而跳过，未实际执行迁移往返、HTTP 设置和真实发布；未做跨进程、多节点或浏览器验收。大模型与 RAG 相关工作保持暂停。

### 普通 JSON 响应值级敏感检测（非大模型）

- **补齐 response_body 消费**：新增独立响应规则编译入口，保留请求侧原有位置过滤与缓存语义；普通非附件 JSON 复用响应相位首次解析根值，不二次解析。排序遍历对象并扫描所有嵌套数组元素，支持字符串、数字字面量和布尔值。
- **证据与动作**：命中产 `sensitive_data / sensitive.response_value`（OBSERVE/MEDIUM），证据只含字段路径、数据类型、等级、response_body 与 RESPONSE 方向，不保存或上报敏感值；命中写入 `SensitiveFields` 供字段权限去重，并由既有 apidata 清聚进入敏感字段台账。本规则不新增阻断或响应改写。
- **资源与边界**：复用 RE2、单值 4096 rune、512 次规则求值和 20 条值级命中上限，同时受 JSON 深度/字段数约束。无规则、请求侧位置、非 JSON、解析失败、采样 0、截断及流式不扫描；gzip/br、XML/表单普通响应不在本次扩展内。
- **验证**：detectors/pipeline/response 与 Guard 完整相关包测试通过；真实 serveNext 用例确认普通 JSON 主事件包含值级明细、PROTECT 下该观测不阻断、原始响应不变且序列化事件不含敏感值。无新增 API、数据库结构或依赖；未做真实 PostgreSQL 清聚和登录态浏览器验收。大模型与 RAG 相关工作保持暂停。

### 字符串参数固定格式候选（迁移000206，非大模型）

- **真实值格式观测**：Guard 与 mirrorcap 既有观测扩展新增 `format_sample/format_candidate`，仅对非敏感、非空且带脱敏哈希的字符串按完整值识别 UUID、EMAIL、IPV4、IPV6、DATE、DATETIME；未知格式计入分母。敏感抑制、空值、数字和布尔不产出格式字段，不上报明文。
- **保守候选聚合**：000206 为观测增加格式样本总数/候选计数，为统计画像增加候选/占比。至少 20 个合格字符串样本且唯一最高占比 ≥0.9 才生成；平手、样本不足、非法标签、旧观测及矛盾计数不生成，候选失去阈值时统计与观测约束同步撤除。
- **只读展示**：候选与占比仅进入 `observed_constraints`，不进入 recommended/confirmed、不自动阻断。接口详情参数表新增“格式候选”中文标签与百分比，缺失、旧数据、未知或非法比例显示 `-`。
- **验证与边界**：服务端全量 Go 测试通过，网关 apievents/Guard/mirrorcap 测试通过；前端接口详情 22 项测试、Prettier、ESLint、typecheck 和生产构建通过。真实 PostgreSQL/Valkey 集成用例因测试凭据未配置而跳过，迁移往返和实库统计重算未实际执行；未做登录态浏览器验收。大模型与 RAG 相关工作保持暂停。

### API 技术协议与交互模式维度（非大模型）

- **真实协议数据源**：自动分类在既有路径/方法维度之外，新增 `TECHNICAL_PROTOCOL` 与 `INTERACTION_MODE`，只消费接口已保存的 `protocol_type`；SQL Store 与 MemStore 使用同一映射，分类锁定语义不变。空协议不产出，未知协议只标 UNKNOWN_HTTP_API，不编造交互模式。
- **交互语义**：支持请求响应、远程调用、事件回调、文件传输、服务端推送、双向流六类，覆盖 REST/JSON、XML、Form、GraphQL、RPC、SOAP、Webhook、文件、WebSocket、SSE、gRPC 及历史协议值。
- **展示与验证**：用途分类表格和详情抽屉新增两维中文标签，协议复用现有 API_PROTOCOL_META，未知值保留原文。apiassets 测试、前端 6 项测试、Prettier、ESLint、typecheck 和生产构建通过；实库集成因测试凭据未配置跳过，未做登录态浏览器验收。
- **范围说明**：§34 九类用途维度均已有实现，分别使用路径启发式、已确认配置或真实观测，不能据此宣称所有维度都具备同等自动化置信度或已完成实库验收。大模型与 RAG 相关工作保持暂停。

### 数据敏感等级分类维度（非大模型）

- **真实模型投影**：新增 `DATA_SENSITIVITY`，SQL AutoClassify 仅读取当前模型 `current_model_version_id` 对应参数行的 `sensitivity_level/confidence`，按 HIGH>MEDIUM>LOW>UNKNOWN 取最高级，置信度取该级最大值并归一到 0..1；旧候选不混入。
- **未知与锁定边界**：无当前模型或无参数行不产出，不默认 NONE；MemStore 无此数据源时跳过。分类锁定检查先于查询和写入，查询/写入失败整体回滚。
- **展示与验证**：用途分类表格和详情新增数据敏感等级及高/中/低/未知中文映射。apiassets 测试、前端 7 项测试、Prettier、ESLint、typecheck 和生产构建通过；实库用例因测试凭据未配置跳过，未做真实浏览器验收。大模型与 RAG 相关工作保持暂停。

### 身份要求分类维度（非大模型）

- **真实事件观测**：新增 `IDENTITY_REQUIREMENT`，SQL AutoClassify 聚合近 30 天 `api_runtime_events` 的匿名成功（空 auth_type 且 2xx/3xx）、匿名拒绝（空 auth_type 且 401/403）与认证成功（非空 auth_type 且 2xx/3xx）。
- **保守分类**：匿名成功+认证成功为 AUTH_OPTIONAL；无匿名成功但有匿名拒绝+认证成功为 AUTH_REQUIRED；其余分别为 ANONYMOUS_ALLOWED、ANONYMOUS_REJECTED、AUTHENTICATED_OBSERVED。仅观测到认证成功不会误判为强制认证，无有效事件不产出，MemStore 无事件源不伪造。
- **展示与验证**：用途分类表格和详情显示需要/可选认证、允许匿名、匿名被拒及仅观测认证成功，均标明“观测”。apiassets 测试、前端 8 项测试、Prettier、ESLint、typecheck 和生产构建通过；实库因测试凭据未配置跳过，未做真实浏览器验收。大模型与 RAG 相关工作保持暂停。

### 业务流程阶段分类维度（非大模型）

- **启用流程声明**：新增 `BUSINESS_FLOW_STAGE`，SQL AutoClassify 仅消费启用流程的真实步骤，按每个流程的最小 sequence、空前驱和 terminal 映射 START、INTERMEDIATE、TERMINAL、START_AND_TERMINAL；多流程不同角色为 MULTI_STAGE，同角色去重且不受行序影响。
- **证据边界**：不按 step_id 或路径猜阶段名称，不将最大 sequence 自动当终点；无启用流程不产出，禁用流程不混入，MemStore 无流程数据不伪造。查询和写入失败整体回滚。
- **展示与验证**：用途分类表格和详情新增开始/中间/终点/起止一体/多阶段中文映射。apiassets 测试、前端 9 项测试、Prettier、ESLint、typecheck 和生产构建通过；实库因测试凭据未配置跳过，未做真实浏览器验收。大模型与 RAG 相关工作保持暂停。

### 风险标签分类维度（非大模型）

- **活动风险来源**：新增 `RISK_LABEL`，SQL AutoClassify 仅消费本端点 NEW/CONFIRMED/IN_PROGRESS 的 `api_runtime_findings`，按 CRITICAL>HIGH>MEDIUM>LOW>INFO 取最高级真实 finding_type，同级多个类型为 MULTI_RISK，开放类型仍限制规范形状与长度。
- **闭环清理**：同事务先计算后删除旧 RISK_LABEL 再按需写入；RESOLVED/FALSE_POSITIVE/IGNORED/ARCHIVED 或无活动发现不保留旧标签，非法活动行、删除或写入失败整体回滚，分类锁定先于任何修改。
- **展示与验证**：用途分类表格和详情新增影子/僵尸/下线、越权、模型偏离、敏感泄露、批量赋值、行为异常及多重风险中文映射，自定义类型保留原文。apiassets 测试、前端 10 项测试、Prettier、ESLint、typecheck 和生产构建通过；实库因测试凭据未配置跳过，未做真实浏览器验收。大模型与 RAG 相关工作保持暂停。

### 业务对象分类维度（非大模型）

- **真实对象模型派生**：新增 `BUSINESS_OBJECT`，SQL AutoClassify 只读取当前端点的 `api_object_models` 与 `api_endpoint_path_segments`；path 对象要求变量段并取前一处非空静态段，无法找到回退变量名，query 对象取参数名，不直接按路径猜测。
- **多对象与清理**：类型 trim+大写并限制 1–128 字符、排除控制字符；多个不同类型为 MULTI_OBJECT，同类型去重且不受行序影响。有效行任一 publishable 时置信度 0.9，否则 0.65；同事务删除旧值后按需写入，缺失不报错、非法形状回滚，分类锁定先于修改。
- **展示与验证**：用途分类表格和详情新增业务对象与多重业务对象展示，自定义类型保留原文。apiassets 测试、前端 11 项测试、Prettier、ESLint、typecheck 和生产构建通过；实库因测试凭据未配置跳过，未做真实浏览器验收。大模型与 RAG 相关工作保持暂停。

### 凭据维度每分钟限速（迁移000207，非大模型）

- **真实凭据维度**：新增 `gateway_runtime:credential_rate_per_minute`，默认空串关闭；复用管线既有加盐 `CredentialKey`，覆盖 Authorization/Token、API Key 和 Session，匿名不回退 IP，不回写原始凭据或指纹证据。
- **阈值与处置**：有界追踪器按自然分钟计数，第 N+1 次请求产 `ratelimit.credential_rate`（RATE_LIMIT/HIGH）；OBSERVE 只记录，PROTECT 由既有决策链映射 429。证据只含凭据类别、窗口计数、阈值和窗口。
- **发布一致性**：保存/发布/网关拒绝负数、非数字和小数；正数进入 handler 与 `api_policy_version`，WDSP 关闭时剥除，回滚按当前设置重放。000207 使用 `ON CONFLICT DO NOTHING` 保留已有设置，无新增路由或前端依赖。
- **共享存储**：`StoreOverrides.CredentialRateWindow` 接入既有 WindowStore；`behavior_store=valkey` 时使用独立 `credrate` 命名空间与 Lua 原子窗口，键材料继续 HashParts，不与 behavior/apiwrite/mcpcall 串计数。默认 memory 或 Valkey 故障期仍是节点本地计数，故障期与恢复后不回灌样本。
- **验证与边界**：detectors/pipeline/Guard/behaviorstore 及竞态回归通过；两个 Guard 共享存储可累计达阈，独立内存互不累计，匿名不进入存储。OpenAPI 766 操作双向零差。两项管理面实库集成因测试凭据未配置跳过；真实 Valkey 用例因 Docker 不可用跳过，未做正式多节点故障、真实发布或浏览器验收。大模型与 RAG 相关工作保持暂停。

### 对象限速共享存储与匿名边界（非大模型）

- **共享计数**：新增 `StoreOverrides.ObjectRateWindow` 和 Valkey `objrate` 独立命名空间，复用自然分钟 Lua、TTL 与告警节流。计数键仍由凭据身份、端点、对象来源/参数和 ValueHash 组成，不含原对象值；默认内存和故障降级保持独立实例。
- **匿名纠偏**：对象限速身份入参由通用 TrackingKey 改为真实 CredentialKey；匿名不再回退 IP 进入对象限速桶，避免 NAT/共享出口把不同访客合并。无凭据或无对象标识不记账，小时/日配额仍沿用原 TrackingKey 规则。
- **验证与边界**：detectors/pipeline/Guard/behaviorstore 及竞态回归通过；两个 Guard 共享存储时同身份同对象跨实例达阈，不同对象/身份隔离，PROTECT 429、OBSERVE 记录。真实 Valkey 用例因 Docker 不可用跳过，未做正式多节点故障验收；分页/批量等其余资源边界不因此改变。大模型与 RAG 相关工作保持暂停。

### 小时与日配额共享存储（非大模型）

- **定窗共享接口**：新增 `QuotaStore`、`HourlyQuota/DailyQuota` 请求级注入及独立内存构造器；保持自然小时和 UTC 自然日，跨窗重置且不保留历史样本，默认未绑定仍使用原包级内存。
- **原子配额键**：Valkey 使用 `quota_hour/quota_day` 独立命名空间，键哈希包含身份+端点及当前窗口起点；`INCR+PEXPIRE` 一次原子往返，TTL 下限 2 小时/48 小时，不复用分钟窗 HGETALL。独立内存降级、告警节流和恢复不回灌保持一致。
- **验证与边界**：detectors/pipeline/Guard/behaviorstore 及竞态回归通过；两个 Guard 共享配额时 N+1 达阈，不同身份/端点隔离，PROTECT 429、OBSERVE 记录，匿名仍按原 IP tracking 规则。真实 Valkey 用例因 Docker 不可用跳过；正式多节点故障与性能未验收。大模型与 RAG 相关工作保持暂停。

### 可信租户每分钟限速（迁移000208，非大模型）

- **可信身份来源**：新增 `tenant_rate_per_minute`，默认空串关闭；只消费 JWT 信任链 `VERIFIED` 且非空的 `VerifiedTenantID`，不信任租户请求头或参数。未验证、验证失败、缺租户和匿名请求不进入本限速。
- **计数与处置**：按 `Fingerprint(identity_salt, "jwt-tenant:"+tenant)` 在自然分钟窗口计数，第 N+1 次产 `ratelimit.tenant_rate`（RATE_LIMIT/HIGH），PROTECT 映射 429；事件不含租户原文或指纹。保存/发布/网关拒绝负数、非数字和小数，配置进入版本戳、WDSP 门控与回滚重放。
- **共享存储**：`TenantRateWindow` 使用 Valkey `tenrate` 独立命名空间及原子窗口，默认内存/故障期为独立本地实例，恢复不回灌；与其他限速命名空间隔离。
- **验证与边界**：detectors/pipeline/Guard/behaviorstore 完整测试及租户相关竞态测试通过，管理面四包回归通过；跨 Guard 共享、不可信/缺租户不触存储、租户隔离与 429 已覆盖。OpenAPI 766 操作双向零差。两项实库集成因测试凭据未配置跳过，真实 Valkey 因 Docker 不可用跳过；未做正式多节点或浏览器验收。大模型与 RAG 相关工作保持暂停。

### 操作动作每分钟限速（迁移000209，非大模型）

- **真实 ACTION 映射**：新增 `action_rate_per_minute` 与 `api_endpoint_actions` 发布段；管理面从 `api_classification_dimensions` 的 ACTION 行连接真实 endpoint_key，不按路径猜测。动作按既有 §34.2 词表校验，同端点冲突、非法值或读取失败中止发布，不用半份配置冒充成功。
- **计数与处置**：按应用 ID + 操作动作在自然分钟窗口计数，第 N+1 次产 `ratelimit.action_rate`（RATE_LIMIT/HIGH），PROTECT 429、OBSERVE 记录。空应用、未分类端点及关闭配置不参与，证据只含动作与窗口元数据。
- **发布与共享**：阈值和映射进入 handler、`api_policy_version`、WDSP 门控及回滚重放；仅启用时加载映射。`ActionRateWindow` 使用 Valkey `actionrate` 独立命名空间、TTL 和独立内存降级，默认本地、恢复不回灌。
- **验证与边界**：服务端 apiassets/settings/guardconfig/gatewayconfig/app 测试通过；网关 detectors/pipeline/Guard/behaviorstore 完整及动作竞态测试通过，覆盖应用/动作隔离、未分类、跨 Guard 429 和窗口故障边界。OpenAPI 766 操作双向零差。两项实库集成因凭据未配置跳过，真实 Valkey 因 Docker 不可用跳过；动作限速已支持内置及自定义 ACTION；自定义值统一大写，须匹配 `^[A-Z][A-Z0-9_]*$` 且不超过 64 字节，非法/超长仍拒绝。新增实库用例因 ACTION_RATE_TEST_PG_DSN 未配置而跳过。大模型与 RAG 相关工作保持暂停。

### 响应涉敏未脱敏弱点派生（非大模型）

- **新弱点码**：`SENSITIVE_RESPONSE_UNMASKED`（SENSITIVE/MEDIUM），近 24 小时内同端点包含 `sensitive.response_field` 或 `sensitive.response_value`，且未观察到 `response.mask_applied` 的事件达到 3 个样本后派生；复用现有 upsert、FIXED→REPRODUCED 和系统动作历史。
- **保守证据语义**：任一事件有成功脱敏标记即整条排除；现有事件无字段级部分脱敏对账，因此不会据此声称该事件已完全脱敏。`response.mask_failed` 不会被误当成功。弱点只表示“未观察到成功脱敏”，不代表 TLS 未加密或漏洞已证实，证据不含敏感值。
- **展示与验证**：弱点列表和详情直接展示服务端真实名称、分类、级别与既有证据摘要，页面明确观测口径。apiweakness 全量测试、前端 6 项测试、Prettier、ESLint、typecheck 和生产构建通过；实库用例因 POSTGRES_PASSWORD 未配置而跳过，未实际执行数据库断言或浏览器验收。大模型与 RAG 相关工作保持暂停。

### 业务功能分组与接口成员（迁移000210，非大模型）

- **真实实体**：新增 `api_endpoint_groups` 与 `api_endpoint_group_members`；分组归属应用，编码在应用内唯一，接口可属于多个组。创建/更新校验编码、名称、描述、启停及成员同应用关系，成员增删和删除使用真实数据库约束/事务。
- **管理与权限**：新增 `/api/v1/api-security/endpoint-groups` 下 8 个 CRUD/成员接口，`api_endpoint_group.read/manage` 权限，SECURITY_ADMIN 读写、AUDIT_ADMIN 只读；全部写操作审计，沿用认证、CSRF、标准分页和 400/404/409 错误语义。
- **管理页面**：新增 `/api-endpoint-groups`，支持应用筛选、分组新建/编辑/启停/删除、成员抽屉、真实接口搜索/添加/移除和只读模式；所有成功反馈均在真实 API 成功后发生。
- **验证与边界**：服务端全量竞态、go vet 和 API 构建通过；前端全量 171 文件/1282 项测试、lint、typecheck、生产构建通过；OpenAPI 774 操作双向零差。两项实库用例因测试凭据未配置跳过，未做真实浏览器 E2E。分组与成员数据源及后续限速发布见下节。大模型与 RAG 相关工作保持暂停。

### 接口组每分钟限速（迁移000211，非大模型）

- **真实组映射**：新增 `group_rate_per_minute` 与嵌套 `api_endpoint_groups`（application_id→endpoint_key→排序去重组码）；只消费启用分组的真实成员，不跨应用拍平，未分组/禁用组不参与。冲突、非法组码或读取失败中止发布。
- **多组计数**：当前请求对每个所属组分别计数，键为应用+组码；第 N+1 次产 `ratelimit.group_rate`（RATE_LIMIT/HIGH），PROTECT 429、OBSERVE 记录，证据只含组码与窗口元数据。
- **发布与共享**：阈值/映射进入 handler、`api_policy_version`、WDSP 门控及回滚重放，仅启用时加载。`GroupRateWindow` 使用 Valkey `grouprate` 独立命名空间、TTL 和独立内存降级，恢复不回灌。
- **验证与边界**：服务端 apigroups/settings/guardconfig/gatewayconfig/app 测试通过；网关 detectors/pipeline/Guard/behaviorstore 完整及分组竞态测试通过，覆盖多组、多应用/端点隔离和跨 Guard 429。OpenAPI 774 操作双向零差。实库集成因凭据未配置跳过，真实 Valkey 因 Docker 不可用跳过；未做正式多节点或浏览器验收。大模型与 RAG 相关工作保持暂停。

### 限速 BLOCK 与 TEMP_BLOCK 处置（迁移000212，非大模型）

- **决策动作**：新增 `api_rate_limit_action`，支持 RATE_LIMIT/BLOCK/TEMP_BLOCK；空值默认 RATE_LIMIT，OBSERVE 仍只记录。BLOCK 走既有403，TEMP_BLOCK走真实封禁而非只改文案。
- **真实封禁**：新增 `api_temp_block_seconds`（默认60，1..86400），TEMP_BLOCK 从真实IP结果写 temporaryblock.Block（Auto=true、应用归属、api_rate_limit原因和到期时间），当前请求403，后续请求由既有自动封禁入口403；发 CCTempBlockCreated，缺IP/写失败Warn不伪造创建事件。
- **发布与验证**：设置白名单、运行时加载、版本戳、WDSP门控与回滚重放贯通；decision/pipeline/Guard及管理面四包测试通过，竞态定向通过，后续真实Blocked与120秒事件验证通过。OpenAPI 774操作双向零差；实库因凭据未配置跳过。大模型与 RAG 相关工作保持暂停。

### 响应安全深化：ENCRYPT/MAP、压缩与非 JSON（迁移000213，非大模型）

- **ENCRYPT/MAP**：ENCRYPT 使用 AES-256-GCM，MAP 使用同密钥 HMAC 确定性映射；规则契约统一为 key_id/map_id，密钥经密文设置解密下发，快照脱敏且回滚重注，缺失或不匹配拒绝发布。新增授权恢复接口（api_data.manage），审计不含明文/密文/密钥；MAP 不可逆不恢复。
- **gzip/br**：捕获保留原压缩字节，限制解压大小后进入既有检测/脱敏；未修改时原字节交付，修改后按原编码重压缩并修正长度。多重编码/损坏/超限按失败策略处理，Range 不改写。Brotli 锁定 v1.3.0（MIT），依赖与许可证已登记。
- **XML/文本/SSE**：普通 XML 元素/属性与 text/plain 完整行支持 response_body 值级观测，拒绝 DTD/非法 UTF-8并限制预算；SSE 按单事件分片检测 JSON/文本 data，支持 keepalive，单事件1MiB、事件4096、流16MiB，未完结/超预算明确partial，不整流缓存、不宣称撤回或流式脱敏。
- **验证与边界**：dynamic_security、Guard 与 server 相关包测试通过，真实 serveNext 覆盖算法、gzip/br、XML/文本、SSE及组合；前端 12 项测试与生产构建通过，OpenAPI 775 操作双向零差。实库密钥发布/解密因测试凭据未配置跳过；未做真实 Caddy 长连接、浏览器互操作、压缩性能或许可证全量审计（既有 yaml 登记缺项仍在）。大模型与 RAG 相关工作保持暂停。

### 身份手工封禁与解封（迁移000214，非大模型）

- **状态与权限**：新增 `POST /security/identities/{id}/block`（reason必填≤512）和 `/unblock`，权限 `security_identities.block`（SYSTEM_ADMIN/SECURITY_ADMIN）。事务保证幂等、404和并发安全；首次封禁原因不被重复操作覆盖，HIGH审计不含身份键或原因。
- **发布与执行**：当前 BLOCKED 名单以 `{id,identity_key}` 发布并纳入版本戳、WDSP门控与回滚重放。网关在身份观测后、保护地址/白名单前按真实身份键命中即403，Bot/API/WAF不可绕过；新 `IDENTITY_MANUAL_BLOCK` 事件含记录ID与最终处置，不含身份键或凭据。
- **前端与解封**：身份详情按权限显示封禁/解封、原因校验、状态标签和真实错误，成功后重新获取详情；解封发布移除后放行，历史快照不会重封 NORMAL 身份。
- **验证与边界**：管理面四包、Guard 完整测试和前端 11 项测试通过，生产构建通过；OpenAPI 777 操作双向零差。实库迁移/封禁/审计因测试凭据未配置跳过，未做真实浏览器或跨进程发布验收。大模型与 RAG 相关工作保持暂停。

### 身份风险 CHALLENGE（迁移000215，非大模型）

- **策略与兼容**：全局及按应用风险策略新增 `challenge_threshold`，默认 0 关闭；开启时须满足 `rate_limit_threshold < challenge_threshold < block_threshold`。旧客户端省略字段保留原值，显式 0 正常保存、发布及回滚。启用时要求 `actions.risk_challenge` 能力，纯旧策略不增加发布门槛。
- **决策与执行**：风险引擎按 BLOCK → CHALLENGE → RATE_LIMIT 评估；OBSERVE 只发 `RISK_POLICY_CHALLENGE/would_challenge`，PROTECT 在风险点登记请求内部待挑战上下文，继续配额、CC，再由既有 Bot 统一步骤执行。仍走 selector、clearance、请求合格性及机器身份豁免，不修改 Bot 挑战协议。
- **安全与事件**：PROTECT 启用挑战但 Bot 缺失、OFF 或 OBSERVE 时拒绝配置；Offer 的真实 429/503 不记 challenged。只有实际 403 挑战页才记 `challenged` 并挂最终处置，采集映射 CHALLENGE 而非 REJECT。selector 范围外及不合格导航不签发 HTML，后续 JWT/API/WAF 不绕过。
- **前端**：共用风险表单支持挑战阈值、跨字段校验、旧响应补 0、应用继承和显式停用，提示 Bot PROTECT/selector 与 HTTPS GET 文档导航前提。
- **验证与边界**：服务端相关五包、riskengine 与 Guard 完整测试通过，前端风险策略 12 项、改动文件 ESLint、typecheck 和生产构建通过；OpenAPI 777 操作双向零差。000215 静态检查通过，真实 PostgreSQL 迁移因凭据未配置跳过；未做真实 Caddy、浏览器或多节点生产验收。

### 其他

阶段7 收尾优先合 `main` 再同步 `develop`；可选增强：完整 RAG、策略版本快照、多租户 AI 计费、更深度的 What-If 回放与压测归档。

独立测试工程方案（docs/INDEPENDENT_REGRESSION_TEST_AUTOMATION_DESIGN.md）的产品配合项 P-T1 已落地（2026-08-30）：全部 API 响应携带 `X-Jiuzhang-Environment` 头（取值 `APP_ENV`），`GET /api/v1/health` 无需登录返回 `environment`/`product` 字段；测试环境部署置 `APP_ENV=test`，门禁据此识别，prod/缺失即终止。
