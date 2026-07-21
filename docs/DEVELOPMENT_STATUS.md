# 开发状态

## 当前阶段

**阶段3：Web应用接入、源站、证书与网关配置发布** — 已完成
**阶段4：WAF策略和事件中心** — 待启动

## 阶段进度总览

| 阶段 | 内容 | 状态 | 完成时间 |
|------|------|------|---------|
| 阶段0 | 项目初始化 | 已完成 | 2026-07-20 |
| 阶段0.1 | 工程基线修正 | 已完成 | 2026-07-20 |
| 阶段1 | 网关技术验证 | 已完成 | 2026-07-20 |
| 阶段2 | 身份认证、三权权限与系统基础 | 已完成 | 2026-07-21 |
| 阶段3 | Web应用接入、源站、证书与网关配置发布 | 已完成 | 2026-07-21 |
| 阶段4 | WAF策略和事件中心 | 未开始 | - |
| 阶段5 | 访问控制和CC防护 | 未开始 | - |
| 阶段6 | 首页和安全报表 | 未开始 | - |
| 阶段7 | 质量和交付 | 未开始 | - |

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

## 测试

**阶段3新增：后端单元 28 + 接口集成 9 + 前端 33 + E2E 1 + 真实网关验证 6 = 77 用例全部通过（阶段2回归 41 用例同步通过）。**

## 遗留问题

1. 开发环境管理面使用 HTTP，生产必须启用 HTTPS 且 `COOKIE_SECURE=true`（配置已强制 prod 校验）；
2. 审计哈希链为基础防篡改（数据库 RULE 禁改删 + 哈希链），未含可信时间戳/外部存证（后续可选）；
3. 前端 antd 全量引入单 chunk 较大，未做代码分割（后续阶段优化）；
4. 阶段3后端未提供证书绑定/解绑独立 HTTP 接口（`certificates.bind` 权限已预留、`Store.BindApplication` 已实现但暂无独立路由，绑定在应用详情内通过证书选择完成，后续可补充独立接口）；
5. 源站主动健康检查由 Caddy reverse_proxy health_checks 承担，独立健康检查调度与历史展示在后续增强；
6. 发布验证为基础检查（Caddy admin 可用 + 配置加载），源站级发布后健康验证在后续增强；
7. 阶段3 macOS 开发环境后端需容器化访问网关 socket（bind mount 不支持 unix socket），生产 Linux 部署通过共享卷正常。

## 下一步

阶段4：WAF策略和事件中心（策略管理、规则配置、安全事件中心）。
