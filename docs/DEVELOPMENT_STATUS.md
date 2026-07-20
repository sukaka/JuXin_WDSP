# 开发状态

## 当前阶段

**阶段1：网关技术验证** — 已完成
**阶段2：用户权限和系统基础** — 待启动

## 阶段进度总览

| 阶段 | 内容 | 状态 | 完成时间 |
|------|------|------|---------|
| 阶段0 | 项目初始化 | 已完成 | 2026-07-20 |
| 阶段0.1 | 工程基线修正 | 已完成 | 2026-07-20 |
| 阶段1 | 网关技术验证 | 已完成 | 2026-07-20 |
| 阶段2 | 用户权限和系统基础 | 未开始 | - |
| 阶段3 | 应用接入和配置发布 | 未开始 | - |
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

## 遗留问题

1. `create-vite` 在非交互环境下失败，前端项目为手动初始化，结构与标准模板一致，已补齐 `public/` 目录；
2. 后端 Go 客户端尚未引入，阶段2引入时如使用 Redis 协议兼容客户端（如 go-redis），需在 THIRD_PARTY_NOTICES.md 单独记录其名称、版本与许可证；
3. POC 审计引擎为 `On`（go-ftw marker 机制需要全量事务日志），生产配置发布时应按应用策略下发 `RelevantOnly`；
4. `handle_errors` 错误处理链路不经过主路由 `header` 指令，阻断响应的 Server 头清理需在错误链路单独配置（阶段3统一处理）；
5. 全量替换配置会覆盖 admin 设置：后续配置生成器必须始终显式包含 `admin unix//var/run/caddy/admin.sock`，发布前校验必须拒绝缺失或 TCP 形式的 admin 配置；
6. 阶段1 POC 未启用 TLS、多应用路由、真实 IP 识别与 CC 防护（分别在阶段3、阶段5实现）。

## 下一步

阶段2：用户权限和系统基础（登录、三权角色、权限中间件、登录日志、操作审计、系统设置、数据库迁移、前端基础布局）。
