# 依赖锁定清单

本文档记录九章WEB应用智能防护系统V2.0所有第三方组件的精确版本。核查日期：2026-07-20。禁止使用 `latest` 标签。

## 网关核心组件（阶段1锁定）

| 组件名称 | 版本号 | Git提交号 | 许可证 | 项目地址 | 发布日期 | 兼容性说明 | 是否修改 |
|---------|--------|----------|--------|---------|---------|-----------|---------|
| Caddy | v2.11.4 | e2eee6a7fce3 | Apache-2.0 | https://github.com/caddyserver/caddy | 2026-06-03 | 网关基础，coraza-caddy v2.5.0 声明兼容 caddy v2.11.x | 否 |
| Coraza WAF | v3.7.0 | 27069d06c896 | Apache-2.0 | https://github.com/corazawaf/coraza | 2026-04-06 | WAF 检测引擎，支持 SecLang 与 CRS 4.x | 否 |
| coraza-caddy | v2.5.0 | 55c03d45dc55 | Apache-2.0 | https://github.com/corazawaf/coraza-caddy | 2026-04-12 | Caddy 集成模块，go.mod 声明依赖 caddy v2.11.2、coraza v3.7.0 | 否 |
| OWASP CRS | v4.28.0 | 55b09f5acfd1 | Apache-2.0 | https://github.com/coreruleset/coreruleset | 2026-07-02 | 通用攻击规则集，tarball sha256: d8acc96f25ad07c8e3a595a23c797324f6d77e59ddf9e26e90dd95ebd2e676ce | 否 |
| xcaddy | v0.4.5 | 328cac711a1f | Apache-2.0 | https://github.com/caddyserver/xcaddy | 2025-07-29 | Caddy 自定义构建工具（仅构建期使用） | 否 |
| go-ftw | v2.4.0 | 23db497e3a61 | Apache-2.0 | https://github.com/coreruleset/go-ftw | 2026-05-23 | CRS 回归测试框架（仅测试期使用） | 否 |

## 基础镜像（Docker）

| 镜像 | 标签 | 摘要 | 用途 |
|------|------|------|------|
| golang | 1.25-alpine | sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 | 网关构建阶段 |
| alpine | 3.24 | sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b | 网关运行阶段 |
| postgres | 16.4-alpine | sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c | 主数据库 |
| valkey/valkey | 8.1.8-alpine | sha256:94365b275456ae14621001c03556c732b1d93a0cdeacc317d1bdd52eba680885 | 缓存/锁/任务状态 |

## 基础设施组件

| 组件名称 | 版本号 | 许可证 | 项目地址 | 使用方式 | 是否修改 |
|---------|--------|--------|---------|---------|---------|
| PostgreSQL | 16.4 | PostgreSQL License | https://www.postgresql.org | 主数据库 | 否 |
| Valkey | 8.1.8 | BSD-3-Clause | https://github.com/valkey-io/valkey | 缓存、会话辅助状态、分布式锁、任务状态 | 否 |

## 运行时工具链

| 组件 | 版本 | 说明 |
|------|------|------|
| Go | 1.25.x（本地 1.25.6，容器 golang:1.25-alpine） | 后端与网关构建 |
| Node.js | 24.13.0（`.nvmrc` / `.node-version`） | 前端构建 |
| npm | 11.x（随 Node.js 24 自带） | 前端包管理器 |

## 前端依赖

以 `web/package.json` 与 `web/package-lock.json` 为准，CI 使用 `npm ci` 安装。

## 后端依赖

阶段2引入，以 `server/go.mod` / `server/go.sum` 为准。如使用 Redis 协议兼容客户端连接 Valkey，需在本文件与 THIRD_PARTY_NOTICES.md 单独登记。

## 更新记录

- 2026-07-20：阶段1首次核查锁定。OWASP CRS 采用 v4.28.0（方案基线为 4.26.x，实际取同大版本下最新发布 v4.28.0）。
