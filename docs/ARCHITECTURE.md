# 架构设计文档

## 总体架构

```text
                        用户浏览器
                             │
                             ▼
                 九章WEB管理控制台
              React + TypeScript + Vite
                             │
                             ▼
                    九章管理服务
                           Go
       ┌─────────────────────┼─────────────────────┐
       │                     │                     │
       ▼                     ▼                     ▼
  PostgreSQL               Valkey            文件存储目录
 配置/事件/审计       缓存/锁/任务状态       证书/报表/备份
       │
       ▼
                  九章网关配置控制器
       配置生成→校验→发布→验证→回滚→版本记录
                             │
                       Unix Socket
                             │
                             ▼
                    九章防护网关
                 Caddy + Coraza + CRS
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
   九章Guard模块    Coraza检测     反向代理模块
  黑白名单/CC等      WAF规则          Caddy
         │             │
         └──────┬──────┘
                ▼
             源站系统
```

## 组件说明

### 管理前端（web/）

- **技术栈**：React 18、TypeScript、Vite、Ant Design 5、ECharts、TanStack Query、Zustand
- **职责**：管理控制台 UI、数据展示、用户交互
- **约束**：不直接调用 Caddy Admin API，所有操作通过管理后端

### 管理后端（server/）

- **技术栈**：Go 1.24+、PostgreSQL、Valkey
- **职责**：
  - 用户认证与权限控制
  - 业务配置管理
  - 网关配置生成、校验、发布、回滚
  - 安全事件采集与存储
  - 报表生成
  - 操作审计
- **架构**：模块化单体，按业务领域分包

### 防护网关（gateway/）

- **技术栈**：Caddy 2.11.x、Coraza WAF 3.7.x、coraza-caddy 2.6.x、OWASP CRS 4.26.x
- **自主模块**：jiuzhang_guard（IP 黑白名单、CC 防护、真实 IP 识别）
- **职责**：流量接入、攻击检测、访问控制、反向代理
- **管理接口**：仅通过 Unix Socket 暴露，不绑定 TCP 端口

### 数据存储

- **PostgreSQL**：配置、事件、审计、用户权限
- **Valkey**：缓存、分布式锁、任务状态（兼容 Redis 协议的 BSD-3-Clause 分支）
- **文件系统**：证书、报表、备份、日志

## 请求处理顺序

```text
接收请求
  ↓
生成 Request ID
  ↓
识别真实客户端 IP
  ↓
可信代理判断
  ↓
IP 白名单判断
  ↓
IP 黑名单判断
  ↓
L7 请求阶段（URI/方法/请求头/Cookie/Query/来源 IP/请求体，首中即停）
  ↓
CC 频率限制
  ↓
Bot 挑战判定（bot_policy，可选，默认 OFF；OBSERVE 只记录不实断，PROTECT 挑战/verify；
保护地址/白名单/L7 allow 不跳过 Bot；保留命名空间 /_wdsp/bot/v1/ 在本步骤最前置
本地处理，verify 与墓碑均不反向代理）
  ↓
请求大小及协议检查
  ↓
Coraza/CRS 攻击检测
  ↓
反向代理到源站
  ↓
L7 响应阶段（返回头/返回体关键字或正则；完整正文 ≤1 MiB，超限/流式降级透传）
  ↓
返回响应
  ↓
记录访问日志和安全事件
```

## 配置发布流程

```text
用户修改业务配置
  ↓
保存到 PostgreSQL
  ↓
生成配置快照
  ↓
生成 Caddy 配置和 Coraza 配置
  ↓
静态语法校验
  ↓
安全校验
  ↓
生成配置差异
  ↓
调用 Caddy Adapt/Validate
  ↓
调用 Caddy Admin API 发布
  ↓
检查应用端口和健康状态
  ↓
标记配置已生效
  ↓
记录配置版本和审计
```

## 项目目录结构

```text
jiuzhang-waf/
├── AGENTS.md
├── README.md
├── LICENSE
├── THIRD_PARTY_NOTICES.md
├── CHANGELOG.md
├── Makefile
├── docker-compose.yml
├── .env.example
├── .gitignore
├── .github/workflows/
├── docs/
│   ├── PRODUCT_REQUIREMENTS.md
│   ├── ARCHITECTURE.md
│   ├── DATABASE_DESIGN.md
│   ├── API_DESIGN.md
│   ├── SECURITY_DESIGN.md
│   ├── DEPLOYMENT.md
│   ├── TEST_PLAN.md
│   ├── OPEN_SOURCE_COMPLIANCE.md
│   ├── DEVELOPMENT_STATUS.md
│   └── decisions/
├── web/
│   ├── src/
│   ├── tests/
│   ├── package.json
│   └── vite.config.ts
├── server/
│   ├── cmd/
│   ├── internal/
│   │   ├── auth/
│   │   ├── users/
│   │   ├── applications/
│   │   ├── certificates/
│   │   ├── policies/
│   │   ├── rules/
│   │   ├── events/
│   │   ├── reports/
│   │   ├── audits/
│   │   ├── gateway/
│   │   └── system/
│   ├── migrations/
│   ├── tests/
│   └── go.mod
├── gateway/
│   ├── cmd/
│   ├── modules/
│   │   └── jiuzhang_guard/
│   ├── configs/
│   ├── rules/
│   │   ├── crs/
│   │   ├── jiuzhang/
│   │   └── exclusions/
│   ├── tests/
│   └── go.mod
├── deployment/
│   ├── docker/
│   ├── scripts/
│   ├── systemd/
│   └── examples/
├── runtime/
│   ├── configs/
│   ├── certificates/
│   ├── logs/
│   ├── reports/
│   └── backups/
└── test/
    ├── e2e/
    ├── waf/
    ├── performance/
    └── security/
```

## 技术决策记录

重要技术决策见 `docs/decisions/` 目录。
