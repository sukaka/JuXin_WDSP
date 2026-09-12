# 九章 WDSP

**统一 Web 与 API 动态防护平台 · 当前版本 1.2.0**

九章 WDSP 部署在业务入口，对 HTTP/HTTPS 请求与响应进行统一接入、解析、检测、决策和审计。平台在传统 Web 应用防火墙能力之上，进一步理解 API 资产、调用身份、参数结构和业务行为，面向政府、企事业单位、数据接口平台及内部业务系统提供动态防护能力。

> 当前版本与发布标签以 [VERSION.md](VERSION.md) 为准，版本变更见 [CHANGELOG.md](CHANGELOG.md)。

## 为什么是 WDSP

普通 WAF 主要判断“单个请求是否包含已知攻击特征”；九章 WDSP 在同一条流量链上同时理解“访问了什么 API、由谁调用、参数是否符合模型、业务行为是否异常，以及响应是否泄露敏感信息”。

| 能力 | 九章 WDSP 的实现 |
|------|-----------------|
| Web 与 API 统一防护 | 一条流量链、一次解析，WAF、API 发现、模型学习和风险检测共享请求上下文 |
| 未知 API 资产发现 | 从真实流量识别并归一化 REST、JSON、XML、SOAP、GraphQL、Webhook 等接口，发现 Shadow、Zombie、Deprecated 和 Debug API |
| 身份与业务行为理解 | 基于 Cookie、Session、Token、JWT、OAuth、API Key 的不可逆指纹建立调用身份与行为基线，不以 IP 冒充身份 |
| 请求与响应双向检测 | 同时分析请求结构、响应结构、异常状态、错误信息和敏感数据暴露 |
| 动态正向模型 | 学习参数类型、长度、值域、枚举、必填性及字段关系，检测 Schema 偏离和业务参数异常 |
| 统一风险决策 | 汇聚攻击、身份、行为、授权和数据风险信号，统一输出观察、限速、临时封禁或阻断动作 |
| 渐进式上线 | 支持 `OFF`、`OBSERVE`、`PROTECT`，先学习和验证证据，再进入确定性处置 |
| 可解释安全运营 | 以 Request ID 串联检测明细、处置结果和审计记录，支持事件调查、报表、What-if 分析与 AI 辅助运营 |

完整差异化能力见 [WDSP Top 20](docs/WDSP_TOP20_VS_WAF.md)。

## 核心能力

### Web 应用防护

- 基于 Coraza WAF 与 OWASP CRS 检测 SQL 注入、XSS、命令执行、文件包含等攻击；
- Web 应用、域名、源站、HTTPS 证书和防护策略统一管理；
- IP 黑白名单、L7 访问控制、CC 防护、Bot 挑战和临时封禁；
- 自定义规则、规则覆盖、误报例外、配置预览、发布、版本对比与回滚；
- 安全事件处置、访问日志、安全态势、统计报表和操作审计。

### API 动态防护

- API 自动发现、路径模板化、资产分类、生命周期与风险标记；
- OpenAPI 等多格式规范导入、资产核对和模型版本管理；
- 请求/响应 Schema 学习、参数关系学习与偏离检测；
- JWT 信任链、身份行为观测、认证异常、授权配额与撤销凭据检测；
- BOLA/BFLA、多租户授权、Mass Assignment 和业务流程偏离辅助检测；
- 敏感数据识别、响应采样、错误泄露检测和运行时指标；
- API 调用拓扑、身份—API—对象关系与统一 Finding/Decision。

### 平台与交付

- 三权分立 RBAC、服务端会话、CSRF 防护、登录保护和防篡改审计链；
- PostgreSQL 持久化、Valkey 状态存储、加密备份与恢复；
- AI 安全运营、攻击画像、对抗提示词门禁和会话自动续跑；
- APM、分布式流量 Agent、多节点发布与主备高可用能力；
- amd64/arm64 离线交付、Ed25519 包签名、离线授权和升级预检。
- 提供面向 openEuler 与兆芯 KX/KH 的 amd64 自解压 `.run` 安装包，自动检查依赖并可选执行安全的宿主机性能调优与服务精简。

## 系统架构

```text
客户端流量
    │
    ▼
Caddy + Coraza/CRS + jiuzhang_guard
    ├── 真实客户端 IP / JWT 信任链 / 身份与行为观测
    ├── 访问控制 / 风险策略 / CC / Bot 挑战
    ├── API 动态防护 / 请求协议检查 / Web 攻击检测
    └── 响应侧检测与安全事件采集
    │
    ▼
业务源站

管理控制台（React） ── 管理 API（Go） ── PostgreSQL / Valkey
                              │
                              └── 配置编译、发布、审计、报表与 AI 运营
```

防护网关以 Caddy 2.11.x、Coraza WAF 3.7.x、coraza-caddy 2.5.x 和 OWASP CRS 4.26.x 为基础，核心管理面、控制面和 `jiuzhang_guard` 网关扩展自主开发。真实执行顺序见 [AGENTS.md](AGENTS.md#请求处理顺序网关)，整体设计见 [架构文档](docs/ARCHITECTURE.md)。

## 快速开始

### 环境要求

- Linux，推荐 Ubuntu 22.04+ 或 CentOS 8+
- Docker 24+ 与 Docker Compose v2
- 建议 4 核 CPU、8 GB 内存、本地 SSD
- 源码开发另需 Go 1.24+、Node.js 24 和 npm 11+

### 生产安装

推荐使用安装向导。它会检查环境、生成强随机配置、启动服务并初始化三权账号：

```bash
sudo bash ops/install/install.sh
```

初始口令只显示一次；首次登录后必须立即修改。生产部署、离线安装和安装后核验请阅读 [安装向导](docs/INSTALLATION_GUIDE.md)、[openEuler / 兆芯安装与优化](docs/OPENEULER_ZHAOXIN_INSTALLATION.md) 与 [部署文档](docs/DEPLOYMENT.md)。

### 开发环境

```bash
# 1. 准备配置，替换所有 CHANGE_ME 项
cp .env.example .env

# 2. 构建并启动 WDSP 环境
make stage8-build
make stage8-up

# 3. 查看服务状态
make stage8-status
```

停止环境：

```bash
make stage8-down
```

`.env` 包含敏感配置，不得提交到 Git。若只需运行基础依赖，可执行 `make docker-up`。

## 构建与测试

```bash
# 全栈构建
make build

# 后端与前端测试
make test

# 静态检查
make lint
make typecheck

# WDSP 阶段8完整测试矩阵
make stage8-test-all
```

更细的 API 安全测试目标可通过 `make help` 和 [测试计划](docs/TEST_PLAN.md) 查看。生产发布前还应执行对应的性能、安全、回归和离线交付验收，不应只以单一测试命令作为上线依据。

## 项目结构

```text
gateway/       防护网关、动态安全引擎与自主 Caddy 模块
server/        Go 管理 API、业务服务与数据库迁移
web/           React 18 + TypeScript 管理控制台
deployment/    Compose、裸机、HA、APM 与旁路采集部署配置
ops/           安装、升级、备份、恢复、诊断和离线打包工具
test/          网关、接口、E2E、性能、回归和安全测试
docs/          产品、架构、能力设计、任务书与运维文档
```

## 产品形态

仓库使用同一套代码和数据库演进主线，通过配置形成三种产品形态：

| Edition | `PRODUCT_EDITION` | Web 防护 | API 动态防护 |
|---------|-------------------|----------|--------------|
| 九章 WAF | `waf` | 开启 | 默认关闭 |
| 九章 WDSP | `wdsp` | 开启 | 开启 |
| 九章 API 安全系统 | `api` | 不交付专属管理界面 | 开启 |

产品线、能力边界与分支规则见 [产品线与分支策略](docs/BRANCHING_AND_PRODUCT_LINES.md)。

## 当前状态

- 阶段 0—7 已完成：工程基线、网关、管理基础、应用接入、WAF 策略、访问控制、报表交付和 AI 安全运营；
- 阶段 8 已形成统一 Web/API 动态防护主线，并持续完善 API 资产、模型、身份授权、行为分析、响应安全和分布式采集能力；
- 当前 WDSP 发布版本为 **1.2.0**，发布标签为 **`wdsp-v1.2.0`**。

详细完成项及验收证据见 [开发状态](docs/DEVELOPMENT_STATUS.md)、[阶段8任务书](docs/tasks/STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md) 和 [变更记录](CHANGELOG.md)。

## 重点文档

- [产品需求](docs/PRODUCT_REQUIREMENTS.md)
- [架构设计](docs/ARCHITECTURE.md)
- [安全设计](docs/SECURITY_DESIGN.md)
- [API 安全能力现状](docs/API_SECURITY_CURRENT_STATE.md)
- [三微模型统一维度框架](docs/API_MICRO_MODELS.md)
- [统一 Finding 与统一决策](docs/API_UNIFIED_FINDING_DECISION.md)
- [API 身份与授权安全](docs/API_IDENTITY_AUTHORIZATION.md)
- [API 响应侧安全](docs/API_RESPONSE_SECURITY.md)
- [AI 自动化渗透防护增强](docs/WDSP_AI_PENTEST_PROTECTION_ENHANCEMENT.md)
- [Bot 挑战运维手册](docs/BOT_CHALLENGE_OPERATIONS.md)
- [分布式 Agent 设计](docs/agents/WDSP_DISTRIBUTED_AGENT_DESIGN.md)
- [安装向导](docs/INSTALLATION_GUIDE.md)
- [openEuler / 兆芯 `.run` 安装与主机优化](docs/OPENEULER_ZHAOXIN_INSTALLATION.md)
- [高可用运维](docs/HA_OPERATIONS_GUIDE.md)
- [开源合规](docs/OPEN_SOURCE_COMPLIANCE.md)
- [第三方组件清单](THIRD_PARTY_NOTICES.md)

## 安全与合规

- 所有依赖和容器镜像必须锁定明确版本，禁止使用 `latest`；
- PostgreSQL 与 Valkey 默认仅绑定本机，Caddy Admin API 使用 Unix Socket；
- 私钥、密码、Token、授权签名私钥和 `.env` 不得提交到仓库；
- API 动态防护、身份行为、Bot 和风险策略均采用显式开关及分阶段模式，生产启用前应先完成证据验证；
- 自主代码保留全部权利，第三方组件遵循各自许可证。

## 版权

Copyright © 聚信得仁<br>
All Rights Reserved.
