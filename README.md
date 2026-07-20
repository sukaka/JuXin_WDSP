# 九章WEB应用智能防护系统 V2.0

一套自主研发的反向代理型 Web 应用防火墙（WAF）管理系统。

## 产品简介

九章WEB应用智能防护系统V2.0部署在 Web 应用前端，对 HTTP/HTTPS 流量进行接入、转发、检测、分析和阻断。系统面向政府、企事业单位、中小型网站及内部业务系统，提供统一接入、攻击检测、防护处置和审计报告能力。

系统采用「自主管理平台 + 自主控制组件 + 开源检测引擎」架构：

- **管理面**：React + TypeScript + Ant Design
- **控制面**：Go + PostgreSQL + Valkey
- **防护面**：Caddy + Coraza WAF + OWASP CRS + 自主 jiuzhang_guard 模块

## 核心能力

- Web 应用接入与反向代理
- SQL 注入、XSS、命令执行、文件包含等攻击检测
- 攻击事件记录、分析与处置
- IP 黑白名单与访问控制
- CC 攻击和高频访问防护
- HTTPS 证书管理
- 防护策略配置与规则启停
- 误报例外策略
- 安全态势展示与安全报表
- 三权分立用户体系与操作审计
- 配置版本管理、发布与回滚
- 系统备份与恢复

## 快速开始

### 环境要求

- Docker 24+
- Docker Compose v2+
- Go 1.24+
- Node.js 24（见 `.nvmrc`）
- npm 11+（随 Node.js 自带）

### 启动基础环境

```bash
cp .env.example .env
# 编辑 .env，设置 POSTGRES_PASSWORD 和 VALKEY_PASSWORD
docker compose up -d postgres valkey
```

### 初始化数据库

```bash
# 待阶段2完成后提供迁移命令
```

### 构建

```bash
make build
```

### 运行测试

```bash
make test
```

## 项目结构

详见 [项目目录结构](docs/ARCHITECTURE.md#项目目录结构)。

## 文档

- [产品需求文档](docs/PRODUCT_REQUIREMENTS.md)
- [架构设计文档](docs/ARCHITECTURE.md)
- [数据库设计文档](docs/DATABASE_DESIGN.md)
- [接口设计文档](docs/API_DESIGN.md)
- [安全设计文档](docs/SECURITY_DESIGN.md)
- [部署文档](docs/DEPLOYMENT.md)
- [测试计划](docs/TEST_PLAN.md)
- [开发状态](docs/DEVELOPMENT_STATUS.md)
- [第三方组件清单](THIRD_PARTY_NOTICES.md)
- [开源合规说明](docs/OPEN_SOURCE_COMPLIANCE.md)

## 开发阶段

| 阶段 | 内容 | 状态 |
|------|------|------|
| 阶段0 | 项目初始化 | 进行中 |
| 阶段1 | 网关技术验证 | 未开始 |
| 阶段2 | 用户权限和系统基础 | 未开始 |
| 阶段3 | 应用接入和配置发布 | 未开始 |
| 阶段4 | WAF策略和事件中心 | 未开始 |
| 阶段5 | 访问控制和CC防护 | 未开始 |
| 阶段6 | 首页和安全报表 | 未开始 |
| 阶段7 | 质量和交付 | 未开始 |

## 版权

Copyright © 聚信得仁
All Rights Reserved.

本项目自主代码保留全部权利；第三方组件遵循其各自许可证，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
