# AGENTS.md — 九章WEB应用智能防护系统V2.0

## 项目定位

九章WEB应用智能防护系统V2.0是一套自主研发的反向代理型Web应用防火墙（WAF）管理系统，基于 Caddy + Coraza WAF + OWASP CRS 构建底层防护能力，管理面与网关控制面完全自主开发。

## 开发原则

1. **独立开发**：不复制任何现有WAF产品的源代码、界面、接口、数据库结构或文案。
2. **宽松许可证**：第三方组件优先选择 Apache-2.0 / MIT / BSD；未经书面批准不得引入 GPL / AGPL 组件。
3. **版本锁定**：所有依赖、Docker 镜像必须明确锁定版本，禁止使用 `latest` 标签。
4. **一次一阶段**：一次只完成一个阶段或一个明确模块，不得跳跃式开发。
5. **先读后改**：修改代码前必须先读取本文档、相关设计文档和现有代码。
6. **测试先行**：所有功能必须附带单元测试；接口功能必须附带接口测试；关键流程必须附带 E2E 测试。
7. **安全底线**：不得为了通过测试而删除权限校验、参数校验、CSRF 防护或日志脱敏。

## 技术路线

| 层级 | 技术 |
|------|------|
| 管理前端 | React 18 + TypeScript + Vite + Ant Design 5 + ECharts + TanStack Query + Zustand |
| 管理后端 | Go 1.24+、PostgreSQL 16+、Valkey 8+、RESTful API、OpenAPI 3 |
| 防护网关 | Caddy 2.11.x、Coraza WAF 3.7.x、coraza-caddy 2.5.x、OWASP CRS 4.26.x |
| 自主网关扩展 | jiuzhang_guard Caddy Module |
| 部署 | Docker Compose |
| 测试 | Go Test、Vitest、Playwright、go-ftw |

## 请求处理顺序（网关）

接收请求 → 生成 Request ID → 识别真实客户端 IP → 可信代理判断 → IP 白名单 → IP 黑名单 → CC 频率限制 → 请求大小及协议检查 → Coraza/CRS 攻击检测 → 反向代理到源站 → 返回响应 → 记录访问日志和安全事件

Caddy 中间件顺序必须经过集成测试验证，不得凭经验随意调整。

## 禁止事项

- 不得复制、Fork、反编译雷池或其他 WAF 产品；
- 不得复刻雷池页面布局、接口路径、数据库表结构或文案；
- 不得使用 `latest` Docker 镜像标签；
- 不得将 Caddy Admin API 暴露到 TCP 端口，必须使用 Unix Socket；
- 不得把私钥、密码、Token 提交到 Git；
- 不得在生产代码中保留默认密码；
- 不得用 Mock 数据或占位接口冒充功能完成；
- 不得跳过数据库迁移、权限校验、参数校验、操作审计和测试；
- 不得静默吞掉错误。

## 阶段划分

- 阶段0：项目初始化（阶段1-6 已全部完成，详见 docs/DEVELOPMENT_STATUS.md）
- 阶段1：网关技术验证
- 阶段2：用户权限和系统基础
- 阶段3：应用接入和配置发布
- 阶段4：WAF策略和事件中心
- 阶段5：访问控制和CC防护
- 阶段6：首页和安全报表
- 阶段7：质量和交付

## 文档索引

- [产品需求](docs/PRODUCT_REQUIREMENTS.md)
- [架构设计](docs/ARCHITECTURE.md)
- [数据库设计](docs/DATABASE_DESIGN.md)
- [接口设计](docs/API_DESIGN.md)
- [安全设计](docs/SECURITY_DESIGN.md)
- [部署文档](docs/DEPLOYMENT.md)
- [测试计划](docs/TEST_PLAN.md)
- [开源合规](docs/OPEN_SOURCE_COMPLIANCE.md)
- [开发状态](docs/DEVELOPMENT_STATUS.md)
- [产品线与分支策略（WAF/WDSP）](docs/BRANCHING_AND_PRODUCT_LINES.md)
- [阶段8/WDSP 开工说明](docs/tasks/STAGE_8_WDSP_KICKOFF.md)
- [阶段8 任务书](docs/tasks/STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md)

## 版权

Copyright © 聚信得仁
All Rights Reserved.
