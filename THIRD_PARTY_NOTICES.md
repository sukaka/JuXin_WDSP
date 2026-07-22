# 第三方组件声明

本文档记录九章WEB应用智能防护系统V2.0所使用的第三方开源组件。所有组件均以实际锁定版本的仓库许可证文件为准。

## 使用原则

1. 优先选择 Apache-2.0、MIT、BSD 等宽松许可证组件；
2. 未经书面批准，不得引入 GPL、AGPL 组件；
3. 所有组件版本必须明确锁定，禁止使用 `latest`；
4. 升级组件前必须重新核查许可证和兼容性；
5. 不得删除或修改任何第三方组件的版权声明。

## 核心防护组件

| 软件名称 | 项目来源 | 锁定版本 | 许可证 | 是否修改 | 使用方式 | 许可证文件位置 |
|---------|---------|---------|--------|---------|---------|---------------|
| Caddy | https://github.com/caddyserver/caddy | v2.11.4 (e2eee6a7fce3) | Apache-2.0 | 否 | 反向代理网关 | [licenses/caddy/LICENSE](licenses/caddy/LICENSE) |
| Coraza WAF | https://github.com/corazawaf/coraza | v3.7.0 (27069d06c896) | Apache-2.0 | 否 | WAF 检测引擎 | [licenses/coraza/LICENSE](licenses/coraza/LICENSE) |
| coraza-caddy | https://github.com/corazawaf/coraza-caddy | v2.5.0 (55c03d45dc55) | Apache-2.0 | 否 | Caddy 集成模块 | [licenses/coraza-caddy/LICENSE](licenses/coraza-caddy/LICENSE) |
| OWASP CRS | https://github.com/coreruleset/coreruleset | v4.28.0 (55b09f5acfd1) | Apache-2.0 | 否 | 通用攻击规则集 | [licenses/owasp-crs/LICENSE](licenses/owasp-crs/LICENSE) |
| xcaddy | https://github.com/caddyserver/xcaddy | v0.4.5 (328cac711a1f) | Apache-2.0 | 否 | Caddy 构建工具（仅构建期） | [licenses/xcaddy/LICENSE](licenses/xcaddy/LICENSE) |
| go-ftw | https://github.com/coreruleset/go-ftw | v2.4.0 (23db497e3a61) | Apache-2.0 | 否 | CRS 回归测试（仅测试期） | [licenses/go-ftw/LICENSE](licenses/go-ftw/LICENSE) |

## 基础设施组件

| 软件名称 | 项目来源 | 计划版本 | 许可证 | 是否修改 | 使用方式 | 许可证文件位置 |
|---------|---------|---------|--------|---------|---------|---------------|
| PostgreSQL | https://www.postgresql.org | 16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c | PostgreSQL License | 否 | 主数据库 | [licenses/postgresql/LICENSE](licenses/postgresql/LICENSE) |
| Valkey | https://github.com/valkey-io/valkey | 8.1.8-alpine@sha256:94365b275456ae14621001c03556c732b1d93a0cdeacc317d1bdd52eba680885 | BSD-3-Clause | 否 | 缓存、会话辅助状态、分布式锁、任务状态 | [licenses/valkey/LICENSE](licenses/valkey/LICENSE) |

## 基础镜像（Docker）

| 软件名称 | 锁定版本 | 许可证 | 使用方式 |
|---------|---------|--------|---------|
| golang | 1.25-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 | BSD-3-Clause | 网关/测试源站构建阶段 |
| alpine | 3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b | MIT | 网关/测试源站运行阶段 |
| curlimages/curl | 8.21.0@sha256:7c12af72ceb38b7432ab85e1a265cff6ae58e06f95539d539b654f2cfa64bb13 | curl License (MIT/X) | 阶段1配置控制器容器 |

## 后端依赖（Go）

阶段2及以后补充，以 `server/go.mod` 和 `gateway/go.mod` 实际锁定版本为准。

## 前端依赖（Node.js）

阶段0初始依赖如下，后续以 `web/package.json` 实际锁定版本为准。

| 软件名称 | 计划版本 | 许可证 | 使用方式 |
|---------|---------|--------|---------|
| React | 18.x | MIT | 前端框架 |
| TypeScript | 5.x | Apache-2.0 | 类型系统 |
| Vite | 6.x | MIT | 构建工具 |
| Ant Design | 5.x | MIT | UI 组件库 |
| ECharts | 5.x | Apache-2.0 | 图表库 |
| TanStack Query | 5.x | MIT | 数据请求 |
| Zustand | 5.x | MIT | 状态管理 |
| Vitest | 3.x | MIT | 单元测试 |
| Playwright | 1.x | Apache-2.0 | E2E 测试 |

## 阶段5新增组件

| 软件名称 | 项目来源 | 锁定版本 | 许可证 | 是否修改 | 使用方式 | 许可证文件位置 |
|---------|---------|---------|--------|---------|---------|---------------|
| valkey-go | https://github.com/valkey-io/valkey-go | v1.0.76 | Apache-2.0 | 否 | jiuzhang_guard 模块 Valkey 客户端（CC计数/临时封禁） | [licenses/valkey-go/LICENSE](licenses/valkey-go/LICENSE) |

## 阶段6新增组件

| 软件名称 | 项目来源 | 锁定版本 | 许可证 | 是否修改 | 使用方式 | 许可证文件位置 |
|---------|---------|---------|--------|---------|---------|---------------|
| gofpdf | https://github.com/jung-kurt/gofpdf | v2.17.3 | MIT | 否 | PDF 报告生成（管理后端） | [licenses/gofpdf/LICENSE](licenses/gofpdf/LICENSE) |
| Noto Sans CJK | https://github.com/notofonts/noto-cjk | noto-cjk main（sha256 见 server/assets/fonts/README.md） | OFL-1.1 | 否 | PDF 报告中文字体（server/assets/fonts/） | [licenses/noto-fonts/LICENSE](licenses/noto-fonts/LICENSE) |
| ECharts | https://github.com/apache/echarts | 6.1.0 | Apache-2.0 | 否 | 前端图表（态势与报表页） | [licenses/echarts/LICENSE](licenses/echarts/LICENSE) |

## 许可证原文

各组件许可证原文存放于 `licenses/` 目录下，按组件名称分目录保存。阶段0先建立目录结构，正式引入组件时同步归档对应许可证文件。

## 安全风险说明

- 使用第三方组件即引入其上游安全风险，需定期跟踪 CVE；
- 每次版本升级后重新核查许可证和兼容性；
- 发现高危漏洞时优先升级，无法升级时评估替代方案。

## 版权归属

九章WEB应用智能防护系统V2.0自主代码版权归聚信得仁所有。第三方组件版权归其各自作者和贡献者所有。
