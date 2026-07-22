# 开源合规说明

## 目标

确保九章WEB应用智能防护系统V2.0在独立开发的前提下，合法、合规地使用第三方开源组件。

## 许可证策略

### 允许使用

- Apache-2.0
- MIT
- BSD-2-Clause / BSD-3-Clause
- ISC
- PostgreSQL License

### 限制使用

- LGPL：仅限动态链接且不修改组件本身，需单独审批；
- MPL-2.0：需单独审批。

### 禁止使用

- GPL-2.0 / GPL-3.0
- AGPL-3.0
- SSPLv1 / RSALv2（本项目不采用 Redis 7.4+，键值存储统一使用 BSD-3-Clause 的 Valkey）

## 合规检查清单

每次引入或升级第三方组件时必须完成：

- [ ] 确认组件名称、版本、来源仓库；
- [ ] 获取并归档对应版本的 LICENSE 文件；
- [ ] 确认许可证类型符合本项目策略；
- [ ] 记录是否修改组件源代码；
- [ ] 记录使用方式（直接引用 / 修改后引用 / 仅运行时使用）；
- [ ] 更新 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)；
- [ ] 扫描已知 CVE；
- [ ] 在 `licenses/` 目录归档许可证原文。

## 自主代码声明

本项目自主开发的代码、界面、文档、数据库结构、接口定义等，版权归聚信得仁所有，保留全部权利。自主代码不采用开源许可证发布。

## 第三方代码隔离

- 不得将第三方组件源代码复制到本项目自主代码目录中；
- 通过包管理器（Go Modules、npm、Docker 镜像）引用第三方组件；
- 如需修改第三方组件，必须优先提交上游补丁，确实无法上游化的，在独立目录中维护补丁并明确标注。

## 审计要求

- 每个阶段结束时重新运行许可证扫描；
- 发布前生成完整的依赖清单和许可证报告；
- 保留 Git 提交记录作为独立开发证明。

## 当前状态

### 阶段0（2026-07-20）

建立合规框架，引入 PostgreSQL 16.4 与 Valkey 8.1.8 容器镜像（Valkey BSD-3-Clause 许可证已归档 `licenses/valkey/`）。

### 阶段0.1（2026-07-20）

Redis 替换为 Valkey（规避 RSALv2/SSPLv1 合规风险），npm 统一包管理，全部镜像锁定版本+摘要。

### 阶段1（2026-07-20）

引入组件均为宽松许可证，许可证原文已归档：

| 组件 | 版本 | 许可证 | 归档位置 |
|------|------|--------|---------|
| Caddy | v2.11.4 | Apache-2.0 | licenses/caddy/ |
| Coraza WAF | v3.7.0 | Apache-2.0 | licenses/coraza/ |
| coraza-caddy | v2.5.0 | Apache-2.0 | licenses/coraza-caddy/ |
| OWASP CRS | v4.28.0 | Apache-2.0 | licenses/owasp-crs/（规则目录另附 LICENSE） |
| xcaddy | v0.4.5 | Apache-2.0 | licenses/xcaddy/ |
| go-ftw | v2.4.0 | Apache-2.0 | licenses/go-ftw/ |
| curlimages/curl | 8.21.0 | curl License | licenses/curl/ |
| 基础镜像 | golang/alpine | BSD/MIT | licenses/other/README.md |

- 所有组件未经修改，通过 xcaddy 编译集成 / 只读挂载 / 容器镜像方式使用；
- 无 GPL/AGPL 组件；
- 无 `latest` 标签；
- 详细版本与摘要见 [DEPENDENCIES.md](DEPENDENCIES.md)。

### 阶段5（访问控制与CC防护）

| 组件 | 版本 | 许可证 | 归档位置 |
|------|------|--------|---------|
| valkey-go | v1.0.76 | Apache-2.0 | licenses/valkey-go/ |

- jiuzhang_guard 为自主开发 Caddy 模块（gateway/modules/jiuzhang_guard，独立 go.mod），不引入额外第三方运行时组件；
- 无 GPL/AGPL 组件，许可证原文已归档。

### 阶段6（首页报表/备份恢复/升级交付）

| 组件 | 版本 | 许可证 | 归档位置 |
|------|------|--------|---------|
| gofpdf | v2.17.3 | MIT | licenses/gofpdf/ |
| Noto Sans CJK | noto-cjk main（sha256 见 server/assets/fonts/README.md） | OFL-1.1 | licenses/noto-fonts/ |
| ECharts | 6.1.0 | Apache-2.0 | licenses/echarts/ |
| PostgreSQL License 文本 | 16.4 对应 | PostgreSQL License | licenses/postgresql/（本阶段补齐归档） |

- gofpdf 用于 PDF 报告生成，Noto Sans CJK 为 PDF 内嵌中文字体（OFL-1.1 允许随产品分发内嵌），ECharts 用于态势与报表页图表；
- 本阶段起由 `scripts/generate-sbom.sh` 生成 SBOM（docs/SBOM.spdx.json / docs/SBOM.cyclonedx.json），
  由 `scripts/license-audit.sh` 审计 licenses/ 归档一致性与禁用许可证（GPL/AGPL/SSPL 出现即失败）；
- 无 GPL/AGPL 组件，无 `latest` 标签，许可证原文已归档。
