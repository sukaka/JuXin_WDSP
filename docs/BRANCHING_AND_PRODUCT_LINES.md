# 产品线与分支策略（WAF / WDSP / API）

本文约定九章在 **同一仓库** 内维护三条产品交付线的方式，避免「多主干」分叉导致公共 bug 修多遍、修漏。

| 产品 | 含义 | 与代码关系 |
|------|------|------------|
| **WAF** | 已交付的 Web 应用防火墙（阶段1–6 主体 + 修 bug / 小改进） | 共享底座 + Web 防护域；**默认可独立发补丁** |
| **WDSP** | Web 动态安全防护 = **WAF + API 动态防护**（阶段8 及以后） | 同一代码库的**超集**；API 能力可开关、可独立打包边界 |
| **API** | 未来「九章API安全系统」= 共享底座 + API 能力域（不含 Web 防护交付） | 同一仓库的**另一种 edition 打包**；能力域边界见阶段8 任务书 §49 与本文 §5.1 |

**原则一句话**：一套代码、一条可发 WAF 的主干修公共问题；三条产品线共用同一底座、同一仓库，用 edition / 能力开关区分交付；公共缺陷永远只修一份，不维护多份拷贝仓库。

三条产品线的能力构成：

```text
共享底座（认证 / RBAC / 审计 / 发布 / 应用接入 / 统一流量引擎 / 事件中心 / 报表 / AI 底座）
   ├── + Web 防护域          = WAF
   ├── + Web 防护域 + API 域 = WDSP
   └── + API 能力域          = API（九章API安全系统，随阶段8 能力域成熟后启用）
```

---

## 1. 仓库与远程

- 仓库：`JiuZhang_WAF`（GitHub 私有仓等），**单一 monorepo**。
- 默认远程：`origin`，默认主分支：`main`。
- **禁止**为 WDSP 或未来的 API 产品再 fork 一份完整业务仓长期多开（公共 bug 必漏修）。API 独立产品是同一仓库的 edition 打包，不是新仓库。

---

## 2. 分支命名

| 分支 | 用途 | 谁往里合 |
|------|------|----------|
| **`main`** | **WAF 可发版线**。稳定能力 + bugfix + **向后兼容的小改进**。 | `hotfix/*`、`fix/*`、经评审的 `feature/*`（仅限小兼容改动） |
| **`develop`**（可选长期线） | **WDSP / 阶段8 / API 能力域集成线**。API 动态防护、统一上下文、API edition 打包等大功能在此集成。 | `feature/wdsp-*`、`feature/stage8-*`、`feature/api-*`；并 **定期合入 `main`** |
| **`feature/<topic>`** | 短生命周期功能分支（1–2 周内合入目标线） | → `main` 或 → `develop`（见下） |
| **`feature/wdsp-*` / `feature/stage8-*` / `feature/api-*`** | WDSP / 阶段8 / API 能力域专用功能 | → **`develop`**（勿直接污染 `main` 发版语义） |
| **`fix/*`** | 非紧急缺陷 | → 视影响面：公共问题 → `main`；仅 WDSP/API → `develop` |
| **`hotfix/waf-*`** | **线上 WAF 紧急修复** | → **`main`**，再立刻 **merge `main` → `develop`** |
| **`release/waf-x.y`** | （可选）WAF 发版冻结窗口 | 仅接受 hotfix |
| **`release/wdsp-x.y` / `release/api-x.y`** | （可选）WDSP / API 发版冻结窗口 | 从 `develop` 拉出，可再合 `main` 补丁 |

### 合入方向（硬约定）

```text
hotfix/fix(公共) ──► main ──► develop（定期 / 每发 WAF 补丁后必须）
feature/wdsp-*、feature/stage8-*、feature/api-* ──► develop
feature(小兼容)  ──► main（评审确认不影响 WAF 发版）
develop          ──► main   仅当：API 能力默认关闭或 WAF 包确认不带半成品，且通过回归
```

**禁止**：

- 在 `develop` 上修公共 bug 却 **不** 回 `main`。
- 把未完成、默认开启的 API 大功能直接合进 `main` 并打 WAF 包。
- 多个长期分叉的「各自 main」互不 merge。

---

## 3. 什么改动进哪条线

判断标准是**代码归属的能力域**，而不是 bug 在哪条产品线被发现：API 产品用户报出的底座 bug 同样修 `main`。

| 改动类型 | 目标分支 | 说明 |
|----------|----------|------|
| 认证、RBAC、审计、发布、应用接入、备份、监控、统一流量引擎公共部分 | `main` | 共享底座，三条产品线共用 |
| WAF 策略、事件、Coraza/CRS、CC、访问控制 | `main` | Web 防护域，WAF 核心 |
| 报表、AI 底座（已交付部分） | `main` | 修 bug / 小改进 |
| 阶段7 AI 小修、权限修复 | `main` 优先 | 大块未验收能力可走 `feature/ai-*` → 评审后再合 |
| 统一 `RequestContext`、一次解析、API 发现/学习/偏离 | **`develop` / `feature/stage8-*`** | API 能力域，WDSP 增量 |
| API 资产前端、图谱、BOLA 等 | **`develop`** | API 能力域，WDSP 增量 |
| 阶段8 AI Tool（`api_*`） | **`develop`**，且依赖阶段7 Tool 底座已可用 | 见任务书 §48 |
| API edition 打包、菜单/路由按 edition 过滤 | **`develop`** | 跟随阶段8 里程碑 |

---

## 4. 版本与 Tag

### 4.1 产品版本号

| 产品 | 建议格式 | 示例 |
|------|----------|------|
| WAF | `MAJOR.MINOR.PATCH` | `1.0.0` → `1.0.1`（补丁） |
| WDSP | `MAJOR.MINOR.PATCH` 或带前缀 | `wdsp-0.1.0` / `2.0.0` |
| API | `MAJOR.MINOR.PATCH` 或带前缀 | `api-0.1.0` |

- **PATCH**：仅 bugfix / 安全补丁，API 兼容。  
- **MINOR**：小功能、兼容增强。  
- **MAJOR**：不兼容变更或产品代际。  
- WDSP / API 发版说明中应写清：**基于的共享底座版本 / 对应 git tag**。

### 4.2 Git Tag 约定

```text
waf-v1.0.0          # WAF 正式版（打在 main 上某 commit）
waf-v1.0.1          # WAF 补丁
wdsp-v0.1.0         # WDSP 正式/预览版（打在 develop 或 release/wdsp-* 上）
api-v0.1.0          # API 正式/预览版（打在 develop 或 release/api-* 上）
```

- Tag **不可变**；纠错发新 PATCH，不改写旧 tag。  
- 同一 monorepo commit 可只打一种产品 tag，也可同一 commit 打多种产品 tag（当该 commit 同时满足多套发版条件时）。

### 4.3 发版检查清单（摘要）

**WAF 包**

- [ ] 基于 `main`（或 `release/waf-*`）  
- [ ] API 动态防护 **默认关闭**，菜单/权限不暴露半成品  
- [ ] 回归：登录、发布、WAF 阻断、CC、备份等冒烟通过  

**WDSP 包**

- [ ] 已 merge 最新 `main`（含全部 WAF 补丁）  
- [ ] API 能力开关可开；关闭时行为与 WAF 一致  
- [ ] 阶段8 相关冒烟 + 不影响 WAF 核心路径  

**API 包**

- [ ] 已 merge 最新 `main`（含全部底座与 WAF 补丁）  
- [ ] Web 防护专属菜单/策略面板不暴露；底座功能（登录/审计/发布/事件中心）正常  
- [ ] API 能力域冒烟通过；共享底座行为与 WAF/WDSP 一致  

---

## 5. 产品 Edition 与能力开关

构建 / 部署用环境变量或配置区分交付物（实现时可落在 `.env` / compose / 安装包清单，名称保持稳定）：

| 变量（建议） | WAF 默认 | WDSP 默认 | API 默认 | 含义 |
|--------------|----------|-----------|----------|------|
| `PRODUCT_EDITION` | `waf` | `wdsp` | `api` | 产品形态：菜单、文档、打包清单 |
| `API_DYNAMIC_PROTECTION_ENABLED` | `false` | `true` | `true` | 是否加载 API 发现/学习/偏离等检测器 |
| `WEB_WAF_ENABLED`（可选，随 API edition 引入） | `true` | `true` | `false` | 是否交付 Web 防护专属策略面板/菜单；统一流量引擎基础防护不受影响 |
| （可选）`AI_SOC_ENABLED` | 按安装选择 | 按安装选择 | 按安装选择 | 与阶段7 打包解耦，可单独关 |

约定：

1. **同一套二进制/镜像** 可通过 edition 打成三种包；差异在配置与前端路由过滤，不在多套源码树。  
2. `API_DYNAMIC_PROTECTION_ENABLED=false` 时：**不得**改变现有 WAF 请求处理正确性；不得依赖 API 表不存在就 panic（迁移策略：WAF 包可不跑阶段8 迁移，或迁移空转无害）。  
3. 三条产品线共享同一数据库 schema 演进主线；任一 edition 不跑的能力域迁移必须空转无害。  
4. 前端：`PRODUCT_EDITION=waf` 时隐藏 API 资产/模型/图谱等菜单；`PRODUCT_EDITION=api` 时隐藏 WAF 策略/CC/访问控制等 Web 防护专属菜单；权限种子仍可存在，路由守卫拒绝访问。  
5. 未来「九章 API 安全系统」独立产品：抽取 **API 能力域模块**，复用本仓底座，**不**再复制用户/审计/发布。

### 5.1 能力域目录边界（硬约束）

为保证三条产品线长期共用底座、且 API 能力域未来可拆分独立产品，阶段8 起代码按三个能力域组织：

| 能力域 | 网关（`gateway/`） | 服务端（`server/`） | 前端（`web/src/`） |
|--------|--------------------|---------------------|--------------------|
| 共享底座 | Request ID、真实 IP、可信代理、配置热加载、统一流量引擎骨架、日志/事件总线 | `internal/` 下用户、认证、RBAC、审计、应用接入、发布、备份、报表等既有模块 | 布局、登录、系统管理、审计、应用接入 |
| Web 防护域 | Coraza/CRS 集成、CC、访问控制、WAF 策略执行 | WAF 策略、事件中心、访问控制、CC 配置模块 | WAF 策略、事件中心、访问控制页面 |
| API 能力域 | `modules/api_*`：API 识别、采样、Schema/偏离检测输出 | `internal/api_*`：API 资产、模型版本、参数模型、图谱、BOLA | `pages/api-*`：API 资产、模型、图谱页面 |

边界规则：

1. **底座不得 import 任一能力域**；能力域之间不得互相 import。API 域需要 Web 检测结果时，通过统一 `RequestContext` / 统一决策接口读取，不直接依赖 Coraza 适配器。  
2. API 逻辑禁止写死进 WAF 规则页面或 Coraza 适配器内部（阶段8 任务书 §49）。  
3. 新增能力域的表、接口、前端路由必须挂在对应域目录下，PR 评审时按目录核对归属。  
4. 修公共 bug 时若发现必须改能力域代码才能绕过，说明边界已被侵蚀：应把逻辑重构回边界内，而不是跨域打补丁。  
5. 新增共享底座能力（三条线都要用的通用功能）一律进底座目录、走 `main`，不放在任何能力域里「先凑合」。

---

## 6. 日常工作流

### 6.1 修线上 Bug（任一产品线）

```text
1. 判断归属：底座 / Web 防护域 → main；仅 API 能力域 → develop
2. 从 main 拉 hotfix/<product>-<issue>（公共问题一律视为 waf 线处理）
3. 修复 + 测试
4. PR → main，打 tag waf-vX.Y.Z（若发补丁）
5. 立即：merge main → develop（或 rebase develop 于 main）
6. 若 WDSP / API 已发版，评估是否打对应产品补丁 tag
```

### 6.2 做 WDSP / 阶段8 / API 能力域功能

```text
1. 从 develop（或最新 main）拉 feature/stage8-<topic> 或 feature/api-<topic>
2. 开发仅限 API 能力域 / 统一引擎相关；公共 bug 仍回 main
3. PR → develop
4. 发 WDSP 或 API 包前：develop 合入最新 main，全量回归
```

### 6.3 同步节奏

| 动作 | 频率建议 |
|------|----------|
| `main` → `develop` | **每次 hotfix 后必须**；平时至少每周一次 |
| `develop` → `main` | 仅里程碑：API 默认关 + WAF 回归绿，或明确「main 开始承载关闭态 API 骨架」 |

### 6.4 多产品 CI 验证矩阵

「关闭态行为一致」「底座改动不影响任一产品线」不得只靠人工评审。同一 commit 必须在 CI 中按 edition 矩阵验证：

| CI 任务 | edition | 内容 | 门禁 |
|---------|---------|------|------|
| `build` | `waf` / `wdsp` / `api` | 三种打包配置均可构建 | 每个 PR |
| `smoke-waf` | `waf` | 登录、发布、WAF 阻断、CC、备份冒烟；断言 API 菜单/路由不可达 | PR → `main` 必绿 |
| `smoke-wdsp` | `wdsp` | 阶段8 冒烟 + WAF 核心路径回归 | PR → `develop` 必绿；改底座代码的 PR → `main` 也必绿 |
| `smoke-api` | `api` | API 能力可用；WAF 专属菜单不暴露；底座功能正常 | API edition 引入后，PR → `develop` 必绿 |

规则：

- 任一产品线发版前：对应 edition 的 CI 全绿，且分支已含最新 `main`。  
- 某 edition 尚未实现前，其 CI 任务以「跳过并记录」处理，不得静默缺失；实现后立即转为门禁。  
- 底座代码的 PR 若导致任一 smoke 任务变红，按公共缺陷处理，先修再合。

---

## 7. 与阶段7 / 阶段8 的关系

| 阶段 | 建议落点 |
|------|----------|
| 阶段7 收尾（模型管理、权限、小缺陷） | 优先 `main`，保持 AI 底座可被三条产品线共用 |
| 阶段8 统一链路、API 资产/学习/检测 | **`develop` / `feature/stage8-*`** |
| 阶段8 AI Tool（`api_*`） | `develop`，依赖阶段7 Tool/证据机制可用后再接 |
| API edition 打包（菜单过滤、安装清单） | `develop`，跟随阶段8 里程碑 |

并行开发时：

- **轨道 A**：`main` 修 WAF + 阶段7 尾巴  
- **轨道 B**：`develop` 做 WDSP 主干与 API 能力域  
- **硬依赖阶段7 的仅**：API 相关 AI Tool 接入与验收，不挡 RequestContext / 发现 / 学习 / 统一决策 等开发  

详见：

- [阶段4–7 合并修复方案](tasks/STAGE_4_7_REMEDIATION_PLAN.md)  
- 阶段8 任务书（统一 Web 与 API 动态防护）  

---

## 8. PR 与评审最低要求

- PR 标题标明产品影响：`[waf]` / `[wdsp]` / `[api]` / `[shared]`。  
- **shared**：必须说明是否影响发布兼容与默认配置，并确认 CI 矩阵中相关 smoke 全绿。  
- **wdsp / api**：说明是否默认关闭、对纯 WAF 路径的影响；新增代码归属的能力域目录是否符合 §5.1。  
- 禁止为过测试删除权限校验、脱敏或 fail-closed 相关逻辑（见 `AGENTS.md`）。

---

## 9. 禁止事项（摘要）

1. 多仓库拷贝式分叉维护（包括未来 API 独立产品）。  
2. 公共缺陷只修在某一条产品线分支。  
3. 半成品 API 默认开启进入 WAF 正式包。  
4. 强推 / 改写已发布 tag 历史。  
5. 用 Mock 冒充任一产品线发版完成。  
6. 底座 import 能力域、能力域互相 import（见 §5.1）。  

---

## 10. 快速对照

| 我要… | 怎么做 |
|-------|--------|
| 修生产 WAF bug | `hotfix` → `main` → 再合 `develop` |
| 修 API / WDSP 线发现的**底座** bug | 同上：一律 `main` → 再合 `develop` |
| 修仅 API 能力域的 bug | `fix` → `develop` |
| 做 API 发现/学习 | `feature/stage8-*` → `develop` |
| 做三条线都要用的通用功能 | 进底座目录，`feature` → `main`，评审确认兼容 |
| 发 WAF 1.0.1 | `main` + tag `waf-v1.0.1`，edition=waf |
| 发 WDSP 0.1 | `develop`（已含 main）+ tag `wdsp-v0.1.0`，edition=wdsp |
| 发 API 0.1 | `develop`（已含 main）+ tag `api-v0.1.0`，edition=api |
| 保证三条线都有修复 | **只改一份 + main 向 develop 单向常合 + CI edition 矩阵兜底** |

---

Copyright © 聚信得仁  
All Rights Reserved.
