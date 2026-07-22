# 产品线与分支策略（WAF / WDSP）

本文约定九章在 **同一仓库** 内维护两条产品交付线的方式，避免「双主干」分叉导致 bug 修两边。

| 产品 | 含义 | 与代码关系 |
|------|------|------------|
| **WAF** | 已交付的 Web 应用防火墙（阶段1–6 主体 + 修 bug / 小改进） | 共享底座 + Web 防护；**默认可独立发补丁** |
| **WDSP** | Web 动态安全防护 = **WAF + API 动态防护**（阶段8 及以后） | 同一代码库的**超集**；API 能力可开关、可独立打包边界 |

**原则一句话**：一套代码、一条可发 WAF 的主干修公共问题；WDSP 大功能在旁支演进，定期合入主干修复；用 edition / 能力开关区分交付，不维护两份拷贝仓库。

---

## 1. 仓库与远程

- 仓库：`JiuZhang_WAF`（GitHub 私有仓等），**单一 monorepo**。
- 默认远程：`origin`，默认主分支：`main`。
- **禁止**为 WDSP 再 fork 一份完整业务仓长期双开（公共 bug 必漏修）。

---

## 2. 分支命名

| 分支 | 用途 | 谁往里合 |
|------|------|----------|
| **`main`** | **WAF 可发版线**。稳定能力 + bugfix + **向后兼容的小改进**。 | `hotfix/*`、`fix/*`、经评审的 `feature/*`（仅限小兼容改动） |
| **`develop`**（可选长期线） | **WDSP / 阶段8 集成线**。API 动态防护、统一上下文等大功能在此集成。 | `feature/wdsp-*`、`feature/stage8-*`；并 **定期合入 `main`** |
| **`feature/<topic>`** | 短生命周期功能分支（1–2 周内合入目标线） | → `main` 或 → `develop`（见下） |
| **`feature/wdsp-*` / `feature/stage8-*`** | WDSP / 阶段8 专用功能 | → **`develop`**（勿直接污染 `main` 发版语义） |
| **`fix/*`** | 非紧急缺陷 | → 视影响面：公共问题 → `main`；仅 WDSP → `develop` |
| **`hotfix/waf-*`** | **线上 WAF 紧急修复** | → **`main`**，再立刻 **merge `main` → `develop`** |
| **`release/waf-x.y`** | （可选）WAF 发版冻结窗口 | 仅接受 hotfix |
| **`release/wdsp-x.y`** | （可选）WDSP 发版冻结窗口 | 从 `develop` 拉出，可再合 `main` 补丁 |

### 合入方向（硬约定）

```text
hotfix/fix(公共) ──► main ──► develop（定期 / 每发 WAF 补丁后必须）
feature/wdsp-*    ──► develop
feature(小兼容)   ──► main（评审确认不影响 WAF 发版）
develop           ──► main   仅当：API 能力默认关闭或 WAF 包确认不带半成品，且通过回归
```

**禁止**：

- 在 `develop` 上修公共 bug 却 **不** 回 `main`。
- 把未完成、默认开启的 API 大功能直接合进 `main` 并打 WAF 包。
- 两个长期分叉的「各自 main」互不 merge。

---

## 3. 什么改动进哪条线

| 改动类型 | 目标分支 | 说明 |
|----------|----------|------|
| 认证、RBAC、审计、发布、应用接入 | `main` | 共享底座 |
| WAF 策略、事件、Coraza/CRS、CC、访问控制 | `main` | WAF 核心 |
| 报表、备份、监控（已交付部分） | `main` | 修 bug / 小改进 |
| 阶段7 AI 小修、权限修复 | `main` 优先 | 大块未验收能力可走 `feature/ai-*` → 评审后再合 |
| 统一 `RequestContext`、一次解析、API 发现/学习/偏离 | **`develop` / `feature/stage8-*`** | WDSP 增量 |
| API 资产前端、图谱、BOLA 等 | **`develop`** | WDSP 增量 |
| 阶段8 AI Tool（`api_*`） | **`develop`**，且依赖阶段7 Tool 底座已可用 | 见任务书 §48 |

---

## 4. 版本与 Tag

### 4.1 产品版本号

| 产品 | 建议格式 | 示例 |
|------|----------|------|
| WAF | `MAJOR.MINOR.PATCH` | `1.0.0` → `1.0.1`（补丁） |
| WDSP | `MAJOR.MINOR.PATCH` 或带前缀 | `wdsp-0.1.0` / `2.0.0` |

- **PATCH**：仅 bugfix / 安全补丁，API 兼容。  
- **MINOR**：小功能、兼容增强。  
- **MAJOR**：不兼容变更或产品代际。  
- WDSP 发版说明中应写清：**基于的 WAF 底座版本 / 对应 git tag**。

### 4.2 Git Tag 约定

```text
waf-v1.0.0          # WAF 正式版（打在 main 上某 commit）
waf-v1.0.1          # WAF 补丁
wdsp-v0.1.0         # WDSP 正式/预览版（打在 develop 或 release/wdsp-* 上）
```

- Tag **不可变**；纠错发新 PATCH，不改写旧 tag。  
- 同一 monorepo commit 可只打一种产品 tag，也可同一 commit 打 `waf-v*` 与 `wdsp-v*`（当该 commit 同时满足两套发版条件时）。

### 4.3 发版检查清单（摘要）

**WAF 包**

- [ ] 基于 `main`（或 `release/waf-*`）  
- [ ] API 动态防护 **默认关闭**，菜单/权限不暴露半成品  
- [ ] 回归：登录、发布、WAF 阻断、CC、备份等冒烟通过  

**WDSP 包**

- [ ] 已 merge 最新 `main`（含全部 WAF 补丁）  
- [ ] API 能力开关可开；关闭时行为与 WAF 一致  
- [ ] 阶段8 相关冒烟 + 不影响 WAF 核心路径  

---

## 5. 产品 Edition 与能力开关

构建 / 部署用环境变量或配置区分交付物（实现时可落在 `.env` / compose / 安装包清单，名称保持稳定）：

| 变量（建议） | WAF 默认 | WDSP 默认 | 含义 |
|--------------|----------|-----------|------|
| `PRODUCT_EDITION` | `waf` | `wdsp` | 产品形态：菜单、文档、打包清单 |
| `API_DYNAMIC_PROTECTION_ENABLED` | `false` | `true` | 是否加载 API 发现/学习/偏离等检测器 |
| （可选）`AI_SOC_ENABLED` | 按安装选择 | 按安装选择 | 与阶段7 打包解耦，可单独关 |

约定：

1. **同一套二进制/镜像** 可通过 edition 打成两种包；差异在配置与前端路由过滤，不在两套源码树。  
2. `API_DYNAMIC_PROTECTION_ENABLED=false` 时：**不得**改变现有 WAF 请求处理正确性；不得依赖 API 表不存在就 panic（迁移策略：WAF 包可不跑阶段8 迁移，或迁移空转无害）。  
3. 前端：`PRODUCT_EDITION=waf` 时隐藏 API 资产/模型/图谱等菜单；权限种子仍可存在，路由守卫拒绝访问。  
4. 未来「九章 API 安全系统」独立产品：抽取 **API 能力域模块**，复用本仓底座，**不**再复制用户/审计/发布。

---

## 6. 日常工作流

### 6.1 修 WAF 线上 Bug

```text
1. 从 main 拉 hotfix/waf-<issue>
2. 修复 + 测试
3. PR → main，打 tag waf-vX.Y.Z（若发补丁）
4. 立即：merge main → develop（或 rebase develop 于 main）
5. 若 WDSP 已发版，评估是否打 wdsp 补丁 tag
```

### 6.2 做 WDSP / 阶段8 功能

```text
1. 从 develop（或最新 main）拉 feature/stage8-<topic>
2. 开发仅限 API/统一引擎相关；公共 bug 仍回 main
3. PR → develop
4. 发 WDSP 前：develop 合入最新 main，全量回归
```

### 6.3 同步节奏

| 动作 | 频率建议 |
|------|----------|
| `main` → `develop` | **每次 WAF hotfix 后必须**；平时至少每周一次 |
| `develop` → `main` | 仅里程碑：API 默认关 + WAF 回归绿，或明确「main 开始承载关闭态 API 骨架」 |

---

## 7. 与阶段7 / 阶段8 的关系

| 阶段 | 建议落点 |
|------|----------|
| 阶段7 收尾（模型管理、权限、小缺陷） | 优先 `main`，保持 AI 底座可被 WAF/WDSP 共用 |
| 阶段8 统一链路、API 资产/学习/检测 | **`develop` / `feature/stage8-*`** |
| 阶段8 AI Tool（`api_*`） | `develop`，依赖阶段7 Tool/证据机制可用后再接 |

并行开发时：

- **轨道 A**：`main` 修 WAF + 阶段7 尾巴  
- **轨道 B**：`develop` 做 WDSP 主干  
- **硬依赖阶段7 的仅**：API 相关 AI Tool 接入与验收，不挡 RequestContext / 发现 / 学习 / 统一决策 等开发  

详见：

- [阶段4–7 合并修复方案](tasks/STAGE_4_7_REMEDIATION_PLAN.md)  
- 阶段8 任务书（统一 Web 与 API 动态防护）  

---

## 8. PR 与评审最低要求

- PR 标题标明产品影响：`[waf]` / `[wdsp]` / `[shared]`。  
- **shared / waf**：必须说明是否影响发布兼容与默认配置。  
- **wdsp**：说明是否默认关闭、对纯 WAF 路径的影响。  
- 禁止为过测试删除权限校验、脱敏或 fail-closed 相关逻辑（见 `AGENTS.md`）。

---

## 9. 禁止事项（摘要）

1. 双仓库拷贝式分叉维护。  
2. 公共缺陷只修在 WDSP 线。  
3. 半成品 API 默认开启进入 WAF 正式包。  
4. 强推 / 改写已发布 tag 历史。  
5. 用 Mock 冒充 WDSP 或 WAF 发版完成。  

---

## 10. 快速对照

| 我要… | 怎么做 |
|-------|--------|
| 修生产 WAF bug | `hotfix` → `main` → 再合 `develop` |
| 做 API 发现/学习 | `feature/stage8-*` → `develop` |
| 发 WAF 1.0.1 | `main` + tag `waf-v1.0.1`，edition=waf |
| 发 WDSP 0.1 | `develop`（已含 main）+ tag `wdsp-v0.1.0`，edition=wdsp |
| 保证两边都有修复 | **只改一份 + main 向 develop 单向常合** |

---

Copyright © 聚信得仁  
All Rights Reserved.
