# 阶段8 / WDSP 开工说明

| 项 | 内容 |
|----|------|
| 产品 | **WDSP** = WAF + 统一 Web/API 动态防护（阶段8） |
| 开发线 | `develop`（集成）/ `feature/stage8-*`（功能） |
| WAF 发版线 | `main`（仅 bugfix / 小兼容；不堆未完成 API 能力） |
| 分支策略 | [BRANCHING_AND_PRODUCT_LINES.md](../BRANCHING_AND_PRODUCT_LINES.md) |
| 完整任务书 | [STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md](STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md) |

---

## 1. 开工状态

- [x] 远程分支 `develop` 已从 `main` 创建  
- [x] 任务书入库  
- [x] `PRODUCT_EDITION` / `API_DYNAMIC_PROTECTION_ENABLED` 配置骨架  
- [x] `gateway/dynamic_security/context`：`RequestContext` 类型与最小化约束  
- [x] Wave A：parse/normalize/classifier/decision/pipeline；外部 WAF match 写入上下文；API 关 skip  
- [x] Wave B：API发现/确认 API + 迁移 + 前端页  
- [x] Wave C：学习候选/冻结 + schema 偏离 + 主事件多明细  
- [x] Wave D：阶段7 AI Tool 接入（`api_*` 已落地：aitools/api_tools.go 10 个 + api_ops_tools.go 5 个，全部 READ_ONLY 且仅 WDSP 形态注册）  

---

## 2. 波次（与任务书执行顺序对齐）

### Wave A — 统一引擎骨架（当前）

1. 产品 edition 与 API 能力总开关（**默认关闭**，保证 WAF 包行为不变）  
2. `RequestContext` 数据结构与扩展注册约定  
3. 请求体解析限制（大小/深度/字段数）配置  
4. 后续：`parser` / `normalizer`；把 jiuzhang_guard、Coraza 改为「写上下文 + 统一决策」  

**验收**：开关关闭时现有 WAF 路径无行为回归；开关打开时仅多日志/空检测管线可观测。

### Wave B — API 资产与学习

- 识别、路径归一、API表、参数/Schema 微模型、版本/确认/冻结  

### Wave C — 运行时检测与统一决策

- 偏离、敏感、身份限流、BOLA 基础、统一决策、统一主事件  

### Wave D — AI 与收口

- `api_*` Tools；前端资产页；性能/安全测试；退出条件勾选  

---

## 3. 目录约定（本仓）

```text
gateway/dynamic_security/     # 阶段8 运行时库（可被 Caddy module 引用）
  context/                    # RequestContext
  parser/                     # 后续
  ...
server/internal/product/      # 产品 edition / 能力开关（管理面）
docs/tasks/STAGE_8_*.md
```

网关侧现有 `gateway/modules/jiuzhang_guard` **保留**；阶段8 通过适配层挂接，避免一次性推翻阶段5。

---

## 4. 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `PRODUCT_EDITION` | `waf` | `waf` \| `wdsp`，影响菜单/打包语义 |
| `API_DYNAMIC_PROTECTION_ENABLED` | `false` | 是否启用 API 动态防护管线 |
| `API_MAX_BODY_PARSE_BYTES` | `1048576` | 完整解析请求体上限（1MiB） |
| `API_MAX_BODY_SAMPLE_BYTES` | `65536` | 超限后采样长度 |
| `API_MAX_JSON_DEPTH` | `32` | JSON 最大深度 |
| `API_MAX_FIELD_COUNT` | `2048` | 单请求最大字段数 |

---

## 5. 协作规则（再强调）

1. WAF 线上 bug → `main` → 再 merge 进 `develop`  
2. 阶段8 功能 → `feature/stage8-*` → `develop`  
3. 未完成 API **默认关闭**，不得破坏 `main` 上 WAF 发版  
4. 一次只推进一个明确子目标（见 `AGENTS.md`）  

---

Copyright © 聚信得仁  
All Rights Reserved.
