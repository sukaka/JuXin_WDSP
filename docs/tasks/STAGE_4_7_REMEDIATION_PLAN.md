# 阶段4–7 安全与功能合并修复方案

| 项 | 内容 |
|----|------|
| 状态 | 主项已实施（2026-07-22）；M-08、M-22–M-24 已完成；M-26 两项已完成（2026-09-10）；M-13 部分完成（仅日志，节流事件与首刷拒绝待补） |
| 依据 | 本地代码审查（安全）+ 功能审计（产品闭环） |
| 范围 | 网关 `jiuzhang_guard`、管理面 Stage4–7、发布管道、AI 草稿、备份恢复 |
| 原则 | 一次一波次交付；先打通「配置→发布→网关生效」再修运营体验；安全缺陷与功能断点同等优先级排序 |

---

## 1. 背景与结论

两次审查结论互补：

| 维度 | 核心判断 |
|------|----------|
| **安全审查** | 架构与主序大体正确；残余风险集中在 **密钥泄漏**、**共享 engine 生命周期**、**故障默认 fail-open**、**429 响应头**、版本 API 回传敏感配置。 |
| **功能审计** | 管理面表面完整，但多条 **Stage4/5 主防护链路未闭合**：自定义规则不下发、策略无法绑定应用、`rule_overrides` 空壳、保护地址可能旁路 ACL/CC、TEMP_BLOCK 在 Valkey 抖动下失效。 |

**总评**：文档与 UI 易给人「阶段4–6 已可正式交付」的印象；若不修复下列 P0，**策略/自定义规则/CC 临时封禁在真实拓扑下可能无效或部分无效**，同时存在 **Valkey 凭据经版本 API/历史配置外泄** 的风险。

本方案将两份问题清单 **去重合并**，按 **对真实防护与数据安全的影响** 分波次执行，并明确验收标准。

---

## 2. 问题合并总表

编号规则：`S-` 源自安全审查，`F-` 源自功能审计，`M-` 为合并后的统一项（实现时以 M- 为准）。

### 2.1 P0 — 必须在下一波交付前关闭

| ID | 来源 | 问题摘要 | 类型 | 关键路径 |
|----|------|----------|------|----------|
| **M-01** | S1 | Guard/Valkey 密码写入 `access_control_versions`、版本 List/Get、Caddy 配置历史；API 可读明文 | 安全 | `guardconfig/provider.go`、`accesscontrolversions`、发布落盘 |
| **M-02** | F2 | 防护策略↔应用 **无绑定 API/UI**，PL/阈值发布永远回落默认 | 功能断链 | `protectionpolicies`、`app.go`、前端策略/应用页 |
| **M-03** | F1 | 自定义规则仅 DB+UI，发布只 Include 静态 `jiuzhang-custom.conf` | 功能断链 | `gatewayconfig/generator.go`、`publisher`、`customrules` |
| **M-04** | F4 | 保护地址 `clientIP \|\| ConnectionIP` 提前放行，本机反代/LB 拓扑可旁路 ACL/CC | 安全+功能 | `jiuzhang_guard/module.go`、保护地址刷新逻辑 |
| **M-05** | F5 + S8 | TEMP_BLOCK：`Refresh` 全量替换冲掉本地封禁；Valkey Put 失败仍宣称封禁 | 功能+韧性 | `temporaryblock`、`module.go` |
| **M-06** | S2 + F6 | `sync.Once` 半初始化：首次 Valkey 失败后后续 Provision 返回残缺 engine → panic 风险 | 安全+稳定 | `jiuzhang_guard/module.go` |
| **M-07** | S3 + F17 | 共享 engine 首次成功后不随配置热更（密码/地址/backend）；发布「成功」但运行时仍旧配置 | 运维正确性 | `module.go` + 发布校验/文档 |

### 2.2 P1 — 强烈建议本阶段内完成

| ID | 来源 | 问题摘要 | 类型 |
|----|------|----------|------|
| **M-08** | F3 | `rule_overrides` 表+权限已有，无 CRUD/发布注入；文档标已完成 | 功能空壳 / 文档诚实 |
| **M-09** | F7 | 临时例外 `ExpireTemporary` 无调度；UI 仍 ENABLED，网关 ctl 靠下次发布 | 功能 |
| **M-10** | S9 + F8 | 发布加载例外 `_, err` 丢弃 → DB 抖动可「成功发布但零例外」 | 安全+功能 |
| **M-11** | S4 | 429 `Content-Type` 写在 `WriteHeader` 之后被忽略 | 协议正确性 |
| **M-12** | S5 | `GUARD_FAIL_OPEN` 默认 `true`；生产宜 fail-closed | 安全策略 |
| **M-13** | S6 | 启动 `blockCache.Refresh` 失败无日志/事件，空缓存窗口 | 可观测 |
| **M-14** | F13 | 全局 CC 触发的 TEMP_BLOCK 带 `AppID`，跨应用多放过一轮 | 功能 |
| **M-15** | F12 | 恢复维护模式 flag 未在 API 中间件强制 | 功能 |
| **M-16** | F11 | 报告任务卡在 COLLECTING/RENDERING 无回收 | 功能 |

### 2.3 P2 — 体验、可观测与诚实性

| ID | 来源 | 问题摘要 |
|----|------|----------|
| **M-17** | F9 | 访问控制版本 list/diff/rollback 仅 API，无前端 |
| **M-18** | F10 | 事件统计分布基于最近 100 条样本，占比误导 |
| **M-19** | S10 | 版本 List 返回完整 config blob（即便 redact 密码后也过重） |
| **M-20** | F14 | 白名单是否绕过临时封禁需产品定调并写进文档/实现 |
| **M-21** | F15 / S 相关 | 令牌桶拒绝 `current_count=0`，事件计量失真 |
| **M-22** | F16 | 例外策略无 PUT 更新 |
| **M-23** | S7 | AI draft 插入未走完整 `ValidateInput` |
| **M-24** | F18 | `CC_TEMP_BLOCK_EXPIRED/RELEASED` 事件未产出 |
| **M-25** | 文档 | Stage7 标「未开始」与代码不符；多项「已完成」需降级或补齐 |
| **M-26** | S11/S12 | 可信链全 trusted 回落；CSRF Origin 端口归一（nit） |

---

## 3. 目标架构约束（修复时不得破坏）

1. **请求处理顺序**（网关）：Request ID → 真实客户端 IP → 可信代理 → IP 白 → IP 黑 → 临时封禁 → CC → 协议/大小 → Coraza/CRS → 反代。  
2. **白名单**：绕过黑名单与 CC，**不绕过 WAF**；是否绕过「人工临时封禁」见 M-20 产品决策。  
3. **保护地址语义**：「该地址作为 **客户端** 时永不被封」≠「经该连接源进来的所有流量免检」。  
4. **密钥**：版本历史、List API、diff、备份导出 **不得** 回传 Valkey/私钥明文；运行时注入仅在发布写网关配置瞬间从环境/密钥库读取。  
5. **故障策略**：生产默认 fail-closed；fail-open 仅显式开关 + 告警。  
6. **一次一阶段交付**：本方案拆为 4 个可独立验收的波次（Wave），每波附测试，不跳波宣称完成。

---

## 4. 分波次实施方案

### Wave A — 密钥与引擎安全（约 1–2 人日）

**目标**：消除凭据外泄与 engine 崩溃类缺陷。

| 任务 | 对应 | 做法要点 |
|------|------|----------|
| A1 版本快照脱敏 | M-01, M-19 | 快照/API/diff 中 `password` 固定空或 `***`；List 仅元数据；Get 仍脱敏。发布时从 `config`/环境注入真实密码生成 Caddy JSON。回滚历史版本时 **重新注入当前运行时密钥**，不从历史 JSON 读密码。 |
| A2 修复 Once 半初始化 | M-06 | `initErr` 提升为包级/engine 字段；失败可重试或始终 sticky error；禁止返回 `limiter/blockCache == nil` 的 engine。单测：首次失败 → 二次 Provision。 |
| A3 Engine 可调和 | M-07 | Provision 时比较 backend/addr/db/密码哈希；变化则重建 limiter/blockCache。短期若无法热更：发布校验失败 + UI 明确「需重启网关」。 |
| A4 429 Content-Type | M-11 | 先设 Header 再 `WriteHeader`；用冻结 Header 的 ResponseWriter 测 JSON/HTML 分支。 |
| A5 生产 fail-closed | M-12, M-13 | `APP_ENV=prod` 默认 `GUARD_FAIL_OPEN=false`；Refresh 失败 Error 日志 + 节流事件；可选 fail-closed 时首刷失败拒绝服务。 |

**验收**

- [ ] 版本 List/Get/diff 响应与 DB 快照中无真实 Valkey 密码。  
- [ ] 发布后网关仍能连 Valkey（注入路径正确）。  
- [ ] Valkey 首次连接失败不会导致后续 panic。  
- [ ] 429 响应带正确 `Content-Type`。  
- [ ] 生产配置默认 fail-closed（或文档+强制 prod 校验）。

---

### Wave B — Stage4 防护主链路闭合（约 2–3 人日）

**目标**：「策略绑定 / 自定义规则 / 例外加载」真实进网关。

| 任务 | 对应 | 做法要点 |
|------|------|----------|
| B1 策略绑定 API+UI | M-02 | `POST/DELETE /api/v1/protection-policies/{id}/applications` 或应用侧绑定；前端策略详情 + 应用详情可操作；发布继续用 `GetApplicationPolicyParams`。内置策略可绑。乐观锁/审计。 |
| B2 自定义规则发布注入 | M-03 | 发布时加载 `status=ENABLED` 自定义规则 SecLang，写入生成配置（建议 CRS 后、`jiuzhang-custom` 前或替代静态 include 的动态段）；内容进版本哈希。禁用/删除后下一次发布移除。 |
| B3 例外加载失败即失败 | M-10 | `GetEnabledExceptions` 错误 → 发布任务失败（与 guard 快照失败一致）。 |
| B4 临时例外调度 | M-09 | `guardjanitor` 或 Stage6 worker 调用 `ExpireTemporary`；可选提醒「需重新发布」；发布时已过滤过期行保持。 |
| B5 rule_overrides 二选一 | M-08 | **选项甲（推荐交付）**：实现最小 DISABLE 覆盖 + 发布 `ctl:ruleRemoveById`。**选项乙**：本波只改文档/状态为「未完成」，权限隐藏，避免假完成。 |

**验收**

- [ ] 绑定策略 PL=2、阈值自定义 → 发布 → 网关 SecLang 含对应 `900001` 变量。  
- [ ] 启用自定义规则 → 发布 → 真实请求命中该规则（或 DetectionOnly 有审计）。  
- [ ] 模拟 DB 查例外失败 → 发布任务 FAILED，网关配置不变。  
- [ ] 临时例外到期后状态为 EXPIRED（DB）；再发布后 ctl 消失。  
- [ ] rule_overrides：甲有端到端用例，或乙文档/菜单已降级。

---

### Wave C — 访问控制 / CC 运行时正确性（约 2 人日）

**目标**：生产拓扑下 ACL/CC/临时封禁行为符合产品语义。

| 任务 | 对应 | 做法要点 |
|------|------|----------|
| C1 保护地址只按 clientIP 早放行 | M-04 | `ServeHTTP` 仅 `protected.Contains(clientIP)` 早退；连接源保护仅体现在「禁止把该 IP 加入黑名单/临时封禁」的管理 API（已有则复核）。补集成：经 127.0.0.1 反代 + 不可信 XFF 时 ACL 仍生效。 |
| C2 TEMP_BLOCK 合并刷新 | M-05 | `Refresh` 与本地 map **按 field 合并、取较大 expires_at**；Put 失败：本地保留 + 事件标记同步失败；勿在 Put 失败时宣称集群级成功。 |
| C3 全局 TEMP_BLOCK AppID | M-14 | 策略 scope=GLOBAL 时自动封禁 `AppID=""`。 |
| C4 白名单 vs 临封产品决策 | M-20 | 默认建议：**人工/管理面临封优先于白名单**，CC 自动封禁可被白名单覆盖——或统一文档「白名单优先于一切 IP 层动作」。实现与设计文档、前端提示一致。 |
| C5 计量与事件 | M-21, M-24 | 拒绝时 `current_count` 反映用量；解封/到期写 access_control 事件（或 analytics 改映射）。 |

**验收**

- [ ] 本机反代拓扑下黑名单/CC 仍按真实客户端生效。  
- [ ] Valkey 短暂不可写时，本节点 TEMP_BLOCK 仍持续至 `block_duration`（至少不被 1s 轮询清掉）。  
- [ ] 全局策略触发后，其他应用立即拦截（全局 ban key）。  
- [ ] 事件中心/CC 概览数字与真实拒绝相关，不再大量 `current_count=0`。

---

### Wave D — 运营闭环与文档诚实（约 1.5–2 人日）

**目标**：交付、恢复、报表、AI 草稿不「假完成」。

| 任务 | 对应 | 做法要点 |
|------|------|----------|
| D1 维护模式强制 | M-15 | 中间件读 `jiuzhang:maintenance`：阻断发布/写操作（保留只读健康与恢复确认）；恢复结束 defer 清理失败则告警。 |
| D2 报告僵尸任务 | M-16 | worker 启动/周期：超时 `COLLECTING|AGGREGATING|RENDERING` → `FAILED`+`WORKER_LOST`，允许重试。 |
| D3 访问控制版本 UI | M-17 | 列表/差异/回滚 + 任务进度（复用配置版本交互）；接口已脱敏（依赖 Wave A）。 |
| D4 事件统计 | M-18 | 改用 analytics 接口或标明「样本统计」；去掉误导性「全量占比」。 |
| D5 AI 草稿校验 | M-23 | draft 创建走与人机相同的 Validate/Create 助手；`created_by` 为真实主体。 |
| D6 例外可更新（可选） | M-22 | PUT + 乐观锁，或 UI 明确「不可变，仅新建」。 |
| D7 文档与状态 | M-25 | 更新 `DEVELOPMENT_STATUS`：Stage7 进行中；列出 Wave 完成项与诚实遗留；修正「规则覆盖/自定义规则下发」等勾选。 |

**验收**

- [ ] 恢复期间无法误发布配置。  
- [ ] 杀进程后卡住的报告任务可失败并可重试。  
- [ ] 安全管理员可在 UI 回滚访问控制版本。  
- [ ] DEVELOPMENT_STATUS 与代码一致。

---

## 5. 建议排期与依赖

```text
Wave A (安全底座)
    │
    ├─► Wave B (Stage4 闭环)     // 可与 C 部分并行，但 A1 须先于「版本 UI/回滚演示」
    │
    └─► Wave C (ACL/CC 运行时)
            │
            └─► Wave D (运营/文档)
```

| 波次 | 依赖 | 建议顺序 |
|------|------|----------|
| A | 无 | 最先 |
| B | A1 强烈建议先完成（避免联调时继续写明文密码进版本） | 第二 |
| C | A2/A3 建议先完成（engine 稳定后再测 TEMP_BLOCK） | 可与 B 并行（不同目录） |
| D | A1 完成后再做版本 UI；B 完成后再强调 AI 自定义规则草稿 | 最后 |

**不建议**：先做菜单/文案优化或 Stage7 新能力扩展，再回头补主链路。

---

## 6. 测试矩阵（每波最低要求）

| 波次 | 单测 | 集成/接口 | 网关/安全 | 前端 |
|------|------|-----------|-----------|------|
| A | engine 失败重试、Content-Type、脱敏序列化 | 版本 API 无密码 | fail-closed 冒烟 | — |
| B | 生成器含自定义规则/策略参数 | 绑定→发布任务成功 | 自定义规则/PL 实测 | 绑定与发布提示 |
| C | Refresh 合并、全局 ban key、保护地址 | — | 反代拓扑 ACL/CC、TEMP_BLOCK 持久 | — |
| D | worker 超时回收 | 维护模式 503/拒绝写 | — | 版本页、统计页文案 |

回归：现有 stage4/5/6 集成与 E2E 冒烟不得回退；新增用例进 `docs/STAGE*_TEST_REPORT` 或本文件验收勾选。

---

## 7. 明确不做或延后（本方案边界）

| 项 | 说明 |
|----|------|
| 多节点 CC 全局强一致 | 任务书已声明暂不开发；Valkey 共享计数保持，修复本地/刷新语义即可 |
| `policy_versions` 完整产品 | 已在遗留项；本方案用配置发布闭环，不新开策略版本中心 |
| AI 评估集管理页 | P2；API 可保留内部用 |
| antd 分包、72h 稳定性 | 既有遗留，不阻塞本方案 |
| 复制竞品交互 | 禁止；仅修复自研链路 |

---

## 8. 风险与回滚

| 风险 | 缓解 |
|------|------|
| A1 脱敏后旧快照回滚缺密码 | 回滚路径强制运行时注入；集成测覆盖 |
| C1 改保护地址后健康检查被 CC | 健康检查走独立路径或不经 Guard；或保护「客户端 IP」而非连接源 |
| B2 动态自定义规则语法错误导致 WAF 加载失败 | 发布前 Validate SecLang；失败保护/自动回滚沿用现网发布器 |
| A3 热更 engine 丢计数 | 文档说明短暂窗口；或仅允许密码/地址变化时重建并告警 |

发布失败保护、配置校验拒绝非法配置等既有机制 **不得删除** 以「先过测试」。

---

## 9. 交付物清单

每波结束产出：

1. 代码 + 单测/集成测通过记录  
2. `CHANGELOG.md` 简述  
3. `docs/DEVELOPMENT_STATUS.md` 勾选/降级同步  
4. 本文件对应验收项打勾  
5. （Wave D）遗留问题列表更新

---

## 10. 推荐立即开工顺序（执行清单）

若只开一个迭代，按下列顺序改（合并了「上边安全方案」与「功能审计方案」的最高 ROI）：

1. **M-01** 版本/API 脱敏 + 发布时注入密钥  
2. **M-06** engine `Once`/initErr  
3. **M-02** 策略绑定 API+UI  
4. **M-03** 自定义规则进发布  
5. **M-04** 保护地址仅 clientIP  
6. **M-05** TEMP_BLOCK Refresh 合并  
7. **M-10 / M-11 / M-12** 例外发布失败保护、429 头、生产 fail-closed  
8. **M-08** rule_overrides 实现或诚实降级  
9. **M-07 / M-09 / M-14** engine 调和、例外到期、全局 ban  
10. **Wave D** 维护模式、报告回收、AC 版本 UI、文档

---

## 11. 附录：原审查编号对照

| 合并 ID | 安全审查 | 功能审计 |
|---------|----------|----------|
| M-01 | Issue 1 | — |
| M-02 | — | F2 |
| M-03 | — | F1 |
| M-04 | — | F4 |
| M-05 | Issue 8 相关 | F5 |
| M-06 | Issue 2 | F6 |
| M-07 | Issue 3 | F17 |
| M-08 | — | F3 |
| M-09 | — | F7 |
| M-10 | Issue 9 | F8 |
| M-11 | Issue 4 | — |
| M-12 | Issue 5 | — |
| M-13 | Issue 6 | — |
| M-14 | — | F13 |
| M-15 | — | F12 |
| M-16 | — | F11 |
| M-17 | — | F9 |
| M-18 | — | F10 |
| M-19 | Issue 10 | — |
| M-20 | — | F14 |
| M-21 | — | F15 |
| M-22 | — | F16 |
| M-23 | Issue 7 | F10 AI 段 |
| M-24 | — | F18 |
| M-25 | — | 文档表 |
| M-26 | Issue 11–12 | — |

原始审查落盘（会话产物，可能随 tmp 清理）：

- 安全：`grok-review-ca643c90.md`  
- 功能：`grok-review-functional-ca643c90.md`  

---

## 12. 版权

Copyright © 聚信得仁  
方案用途：指导阶段4–7 合并修复与阶段7 正式交付前的质量闸门。  
All Rights Reserved.
