# 阶段8 测试报告：统一 Web 与 API 动态防护（WDSP）

**报告日期**：2026-07-23
**状态**：交付收口（统一引擎已挂接真实请求链，全链路实测通过）
**环境**：macOS arm64 / Docker Desktop；compose = `docker-compose.stage5.yml` + `docker-compose.wdsp.yml`（`PRODUCT_EDITION=wdsp`、`API_DYNAMIC_PROTECTION_ENABLED=true`）

## 1. 范围

- 统一动态安全引擎（一次解析 → 分类 → 归一 → 检测 → 统一决策）挂接 `jiuzhang_guard` 请求链
- 多协议解析（JSON/form/XML/multipart/GraphQL）与 8 个运行时检测器
- 统一事件流（网关 JSONL → 采集器 → `api_runtime_events`）与端点自动发现
- 冻结模型 / 已知端点基线经发布通道下发网关
- `/api/v1/api-security/*` 43 条接口、27 权限点、27 张表、12 个前端页面、10 个 `api_*` AI 工具
- 纯 WAF 形态回归（关闭零影响）

## 2. 自动化结果摘要

| 套件 | 命令 | 结果 |
|------|------|------|
| 引擎单测 | `cd gateway/dynamic_security && go test ./...` | 通过（9 包；parser 13 用例、detectors 30+ 用例、pipeline 集成用例，含 `-race`） |
| guard 单测 | `cd gateway/modules/jiuzhang_guard && go test ./...` | 通过（8 包；含 6 个 API 管线挂接用例：关闭透传/OBSERVE 记录/PROTECT 403/请求体保全/生命周期） |
| 后端包单测 | `go test ./internal/{apiassets,apimodels,apisecurity,apiruntime,guardconfig,product,aitools}` | 通过（含采集器 3 用例、模型 diff、策略矩阵、AI 工具 12 用例） |
| 前端单测 | `cd web && npx vitest run` | 通过（16 文件 105+ 用例；12 个阶段8 页面权限显隐与列表渲染） |
| 接口集成 | `make stage8-test-api`（`TestStage8*`，真实 postgres+valkey） | **9/9 通过**（端点组合并/拆分、学习启停、模型全生命周期、参数、分类、规范导入、风险运行时、策略、越权+审计） |
| 全链路 e2e | `make stage8-test-gateway` | **15/15 通过**（edition→发布→流量→发现→冻结→下发→OBSERVE 记录→PROTECT 阻断→策略发布） |
| 流量回放 | `make stage8-test-replay` | **10/10 通过**（主事件与访问日志共享 Request ID、幂等重放、Web 路径隔离、偏离重放） |
| 安全 | `make stage8-test-security` | **11/11 通过**（XXE 拒绝、>1MB 截断、PROTECT 敏感 Query 403、401/403/CSRF、注入无泄露） |
| 性能 | `make stage8-test-performance` | **5/5 通过**（管线 p95 开销比 0.83、采集 210 事件/15s、1MB 解析 p95 62ms） |
| 前端 E2E | `make stage8-test-e2e` | Playwright `stage8-api-security.spec.ts` 7 场景（结果见 §3.8） |
| 纯 WAF 回归 | `PRODUCT_EDITION=waf` + `test/waf/scripts/stage5-gateway-tests.sh` | **40/40 通过**；`/api/v1/api-security/*` 整组 404，`edition` 探测为 `waf/false` |

## 3. 关键实测证据

### 3.1 引擎挂接（任务书第二章核心原则）

- 纯 WAF 形态：管理面探测 `{"edition":"waf","api_dynamic_protection":false}`，`/api/v1/api-security/*` 404；stage5 网关回归 40/40，行为与挂接前一致。
- WDSP 形态：发布配置后 guard JSON 含 `api_dynamic_protection/api_protection_mode/api_events_log/api_formal_schemas/api_known_endpoints`；请求流经 `serveNext` 进入统一管线。

### 3.2 统一事件与发现

- 发送 `POST /v1/orders/123 {"id":1,...}`：自动发现 `POST /v1/orders/{id}`（hit_count 累计），`api_runtime_events` 含该端点主事件，明细含 `authentication`/`resource` 检测器记录。
- 回放同一 `request_id` 的事件行两次，主事件仍 1 条（request_id 幂等）；同一 Request ID 同时出现在 Web 访问日志（Web/API 统一 ID 成立）。

### 3.3 模型下发与决策

- 候选 → 确认冻结（FORMAL v1；第二个候选 v2，旧 FORMAL→SUPERSEDED；版本号严格 +1）→ 发布下发 → OBSERVE 下 `{"id":"abc"}` 产生 `schema.type_mismatch` 明细不阻断 → 策略接口切 PROTECT + 发布 → 同类请求被 **403**，合规请求放行。

### 3.4 解析安全

- XML 带 `<!DOCTYPE … ENTITY … file:///etc/passwd">`：引擎拒绝 DTD，无 5xx，事件链路正常。
- 1.1MB JSON body：截断采样而非 5xx；~1MB 解析 p95 62ms。
- 敏感 Query（`?id_card=110`）：PROTECT 下 403，事件含 `sensitive.in_query` 明细。

### 3.5 权限与审计

- AUDIT_ADMIN 对 21 个写操作全部 403，读接口 200；SECURITY_ADMIN 的 confirm/merge/policy PUT 落 `api_*` 模块审计。
- AI 工具：10 个 `api_*` 全部 READ_ONLY 注册并同步 `ai_tools` 表（ENABLED），AI 无确认/发布/修改路径。

### 3.6 性能（55 章）

- 管线开销：API 臂 p95 4.3ms vs Web 臂 5.2ms（增幅 < 50% 约束满足）。
- 采集吞吐：200 事件突发后 15s 窗口内入库 210 条（≥180）。
- 大 body：1MB JSON 解析 p95 62.5ms（< 2s 约束满足）。

### 3.7 发现并已修复的问题（本阶段实测暴露）

| 问题 | 根因 | 处置 |
|------|------|------|
| api 容器启动崩溃 | 000018 迁移索引自重命名 | 删除该行，迁移重放通过 |
| 主事件不入库 | `SavePrimary` 参数类型推断失败（SQLSTATE 42P08） | 改 `NULLIF($2::varchar,'')` 幂等插入 |
| 发布失败 SAVE_VERSION_FAILED | 秒级时间戳版本号快速连发撞唯一约束 | 毫秒时间戳 + 序号重试 |
| 首个 FORMAL version_number=2 | Confirm 把 CANDIDATE 行计入 MAX+1 | 版本号改为创建时分配 |
| 拓扑页空白 | 后端返回 `applications`、前端读 `groups` | 前端对齐 |
| stage8 脚本 bash 变量名错误 | macOS UTF-8 locale 把全角字符并入变量名 | 统一 `${VAR}` 大括号 |
| 安全测试大 body 502 | testorigin 对未知路径立即 404 关连接（源站行为，非引擎） | 用例改打读取 body 的 `/echo` |
| 性能采样"污染" | 脚本把源站 404 当异常 | 采样口径改为 200/404 干净、429/5xx 污染 |

### 3.8 前端 E2E（Playwright）

`cd web && npx playwright test e2e/stage8-api-security.spec.ts`：**6 通过 / 1 跳过**（用例7 WAF 形态按设计跳过，已由 §2 纯 WAF 回归覆盖）：

1. 菜单可见性：「接口防护」分组 12 项全部可见，三个核心页面可打开；
2. 端点资产：网关流量自动发现 → 中文状态 Tag → 行内确认（二次确认弹窗）→ 已确认；
3. 模型版本：选择端点 → Drawer 创建候选 → 确认冻结 → 正式；
4. 策略页：改「防护」保存 → 模式 Tag 与来源（数据库）变更 → 刷新保持 → 恢复观察；
5. 学习中心：启动学习 → 学习中 → 停止 → 已暂停；
6. 权限：AUDIT_ADMIN 菜单全可见但确认/忽略/保存/发布按钮均不渲染。

过程中发现并修复一个 dev 环境缺陷：vite dev 代理前缀 `/api` 会吞掉阶段8 页面路由（`/api-endpoints` 等整页刷新被代理到后端 404），已收敛为 `/api/v1`（`web/vite.config.ts`）。

## 4. 诚实遗留（任务书超集）

1. 学习自动化：样本达阈值自动生成候选模型未实现（候选手工/接口创建）；参数统计画像（字符串/数值/条件关系）仅有表结构；`api_learning_samples` 当前无生产写入方。
2. 响应侧解析与 `MASK_RESPONSE` 未实现（响应字段存在但无写入点）。
3. 行为基线/限速为单节点进程内滑窗（多节点需 Valkey 化）；图谱调用边仅 caller→target 形态；BOLA/BFLA 为辅助信号而非全量规则库；Zombie API 判定未实现。
4. Coraza 命中未同步进 RequestContext（经 request_id 在管理面关联；不 fork coraza-caddy）。
5. 客户端自带 `X-Request-Id` 会被网关强制覆盖（`gatewayconfig/generator.go` 以 `{http.request.uuid}` 统一下发），统一 ID 语义为"网关生成的同一 ID 贯穿 Web/API 事件与访问日志"。
6. 采集器副作用（端点发现命中计数）为 at-least-once 语义：断点未提交的重放窗口内 hit_count 可能偏高（开发环境实测曾放大；不影响事件幂等）。

## 5. 自动化命令（63 章）

`make stage8-build / stage8-migrate / stage8-seed / stage8-up / stage8-status / stage8-down`、`make stage8-test-unit / -api / -gateway / -discovery / -learning / -versioning / -schema / -classification / -identity / -authorization / -sensitive-data / -behavior / -graph / -replay / -e2e / -performance / -security / -all`，全部可重复执行、失败返回非零。

---

Copyright © 聚信得仁
All Rights Reserved.
