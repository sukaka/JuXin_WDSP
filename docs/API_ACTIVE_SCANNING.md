# API 主动扫描设计（规划稿）

> **当前状态：未实现（NOT_IMPLEMENTED）**。
> 本文档是 API 安全能力补全（对应《WDSP_API_SECURITY_COMPLETION_PLAN》§232，下称"补全任务书"）要求的
> **设计规划稿**，描述主动扫描能力的目标架构与落地方案。截至 2026-08-16，仓库内主动扫描
> **全库零实现**：无表、无路由、无引擎适配、无隔离标记（现状盘点见
> `docs/API_SECURITY_CURRENT_STATE.md` §3 P1-07、§5.3）。文中所有"拟新增"的表、接口、
> 配置与模块均不存在于当前代码，不得以本文档作为任何功能已完成的依据。
> 凡引用既有代码处均给出真实路径，引用规划内容处均标注（规划）。

## 一、目的与范围

### 1.1 定位

主动扫描（Active Scanning）是对**已纳管 API 资产**发起的、经授权的、有限度的主动验证，
回答被动观测回答不了的问题：这个接口未认证到底能不能访问？已下线的接口是不是真的关了？
整改完的弱点现在还能不能复现？

定位纪律（与阶段8 任务书 §4.2"本阶段暂不开发"清单对齐）：

- **不是 DAST 平台**：不做全量攻击载荷库、不做模糊测试平台、不做自动渗透
  （阶段8 任务书 §4.2 明确排除 `DAST全量主动扫描` / `API模糊测试平台` / `自动渗透攻击`）；
- **是有限主动验证**：探针集收敛于本系统自身检测语义的验证需求（认证、生命周期、
  敏感暴露、Schema 符合性、水平越权对比），靶标只来自已发现/已确认资产；
- **引擎可替换**：扫描执行通过 Engine Adapter 抽象，内置轻量探针引擎先行，
  外部引擎（如企业既有扫描器）以结果导入方式接入，不内嵌第三方渗透框架。

### 1.2 与被动观测的关系

```text
被动观测（已实现）                    主动扫描（本规划）
─────────────                      ─────────────
真实流量 → 统一引擎检测              授权探针 → 目标API
  → api_runtime_events               → api_scan_jobs / api_scan_findings
  → api_runtime_findings（物化）       → 复核/补证 api_runtime_findings
  → apiweakness 派生弱点               → 弱点复测回写（RETEST_PASS/FAIL）
"我们看到了什么"                      "我们验证了什么"
```

主动扫描不产生第二套事件中心、第二套检测语义：扫描产生的安全结论复用
`api_runtime_findings` / `api_weaknesses` 现有载体（对应补全任务书禁止事项 #1
"不得建设第二套 API 事件中心"），仅新增目标/授权/任务/发现/凭据五类自有表（§四~§九）。

## 二、现状与可复用基础

以下能力**已实现**，是本设计的直接依赖（路径均已核实）：

| 能力 | 位置 | 复用方式 |
|------|------|----------|
| API资产与生命周期 | `server/internal/apiassets/`（`api_endpoints`，DISCOVERED/CONFIRMED/IGNORED/DEPRECATED） | 扫描靶标来源 |
| 应用/域名归属 | 阶段3 `applications` / `application_domains`（迁移 000004） | 扫描范围授权边界 |
| 统一引擎与决策 | `gateway/dynamic_security/pipeline/pipeline.go`、`decision/engine.go` | 扫描流量识别信号接入点 |
| 事件上行 | guard `apievents` JSONL → `server/internal/apiruntime/collector.go` → `api_runtime_events` | 扫描流量落事件并打标 |
| Findings 物化 | `server/internal/apiruntime/findings.go`（dedup_fingerprint 幂等、脱敏纪律） | 扫描复核结论入库 |
| 弱点中心与复测接口 | `server/internal/apiweakness/`（NEW→…→FIXED→复测；`POST /api/v1/api-security/weaknesses/{id}/retest`，权限 `api_weakness.handle`，见 `routes.go:29`） | 复测结果回写 |
| 操作审计哈希链 | `server/internal/audits/audits.go`（`Service.Record`，禁改删 RULE） | 扫描授权/启停/结果操作留痕 |
| 周期任务模式 | `server/internal/learningjobs/janitor.go`（SweepOnce 可测 + ticker Run） | 扫描调度器结构模板 |
| 对称加密服务 | `server/internal/encryption/encryption.go`（AES-GCM，密钥十六进制配置） | 扫描凭据落库加密 |
| 权限与三权 | `server/internal/authz`、`middleware.RequirePermission`；迁移 000019/000041 权限种子模式 | 扫描权限点登记 |
| 产品形态开关 | `server/internal/product/edition.go`（`API_DYNAMIC_PROTECTION_ENABLED`） | 扫描能力整体启停 |
| 系统设置 | `server/internal/settings/`（group/key 读取，janitor 已示范） | 扫描全局开关与限额配置 |

**现状缺口（本规划要补的）**：补全任务书 §169 建议的 `api_scan_targets` /
`api_scan_jobs` / `api_scan_findings` 三表尚不存在（现状盘点 §5.3）；学习样本过滤词表
虽含"扫描器流量"（阶段8 任务书 §25），但样本过滤当前无 Scanner 识别
（现状盘点 P0-01 缺口 #4）；AI 工具 `api_scan.get` 因后端缺失不存在（现状盘点 §6.6）。

## 三、总体架构（规划）

```text
管理面（server，全部拟新增包 server/internal/apiscan/）
  目标管理 Target ── 授权 Authorization ── 任务调度 Scheduler ── 引擎适配 Engine Adapter
       │                                        │
       │                              ┌─────────┴──────────┐
       │                              ▼                    ▼
       │                        内置探针引擎          外部引擎结果导入
       │                        （本仓库实现）        （适配器解析导入）
       │                              │
       ▼                              ▼
  api_scan_targets / api_scan_authorizations / api_scan_jobs / api_scan_findings（规划表）
                                     │
                                     │ 发现复核/复测回写
                                     ▼
  api_runtime_findings（已实现载体）  api_weaknesses retest（已实现接口）

网关侧（gateway，拟新增 scanner 识别信号）
  统一引擎挂点 serveNext（apiprotect.go）内：
    扫描标记识别（签名头校验）→ RequestContext 打标
      → 学习样本排除 + 事件 details_json 标记 + 决策按扫描策略处理
```

模块边界纪律（对应阶段8 任务书 §49）：扫描逻辑收在独立包 `apiscan`，不得写进
WAF 规则页、Coraza 适配器或 `jiuzhang_guard` 传统检查路径；网关侧只增加"识别与打标"，
不在网关内实现扫描器本体。

## 四、扫描目标（Target）

### 4.1 目标来源与范围模型（规划）

扫描目标**只允许来自已纳管资产**，不支持自由填写任意地址发起扫描：

- API级：`api_endpoints` 中 `asset_status=CONFIRMED` 的API（DISCOVERED API
  须先人工确认，避免对未知归属地址主动发包）；
- 应用级：阶段3 `applications` / `application_domains` 确定域名与源站边界，
  目标地址解析必须落在应用登记域名内；
- 显式排除：`IGNORED` API、标记为生产禁扫的API（见 §十一 安全约束）。

拟新增表 `api_scan_targets`（规划）：

| 列 | 说明 |
|----|------|
| `id` | 主键 |
| `name` / `description` | 目标名称与说明 |
| `scope_type` | `ENDPOINT_SET` / `APPLICATION` |
| `application_id` | 应用边界（APPLICATION 时必填，FK） |
| `endpoint_filter` | JSONB：API子集过滤（方法/路径前缀/标签），运行时解析为API清单快照 |
| `environment` | `TEST` / `STAGING` / `PROD`；**默认只允许 TEST/STAGING**，PROD 需显式授权升级 |
| `status` | `ENABLED` / `DISABLED` |
| `created_by` / `created_at` / `updated_at` | 常规审计列 |

### 4.2 目标快照（规划）

每次扫描任务启动时将目标解析为**API清单快照**存 `api_scan_jobs.endpoint_snapshot`
（JSONB，含 endpoint_id / method / normalized_path / 解析时刻资产状态），保证：

- 扫描范围可追溯（审计能回答"这次扫了哪些接口"）；
- 扫描期间资产变更不影响进行中的任务；
- 复测任务快照与弱点记录的 endpoint_id 强绑定，防止"测错对象"。

## 五、授权模型（Authorization）

主动扫描是向业务系统主动发包的行为，**授权先于一切执行**。

### 5.1 授权单（规划）

拟新增表 `api_scan_authorizations`：

| 列 | 说明 |
|----|------|
| `id` | 主键 |
| `target_id` | 授权对象（FK `api_scan_targets`） |
| `authorized_by` | 授权人（FK users，须持 `api_scan.authorize` 权限点） |
| `environment_ack` | 环境确认：`PROD` 目标必须显式勾选"已知晓生产风险" |
| `window_start` / `window_end` | 允许扫描的时间窗（过期授权自动失效，执行前强校验） |
| `max_rps` / `max_requests` | 本次授权的速率与总量上限 |
| `allowed_probe_sets` | 授权探针集白名单（见 §6.3） |
| `status` | `ACTIVE` / `EXPIRED` / `REVOKED`（撤销立即生效，调度器每轮重查） |

纪律：

- **双人分离**：建目标（`api_scan.manage`）与授权（`api_scan.authorize`）是两个权限点，
  同人同目标不得自审自批（三权口径，与阶段2 三权模型一致）；
- **授权即审计**：创建/撤销/过期均写操作审计哈希链（`audits.Service.Record`）；
- **运行期持续有效**：任务执行中每批次发包前复查授权状态与时间窗，
  撤销即刻停发（对应 §十一 紧急停止）。

### 5.2 权限点（规划，种子迁移由实施分片统一登记）

| 权限点 | 用途 |
|--------|------|
| `api_scan.read` | 目标/任务/发现查询 |
| `api_scan.manage` | 目标与任务创建、启停 |
| `api_scan.authorize` | 授权单签发与撤销 |
| `api_scan.credential` | 扫描凭据维护（见 §七） |

## 六、扫描引擎适配（Engine Adapter）

### 6.1 适配层接口（规划）

```text
// 拟新增 server/internal/apiscan/engine.go（接口示意，非现有代码）
type Engine interface {
    // ProbeSets 返回该引擎支持的探针集清单
    ProbeSets() []ProbeSet
    // Run 执行一个任务分片；逐条回调 ProbeResult，受 ctx 取消与限额约束
    Run(ctx context.Context, job JobSlice, emit func(ProbeResult) error) error
}
```

- **内置探针引擎（v1 唯一实现）**：基于 `net/http` 的轻量发包器，实现 §6.3 探针集；
  不依赖任何第三方扫描框架（符合"不引入新第三方依赖"纪律）；
- **外部引擎适配器（后续分期）**：以**结果导入**方式接入企业既有扫描器
  （上传 JSON 报告 → 适配器解析为 `api_scan_findings`），不做在线联动、不内嵌引擎二进制；
- 引擎输出统一收敛为 `ProbeResult`（目标API + 探针集 + 请求摘要 + 响应摘要 + 结论），
  结论判定规则在管理面侧，引擎不得直接写 findings/weakness（与统一引擎
  "检测器不定案"纪律同构）。

### 6.2 任务模型（规划）

拟新增表 `api_scan_jobs`：

| 列 | 说明 |
|----|------|
| `id` / `target_id` / `authorization_id` | 任务、目标、所凭授权 |
| `job_type` | `FULL`（目标全量探针集）/ `RETEST`（弱点定向复测，关联 `weakness_id`） |
| `endpoint_snapshot` | API清单快照（见 §4.2） |
| `status` | `PENDING` → `RUNNING` → `COMPLETED` / `FAILED` / `CANCELLED` / `STOPPED`（紧急停止） |
| `probe_stats` | JSONB：各探针集 完成/命中/错误 计数 |
| `rate_limit_rps` / `max_requests` | 从授权单继承的执行限额（执行侧硬约束） |
| `started_at` / `finished_at` / `last_error` | 执行轨迹（不静默吞错：失败原因落列） |

调度器采用与 `learningjobs` janitor 相同的结构：`SweepOnce`（取一个到期任务推进一个
分片，可独立单测）+ `Run`（ticker 周期调度，挂 app.go 装配），并发任务数、单任务
分片大小走 `settings` 读取，默认单并发。

### 6.3 内置探针集（规划）

探针集收敛于本系统检测语义的验证需求，每个探针集独立授权、独立计数：

| 探针集 | 验证问题 | 方法约束 |
|--------|----------|----------|
| `AUTH_REQUIRED` | 未认证访问是否被拒 | 不带凭据重放 GET/POST，判定 401/403 vs 2xx |
| `DEPRECATED_ALIVE` | DEPRECATED API是否仍在提供服务 | 原方法重放，判定是否仍可正常响应 |
| `SENSITIVE_EXPOSURE` | 响应是否暴露敏感字段 | 只读重放，响应体按 `apidata` 敏感类型词表判定（不落原文，只落字段名） |
| `SCHEMA_CONFORM` | 请求构造是否符合 FORMAL Schema | 按 `api_runtime_policies` 编译产物构造合法/非法样本各一，对比决策差异 |
| `BOLA_COMPARE` | 水平越权是否可利用 | **双低权身份**（凭据 A/B，见 §七）访问各自与他人对象标识，对比响应差异；只做只读方法 |
| `METHOD_ENUM` | 是否存在未登记方法 | 对API试 OPTIONS/TRACE/PUT/DELETE 等，记录允许方法集 |

明确不包含：注入类攻击载荷、暴力破解、 fuzzing、大流量压测、写方法破坏性试探
（写方法仅 `SCHEMA_CONFORM` 在 TEST/STAGING 环境经授权使用，且使用专用构造数据）。

## 七、扫描凭据（Credentials）

认证态扫描（`BOLA_COMPARE`、认证基线复测）需要凭据，凭据管理纪律与全仓库
"不落明文"口径一致：

- 拟新增表 `api_scan_credentials`：存加密后的凭据（`encryption.Service` AES-GCM
  加密落库，与既有证书/密钥存储同一机制）；**密钥不出现在任务、快照、审计正文与
  事件证据中**——任务只持 `credential_id` 引用，发包时即时解密使用，用后即弃；
- 凭据类型：`BEARER_TOKEN` / `BASIC` / `API_KEY_HEADER` / `COOKIE`；
  类型词表与统一引擎认证识别口径对齐（`detectors/authentication.go`）；
- **双身份约束**：`BOLA_COMPARE` 强制要求同目标配置两个低权凭据（A/B），
  禁止配置高权/管理员凭据；凭据创建时人工声明"该凭据为测试专用低权账号"；
- 凭据的创建/更新/删除走 `api_scan.credential` 权限点 + 操作审计；列表与详情接口
  永不回显密文或明文（仅回显名称/类型/创建时间/最近使用时间）；
- 凭据轮换不阻断历史任务追溯：任务快照只存凭据 ID 与指纹（HMAC 截断，与身份指纹
  `identity_salt` 机制同法），不存凭据内容。

## 八、流量隔离与学习保护（Isolation）

扫描流量进入与真实流量**同一条网关处理链**（不旁路统一引擎，不建第二条链路），
但必须可识别、可隔离，防止污染学习与运营数据。这是对补全任务书禁止事项 #12
"Scanner 污染学习"的正面补齐（现状：未违反也无防护，见现状盘点 §7）。

### 8.1 扫描流量识别（规划）

- 扫描器发包携带专用签名头（规划名 `X-JiuZhang-Scan`）：值为
  `{job_id}.{hmac}`，HMAC 密钥由管理面生成、作为新的下发键经发布通道
  （`guardconfig` → Caddy JSON）随配置下发网关——发布通道扩键既有先例
  （`api_mask_rules` / `api_policy_version` 等键），密钥本身不进事件与审计正文；
- 网关在统一引擎挂点内、解析后立刻校验签名头（拟新增于
  `gateway/dynamic_security` 的轻量识别器，非检测器，不参与决策打分）：
  - 校验通过 → `RequestContext` 打 `Scanner=true` + `ScanJobID`；
  - 签名头存在但校验失败 → 抹除标记按普通流量处理，并产一条
    `scanner.spoofed_header` OBSERVE 级明细（防伪造标记绕过学习保护）。

### 8.2 隔离语义（规划）

| 面 | 隔离行为 |
|----|----------|
| 学习样本 | `apiruntime/samples.go` 过滤新增一条：`Scanner=true` 事件一律不进学习样本（落实阶段8 任务书 §25"扫描器流量"排除项，同时修复现状盘点 P0-01 缺口 #4 的 Scanner 识别空白） |
| 事件流 | 扫描流量仍产 `api_runtime_events`（可观测、可审计），`details_json` 带 `scan_job_id`；Findings 物化规则对扫描流量事件**只物化到 `api_scan_findings`**，不写入 `api_runtime_findings`，避免扫描噪声淹没真实风险运营 |
| 决策 | 扫描标记流量的决策动作由扫描策略决定：默认 `OBSERVE`（探测需要看到真实响应，不应被 PROTECT 阻断）；阻断仍发生时如实记录（本身即为有效信号） |
| 访问控制/CC | 扫描器出口 IP 列表由目标配置显式声明，经既有白名单机制放行频率限制；**不**自动信任——未声明来源的签名头流量不享受放行 |
| 封禁 | `Scanner=true` 流量不进自动临时封禁计数（防止扫描触发自锁），伪造标记流量除外 |

### 8.3 与资产发现的边界

扫描探针命中的路径仍走既有资产发现链路；`Scanner=true` 流量发现的"新API"
直接落 `DISCOVERED` 且 `details_json` 标记扫描来源，不自动确认——扫描可以暴露
Shadow 面，但资产确认仍是人工动作。

## 九、扫描发现（Findings）

### 9.1 拟新增表 `api_scan_findings`

| 列 | 说明 |
|----|------|
| `id` / `job_id` / `target_id` | 发现归属 |
| `endpoint_id` / `endpoint_key` | 命中API（快照解析后锚定） |
| `probe_set` | 来源探针集（§6.3 词表） |
| `conclusion` | `CONFIRMED_VULN` / `SUSPICIOUS` / `NEGATIVE` / `ERROR` |
| `severity` | INFO/LOW/MEDIUM/HIGH/CRITICAL（与 findings 词表一致） |
| `evidence_json` | **脱敏证据**：请求方法/路径/状态码/命中字段名/判定规则；响应体不落原文，敏感判定只落字段名与类型（与 `apiruntime/findings.go` 脱敏纪律同一标准） |
| `first_seen_at` / `last_seen_at` / `occurrence_count` | 幂等去重（`UNIQUE(job_type, endpoint_id, probe_set, conclusion)` 语义的去重指纹） |

### 9.2 与既有载体的衔接（规划）

```text
api_scan_findings（扫描原始结论）
   ├─ conclusion=CONFIRMED_VULN / SUSPICIOUS
   │    → 复核接口：人工确认后物化进 api_runtime_findings
   │      （finding_type 按探针集映射：AUTH_REQUIRED→UNAUTHENTICATED_ACCESS、
   │        BOLA_COMPARE→BOLA、DEPRECATED_ALIVE→ZOMBIE/DEPRECATED 等；
   │        复用 recordFindings 的 dedup_fingerprint 幂等机制）
   │    → 或一键转为 api_weaknesses（NEW，source=SCAN），进入弱点生命周期
   └─ RETEST 任务的 NEGATIVE / CONFIRMED_VULN → 回写弱点复测（见 §十）
```

纪律：扫描发现**不自动改写** `api_runtime_findings` 与 `api_weaknesses` 状态——
自动化的终点是"产生待复核结论"，确认与状态流转走既有人工接口
（与"AI/自动不得直接定案"的全库纪律一致；唯一的自动流转是 §十 的复测回写，
且复测回写本身走 `apiweakness` 已实现的 RETEST 状态机）。

## 十、复测联动（Retest）

复测是主动扫描的第一优先级场景（弱点中心已实现完整生命周期，缺的就是"怎么验证
修好了"的执行手段）：

```text
api_weaknesses 状态 FIXED（已实现）
  → 人工发起复测（拟新增 POST /api/v1/api-security/scans/retest {weakness_id}）
  → apiscan 生成 job_type=RETEST 任务：
      探针集按 weakness_code 映射（UNAUTHENTICATED_SENSITIVE_API→AUTH_REQUIRED、
      DEPRECATED_STILL_CALLED→DEPRECATED_ALIVE、SENSITIVE_IN_QUERY→SENSITIVE_EXPOSURE …）
      目标锁定该弱点的 endpoint_id，凭据复用目标配置
  → 任务完成，按结论自动回写既有复测接口语义：
      NEGATIVE（未复现）      → RETEST_PASS → ARCHIVED
      CONFIRMED_VULN（复现）  → RETEST_FAIL → REPRODUCED（重新进入指派整改）
  → 复测动作落 api_weakness_actions（该表只增不改，已实现）+ 操作审计
```

边界：

- 复测回写只接受 `FIXED` 状态的弱点，其余状态拒绝（与 `apiweakness` 状态机一致）；
- 回写失败（如弱点期间被人工归档）不静默吞错：任务置 FAILED + `last_error`，
  不伪造复测结论；
- 人工复测入口（既有 `POST /weaknesses/{id}/retest`）与扫描复测回写并存，
  `api_weakness_actions` 以 `actor` 区分来源（扫描回写 actor 为任务标识）。

## 十一、安全约束（Safety）

主动扫描自身必须是安全的，约束按"默认最严、显式放宽"设计：

1. **整体启停**：扫描能力挂产品开关与全局 settings 开关（`api_scan.enabled`，
   默认关）；关闭时调度器空转、接口可用但拒绝创建任务；
2. **环境默认**：新建目标默认 `TEST`；`PROD` 目标需授权单显式环境确认 +
   独立审计要点；`BOLA_COMPARE`、写方法探针在 PROD 直接拒绝；
3. **速率与总量硬限**：执行侧强制 `max_rps` / `max_requests`（取自授权单，
   令牌桶实现于扫描执行器内，不依赖网关 CC）；超限即停并如实落任务状态；
4. **紧急停止**：`POST /scans/jobs/{id}/stop`（`api_scan.manage`）立即取消
   执行上下文；授权撤销（§5.1）对所有在跑任务同效；停止动作写审计；
5. **并发上限**：全局并发任务数（默认 1）与单目标互斥（同目标同时仅一个任务），
   经 settings 可调，调度器每轮强校验；
6. **禁破坏性探针**：探针集白名单制（§6.3），引擎不得执行白名单外探针；
   写方法仅 `SCHEMA_CONFORM` 在 TEST/STAGING 经授权可用；
7. **凭据最小权力**：仅低权测试凭据，加密落库、用时解密、永不回显（§七）；
8. **审计全覆盖**：目标/授权/凭据/任务的创建、变更、启停、复测回写全部进
   操作审计哈希链；扫描发现导出经既有审计导出路径；
9. **防滥用**：扫描接口全部登录 + 权限点 + 参数校验（词表白名单），与全库
   API 同一纪律；不对未确认资产、未登记域名发包；
10. **降级纪律**：扫描依赖（数据库/发布通道）故障只影响扫描任务本身，
    绝不影响防护链路（与 AI 模块"与防护内核解耦"同则）。

## 十二、接口与前端（规划）

接口（全部拟新增于 `/api/v1/api-security/scans/*`，权限点见 §5.2）：

```text
GET/POST        /targets                目标列表/创建
PUT/DELETE      /targets/{id}           目标维护/停用
POST            /targets/{id}/authorize 签发授权单
POST            /authorizations/{id}/revoke 撤销授权
GET/POST        /jobs                   任务列表/发起（FULL）
POST            /jobs/{id}/stop         紧急停止
GET             /jobs/{id}              任务详情（含快照与计数）
GET             /findings               扫描发现列表（过滤/分页）
POST            /findings/{id}/promote  复核物化为 runtime finding / 转弱点
POST            /retest                 对 FIXED 弱点发起定向复测
GET/POST/PUT    /credentials            凭据维护（永不回显密文）
```

前端（规划）：`web/src/pages/api-scan/` 目标与授权页、任务页（进度/停止）、
扫描发现页（复核/转弱点）、凭据管理页；弱点详情页增加"发起复测"入口。
OpenAPI 收录与 RBAC 种子迁移随实施分片一并交付。

## 十三、实施分期建议（规划）

| 期 | 内容 | 依赖 |
|----|------|------|
| S1 | 扫描各表迁移 + 目标/授权/凭据管理 + 权限种子 + 审计 | 无 |
| S2 | 内置探针引擎 + 调度器（SweepOnce/Run）+ 任务生命周期 + 限额 | S1 |
| S3 | 网关扫描标记识别 + 学习样本排除 + 事件打标 + 决策/封禁隔离 | S2，需发布通道下发扫描 HMAC 密钥 |
| S4 | 扫描发现 + 复核物化 + 转弱点 + RETEST 回写 | S2（S3 非强依赖，标记缺失时按未隔离形态降级运行并记录） |
| S5 | 前端四页 + 弱点详情复测入口 + OpenAPI + E2E | S4 |
| S6 | 外部引擎结果导入适配器（可选） | S4 |

每期验收底线：单元测试覆盖状态机与探针判定；接口测试覆盖权限/参数校验；
S3 需网关侧测试（签名头识别/伪造标记/样本排除）；全程不得为通过测试删除
权限校验、参数校验与审计（AGENTS.md 安全底线）。

## 十四、明确不做（与任务书口径一致）

- 不做 DAST 全量扫描、不做 fuzz 平台、不做自动渗透（阶段8 任务书 §4.2）；
- 不做未授权目标扫描、不做网段级发现扫描；
- 不做高权凭据扫描、不做生产环境写方法探针；
- 扫描结论不自动改写模型/策略/发布（确认与发布永远是人工动作）；
- 不建第二套事件中心与第二套检测语义（复用 `api_runtime_events` /
  `api_runtime_findings` / `api_weaknesses` 载体）；
- 不在网关内实现扫描器本体，不向 `jiuzhang_guard` 传统检查路径塞扫描逻辑。

---

*本文档为规划稿，描述目标设计而非现状；实施完成后应更新
`docs/API_SECURITY_CURRENT_STATE.md` P1-07 状态列。*
