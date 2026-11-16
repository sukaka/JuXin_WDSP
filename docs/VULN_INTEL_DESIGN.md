# CVE 漏洞库与外部利用情报接入设计

版本：V1.1（2026-10-22）　状态：**PHP 场景 MVP 已实现**（迁移 000189）；完整能力（NVD 全量库 / CISA KEV / EPSS / SBOM 匹配 / 签名情报包）仍为后续迭代

> 本文 V1.0 为纯设计评审稿。V1.1 起分两部分：第一部分记录**已实现的 MVP 事实口径**
> （与代码核对一致，如有出入以代码为准）；第二部分保留 V1.0 完整设计原文，作为后续
> 迭代基线（未实现，落地时须按第一部分既有表结构/迁移号演进，不能直接套用）。

## 第一部分：MVP 实现现状（2026-10-22，迁移 000189）

### 1. 范围与边界

MVP 目标：PHP 技术栈场景的漏洞情报**提醒闭环**——NVD 每日同步 PHP 相关漏洞 +
离线 JSON 导入 + 按订阅技术栈聚合提醒（系统告警 + 通知渠道）。代码：
`server/internal/vulnintel/`（vulnintel.go 类型与校验 / store.go 仓储 / nvd.go NVD
同步器 / alert.go 提醒引擎 / settings.go 订阅设置 / handler.go HTTP 接口）。

边界（明确不做）：

- 只提醒，不自动创建 WAF 规则、虚拟补丁或任何阻断动作；
- 在线同步仅访问硬编码 NVD API 2.0 地址，管理面不开放任何出站地址配置（无 SSRF 面）；
- 应用技术栈首版手动维护（`application_technologies`），无站点指纹自动识别；
- 无 KEV / EPSS / SBOM 匹配，无签名离线情报包（导入为明文 JSON，无验签 / 防回滚）；
- 无 license 能力门控（V1.0 §七设想的 `features=threat_intel` 未实施；注意通知渠道
  类别 code 恰好也叫 `threat_intel`，二者无关）；
- CNVD/CNNVD 等无开放 API 的国内源经 JSON 导入通道进入（source=MANUAL），无独立录入界面；
- `raw_json` 原始报文仅落库追溯（≤64KB 截断），任何接口不返回。

### 2. 数据模型（迁移 000189）

四张表（`server/migrations/000189_vuln_intel.up.sql`）：

| 表 | 用途 | 关键点 |
|---|---|---|
| `vuln_advisories` | 漏洞库 | `cve_id` 唯一键；severity 词表 CRITICAL/HIGH/MEDIUM/LOW/NONE；source 词表 NVD/MANUAL；`tech_tags`/`references_json` JSONB（tech_tags 有 GIN 索引）；`raw_json` 追溯证据 |
| `application_technologies` | 应用技术栈映射 | `(application_id, tech_name)` 唯一；tech_name 小写 1-64（`^[a-z0-9][a-z0-9._+-]{0,63}$`）；应用删除级联清理 |
| `vuln_alerted` | 提醒去重 | `(advisory_id, tech_name)` 唯一；`ON CONFLICT DO NOTHING` 幂等 |
| `vuln_intel_sync_state` | 同步状态 | source 主键（NVD）；窗口起止 / upsert 计数 / status（IDLE/SUCCESS/FAILED）/ failure_message |

权限种子：`vuln_intel.read`（SYSTEM_ADMIN + SECURITY_ADMIN）、`vuln_intel.manage`（仅 SYSTEM_ADMIN）。

### 3. 在线 NVD 同步（纯下行）

- 目标地址硬编码 `NVDBaseURL = https://services.nvd.nist.gov/rest/json/cves/2.0`
  （nvd.go）；仅 https GET，固定 User-Agent，client 超时 60s，单页响应上限 32MB；
  不接受自定义 URL（同步器构造无 URL 入参，仅包内测试缝可覆盖）。
- 查询固定 `keywordSearch=php`；首次同步窗口为最近 48 小时，其后从上次窗口终点
  回拨 1 小时（NVD 修订会刷新 lastModified，upsert 按 cve_id 幂等吸收重复）；
  分页 2000 条/页、页间 7 秒限速（无 API key，遵守 NVD 30s/5 次建议并留余量；
  V1.0 设想的 `nvd_api_key` 设置项未实现）、单次同步 50 页保护上限。
- 技术标签确定性提取（`ExtractTechTags`）：英文描述含 php 子串（大小写不敏感）或
  任一 CPE 以 `cpe:2.3:a:php:php` 开头 → tech=php；severity 取全部 CVSS 指标
  （v4.0/v3.1/v3.0/v2）最高分值派生，无指标为 NONE（不虚构级别）。
- 每日循环：app.go 装配 `Syncer.RunDaily`——启动 1 分钟首轮避让启动期，之后每 24
  小时一轮；每轮热读 `vuln_intel.sync_enabled`（默认 false，界面即时生效，关闭时
  空转，默认部署零行为变化）；单轮失败仅记日志，失败原因已由 Run 如实落
  `vuln_intel_sync_state`（FAILED + failure_message，不刷新窗口终点，下轮重试同窗口）；
  并发互斥（ErrSyncRunning）。

### 4. 手动同步与 JSON 导入

- `POST /api/v1/vuln-intel/sync`（vuln_intel.manage）：手动触发一次同步，**不受
  sync_enabled 开关约束**；整体超时 5 分钟；已有同步在进行返回 409；失败返回 502
  且原因落 sync_state + 失败审计。
- `POST /api/v1/vuln-intel/import`（vuln_intel.manage）：JSON 数组导入，body ≤4MB、
  单批 ≤500 条；逐条校验（CVE 形态 / 词表 / 字段上限 / tech_tags 必填），非法条目进
  `invalid_entries` 明细、不阻断合法条目；severity 缺省时按 cvss_score 派生、无分值
  为 NONE；source 固定 MANUAL；与 NVD 同步共用 cve_id 幂等 upsert 与同一提醒引擎。
  （V1.0 的 ed25519 签名 `.jzintel` 包、manifest 校验与 data_date 防回滚均未实现。）

### 5. 订阅与聚合提醒（VULN_INTEL_NEW）

- 订阅设置（system_settings 组 `vuln_intel`，热读热生效）：`watch_techs`（默认
  `["php"]`，≤10 个）、`min_severity`（默认 HIGH；词表 LOW/MEDIUM/HIGH/CRITICAL）、
  `sync_enabled`（默认 false）。
- 提醒引擎（alert.go `Alerter.ProcessNew`）：仅对**本批新建**情报（upsert 返回
  isNew；冲突更新不重复提醒）按 watch_techs 逐技术栈过滤（HasTech + SeverityGte
  门槛），每个技术栈合并为一条 `VULN_INTEL_NEW` 系统告警，component=
  `vuln_intel:<tech>`（同技术栈后续提醒走系统告警引擎合并/冷却）；默认 HIGH，
  批次含 CRITICAL 时升 CRITICAL。
- 文案预算 1000 字符（system_alerts.message 列上限）：最高级别 / CVE 列表（≤10 条，
  超出折"等 N 个"）/ 发布日期范围 / 受影响应用（≤5 个，无映射时如实提示"未标记
  使用 X 的应用"）/ 参考链接（首条 references，缺省 NVD 详情页）。
- 去重：`vuln_alerted (advisory_id, tech_name)` 唯一键——同一漏洞同一技术栈只提醒
  一次；提醒失败时不记 vuln_alerted，下轮同步/导入重新评估，不漏提醒；告警触发函数
  未注入（nil）时同样不记账、直接跳过。
- 通知渠道：`VULN_INTEL_NEW` 归属固定类别 `threat_intel`（"漏洞情报"，notify.go
  固定 10 类词表之一），渠道按类别订阅即可接收；告警类型中文名"漏洞情报提醒"。

### 6. 应用技术栈手动映射

- `GET/PUT /api/v1/vuln-intel/tech-assets`：GET 列出全部未删除应用及标签；PUT 为
  **整组替换**语义（body 即全量目标态，未列出应用清空标签；单事务），≤1000 应用、
  单应用 ≤20 标签；应用不存在/已删除返回 400。该映射是提醒文案"受影响应用"段与
  详情页交叉查询的唯一来源——首版全靠人工维护，不维护则文案如实显示未标记。

### 7. API 与权限

九条路由（app.go 注册，authChain + RequirePermission 强制认证/CSRF/权限；写操作落
操作审计 module=`vuln_intel`，action ∈ sync/import/replace_tech_assets/
update_settings，RiskMedium；同步失败记 ResultFailure）：

| 方法/路径 | 权限 |
|---|---|
| GET `/api/v1/vuln-intel/overview` | vuln_intel.read |
| GET `/api/v1/vuln-intel/advisories` | vuln_intel.read |
| GET `/api/v1/vuln-intel/advisories/{cve_id}` | vuln_intel.read |
| POST `/api/v1/vuln-intel/sync` | vuln_intel.manage |
| POST `/api/v1/vuln-intel/import` | vuln_intel.manage |
| GET `/api/v1/vuln-intel/tech-assets` | vuln_intel.read |
| PUT `/api/v1/vuln-intel/tech-assets` | vuln_intel.manage |
| GET `/api/v1/vuln-intel/settings` | vuln_intel.read |
| PUT `/api/v1/vuln-intel/settings` | vuln_intel.manage |

OpenAPI 片段 `server/openapi/fragments/21-vuln-intel.yaml`。前端 `/vuln-intel`
（菜单「安全运营 → 漏洞情报」，vuln_intel.read；
`web/src/pages/vuln-intel/VulnIntelPage.tsx`）：概览卡（含同步状态与失败原因）/
列表（关键字/级别/技术/来源/发布区间过滤）/详情抽屉（含受影响应用）/订阅设置/
技术资产维护/JSON 导入/手动同步；写操作入口按 vuln_intel.manage 隐藏。

### 8. 测试现状（已测 / 未测）

已测（2026-10-23 本地实跑通过）：

- 服务端单测 `go test ./internal/vulnintel/`：14 个测试函数——vulnintel_test.go
  7 例（CVE/技术名/级别派生/条目校验/标签提取/订阅解析与校验）+ nvd_test.go 4 例
  （fake NVD httptest：解析映射、首次 48h 窗口 + 增量回拨、失败如实落 FAILED 保留
  上次成功现场、并发互斥）+ alert_test.go 3 例（聚合提醒/级别门槛与订阅过滤/失败
  路径不记账）；
- 前端 `vitest run` VulnIntelPage 13 例全绿（概览/列表/过滤/详情/设置/技术资产/
  导入三态/手动同步/无 manage 权限隐藏写入口/导入 JSON 解析）。

未测 / 未实测（如实声明）：

- **真实 NVD 联机同步未实测**：从未对真实 services.nvd.nist.gov 发起过同步，真实
  出站可达性、限速表现与真实响应解析均以 fake 服务端单测代替；
- 集成测试 `server/tests/vuln_intel_api_test.go` 5 例（TestVulnIntelAPI /
  TestVulnIntelAPIPermissions / TestVulnIntelImportValidation /
  TestVulnIntelTechAssetsReplace / TestVulnIntelMigration000189Replay）本地因无
  POSTGRES_PASSWORD/VALKEY_PASSWORD 按惯例 SKIP（CI 全量执行）；
- 每日定时循环仅逻辑级单测覆盖，未做长周期真实调度运行观测。

---

## 第二部分：完整能力设计（V1.0 原文，后续迭代基线，未实现）

> 以下为 V1.0（2026-09-14）设计评审稿原文。与 MVP 的出入以第一部分为准，要点：
> ① 迁移编号 000164–000166 未被使用（实际落 000189；后续迁移号按届时最大值顺延）；
> ② V1.0 数据源表中的 NVD URL 笔误为 `services.nist.gov`，正确地址为
> `services.nvd.nist.gov`（MVP 已按后者硬编码）；③ V1.0 表结构（vuln_cves /
> vuln_cpe_matches / vuln_intel_imports）与 MVP 表（vuln_advisories /
> application_technologies / vuln_alerted / vuln_intel_sync_state）不同，落地完整
> 能力时需设计迁移演进而非直接套用；④ 签名离线包、KEV/EPSS、SBOM 匹配、license
> 门控均未实现。

> 上游背景：PSIRT + Reporting Clock 与 "Active Exploitation 进入漏洞风险模型第一层" 两项 P0 建议（详见会议纪要）。本设计只覆盖其中的**数据底座**：CVE 漏洞库 + 外部利用情报（CISA KEV / EPSS）接入与产品侧（SBOM）匹配。PSIRT 生命周期实体、统一风险优先级模型、虚拟补丁联动在各自设计文档中展开，本文只定义它们消费的下游契约。

### 一、目标与非目标

#### 目标

1. 内置 CVE 漏洞库（NVD 全量 + 增量），支持检索、过滤、详情查看。
2. 接入外部利用情报：CISA KEV（主动利用证据）+ FIRST EPSS（利用概率），使 `active_exploitation` 成为一等字段。
3. 离线优先：客户现场多为离线/半离线部署（离线交付是产品核心形态），情报必须可经**签名数据包**导入，不依赖外网。
4. 产品侧（PSIRT）自动匹配：基于 SBOM 组件清单识别聚信产品自身受影响组件，产出待办。
5. 为统一风险模型（`active_exploitation` / `exploit_observed_at` 等字段）与客户侧弱点增强提供数据契约。

#### 非目标

- 不做漏洞扫描器（不主动探测客户资产漏洞；客户侧扫描已有 apiscan 模块）。
- 不做商业威胁情报产品的完整替代（无 IOC/TTP/组织画像）。
- 不引入遥测回传：情报流是**纯下行**，聚信服务器不上传任何客户数据。（MVP 已落实此条）
- AI 不直接判定风险优先级（与"AI Generate ≠ AI Auto Block"同一治理线：AI 只做信息补全/摘要，优先级由确定性规则计算）。

### 二、数据源

| 源 | 内容 | 获取方式 | 频率 | 合规说明 |
|---|---|---|---|---|
| NVD API 2.0 | CVE 描述、CVSS v3.1/v4.0、CWE、CPE configurations、参考链接 | `https://services.nvd.nist.gov/rest/json/cves/2.0`（增量窗口 `lastModStartDate/lastModEndDate`；MVP 用 `keywordSearch=php` + `pubStartDate/pubEndDate`） | 每日增量 | 公开数据（NIST，美国政府作品无版权），需保留出处；无 API key 限速 5 req/30s，有 key 50 req/30s |
| CISA KEV | 已知被主动利用漏洞清单（dateAdded、dueDate、requiredAction、knownRansomwareCampaignUse） | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 每日 | CISA 公开数据，鼓励再分发，保留出处 |
| FIRST EPSS | CVE 利用概率评分（score/percentile） | `https://epss.cyentia.com/epss_scores-current.csv.gz` | 每日 | FIRST.org 公开数据，保留出处 |
| 手工导入 | CNVD/CNNVD 等无开放 API 的国内源、厂商通告 | 页面录入/CSV 导入（后续迭代；MVP 为 JSON 导入） | 人工 | — |

设计要点：

- 三个在线源的 URL **硬编码白名单**（不接受用户配置任意 URL），走 https + 响应大小上限 + 超时，杜绝 SSRF 面。（MVP 已对 NVD 落实此条）
- 所有源在库中保留 `source` 与原始拉取时间，页面对外展示注明出处（合规要求）。
- 离线数据包与在线同步共用同一份入库管线（归一化 → upsert），仅数据来源标记不同。（MVP 已落实此条：导入与同步共用 upsert 与提醒引擎）

### 三、数据模型（PostgreSQL）

> 注意：以下迁移编号与表结构为 V1.0 设计值，未实现；MVP 实际落 000189 四表（见第一部分 §2）。

迁移编号顺延（V1.0 时最大 000163，本设计曾预留 000164–000166，未使用）。

#### 3.1 `vuln_cves`（CVE 主表，设计值）

| 列 | 类型 | 说明 |
|---|---|---|
| cve_id | varchar(20) PK | `CVE-YYYY-NNNNN` |
| description | text | 英文原文描述 |
| description_zh | text | 中文摘要（AI 补全，人工确认前标记 `zh_status=AI_DRAFT`） |
| cvss_v31_score / cvss_v31_vector | numeric(3,1) / varchar(128) | 可空 |
| cvss_v40_score / cvss_v40_vector | numeric(3,1) / varchar(128) | 可空 |
| severity | varchar(16) | 派生：CRITICAL/HIGH/MEDIUM/LOW/NONE（取最高可用 CVSS 版本） |
| cwe_ids | jsonb | `["CWE-79"]` |
| configurations | jsonb | NVD CPE 节点原文（版本区间匹配依据） |
| references_json | jsonb | `[{url, source, tags}]`，上限 50 条截断 |
| published_at / last_modified_at | timestamptz | NVD 原始时间 |
| epss_score / epss_percentile | numeric(6,5) / numeric(6,5) | 可空，EPSS 日更覆盖 |
| **is_kev** | boolean not null default false | KEV 在榜标记（主动利用证据） |
| **kev_added_at** | timestamptz | 即下游契约的 `exploit_observed_at` |
| kev_due_date | date | KEV 要求整改期限（BOD 22-01 对联邦机构；可作客户参考时钟） |
| kev_required_action | text | KEV 修复指引原文 |
| kev_ransomware | boolean | 已知勒索软件使用 |
| source | varchar(16) | NVD / MANUAL |
| created_at / updated_at | timestamptz | |

索引：`severity`、`is_kev WHERE is_kev`、`last_modified_at DESC`、`epss_score DESC NULLS LAST`。检索走 `cve_id` 前缀 + `description` trigram（pg_trgm 已在用则复用，否则 ILIKE）。

规模估算：NVD 全量约 26–30 万条（年增 ~4 万），单行均 ~2KB，全量 <1GB，PG 单表无压力；KEV 仅 ~1500 条，EPSS 为全量评分每日覆盖更新。

#### 3.2 `vuln_cpe_matches`（组件↔CVE 匹配结果，设计值）

产品侧（SBOM）匹配产物，PSIRT 设计消费：

| 列 | 说明 |
|---|---|
| id uuid PK | |
| cve_id → vuln_cves | FK |
| component_name / component_version | 来自 SBOM（如 `coraza v3.7.0`） |
| purl / cpe | 匹配标识 |
| match_kind | `SBOM_AUTO` / `MANUAL_CONFIRM` / `DISMISSED`（误报关闭） |
| status | `OPEN` / `MITIGATED` / `PATCHED` / `NOT_AFFECTED` / `DISMISSED`（PSIRT 状态机挂接点此列） |
| first_matched_at / updated_at | |

UNIQUE(cve_id, component_name, component_version)。

#### 3.3 `vuln_intel_sync_state`（同步状态，设计值）

每数据源一行：`source`（NVD/KEV/EPSS）PK、`mode`（ONLINE/OFFLINE）、`last_sync_at`、`last_window_start/end`、`records_upserted`、`status`（OK/RUNNING/FAILED）、`failure_message`、`data_date`（情报数据自身日期，离线包回滚防护用）。

> MVP 已实现同名表但结构更简：无 mode/data_date，status 词表为 IDLE/SUCCESS/FAILED（见第一部分 §2）。

#### 3.4 `vuln_intel_imports`（离线导入批次，设计值）

`id`、文件名、包数据日期、包内各源记录数、签名验证结果、导入人、request_id、created_at——操作审计之外的可追溯批次记录。（MVP 未实现，导入仅有操作审计。）

### 四、同步与导入架构

```
在线模式（聚信内网/可联网环境）          离线模式（客户现场，P0）
┌─────────────────────┐               ┌──────────────────────────┐
│ intel sync worker    │               │ 聚信发布侧 intel-pack 工具 │
│ 每日定时/手动触发     │               │ 拉取三源 → 归一化 → 打包   │
│ NVD/KEV/EPSS（白名单）│               │  → manifest → ed25519 签名 │
└─────────┬───────────┘               └───────────┬──────────────┘
          │ 归一化 upsert                          │ 前端上传 .jzintel 包
          ▼                                        ▼
┌──────────────────────────────────────────────────────────┐
│              入库管线（归一化 → 校验 → 批量 upsert）          │
│  离线包：验签(ed25519，复用升级包公钥) → 数据日期防回滚 → 入库 │
└──────────────────────────────────────────────────────────┘
```

#### 4.1 在线同步 worker（设计值；MVP 实际为 `server/internal/vulnintel/nvd.go`）

- app.go 装配，默认每日运行（`vuln_intel.sync_enabled` 系统设置可关）。MVP 口径：启动 1 分钟首轮、其后 24h 一轮，开关关闭时空转；同步失败如实落 `vuln_intel_sync_state`（失败原因概览页可见），未实现"同类失败 24h 只报一次"的 system_alerts 告警。
- NVD 增量：窗口回拨防漏（MVP 为上次窗口终点回拨 1h），单页 2000 条翻页；V1.0 的"首次离线基线包引导 / 全量在线拉取"未实现（MVP 首窗固定最近 48h）。
- KEV/EPSS：整文件下载、全量替换式 upsert、KEV 下榜处理——未实现。
- 限流：无 API key 时页间 7s（MVP 口径）；`vuln_intel.nvd_api_key` 敏感设置项未实现。
- 断点：同步状态落 `vuln_intel_sync_state`，崩溃后从窗口起点重跑（upsert 幂等）。（MVP 已落实此条）

#### 4.2 离线情报包（未实现）

- **制作侧**（聚信发布管线，非交付代码路径）：`ops/offline-package/` 新增 `build-intel-pack.sh`，输出 `jiuzhang-intel-YYYYMMDD.tar.gz`（`nvd.jsonl.gz` + `kev.json` + `epss.csv.gz` + `manifest.json`），用 `tools/regsign` 同款 ed25519 私钥生成 `.sig` 分离签名；随产品版本发布节奏产出（建议每周）。
- **消费侧**：`POST /api/v1/vuln-intel/import`（multipart，上限 512MB，流式落临时文件再验签）：
  1. ed25519 验签（复用 `server/internal/upgrades/artifact.go` 的 `packageReleasePublicKey()` 与清单绑定机制，抽取共用校验函数到公共包，升级包与情报包共用）；
  2. `manifest.json` 逐文件 sha256 校验；
  3. **防回滚**：`data_date` 早于库内当前 `data_date` 时拒绝（提供 `force=true` 显式覆盖 + 审计）；
  4. 分批 COPY/upsert 入库（每批 5000 行事务），写 `vuln_intel_imports` + 审计。
- 验签失败/清单不符 → 400 + 安全审计（RiskHigh），与升级包同语义。

> MVP 实际导入接口为同路径的明文 JSON 数组（≤4MB、≤500 条），无验签与防回滚；升级为签名包时需保持路径兼容或新增端点。

### 五、产品侧匹配引擎（SBOM → CVE，未实现）

- 输入：`docs/SBOM.cyclonedx.json`（`scripts/generate-sbom.sh` 已产出，含 purl/版本）+ 固化的 `cpe_aliases` 映射表（人工维护：组件名→CPE vendor/product，如 `coraza → coraza:coraza_waf`；首版覆盖 DEPENDENCIES.md 全部核心组件，约 40 条）。
- 匹配：按 CPE vendor/product 命中 `configurations`，再做版本区间（`versionStartIncluding` 等）比较；版本不可比较时降级为"疑似命中"由人工确认。
- 产出：`vuln_cpe_matches`（`SBOM_AUTO`），PSIRT 生命周期在其上挂接（本设计不展开）。
- 触发：情报入库后增量匹配（仅对新增/更新 CVE）+ SBOM 变更后全量重匹配。
- 客户侧资产关联（站点指纹 → 组件 → CVE）与虚拟补丁（CVE → CRS/自定义规则覆盖建议）：**后续迭代**，依赖站点发现指纹能力，本文只预留 `match_kind` 扩展位。

### 六、API 与前端（设计值）

#### 6.1 API（权限点 `vuln_intel.read` / `vuln_intel.manage`——MVP 已按此权限模型落 000189 种子，read 授 SYSTEM_ADMIN+SECURITY_ADMIN，manage 仅 SYSTEM_ADMIN）

| 方法/路径 | 权限 | 说明 |
|---|---|---|
| GET `/api/v1/vuln-intel/cves` | read | 分页 + 关键字 + severity/年份/is_kev/has_epss/组件名 过滤（未实现；MVP 为 `/advisories`） |
| GET `/api/v1/vuln-intel/cves/{cve_id}` | read | 详情：CVSS 双版本、CWE、KEV 全字段、EPSS、命中组件列表（未实现；MVP 详情为 advisory + 受影响应用） |
| GET `/api/v1/vuln-intel/overview` | read | 卡片：总 CVE 数、KEV 数、近 7 日新增、产品组件命中待办数、各源同步状态（MVP 已实现简化版） |
| POST `/api/v1/vuln-intel/sync` | manage | 手动触发在线同步（MVP 已实现；并发中 409） |
| POST `/api/v1/vuln-intel/import` | manage | 离线包上传导入（验签+防回滚+审计）（MVP 已实现明文 JSON 版） |
| GET `/api/v1/vuln-intel/imports` | read | 导入批次列表（未实现） |

OpenAPI 片段 `21-vuln-intel.yaml`（MVP 已落，`make openapi-reconcile` 对账）。

#### 6.2 前端（设计值）

- 菜单：「安全运营」分组新增「漏洞情报」（`/vuln-intel`，`vuln_intel.read`）。（MVP 已落实）
- 页面：顶部概览卡（含同步状态与"导入情报包"入口）+ CVE 列表（SmartTable 服务端分页，KEV 红色徽标、EPSS 百分位、severity 着色）+ 详情 Drawer（描述/CVSS 向量/参考链接/KEV 面板/命中组件表）。MVP 口径：列表 + 详情抽屉 + 订阅设置 + 技术资产映射 + JSON 导入，无 KEV/EPSS 元素。
- 导入入口：上传组件（Dragger）→ 显示验签结果与批次摘要；失败原因明示（签名无效/数据过旧/文件损坏）。MVP 口径：粘贴 JSON 文本导入，展示 received/inserted/updated/invalid 统计与逐条失败明细。

### 七、安全、合规与许可证

- **纯下行**：无任何遥测回传；在线模式只访问白名单 URL。（MVP 已落实：单一硬编码 NVD 地址）
- **签名与防篡改**：离线包 ed25519 + 清单 sha256，与升级包同一密钥体系与校验代码路径。（未实现）
- **审计**：同步触发、导入（含验签失败）、匹配关闭（DISMISSED）全部落 operation_audits。（MVP 已落实同步/导入/映射/设置四类写操作审计）
- **许可证门控**：license payload `features` 数组新增 `threat_intel`（离线授权设计既有机制）；未授权时不隐藏 CVE 检索（基础能力），但**关闭在线同步与离线导入之外的高阶能力**——具体裁剪点在实施时与产品确认（建议：KEV/EPSS 字段与组件匹配为 `threat_intel` 门控）。（MVP 未实施任何 license 门控）
- **数据合规**：页面与导出保留来源标注（NVD/CISA/FIRST）；CNVD/CNNVD 类手工录入数据标记 `source=MANUAL`。（MVP 已落实 source 词表）

### 八、AI 角色边界

- AI 可做：CVE 中文摘要草稿（`description_zh`，`AI_DRAFT` 状态人工确认后生效）、CPE 别名映射建议（人工确认入库）、KEV 影响面汇总文案。（均未实现）
- AI 不可做：风险优先级排序、KEV/EXPLOIT 状态判定、匹配结果自动关闭——全部为确定性规则或人工操作。

### 九、分期实施（V1.0 分期；实际演进为 MVP 先行）

| 期 | 内容 | 验收 |
|---|---|---|
| MVP（实际，2026-10-22） | 000189 四表；NVD keywordSearch=php 每日同步 + JSON 导入 + 订阅聚合提醒（VULN_INTEL_NEW）+ 应用技术栈手动映射 + 前端页面 | 单测/前端测试通过；真实 NVD 联机同步未实测（见第一部分 §8） |
| P0 | CVE 全量库（原 000164–000166 演进）；离线签名包制作脚本 + 导入验签/防回滚；KEV 字段接入 | 离线包在 stage5 导入真实 KEV+NVD 子集，页面可查，验签负例被拒 |
| P1 | KEV/EPSS 整量同步 + 限速 + 告警；SBOM 匹配引擎 + `vuln_cpe_matches`；EPSS 接入 | 在线同步跑通增量窗口；SBOM 全量匹配出产 OPEN 待办 |
| P2 | 中文摘要 AI 草稿流；手工导入通道增强；客户侧资产关联与虚拟补丁（依赖站点指纹，另行立项） | — |

### 十、测试与质量（设计值）

- 单测：归一化（NVD/KEV/EPSS 样本 JSON 固化为测试夹具）、验签/防回滚/清单校验、版本区间匹配矩阵、限流退避。
- 接口测试：列表过滤矩阵、详情 404、权限 403、导入负例（坏签名/旧数据/截断文件）。
- 集成：stage5 导入真实周度包子集，验证 `is_kev` 与 `kev_added_at` 正确落库并在页面展示。
- 性能：30 万行全量导入 < 10 分钟；列表分页 P95 < 300ms（索引验证 EXPLAIN）。

---

Copyright © 聚信得仁. All Rights Reserved.
