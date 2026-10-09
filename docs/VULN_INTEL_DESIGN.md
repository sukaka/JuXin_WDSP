# CVE 漏洞库与外部利用情报接入设计

版本：V1.0（2026-09-14）　状态：设计评审中

> 上游背景：PSIRT + Reporting Clock 与 "Active Exploitation 进入漏洞风险模型第一层" 两项 P0 建议（详见会议纪要）。本文档只覆盖其中的**数据底座**：CVE 漏洞库 + 外部利用情报（CISA KEV / EPSS）接入与产品侧（SBOM）匹配。PSIRT 生命周期实体、统一风险优先级模型、虚拟补丁联动在各自设计文档中展开，本文只定义它们消费的下游契约。

## 一、目标与非目标

### 目标

1. 内置 CVE 漏洞库（NVD 全量 + 增量），支持检索、过滤、详情查看。
2. 接入外部利用情报：CISA KEV（主动利用证据）+ FIRST EPSS（利用概率），使 `active_exploitation` 成为一等字段。
3. 离线优先：客户现场多为离线/半离线部署（离线交付是产品核心形态），情报必须可经**签名数据包**导入，不依赖外网。
4. 产品侧（PSIRT）自动匹配：基于 SBOM 组件清单识别聚信产品自身受影响组件，产出待办。
5. 为统一风险模型（`active_exploitation` / `exploit_observed_at` 等字段）与客户侧弱点增强提供数据契约。

### 非目标

- 不做漏洞扫描器（不主动探测客户资产漏洞；客户侧扫描已有 apiscan 模块）。
- 不做商业威胁情报产品的完整替代（无 IOC/TTP/组织画像）。
- 不引入遥测回传：情报流是**纯下行**，聚信服务器不上传任何客户数据。
- AI 不直接判定风险优先级（与"AI Generate ≠ AI Auto Block"同一治理线：AI 只做信息补全/摘要，优先级由确定性规则计算）。

## 二、数据源

| 源 | 内容 | 获取方式 | 频率 | 合规说明 |
|---|---|---|---|---|
| NVD API 2.0 | CVE 描述、CVSS v3.1/v4.0、CWE、CPE configurations、参考链接 | `https://services.nist.gov/rest/json/cves/2.0`（增量窗口 `lastModStartDate/lastModEndDate`） | 每日增量 | 公开数据（NIST，美国政府作品无版权），需保留出处；无 API key 限速 5 req/30s，有 key 50 req/30s |
| CISA KEV | 已知被主动利用漏洞清单（dateAdded、dueDate、requiredAction、knownRansomwareCampaignUse） | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 每日 | CISA 公开数据，鼓励再分发，保留出处 |
| FIRST EPSS | CVE 利用概率评分（score/percentile） | `https://epss.cyentia.com/epss_scores-current.csv.gz` | 每日 | FIRST.org 公开数据，保留出处 |
| 手工导入 | CNVD/CNNVD 等无开放 API 的国内源、厂商通告 | 页面录入/CSV 导入（后续迭代） | 人工 | — |

设计要点：

- 三个在线源的 URL **硬编码白名单**（不接受用户配置任意 URL），走 https + 响应大小上限 + 超时，杜绝 SSRF 面。
- 所有源在库中保留 `source` 与原始拉取时间，页面对外展示注明出处（合规要求）。
- 离线数据包与在线同步共用同一份入库管线（归一化 → upsert），仅数据来源标记不同。

## 三、数据模型（PostgreSQL）

迁移编号顺延（当前最大 000163，本设计使用 000164–000166）。

### 3.1 `vuln_cves`（CVE 主表，000164）

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

### 3.2 `vuln_cpe_matches`（组件↔CVE 匹配结果，000165）

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

### 3.3 `vuln_intel_sync_state`（同步状态，000166）

每数据源一行：`source`（NVD/KEV/EPSS）PK、`mode`（ONLINE/OFFLINE）、`last_sync_at`、`last_window_start/end`、`records_upserted`、`status`（OK/RUNNING/FAILED）、`failure_message`、`data_date`（情报数据自身日期，离线包回滚防护用）。

### 3.4 `vuln_intel_imports`（离线导入批次，000166）

`id`、文件名、包数据日期、包内各源记录数、签名验证结果、导入人、request_id、created_at——操作审计之外的可追溯批次记录。

## 四、同步与导入架构

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

### 4.1 在线同步 worker（server/internal/vulnintel/syncer.go）

- app.go 装配，默认每日 03:40 运行（`vuln_intel.sync_enabled` 系统设置可关；联网不可达时优雅失败 + system_alerts 告警，不刷屏——同类失败 24h 内只报一次）。
- NVD 增量：`lastModStartDate = last_sync_at - 1h`（窗口回拨防漏），单页 2000 条翻页；首次无状态时提示走离线基线包引导（全量在线拉取约 2–4 小时，仅作为备选）。
- KEV/EPSS：整文件下载（<10MB / ~40MB gz），全量替换式 upsert；KEV 下榜处理（`is_kev=false` 但保留历史字段）。
- 限流：无 API key 时 6s/请求；`vuln_intel.nvd_api_key`（敏感设置项，加密存储）。
- 断点：同步状态落 `vuln_intel_sync_state`，崩溃后从窗口起点重跑（upsert 幂等）。

### 4.2 离线情报包（P0）

- **制作侧**（聚信发布管线，非交付代码路径）：`ops/offline-package/` 新增 `build-intel-pack.sh`，输出 `jiuzhang-intel-YYYYMMDD.tar.gz`（`nvd.jsonl.gz` + `kev.json` + `epss.csv.gz` + `manifest.json`），用 `tools/regsign` 同款 ed25519 私钥生成 `.sig` 分离签名；随产品版本发布节奏产出（建议每周）。
- **消费侧**：`POST /api/v1/vuln-intel/import`（multipart，上限 512MB，流式落临时文件再验签）：
  1. ed25519 验签（复用 `server/internal/upgrades/artifact.go` 的 `packageReleasePublicKey()` 与清单绑定机制，抽取共用校验函数到公共包，升级包与情报包共用）；
  2. `manifest.json` 逐文件 sha256 校验；
  3. **防回滚**：`data_date` 早于库内当前 `data_date` 时拒绝（提供 `force=true` 显式覆盖 + 审计）；
  4. 分批 COPY/upsert 入库（每批 5000 行事务），写 `vuln_intel_imports` + 审计。
- 验签失败/清单不符 → 400 + 安全审计（RiskHigh），与升级包同语义。

## 五、产品侧匹配引擎（SBOM → CVE）

- 输入：`docs/SBOM.cyclonedx.json`（`scripts/generate-sbom.sh` 已产出，含 purl/版本）+ 固化的 `cpe_aliases` 映射表（人工维护：组件名→CPE vendor/product，如 `coraza → coraza:coraza_waf`；首版覆盖 DEPENDENCIES.md 全部核心组件，约 40 条）。
- 匹配：按 CPE vendor/product 命中 `configurations`，再做版本区间（`versionStartIncluding` 等）比较；版本不可比较时降级为"疑似命中"由人工确认。
- 产出：`vuln_cpe_matches`（`SBOM_AUTO`），PSIRT 生命周期在其上挂接（本设计不展开）。
- 触发：情报入库后增量匹配（仅对新增/更新 CVE）+ SBOM 变更后全量重匹配。
- 客户侧资产关联（站点指纹 → 组件 → CVE）与虚拟补丁（CVE → CRS/自定义规则覆盖建议）：**后续迭代**，依赖站点发现指纹能力，本文只预留 `match_kind` 扩展位。

## 六、API 与前端

### 6.1 API（权限点 `vuln_intel.read` / `vuln_intel.manage`，迁移种子，read 授 SYSTEM_ADMIN+SECURITY_ADMIN，manage 仅 SYSTEM_ADMIN）

| 方法/路径 | 权限 | 说明 |
|---|---|---|
| GET `/api/v1/vuln-intel/cves` | read | 分页 + 关键字 + severity/年份/is_kev/has_epss/组件名 过滤 |
| GET `/api/v1/vuln-intel/cves/{cve_id}` | read | 详情：CVSS 双版本、CWE、KEV 全字段、EPSS、命中组件列表 |
| GET `/api/v1/vuln-intel/overview` | read | 卡片：总 CVE 数、KEV 数、近 7 日新增、产品组件命中待办数、各源同步状态 |
| POST `/api/v1/vuln-intel/sync` | manage | 手动触发在线同步（RUNNING 时 409） |
| POST `/api/v1/vuln-intel/import` | manage | 离线包上传导入（验签+防回滚+审计） |
| GET `/api/v1/vuln-intel/imports` | read | 导入批次列表 |

OpenAPI 新片段 `21-vuln-intel.yaml`，`make openapi-reconcile` 对账。

### 6.2 前端

- 菜单：「安全运营」分组新增「漏洞情报」（`/vuln-intel`，`vuln_intel.read`）。
- 页面：顶部概览卡（含同步状态与"导入情报包"入口）+ CVE 列表（SmartTable 服务端分页，KEV 红色徽标、EPSS 百分位、severity 着色）+ 详情 Drawer（描述/CVSS 向量/参考链接/KEV 面板/命中组件表）。
- 导入入口：上传组件（Dragger）→ 显示验签结果与批次摘要；失败原因明示（签名无效/数据过旧/文件损坏）。

## 七、安全、合规与许可证

- **纯下行**：无任何遥测回传；在线模式只访问三个白名单 URL。
- **签名与防篡改**：离线包 ed25519 + 清单 sha256，与升级包同一密钥体系与校验代码路径。
- **审计**：同步触发、导入（含验签失败）、匹配关闭（DISMISSED）全部落 operation_audits。
- **许可证门控**：license payload `features` 数组新增 `threat_intel`（离线授权设计既有机制）；未授权时不隐藏 CVE 检索（基础能力），但**关闭在线同步与离线导入之外的高阶能力**——具体裁剪点在实施时与产品确认（建议：KEV/EPSS 字段与组件匹配为 `threat_intel` 门控）。
- **数据合规**：页面与导出保留来源标注（NVD/CISA/FIRST）；CNVD/CNNVD 类手工录入数据标记 `source=MANUAL`。

## 八、AI 角色边界

- AI 可做：CVE 中文摘要草稿（`description_zh`，`AI_DRAFT` 状态人工确认后生效）、CPE 别名映射建议（人工确认入库）、KEV 影响面汇总文案。
- AI 不可做：风险优先级排序、KEV/EXPLOIT 状态判定、匹配结果自动关闭——全部为确定性规则或人工操作。

## 九、分期实施

| 期 | 内容 | 验收 |
|---|---|---|
| P0 | 000164–000166 迁移；入库管线；离线包制作脚本 + 导入接口（验签/防回滚/审计）；CVE 检索/详情/概览 API + 前端页面；KEV 字段接入 | 离线包在 stage5 导入真实 KEV+NVD 子集，页面可查，验签负例被拒 |
| P1 | 在线同步 worker（NVD 增量 + KEV/EPSS 整量 + 限速 + 告警）；SBOM 匹配引擎 + `vuln_cpe_matches`；EPSS 接入 | 在线同步跑通增量窗口；SBOM 全量匹配出产 OPEN 待办 |
| P2 | 中文摘要 AI 草稿流；手工导入通道；客户侧资产关联与虚拟补丁（依赖站点指纹，另行立项） | — |

## 十、测试与质量

- 单测：归一化（NVD/KEV/EPSS 样本 JSON 固化为测试夹具）、验签/防回滚/清单校验、版本区间匹配矩阵、限流退避。
- 接口测试：列表过滤矩阵、详情 404、权限 403、导入负例（坏签名/旧数据/截断文件）。
- 集成：stage5 导入真实周度包子集，验证 `is_kev` 与 `kev_added_at` 正确落库并在页面展示。
- 性能：30 万行全量导入 < 10 分钟；列表分页 P95 < 300ms（索引验证 EXPLAIN）。

---

Copyright © 聚信得仁. All Rights Reserved.
