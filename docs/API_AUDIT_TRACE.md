# API 审计与溯源设计（阶段8 / WDSP，补全任务书 §231 口径）

## 一、目的与范围

本文档描述 API 安全域的审计与溯源能力现状：请求级审计（`api_runtime_events`
六审计列与响应后输出）、管理面操作审计哈希链、主体审计（Identity 单维现状）、
全链脱敏纪律，以及"事件→风险→弱点→模型/策略版本"溯源链的已通段与断点。

覆盖代码：`gateway/modules/jiuzhang_guard/apievents/`（事件输出）、
`gateway/modules/jiuzhang_guard/apiprotect.go`（事件时机与字段装配）、
`server/internal/apiruntime/`（采集器、events.go 落库、findings.go 物化）、
`server/internal/audits/audits.go`（操作审计哈希链）、
迁移 000001（审计表与禁改删 RULE）、000029（事件身份列）、000030（响应状态码）、
000035（六审计列）、000036（findings 物化列）、000037（运行时策略版本）。

## 二、请求级审计（api_runtime_events）

### 2.1 事件流与时机

```text
网关统一引擎（jiuzhang_guard 请求链 serveNext 唯一挂点）
  ▼ emitAPIEvent（apiprotect.go:385）→ JSONL 文件 api-runtime-events.log
采集器 Collector（断点续传/轮转/错误文件；2s 周期）
  ▼ SavePrimary（apiruntime/events.go:28）
api_runtime_events（request_id 幂等：同一 Request ID 只生成一个主事件）
```

事件输出时机（apiprotect.go 头注释与 emitAPIEvent 实现）：

| 请求类别 | 输出时机 | response_status 语义 |
|----------|----------|----------------------|
| 阻断类（BLOCK/RATE_LIMIT/TEMP_BLOCK） | 阻断时输出 | 按决策映射 403/429 |
| API 放行流量 | **下游响应完成后输出** | 真实回包状态码 + 真实 latency_ms（入口到响应完成） |
| 非 API 命中（有检测明细的非 API 流量） | 响应前输出（既有行为） | 0 = 未采集 |
| 纯 ALLOW 无明细 | 不落主事件表（notable 过滤，collector.go:91） | — |

响应后输出是 API 安全补全第一批的关键修复：此前放行请求在上游响应前输出事件，
状态码恒 0，学习样本的 response_status 过滤规则无原料；现 API 流量事件携带真实
状态码、时延与响应侧 findings（响应相位明细随同一主事件输出）。

### 2.2 审计列（迁移 000035 新增六列）

| 列 | 语义 | 来源 |
|----|------|------|
| `client_ip` | 真实客户端 IP（guard 入口已改写 RemoteAddr；空 = 不可得） | 网关事件 client_ip |
| `method` | 请求方法（冗余自 endpoint_key 前缀，便于按方法过滤/聚合） | 解析产物 |
| `raw_path` | 归一化前原始路径（不含 query，Emit 时封顶 512 字符） | 解析产物 |
| `latency_ms` | 请求处理耗时（毫秒） | 响应后输出计时 |
| `model_version` | 判定所用 FORMAL 模型版本号（发布通道 api_formal_model_versions 按API下发，网关随事件回报） | 发布通道 |
| `policy_version` | 判定所运行 API 策略版本戳（发布通道 api_policy_version：冻结模型+确认约束+脱敏规则的规范序列化 sha256） | 发布通道 |

落库纪律（events.go:41-66）：六列全部可空；旧版网关事件缺字段时为零值，
空串/非正耗时统一落 NULL——**不伪造 0 值审计数据**（latency_ms=0 视为未上报而非
真实 0 毫秒）。列表接口 `GET /api/v1/api-security/runtime/events`
（api_runtime.read）返回全部审计列，并支持 identity_fingerprint 精确过滤。

### 2.3 覆盖面的如实说明

请求级审计仍是"值得注意"子集而非全量：notable 判定（有检测明细或动作非 ALLOW）
之外的纯通行 API 请求只喂API发现与流量趋势桶，不落主事件表。全量访问日志
（access_logs，000023）覆盖全量请求，但与 API 域**无关联键**（断点见第六节）。

## 三、操作审计哈希链

管理面操作审计（`audits/audits.go`，阶段2 起闭环）：

- **哈希链**：每条记录计算 `record_hash`（含上一条 `previous_hash`），
  `VerifyChain` 可全量校验链完整性；
- **禁改删**：数据库层 RULE 禁止 UPDATE/DELETE（迁移 000001）；
- **脱敏**：before/after 摘要经 `MaskSensitiveJSON`（口令、密钥、令牌等敏感键
  值替换为掩码）；
- **导出**：审计导出走既有导出链路。

API 安全域已接入操作审计的动作（示例）：模型生命周期（候选/评审/确认/激活/回滚）、
弱点处置（confirm/assign/fixed/retest/ignore/archive，module=api_security，
object_type=api_weakness）、敏感数据类型与脱敏规则管理（apidata）、
学习达标自动完成（learning_auto_complete，actor=system）、策略模式变更与发布。
风险处置（findings 七态状态机八条接口）已按同一纪律接入操作审计
（`apisecurity/risk_handler.go` recordAudit，object_type=api_runtime_finding）。

## 四、主体审计（Identity 单维现状）

- 事件级主体：`identity_fingerprint`（仅凭据派生，匿名为空）+ `auth_type` +
  `source_fingerprint`（客户端 IP 的加盐指纹；迁移 000029）；
- 风险级主体：findings 物化时提取 `subject_type/subject_id`
  （IDENTITY=身份指纹 / IP=来源指纹；永不落明文，findings.go:112）；
- 画像级主体：`api_identity_profiles`（指纹 × API聚合，质量分与风险评估，
  见 docs/API_IDENTITY_AUTHORIZATION.md 第四节）。

现状为 **Identity 单维主体审计**：无应用/租户/角色维度的主体审计视图，
任务书 §86 的多维主体审计为后续迭代项。

## 五、脱敏纪律（全链）

| 环节 | 纪律 | 代码锚点 |
|------|------|----------|
| 请求解析 | authorization/cookie/x-api-key 头值即替换 `[redacted]` | parser/parse.go |
| 身份/来源标识 | 一律 HMAC-SHA256 截断指纹，盐 identity_salt；凭据明文不出函数作用域 | detectors/fingerprint.go |
| 参数值观测 | 只存 length/hash/num（hash 为截断 sha256），明文不出网关 | detectors/paramobs.go |
| 事件证据 | DetectorMatch.Evidence 只含脱敏键值（长度分档/形态标签） | 各检测器 |
| 响应头快照 | set-cookie/www-authenticate 等仅标记存在，值截断、头数封顶 | apiresponse.go:234 |
| 风险证据 | 白名单键附值（截断 128），白名单外只留键名；参数值永不落库 | findings.go:125-145 |
| 弱点证据 | 仅规则/计数/窗口/时间摘要 | sweep.go:170 |
| 操作审计摘要 | MaskSensitiveJSON 敏感键掩码 | audits.go:99 |
| 明文开口 | `client_ip` 是唯一明文审计列（审计溯源有意开口，迁移 000035 注释口径：指纹用于聚合关联，明文 IP 仅供审计溯源） | — |

任务书 §89"二次认证查看原值"不存在——值本不落库，无可还原（比任务书更保守）。

## 六、溯源链现状与断点

### 6.1 已通段

```text
Event（api_runtime_events，request_id 幂等）
  ├─→ Finding（api_runtime_findings；采集器物化，request_id 关联首次命中）
  │     └─→ Weakness（api_weaknesses；Sweeper 派生，只读不回写）
  ├─→ ModelVersion（model_version 列直答"命中时生效哪版模型"；
  │     schema 违例另经 api_schema_violations.model_version_id 精确关联）
  ├─→ RuntimePolicy（policy_version 列 = 发布内容哈希，可比对发布记录；
  │     API级策略版本状态机见 api_runtime_policies，迁移 000037）
  ├─→ Identity（identity_fingerprint → api_identity_profiles 画像与风险详情）
  └─→ 操作审计（request_id 贯穿管理面操作审计记录）
```

### 6.2 断点（如实标注）

1. **Coraza 阻断不归因**：guard 先于 coraza 执行，Coraza 独立 403 的请求其
   api_runtime_events 记录（若已产出）的 final_action/response_status 不反映
   WAF 阻断；管理面仅经 x-request-id 事后关联 security_events（P0-08 未实现，
   禁止形态仍是现状）；
2. **纯 ALLOW 无请求级记录**：全量溯源需借助 access_logs，而 access_logs 与
   API 域无关联键（request_id 未贯通）；
3. **Event→Object 无对象维度列**：对象标识只在事件证据扩展中，无独立列可聚合；
4. **Event→SensitiveData 非结构化**：经 findings/弱点证据摘要间接可达，
   无字段级直接外键；
5. **主体审计单维**：见第四节；
6. **未实现项**：数据审计（任务书 §87）、流向图（§90）、离线审计任务（§91）。

## 七、关键设计决策

1. **响应后输出优先于字段完备**：API 放行流量事件延迟到响应完成后输出，
   换取真实状态码/时延/响应侧 findings；阻断类保持即时输出（审计时延敏感场景
   本就已被拒绝，无响应可等）；
2. **NULL 优于 0**：旧版网关缺字段一律落 NULL，宁可"未知"不可"伪造准确值"；
3. **幂等先行**：request_id 幂等 + dedup_fingerprint 幂等，采集器重放/重复上报
   静默去重而非产生重复审计行；
4. **明文最小开口**：全链只开 client_ip 一个明文审计列，其余一律指纹/摘要；
5. **审计写入不阻断业务**：事件输出、findings 物化失败仅告警，不影响请求主流程
   （与采集器既有纪律一致；操作审计则为管理面同步链路，失败如实返回）。

## 八、与任务书对应章节

- 补全任务书 §231（审计溯源文档口径）：本文档；
- 补全任务书 §86-91（主体/数据/请求级审计、查看原值、流向图、离线审计）：
  第四~六节；
- 补全任务书 §213（溯源链）：第六节；
- 现状盘点：docs/API_SECURITY_CURRENT_STATE.md P0-20 / P0-21；
- 相邻文档：docs/AUDIT_DESIGN.md（管理面操作审计总体设计）、
  docs/API_RISK_WEAKNESS.md（事件→风险→弱点链路）、
  docs/API_RESPONSE_SECURITY.md（响应侧事件与脱敏执行）。
