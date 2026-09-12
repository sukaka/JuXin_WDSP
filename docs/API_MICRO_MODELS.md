# API 三微模型统一维度框架（阶段8 / WDSP）

## 一、目的与范围

本文档统一「参数微模型 / 身份微模型 / 访问微模型」三个微模型的定位、维度划分与相互
关系，把管理层给出的维度口径与阶段8 现有实现对齐，作为后续模型补全工作的共同依据。

三个微模型共同回答 API 动态防护的核心问题——**这次调用正不正常**：

| 模型 | 回答的问题 | 一句话定位 |
|------|-----------|-----------|
| 参数微模型 | 报文形态对不对 | 以单参数为粒度建立字段形态基线 |
| 身份微模型 | 调用方是谁 | 以凭据为来源归并出可计数的调用者身份 |
| 访问微模型 | 这次访问正不正常 | 以身份为坐标，从环境与对象两个维度评估访问行为 |

与现有设计文档的关系：参数细节见 `docs/API_PARAMETER_MODEL.md`，身份与凭据见
`docs/API_IDENTITY_SECURITY.md`，对象级授权见 `docs/API_AUTHORIZATION_ANALYSIS.md`，
行为基线见 `docs/API_BEHAVIOR_ANALYSIS.md`。本文档只做维度框架的统一与差距盘点，
不重复各模型的内部结构定义。

## 二、统一维度框架

```text
HTTP 请求
  ▼
┌─ 参数微模型（报文形态）────────────────────────────┐
│  URL（PATH）/ Query / Header / Payload（JSON/XML） │
│  → 字段形态基线：类型、长度、值域、枚举、必填、关系   │
└──────────────────────────────────────────────────┘
  ▼
┌─ 身份微模型（调用者是谁）───────────────────────────┐
│  Cookie / Session / Token·JWT·OAuth / API Key      │
│  → 身份指纹（不落明文）→ 归并维度：用户              │
└──────────────────────────────────────────────────┘
  ▼
┌─ 访问微模型（访问行为是否正常）─────────────────────┐
│  环境维度：IP / 地理位置 / UA / 访问流量 / 访问时间   │
│  对象维度：身份 × 对象标识（BOLA 辅助）              │
└──────────────────────────────────────────────────┘
  ▼
decision.Decide 统一决策（检测器只产出信号，不各自定案）
```

### 2.1 参数微模型维度

管理层口径与实现完全对应（任务书第十三章通用参数标识）：

| 管理层维度 | 实现承载 | 说明 |
|-----------|---------|------|
| URL | `location=PATH` + 归一化路径段 | 数字/UUID/hex 段归一化为占位符 |
| Query 参数 | `location=QUERY` | 直接用解析值参与约束检测 |
| Header 头 | `location=HEADER` | 同上 |
| Json/XML 等格式 Payload | `location=BODY` + `structured_path` | 点路径精确到嵌套字段（如 `user.address.tel`） |

字段形态基线沿三层约束运转：observed（观测事实）→ recommended（系统建议）→
confirmed（人工定案，检测依据）；约束词汇钉死为 `min_length` / `max_length` /
`minimum` / `maximum` / `enum`。纪律不变：**字段名只是数据**，不对具体字段名
写死业务规则；观测值永远不直接成为阻断依据。

### 2.2 身份微模型维度

管理层口径为全谱系凭据，当前实现覆盖 API 凭据并已补齐 Cookie 存在性维度
（第一批，2026-08），Session 画像仍为明确差距：

| 管理层维度 | 实现现状 | 说明 |
|-----------|---------|------|
| Token / JWT / OAuth | 部分实现 | `Authorization` 头存在性、scheme 白名单、弱凭据规则（OBSERVE 级）；JWT 结构解析未实现 |
| Cookie | 部分实现 | `identity.cookie_present` 存在性信号（INFO）+ `sess:` 指纹 + `cookie_session` 认证类型；完整性/有效性校验未实现 |
| Session | 部分实现 | `sess:` 指纹随运行时事件落库；会话画像（`api_identity_profiles` 写入）未实现 |
| 用户 | 部分实现 | CredentialKey（仅凭据派生）产出身份指纹并随事件落库；TrackingKey 服务进程内计数 |
| （API Key） | 已实现 | `X-API-Key` 存在性与弱凭据规则 |

身份微模型的输出是一个东西：**身份指纹**（不可逆、不落明文），它同时是访问微模型
两个维度的聚合坐标。补齐 Cookie/Session 维度时沿用同一纪律——只取存在性与指纹，
任何凭据明文不出解析层。

**边界规则（全模型通用）**：IP 属于访问微模型的环境维度，**身份维度只由凭据
派生**。无凭据流量的身份一律记为"匿名"，不得以 IP 冒充身份——NAT/出口代理会把大量
用户折叠成一个"身份"，污染行为基线与对象访问判定。该规则已落地（第一批，
2026-08）：旧 `IdentityKey` 的 IP 回退写法拆分为 `CredentialKey`（仅凭据派生，
匿名为空串）与 `TrackingKey`（无凭据回退 IP，仅供滑窗计数，不进事件与画像）。

### 2.3 访问微模型维度

访问微模型由两个互补子维度构成，缺一不可：

**环境维度**（管理层口径：访问异常与账号接管检出面）：

| 维度 | 回答 | 实现现状 |
|------|------|---------|
| IP | 从哪来 | 已有（访问日志/事件均含 client_ip）；同凭据跨 IP 跳变信号已落地（第二批 `auth.credential_ip_spread`，OBSERVE 级） |
| 地理位置 | 是否异地 | 大屏可视化已有离线 GeoIP（国家级）；检测侧未接入 |
| UA | 客户端是否突变 | 事件含 user_agent_summary；无基线比对 |
| 访问流量 | 速率是否异常 | 已实现：RATE_SPIKE 相对基线突增 + API 写限速固定上限 |
| 访问时间 | 时段是否异常 | 部分实现：管理面离线画像已落地（第二批：`api_behavior_profiles.hour_dist` 时段分布，aggregations 任务写入）；时段异常的实时检测信号未接入 |

**对象维度**（现有实现口径：BOLA 辅助检测面）：

| 维度 | 回答 | 实现现状 |
|------|------|---------|
| 对象标识 | 碰的是哪类对象 | 已实现：路径多对象段逐段识别 + Query 参数值形态识别（numeric/uuid/hex，第二批）；Body 字段留待 semantic_type 联动 |
| 身份 × 对象 | 该不该碰 | 部分实现：无凭据访问对象 OBSERVE；同身份连续 +1 枚举写升 BLOCK；所有者关系未建模 |

纪律不变：**不得仅因访问不同对象 ID 就认定 BOLA**——访问微模型输出行为事实与
风险证据，终局结论留给策略与人工研判。

## 三、模型间关系

1. **身份是坐标系**。没有身份指纹，环境基线（"他平时从哪来"）和对象判定
   （"他该不该碰"）都没有聚合主体；身份微模型是另外两个模型的前置依赖。
2. **参数反哺访问**。参数微模型的 `semantic_type`（id 类语义）可作为对象标识的
   候选来源，把对象识别从路径段扩展到 Query 参数与 JSON 字段。
3. **环境强化身份与访问**。同凭据地理位置跳变、UA 突变既是身份异常信号（凭据
   可能被盗用），也是访问异常信号（账号接管），两个模型消费同一份环境事实。
4. **统一决策**。三个模型的检测器一律只 AddMatch，动作由 `decision.Decide`
   按防护模式统一输出，禁止任何微模型自行定案（任务书 2.4）。

## 四、现状差距与演进建议（按优先级）

| # | 事项 | 所属模型 | 现状 | 建议 |
|---|------|---------|------|------|
| 1 | 身份指纹进运行时事件 | 身份 | ✅ 已完成（第一批，2026-08） | 已落地：`apievents.Record` 携带 `identity_fingerprint` + `auth_type`，迁移 000029 落库，事件列表支持 `identity_fingerprint` 过滤 |
| 2 | 指纹算法升级 | 身份 | ✅ 已完成（第一批，2026-08） | 已落地：统一 `detectors.Fingerprint`（HMAC-SHA256 截断 16 字节 hex），盐取自 `identity_salt` 配置（fingerprint.go） |
| 3 | Cookie/Session 身份维度 | 身份 | ✅ 已完成（第一批，2026-08） | 已落地：`identity.cookie_present` 信号、`sess:` 指纹、`cookie_session` 认证类型；会话画像与完整性校验留后续批次 |
| 4 | IP 与身份解耦 | 身份/访问 | ✅ 已完成（第一批，2026-08） | 已落地：CredentialKey（仅凭据）/ TrackingKey（IP 回退仅供计数）分离（authentication.go:163/182，见 2.2 边界规则） |
| 5 | 参数统计画像写入方 | 参数 | ✅ 已完成（第二批，2026-08） | 已落地：`apimodels.Store.RefreshParameterStatistics`（learningjobs 每轮 Sweep 后触发）聚合 accepted 学习样本 UPSERT `api_parameter_statistics`（sample_count/example_hashes），并按样本量分级自动生成 observed/recommended（<100 不生成、100–999 上限×2、≥1000 收紧 P95、enum 护栏 distinct≤20 且样本≥100）；长度/值域/基数因参数值不出网关无真实数据源，保持 NULL 待值观测通路 |
| 6 | 访问时间基线 | 访问（环境） | ✅ 已完成（第二批，2026-08） | 已落地：`aggregations` 离线画像任务按 endpoint × 身份 × 3600s 窗口聚合 `api_runtime_events`（request_count/avg_rate/status_code_dist + `hour_dist` UTC 小时桶时段分布按 24h 回看，迁移 000030），`GET /api/v1/api-security/behavior-profiles` 只读查询（`api_runtime.read`）；时段异常实时检测信号留后续批次 |
| 7 | 同凭据跨 IP / 并发度异常 | 访问（环境）+身份 | ✅ 已完成（第二批，2026-08） | 已落地：网关新检测器 `envanomaly.go`——`auth.credential_ip_spread`（同凭据滑窗 distinct IP≥3，OBSERVE/MEDIUM/+15，证据只含 distinct 数与窗口）与 `auth.credential_concurrency`（同凭据并发≥8，OBSERVE/LOW/+10）；仅凭据维度聚合、匿名跳过，阈值可配（`credential_ip_spread_limit` / `credential_concurrency_limit`） |
| 8 | 对象标识来源扩展 | 访问（对象） | ✅ 已完成（第二批，2026-08；Body 留待 semantic_type 联动） | 已落地：`resource.go` 多对象段逐段评估（游标键含段位置），Query 参数值形态识别（数字/UUID/长 hex）产出对象访问信号（证据 source=query/param 名，值不入证据）；JSON Body 字段经参数 `semantic_type` 联动留后续批次 |
| 9 | 滑窗/游标 Valkey 化 | 三个模型共用 | ✅ 已完成（第三批，2026-08） | 已落地：`detectors/store.go` 可插拔存储接口（WindowStore/ObjectCursorStore/IPSpreadStore/ConcurrencyStore + StoreOverrides 注入）与 Valkey 实现 `jiuzhang_guard/behaviorstore`（Lua 原子计数、键 `jiuzhang:guard:api:<ns>:<sha256截断>`、TTL 下限、Fail-open 降级内存并 Warn 节流），多节点共享基线路径已通；Valkey 为可选存储，配置 `behavior_store`（memory\|valkey）**默认 memory**，默认内存实现零变化 |
| 10 | 模型成熟度状态机 | 三个模型共用 | ✅ 已完成（第三批，2026-08） | 已落地：`GET /api/v1/api-security/model-maturity`（`api_runtime.read`，`server/internal/apisecurity/maturity.go`）按真实表计数推导四模型 LEARNING → CANDIDATE → CONFIRMED → ENFORCING（+ metrics + 中文 summary）；管理面页面「模型成熟度」`/api-model-maturity`（API 防护分组，`api_runtime.read` + WDSP 能力门控） |
| 11 | 参数值观测通路 | 参数 | ✅ 已完成（增强批，2026-08） | 网关 `CollectParamObservations`（length/hash/num，无明文）→ 事件 JSONL → `api_parameter_value_obs` → `RefreshParameterStatistics` 回填 statistics → recommended 可产；PATH/COOKIE 约束消费；`semantic_type` 启发式推断；关系 CO_OCCURS 候选；批量确认 `POST .../parameters/confirm-batch` |
| 12 | 身份画像与质量分 | 身份 | ✅ 已完成（增强批，2026-08） | `aggregations.RunIdentityProfiles` UPSERT `api_identity_profiles`；`GET /api-security/identity-profiles`（质量分 0–100）；JWT 结构级信号（alg=none/kid 穿越/空签名/exp，均 OBSERVE） |
| 13 | 环境异常扩展 | 访问（环境） | ✅ 已完成（增强批，2026-08） | 进程内时段基线 `auth.credential_unusual_hour`、UA 族突变 `auth.credential_ua_change`、多信号叠加 `auth.env_anomaly_stack`；对象维度 BODY 经 `semantic_type` 联动 |
| 14 | 多节点行为存储 | 访问 | ✅ 可选（第三批） | 生产多网关建议 `behavior_store=valkey`（默认 memory） |

## 五、与任务书对应章节

- 第十三至二十一章（参数标识与各类参数微模型）：2.1 节维度对应；
- 第三十五章（API 身份与凭据模型）：2.2 节；Cookie/Session 为超出当前实现的
  扩展维度；
- 第三十六章（API 维度资源保护）、四十三章（业务行为学习）：2.3 节环境维度；
- 第四十至四十二章（BOLA/BFLA/字段级越权）：2.3 节对象维度；
- 2.4（统一决策）、7.1（数据最小化）：全模型通用纪律；
- 第五十章（表结构）：`api_parameter_models` / `api_identity_profiles` /
  `api_behavior_profiles` / `api_object_models`；
- 第五十二章（权限与审计）：写操作全量审计纪律不变。

Copyright © 聚信得仁
All Rights Reserved.
