# API 授权分析设计（BOLA / BFLA 辅助，阶段8 / WDSP）

## 一、目的与范围

本文档描述阶段8 对象级授权风险分析（BOLA / BFLA 辅助检测）的实现：归一化路径中的
对象段识别、无凭据对象访问检测规则与升档规则、`api_object_models` 表结构。

遵循任务书第四十章的底线约束：**不得仅因访问不同对象 ID 就直接确认 BOLA**。
实现因此定位为"辅助信号"——对象段 + 无凭据 + 连续枚举行为特征，输出风险结论与证据，
供统一决策与人工研判，不做越权终局认定。

覆盖代码：`gateway/dynamic_security/detectors/resource.go`（对象访问检测）、
`gateway/dynamic_security/normalizer/path.go`（对象段归一化来源）、
迁移 000018 `api_object_models`。

## 二、架构与数据流

```text
parser.ParseRequest
  │  NormalizedPath（normalizer.NormalizePath：数字段→{id}、UUID→{uuid}、长hex→{hex}）
  ▼
pipeline.Process（pipeline.go:97）
  ▼
detectors.CheckResourceAccess(ctx, parsed, identity)   （resource.go:42）
  ├─ objectSegment：归一化路径首个对象段 → (类型, 原始值)
  │    无对象段 → 直接返回
  ├─ ctx.SetExtension("api.object_id_type", 类型)       （始终写入）
  ├─ hasCredential（authorization / x-api-key 存在性）→ 有凭据则返回
  └─ 无凭据 → resource.unauthenticated_object_access（OBSERVE/MEDIUM）
       └─ 升档：numeric + 写方法 + 同一 identity+endpoint 连续数字 ID
            → BLOCK 类 / HIGH（sequential_numeric_id）
  ▼
decision.Decide：BLOCK 类 match 在 PROTECT 模式 → ActionBlock（engine.go:62-83）
```

注意该检测器在管线中对全部已解析流量执行（pipeline.go:97），不在 `api.IsAPI`
门控之内——对象段信号对 Web 表单路径同样有效；只有生命周期与写限速检测才限定
API 流量（pipeline.go:98-105）。

## 三、对象段识别

### 3.1 归一化层产出对象段

`normalizer.NormalizePath`（`gateway/dynamic_security/normalizer/path.go:17-56`）
逐段替换动态路径段：

| 段形态 | 正则 | 占位符 |
|--------|------|--------|
| 纯数字 | `^\d+$` | `{id}` |
| UUID | `^[0-9a-f]{8}-...{12}$`（大小写不敏感） | `{uuid}` |
| 长十六进制（≥16 位） | `^[0-9a-f]{16,}$` | `{hex}` |

其余段保持字面量。归一化只认形态不认语义，"10001"是用户 ID 还是订单号不做猜测。

### 3.2 对象类型提取

`objectSegment`（resource.go:83-105）将归一化路径与原始路径按 `/` 对齐切分，
返回**首个**对象段的类型与原始值：`{id}`→`numeric`、`{uuid}`→`uuid`、
`{hex}`→`hex`；无对象段返回空。命中后对象类型始终写入上下文扩展
`api.object_id_type`（resource.go:50），供事件明细与后续消费方使用——即使请求
带有凭据、不产生 match，对象类型事实也保留在上下文中。

## 四、无凭据对象访问检测与升档规则

### 4.1 基础规则

`CheckResourceAccess`（resource.go:42-80）：

- 凭据存在性 `hasCredential`（resource.go:108-114）只看解析层头集合中
  `authorization` / `x-api-key` 键是否存在（值已是 `[redacted]` 标记）；
- 对象段存在且无凭据 → 追加 match：

```text
RuleID:   resource.unauthenticated_object_access
Category: OBSERVE    Severity: MEDIUM    ScoreDelta: 15
Evidence: object_type（numeric/uuid/hex）、method
```

### 4.2 升档规则（连续数字 ID 枚举）

在基础 match 之上，满足全部条件时升档（resource.go:67-78）：

1. 对象类型为 `numeric`；
2. 写方法（`IsWriteMethod`：POST / PUT / PATCH / DELETE，
   `detectors/ratelimit.go:22-29`）；
3. 调用方身份键非空（`IdentityKey`，见 docs/API_IDENTITY_SECURITY.md）；
4. 原始对象 ID 可解析为 int64，且与同一 `identity + endpoint_key` 维度上一次
   记录的对象 ID **紧邻**（`id == prev + 1`，`objectTracker.consecutive`，
   resource.go:27-36）。

升档后：`Category=BLOCK`、`Severity=HIGH`、`ScoreDelta=30`，Evidence 增加
`pattern=sequential_numeric_id`，Message 改为
`sequential numeric object id on write without credential`。

游标实现：包级 `defaultObjectTracker`（resource.go:19），键为
`identity|endpoint_key`，值为上一数字对象 ID，LRU 定容 10000 键
（`objectTrackerMaxKeys`，resource.go:15），与行为滑窗共用同一套进程内 LRU
基础设施（`detectors/window.go`）。决策引擎对 BLOCK 类 match 在 PROTECT 模式下
输出 `ActionBlock`、OBSERVE 模式下降为观察（`decision/engine.go:62-83`）。

## 五、api_object_models 表结构

迁移 000018 第 242-252 行：

| 列 | 说明 |
|----|------|
| `endpoint_id` | 端点，FK 级联删除 |
| `object_segment` | 归一化段位置或参数名 |
| `identifier_type` | 标识符形态：`numeric` / `uuid` / `hash` / `mixed`，默认 `unknown` |
| `example_hash` | 样本哈希（不落明文） |
| `entropy_estimate` | 熵估计（可空） |
| `created_at` / `updated_at` | 时间戳 |

约束：`UNIQUE (endpoint_id, object_segment)`。该表承载任务书第四十章
"对象标识候选"的持久化形态，供后续所有者关系配置与历史访问基线使用。

## 六、关键设计决策

1. **辅助信号，不认定越权**。规则命名与注释明确"不直接认定 BOLA"
   （resource.go:13-14）；检测输出的是"无凭据访问对象"与"连续枚举写"两个
   行为事实，越权结论留给策略与人工。
2. **对象类型始终落上下文**。无论是否有凭据、是否产生 match，
   `api.object_id_type` 都写入扩展——风险分析需要事实而非只有告警。
3. **升档三重收敛**。只有 `numeric + 写方法 + 同身份连续 +1` 才升 BLOCK 类：
   UUID/hex 天然抗枚举不升档，读方法遍历不升档（避免抓取类误伤升级为阻断），
   不同身份的递增不互相污染。
4. **游标定容有界**。对象游标与滑窗同为 LRU 定容（10000 键），防随机键耗尽
   内存，与阶段5 计数器同一纪律。
5. **证据不含对象 ID 明文**。Evidence 只有 `object_type` 与 `method`（升档时加
   `pattern`），连续游标中的 ID 不出进程内存。

## 七、当前实现范围与限制

- **无凭据是唯一凭据维度规则**。当前只检测"带对象段且完全无凭据"的访问；
  有凭据场景的对象级越权（A 用户读 B 用户对象）不做判定——系统不建模对象
  所有者关系，任务书第四十章的所有者关系配置与历史访问基线未实现。
- **连续 id 枚举的跨身份判定在演进中**。游标按 `identity + endpoint` 隔离，
  同一身份换 IP（无凭据时回退 IP 键）即换维度；多身份协同枚举、慢速低频枚举
  （隔天继续 +1）当前识别不到。
- **只取首个对象段**。多对象段路径（如 `/orgs/{id}/users/{id}`）只分析第一个；
  Query / JSON Body 中的对象标识不纳入对象段识别（任务书四十章的 Query 参数、
  JSON 字段候选来源未实现）。
- **api_object_models 仅建表**。对象模型的持久化（段位置、identifier_type、
  熵估计）无写入方与查询接口。
- **BFLA 与字段级越权未实现**。任务书第四十一章的角色-功能偏离、第四十二章的
  只读/管理字段标记与 Mass Assignment 检测均无对应代码；用途分类的
  `PURPOSE=ADMIN` 标签（见 docs/API_CLASSIFICATION_DESIGN.md）是当前唯一的
  功能级信号，未接入检测规则。
- **升档依赖进程内游标**。与滑窗同一单节点限制：多网关部署各节点游标独立，
  进程重启清零（`detectors/window.go:9-12`）。

## 八、与任务书对应章节

- 第四十章（对象标识与 BOLA 辅助检测）：路径变量候选来源、"不得仅因访问不同
  对象 ID 就直接确认 BOLA"的约束落地；枚举检测输出证据与风险等级；
- 第四十一章（BFLA 辅助检测）、第四十二章（字段级越权与 Mass Assignment）：
  当前未实现，见第七节；
- 三十六章（API 维度资源保护）：写方法限速信号见 `detectors/ratelimit.go`，
  与本检测共用身份维度键；
- 第五十章：`api_object_models` 表结构。

Copyright © 聚信得仁
All Rights Reserved.
