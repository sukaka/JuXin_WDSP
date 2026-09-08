# API Schema 防护设计（阶段8 / WDSP）

## 一、目的与范围

Schema 防护以**人工确认后冻结的正式模型**为基准，对运行期请求做偏离检测：
请求结构偏离正式模型即产生检测明细，由统一决策引擎按当前防护模式决定放行、
观察或阻断。本文覆盖：

- 冻结正式模型的载体与下发链路；
- 偏离检测三规则及其类别/分值（`gateway/dynamic_security/detectors/schema.go`）；
- 防护模式（OFF/OBSERVE/PROTECT）与阻断语义；
- PROTECT 下敏感 Query 参数的阻断（`detectors/sensitive.go`）；
- 违例的记录与查询。

模型版本体系（候选→确认→冻结）见 `docs/API_MODEL_VERSIONING.md`；统一决策见
`docs/UNIFIED_DYNAMIC_SECURITY_ARCHITECTURE.md` §2.2。

## 二、冻结正式模型与下发链路

正式模型在运行期的载体是一张**字段类型表**：

```text
api_formal_schemas: endpoint_key → { 字段路径 → 期望粗类型 }
  例： "POST /v1/orders" → { "amount": "number", "buyer.name": "string",
                              "items[]": "array", "items[].sku": "string" }
```

字段路径与粗类型词表来自一次解析器（`.` 连接的嵌套路径、`[]` 数组元素、
`string|number|bool|object|array|null`，`parser/parse.go:218-265`）；
模型的确认、冻结、版本化在管理面完成（`server/internal/apimodels/`）。

下发链路：

```text
apimodels.ListFormalSchemas（store.go:497-520）
  │  SELECT DISTINCT ON (endpoint_key) ... WHERE status='FORMAL'
  │  （同一键多 FORMAL 取最近确认者；正常 Confirm 流程至多一个）
  ▼
guardconfig.Provider.BuildGuardConfig（provider.go:302-310）
  │  仅 API 动态防护开启时注入；下发失败则发布失败，不带病发布
  ▼
gatewayconfig.buildGuardHandler → Caddy JSON "api_formal_schemas"
  （guard.go:137-139；配置快照随 access_control_versions 版本化，可回滚）
  ▼
guard 运行时 Guard.APIFormalSchemas（module.go:131）
  ▼
serveNext → runAPIProtection：ek = EndpointKey(method, path)
  cfg.FormalSchema = g.APIFormalSchemas[ek]（apiprotect.go:68-74）
```

模型更新与发布语义一致：确认/激活新模型后需触发配置发布，网关重载后生效；
发布失败不影响当前有效配置（沿用阶段3 起的发布纪律）。

## 三、偏离检测三规则

`CheckSchemaDeviation`（`detectors/schema.go:12-56`）对比「本次请求解析出的
JSON 字段类型表」与「冻结正式模型」：

| 规则 | RuleID | Category | Severity | Δ分 | 含义 |
|------|--------|----------|----------|-----|------|
| 未定义字段 | `schema.undefined_field` | OBSERVE | MEDIUM | +15 | 请求出现正式模型没有的字段 |
| 类型不匹配 | `schema.type_mismatch` | BLOCK | HIGH | +40 | 同名字段粗类型与模型不一致 |
| 缺失字段 | `schema.missing_field` | OBSERVE | LOW | +5 | 正式模型中的字段本次未出现 |

判定细节：

- 比对仅基于字段名/路径与粗类型，**不比较字段值**（数据最小化）；
- 正式模型中类型为空的字段只做存在性约束，不做类型约束（`schema.go:30`）；
- 偏离只产生 `DetectorMatch`（detector=`api_schema`），**不修改正式模型**——
  偏离流量永远不会反向扩大模型（任务书 §2.6，`schema.go:11`）；
- 请求体被截断（`BodyTruncated`）时不做字段级遍历（`parse.go:133-137`），
  截断请求不参与偏离比对，避免半个 Schema 造成误报。

## 四、决策与防护模式

防护模式三态（`decision/engine.go:13-17`），来源优先级
`settings 表覆盖 > 环境变量 API_PROTECTION_MODE > 内置默认 OBSERVE`
（`apisecurity/policy.go:95-113`、`guardconfig/provider.go:113-120`）：

| 模式 | 语义 |
|------|------|
| OFF | 引擎不产出任何动作，恒 ALLOW（`engine.go:33-36`） |
| OBSERVE | 全部检测照常执行、事件照常输出，BLOCK 类命中降级为 OBSERVE，不拦截（`engine.go:83-84`） |
| PROTECT | BLOCK 类命中映射为最终 BLOCK，网关返回 403（`engine.go:81-82`、`apiprotect.go:95-96`） |

三条偏离规则进入决策引擎后的效果：

- `type_mismatch`（Category=BLOCK、Severity=HIGH、Δ40）：
  PROTECT 下单独即可定 BLOCK；OBSERVE 下记录为 OBSERVE；
- `undefined_field`（OBSERVE/MEDIUM/Δ15）与 `missing_field`（OBSERVE/LOW/Δ5）：
  任意模式下最终动作都是 OBSERVE 级，不直接阻断；其分值会累入 `RiskScore`
  影响风险等级展示（`context.go:154-157`），但**动作判定是逐条明细进行的**
  （`engine.go:50-71`）：只有某条明细自身构成 BLOCK 类条件（Category=BLOCK、
  Severity=CRITICAL/HIGH 或单条 `ScoreDelta≥50`）才会升级为 BLOCK，
  多条低分明细的分值累加不会抬升最终动作。

guard 侧动作映射：`BLOCK→403`、`RATE_LIMIT→429`、`TEMP_BLOCK→403`
（`apiprotect.go:94-103`）；响应不带内部规则细节。

启用但模式未配置时按 OBSERVE（fail-safe，`apiprotect.go:37-44`）；
模式白名单在 guard `Validate`（`module.go:395-401`）、发布组装
（`provider.go:109`）、策略接口（`policy.go:26`）三处一致校验。

## 五、PROTECT 下的敏感 Query 阻断

与 Schema 偏离并列、同属 PROTECT 可阻断语义的还有敏感字段检测
（`detectors/sensitive.go`）。该检测**只匹配字段名/路径，不触碰字段值**：

| 规则 | 位置 | Category | Severity | Δ分 | 说明 |
|------|------|----------|----------|-----|------|
| `sensitive.in_query` | URL Query 键名 | BLOCK | HIGH | +40 | 敏感参数出现在 URL 明文（会进代理日志/浏览器历史），PROTECT 下 403 |
| `sensitive.field` | JSON/Form/XML 字段名 | OBSERVE | MEDIUM | +10 | 敏感字段出现（本身合法，记录画像） |

内置字段名模式（`sensitive.go:28-34`）覆盖 phone/email/id_card/bank_card/
credential 五类中英文常见命名，短关键字（tel/pan/sfz）加非字母边界防误命中
（hotel/company）；单请求敏感明细上限 20 条防超大报文撑爆事件
（`sensitive.go:37`）。模式表可经 `pipeline.Config.SensitivePatterns` 替换，
编译失败视为配置错误返回（不静默吞错，`pipeline.go:91-94`）。

## 六、违例记录与查询

- 运行期：所有偏离/敏感明细随统一主事件写入 `api_runtime_events.details_json`
  （同一 Request ID 一个主事件，按 request_id 幂等，`apiruntime/events.go:25-44`）；
  查询接口 `GET /api/v1/api-security/runtime/events`（按 endpoint_key/
  final_action 过滤，`apisecurity/runtime.go:348-391`）。
- 专项违例表 `api_schema_violations`（字段：violation_type/field_path/expected/
  observed/action_taken，迁移 000018）已有生产写入方（P0-2）：采集器 ETL 把
  schema 类检测明细（`detector=api_schema`，含偏离三规则与参数约束四规则）
  映射为违例行（`server/internal/apiruntime/violations.go`，request_id 幂等），
  查询接口 `GET /api/v1/api-security/violations` 直接可用。

## 七、关键设计决策

1. **基准只能是冻结模型**。`FormalSchema` 只来自 status=FORMAL 的版本，
   候选/评审中版本不下发、不参与比对（`store.go:497-501`）。运行时检测基准
   永远是人确认过的，不是机器刚学到的（任务书 §2.6）。
2. **偏离只观测、不扩模**。`CheckSchemaDeviation` 没有任何写模型的路径；
   模型变更只能走「新候选 → 人工确认 → 发布」闭环（`apimodels/store.go:126-199`）。
   攻击者持续发送异常请求不会改变防护基准。
3. **三规则而非全量校验**。偏离检测聚焦「多了什么、类型对不对、少了什么」三类
   最高信噪比信号；长度/数值范围/枚举等细粒度约束由参数模型
   （`api_parameter_models`）承载，经 `api_parameter_constraints` 下发字段由
   `CheckParamConstraints` 消费（P0-2 已接通，见第八节）。
4. **缺失字段只记 LOW**。可选参数与稀疏调用是 API 常态，缺失不等于异常；
   真正高危的是「多出来的字段」（Mass Assignment 面）与「类型被换掉」，
   分别给 MEDIUM 与 BLOCK。
5. **敏感 Query 可阻断、敏感字段只观察**。URL 明文外泄有确定的泄露面
   （日志/历史/Referer），阻断收益明确；请求体内出现 password 字段是正常业务，
   只画像不拦截。
6. **模式 fail-safe 默认 OBSERVE**。新模式上线先观察后防护，避免误阻断业务；
   OFF/OBSERVE/PROTECT 全部经发布通道下发，与配置版本一同回滚。

## 八、当前实现范围与限制

对照任务书 §32 的 19 类偏离检测：

1. **Schema 偏离三类**（`CheckSchemaDeviation`）：undefined_field / type_mismatch /
   missing_field，**仅覆盖请求 JSON 体**；Query/Header/Cookie/Form/XML 参数不参与
   正式模型比对（表单/XML 字段已解析入 `Parsed`，比对器尚未消费）。
2. **参数级确认约束（P0-2 已接通）**：`min_length`/`max_length`、`minimum`/`maximum`、
   `enum` 与参数 `required` 经发布通道下发网关 `CheckParamConstraints`；
   格式（正则/语义类型）、NULL/空值、数组元素数、对象字段数、嵌套深度、动态 Key、
   文件类型、请求 Content-Type、响应 Schema、响应敏感字段新增、未定义状态码仍未实现；
   `MASK_RESPONSE` 动作已定义无生产者。
3. **必填语义双轨**：`missing_field` 仍把正式模型全部字段视为应出现（粗化）；
   参数模型 `required` 列已由参数约束检测消费（`schema.param_required`，OBSERVE/LOW）。
4. **违例专项表已接通 ETL**（`apiruntime.SaveSchemaViolations`）；`api_runtime_findings`
   的 SCHEMA_DEVIATION 条目仍依赖独立 findings 链路。
5. **响应侧未覆盖**：响应 Schema 与响应敏感数据检测依赖响应解析挂点，
   当前管线只处理请求。
6. **比对粒度为粗类型**：`number` 不区分整数/浮点与精度，`string` 不含长度与
   字符集；类型词表与解析器一致（六种+unknown）。

## 九、与任务书章节对应

| 本文章节 | 任务书 |
|----------|--------|
| 二、下发链路 | §四十七 统一策略模型（模型随发布下发） |
| 三、三规则 | §三十二 Schema偏离检测（裁剪子集） |
| 四、防护模式 | §四十五 统一风险决策、§51.6 策略接口 |
| 五、敏感 Query | §三十七 敏感数据识别（请求侧子集） |
| 六、违例记录 | §四十六 统一事件中心、§51.6 风险运行时 |
| 七、决策 1/2 | §2.6 动态学习不等于自动放宽、§三十 人工确认与冻结 |

---

Copyright © 聚信得仁
All Rights Reserved.
