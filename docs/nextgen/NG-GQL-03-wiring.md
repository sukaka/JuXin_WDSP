# NG-GQL-03 GraphQL 成本预算链路（管理面 → 发布 → pipeline 执行 → OBSERVE/PROTECT）

状态：已上线（2026-10-04，S2 首批）。本文是链路事实源：链路图、配置契约、失败分流映射、
覆盖口径、E2E 证据摘录。算法事实源见 `NG-GQL-02-cost-model.md`（gqlast 包）；本文不重复公式。

## 1. 链路图

```
管理面 PUT/GET/DELETE /api/v1/api-security/apps/{id}/graphql-policy
  → api_graphql_policies 表（迁移 000171，按应用一行；无行=关闭）
  → 发布链 guardconfig.loadAPIGraphQL（fail-hard；enabled 行 → GuardConfig.api_graphql）
  → 按应用注入 handler JSON api_graphql.policies.<application_id>（WDSP 门控，
    stripAPIGuardSections 回滚剥除；内容纳入 api_policy_version 版本戳）
  → 网关 Provision 编译（fail-safe：空键跳过/超 64MiB 归零 Warn，不拒载）
  → serveNext 装配 pipeline.Config.GraphQL（按 g.AppID 解析）
  → pipeline.checkGraphQL（Admission 短路之后、统一决策之前）：
      parser 识别（application/graphql 或 /graphql JSON 含 query；文档原文入
        Parsed.GraphQLQuery，仅请求内存活）
      → gqlast.ParseBounded（五道硬边界 64KiB/深度20/节点10000/alias100/fragment循环）
      → gqlast.SelectOperation（NG-T-G01 只算被选定 operation；
        按客户端显式 operationName——推断名不得冒充指定，
        parser.GraphQLOperationNameSpecified 字段承载）
      → trusted_doc_digests 命中直通（免成本判定，照常解析与操作选择）
      → CostOfCached（LRU 键=文档摘要+noschema-v1+api_policy_version）
      → 单请求预算 → 时间窗预算（app+tenant 定窗累计，匿名独立桶）
  → decision 定案（category=BLOCK 取得阻断资格）
  → guard BLOCK 分支：GraphQL 协议错误语义 JSON（非 WAF HTML 阻断页）
```

## 2. 配置契约（管理 API 与发布 payload 同构）

| 字段 | 类型 | 默认（0 值语义） | 校验 |
|---|---|---|---|
| `enabled` | bool | false（关闭，全链零行为） | — |
| `limits.max_doc_bytes` | int | 65536 | 0..64MiB（超 64MiB 网关归零走默认） |
| `limits.max_depth` | int | 20 | ≥0 |
| `limits.max_nodes` | int | 10000 | ≥0 |
| `limits.max_aliases` | int | 100 | ≥0 |
| `limits.max_fragment_exp` | int | 1000 | ≥0 |
| `weights.default_field_weight` | int64 | 1 | 0..2^40 |
| `weights.default_list_bound` | int64 | 100 | 0..2^40 |
| `weights.introspection_weight` | int64 | 50 | 0..2^40 |
| `weights.fields.<path>` | object | 无覆盖 | 键 ≤128 字符（`Type.field` 或 `*.field`），≤4096 条；weight/list_bound ≥0 |
| `budget.per_request_budget` | int64 | 5000 | 0..2^40 |
| `budget.window_seconds` | int64 | 60 | 0..2^40 |
| `budget.window_budget` | int64 | 100000 | 0..2^40（具名主体桶） |
| `budget.anonymous_budget` | int64 | 20000 | 0..2^40（匿名独立桶） |
| `trusted_doc_digests[]` | string[] | 空 | 32 位小写 hex（gqlast.DigestDocument 规范化 sha256 前 16 字节），≤1024 条 |

版本与生效：`version` 单调 +1（PUT）；策略经整站发布链生效（管理端点不隐式发布）；
内容纳入 `api_policy_version` 版本戳（omitempty：未下发时与旧版本逐字节一致）；
回滚覆盖快照经 `stripAPIGuardSections` 剥除（WDSP 门控同 api_admission 段）。

## 3. 失败分流映射（NG-T-G06）

| 触发 | reason（evidence.reason / 响应 extensions.code） | OBSERVE | PROTECT |
|---|---|---|---|
| 语法错误 / 多 operation 未命名 / operationName 不存在 / 无 operation / 超五道硬边界 | `GQL_ADMISSION_REJECTED` | category=OBSERVE finding（rule_id=gql.admission，evidence.error_kind 分类） | category=BLOCK → 403 GraphQL 协议错误 JSON |
| 单请求成本超预算 | `GQL_COST_EXCEEDED` | 同上（rule_id=gql.cost_v1，evidence cost/budget/operation_kind） | category=BLOCK → 403 同上 |
| 时间窗预算超限（app+tenant 定窗） | `GQL_WINDOW_EXCEEDED` | 同上（rule_id=gql.window，evidence cost=窗内累计/budget=窗限） | category=BLOCK → 403 同上 |
| trusted_doc_digests 命中 | `GQL_TRUSTED_DOC` | category=OBSERVE（rule_id=gql.trusted_doc），免成本判定直通 | 同左（直通） |

- 阻断响应（guard 直接写出，committed）：HTTP 403 + `application/json` +
  `{"errors":[{"message":"GraphQL request rejected by protection policy","extensions":{"code":<reason>,"request_id":<id>}}]}`；
  message 通用文案不泄露成本细节，reason 经 extensions.code 传递（防探测与可排障平衡）。
- 证据脱敏：evidence 仅 cost/budget/reason/operation_kind/error_kind，绝不含查询文本/变量值。
- 决策资格：graphql 检测器 PROTECT 一律 category=BLOCK（决策引擎 cat==BLOCK 即阻断资格，
  不依赖可信源名单）；EXCEPTED（受限例外）明细不驱动响应 reason。

## 4. 覆盖观测口径（NG-COV-01）

每个 **GraphQL 分类**请求一条 `detector="graphql.cost_v1"` 记录（非 GraphQL 请求不产生——
避免噪音洪流；app 无策略段时管线本体零行为变化，覆盖记录仅在覆盖功能开启时存在）：

| 情形 | status | reason_code |
|---|---|---|
| 策略 nil/disabled | SKIPPED | COV_DISABLED |
| 完成（放行/trusted/预算判定完成） | FULL | — |
| 超五道硬边界 | PARTIAL | COV_INPUT_TRUNCATED（truncated=true） |
| 语法/操作选择类失败 | PARTIAL | COV_PARSE_ERROR |

`scope.bytes` = 查询文档字节数（如实范围，不夸大）。

## 5. 时间窗预算状态（本批边界）

- 键：`application_id|tenant`（tenant=凭据指纹（detectors.CredentialKey 同口径脱敏）或
  `anonymous` 独立桶，预算分别取 window_budget/anonymous_budget）。
- 语义：**定窗累计**（windowSeconds 对齐自然边界滚动；本批口径，非令牌桶平滑）。
- 状态通道：`pipeline.WindowBudgetStore` 接口 + 进程内实现（本批默认形态）。
  Valkey 注入点保留（GraphQLPolicy.WindowStore）——detectors StoreOverrides 的窗口原语
  为计数型（AddAndCount），不适配 token/cost 型累计，接入留后续批次；
  进程内形态不标 COV_DEPENDENCY_UNAVAILABLE（它是本批规定默认而非故障降级；
  未来 Valkey 配置后不可用回退内存时按「不静默降级」如实标记）。

## 6. E2E 证据摘录（stage5，2026-10-04）

| 场景 | 结果 |
|---|---|
| 默认（无策略段） | `HTTP/1.1 404` + `X-Wdsp-Origin-Mark: jiuzhang-test-origin`（到达源站，零行为） |
| OBSERVE（per_request=5，cost 9） | 404+origin mark（放行）；事件 `OBSERVE category=OBSERVE reason=GQL_COST_EXCEEDED`；coverage agg `graphql.cost_v1 FULL=1` |
| PROTECT 同查询 | 403 `{"errors":[{"extensions":{"code":"GQL_COST_EXCEEDED",...},"message":"GraphQL request rejected by protection policy"}]}`，**无 origin mark（未到达源站）** |
| 多 operation 未命名 PROTECT | 403 `extensions.code=GQL_ADMISSION_REJECTED`；OBSERVE 下放行，事件 `gql.admission kind=MULTIPLE_OPERATIONS` |
| trusted digest 登记后 PROTECT | 同文档 404+origin mark（放行）；白名单外变体仍 403 GQL_COST_EXCEEDED |
| 时间窗（anonymous=20，cost 9/发） | 新窗 req1 PASS（9）req2 PASS（18）req3 `GQL_WINDOW_EXCEEDED`（27>20） |

清理：策略行删除、模式恢复现场（settings api_protection.mode 保持测试前既有 PROTECT）、
复测零行为（404+origin mark）。回归：stage5-gateway-tests 40/40、custom-pack-blocking 13/13、
dynamic_security 16 包、jiuzhang_guard、server 相关包全绿；OpenAPI 对账 678 双向零差集。
