# S2 GraphQL 语义与资源预算：出口记录（2026-10-04）

> 依据：RD_PLAN §7 与 NG-S1-TASKBOOK 同规格出口口径。结论：**S2 三任务全部闭环，首批 GraphQL 能力已具备**（HTTP query/mutation；订阅/WebSocket/multipart/联邦按 §7.3 边界明示未实现）。
> 详细证据：docs/nextgen/NG-GQL-01-library-eval.md、NG-GQL-02-cost-model.md、NG-GQL-03-wiring.md 及各包测试。

## 任务闭环

| 任务 | 交付 | 证据 |
|---|---|---|
| NG-GQL-01 库评估/AST/操作选择 | gqlparser v2.5.60（MIT 锁定）+ `gqlast` 五道硬边界（64KiB/深度20/alias100/节点10000/fragment循环）+ 操作选择四分支 | 13 单测；fuzz 889k execs 零崩；license-audit 通过 |
| NG-GQL-02 成本预算 | 冻结设计 D1-D11（response-key 合并/列表上界/饱和不绕回/三预算分离/版本化缓存键）+ `CostOf`/`CostOfCached`/`DigestDocument` | 11 黄金样本全过（手算锚定/合并/内省/饱和/缓存版本） |
| NG-GQL-03 配置/证据/执行接线 | per-app `graphql-policy`（迁移 000171 + 管理 API + 版本戳 + OpenAPI 678 零差集）→ pipeline `checkGraphQL` → 失败四分流（GQL_ADMISSION_REJECTED / GQL_COST_EXCEEDED / GQL_WINDOW_EXCEEDED / GQL_TRUSTED_DOC） | pipeline 9 例 + guard 7 例 + apigql 真实 PG 6/6；stage5 E2E 六步全过（见下） |

## stage5 E2E 证据（原样摘录）

- 默认（无策略段）：GraphQL 查询到达源站（origin mark），零行为；
- OBSERVE：大成本放行 + 事件 `GQL_COST_EXCEEDED` 拟动作 + coverage agg 有 `graphql.cost_v1` 行；
- PROTECT：403 `application/json` `{"errors":[{"extensions":{"code":"GQL_COST_EXCEEDED",...}}]}`（**非 WAF HTML 阻断页**），源站记录=0 新增（未到达）；
- 多 operation 未命名：PROTECT `GQL_ADMISSION_REJECTED`；OBSERVE 放行仅记录（kind=MULTIPLE_OPERATIONS）；
- trusted digest：PROTECT 下白名单内文档放行、变体仍 403；
- 时间窗：匿名独立桶连续超成本请求累计触发 `GQL_WINDOW_EXCEEDED`；
- 回归：stage5-gateway-tests 40/40、custom-pack-blocking 13/13、dynamic_security 16 包、jiuzhang_guard、server 受影响包全绿。

## 边界与遗留（如实登记）

1. **窗口预算为进程内定窗**（单节点形态正确；多节点共享计费留后续——接入 Valkey 前不得宣称跨节点一致；不标 COV_DEPENDENCY_UNAVAILABLE 因非故障降级，见 wiring §5）。
2. **Schema 感知权重未接入**（当前 `*.field`+默认保守口径；schema 接入后替换 CostCache 的 `noschema-v1` 常量键并做变量相关成本缓存复评审）。
3. 订阅/WebSocket/multipart 增量结果/联邦内部调用：**未实现**（RD_PLAN §7.3 边界外，能力清单 graphql=parse 未虚标 cost_v1）。
4. 变量相关成本缓存复用（当前变量不求值、成本天然与变量值无关、缓存安全；引入求值必须重新评审缓存键 D9）。
5. 成本预算本身不代替字段级业务授权（RD_PLAN §7.3；授权实断属 S3）。
