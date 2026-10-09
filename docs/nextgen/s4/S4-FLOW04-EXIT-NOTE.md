# S4-FLOW04 出口记录（NG-FLOW-04 管理恢复与运行观测 全链验收）

日期：2026-10-06 ｜ 范围：FLOW-04 双轨（web 三 Tab 增强 + server metrics 内嵌）联调验收
设计：`docs/nextgen/NG-FLOW-strong-flow.md`（契约节冻结；实现状态 §9 本批追加）

## 出口判定：PASS（FLOW-04 承诺项全部验收，回归零回退，S4 阶段关闭）

| 验收项（设计 §1.9/§15.2 映射） | 结果 | 证据位置 |
|---|---|---|
| 定义管理页面（版本/状态图/允许转换/成功条件/异常策略） | PASS | Playwright ①：新建草稿（表单+步骤编辑）→activate 确认弹窗→列表 ACTIVE→详情抽屉步骤序列图（Steps+successRuleText+超时/租约/重试语义+UNKNOWN 恒不阻断 Alert） |
| 实例管理区块（列表/详情/恢复操作） | PASS | Playwright ②③④：CONFIRMED 实例轨迹 COMMIT OK+INSTANCE_CONFIRMED；PROTECT 403 轨迹 REJECTED/FLOW-RESERVE-001；INDETERMINATE 警示条逐字+恢复面板全流+恢复记录区块 |
| INDETERMINATE「未知，不显示安全通过」（§9.4 红线） | PASS | 详情抽屉 Alert 逐字断言 + `status_semantics=UNKNOWN_NOT_CONFIRMED` 码文本在册 |
| 运行指标（实例计数按状态/INDETERMINATE 率与积压/对账时延/reserve 冲突率） | PASS | stage5 metrics 端点逐行实证（见下「指标冒烟证据行」） |
| 权限/越权（read/manage/路由守卫） | PASS | Playwright ⑤：jiuzhang_admin definitions/instances/resolve 三处 403 + 页面路由守卫整页「无访问权限」 |
| 恢复操作 HIGH 审计/乐观锁/终态拒重复 | PASS | FLOW-03 批已验（本批页面链复用：恢复面板随行 expected_version、409 分类提示区块在册） |
| OpenAPI 兼容 | PASS | schema 零变化，reconcile 700 双向零差集持平 |

## stage5 指标冒烟证据行（原样）

**定义 activate（OBSERVE 两步）→ 正常流 CONFIRMED（判定不命中造 INDETERMINATE 后 resolve 收口）→ PROTECT 违规 403 → `GET /api/v1/api-security/metrics`：**

```
strong_flow_instances{application_id="0434636e-…",status="ACTIVE"} 1
strong_flow_instances{application_id="0434636e-…",status="CONFIRMED"} 1
strong_flow_instances{application_id="0434636e-…",status="INDETERMINATE"} 0
strong_flow_instances{application_id="0434636e-…",status="CANCELLED"} 0
strong_flow_instances{application_id="0434636e-…",status="FAILED"} 0
strong_flow_indeterminate_backlog{application_id="0434636e-…"} 0（resolve 后真实当前值）
strong_flow_reserve_conflict_ratio{application_id="0434636e-…"} 0.3333333333333333（RESERVE 3 中 1 冲突=1/3）
——INDETERMINATE 未收口轮（backlog/滞留非零实证）——
strong_flow_indeterminate_backlog{application_id="0434636e-…"} 1
strong_flow_indeterminate_ratio{application_id="0434636e-…"} 0.3333333333333333
strong_flow_indeterminate_age_avg_seconds{application_id="0434636e-…"} 25.997551
strong_flow_indeterminate_age_max_seconds{application_id="0434636e-…"} 25.997551
```

## Playwright 五场景（`web/e2e/strong-flow-admin.spec.ts`，chromium，两轮稳定全绿）

```
✓ ① 定义全流页面操作：新建草稿 → activate → ACTIVE → 详情步骤序列图 (7.0s)
✓ ② 正常流：API 制造完整流程 → 实例 CONFIRMED → 详情轨迹 INSTANCE_CONFIRMED (19.1s)
✓ ③ 违规 403：PROTECT 跳步请求 → 实例轨迹 REJECTED/FLOW-RESERVE-001 页面可见 (8.1s)
✓ ④ INDETERMINATE 对账：判定不命中 → 警示条逐字 → 页面恢复 CONFIRMED+恢复记录 (21.1s)
✓ ⑤ 越权：jiuzhang_admin 端点 403 + 页面操作入口隐藏 (845ms)
5 passed (1.2m)
```

## 联调新发现与偏差登记（详见设计 §9.2）

1. **多 ACTIVE 定义绑定同端点时 finalize 只消费首个成功预留**——其余绑定实例恒 PENDING 不可 CONFIRMED（场景②实证 v25 register 无 COMMIT）。多绑定 CONFIRMED 语义待设计明确；E2E 以「发布面单定义」（`retireAllE2EDefs`+settle）编排。
2. **实例键 HMAC 输入不含 definition_id**（§1.2 冻结形态）——历史同版本号不同名定义同 ref 撞键（`instance_terminal` 跨轮实证）；E2E 以每轮唯一 ref 规避；建议后续批评估实例键加 definition_id 分量（线契约裁决）。
3. **E2E 清理纪律**：采集延迟在途事件会重建实例行（resolveInstance upsert）——`cleanupStrongFlowSettled` 两遍清理夹 8s 采集窗+两遍发布；Valkey 热状态（24h TTL）只随版本/ref 更迭自然过期。
4. **RETIRED PROTECT 育龄窗内仍按 mode 实断**（裁决 1 语义正确延伸，v20 实证）——跨场景编排先 retire+settle。
5. **登录限流键 PTTL=-1 可致永久 429**（既有注释坑）——global-setup 已含限流键清理纪律。
6. **越权页面语义**：jiuzhang_admin 被路由守卫（RequirePermission api_flow.read）整页拒绝（「无访问权限」）——比「入口隐藏」更强，与端点 403 互证（spec 按此断言）。
7. **调试工具性修正**（spec 固化）：node undici 静默丢弃 Host 头（网关直发必须 curl 承载）；antd 两字按钮插空格（getByRole name 不匹配，改 `.ant-drawer-extra`/`.ant-drawer-close` 结构定位）；activate 的 triggerPublish 遇 LOCK_BUSY 不重试（createAndActivate 显式 publishAndWait）。

## 回归输出（原样关键行）

```
阶段5真实网关测试汇总：总用例数 40，通过 40，失败 0
CUSTOM_PACK 二次阻断评估验证：13/13 通过，0 失败
server：ok metrics 4.023s / strongflow 4.472s / apiruntime 5.554s / app 4.330s（-count=1）
gateway：dynamic_security 17 包 ok / jiuzhang_guard 17 包 ok，无 FAIL（-count=1）
web：tsc -b 干净 / vitest 1045 passed (1045) / vite build ✓
python3 tools/check-api-reconcile.py：代码注册路由 700  OpenAPI 片段收录 700  对账通过：双向零差集
gofmt/prettier：本批文件干净
```

## 现场还原终态

- E2E-* 定义全 RETIRED（spec afterAll：retireAllE2EDefs+settle 两遍清理夹采集窗）；实例/步骤事件 PG 清零；autosave 无 api_strong_flows 段；发布还原 SUCCESS。
- spec 调试输出已删；stage5 全栈 healthy（api/gateway/postgres/valkey/testorigin）。
