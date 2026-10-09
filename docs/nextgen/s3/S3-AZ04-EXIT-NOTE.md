# S3-AZ04 出口记录（NG-AZ-04 管理向导 / 影响评估 / 全链验收）

日期：2026-10-05 ｜ 范围：冻结设计 §1~§5 全量（A server 轨 + B web 轨 + C 集成验收）
设计：`docs/nextgen/NG-AZ-04-protect-wizard.md`（契约节冻结；实现状态节 §6 本批追加）

## 出口判定：PASS（全部验收项完成，回归零回退）

| 验收项 | 结果 | 证据位置 |
|---|---|---|
| D1 六要素信息架构（态势 Tab 聚合） | PASS | Playwright ①：五统计卡/关系来源与最后同步/冲突表/节点 ACK 表/readiness 三态徽章全可见 |
| D2 readiness 服务端派生 | PASS | stage5 三态实证（READY / NOT_PUBLISHABLE 三因子全列 / BLOCKED_BY_CONFLICT 双因子）；DeriveReadiness 六态矩阵单测 |
| D3 影响评估 | PASS | stage5：observe_violation_count=4 / principals=3 / 样本 4 条（evidence_read）/ 词表外 400；键族修正后字面键入计（见偏差 §6.4-2） |
| D4 业务确认单强制引用 | PASS | stage5 全流（签发→签署→PATCH 消费，consumed_audit_id=request_id 落库）+ 五类拒绝逐条 400 + PATCH 事务回滚不留半切换（PG 契约） |
| D5 向导五步与失败路径 | PASS | Playwright ②全流 + ③能力门「配置与生效不一致」+CAP_MISSING(required=az/3,actual=az/2)+Popconfirm 快捷切回；B 轨 vitest 状态机 6/6 |
| D6 双人复核不做+如实标注 | PASS | 签署区固定文案（单人切换模式标注） |
| D7 VERIFIED_VIOLATION 呈现 | PASS | Playwright ⑤决策详情证据区块八因子/已实断/四要素回执；事件详情页「授权实断证据」区块（vitest 含空态对照） |
| D8 权限/审计 | PASS | 零新增权限点；jiuzhang_admin 五端点全 403（单测+E2E 双证）；审计 HIGH 行在册（request_id 溯源） |
| D9 测试计划 | PASS | 见「回归输出」；§8.4 用例群逐项状态见下表 |
| D10 兼容/增量 | PASS | OpenAPI 691（+5）双向零差集；迁移 000175 单表零既有表变更；前端零新重依赖 |

## §15.2 三项完成证据实证

**页面 E2E**（Playwright 五场景全绿，chromium，`web/e2e/authz-protect-wizard.spec.ts`）：
```
✓ ① 态势 Tab 六要素展示（readiness 徽章/关系来源与最后同步/冲突/节点 ACK） (2.2s)
✓ ② 向导五步全流（评估→四要素→签署→提交→发布生效→403 实证→决策可见） (8.5s)
✓ ⑤ VERIFIED_VIOLATION 决策详情证据区块（八因子/已实断/四要素回执） (2.3s)
✓ ③ 能力门阻塞提示（az/2 自报→发布 FAILED→配置与生效不一致+CAP_MISSING→快捷切回） (4.8s)
✓ ④ jiuzhang_admin 越权对照（新端点与签署全 403） (444ms)
5 passed (20.6s)
```

**审计**：`operation_audits` 在册 HIGH 行（module=api_security / action=update / object_type=api_object_model / username=sec_admin_s5 / request_id 可溯源，如 b0b7c08b-…/8fcc3efa-…）；after 摘要被既有审计脱敏器整段遮蔽（摘要含负责人邮箱形态触发脱敏规则——宁可过遮不漏明文的既有纪律；内容经 request_id 关联确认单与运行事件复核）。确认单签发同属 HIGH 审计面（与 PATCH 同一审计链）。

**业务确认单**（stage5 实证，应用删除后级联清理——留存不删指运行期语义）：影响评估签发 token（15 分钟 TTL 绑定端点×对象段）→ 签署落库（signed_at + 冻结文案 v1：「我已知悉：本端点切换 PROTECT 后，经显式资格判定成立的违规请求将被实断（403 AUTHZ_VIOLATION_DENIED）；UNKNOWN 永不阻断。近 7 天观测违规 4 次、涉及主体 3 个；我（sec_admin_s5）作为业务负责人确认承担实断影响。（确认文案 v1）」）→ PATCH 同事务消费（consumed_at + consumed_audit_id=PATCH request_id 落库，实测三列 `t|t|399f20f8-…`）→ 复用/过期/绑定不符/未签署/不存在逐类 400 精确消息。

## stage5 联调六组关键证据行

```
① 影响评估：observe_violation_count=4 | unknown_total=0 | principals=3 | readiness=READY | samples=4 | token 签发
② 签署（confirm_token 路径）：sign: SUCCESS | signed_at=2026-10-04T22:50:50 | owner=zhang.lei@example.com
③ PATCH（携带 token）：patch: SUCCESS | enforcement: PROTECT → publish: PUBLISH_OK
④ 请求实证：other → 403 {"code":"AUTHZ_VIOLATION_DENIED","message":"无权访问该对象","request_id":"42cde486-…"}（源站零到达 mark 缺席）；owner → 200 mark 出席
⑤ decisions：decision=VERIFIED_VIOLATION total=1（reason AUTHZ-BOLA-001 / enforced=true / owner 在册）
⑥ 确认单落库：signed_at=t | consumed_at=t | consumed_audit_id=399f20f8-6228-…（PATCH request_id 溯源闭环）
五类拒绝：不存在/已被消费/已过期/绑定不符/未签署 → 全部 INVALID_ARGUMENT 精确消息
断网：停网关容器 210s → readiness 各行出「节点能力自报不足 az/3 或能力清单不可用」阻塞因子（PROTECT_ACTIVE 展示态徽章覆盖、因子随附）；恢复后 node-acks FRESH（staleness=87）+ 因子消失
readiness 三态：READY（tenants）/ NOT_PUBLISHABLE（debug_flag，publishable+词表+排他三因子全列）/ BLOCKED_BY_CONFLICT（orders，冲突+无关系双因子）
```

## §8.4 全链验收用例群逐项状态

| 用例 | 状态 | 覆盖位置 |
|---|---|---|
| 跨租户同名对象 | 已覆盖 | AZ-03 联调 N9（TENANT-001 OBSERVE_VIOLATION 放行） |
| 撤销后回滚 | 已覆盖 | AZ-02（水位回退拒载）+ AZ-03 N4（撤销 UNKNOWN 放行） |
| 快照过期 | 已覆盖 | AZ-02（PreviousValid 资格过滤/拒载） |
| 旧节点 | 已覆盖+本批复验 | AZ-03 C08 三态 + 本批 Playwright ③（az/2 阻塞提示+快捷切回） |
| 断网 | **本批补** | stage5 停网关容器：清单陈旧→readiness 阻塞因子出现→恢复 FRESH |
| 时钟偏差 | 已覆盖 | AZ-02 skew 判定与 ACK CLOCK_SKEW 列（stage5 注入限制已注明） |
| 重新授权 | 已覆盖 | AZ-02 reauthorize CONFIRMED 恢复；本批对象授权 Tab 操作路径在 Playwright ②覆盖 |
| 集成四断言 | 已覆盖 | AZ-03 联调系统覆盖（客户端/源站/决策/事件），本批向导层复用其数据链 |

## 回归输出（原样关键行）

```
阶段5真实网关测试汇总：总用例数 40，通过 40，失败 0
CUSTOM_PACK 二次阻断评估验证：13/13 通过，0 失败
server：apiauthzwizard / apisecurity / apiauthz / app / guardconfig / gatewayconfig / apiruntime 全 ok（-count=1）
web：tsc -b 干净 / eslint 干净 / vitest 1019 passed (1019) / vite build ✓
python3 tools/check-api-reconcile.py：代码注册路由 691  OpenAPI 片段收录 691  对账通过：双向零差集
gofmt -l <改动包>：干净
PG 契约（一次性容器 postgres:16.4-alpine digest 锁定，用毕已删）：迁移 175 up/up/down/up 全链通过；
  影响评估聚合/确认单生命周期五拒/consume 五类/PATCH 事务回滚契约全 PASS
```

## 本批交付物清单

- 迁移：`server/migrations/000175_authz_enforcement_confirmations.{up,down}.sql`
- server：`internal/apiauthzwizard/`（readiness/impact/confirmations/capability/handler 五文件）、`apisecurity/object_models_update.go`（confirm_token 强制+同事务消费+五类 400）、`app/app.go`（装配）
- web：`pages/api-authz/{PostureTab,ProtectWizard,ObjectAuthorizationTab}.tsx`、`components/AuthzEnforcement.tsx`、`utils/authzEnforcement.ts`、`api/{apiAuthz,apiSecurity}.ts`、`pages/api-runtime-events/ApiRuntimeEventsPage.tsx`（证据区块接入）+ vitest 套件
- E2E：`web/e2e/authz-protect-wizard.spec.ts`（五场景）
- OpenAPI：+5 端点（readiness/impact/confirmations list+sign/conflicts）+ PATCH confirm_token 字段（691 零差集）
- 文档：设计文档 §6 实现状态节、CHANGELOG Unreleased 条目、本记录、S3 阶段小结

## 遗留与后续（移交）

1. VERIFIED_VIOLATION 报表归并（reason_code+enforced 派生视图）与风险中心展示。
2. 双人复核工作流（发起/审批/超时/通知）与确认单审批化演进。
3. 角色基线 enforcement 行级管理写通道（含「显式行级 OBSERVE 覆盖端点」语义定稿）。
4. TENANT-001 阻断资格评审（租户语义数据齐备后）。
5. 权威来源管理页面与确认单列表页（当前确认单经审计与决策详情可达；列表页 UI 顺延）。
6. ha-lab 双节点 PROTECT 分区演练（顺延自 AZ-02/03）。

## 现场状态

stage5 已还原：az4app（域名/源站/策略/关系/冲突/确认单/基线/模型/端点/应用）全部清理，identity_salt/object_hmac_key/api_node_heartbeat_seconds 设置行删除，两次发布还原（autosave 零 az4/零 api_authz_models 残留键）；迁移 000175 与代码/文档/OpenAPI 保留在线；临时工具 server/tmpaz2sign 与 /tmp/az4-* fixture 已删。
