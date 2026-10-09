# S3-AZ02 出口记录（NG-AZ-02 撤销水位 / 租约 / 节点 ACK）

日期：2026-10-05 ｜ 范围：冻结设计 §1~§5 全量（A 决策链 + B ACK 通道 + 集成验收）
设计：`docs/nextgen/NG-AZ-02-watermark-lease-ack.md`（契约节冻结；实现状态节本批追加）

## 出口判定：PASS（全部验收项完成，回归零回退）

| 验收项 | 结果 | 证据位置 |
|---|---|---|
| D1 向量水位（手工+权威双通道、只增、回滚不回退） | PASS | manual_seq=2 / sources=2；回滚后库值不变 |
| D3 PreviousValid 资格过滤 | PASS（语义） | 单测锁定；同代水位在场、低代水位置空（说明见实现状态偏差 #6） |
| D4-1 水位回退拒绝 | PASS | `ROLLBACK_PUBLISH_FAILED … revocation watermark regression (incoming manual_seq=1 < applied=2)` |
| D4-3 v1 兼容 | PASS | v1 快照 v2 逻辑全惰性（单测 + 黄金回归不回退） |
| D4-4 能力门 az/2 | PASS | `CAPABILITY_MISSING … CAP_MISSING:detectors.authzdecide(required=az/2,actual=az/1)`；janitor 自愈恢复 |
| D5 租约双策略 | PASS | strict AUTHZ-LEASE-001+dependency_unavailable；degraded 评估继续+AUTHZ-LEASE-002 |
| D6 节点 ACK | PASS | node-acks API（sec_admin 200 / jiuzhang_admin 403）；STALE_EXPIRED staleness=39 lease=15 |
| D7 冲突排除 | PASS | AUTHZ-CONFLICT-001；REVOKE 后 RESOLVED→ALLOW 恢复 |
| D8 漂移 | PASS（修正后语义） | 负向差值判漂移（公式修正见实现状态偏差 #1）；心跳 skew 列在册 |
| D9 时延方法学 | PASS（如实） | REVOKE→ACK 4/6/7/7s（p50 6.5s max 7s）；P99≤5s 为候选非承诺（心跳 30s 合法区间外）；GRANT 臂不可经撤销水位测量 |
| D10 兼容/对账 | PASS | OpenAPI 686 双向零差集；全字段 omitempty |

## 回归输出（原样关键行）

```
阶段5真实网关测试汇总：总用例数 40，通过 40，失败 0
CUSTOM_PACK 二次阻断评估验证：13/13 通过，0 失败（隔离重跑；首轮后台并行与清理发布锁竞争属现场竞争非回退）
server 8 包：apiauthz / apiauthzauthority / gatewayconfig / guardconfig / apisecurity / applications / settings / app 全 ok
gateway：dynamic_security 16 包、modules/jiuzhang_guard 全 ok
python3 tools/check-api-reconcile.py：代码注册路由 686  OpenAPI 片段收录 686  对账通过：双向零差集
```

## 本批交付物清单

- 迁移：`server/migrations/000173_authz_watermark_lease.{up,down}.sql`
- server：`gatewayconfig/{guard.go,authz_decision.go,authz_lifecycle.go,capability_gate.go}`、`guardconfig/apiruntime.go`、`apiauthz/relations.go`、`apisecurity/object_models*.go`、`applications/{store.go,handler.go}`、`settings/settings.go`、`app/app.go`（键清单）
- gateway：`dynamic_security/detectors/{authz_watermark.go,authzdecide.go}`、`dynamic_security/events/authz.go`、`modules/jiuzhang_guard/{module.go,apiprotect.go,authz_watermark.go,apiheartbeat.go,capability_report.go}`、`apievents/apievents.go`
- 测试：detectors authz_watermark/authzdecide_v2、jiuzhang_guard authz_watermark/apiheartbeat、server capability_gate/object_models_update 等新增套件
- OpenAPI：object-models PATCH + 对象模型发布状态字段 + applications.authz_lease_seconds（686 零差集）
- 文档：NG-AZ-02 设计文档实现状态节、CHANGELOG Unreleased 条目、本记录

## 遗留与后续（移交）

1. D8 节点侧漂移修正语义已在实现状态节登记（负向差值专用）；后续可在 RD_PLAN §14.3 评审该公式终稿。
2. 前端页面（授权页水位/租约/ACK/冲突展示）——§8.4 界面项，后续前端批次。
3. 多节点 ha-lab 分区编排演练（NG-T-A07 的 test/ha 设施复用）。
4. 时延目标 P99≤5s 需心跳周期 ≤5s 的部署形态评审（当前 30~300s 合法区间外）；撤销→ACK 现行形态为「发布即首拍」秒级。
5. 快照体积基准（200000 relations 上限形态 + 冲突集 10000 上限形态的发布/加载耗时抽测）。
6. 权威在线推送通道、来源删除端点（NG-AZ-01 移交）、双人复核（§6 待定项）。

## 现场状态

stage5 已恢复：测试关系/冲突/来源/对象模型/端点/JWT 策略/设置行全部清理并发布还原（autosave 无 lease/heartbeat/salt/conflict 残留键）；迁移 000173、权限种子、管理端点、代码与文档保留在线。
