// Package apinodes API 网关节点版本校验 v1（W12-NODE，任务书 §200-201 遥测路径；
// W17-HB 起活性+版本升级心跳数据源）。
//
// 数据源：
//   - api_runtime_events 的 gateway_node / policy_version / model_version
//     （gateway_node 列由迁移 000069 补；业务流量事件，Sweeper 周期聚合）；
//   - 网关节点心跳（W17-HB：网关周期向 API 事件日志写 heartbeat=true 合成记录，
//     apiruntime.Collector 识别后不产业务数据，经 RecordHeartbeat 直写本视图）——
//     修复无流量时段节点状态失真（SILENT 误判）：last_seen_at 以心跳时间为准，
//     策略版本以心跳上报为准（优先于历史业务事件版本，合并不回退口径见
//     Store.UpsertNode/Store.RecordHeartbeat）。
//
// 本包职责：
//   - 周期聚合：Sweeper.SweepOnce 按 gateway_node 分组聚合事件表
//     （max(occurred_at)/最新非空 policy_version/model_version/count），
//     upsert api_gateway_nodes（聚合绝对值 + 与心跳合并不回退，重扫幂等），
//     并按合并后有效活性重算状态（ACTIVE ≤5min / STALE ≤1h / SILENT >1h）；
//   - 版本一致性：活跃节点（非 SILENT）间最近 policy_version 去重 >1 时，
//     产 CONFIG_HASH_MISMATCH 系统告警（复用 systemalerts.Engine 小接口，
//     nil 时仅 slog 记录不一致事实，不静默吞错）；恢复一致后 AutoRecover
//     自动解决（RECOVERED）；
//   - 只读接口：GET /api/v1/api-security/nodes（节点列表+状态+版本+一致性标记）
//     与 /nodes/consistency（按版本分组对比，明确回答是否一致）。
//     权限点 api_runtime.read（与 apisecurity 运行时只读接口同一权限域）。
//
// 如实说明：这是「经事件遥测+心跳的节点版本校验」，不是多节点同步协议——
// 节点注册/主动同步/配置推送等全量协议（任务书 §200）为后续工程。
package apinodes
