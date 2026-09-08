// Package apiauthz API 授权实体层（WDSP 阶段8 P0-15/16/17 补全，W3-A 分片）。
//
// 三块能力（与 docs/API_SECURITY_CURRENT_STATE.md P0-15/16/17 节对应）：
//
//   - 角色功能级基线（api_role_baselines，BFLA）：角色×方法×动作的允许基线，
//     支持 MANUAL/SPEC/OBSERVED/IMPORTED 四种来源，候选（confirmed=FALSE）经
//     人工确认后成为正式基线；CRUD + confirm 全部带操作审计。
//   - 对象权属基线（api_object_ownership，BOLA）：SweepOnce 扫描
//     api_runtime_events（identity_fingerprint 非空），用端点 normalized_path
//     模板匹配 raw_path 提取路径占位符段值后 upsert（access_count++/last_seen）。
//     权属记录是「谁访问过哪个对象」的观测证据，支撑五档 BOLA 评估而非直接定罪。
//   - 对象模型（api_object_models，BOLA 实体画像）：SweepObjectModelsOnce 扫描
//     api_runtime_events 全量事件（不限身份），按端点模板提取路径占位段与
//     Query 对象参数形态后 upsert（sample_count++/形态合并/first/last_seen）。
//   - 字段权限（api_field_permissions，Mass Assignment / 字段越权）：
//     字段路径×方向×属性基线，role/tenant 为 NULL 时是默认行，非空为覆盖行。
//
// BOLA 评估读接口（GET .../authz/evaluate）输出五档结论：
// POLICY_CONFIRMED / HIGH_CONFIDENCE / LIKELY / POSSIBLE / INSUFFICIENT_EVIDENCE，
// 规则与「不仅凭 ID 变化定罪」纪律见 evaluate.go。
//
// 装配（集成方）：NewStore(db) → NewHandler(store, auditSvc) →
// RegisterRoutes(mux, authz, h)；周期任务挂 store.SweepOnce 与
// store.SweepObjectModelsOnce（HasMore 排空模式同其他 sweep）。
// 权限点 api_authorization.read / api_authorization.manage 的种子迁移由集成方
// 统一登记（本包只引用常量）。
package apiauthz
