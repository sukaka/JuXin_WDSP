// Package apiweakness API 弱点中心（WDSP 任务书 P0-13：Risk/Weakness 分离）。
//
// 分离语义（与 docs/API_SECURITY_CURRENT_STATE.md P0-13 节对应）：
//
//   - Risk / findings（api_runtime_findings、api_runtime_events）是「运行时异常信号」：
//     一次性事件——某请求在某时刻命中了什么检测器。量大、可降噪、可误报，
//     回答「刚刚发生了什么」。
//   - Weakness（api_weaknesses）是「长期缺陷」：从持续信号中归纳出的、
//     需要人跟进的弱点——未认证敏感接口、已下线仍被调用、敏感数据进查询串、
//     Schema 漂移长期不修。回答「我们有哪些一直存在的问题」。
//
// 弱点生命周期：NEW（扫描发现）→ CONFIRMED（确认真实）→ TO_FIX（指派整改）
// → FIXED（整改完成）→ 复测通过 ARCHIVED / 复测失败 REPRODUCED → 重新指派。
// 任何阶段可 IGNORE（接受风险/误报）；FIXED 之后再次被扫描命中自动回到 REPRODUCED。
// 每次流转与派生命中都写 api_weakness_actions（整改/复测历史，只增不改）。
//
// 装配（集成方）：NewStore(db) → NewHandler(store, auditSvc) →
// RegisterRoutes(mux, authz, h)；周期任务挂 NewSweeper(store).SweepOnce。
// 权限点 api_weakness.read / api_weakness.handle 的种子迁移由集成方统一登记。
package apiweakness
