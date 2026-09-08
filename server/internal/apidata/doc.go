// Package apidata API 敏感数据管理面（WDSP 阶段8 P0-19 补全，S5 分片）。
//
// 三块能力（与 docs/API_SECURITY_CURRENT_STATE.md P0-19 节对应）：
//
//   - 敏感数据类型（api_sensitive_data_types）：分类分级实体，内置种子与
//     gateway/dynamic_security/detectors/sensitive.go 词表对齐（对应关系见迁移
//     000040 注释）；内置类型 is_builtin=TRUE，禁删且名称不可改（与网关证据标签的
//     对齐键，改名会断开归并）。
//   - 脱敏规则（api_masking_rules）：GLOBAL < APPLICATION < ENDPOINT 优先级合并的
//     脱敏计划由 MaskPlanForEndpoint 纯函数求值；表列名为跨分片契约，
//     发布分片按列名读取下发网关，不得改动。
//   - 敏感字段运行时回填（api_sensitive_fields）：SweepOnce 扫描
//     api_runtime_events.details_json 中 detector=sensitive_data 的证据，
//     upsert 敏感字段（occurrence_count++/last_seen，detection_source='RUNTIME'）。
//
// 装配（集成方）：NewStore(db) → NewHandler(store, auditSvc) →
// RegisterRoutes(mux, authz, h)；周期任务挂 store.SweepOnce。
// 权限点 api_data.read / api_data.manage 的种子迁移由集成方统一登记（本包只引用常量）。
package apidata
