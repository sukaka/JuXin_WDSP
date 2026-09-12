// Package apiscan API 主动扫描 v1（P1-07，设计稿 docs/API_ACTIVE_SCANNING.md）。
//
// 定位：对已纳管 API 资产的经授权有限主动验证（非 DAST）：探针集收敛于本系统
// 检测语义的验证需求（认证缺失/下线存活/敏感暴露/Schema 符合/水平越权对比/方法枚举），
// 靶标只来自已纳管应用（api_scan_targets.application_id FK applications），
// 授权先于一切执行（api_scan_authorizations，撤销即刻停发）。
//
// 模块边界：扫描逻辑全部收在本包；复用 apiweakness 复测状态机（retest.go 小接口
// 桥接，由集成方装配）；扫描流量隔离签名头 X-JiuZhang-Scan（HMAC(job_id)），
// 学习样本排除规则在 apiruntime/samples.go（details 含 detector=scanner 明细即排除，
// 网关识别上线前该规则处于待命态，见报告说明）。
package apiscan
