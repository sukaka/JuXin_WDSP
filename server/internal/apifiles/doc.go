// Package apifiles API 文件资产（P1-04，任务书 §16/§106/§107 子集）。
//
// 数据源：网关统一主事件 file_observations（multipart 上传 part 元数据 /
// Content-Disposition 下载观测，仅元数据不落文件内容）经 apiruntime 采集器
// UPSERT 进 api_file_assets（迁移 000061）。
//
// 本包职责：
//   - 只读查询：GET /api/v1/api-security/file-assets（过滤/分页）与
//     /file-assets/stats（§106 上传/下载计数、敏感文件计数、File/IP/Account/API TOP）；
//   - 文件风险 v1（§107 子集）：同身份批量下载判定（近 1h 同一身份指纹下载
//     不同文件数超阈值）→ 物化 api_runtime_findings（finding_type=FILE_BULK_DOWNLOAD）。
//
// 权限：复用 api_data.read（与 apigeo/apidata 同一权限域，种子见迁移 000041）。
// 判定口径如实声明：敏感类型仅凭扩展名词表 v1（文件内容不可达）；
// 下载观测仅覆盖 Content-Disposition 携带 filename 的响应（v1 精度优先）。
package apifiles
