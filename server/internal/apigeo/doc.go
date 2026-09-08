// Package apigeo API 数据出境基础（W7-XB / P1-03，任务书 §98-99 第一片）。
//
// 能力闭环：
//   - 生产方 Sweeper.SweepOnce：增量扫描 api_runtime_events 中涉敏事件
//     （details_json 含 detector=sensitive_data 明细），对 client_ip 做 GeoIP 归属判定，
//     境外来源（国家码不在 system_settings api_data.home_regions 内）落库
//     api_cross_border_events 观察记录（OUT=响应侧出境 / IN=请求侧入境）；
//   - 读接口 GET /api/v1/api-security/cross-border：国家/地区×敏感类型×端点聚合看板
//   - 明细分页；权限点 api_data.read（种子见迁移 000041）；
//   - 本土地区配置：system_settings 组 api_data 键 home_regions（默认 CN，
//     逗号分隔 ISO 3166-1 alpha-2，迁移 000058 种子）。
//
// GeoIP 数据源（诚实声明）：
//
//	仓库内归档的 web/public/assets/geo/country.mmdb（@ip-location-db/
//	geo-whois-asn-country，CC0-1.0；其中 NRO 统计数据 CC-BY-4.0，使用须署名
//	https://www.nro.net ，许可文本见 licenses/geoip-country-mmdb/）。该库仅含
//	country_code（无 ASN/城市），IPv4+IPv6 双栈。因服务端禁止新增第三方依赖，
//	本包自带只读 mmdb 解析器（mmdb.go，按 MaxMind DB 公开格式实现，仅覆盖
//	国家码查询所需子集）。纯真 qqwry.dat 为 GBK 中文地名且仅 IPv4，不适配
//	国家码判定口径，未采用。
//
// 降级语义：运行时数据文件缺失/损坏时 GeoIP 停用（lookup=nil）——Sweep 空转
// 并在结果中如实标注 GeoEnabled=false（不吞错、不伪造判定），读接口返回
// geo_enabled=false + 既有数据（可能为空）。集成方将数据文件部署到
// 装配路径（建议 runtime/geoip/country.mmdb）后能力自动启用。
//
// 判定口径：内网/保留地址（含 CGNAT）与 GeoIP 未收录（UNKNOWN）一律不记为
// 跨境——未知归属不能证明出境，宁可漏报不可误报；归属变更（home_regions
// 调整或库更新）不回溯历史行，仅对水位之后的新事件生效。
package apigeo
