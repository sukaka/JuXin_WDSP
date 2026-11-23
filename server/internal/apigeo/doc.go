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
//	统一离线 GeoIP 引擎（engine.go）零外部依赖融合两类宽松许可数据源：
//	  1. ip2region（ip2region_v4.xdb，Apache-2.0 OR MIT，许可归档 licenses/ip2region/）：
//	     自研纯 Go 只读 XDB 解析器（xdb.go，兼容 v2/v3），提供精准国内省市与运营商信息；
//	  2. DB-IP Lite / MaxMind MMDB（city-ipv6.mmdb，CC BY 4.0，署名见大屏地球面板与
//	     licenses/dbip-city/；country.mmdb，CC0-1.0 含 NRO CC-BY-4.0，归档见
//	     licenses/geoip-country-mmdb/）：自研只读 MMDB 解析器（mmdb.go）同时兼容
//	     sapics 扁平格式与官方 DB-IP Lite / MaxMind GeoIP2 嵌套格式，运维可直接将官方
//	     dbip-city-lite-YYYY-MM.mmdb 或 dbip-country-lite-YYYY-MM.mmdb 放入 runtime/geoip/ 覆盖。
//
//	除数据出境判定外，本包还向安全事件、访问日志、报告和攻击态势大屏提供统一的纯内存
//	单条/批量归属地查询能力（GET/POST /api/v1/geoip/lookup）。
//
// 降级语义：运行时数据文件缺失/损坏时 GeoIP 引擎处于未启用态（Enabled()==false），
// 数据出境侧注入 nil 保持降级（Sweep 空转、看板如实标注 geo_enabled=false），
// 不吞错、不伪造判定。数据文件就位后（runtime/geoip/ 或 /app/assets/geoip/）自动启用。
//
// 判定口径：内网/保留地址（含 CGNAT）与 GeoIP 未收录（UNKNOWN）一律不记为
// 跨境——未知归属不能证明出境，宁可漏报不可误报；归属变更（home_regions
// 调整或库更新）不回溯历史行，仅对水位之后的新事件生效。
package apigeo
