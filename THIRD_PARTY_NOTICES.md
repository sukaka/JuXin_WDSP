# 第三方组件声明

本文档记录九章WEB应用智能防护系统V2.0所使用的第三方开源组件。所有组件均以实际锁定版本的仓库许可证文件为准。

## 使用原则

1. 优先选择 Apache-2.0、MIT、BSD 等宽松许可证组件；
2. 未经书面批准，不得引入 GPL、AGPL 组件；
3. 所有组件版本必须明确锁定，禁止使用 `latest`；
4. 升级组件前必须重新核查许可证和兼容性；
5. 不得删除或修改任何第三方组件的版权声明。

## 核心防护组件

| 软件名称 | 项目来源 | 锁定版本 | 许可证 | 是否修改 | 使用方式 | 许可证文件位置 |
|---------|---------|---------|--------|---------|---------|---------------|
| Caddy | https://github.com/caddyserver/caddy | v2.11.4 (e2eee6a7fce3) | Apache-2.0 | 否 | 反向代理网关 | [licenses/caddy/LICENSE](licenses/caddy/LICENSE) |
| Coraza WAF | https://github.com/corazawaf/coraza | v3.7.0 (27069d06c896) | Apache-2.0 | 否 | WAF 检测引擎 | [licenses/coraza/LICENSE](licenses/coraza/LICENSE) |
| coraza-caddy | https://github.com/corazawaf/coraza-caddy | v2.5.0 (55c03d45dc55) | Apache-2.0 | 否 | Caddy 集成模块 | [licenses/coraza-caddy/LICENSE](licenses/coraza-caddy/LICENSE) |
| OWASP CRS | https://github.com/coreruleset/coreruleset | v4.28.0 (55b09f5acfd1) | Apache-2.0 | 否 | 通用攻击规则集 | [licenses/owasp-crs/LICENSE](licenses/owasp-crs/LICENSE) |
| CRS 应用排除插件（wordpress/nextcloud/phpmyadmin/drupal/dokuwiki/xenforo） | https://github.com/coreruleset/plugin-registry | 各插件 commit PINNED（见 licenses/crs-plugins/README.md） | Apache-2.0 | 否 | 应用专属误报排除 | [licenses/crs-plugins/LICENSE](licenses/crs-plugins/LICENSE) |
| CRS auto-decoding-plugin | https://github.com/coreruleset/auto-decoding-plugin | 1.0.0 (6885a9728d3f) | Apache-2.0 | 是（剔除 sqlHexDecode 两条规则与 10 行 CRS4 已删规则引用，默认禁用；见 JIUZHANG-NOTES.md） | ARGS 多轮解码抗混淆（默认禁用，按站启用） | [licenses/crs-plugins/LICENSE](licenses/crs-plugins/LICENSE) |
| crawler-user-agents | https://github.com/monperrus/crawler-user-agents | 9345a7ad9c49 | MIT | 否（经 tools/rulegen/crawler-ua 生成规则） | 爬虫 UA 指纹标记（OBSERVE） | [licenses/crawler-user-agents/LICENSE](licenses/crawler-user-agents/LICENSE) |
| ai.robots.txt | https://github.com/ai-robots-txt/ai.robots.txt | 987266f3c581 | MIT | 否（经 tools/rulegen/ai-crawler 生成规则） | AI 爬虫 UA 标记（OBSERVE） | [licenses/ai-robots-txt/LICENSE](licenses/ai-robots-txt/LICENSE) |
| vektah/gqlparser | https://github.com/vektah/gqlparser | v2.5.60（go.mod 锁定） | MIT | 否 | GraphQL 文档 AST 解析（gateway/dynamic_security/gqlast 包装层带自建资源硬边界） | [licenses/gqlparser/LICENSE](licenses/gqlparser/LICENSE) |
| xcaddy | https://github.com/caddyserver/xcaddy | v0.4.5 (328cac711a1f) | Apache-2.0 | 否 | Caddy 构建工具（仅构建期） | [licenses/xcaddy/LICENSE](licenses/xcaddy/LICENSE) |
| go-ftw | https://github.com/coreruleset/go-ftw | v2.4.0 (23db497e3a61) | Apache-2.0 | 否 | CRS 回归测试（仅测试期） | [licenses/go-ftw/LICENSE](licenses/go-ftw/LICENSE) |
| gopacket | https://github.com/google/gopacket | v1.1.19 | BSD-3-Clause | 否 | 镜像（旁路）采集器抓包/TCP 重组（pcapgo AF_PACKET 纯 syscall + tcpassembly，无 libpcap/cgo） | [licenses/gopacket/LICENSE](licenses/gopacket/LICENSE) |

## 基础设施组件

| 软件名称 | 项目来源 | 计划版本 | 许可证 | 是否修改 | 使用方式 | 许可证文件位置 |
|---------|---------|---------|--------|---------|---------|---------------|
| PostgreSQL | https://www.postgresql.org | 16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c | PostgreSQL License | 否 | 主数据库 | [licenses/postgresql/LICENSE](licenses/postgresql/LICENSE) |
| Valkey | https://github.com/valkey-io/valkey | 8.1.8-alpine@sha256:94365b275456ae14621001c03556c732b1d93a0cdeacc317d1bdd52eba680885 | BSD-3-Clause | 否 | 缓存、会话辅助状态、分布式锁、任务状态 | [licenses/valkey/LICENSE](licenses/valkey/LICENSE) |

## 基础镜像（Docker）

| 软件名称 | 锁定版本 | 许可证 | 使用方式 |
|---------|---------|--------|---------|
| golang | 1.25-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 | BSD-3-Clause | 网关/测试源站构建阶段 |
| alpine | 3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b | MIT | 网关/测试源站运行阶段 |
| curlimages/curl | 8.21.0@sha256:7c12af72ceb38b7432ab85e1a265cff6ae58e06f95539d539b654f2cfa64bb13 | curl License (MIT/X) | 阶段1配置控制器容器 |

## 后端依赖（Go）

阶段2及以后补充，以 `server/go.mod` 和 `gateway/go.mod` 实际锁定版本为准。

## 前端依赖（Node.js）

阶段0初始依赖如下，后续以 `web/package.json` 实际锁定版本为准。

| 软件名称 | 计划版本 | 许可证 | 使用方式 |
|---------|---------|--------|---------|
| React | 18.x | MIT | 前端框架 |
| TypeScript | 5.x | Apache-2.0 | 类型系统 |
| Vite | 6.x | MIT | 构建工具 |
| Ant Design | 5.x | MIT | UI 组件库 |
| ECharts | 5.x | Apache-2.0 | 图表库 |
| TanStack Query | 5.x | MIT | 数据请求 |
| Zustand | 5.x | MIT | 状态管理 |
| Vitest | 3.x | MIT | 单元测试 |
| Playwright | 1.x | Apache-2.0 | E2E 测试 |

## 阶段5新增组件

| 软件名称 | 项目来源 | 锁定版本 | 许可证 | 是否修改 | 使用方式 | 许可证文件位置 |
|---------|---------|---------|--------|---------|---------|---------------|
| valkey-go | https://github.com/valkey-io/valkey-go | v1.0.76 | Apache-2.0 | 否 | jiuzhang_guard 模块 Valkey 客户端（CC计数/临时封禁） | [licenses/valkey-go/LICENSE](licenses/valkey-go/LICENSE) |

## 阶段6新增组件

| 软件名称 | 项目来源 | 锁定版本 | 许可证 | 是否修改 | 使用方式 | 许可证文件位置 |
|---------|---------|---------|--------|---------|---------|---------------|
| gofpdf | https://github.com/jung-kurt/gofpdf | v2.17.3 | MIT | 否 | PDF 报告生成（管理后端） | [licenses/gofpdf/LICENSE](licenses/gofpdf/LICENSE) |
| Noto Sans CJK | https://github.com/notofonts/noto-cjk | noto-cjk main（sha256 见 server/assets/fonts/README.md） | OFL-1.1 | 否 | PDF 报告中文字体（server/assets/fonts/） | [licenses/noto-fonts/LICENSE](licenses/noto-fonts/LICENSE) |
| ECharts | https://github.com/apache/echarts | 6.1.0 | Apache-2.0 | 否 | 前端图表（态势与报表页） | [licenses/echarts/LICENSE](licenses/echarts/LICENSE) |
| godocx | https://github.com/gomutex/godocx | v0.1.5 | MIT | 否 | Word（docx）报告生成（管理后端） | [licenses/godocx/LICENSE](licenses/godocx/LICENSE) |
| go-charts | https://github.com/vicanso/go-charts | v2.6.10 | MIT | 否 | 报告图表服务端渲染（PNG/SVG） | [licenses/go-charts/LICENSE](licenses/go-charts/LICENSE) |
| go-chart | https://github.com/wcharczuk/go-chart | v2.1.0 | MIT | 否 | go-charts 底层绘图引擎（间接依赖） | [licenses/go-chart/LICENSE](licenses/go-chart/LICENSE) |
| freetype-go | https://github.com/golang/freetype | v0.0.0-20170609003504-e2365dfdc4a0 | FTL（双许可 FTL/GPLv2+，本项目选择 FTL） | 否 | 图表字体光栅化（go-charts 间接依赖） | [licenses/freetype-go/LICENSE](licenses/freetype-go/LICENSE) |

## 大屏可视化新增组件

| 软件名称 | 项目来源 | 锁定版本 | 许可证 | 是否修改 | 使用方式 | 许可证文件位置 |
|---------|---------|---------|--------|---------|---------|---------------|
| echarts-gl | https://github.com/ecomfe/echarts-gl | 2.1.0 | MIT | 否 | 攻击监控大屏 WebGL 地球（globe/lines3D） | [licenses/echarts-gl/LICENSE](licenses/echarts-gl/LICENSE) |
| mmdb-lib | https://github.com/runk/mmdb-lib | 3.0.3 | MIT | 否 | 浏览器端解析 MaxMind 格式 IP 归属库 | [licenses/mmdb-lib/LICENSE](licenses/mmdb-lib/LICENSE) |
| buffer | https://github.com/feross/buffer | 6.0.3 | MIT | 否 | mmdb-lib 浏览器端 Buffer 兼容层 | [licenses/buffer/LICENSE](licenses/buffer/LICENSE) |
| d3-geo | https://github.com/d3/d3-geo | 3.1.1 | ISC | 否 | 球面质心计算与底图投影绘制 | [licenses/d3-geo/LICENSE](licenses/d3-geo/LICENSE) |
| topojson-client | https://github.com/topojson/topojson-client | 3.1.0 | ISC | 否 | TopoJSON 转 GeoJSON | [licenses/topojson-client/LICENSE](licenses/topojson-client/LICENSE) |
| world-atlas | https://github.com/topojson/world-atlas | 2.0.2 | ISC（数据为 Natural Earth，公有领域） | 否 | 世界国家面数据（地球底图与国家质心） | [licenses/world-atlas/LICENSE](licenses/world-atlas/LICENSE) |
| i18n-iso-countries | https://github.com/michaelwittig/node-i18n-iso-countries | 7.14.0 | MIT | 否 | ISO 3166 数字代码转 alpha-2 | [licenses/i18n-iso-countries/LICENSE](licenses/i18n-iso-countries/LICENSE) |
| geo-whois-asn-country-mmdb | https://github.com/sapics/ip-location-db | 2.3.2026061719 | CC0-1.0（含 NRO 统计数据 CC-BY-4.0，需注明 nro.net 来源） | 否 | 离线 IP→国家归属回退库（web/public/assets/geo/country.mmdb 与服务端统一 GeoIP 引擎，自研只读解析器见 server/internal/apigeo） | [licenses/geoip-country-mmdb/](licenses/geoip-country-mmdb/) |
| dbip-city-mmdb | https://github.com/sapics/ip-location-db | 2.3.2026060513 | CC BY 4.0（DB-IP，需署名，大屏地球面板已带链接） | 否 | 离线 IPv6→城市归属库（web/public/assets/geo/city-ipv6.mmdb）；服务端统一 GeoIP 引擎同时兼容官方 DB-IP Lite `.mmdb` 替换升级 | [licenses/dbip-city/](licenses/dbip-city/) |
| ip2region（ip2region_v4.xdb） | https://github.com/lionsoul2014/ip2region | commit f8410adb250b075c20f4c6f463c4b52b821a7970（2026-11-09，sha256:a12ad5aca1277d67e525efcda531a20cc0d654ff4f087150d45bc17fca4bc260） | Apache-2.0 OR MIT | 否 | 离线 IPv4→省市/运营商归属库（server/assets/geoip/ip2region_v4.xdb，自研纯 Go 只读 XDB 解析器见 server/internal/apigeo/xdb.go），供安全事件、访问日志与大屏统一归属地查询 | [licenses/ip2region/LICENSE.md](licenses/ip2region/LICENSE.md) |

## 阶段8 新增与关键间接依赖补登

| 软件名称 | 项目来源 | 锁定版本 | 许可证 | 是否修改 | 使用方式 | 许可证文件位置 |
|---------|---------|---------|--------|---------|---------|---------------|
| protobuf-go | https://github.com/protocolbuffers/protobuf-go | v1.36.11 | BSD-3-Clause | 否 | gRPC 描述符级消息解析（protodesc/dynamicpb，管理后端；由间接依赖转直接启用） | 上游仓库 LICENSE（SBOM 收录，见文末声明） |
| go-humanize | https://github.com/dustin/go-humanize | v1.0.1 | MIT | 否 | godocx 间接依赖（报告导出） | 上游仓库 LICENSE（SBOM 收录，见文末声明） |
| x/image | https://github.com/golang/image | v0.0.0-20200927104501-e162460cd6b5 | BSD-3-Clause | 否 | 图表绘制（go-chart 间接依赖） | 上游仓库 LICENSE（SBOM 收录，见文末声明） |
| yaml.v3 | https://github.com/go-yaml/yaml | v3.0.1 | MIT + Apache-2.0（双许可） | 否 | 规范导入 YAML 解析（OpenAPI/Swagger/JSON Schema/Postman，管理后端，阶段8 §33） | [licenses/yaml/LICENSE](licenses/yaml/LICENSE) |
| modelcontextprotocol/go-sdk | https://github.com/modelcontextprotocol/go-sdk | v1.8.0（go.mod 锁定） | Apache-2.0 / MIT（上游自述正由 MIT 过渡至 Apache-2.0，新代码 Apache-2.0、未授权重许可的贡献仍为 MIT） | 否 | MCP 官方 Go SDK 对测参照客户端（仅测试期 `test/waf/mcp-e2e/`，不入产物） | 上游仓库 LICENSE（SBOM 收录，见文末声明） |
| gRPC（google.golang.org/grpc） | https://github.com/grpc/grpc-go | v1.76.0（go.mod 锁定） | Apache-2.0 | 否 | gRPC 官方 Go SDK 对测参照客户端（仅测试期 `test/waf/grpc-e2e/`，不入产物） | 上游仓库 LICENSE（SBOM 收录，见文末声明） |

## APM 阶段2 数据面新增组件

| 软件名称 | 项目来源 | 锁定版本 | 许可证 | 是否修改 | 使用方式 | 许可证文件位置 |
|---------|---------|---------|--------|---------|---------|---------------|
| ClickHouse | https://github.com/ClickHouse/ClickHouse | 25.8-alpine@sha256:87e0a5b72f5465b18eacca7c76850e7ff551c9795c50e451f5646299e5e24146 | Apache-2.0 | 否 | APM 数据面存储（trace/span 与聚合；schema 由 deployment/apm/clickhouse 维护） | [licenses/clickhouse/LICENSE](licenses/clickhouse/LICENSE)（上游原文 URL 与版本见同目录 README.txt） |
| OpenTelemetry Collector (contrib) | https://github.com/open-telemetry/opentelemetry-collector-contrib | 0.154.0@sha256:b3079f45e19bdb7326bf49cdddce6cf60dfd865138db39f2733ea48ab17bc4cb | Apache-2.0 | 否 | APM 本地 Collector 与中央 Collector Gateway（deployment/apm/collector/ 配置） | [licenses/otel-collector-contrib/LICENSE](licenses/otel-collector-contrib/LICENSE)（上游原文 URL 与版本见同目录 README.txt） |
| clickhouse-go | https://github.com/ClickHouse/clickhouse-go | v2.48.0 | Apache-2.0 | 否 | 管理后端 ClickHouse 客户端（APM 阶段2 下半 trace 检索/瀑布只读查询，server/go.mod 直接依赖） | [licenses/clickhouse-go/LICENSE](licenses/clickhouse-go/LICENSE) |
| ch-go | https://github.com/ClickHouse/ch-go | v0.74.0 | Apache-2.0 | 否 | clickhouse-go 底层列式协议驱动（间接依赖） | [licenses/ch-go/LICENSE](licenses/ch-go/LICENSE) |
| OpenTelemetry Go（otel / otel/sdk / otlptracehttp） | https://github.com/open-telemetry/opentelemetry-go | v1.44.0 | Apache-2.0 | 否 | 管理后端自埋点：TracerProvider、有界 BatchSpanProcessor、OTLP/HTTP trace exporter（server/internal/apm/selftelemetry.go，server/go.mod 直接依赖） | [licenses/opentelemetry-go/LICENSE](licenses/opentelemetry-go/LICENSE) |
| otelhttp（opentelemetry-go-contrib） | https://github.com/open-telemetry/opentelemetry-go-contrib | v0.69.0 | Apache-2.0 | 否 | 管理 API HTTP 中间件埋点（contrib v0.69.x 与 otel v1.44.x 官方配套组合） | [licenses/opentelemetry-go-contrib/LICENSE](licenses/opentelemetry-go-contrib/LICENSE) |
| otel/sdk/metric + otlpmetrichttp（opentelemetry-go） | https://github.com/open-telemetry/opentelemetry-go | v1.44.0 | Apache-2.0 | 否 | 管理后端自埋点 metrics（阶段3）：MeterProvider + 30s 周期 OTLP/HTTP metric exporter（server/internal/apm/selftelemetry.go，server/go.mod 直接依赖） | [licenses/opentelemetry-go/LICENSE](licenses/opentelemetry-go/LICENSE) |
| instrumentation/runtime（opentelemetry-go-contrib） | https://github.com/open-telemetry/opentelemetry-go-contrib | v0.69.0 | Apache-2.0 | 否 | Go runtime 指标采集（go.goroutine.count / go.memory.* / go.config.gogc / go.processor.limit / go.schedule.duration；与 otelhttp 同 contrib 配套版本 v0.69.0） | [licenses/opentelemetry-go-contrib/LICENSE](licenses/opentelemetry-go-contrib/LICENSE) |

## 云 API Observation 事件总线新增组件

| 软件名称 | 项目来源 | 锁定版本 | 许可证 | 是否修改 | 使用方式 | 许可证文件位置 |
|---------|---------|---------|--------|---------|---------|---------------|
| Apache Kafka | https://github.com/apache/kafka | 4.1.2@sha256:5cc2a2fd93fa2687b44015eee04fb2c3edd9e526bd64bf8bec5ff1e268772e0e | Apache-2.0 | 否 | 中心 API Observation 事件总线（KRaft，无 ZooKeeper） | [licenses/apache-kafka/LICENSE](licenses/apache-kafka/LICENSE) |
| franz-go | https://github.com/twmb/franz-go | v1.21.0 | BSD-3-Clause | 否 | 管理后端 Kafka 生产者/消费者客户端 | [licenses/franz-go/LICENSE](licenses/franz-go/LICENSE) |
| Byte Buddy | https://github.com/raphw/byte-buddy | 1.17.8 | Apache-2.0 | 否 | Java 云 API 进程内探针插桩，随 Agent Jar 分发 | [licenses/byte-buddy/LICENSE](licenses/byte-buddy/LICENSE)、[NOTICE](licenses/byte-buddy/NOTICE) |
| Spring Framework | https://github.com/spring-projects/spring-framework | 6.2.11 | Apache-2.0 | 否 | Java 探针 Spring MVC/RestTemplate 编译 API；provided，不打入 Agent Jar | [licenses/spring-framework/LICENSE.txt](licenses/spring-framework/LICENSE.txt) |
| OpenTelemetry Java API | https://github.com/open-telemetry/opentelemetry-java | 1.44.0 | Apache-2.0 | 否 | Java 探针读取现有 Trace Context；provided，不打入 Agent Jar | [licenses/opentelemetry-java/LICENSE](licenses/opentelemetry-java/LICENSE) |

## 许可证原文

各组件许可证原文存放于 `licenses/` 目录下，按组件名称分目录保存。阶段0先建立目录结构，正式引入组件时同步归档对应许可证文件。

## 安全风险说明

- 使用第三方组件即引入其上游安全风险，需定期跟踪 CVE；
- 每次版本升级后重新核查许可证和兼容性；
- 发现高危漏洞时优先升级，无法升级时评估替代方案。

## 间接/传递依赖口径声明

本文件登记直接引入与影响合规判定的关键第三方组件；间接/传递依赖的完整清单（名称、版本、许可证）以 SBOM 为准：`docs/SBOM.cyclonedx.json` 与 `docs/SBOM.spdx.json`（由 `scripts/generate-sbom.sh` 生成，随发布更新）。已入 SBOM 的关键间接依赖（go-humanize、x/image、go-chart、freetype-go 等）已在上文各表补登，其余传递依赖不再逐条罗列。

## 版权归属

九章WEB应用智能防护系统V2.0自主代码版权归聚信得仁所有。第三方组件版权归其各自作者和贡献者所有。
