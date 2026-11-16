# 依赖许可证清单（DEPENDENCY_LICENSES）

本文档按组件逐一登记九章WEB应用智能防护系统V2.0全部第三方依赖的**锁定版本、许可证、licenses/ 归档路径**，满足阶段6 §十七开源合规要求。生成口径：

- **Go 依赖**：以 `gateway/go.mod`、`gateway/modules/jiuzhang_guard/go.mod`（gateway 子模块）、`server/go.mod`、`wdsp-agent/go.mod` 的**直接依赖**为准逐项登记；关键间接依赖（已归档 licenses/ 或影响合规判定者）单独补登；其余传递依赖以 `docs/SBOM.spdx.json` / `docs/SBOM.cyclonedx.json` 为准（由 `scripts/generate-sbom.sh` 生成）。
- **前端依赖**：以 `web/package.json` 的 dependencies 与 devDependencies **直接依赖全量**登记；锁定版本取 `web/package-lock.json` 实际安装版本（2026-09-10 核查 node_modules）。
- **Java 探针**：以 `wdsp-agent/instrumentation/java/pom.xml` 的直接依赖为准，标明随 Jar 分发、provided 或仅测试；新增组件核查日期为 2026-11-06。
- **第三方镜像**：以 `docker-compose.yml`、各级 `Dockerfile`、`deployment/docker-compose.apm.yml` 的 tag + digest 锁定值为准。
- 同步状态由 `scripts/license-audit.sh` 第 5 步校验（licenses/ 每个组件目录必须在本清单登记，本清单引用的归档路径必须真实存在），接入 `make license-audit`。

核查日期：2026-09-10。全部依赖**无 GPL / AGPL / SSPL / RSAL 组件**（freetype-go 为 FTL/GPLv2+ 双许可，本项目选择 FTL，详见文末合规结论）。

## 一、Go 依赖（直接依赖）

### 1.1 gateway 模块（gateway/go.mod）

| 依赖 | 锁定版本 | 许可证 | 用途 | 归档 |
|------|---------|--------|------|------|
| github.com/corazawaf/coraza/v3 | v3.7.0 | Apache-2.0 | WAF 检测引擎（网关与 mirrorcap 旁路采集共用） | [licenses/coraza/](../licenses/coraza/) |
| github.com/google/gopacket | v1.1.19 | BSD-3-Clause | mirrorcap 旁路抓包/TCP 重组（pcapgo AF_PACKET 纯 syscall） | [licenses/gopacket/](../licenses/gopacket/) |

### 1.2 jiuzhang_guard 子模块（gateway/modules/jiuzhang_guard/go.mod，随 gateway 构建）

| 依赖 | 锁定版本 | 许可证 | 用途 | 归档 |
|------|---------|--------|------|------|
| github.com/caddyserver/caddy/v2 | v2.11.4 | Apache-2.0 | 反向代理网关基础 | [licenses/caddy/](../licenses/caddy/) |
| github.com/corazawaf/coraza-caddy/v2 | v2.5.0 | Apache-2.0 | Coraza 的 Caddy 集成模块 | [licenses/coraza-caddy/](../licenses/coraza-caddy/) |
| github.com/valkey-io/valkey-go | v1.0.76 | Apache-2.0 | Valkey 客户端（CC 计数/临时封禁） | [licenses/valkey-go/](../licenses/valkey-go/) |
| github.com/andybalholm/brotli | v1.3.0 | MIT | gzip/Brotli 压缩响应的安全解压与重编码 | [licenses/brotli/](../licenses/brotli/) |
| go.uber.org/zap | v1.28.0 | MIT | 结构化日志 | SBOM 收录，未单独归档 |
| google.golang.org/protobuf | v1.36.11 | BSD-3-Clause | gRPC 描述符级解析（protodesc/dynamicpb） | SBOM 收录，未单独归档 |

### 1.3 server 模块（server/go.mod）

| 依赖 | 锁定版本 | 许可证 | 用途 | 归档 |
|------|---------|--------|------|------|
| github.com/ClickHouse/clickhouse-go/v2 | v2.48.0 | Apache-2.0 | APM ClickHouse 只读查询客户端 | [licenses/clickhouse-go/](../licenses/clickhouse-go/) |
| github.com/gomutex/godocx | v0.1.5 | MIT | Word（docx）报告生成 | [licenses/godocx/](../licenses/godocx/) |
| github.com/google/uuid | v1.6.0 | BSD-3-Clause | UUID 生成 | SBOM 收录，未单独归档 |
| github.com/jackc/pgx/v5 | v5.7.2 | MIT | PostgreSQL 驱动 | SBOM 收录，未单独归档 |
| github.com/jung-kurt/gofpdf/v2 | v2.17.3 | MIT | PDF 报告生成 | [licenses/gofpdf/](../licenses/gofpdf/) |
| github.com/redis/go-redis/v9 | v9.7.0 | BSD-2-Clause | Valkey（Redis 协议兼容）客户端 | SBOM 收录，未单独归档 |
| github.com/vicanso/go-charts/v2 | v2.6.10 | MIT | 报告图表服务端渲染（PNG/SVG） | [licenses/go-charts/](../licenses/go-charts/) |
| go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp | v0.69.0 | Apache-2.0 | 管理 API HTTP 中间件埋点 | [licenses/opentelemetry-go-contrib/](../licenses/opentelemetry-go-contrib/) |
| go.opentelemetry.io/contrib/instrumentation/runtime | v0.69.0 | Apache-2.0 | Go runtime 指标采集 | [licenses/opentelemetry-go-contrib/](../licenses/opentelemetry-go-contrib/) |
| go.opentelemetry.io/otel | v1.44.0 | Apache-2.0 | 自埋点 API | [licenses/opentelemetry-go/](../licenses/opentelemetry-go/) |
| go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp | v1.44.0 | Apache-2.0 | OTLP/HTTP metric exporter | [licenses/opentelemetry-go/](../licenses/opentelemetry-go/) |
| go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp | v1.44.0 | Apache-2.0 | OTLP/HTTP trace exporter | [licenses/opentelemetry-go/](../licenses/opentelemetry-go/) |
| go.opentelemetry.io/otel/sdk | v1.44.0 | Apache-2.0 | TracerProvider / BatchSpanProcessor | [licenses/opentelemetry-go/](../licenses/opentelemetry-go/) |
| go.opentelemetry.io/otel/sdk/metric | v1.44.0 | Apache-2.0 | MeterProvider + 周期导出 | [licenses/opentelemetry-go/](../licenses/opentelemetry-go/) |
| golang.org/x/crypto | v0.54.0 | BSD-3-Clause | 密码学原语 | SBOM 收录，未单独归档 |
| github.com/twmb/franz-go | v1.21.0 | BSD-3-Clause | API Observation Kafka 生产者/消费者客户端 | [licenses/franz-go/](../licenses/franz-go/) |

### 1.4 wdsp-agent 模块（wdsp-agent/go.mod）

| 依赖 | 锁定版本 | 许可证 | 用途 | 归档 |
|------|---------|--------|------|------|
| github.com/cilium/ebpf | v0.22.0 | MIT | eBPF/TC（TCX）抓包后端 | [licenses/cilium-ebpf/](../licenses/cilium-ebpf/) |
| github.com/google/gopacket | v1.1.19 | BSD-3-Clause | pcapgo AF_PACKET 抓包（与 mirrorcap 同版本） | [licenses/gopacket/](../licenses/gopacket/) |
| golang.org/x/sys | v0.45.0 | BSD-3-Clause | 系统调用封装 | SBOM 收录，未单独归档 |

### 1.5 Java 云 API 探针（wdsp-agent/instrumentation/java）

| 依赖 | 锁定版本 | 许可证 | 用途 | 归档 |
|------|---------|--------|------|------|
| net.bytebuddy:byte-buddy | 1.17.8 | Apache-2.0 | Java 字节码插桩，随 Agent Jar 分发 | [licenses/byte-buddy/](../licenses/byte-buddy/) |
| org.springframework:spring-webmvc / spring-web | 6.2.11 | Apache-2.0 | Spring MVC/RestTemplate 插桩编译 API（provided） | [licenses/spring-framework/](../licenses/spring-framework/) |
| io.opentelemetry:opentelemetry-api | 1.44.0 | Apache-2.0 | Trace Context 只读关联（provided） | [licenses/opentelemetry-java/](../licenses/opentelemetry-java/) |
| org.junit.jupiter:junit-jupiter | 5.12.2 | EPL-2.0 | Java 单元测试，不进入交付 Jar | 仅构建测试使用，无运行时传递 |

### 1.6 关键间接依赖补登（影响合规判定或已归档）

| 依赖 | 锁定版本 | 许可证 | 引入路径 | 归档 |
|------|---------|--------|---------|------|
| github.com/ClickHouse/ch-go | v0.74.0 | Apache-2.0 | clickhouse-go 底层列式协议驱动 | [licenses/ch-go/](../licenses/ch-go/) |
| github.com/wcharczuk/go-chart/v2 | v2.1.0 | MIT | go-charts 底层绘图引擎 | [licenses/go-chart/](../licenses/go-chart/) |
| github.com/golang/freetype | v0.0.0-20170609003504-e2365dfdc4a0 | FTL（双许可 FTL/GPLv2+，本项目选择 FTL） | go-chart 字体光栅化 | [licenses/freetype-go/](../licenses/freetype-go/) |
| github.com/dustin/go-humanize | v1.0.1 | MIT | godocx 间接依赖 | SBOM 收录，未单独归档 |
| golang.org/x/image | v0.0.0-20200927104501-e162460cd6b5 | BSD-3-Clause | go-chart 间接依赖 | SBOM 收录，未单独归档 |

> 其余传递依赖（cel.dev/expr、certmagic、xxhash 等）均为宽松许可证，完整清单与许可证以 SBOM 为准；SBOM 中 NOASSERTION 条目由 `scripts/license-audit.sh` 计警告并人工复核。

## 二、前端依赖（web/package.json 直接依赖全量）

### 2.1 dependencies（随产品构建分发）

| 依赖 | package.json 范围 | 锁定版本 | 许可证 | 归档 |
|------|------------------|---------|--------|------|
| @ant-design/icons | ^6.3.2 | 6.3.4 | MIT | SBOM 收录 |
| @ip-location-db/geo-whois-asn-country-mmdb | ^2.3.2026061719 | 2.3.2026061719 | CC0-1.0（含 NRO 数据 CC-BY-4.0） | [licenses/geoip-country-mmdb/](../licenses/geoip-country-mmdb/) |
| @tanstack/react-query | ^5.101.3 | 5.102.8 | MIT | SBOM 收录 |
| antd | ^6.5.1 | 6.6.3 | MIT | SBOM 收录 |
| buffer | ^6.0.3 | 6.0.3 | MIT | [licenses/buffer/](../licenses/buffer/) |
| d3-geo | ^3.1.1 | 3.1.1 | ISC | [licenses/d3-geo/](../licenses/d3-geo/) |
| dayjs | ^1.11.21 | 1.11.23 | MIT | SBOM 收录 |
| echarts | ^6.1.0 | 6.1.0 | Apache-2.0 | [licenses/echarts/](../licenses/echarts/) |
| echarts-gl | ^2.1.0 | 2.1.0 | MIT | [licenses/echarts-gl/](../licenses/echarts-gl/) |
| i18n-iso-countries | ^7.14.0 | 7.14.0 | MIT | [licenses/i18n-iso-countries/](../licenses/i18n-iso-countries/) |
| mmdb-lib | ^3.0.3 | 3.0.3 | MIT | [licenses/mmdb-lib/](../licenses/mmdb-lib/) |
| react | ^18.3.1 | 18.3.1 | MIT | SBOM 收录 |
| react-dom | ^18.3.1 | 18.3.1 | MIT | SBOM 收录 |
| react-router-dom | ^7.18.3 | 7.18.3 | MIT | SBOM 收录 |
| topojson-client | ^3.1.0 | 3.1.0 | ISC | [licenses/topojson-client/](../licenses/topojson-client/) |
| world-atlas | ^2.0.2 | 2.0.2 | ISC（数据为 Natural Earth，公有领域） | [licenses/world-atlas/](../licenses/world-atlas/) |
| zustand | ^5.0.14 | 5.0.15 | MIT | SBOM 收录 |

### 2.2 devDependencies（仅构建/测试期使用，不随产品分发）

| 依赖 | 锁定版本 | 许可证 |
|------|---------|--------|
| @eslint/js | 9.39.5 | MIT |
| @playwright/test | 1.63.0 | Apache-2.0 |
| @testing-library/jest-dom | 6.9.1 | MIT |
| @testing-library/react | 16.3.3 | MIT |
| @types/d3-geo | 3.1.1 | MIT |
| @types/node | 26.5.0 | MIT |
| @types/react | 18.3.31 | MIT |
| @types/react-dom | 18.3.7 | MIT |
| @types/topojson-client | 3.1.5 | MIT |
| @typescript-eslint/eslint-plugin | 8.70.0 | MIT |
| @typescript-eslint/parser | 8.70.0 | MIT |
| @vitejs/plugin-react | 4.7.0 | MIT |
| eslint | 9.39.5 | MIT |
| eslint-plugin-react-hooks | 5.2.0 | MIT |
| eslint-plugin-react-refresh | 0.4.26 | MIT |
| globals | 17.12.0 | MIT |
| ioredis | 5.11.1 | MIT |
| jsdom | 25.0.1 | MIT |
| prettier | 3.9.6 | MIT |
| typescript | 5.6.3 | Apache-2.0 |
| typescript-eslint | 8.70.0 | MIT |
| vite | 6.4.3 | MIT |
| vitest | 3.2.7 | MIT |

## 三、第三方容器镜像

| 镜像 | 锁定（tag@index digest） | 许可证 | 用途 | 归档 |
|------|-------------------------|--------|------|------|
| postgres | 16.4-alpine@sha256:5660c2cb…e37e64c | PostgreSQL License | 主数据库 | [licenses/postgresql/](../licenses/postgresql/) |
| valkey/valkey | 8.1.8-alpine@sha256:94365b27…eba680885 | BSD-3-Clause | 缓存/锁/任务状态 | [licenses/valkey/](../licenses/valkey/) |
| golang | 1.25-alpine@sha256:56961d79…672c587 | BSD-3-Clause | 网关/后端构建阶段 | [licenses/other/](../licenses/other/) |
| alpine | 3.24@sha256:28bd5fe8…434943f8b | MIT | 网关/后端运行阶段 | [licenses/other/](../licenses/other/) |
| node | 24-alpine@sha256:a0b9bf06…c54fbfd | MIT | 前端构建阶段 | [licenses/other/](../licenses/other/) |
| caddy | 2.11.4-alpine@sha256:5f5c8640…d58648 | Apache-2.0 | 前端静态资源托管 | [licenses/caddy/](../licenses/caddy/) |
| clickhouse/clickhouse-server | 25.8-alpine@sha256:87e0a5b7…5e24146 | Apache-2.0 | APM 数据面存储 | [licenses/clickhouse/](../licenses/clickhouse/) |
| apache/kafka | 4.1.2@sha256:5cc2a2fd…c3648da | Apache-2.0 | API Observation 中心事件总线（KRaft） | [licenses/apache-kafka/](../licenses/apache-kafka/) |
| otel/opentelemetry-collector-contrib | 0.154.0@sha256:b3079f45…a17bc4cb | Apache-2.0 | APM 本地/中央 Collector | [licenses/otel-collector-contrib/](../licenses/otel-collector-contrib/) |
| curlimages/curl | 8.21.0@sha256:7c12af72…a64bb13 | curl License（MIT/X 类） | 配置控制器/健康检查 | [licenses/curl/](../licenses/curl/) |
| ollama/ollama | 0.9.6@sha256:f478761c…df185ce | MIT | 阶段7 AI 测试环境（仅测试，不随产品交付） | SBOM 收录，未单独归档 |

完整 digest（含单架构子摘要）见 [DEPENDENCIES.md](DEPENDENCIES.md)。

## 四、规则集、字体与数据文件

| 资产 | 锁定版本 | 许可证 | 用途 | 归档 |
|------|---------|--------|------|------|
| OWASP CRS | v4.28.0 | Apache-2.0 | 通用攻击规则集（只读挂载） | [licenses/owasp-crs/](../licenses/owasp-crs/) |
| OWASP CRS 官方排除插件（wordpress/nextcloud/phpmyadmin/drupal/dokuwiki/xenforo）与 auto-decoding-plugin（默认禁用） | 各插件 commit PINNED（见 licenses/crs-plugins/README.md） | Apache-2.0 | 应用误报排除 / ARGS 多轮解码 | [licenses/crs-plugins/](../licenses/crs-plugins/) |
| monperrus/crawler-user-agents | commit 9345a7ad（PINNED：tools/rulegen/crawler-ua/PINNED.txt） | MIT | 爬虫 UA 指纹数据（生成 scanner-fingerprints-ext.conf） | [licenses/crawler-user-agents/](../licenses/crawler-user-agents/) |
| ai-robots-txt/ai.robots.txt | commit 987266f3（PINNED：tools/rulegen/ai-crawler/PINNED.txt） | MIT | AI 爬虫 UA 清单（生成 ai-crawler-control.conf） | [licenses/ai-robots-txt/](../licenses/ai-robots-txt/) |
| vektah/gqlparser/v2 | v2.5.60（go.mod 精确锁定） | MIT | GraphQL 文档 AST 解析（NG-GQL-01，gqlast 包装层自建资源硬边界） | [licenses/gqlparser/](../licenses/gqlparser/) |
| Noto Sans CJK | noto-cjk main（sha256 见 server/assets/fonts/README.md） | OFL-1.1 | PDF 报告内嵌中文字体 | [licenses/noto-fonts/](../licenses/noto-fonts/) |
| 纯真 CZ88 IP 库（qqwry.dat） | 快照 2026-08-09（sha256:cd4ec244…） | 免费数据库，版权归纯真网络所有，无标准开源许可证（负责人决策引入，仅大屏可视化） | 离线 IPv4→城市归属 | [licenses/cz88-qqwry/](../licenses/cz88-qqwry/) |
| DB-IP City Lite（city.mmdb / city-ipv6.mmdb） | 2.3.2026060513 | CC BY 4.0（署名已履行：大屏地球面板带 "IP Geolocation by DB-IP" 链接） | 离线 IP→城市归属 | [licenses/dbip-city/](../licenses/dbip-city/) |
| geo-whois-asn-country-mmdb（country.mmdb） | 2.3.2026061719 | CC0-1.0（含 NRO 统计数据 CC-BY-4.0，需注明 nro.net） | 离线 IP→国家归属（前端回退与服务端数据出境判定） | [licenses/geoip-country-mmdb/](../licenses/geoip-country-mmdb/) |

## 五、构建/测试工具链（不随产品分发）

| 工具 | 锁定版本 | 许可证 | 用途 | 归档 |
|------|---------|--------|------|------|
| xcaddy | v0.4.5 | Apache-2.0 | Caddy 自定义构建 | [licenses/xcaddy/](../licenses/xcaddy/) |
| go-ftw | v2.4.0 | Apache-2.0 | CRS 回归测试框架 | [licenses/go-ftw/](../licenses/go-ftw/) |
| Go 工具链 | 1.25.x | BSD-3-Clause | 后端/网关编译 | [licenses/other/](../licenses/other/) |
| Maven / Eclipse Temurin 构建镜像 | maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a…858c83d237 | Apache-2.0 / 上游镜像许可证 | Java 17 探针构建与测试，不进入运行镜像 | 构建工具链，见 docs/DEPENDENCIES.md |

## 六、合规结论

1. **无 GPL / AGPL / SSPL / RSAL 组件**：全部直接依赖与镜像均为 Apache-2.0 / MIT / BSD / ISC / OFL-1.1 / CC0-1.0 / PostgreSQL License 等宽松许可证。
2. **freetype-go 为 FTL/GPLv2+ 双许可**，本项目依据双许可条款**选择 FTL**（归档原文见 [licenses/freetype-go/](../licenses/freetype-go/)），不构成 GPL 污染。
3. **非 OSI 标准许可的数据资产**：纯真 qqwry.dat 无标准开源许可证（版权归纯真网络，负责人决策引入，仅大屏可视化，不参与防护判定）；DB-IP City Lite 与 NRO 统计数据为 CC BY 4.0，署名义务已履行。
4. 许可证原文统一归档于 `licenses/` 按组件分目录保存；归档完整性、禁用许可证扫描、本清单与归档的同步核对由 `scripts/license-audit.sh`（`make license-audit`）执行，SBOM 由 `scripts/generate-sbom.sh` 生成。
5. 引入或升级任何组件时，必须同步更新本清单、[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)、[DEPENDENCIES.md](DEPENDENCIES.md) 并重跑 `make license-audit`。
