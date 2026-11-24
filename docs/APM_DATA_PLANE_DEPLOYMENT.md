# APM 阶段2 数据面部署手册（ClickHouse + OTel Collector）

> 文档状态：阶段2 数据面交付物（纯配置与文档，无 Go 代码）
> 编写日期：2026-08-30
> 依据：`docs/BUSINESS_PERFORMANCE_APM_DESIGN.md`（§5 架构 / §12 脱敏 / §13 采样限流 / §14 容量与保留 / §15.2 ClickHouse / §19 部署拓扑）、`docs/APM_STAGE0_ADR.md` D1/D2/D3

## 1. 架构（文字图）

```text
业务宿主机/容器                          中央数据面（管理面同侧）
┌─────────────────────────┐             ┌──────────────────────────────┐
│ 业务应用 + OTel Agent/SDK │             │ 中央 Collector Gateway        │
│         │ OTLP           │             │  mTLS 认证 / 二层脱敏 /       │
│         ▼ 127.0.0.1 或   │   OTLP/mTLS │  尾采样 / 批处理 / 背压        │
│ 本地 Collector           │ ──────────► │         │                   │
│  宿主属性/首层脱敏/       │             │         ▼                   │
│  有界内存队列/有界重试     │             │  ClickHouse（apm 库）        │
└─────────────────────────┘             │  otel_traces + 分钟/小时/天聚合 │
                                        └──────────────┬───────────────┘
                                                       ▼
                                        APM 查询/控制台（阶段2 后续工作包接入）
```

fail-open 纪律（设计 §19.4/§20）：本地 Collector 不可达时 Agent 有界缓冲后丢弃；中央
Collector 或 ClickHouse 不可达时本地/中央队列限量重试、超限丢弃并计数。**遥测链路任何
故障都不得影响 WAF 转发与业务请求**——本包不引入磁盘无限队列、不做同步等待。

## 2. 组件清单与版本（锁定值）

| 组件 | 镜像（tag + index digest） | 许可证 | 配置 |
|---|---|---|---|
| ClickHouse 25.8（LTS） | `clickhouse/clickhouse-server:25.8-alpine@sha256:87e0a5b72f5465b18eacca7c76850e7ff551c9795c50e451f5646299e5e24146` | Apache-2.0 | schema：`deployment/apm/clickhouse/` |
| OTel Collector contrib 0.154.0 | `otel/opentelemetry-collector-contrib:0.154.0@sha256:b3079f45e19bdb7326bf49cdddce6cf60dfd865138db39f2733ea48ab17bc4cb` | Apache-2.0 | `deployment/apm/collector/local-collector.yaml` / `central-gateway.yaml` |

digest 于 2026-08-30 经 `docker buildx imagetools inspect` 实测；平台子摘要与升级哨兵
见 `docs/DEPENDENCIES.md`「APM 阶段2 数据面新增组件」。许可证登记见 `THIRD_PARTY_NOTICES.md`。

## 3. 启动顺序

```bash
# 1. 准备 mTLS 证书（占位目录 deployment/apm/pki/，由部署侧私有 CA 签发）：
#    ca.crt / server.crt / server.key（中央）；client.crt / client.key（本地）
# 2. 准备口令环境变量：
export CLICKHOUSE_ADMIN_PASSWORD='<强随机>'
export CLICKHOUSE_APM_WRITER_USER='apm_writer'          # 首次可用 default 初始化后再建
export CLICKHOUSE_APM_WRITER_PASSWORD='<强随机>'
# 3. 中央数据面（ClickHouse 首次启动自动执行 deployment/apm/clickhouse/*.sql 建表）：
docker compose -f docker-compose.apm.yml --profile central up -d
# 4. 同机部署时将管理面 api 容器接入 APM 数据面内网（首次启用执行一次；后续官方升级、回滚与
#    PCAP 重建脚本会自动保留该网络并探测接入同机运行中的 jiuzhang-apm-clickhouse，且后端会在
#    15 秒冷却后自动重连 ClickHouse，不再需要重启 api）：
docker network connect jiuzhang-apm_apm-data jiuzhang-api
#    随后在「系统设置 → APM 性能监控」或 .env 中配置 APM_CLICKHOUSE_DSN（如
#    clickhouse://default:<口令>@clickhouse:9000/apm）。
# 5. 本地 Collector（生产通常为 systemd 直装，compose 仅为可运行参考）：
docker compose -f docker-compose.apm.yml --profile local up -d
```

顺序依赖：ClickHouse 先就绪（compose 已用 `depends_on: service_healthy` 约束中央
Collector）；本地 Collector 可独立启动，中央不可达时本地有界重试（fail-open）。

## 4. 健康检查

| 组件 | 检查方式 | 端口 |
|---|---|---|
| ClickHouse | `GET /ping`（compose healthcheck 内置） | 127.0.0.1:8123 |
| 中央 Collector | health_check 扩展 + Prometheus 自监控 | 127.0.0.1:13133 / 8888 |
| 本地 Collector | health_check 扩展 + Prometheus 自监控 | 127.0.0.1:13133 / 9888 |

注意：contrib 镜像为 distroless（无 shell），容器内无法执行 healthcheck 命令，须从外部探测。
关键自监控指标：`otelcol_receiver_accepted_spans`、`otelcol_exporter_sent_spans`、
`otelcol_exporter_enqueue_failed_spans`（丢弃）、`otelcol_processor_tail_sampling_*`、
`otelcol_process_memory_rss`（对照 memory_limiter）。

## 5. 备份与 TTL 运维

- TTL 层级（schema 内建，设计 §14.2）：正常 trace 7 天；错误/慢(≥2s)/WAF 高风险 14 天；
  分钟聚合 30 天、小时 180 天、天 365 天；trace 检索表 14 天。整分区删除
  （`ttl_only_drop_parts = 1`），无需手工清理任务。
- 备份：聚合表可由原始表重建，备份优先级低于 `apm.otel_traces`；单副本交付形态用
  文件系统快照或 `BACKUP ... TO Disk`。容量估算公式与磁盘下限见
  `deployment/apm/clickhouse/README.md`（引用设计 §14.1）。
- 敏感泄漏处置（设计 §12.2）：按租户/时间/trace ID 执行 `ALTER TABLE ... DELETE`
  mutation，纳入操作审计。

## 6. 容量规划入口

1. 先按 `deployment/apm/clickhouse/README.md` 的公式估算（请求速率 × 采样率 × span 数）；
2. 阶段2 上线前完成 ADR §7 入口门禁：目标吞吐下 span 大小与 ClickHouse 写入实测，
   未实测前不承诺性能数字；
3. 多实例扩容：中央 Collector 无状态部分可水平扩展，但 tail_sampling 必须在前级用
   loadbalancing exporter 按 trace ID 一致性路由（`central-gateway.yaml` 内注释）。

## 7. 遗留风险与待办

- mTLS 证书为占位路径（`deployment/apm/pki/`），私有 CA 签发与轮换流程待部署侧落地；
- 每证书限流 contrib 无内建实现，当前为全局 memory_limiter + 有界队列兜底，按证书
  配额列入 APM Ingest/自研 processor 工作包；
- `jiuzhang.waf_action=BLOCK` 高风险保留依赖阶段2 网关埋点写入该 span 属性，未接入前
  该策略与 TTL 条件自然不命中（无副作用）；
- ClickHouse 专用写入账号 `apm_writer` 的建号 SQL 见 `deployment/apm/clickhouse/README.md`，
  首次初始化后用 `default` 管理员执行（阶段3 起须追加 otel_metrics_* 五表 INSERT 授权）；
- 运行时指标（metrics 管道）已在阶段3 落地：local/central Collector 均挂 metrics 管道，
  schema 为 `deployment/apm/clickhouse/003_metrics.sql`（otel_metrics_* 五表，原始点 TTL 7 天，
  小时聚合留待后续阶段）；日志信号按设计排期在后续阶段引入，本包不含 logs 管道。

## 8. 九章组件自埋点启用方式（阶段2 收尾）

两个自埋点开关均**默认关闭**，关闭时零开销零行为变化；均遵循遥测 fail-open
纪律（初始化/导出失败仅 Warn 降级，绝不影响管理 API 与 WAF 转发）。

### 8.1 管理后端（jiuzhang-server）

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `APM_SELF_TELEMETRY_ENABLED` | `false` | 自埋点总开关（traces + metrics 双信号）；开启时以 otelhttp 包裹管理 API Handler（仅管理面，不影响网关），并启动 Go runtime 指标采集（30s 周期导出，阶段3） |
| `APM_OTLP_ADDR` | `http://127.0.0.1:4318` | OTLP/HTTP 导出端点（本地 Collector；traces/metrics 同地址） |
| `DEPLOY_ENV` | `prod` | resource `deployment.environment.name` |

resource 固定 `service.name=jiuzhang-server`、`service.instance.id=主机名-PID`（阶段3 起，
运行时指标按实例分组的标识）、`service.version` 取 Go build info 主模块
版本（本地开发构建如实标注 `unknown`）；propagator 为 W3C TraceContext；导出经有界
BatchSpanProcessor（队列 2048 / 批 512 / 单次导出超时 10s）；metrics 经 PeriodicReader
30s 周期导出。改动后重启管理服务生效。

阶段3 自埋点 Go runtime 指标集（contrib instrumentation/runtime v0.69.0，
scope `go.opentelemetry.io/contrib/instrumentation/runtime`）：
`go.goroutine.count`、`go.memory.used`（按 `go.memory.type`=other/stack 拆两序列）、
`go.memory.allocated`、`go.memory.allocations`、`go.memory.gc.goal`、`go.memory.limit`
（未设 GOMEMLIMIT 时不上报）、`go.processor.limit`、`go.config.gogc`（gauge/sum 类）+
`go.schedule.duration`（直方图，经 Producer 附带）。经 Collector metrics 管道落
`apm.otel_metrics_sum`/`apm.otel_metrics_histogram` 表，查询接口为
`GET /api/v1/apm/runtime`（权限 `apm.runtime.read`）。

### 8.2 防护网关（Caddy 原生 tracing）

| 配置项 | 默认 | 说明 |
|---|---|---|
| `GATEWAY_TRACING_ENABLED`（管理后端 env） | `false` | 发布开关：开启后生成的 Caddy JSON 在每条路由链首注入 `http.handlers.tracing` handler（span 名 `jiuzhang-gateway`）；**重新发布后生效** |
| 网关进程 `OTEL_EXPORTER_OTLP_ENDPOINT` 等 `OTEL_*` | 缺省 = OTLP http/protobuf → `127.0.0.1:4318` | Caddy 2.11 tracing 模块的 exporter/采样**不在 JSON 内表达**，经网关进程标准 OTel 环境变量配置（autoexport/autoprop）；缺省采样 `parentbased_always_on`（100% 头采）。改动后重启网关进程生效 |

开启后 `{http.vars.trace_id}` / `{http.vars.span_id}` 占位符在网关日志与下游 handler
可用（本阶段未改访问日志格式，关联字段接线列入后续工作包）。

### 8.3 预期链路与性能口径

```text
jiuzhang-server（otelhttp span）        网关 Caddy（http.handlers.tracing span）
        │ OTLP/HTTP                             │ OTLP/HTTP（autoexport 默认）
        ▼                                       ▼
      本地 Collector（127.0.0.1:4318，首层脱敏/有界队列）
        │ OTLP/mTLS
        ▼
      中央 Collector Gateway（尾采样决策：错误/慢/WAF 高风险保留）→ ClickHouse
```

性能开销按基线模式低档采样纪律（设计 §13）：管理 API QPS 极低，100% 头采无压力；
网关侧为大流量数据面，头采 100% 仅产生 span 生成与有界批量导出开销（量级对照设计
§21.1 Agent 基线），**采样保留决策集中在中央 Collector 尾采样**（网关丢弃的 trace 无法
恢复，故头采不做概率裁剪）；任一环节故障均有界丢弃并计数，不影响转发。两端接入后
应按 ADR §7 入口门禁实测目标吞吐下的开销再承诺数字。

## 9. 阶段5 加固交付物入口（HA 与备份恢复）

- **HA compose 编排**：`deployment/apm/docker-compose.ha.yml`（独立 project，不改本手册
  单副本形态）——中央侧双层：无状态路由层 + 采样层双副本；
- **路由层配置**：`deployment/apm/collector/central-router.yaml`（loadbalancing
  exporter：traces 按 traceID 一致性哈希、metrics 按 service.name 哈希，DNS 解析器
  10s 重解析；tail sampling 多实例硬约束的实现，设计 §13.2/§19.4）；
- **ClickHouse 双副本**：`deployment/apm/clickhouse/ha/001_ha_replicated.sql`
  （ReplicatedMergeTree + ON CLUSTER 变体，与 001 二选一）+
  `deployment/apm/clickhouse/README.md`「HA（双副本 ReplicatedMergeTree，阶段5）」节
  （keeper/macros/写入入口/运维差异）；
- **K8s 清单样例**：`deployment/apm/k8s/daemonset-local-collector.yaml`（DaemonSet +
  hostPort）、`deployment/apm/k8s/deployment-central-collector.yaml`（双层 Deployment +
  PDB + 反亲和 + resources/probes + headless Service）；
- **备份恢复**：`deployment/apm/backup.md`（ClickHouse 原生 BACKUP/RESTORE 实测命令、
  PostgreSQL apm_* 控制面表现状与临时纪律、恢复演练清单）。

## 10. 故障降级行为对照（设计 §20 落地核对，2026-08-31）

逐条核对设计 §20 九类故障场景与当前交付物的实际行为。保障级别口径：
**已配置保证**=交付物配置/代码中已有明确机制；**依赖部署纪律**=机制具备但需部署侧
按本文档操作（证书签发、调度、告警接入等）；**待实测**=机制具备但未经故障注入实测，
或能力在后续工作包。

| 场景（设计 §20） | 设计预期行为 | 当前交付物实际行为与证据 | 保障级别 |
|---|---|---|---|
| Agent 初始化失败 | 应用继续启动，默认不阻断 | 管理后端自埋点初始化/导出失败仅 Warn 降级（`server/internal/apm/selftelemetry.go`，§8.1）；网关 tracing 经 OTel autoexport 有界批量导出，导出器初始化失败不影响转发（§8.2）。业务语言 Agent 未交付（阶段4 范围） | 已配置保证（平台两组件）；业务 Agent 交付后待实测 |
| 本地 Collector 不可达 | Agent 有界缓冲后丢弃，不同步等待 | 管理后端 BatchSpanProcessor 队列 2048/批 512/单次导出 10s，满即丢弃（§8.1）；网关 autoexport 同为有界批量。均异步非阻塞 | 已配置保证；丢弃计数端到端待实测 |
| 中央 Collector 不可达 | 本地队列限量重试 | `collector/local-collector.yaml`：`retry_on_failure.max_elapsed_time=300s` + `sending_queue.queue_size=2000`（有界内存，满即丢弃并计入 `otelcol_exporter_enqueue_failed_spans`），无磁盘队列 | 已配置保证（配置级）；故障注入待实测 |
| ClickHouse 不可用 | 中央队列限量缓存，查询显示数据延迟 | `collector/central-gateway.yaml`：clickhouse exporter `max_elapsed_time=600s` + `queue_size=5000` 有界缓存，超限丢弃并计数；「查询显示数据延迟」提示属查询接口工作包，未实现 | 已配置保证（缓存/丢弃）；查询侧提示待后续工作包 |
| 管理面不可用 | 继续最后有效基线；诊断按本地截止时间停止 | 数据面（Collector/ClickHouse）与管理面故障域隔离（设计 §15.3），采集链路不依赖管理面在线；Agent「继续最后有效基线」属 Agent 生命周期管理（设计 §8.3），业务 Agent 未交付 | 已配置保证（数据面独立运行）；Agent 侧依赖后续阶段 |
| Agent/节点证书过期 | 拒绝数据并提示轮换；不回退明文 | 中央网关与路由层 receiver 设 `client_ca_file` 即强制 `RequireAndVerifyClientCert`（contrib v0.154.0 configtls），过期/未知证书握手即拒绝，不存在明文回退路径；轮换流程与到期告警依赖部署侧私有 CA 制度（`pki/` 为占位） | 已配置保证（拒绝）；轮换提示依赖部署纪律 |
| 遥测突增 | 限流、采样降级、优先保留错误/慢请求 | 两端 `memory_limiter`（本地 70%/中央 75%，spike 20%）+ 全链有界队列超限丢弃计数；`tail_sampling` 错误/慢(≥2s)/`jiuzhang.waf_action=BLOCK` 策略先于 5% 基线命中，`num_traces=100000` 硬配额兜底。每证书配额未实现（§7 遗留项） | 已配置保证（限幅与采样优先级）；洪泛用例待实测（测试计划 §24） |
| 时钟漂移 | 瀑布图校正/提示，实例产生时钟告警 | 平台侧无校正实现：span 时间戳由埋点端写入，漂移直接体现为瀑布错位；校正视图与时钟告警属查询/SLO 工作包 | 待实测；后续工作包 |
| 未部署 Agent 的下游 | 保留网关/上游 span，标记链路缺口 | 网关 tracing 开启（§8.2）后产生 `jiuzhang-gateway` span 并经 W3C TraceContext 向下游传播；下游无 Agent 时链路天然断点，span 本身保留；「部分链路」缺口标记未实现 | 已配置保证（span 保留）；缺口标记待后续工作包 |

HA 形态补充（阶段5 新增行为）：中央侧单采样实例故障时，路由层 DNS 解析器 10s
重解析收敛（`central-router.yaml` `resolver.dns.interval`），收敛窗口内发往故障实例的
span 经有界重试（120s）后丢弃计数；存活实例的尾采样决策不受影响。该行为已配置，
端到端故障注入（杀副本观察丢弃计数与采样连续性）待实测。

---

Copyright © 聚信得仁
All Rights Reserved.
