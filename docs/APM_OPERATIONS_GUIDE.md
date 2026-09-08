# APM 业务性能监控运维手册

> 适用：docs/BUSINESS_PERFORMANCE_APM_DESIGN.md 阶段1～阶段4 已落地能力——
> 无 Agent 业务性能监控（性能总览/服务性能/端点性能三页，access log 全量覆盖含前置拦截）、
> OTel 数据面（ClickHouse schema + 双层 Collector，deployment/apm/）、Agent 控制面
> （注册令牌/CA 证书/签名策略/心跳/撤销）、trace 检索与瀑布、SQL/异常/依赖/运行时/SLO 五页、
> 深度诊断会话（dry_run 预估 + confirm 创建 + kill switch）。
> 读者：交付工程师与现场运维。设计原理与边界声明见设计文档与 docs/APM_STAGE0_ADR.md，
> 接口契约真源为 server/openapi/fragments/12-apm.yaml，本文只讲怎么做。
> 排障症状索引见 docs/APM_TROUBLESHOOTING.md；客户接入步骤见 docs/APM_ONBOARDING_GUIDE.md。

---

## 1. 组件清单与端口

### 1.1 控制面（管理后端内嵌，无独立进程）

APM 控制面以 `server/internal/apm/` 模块内嵌在管理后端（jiuzhang-server）中，随管理 API 同端口
提供 `/api/v1/apm/*` 路由。控制面数据（Agent 登记、注册令牌摘要、签名策略、SLO 定义、诊断
会话）全部落 PostgreSQL（迁移 000088～000093），短期状态走 Valkey。

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `APM_ENABLED` | `false` | APM 总开关；关闭时 `/api/v1/apm/*` 挂 503 降级 stub，前端菜单按 `apm_enabled` 能力隐藏。**亦可在「系统设置 → APM 性能监控」界面配置，界面值优先且立即生效（无需重启），本变量仅为兜底** |
| `APM_CLICKHOUSE_DSN` | 空 | ClickHouse 连接串；空 = 纯无 Agent 模式，trace 检索/瀑布/SQL/异常/依赖/运行时如实降级为空页（不返回 500）。**亦可在「系统设置 → APM 性能监控」界面配置（不回显原文），界面值优先且保存后立即重建连接，本变量仅为兜底** |
| `APM_COLLECTOR_ADDR` | 空 | 下发给 Agent 的 OTLP Collector 地址（注册响应字段；空串 = 数据面未就绪，如实返回） |
| `APM_AGENT_CERT_TTL_HOURS` | 72 | Agent 客户端证书有效期（小时，合法区间 24～168，越界装配侧夹紧） |
| `APM_AGENT_OFFLINE_MINUTES` | 10 | 心跳超时多少分钟判定 Agent OFFLINE（查询侧推导，不落库） |
| `APM_SELF_TELEMETRY_ENABLED` | `false` | 管理后端自埋点总开关（traces + Go runtime metrics 双信号；仅包裹管理 API Handler，不影响网关） |
| `APM_OTLP_ADDR` | `http://127.0.0.1:4318` | 自埋点 OTLP/HTTP 导出端点（指向本地 Collector） |
| `GATEWAY_TRACING_ENABLED` | `false` | 发布开关：开启后生成的 Caddy JSON 在每条路由链首注入 `http.handlers.tracing`；**重新发布后生效**；exporter/采样由网关进程 `OTEL_*` 环境变量控制 |

上述 env 改动后重启管理后端生效；`GATEWAY_TRACING_ENABLED` 还需触发一次配置发布。

### 1.2 数据面组件（deployment/apm/，docker-compose.apm.yml）

| 组件 | 镜像（tag + digest 双锁） | 部署位置 | 端口 |
|---|---|---|---|
| ClickHouse 25.8（LTS） | `clickhouse/clickhouse-server:25.8-alpine@sha256:87e0a5b7…e24146` | 中央数据面（管理面同侧），profile `central` | HTTP 8123（仅回环，运维/查询入口）；native 9000（仅 compose 内网，供中央 Collector 写入，不暴露宿主） |
| 中央 Collector Gateway 0.154.0 | `otel/opentelemetry-collector-contrib:0.154.0@sha256:b3079f45…17bc4cb` | 中央数据面，profile `central` | OTLP gRPC 4317 / HTTP 4318（mTLS，按内网 ACL 收敛）；health_check 13133、Prometheus 自监控 8888（均仅回环） |
| 本地 Collector 0.154.0 | 同上镜像 | 业务宿主机/容器侧，profile `local`（生产多为 systemd 直装） | OTLP gRPC 4317 / HTTP 4318（仅回环，Agent 只允许本机连接）；health_check 13133、Prometheus 自监控 9888（均仅回环） |

- 完整 digest、平台子摘要与升级哨兵见 docs/DEPENDENCIES.md「APM 阶段2 数据面新增组件」。
- contrib 镜像为 distroless（无 shell），容器内无法执行 healthcheck 命令，**必须从外部探测**
  13133/8888 端口。
- 内存基线：中央 Collector 容器 2G（memory_limiter 75% + 20% spike）；本地 Collector 512M
  （70% + 20% spike）。
- mTLS 证书为占位路径 `deployment/apm/pki/`，由部署侧私有 CA 签发（中央 server.crt/
  server.key/ca.crt；本地 client.crt/client.key/ca.crt），私钥权限 0600；签发与轮换流程
  待部署侧落地（如实边界，见 docs/APM_DATA_PLANE_DEPLOYMENT.md §7）。

### 1.3 网关侧 trace 开关（如实口径）

网关 `jiuzhang_guard` 已实现 W3C trace 上下文处理（`trace_trust_external` /
`trace_inject_upstream` 两个字段级开关，默认均为 false：不信任外部 traceparent、不向上游
注入）。**当前版本发布侧恒按 false 下发，取值来源尚未接线管理面设置**（见
server/internal/gatewayconfig/guard.go 字段注释）——即客户侧暂无开启入口，业务服务收到的
请求默认不含网关注入的 traceparent。后续管理面接线工作包完成后，需按 ADR §7 入口门禁做
端到端传播实测。

---

## 2. 启动/停止顺序

### 2.1 启动顺序

```bash
# 0. 前置：签发 mTLS 证书到 deployment/apm/pki/；准备口令
export CLICKHOUSE_ADMIN_PASSWORD='<强随机>'
export CLICKHOUSE_APM_WRITER_USER='apm_writer'          # 首次可用 default 初始化后再建
export CLICKHOUSE_APM_WRITER_PASSWORD='<强随机>'

# 1. 中央数据面：ClickHouse 首次启动（空数据卷）自动执行 deployment/apm/clickhouse/*.sql 建表；
#    compose 已用 depends_on: service_healthy 约束中央 Collector 晚于 ClickHouse 就绪
docker compose -f deployment/docker-compose.apm.yml --profile central up -d

# 2. 本地 Collector（生产通常 systemd 直装，compose 仅为可运行参考）；中央不可达时本地有界重试
docker compose -f deployment/docker-compose.apm.yml --profile local up -d

# 3. 管理后端：配置 APM_ENABLED=true、APM_CLICKHOUSE_DSN 等后启动/重启；
#    APM_CLICKHOUSE_DSN 为空时保持纯无 Agent 模式，不阻塞启动

# 4. 业务侧 Agent：注册令牌 → 注册 → 按策略上报（见 docs/APM_ONBOARDING_GUIDE.md）
```

顺序依赖只有一条硬约束：**ClickHouse 先于中央 Collector 就绪**。本地 Collector 可独立
启动；管理面 APM 查询对 ClickHouse 故障降级（空页 + 提示），不返回 500。

### 2.2 停止顺序

反向执行，遥测链路任何停机都不得影响 WAF 转发与业务请求（fail-open 纪律）：

1. 先停业务侧 Agent/本地 Collector（Agent 有界缓冲后丢弃，不同步等待）；
2. 再停中央 Collector（本地队列限量重试，超限丢弃并计数）；
3. 最后停 ClickHouse；
4. 管理面无需停：数据面不可用时 APM 页面如实降级。若需整体停用 APM，置
   `APM_ENABLED=false` 重启管理后端即可，现有访问日志聚合、系统健康、WAF 防护与
   WDSP 页面行为不变（验收 §25.4）。

---

## 3. 健康检查（自监控指标与页面对应关系）

### 3.1 组件级健康检查

| 组件 | 检查方式 | 通过标准 |
|---|---|---|
| ClickHouse | `curl http://127.0.0.1:8123/ping`（compose healthcheck 内置） | 返回 `Ok.` |
| 中央 Collector | `curl http://127.0.0.1:13133/`（health_check 扩展） | 200 |
| 本地 Collector | `curl http://127.0.0.1:13133/` | 200 |
| 管理后端 APM 查询 | 调用链检索页或 `GET /api/v1/apm/trace-search` | 正常返回；CH 不可用时空页 + `data_source=agentless` + message 提示（不 500） |

### 3.2 关键自监控指标 → 现状页面对应关系

| 关心什么 | 看哪里 | 说明 |
|---|---|---|
| 全量访问日志采集链路是否停滞 | 「系统运维 → 运行监控」EVENT_COLLECTOR 项（accesslog-01 链路，断点名 `accesslog_full`） | 断点滞后超阈值判 DEGRADED 并触发 `EVENT_COLLECTOR_LAG` 告警；`logging.access_log_enabled` 关闭时不判停滞（正常态） |
| 端点级聚合新鲜度 | 「业务性能 → 服务性能」数据时间列（`last_seen_at`） | 为 null 表示窗口内无流量；分钟聚合每分钟重算当前与上一分钟桶 |
| Agent 是否在线 | 「业务性能 → Agent 管理」状态/最后心跳列；「服务性能」观测模式列（Agent 在线 x/y） | OFFLINE 由查询侧按心跳超 `APM_AGENT_OFFLINE_MINUTES`（默认 10 分钟）推导；REVOKED 不计入总数 |
| 中央 Collector 接收/写出/丢弃 | Prometheus `127.0.0.1:8888`：`otelcol_receiver_accepted_spans`、`otelcol_exporter_sent_spans`、`otelcol_exporter_enqueue_failed_spans`（丢弃）、`otelcol_processor_tail_sampling_*`、`otelcol_process_memory_rss`（对照 memory_limiter） | 丢弃计数持续增长 = 背压或下游故障，按 §8.4 与排障手册处置 |
| 本地 Collector 队列与丢弃 | Prometheus `127.0.0.1:9888`（同名指标） | 队列满即丢弃并计数，绝不无限占用业务主机磁盘/内存 |
| ClickHouse 存储健康 | `system.parts`（活跃分区）、`system.mutations`（积压）、merge 积压、磁盘水位 | 见 deployment/apm/clickhouse/README.md 运维要点 |
| trace 数据面可用性 | 「业务性能 → 调用链检索」页 | CH 未配置/不可用时页面显示降级提示与原因（message 字段） |
| 诊断会话实时状态 | 「业务性能 → 诊断中心」会话列表（30 秒轮询）+ kill switch 状态条 | 会话四态 ACTIVE/EXPIRED/STOPPED/KILLED |

### 3.3 无 Agent 侧数据源口径（排障时先分清两条管道）

- **管道 A（端点级）**：guard 全量访问日志 `access-full.jsonl` → accesslog-01 采集器 →
  `access_logs` 表 → 端点级分钟聚合（`http_endpoint_requests_total` /
  `http_endpoint_duration_ms` / `http_endpoint_ttfb_ms`，Top-200 + `__OTHER__` 护栏）。
  **仅 `logging.access_log_enabled=true` 时产出**（默认关，不翻转存量部署）。
- **管道 B（应用级）**：Caddy 原生 access.log → 应用级分钟/小时聚合（`http_requests_total` /
  `http_request_duration_ms`），**默认常开**，不受上述开关影响。

---

## 4. 容量规划

### 4.1 无 Agent 侧（PostgreSQL，阶段1 口径）

```text
access_logs 行/天   = 请求速率 × 86400（含被拦截请求，拦截通常占 <5%）
端点聚合行/天上限   ≈ min(应用数 × Top-200 端点, 实际端点数) × 1440 分钟 × 状态码类别数
```

参照（非性能承诺）：1000 req/s 全开时 `access_logs` ≈ 8640 万行/天，沿用既有 7 天保留与
分批清理（`logging.retention_days`，合法区间 1～90 天）；端点分钟聚合每应用每天
≤ 200×1440×3 ≈ 86 万行上限（实际远小于此）。`metric_minute_aggregates` 既有 30 天
保留不变。开启 `logging.access_log_enabled` 前应按现网请求速率套用上行公式复核磁盘。

### 4.2 Agent 数据面（ClickHouse，设计 §14.1 公式）

```text
spans_per_second    = 请求速率 × trace 采样率 × 每 trace 平均 span 数
raw_bytes_per_day   = spans_per_second × 平均每 span 压缩后字节 × 86400
physical_bytes      = raw_bytes_per_day × 副本系数 × 保留天数
```

规划示例（非性能承诺）：1000 req/s、5% 采样、每 trace 10 span、每 span 压缩后 300 字节
→ 约 500 span/s ≈ 12.96 GB/天（单副本）；双副本约 25.92 GB/天。按本包 TTL 粗算磁盘下限：

```text
disk ≥ raw_bytes_per_day × (7 + 7 × 错误/慢/高风险占比) × 副本系数 × 1.4
     + 分钟/小时/天聚合体量（通常 << 原始层）
```

原始 span 7 天 + 错误/慢（≥2s）/WAF 高风险 14 天 + 聚合层与索引/合并临时空间，统一预留
30%～50% 安全余量。

**实测门禁（如实声明）**：阶段2 上线前须在目标吞吐下实测 span 大小与 ClickHouse 写入速率
（ADR §6/§7 入口门禁），未实测前不承诺性能数字；中央 Collector 尾采样基线 5% 等参数同样
需按实测结果校准。

### 4.3 扩容要点

- 中央 Collector 无状态部分可水平扩展；**tail_sampling 必须在前级用 loadbalancing
  exporter 按 trace ID 一致性路由**（`routing_key: traceID`），否则同一 trace 的 span
  落到不同决策实例导致链路决策错乱（`central-gateway.yaml` 内注释）。
- ClickHouse 副本/分片策略按部署规模确定；控制面与数据面故障域隔离，可独立扩容。
- 每证书限流 contrib v0.154.0 无内建实现，当前为全局 memory_limiter + 有界队列兜底；
  按证书配额列入 APM Ingest/自研 processor 工作包（如实边界）。

---

## 5. TTL 与配额调整

### 5.1 ClickHouse TTL 层级（schema 内建，整分区删除 `ttl_only_drop_parts = 1`）

| 数据 | 默认保留 | 定义位置 |
|---|---:|---|
| 原始正常 trace（apm.otel_traces） | 7 天 | `001_otel_traces.sql` |
| 错误 / 慢（≥2s）/ WAF 高风险 trace | 14 天（TTL 表达式分层） | 同上 |
| trace 检索表（otel_traces_trace_id_ts） | 14 天 | 同上 |
| 服务/端点/SQL 分钟聚合 | 30 天 | `002_aggregates.sql` |
| 小时聚合 | 180 天 | 同上 |
| 天聚合 | 365 天 | 同上 |
| 异常指纹 | 30 天 | 同上 |
| 运行时指标原始点（otel_metrics_* 五表） | 7 天（小时聚合留待后续阶段） | `003_metrics.sql` |

**调整方式**：不直接改 DDL 文件后重跑（全部语句 `IF NOT EXISTS`，不会升级已建表）。修改
TTL 走 `ALTER TABLE ... MODIFY TTL` 并纳入迁移评审；紧急清理按分区：
`ALTER TABLE apm.otel_traces DROP PARTITION 'YYYY-MM-DD';`；敏感泄漏处置按租户/时间/
trace ID 执行 `ALTER TABLE ... DELETE WHERE ...`（mutation，异步，纳入操作审计）。

### 5.2 PostgreSQL 侧保留

- `access_logs`：系统设置 `logging.retention_days`（默认 7 天，1～90），到期自动分批清理。
- 诊断会话元数据与审计：按审计制度保留，**不随原始 trace 同时删除**。

### 5.3 采样与队列配额（deployment/apm/collector/）

| 旋钮 | 位置 | 默认 | 调整建议 |
|---|---|---|---|
| 尾采样策略 | `central-gateway.yaml` tail_sampling policies | 错误 100% 保留、慢 ≥2000ms 全留、`jiuzhang.waf_action=BLOCK` 优先保留、正常基线 5% | 按容量实测调 baseline 百分比；慢阈值与 ClickHouse 慢 TTL 阈值（2s）保持一致 |
| 尾采样状态容量 | 同上 `num_traces` / `expected_new_traces_per_sec` | 100000 / 1000 | 按目标吞吐 × decision_wait（10s）推算 |
| 批量 | 中央 `batch` 1024/2048；本地 512/1024 | 见配置 | 防单批过大导致下游内存尖峰 |
| 有界发送队列 | 中央 `sending_queue` 5000、重试 600s 上限；本地 2000、重试 300s 上限 | 见配置 | 禁止改用 file_storage 磁盘无限队列（fail-open 红线） |
| 内存限幅 | memory_limiter（中央 75%+20%，本地 70%+20%） | 相对容器上限 | 与容器 memory limit 联动调整 |
| 头采 | 网关/自埋点侧 `parentbased_always_on`（100%） | — | 采样保留决策集中在中央尾采；头采丢弃的 trace 无法恢复，不要在 Agent 侧做概率裁剪 |

### 5.4 告警阈值在线调整（apm_alert 组）

系统设置 `apm_alert` 组四个键（迁移 000089 已种子化并登记白名单，可经系统设置 Update
API/页面在线调整；非法值消费侧回退默认）：

| 键 | 默认 | 含义 | 合法区间 |
|---|---|---|---|
| `endpoint_p95_ms` | 2000 | 端点 p95 耗时告警阈值（毫秒） | (0, 600000] |
| `endpoint_error_rate` | 0.2 | 端点 5xx 错误率告警阈值 | (0, 1] |
| `min_requests` | 60 | 窗口最小请求量护栏（防低流量误报） | (0, 1000000] |
| `sustain_minutes` | 3 | 持续超阈分钟桶数护栏 | [1, 5]（评估窗口固定 5 分钟） |

---

## 6. 备份与恢复入口

- **ClickHouse 数据面**：备份/恢复/TTL 运维以 `deployment/apm/clickhouse/README.md`
  「备份」节为准——单副本交付形态用 `BACKUP TABLE apm.* TO Disk(...)` 或文件系统快照；
  聚合表可由原始表重建，备份优先级低于 `apm.otel_traces`。恢复后将聚合表从原始表重算。
- **控制面（PostgreSQL）**：`apm_agents`/`apm_agent_policies`/`apm_slos`/
  `apm_diagnostic_sessions`/注册令牌摘要等随平台既有备份恢复体系（「系统运维 → 备份
  恢复」与 `ops/backup`）一并保护，**不随 ClickHouse 备份**。
- 灾难演练、10 倍突发与网络分区场景属阶段5 测试范围，演练结论以实测记录为准。

---

## 7. 升级与回滚

### 7.1 升级纪律

1. 镜像升级必须 tag + multi-arch index digest 双锁， digest 经 `docker buildx imagetools
   inspect` 实测后登记 docs/DEPENDENCIES.md 与 THIRD_PARTY_NOTICES.md；
2. Collector 升级前对照上游版本（当前基线 contrib v0.154.0）的 clickhouse exporter DDL
   变更做兼容性回归——schema 由本包维护，`create_schema: false`，Collector 不自动建表；
3. ClickHouse 升级前验证现有 DDL/TTL/物化视图在新版本可用；
4. 管理后端随版本发布正常升级（迁移 000088～000093 为加列/加表/加种子，向后兼容）。

### 7.2 数据面升级步骤

1. 升 ClickHouse 并确认 `/ping` 与 `system.parts` 正常；
2. 升中央 Collector，观察 `otelcol_exporter_enqueue_failed_spans` 无持续增长；
3. 逐台升本地 Collector（业务无感，fail-open）；
4. 回归验证：trace 检索、瀑布、SQL/异常/运行时五页与诊断会话各抽查一次。

### 7.3 回滚步骤

1. 先停数据写入侧（本地 Collector/Agent 上报），再回滚中央 Collector 与 ClickHouse
   镜像到锁定 digest；
2. 控制面如需回滚，按迁移 down 文件逆序执行（000093→000088），**不删除已采集的数据**；
3. ClickHouse schema 回滚仅限初始化未投产前：`DROP DATABASE IF EXISTS apm SYNC;`
   （会删除全部 APM 数据，投产环境禁用）；
4. 任一阶段出现异常时的整体兜底：置 `APM_ENABLED=false` 重启管理后端，APM 页面与接口
   整体降级，WAF 与既有功能不受影响。

---

## 8. 告警处置 SOP

### 8.0 告警清单与通知接入

| 类型 | 级别 | 触发 | 自动恢复 | 通知类别 |
|---|---|---|---|---|
| `ENDPOINT_LATENCY_HIGH` 端点响应耗时过高 | MEDIUM | 端点窗口 p95 ≥ 阈值且最近 sustain 个连续分钟桶各自超阈（窗口 5 分钟、整体上移 1 分钟避开在途聚合桶；最小请求量护栏；伪端点 `__OTHER__`/`__UNCLASSIFIED__` 不评估） | 本轮评估未触发即自动恢复（含窗口内已无流量） | —（见下注） |
| `ENDPOINT_ERROR_RATE_HIGH` 端点错误率过高 | HIGH | 端点窗口 5xx 错误率 ≥ 阈值，护栏同上 | 同上 | —（见下注） |
| `APM_SLO_BREACH` SLO 违约 | MEDIUM | SLO 状态进入 BREACHED（错误预算耗尽 remaining<0；每分钟评估，窗口源为小时聚合表） | 回到非 BREACHED 即恢复；SLO 删除后下一轮自动收口 | —（见下注） |
| `EVENT_COLLECTOR_LAG` 事件采集滞后 | MEDIUM | accesslog-01 断点滞后超阈值（默认 120s，`logging.access_log_stale_seconds` 可覆盖，10～86400）；`logging.access_log_enabled` 关闭时不判 | 断点追平即恢复 | 「采集健康」 |

> **如实边界**：通知渠道类别为固定 8 类词表（notify.Categories），APM 三个新告警类型
> **当前未纳入任何类别**——只有「类别留空 = 订阅全部」的通知渠道才能收到 APM 告警；
> 订阅了具体类别的渠道收不到。类别化纳入词表属后续工作项。`EVENT_COLLECTOR_LAG` 已属
> 「采集健康」类别，可正常按类别订阅。

### 8.1 ENDPOINT_LATENCY_HIGH（端点响应耗时过高）

含义：某应用某归一化端点（`app/endpoint`，如 `shop/GET /api/orders/{id}`）在 5 分钟评估
窗口内 p95 持续超阈（默认 2000ms），且窗口请求量 ≥ 60、最近 3 个连续分钟桶各自超阈——
单分钟毛刺与低流量单次抖动不会触发。

处置：

1. 「业务性能 → 端点性能」按 p95 排序定位该端点，确认趋势与错误率是否同步恶化；
2. 进「服务性能」行点击服务详情抽屉，看状态码分布与动作分布（allow/observe/block），
   区分是源站慢还是 WAF 拦截放大；
3. 「调用链检索」按服务 + `min_duration_ms` 过滤慢 trace，开瀑布下钻：
   有 Agent 数据看慢 SQL（SQL 诊断页）/外部依赖（依赖分析页）/运行时（GC、线程池、
   连接池）；无 Agent 数据时口径为网关总耗时 + TTFB（页面已如实标注），结合源站监控定位；
4. 若为发布退化，对比版本维度指标后回滚或修复；确认长期基线变化再考虑调阈值（§5.4）；
5. 恢复后告警自动收口，无需手工关闭。

### 8.2 ENDPOINT_ERROR_RATE_HIGH（端点错误率过高）

含义：端点 5xx 错误率持续超阈（默认 20%），护栏同 8.1。5xx 为用户可见故障，级别 HIGH。

处置：

1. 「端点性能」/「服务详情」确认错误窗口与影响面（单端点还是全应用）；
2. 「调用链检索」按 `error=true` 过滤错误 trace；「异常分析」页按异常指纹聚类定位
   首现时间（first_seen）与影响服务；
3. 关联安全视角：从 trace 视图跳关联 WAF 安全事件，排除攻击触发的上游异常（如注入
   试探导致的 500）；
4. 有 Agent 时下钻 SQL 错误率、依赖错误与运行时饱和度；无 Agent 时核对源站可用性与
   网关到源站连通（「运行监控」上游健康）；
5. 修复后自动恢复；低流量端点不告警是设计行为（min_requests 护栏），不要为覆盖长尾
   把 min_requests 调到 1。

### 8.3 APM_SLO_BREACH（SLO 违约）

含义：某 SLO 在当前窗口进入 BREACHED——availability（只把 5xx 计为失败）窗口达标率
跌破 target，或 latency_p95 的 P95 超过阈值；即错误预算已耗尽（remaining<0）。
component 为 `service/SLO 名`。

处置：

1. 「业务性能 → SLO 管理」打开该 SLO 详情，看达标率趋势（7d 按小时桶/30d 按天桶）与
   预算燃尽速度，判断是突发还是缓变；
2. 按 8.1/8.2 路径下钻到端点与 trace 找根因；窗口内无数据时状态保持 OK 不误报
   （无失败证据），因此触发即代表确有可观测违约；
3. 处置后关注预算恢复节奏；如目标定义不合理（过严/窗口错配），调整 SLO 定义
   （更新后重新评估）；删除 SLO 后其未关闭告警下一轮周期评估（每分钟）自动收口。

### 8.4 采集链路停滞（EVENT_COLLECTOR_LAG，accesslog-01）

含义：全量访问日志采集链路断点滞后超阈（默认 120s）——网关 JSON 全量访问日志 →
accesslog-01 采集器 → `access_logs` 表 → 端点级分钟聚合的某一环停滞。仅
`logging.access_log_enabled=true` 时判级。

处置：

1. 「系统运维 → 运行监控」看 EVENT_COLLECTOR 项的断点滞后秒数与消息；
2. 确认是否真实停滞：低流量站点分钟级无日志属正常（阈值 120s 为保守值，可按
   `logging.access_log_stale_seconds` 放宽）；
3. 真实停滞时依次查：网关侧日志文件是否滚动/写满磁盘 → accesslogs 采集器日志
   （解析失败率看 `EVENT_PARSE_FAILURE_RATE_HIGH` 是否伴随）→ PostgreSQL 写入可用性；
4. 断点恢复后自动追平并恢复告警；追平期间端点级数据会有窗口空洞，聚合任务每分钟
   重算当前与上一分钟桶，空洞不会回填——趋势解读时注意。

---

## 9. 上线前检查清单（APM 部分）

- [ ] `APM_ENABLED=true` 且前端「业务性能」菜单可见（SECURITY_ADMIN/AUDIT_ADMIN）；
- [ ] 端点级数据需要时：`logging.access_log_enabled=true` 已开启且按 §4.1 复核磁盘；
- [ ] 「运行监控」EVENT_COLLECTOR（accesslog-01）无 DEGRADED；
- [ ] 数据面启用时：ClickHouse `/ping` 正常、`apm` 库表齐全、中央/本地 Collector
      13133 健康、Prometheus 自监控无持续丢弃；
- [ ] 管理后端 `APM_CLICKHOUSE_DSN` 已配置且调用链检索页无降级提示；
- [ ] mTLS 证书由私有 CA 签发并挂载（占位路径不得带入生产），私钥 0600；
- [ ] apm_alert 阈值按业务基线评审过；通知渠道类别留空（订阅全部）以覆盖 APM 告警；
- [ ] 容量按 §4 公式估算并预留 30%～50% 余量；目标吞吐实测门禁已通过（未实测不承诺
      性能数字）。

---

Copyright © 聚信得仁
All Rights Reserved.
