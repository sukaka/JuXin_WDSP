# APM 数据面 ClickHouse Schema（阶段2）

本目录维护 APM 数据面的全部 ClickHouse DDL。依据 `docs/BUSINESS_PERFORMANCE_APM_DESIGN.md` §14/§15.2
与 `docs/APM_STAGE0_ADR.md` D2：**由本包维护明确的 Schema、TTL 和迁移，不依赖 Collector 启动时自动建表**
（Collector clickhouse exporter 必须配置 `create_schema: false`，见 `deployment/apm/collector/central-gateway.yaml`）。

## 文件

| 文件 | 内容 | 保留（TTL，设计 §14.2） |
|---|---|---|
| `001_otel_traces.sql` | `apm.otel_traces` 原始 span 表（对齐 otel-collector-contrib v0.154.0 clickhouse exporter 官方 DDL）+ `otel_traces_trace_id_ts` 检索表与物化视图 | 正常 7 天；错误/慢(≥2s)/高风险 14 天（TTL 表达式分层）；检索表 14 天 |
| `002_aggregates.sql` | 服务/端点/SQL 指纹分钟聚合、小时/天滚动聚合、异常指纹表（均从 `otel_traces` 物化视图派生） | 分钟 30 天、小时 180 天、天 1 年（365 天）；异常指纹 30 天 |
| `003_metrics.sql` | 运行时指标表（阶段3）：`otel_metrics_gauge/sum/histogram/exp_histogram/summary`（对齐 v0.154.0 exporter metrics DDL 默认表名；Collector `metrics_tables` 未覆写） | 原始指标点 7 天；小时聚合留待后续阶段 |
| `004_api_observations.sql` | 脱敏 API 观测、字段 HMAC 证据与 DLQ 表；数据流消费者按 Trace ID 从这些共享表重建跨批次关联 | 未配置 TTL |
| `005_data_flow_contributions.sql` | 数据流贡献表；按 `(agent_id,event_id,edge_id)` 幂等去重，保存配对边及单边边修正版本 | 未配置 TTL |
| `006_network_boundary.sql` | 观测与贡献表的网络边界地址、分区和证据列升级 | 继承对应表 |
| `ha/001_ha_replicated.sql` | 阶段5 HA 变体：`otel_traces` 双副本（ReplicatedMergeTree + ON CLUSTER），与 `001_otel_traces.sql` 二选一；位于子目录，**不会**被 entrypoint 自动执行（见下文 HA 节） | 同 001 |

## 初始化与回滚

Docker Compose（`deployment/docker-compose.apm.yml`）已把本目录挂载到
`/docker-entrypoint-initdb.d/`，ClickHouse 首次启动（空数据卷）时自动按文件名顺序执行。

裸机/已有实例手工初始化：

```bash
clickhouse-client --host <ch-host> --user default --password \
  --multiquery < 001_otel_traces.sql
clickhouse-client --host <ch-host> --user default --password \
  --multiquery < 002_aggregates.sql
clickhouse-client --host <ch-host> --user default --password \
  --multiquery < 003_metrics.sql
clickhouse-client --host <ch-host> --user default --password \
  --multiquery < 004_api_observations.sql
clickhouse-client --host <ch-host> --user default --password \
  --multiquery < 005_data_flow_contributions.sql
clickhouse-client --host <ch-host> --user default --password \
  --multiquery < 006_network_boundary.sql
```

幂等性：全部语句为 `IF NOT EXISTS`，可安全重复执行；但**不会**把已建表升级到新定义
（例如修改 TTL 需单独 `ALTER TABLE ... MODIFY TTL`，纳入迁移评审，不直接改本文件后重跑）。

回滚（仅限初始化未投入生产前；会删除全部 APM 数据）：

```sql
DROP DATABASE IF EXISTS apm SYNC;
```

## 容量估算（设计 §14.1）

```text
spans_per_second    = 请求速率 × trace 采样率 × 每 trace 平均 span 数
raw_bytes_per_day   = spans_per_second × 平均每 span 压缩后字节 × 86400
physical_bytes      = raw_bytes_per_day × 副本系数 × 保留天数
```

规划示例（非性能承诺，摘自设计 §14.1）：1000 req/s、5% 采样、每 trace 10 span、
每 span 压缩后 300 字节 → 500 span/s ≈ 12.96 GB/天（单副本）。7 天原始 + 14 天错误层
+ 聚合层与索引/合并临时空间，预留 30%～50% 安全余量。

按本包 TTL 粗算磁盘下限：

```text
disk ≥ raw_bytes_per_day × (7 + 7 × 错误慢高风险占比) × 副本系数 × 1.4
     + 分钟/小时/天聚合体量（通常 << 原始层，按服务×端点×分钟行数估算）
```

阶段2 上线前须在目标吞吐下实测 span 大小与写入速率（ADR §6/§7 入口门禁），再定副本与磁盘。

## 运维要点

- **写入账号**：生产环境为 Collector 创建专用最小权限账号，不要使用 `default`：

  ```sql
  CREATE USER IF NOT EXISTS apm_writer IDENTIFIED WITH sha256_password BY '<强随机口令>';
  GRANT INSERT ON apm.otel_traces TO apm_writer;
  -- 阶段3 运行时指标表（Collector metrics 管道写入）：
  GRANT INSERT ON apm.otel_metrics_gauge TO apm_writer;
  GRANT INSERT ON apm.otel_metrics_sum TO apm_writer;
  GRANT INSERT ON apm.otel_metrics_histogram TO apm_writer;
  GRANT INSERT ON apm.otel_metrics_exp_histogram TO apm_writer;
  GRANT INSERT ON apm.otel_metrics_summary TO apm_writer;
  ```

  （检索表与聚合表由物化视图自动写入，无需单独授权。）

- **分区**：原始表按天分区，过期经 TTL + `ttl_only_drop_parts = 1` 整分区删除；
  紧急清理可按分区删除：`ALTER TABLE apm.otel_traces DROP PARTITION '2026-08-30';`
- **受审计删除**（设计 §12.2 敏感泄漏处置）：按租户/时间/trace ID 用
  `ALTER TABLE ... DELETE WHERE ...`（mutation，异步，纳入操作审计），删除量小；
  大批量优先按分区处理。
- **监控**：关注 `system.parts`（活跃分区数）、`system.mutations`（积压）、
  merge 积压与磁盘水位；Collector 侧丢弃计数见中央 Collector 自监控指标。
- **备份**：单副本交付形态用 `BACKUP TABLE apm.* TO Disk(...)` 或文件系统快照；
  聚合表可由原始表重建，备份优先级低于原始表；诊断会话元数据在 PostgreSQL 控制面，
  不随本库备份。详细备份/恢复命令与演练清单见 `deployment/apm/backup.md`。
- **升级**：Collector 版本升级前对照上游 v0.154.0 之后版本的 DDL 变更做兼容性回归，
  结果登记 `docs/DEPENDENCIES.md`。

## HA（双副本 ReplicatedMergeTree，阶段5）

设计 §19.4 要求「ClickHouse 至少双副本」。双副本为可选形态，与单副本交付并存；
启用后 Collector 写入入口、备份策略相应调整。

### 组件与镜像

不引入新镜像：ClickHouse Keeper 复用已锁定的 `clickhouse/clickhouse-server:25.8-alpine`
镜像内 `clickhouse-keeper`（25.8 官方构建已含，`/usr/bin/clickhouse-keeper` 为
`clickhouse keeper` 的符号链接，已实测）。

### 拓扑与配置样例

最小形态：2 × clickhouse-server（副本）+ 1 × clickhouse-keeper（生产建议 3 节点
keeper 集群，单 keeper 仅为最小可运行形态；keeper 故障不影响已建立的复制数据读写，
仅阻塞新副本/DDL 变更协调）。

每个副本实例追加配置（`/etc/clickhouse-server/config.d/apm-ha.xml`）：

```xml
<clickhouse>
    <remote_servers>
        <apm_ha>
            <shard>
                <internal_replication>true</internal_replication>
                <replica><host>clickhouse-1</host><port>9000</port></replica>
                <replica><host>clickhouse-2</host><port>9000</port></replica>
            </shard>
        </apm_ha>
    </remote_servers>
    <keeper_server>  <!-- 仅 keeper 节点自身需要；副本节点用下方 zookeeper 段 -->
    </keeper_server>
    <zookeeper>
        <node><host>clickhouse-keeper</host><port>9181</port></node>
    </zookeeper>
    <macros>
        <shard>01</shard>              <!-- 双副本单分片：两实例相同 -->
        <replica>clickhouse-1</replica><!-- 每实例唯一：clickhouse-1 / clickhouse-2 -->
    </macros>
</clickhouse>
```

keeper 节点配置（`/etc/clickhouse-keeper/keeper_config.xml`）：

```xml
<clickhouse>
    <keeper_server>
        <tcp_port>9181</tcp_port>
        <server_id>1</server_id>
        <log_storage_path>/var/lib/clickhouse/coordination/log</log_storage_path>
        <snapshot_storage_path>/var/lib/clickhouse/coordination/snapshots</snapshot_storage_path>
        <coordination_settings>
            <operation_timeout_ms>10000</operation_timeout_ms>
            <session_timeout_ms>30000</session_timeout_ms>
        </coordination_settings>
        <raft_configuration>
            <server><id>1</id><hostname>clickhouse-keeper</hostname><port>9234</port></server>
        </raft_configuration>
    </keeper_server>
</clickhouse>
```

启动命令样例（同一锁定镜像）：`clickhouse-keeper --config-file=/etc/clickhouse-keeper/keeper_config.xml`。

### 建表

完成上述配置后，在任一副本执行（`ON CLUSTER apm_ha` 会分发到全部副本）：

```bash
clickhouse-client --host clickhouse-1 --user default --password \
  --multiquery < ha/001_ha_replicated.sql
```

- 与 `001_otel_traces.sql` **二选一**：已用单副本初始化的实例不得再执行本变体
  （`IF NOT EXISTS` 会静默跳过，不会把既有 MergeTree 表升级为复制表）；
  单副本迁移到双副本须新建复制表 + `INSERT INTO SELECT` 或分区搬运，纳入迁移评审。
- 本变体只复制 `otel_traces` 与 `otel_traces_trace_id_ts`；`002_aggregates.sql` /
  `003_metrics.sql` 照常在两副本各自执行（聚合/指标表保持本地引擎，由各副本物化视图
  从本地副本数据独立物化——上游推荐模式，避免 MV 对复制目标表的双写放大与去重
  不确定性；聚合/指标可由原始表重建）。

### 副本形态下的运维差异

- **Collector 写入入口**：clickhouse exporter 端点为单地址 `tcp://clickhouse:9000`；
  双副本时由部署侧在该名称/VIP 后挂 TCP 负载均衡（HAProxy/chproxy/云 LB），或经
  compose `extra_hosts`/K8s Service 固定指向。任一副本接收的写入都会复制到另一副本。
- **备份**：任选一个健康副本执行 `BACKUP` 即可（副本间数据等价）；副本损坏优先用
  复制协议重建（修复节点后自动拉取缺失 parts），备份用于整体灾难恢复
  （见 `deployment/apm/backup.md`）。
- **监控**：追加 `system.replicas`（`is_readonly`、`absolute_delay`、`queue_size`）
  与 keeper 连通性告警；TTL/分区删除经 keeper 复制，无需逐副本操作。
