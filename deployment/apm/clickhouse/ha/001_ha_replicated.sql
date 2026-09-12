-- 九章 APM 阶段5 —— HA 形态 schema 变体：otel_traces 双副本（ReplicatedMergeTree）
-- 依据：docs/BUSINESS_PERFORMANCE_APM_DESIGN.md §19.4「ClickHouse 至少双副本」。
--
-- 与 001_otel_traces.sql 的关系：二选一，不得对同一实例重复执行。
--   - 单副本形态：用上级目录 001_otel_traces.sql（MergeTree，由 compose 首次启动自动执行）；
--   - 双副本形态：用本文件（ReplicatedMergeTree + ON CLUSTER），须在两副本实例上
--     完成 keeper/remote_servers/macros 配置后手工执行（见 ../README.md「HA 双副本」节）。
--   本文件放在 ha/ 子目录，不会被 /docker-entrypoint-initdb.d 的非递归 glob 执行到
--   （官方 entrypoint 只跑顶层 *.sql，已实测 25.8-alpine entrypoint.sh）。
--
-- 前置条件（缺一不可，详见 ../README.md）：
--   1) ClickHouse Keeper 集群（复用锁定镜像内的 clickhouse-keeper，25.8-alpine 已含）；
--   2) 每个副本实例配置 <remote_servers> 集群（本文件约定集群名 apm_ha）与
--      <keeper_server>/<zookeeper> 节点列表；
--   3) 每个副本实例配置 macros：{shard}（双副本单分片=01）与 {replica}（实例唯一名）。
--
-- 范围说明：仅复制「原始 span 表 + trace ID 检索表」（备份优先级最高、不可重建）。
--   002 聚合表与 003 指标表在两副本形态下保持本地引擎（SummingMergeTree/MergeTree），
--   由各副本物化视图从本地副本数据独立物化（上游推荐模式：源表复制、MV 目标表本地），
--   聚合/指标可由原始表重建，不复制以避免 MV 双写放大与去重不确定性。

CREATE DATABASE IF NOT EXISTS apm;

-- 原始 span 主表（列/TTL/索引与 001_otel_traces.sql 完全一致，仅引擎换为
-- ReplicatedMergeTree 并加 ON CLUSTER；TTL 与分区删除经 keeper 在副本间复制）。
CREATE TABLE IF NOT EXISTS apm.otel_traces ON CLUSTER apm_ha (
    Timestamp DateTime64(9) CODEC(Delta, ZSTD(1)),
    TraceId String CODEC(ZSTD(1)),
    SpanId String CODEC(ZSTD(1)),
    ParentSpanId String CODEC(ZSTD(1)),
    TraceState String CODEC(ZSTD(1)),
    SpanName LowCardinality(String) CODEC(ZSTD(1)),
    SpanKind LowCardinality(String) CODEC(ZSTD(1)),
    ServiceName LowCardinality(String) CODEC(ZSTD(1)),
    ResourceAttributes Map(LowCardinality(String), String) CODEC(ZSTD(1)),
    ScopeName String CODEC(ZSTD(1)),
    ScopeVersion String CODEC(ZSTD(1)),
    SpanAttributes Map(LowCardinality(String), String) CODEC(ZSTD(1)),
    Duration UInt64 CODEC(ZSTD(1)),            -- 纳秒
    StatusCode LowCardinality(String) CODEC(ZSTD(1)),  -- Unset / Ok / Error
    StatusMessage String CODEC(ZSTD(1)),
    Events Nested (
        Timestamp DateTime64(9),
        Name LowCardinality(String),
        Attributes Map(LowCardinality(String), String)
    ) CODEC(ZSTD(1)),
    Links Nested (
        TraceId String,
        SpanId String,
        TraceState String,
        Attributes Map(LowCardinality(String), String)
    ) CODEC(ZSTD(1)),
    INDEX idx_trace_id TraceId TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_res_attr_key mapKeys(ResourceAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_res_attr_value mapValues(ResourceAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_span_attr_key mapKeys(SpanAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_span_attr_value mapValues(SpanAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_duration Duration TYPE minmax GRANULARITY 1
) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/apm/otel_traces', '{replica}')
PARTITION BY toDate(Timestamp)
ORDER BY (ServiceName, SpanName, toDateTime(Timestamp), TraceId)
-- 分层 TTL（设计 §14.2）：正常 7 天；错误/慢(≥2s)/高风险 14 天（与单副本一致）。
TTL Timestamp + toIntervalDay(
    if(StatusCode = 'Error'
        OR Duration >= 2 * 1000000000
        OR SpanAttributes['jiuzhang.waf_action'] = 'BLOCK',
       14, 7))
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- trace ID → 时间范围检索表（复制，保留窗口对齐原始表最长层 14 天）
CREATE TABLE IF NOT EXISTS apm.otel_traces_trace_id_ts ON CLUSTER apm_ha (
    TraceId String CODEC(ZSTD(1)),
    Start DateTime CODEC(Delta, ZSTD(1)),
    End DateTime CODEC(Delta, ZSTD(1)),
    INDEX idx_trace_id TraceId TYPE bloom_filter(0.01) GRANULARITY 1
) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/apm/otel_traces_trace_id_ts', '{replica}')
PARTITION BY toDate(Start)
ORDER BY (TraceId, Start)
TTL Start + toIntervalDay(14)
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- 物化视图：ON CLUSTER 在每个副本本地创建；各副本对本地副本数据独立物化，
-- 写入本地（已复制）目标表——不产生跨副本双写（ReplicatedMergeTree 目标表由
-- keeper 去重同一副本的插入；MV 只跟随本副本的 insert 事件）。
CREATE MATERIALIZED VIEW IF NOT EXISTS apm.otel_traces_trace_id_ts_mv ON CLUSTER apm_ha
TO apm.otel_traces_trace_id_ts
AS SELECT
    TraceId,
    min(Timestamp) AS Start,
    max(Timestamp) AS End
FROM apm.otel_traces
WHERE TraceId != ''
GROUP BY TraceId;
