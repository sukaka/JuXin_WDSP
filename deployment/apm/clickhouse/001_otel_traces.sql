-- 九章 APM 阶段2 数据面 —— OTel trace/span 标准表
-- 依据：docs/BUSINESS_PERFORMANCE_APM_DESIGN.md §15.2；docs/APM_STAGE0_ADR.md D2
-- Schema 对齐 opentelemetry-collector-contrib v0.154.0 clickhouse exporter 官方 DDL
-- （exporter/clickhouseexporter/internal/sqltemplates/traces_table.sql 等），
-- 由本包维护建表与 TTL，Collector 端必须设置 create_schema: false（设计 §15.2：
-- 不依赖 Collector 启动时自动建表/升级表）。
-- 升级 Collector 版本前，须对照上游 DDL 复核列结构兼容性。

CREATE DATABASE IF NOT EXISTS apm;

-- 原始 span 主表。列定义与上游 v0.154.0 一致，改动仅限：
--   1) ORDER BY 追加 TraceId（设计 §15.2：排序键含服务、时间、trace ID）；
--   2) 分层 TTL（设计 §14.2：正常 7 天，错误/慢/高风险 14 天）。
CREATE TABLE IF NOT EXISTS apm.otel_traces (
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
) ENGINE = MergeTree()
PARTITION BY toDate(Timestamp)
ORDER BY (ServiceName, SpanName, toDateTime(Timestamp), TraceId)
-- 分层 TTL（设计 §14.2）：
--   正常 trace 7 天；StatusCode='Error'（错误）、Duration >= 2s（慢）、
--   SpanAttributes['jiuzhang.waf_action']='BLOCK'（高风险，由阶段2 网关埋点写入，
--   属性缺失时条件为假，不影响旧数据）延长到 14 天。
-- 慢阈值与中央 Collector tail_sampling 的 latency 阈值保持一致（2000ms）。
TTL Timestamp + toIntervalDay(
    if(StatusCode = 'Error'
        OR Duration >= 2 * 1000000000
        OR SpanAttributes['jiuzhang.waf_action'] = 'BLOCK',
       14, 7))
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- trace ID → 时间范围检索表（与上游 v0.154.0 一致）
CREATE TABLE IF NOT EXISTS apm.otel_traces_trace_id_ts (
    TraceId String CODEC(ZSTD(1)),
    Start DateTime CODEC(Delta, ZSTD(1)),
    End DateTime CODEC(Delta, ZSTD(1)),
    INDEX idx_trace_id TraceId TYPE bloom_filter(0.01) GRANULARITY 1
) ENGINE = MergeTree()
PARTITION BY toDate(Start)
ORDER BY (TraceId, Start)
-- 检索表保留窗口对齐原始表最长层（14 天），避免出现"索引在、数据已删"。
TTL Start + toIntervalDay(14)
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

CREATE MATERIALIZED VIEW IF NOT EXISTS apm.otel_traces_trace_id_ts_mv
TO apm.otel_traces_trace_id_ts
AS SELECT
    TraceId,
    min(Timestamp) AS Start,
    max(Timestamp) AS End
FROM apm.otel_traces
WHERE TraceId != ''
GROUP BY TraceId;
