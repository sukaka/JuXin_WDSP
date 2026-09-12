-- 九章 APM 阶段2 数据面 —— 服务/端点/SQL 指纹聚合与异常指纹
-- 依据：docs/BUSINESS_PERFORMANCE_APM_DESIGN.md §13.3（基数预算：只用归一化 route、
-- SQL 指纹）、§14.2（保留层级：分钟 30 天 / 小时 180 天 / 天 1 年）。
-- 全部派生自 apm.otel_traces，物化视图即时聚合；查询侧禁止无界扫原始表（§21.3）。
-- 耗时采用粗略分桶计数（<100ms / <500ms / <1s / <5s / >=5s），
-- 不在存储层保留完整分位数，需要直方图时按原始表在 TTL 窗口内计算。

-- ============ 服务级分钟聚合 ============
CREATE TABLE IF NOT EXISTS apm.apm_service_minutes (
    Minute DateTime,
    ServiceName LowCardinality(String),
    Env LowCardinality(String),
    RequestCount UInt64,        -- SpanKind = 'Server' 的入口 span 数
    ErrorCount UInt64,
    SlowCount UInt64,           -- Duration >= 2s，与 tail_sampling/慢 TTL 阈值一致
    DurationLt100ms UInt64,
    DurationLt500ms UInt64,
    DurationLt1s UInt64,
    DurationLt5s UInt64,
    DurationGe5s UInt64,
    TotalDurationNs UInt64      -- 平均耗时 = TotalDurationNs / RequestCount
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(Minute)
ORDER BY (ServiceName, Env, Minute)
TTL Minute + toIntervalDay(30)
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS apm.apm_service_minutes_mv
TO apm.apm_service_minutes
AS SELECT
    toStartOfMinute(Timestamp) AS Minute,
    ServiceName,
    ResourceAttributes['deployment.environment.name'] AS Env,
    count() AS RequestCount,
    countIf(StatusCode = 'Error') AS ErrorCount,
    countIf(Duration >= 2 * 1000000000) AS SlowCount,
    countIf(Duration < 100 * 1000000) AS DurationLt100ms,
    countIf(Duration >= 100 * 1000000 AND Duration < 500 * 1000000) AS DurationLt500ms,
    countIf(Duration >= 500 * 1000000 AND Duration < 1000000000) AS DurationLt1s,
    countIf(Duration >= 1000000000 AND Duration < 5 * 1000000000) AS DurationLt5s,
    countIf(Duration >= 5 * 1000000000) AS DurationGe5s,
    sum(Duration) AS TotalDurationNs
FROM apm.otel_traces
WHERE SpanKind = 'Server'
GROUP BY Minute, ServiceName, Env;

-- ============ 端点级分钟聚合 ============
-- EndpointKey 只取归一化路由模板（http.route，§13.3），严禁写入原始 path；
-- Agent 未提供 route 时归入 '__UNCLASSIFIED__'，对应无 Agent 治理口径。
CREATE TABLE IF NOT EXISTS apm.apm_endpoint_minutes (
    Minute DateTime,
    ServiceName LowCardinality(String),
    Env LowCardinality(String),
    EndpointKey LowCardinality(String),   -- 如 "GET /api/orders/{id}"
    RequestCount UInt64,
    ErrorCount UInt64,
    SlowCount UInt64,
    TotalDurationNs UInt64,
    MaxDurationNs SimpleAggregateFunction(max, UInt64)  -- SummingMergeTree 合并时取最大值而非求和
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(Minute)
ORDER BY (ServiceName, Env, EndpointKey, Minute)
TTL Minute + toIntervalDay(30)
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS apm.apm_endpoint_minutes_mv
TO apm.apm_endpoint_minutes
AS SELECT
    toStartOfMinute(Timestamp) AS Minute,
    ServiceName,
    ResourceAttributes['deployment.environment.name'] AS Env,
    if(SpanAttributes['http.route'] != '',
       SpanAttributes['http.method'] || ' ' || SpanAttributes['http.route'],
       '__UNCLASSIFIED__') AS EndpointKey,
    count() AS RequestCount,
    countIf(StatusCode = 'Error') AS ErrorCount,
    countIf(Duration >= 2 * 1000000000) AS SlowCount,
    sum(Duration) AS TotalDurationNs,
    max(Duration) AS MaxDurationNs
FROM apm.otel_traces
WHERE SpanKind = 'Server'
GROUP BY Minute, ServiceName, Env, EndpointKey;

-- ============ SQL 指纹分钟聚合 ============
-- 只存指纹（MD5(db.statement) 的十六进制），不存原始语句（§12.1/§13.3）；
-- db.statement 在写入前已由 Agent/Collector 完成归一化与 bind values 剔除。
CREATE TABLE IF NOT EXISTS apm.apm_sql_minutes (
    Minute DateTime,
    ServiceName LowCardinality(String),
    Env LowCardinality(String),
    DbSystem LowCardinality(String),
    SqlFingerprint String,      -- hex(MD5(normalized db.statement))
    CallCount UInt64,
    ErrorCount UInt64,
    SlowCount UInt64,           -- DB span 慢阈值 500ms
    TotalDurationNs UInt64,
    MaxDurationNs SimpleAggregateFunction(max, UInt64)  -- SummingMergeTree 合并时取最大值而非求和
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(Minute)
ORDER BY (ServiceName, Env, DbSystem, SqlFingerprint, Minute)
TTL Minute + toIntervalDay(30)
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS apm.apm_sql_minutes_mv
TO apm.apm_sql_minutes
AS SELECT
    toStartOfMinute(Timestamp) AS Minute,
    ServiceName,
    ResourceAttributes['deployment.environment.name'] AS Env,
    SpanAttributes['db.system'] AS DbSystem,
    hex(MD5(SpanAttributes['db.statement'])) AS SqlFingerprint,
    count() AS CallCount,
    countIf(StatusCode = 'Error') AS ErrorCount,
    countIf(Duration >= 500 * 1000000) AS SlowCount,
    sum(Duration) AS TotalDurationNs,
    max(Duration) AS MaxDurationNs
FROM apm.otel_traces
WHERE SpanKind = 'Client'
  AND SpanAttributes['db.statement'] != ''
GROUP BY Minute, ServiceName, Env, DbSystem, SqlFingerprint;

-- ============ 小时聚合（由分钟表派生，TTL 180 天） ============
CREATE TABLE IF NOT EXISTS apm.apm_service_hours (
    Hour DateTime,
    ServiceName LowCardinality(String),
    Env LowCardinality(String),
    RequestCount UInt64,
    ErrorCount UInt64,
    SlowCount UInt64,
    DurationLt100ms UInt64,
    DurationLt500ms UInt64,
    DurationLt1s UInt64,
    DurationLt5s UInt64,
    DurationGe5s UInt64,
    TotalDurationNs UInt64
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(Hour)
ORDER BY (ServiceName, Env, Hour)
TTL Hour + toIntervalDay(180)
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS apm.apm_service_hours_mv
TO apm.apm_service_hours
AS SELECT
    toStartOfHour(Minute) AS Hour,
    ServiceName,
    Env,
    sum(RequestCount) AS RequestCount,
    sum(ErrorCount) AS ErrorCount,
    sum(SlowCount) AS SlowCount,
    sum(DurationLt100ms) AS DurationLt100ms,
    sum(DurationLt500ms) AS DurationLt500ms,
    sum(DurationLt1s) AS DurationLt1s,
    sum(DurationLt5s) AS DurationLt5s,
    sum(DurationGe5s) AS DurationGe5s,
    sum(TotalDurationNs) AS TotalDurationNs
FROM apm.apm_service_minutes
GROUP BY Hour, ServiceName, Env;

CREATE TABLE IF NOT EXISTS apm.apm_endpoint_hours (
    Hour DateTime,
    ServiceName LowCardinality(String),
    Env LowCardinality(String),
    EndpointKey LowCardinality(String),
    RequestCount UInt64,
    ErrorCount UInt64,
    SlowCount UInt64,
    TotalDurationNs UInt64,
    MaxDurationNs SimpleAggregateFunction(max, UInt64)  -- SummingMergeTree 合并时取最大值而非求和
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(Hour)
ORDER BY (ServiceName, Env, EndpointKey, Hour)
TTL Hour + toIntervalDay(180)
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS apm.apm_endpoint_hours_mv
TO apm.apm_endpoint_hours
AS SELECT
    toStartOfHour(Minute) AS Hour,
    ServiceName,
    Env,
    EndpointKey,
    sum(RequestCount) AS RequestCount,
    sum(ErrorCount) AS ErrorCount,
    sum(SlowCount) AS SlowCount,
    sum(TotalDurationNs) AS TotalDurationNs,
    max(MaxDurationNs) AS MaxDurationNs
FROM apm.apm_endpoint_minutes
GROUP BY Hour, ServiceName, Env, EndpointKey;

-- ============ 天聚合（由小时表派生，TTL 1 年，SLO 与版本趋势） ============
CREATE TABLE IF NOT EXISTS apm.apm_service_days (
    Day Date,
    ServiceName LowCardinality(String),
    Env LowCardinality(String),
    RequestCount UInt64,
    ErrorCount UInt64,
    SlowCount UInt64,
    TotalDurationNs UInt64
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(Day)
ORDER BY (ServiceName, Env, Day)
TTL Day + toIntervalDay(365)
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS apm.apm_service_days_mv
TO apm.apm_service_days
AS SELECT
    toDate(Hour) AS Day,
    ServiceName,
    Env,
    sum(RequestCount) AS RequestCount,
    sum(ErrorCount) AS ErrorCount,
    sum(SlowCount) AS SlowCount,
    sum(TotalDurationNs) AS TotalDurationNs
FROM apm.apm_service_hours
GROUP BY Day, ServiceName, Env;

-- ============ 异常指纹表 ============
-- 异常用"类型 + 归一化堆栈指纹"聚合（§13.3），保留一个示例 trace 供跳转；
-- 不存堆栈原文。ExampleTraceId 用 AggregatingMergeTree 的 anyState，
-- 同组内取任一示例（SummingMergeTree 无法正确表达"任一示例"语义）。
CREATE TABLE IF NOT EXISTS apm.apm_exception_fingerprints (
    Minute DateTime,
    ServiceName LowCardinality(String),
    Env LowCardinality(String),
    ExceptionType LowCardinality(String),
    Fingerprint String,     -- hex(MD5(exception.stacktrace))，堆栈已归一化
    SampleCount AggregateFunction(count, UInt64),
    ExampleTraceId AggregateFunction(any, String)
) ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(Minute)
ORDER BY (ServiceName, Env, ExceptionType, Fingerprint, Minute)
TTL Minute + toIntervalDay(30)
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS apm.apm_exception_fingerprints_mv
TO apm.apm_exception_fingerprints
AS SELECT
    toStartOfMinute(Timestamp) AS Minute,
    ServiceName,
    ResourceAttributes['deployment.environment.name'] AS Env,
    Events.Attributes['exception.type'] AS ExceptionType,
    hex(MD5(Events.Attributes['exception.stacktrace'])) AS Fingerprint,
    countState() AS SampleCount,
    anyState(TraceId) AS ExampleTraceId
FROM apm.otel_traces
ARRAY JOIN Events
WHERE Events.Name = 'exception'
GROUP BY Minute, ServiceName, Env, ExceptionType, Fingerprint;
