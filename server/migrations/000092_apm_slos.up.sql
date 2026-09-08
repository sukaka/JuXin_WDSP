-- 000092 APM SLO 目标管理（设计 docs/BUSINESS_PERFORMANCE_APM_DESIGN.md §16.2/§18）。
--   apm_slos：SLO 定义（service 为应用编码，对应聚合指标 app 标签；metric_type ∈
--   availability/latency_p95；window ∈ 7d/30d；target 口径随 metric_type——
--   availability 为 (0,1) 达标率、latency_p95 为毫秒阈值，合法性由应用层校验兜底）。
--   注意：window 是 PostgreSQL 保留字，列定义与所有 SQL 引用必须带双引号（"window"）。
--   UNIQUE (service, metric_type, window)：同一服务同一指标同一窗口只允许一条定义，
--   防重复定义导致告警去重键与页面口径歧义。
--   权限复用既有种子：读 apm.overview.read（000088）、写 apm.settings.manage（000089），
--   本迁移不新增权限点。
BEGIN;

CREATE TABLE IF NOT EXISTS apm_slos (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(128)     NOT NULL,
    service     VARCHAR(128)     NOT NULL,
    metric_type VARCHAR(16)      NOT NULL
                CHECK (metric_type IN ('availability', 'latency_p95')),
    target      DOUBLE PRECISION NOT NULL,
    "window"    VARCHAR(4)       NOT NULL
                CHECK ("window" IN ('7d', '30d')),
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ      NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ      NOT NULL DEFAULT now(),
    UNIQUE (service, metric_type, "window")
);

COMMIT;
