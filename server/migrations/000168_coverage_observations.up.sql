-- 000168 执行覆盖观测摄入（NG-COV-01/02 server 侧存储，docs/PRODUCT_REQUIREMENTS.md
-- 阶段8 / NG-BASE-02 §2.2 契约）。
--
--   coverage_observations：请求级覆盖观测明细（网关 coverage-observations.jsonl
--     逐行摄入，采集器确定性 1/N 采样留存，采样率由采集器注入）。明细只读留痕，
--     不进入攻击评分链路（ADR-2 安全不变量）。
--   coverage_counter_snapshots：节点级摄入管线阶段计数快照（每次 flush 一组，
--     stage 命名空间 cov_ingest.*：处理/采样保留与丢弃/聚合溢出与非法/观测与聚合入库），
--     用于丢弃事实本身入聚合展示（契约「丢弃不得静默」）。
--   coverage_minute_agg：聚合落库表（NG-COV-02）：维度键（应用×端点模板×检测器×
--     方向×策略版本×节点×分钟窗）+ 五态计数；维度超限归 other 桶（is_other 标记）。
--     E 口径 = full+partial+skipped+error；not_applicable 另计不进 E——比率在
--     查询侧计算，不落库（E=0 绝不显示 100%，见 server/internal/coverage/agg.go）。
BEGIN;

-- ---------- 请求级明细（采样留存） ----------
CREATE TABLE IF NOT EXISTS coverage_observations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id      VARCHAR(64)  NOT NULL,
    application_id  VARCHAR(64)  NOT NULL DEFAULT '',
    endpoint_key    VARCHAR(560) NOT NULL DEFAULT '',
    detector        VARCHAR(96)  NOT NULL,
    phase           VARCHAR(16)  NOT NULL,
    status          VARCHAR(16)  NOT NULL,
    reason_code     VARCHAR(48)  NOT NULL DEFAULT '',
    na_rule_id      VARCHAR(96)  NOT NULL DEFAULT '',
    scope_bytes     BIGINT       NOT NULL DEFAULT 0,
    scope_messages  INT          NOT NULL DEFAULT 0,
    scope_direction VARCHAR(16)  NOT NULL DEFAULT '',
    bytes_examined  BIGINT       NOT NULL DEFAULT 0,
    truncated       BOOLEAN      NOT NULL DEFAULT false,
    policy_version  VARCHAR(64)  NOT NULL DEFAULT '',
    node_id         VARCHAR(96)  NOT NULL DEFAULT '',
    occurred_at     TIMESTAMPTZ  NOT NULL,
    ingested_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE coverage_observations IS '执行覆盖观测请求级明细（NG-COV-01）：网关 JSONL 摄入，确定性 1/N 采样留存；永不进入攻击评分链路';

CREATE INDEX IF NOT EXISTS idx_coverage_obs_app_time
    ON coverage_observations (application_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_coverage_obs_detector_status_time
    ON coverage_observations (detector, status, occurred_at DESC);

-- ---------- 节点级摄入阶段计数快照 ----------
CREATE TABLE IF NOT EXISTS coverage_counter_snapshots (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id     VARCHAR(96) NOT NULL,
    stage       VARCHAR(48) NOT NULL,
    count       BIGINT      NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE coverage_counter_snapshots IS '覆盖摄入管线节点级阶段计数快照（cov_ingest.*）：每次 flush 一组，丢弃事实入聚合展示（不静默丢弃）';

CREATE INDEX IF NOT EXISTS idx_coverage_counter_snap_node_time
    ON coverage_counter_snapshots (node_id, captured_at DESC);

-- ---------- 分钟聚合（NG-COV-02 落库） ----------
CREATE TABLE IF NOT EXISTS coverage_minute_agg (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id  VARCHAR(64)  NOT NULL DEFAULT '',
    endpoint_key    VARCHAR(560) NOT NULL DEFAULT '',
    detector        VARCHAR(96)  NOT NULL,
    phase           VARCHAR(16)  NOT NULL,
    policy_version  VARCHAR(64)  NOT NULL DEFAULT '',
    node_id         VARCHAR(96)  NOT NULL DEFAULT '',
    minute          TIMESTAMPTZ  NOT NULL,
    full_count      BIGINT       NOT NULL DEFAULT 0,
    partial_count   BIGINT       NOT NULL DEFAULT 0,
    skipped_count   BIGINT       NOT NULL DEFAULT 0,
    error_count     BIGINT       NOT NULL DEFAULT 0,
    na_count        BIGINT       NOT NULL DEFAULT 0,
    is_other        BOOLEAN      NOT NULL DEFAULT false,
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT coverage_minute_agg_dim UNIQUE
        (application_id, endpoint_key, detector, phase, policy_version, node_id, minute)
);

COMMENT ON TABLE coverage_minute_agg IS '执行覆盖分钟聚合（NG-COV-02）：E=full+partial+skipped+error，na 另计不进 E；比率查询侧计算，E=0 绝不显示 100%';
COMMENT ON COLUMN coverage_minute_agg.is_other IS '维度组合超上限归拢 other 桶标记（endpoint_key/detector 为 other 时 true）';

CREATE INDEX IF NOT EXISTS idx_coverage_minute_agg_app_time
    ON coverage_minute_agg (application_id, minute DESC);
CREATE INDEX IF NOT EXISTS idx_coverage_minute_agg_detector_time
    ON coverage_minute_agg (detector, minute DESC);

COMMIT;
