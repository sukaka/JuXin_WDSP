-- API 网络暴露面判定引擎（WDSP）：流量来源聚合证据 + 暴露面评估明细。
--
-- 表：
--   api_endpoint_source_buckets  端点×自然日×来源范围 请求计数（流量证据聚合桶）
--   api_endpoint_source_seen     端点×自然日×来源范围 去重来源指纹
--                                （只存网关上报的盐化指纹，不落明文 IP——与 learning_samples 同纪律）
--   api_exposure_assessments     暴露面评估历史明细（evidence JSONB 元素 {type, summary} 中文摘要）
--
-- 枚举词表一律应用层校验、不落数据库 CHECK（项目纪律）：
--   scope      INTERNAL / PUBLIC / PARTNER
--   verdict    INTERNAL / PARTNER / PUBLIC / UNKNOWN
--   source     MANUAL / TRAFFIC_OBSERVED / CONFIG
--   confidence LOW / MEDIUM / HIGH
-- 权限点零新增：读复用 api_asset.read，重评复用 api_asset.edit，人工确认走现有 classification PUT。

BEGIN;

CREATE TABLE IF NOT EXISTS api_endpoint_source_buckets (
    endpoint_id   UUID        NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    bucket_date   DATE        NOT NULL,
    scope         VARCHAR(16) NOT NULL,
    request_count BIGINT      NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (endpoint_id, bucket_date, scope)
);
-- 清扫取数按日期窗过滤（DISTINCT endpoint_id WHERE bucket_date >= N 天前）
CREATE INDEX IF NOT EXISTS idx_api_endpoint_source_buckets_date
    ON api_endpoint_source_buckets (bucket_date);

CREATE TABLE IF NOT EXISTS api_endpoint_source_seen (
    endpoint_id        UUID         NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    seen_date          DATE         NOT NULL,
    scope              VARCHAR(16)  NOT NULL,
    source_fingerprint VARCHAR(128) NOT NULL,
    first_seen_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    request_count      BIGINT       NOT NULL DEFAULT 0,
    PRIMARY KEY (endpoint_id, seen_date, scope, source_fingerprint)
);
-- 留存清理按日期删除
CREATE INDEX IF NOT EXISTS idx_api_endpoint_source_seen_date
    ON api_endpoint_source_seen (seen_date);

CREATE TABLE IF NOT EXISTS api_exposure_assessments (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID        NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    verdict     VARCHAR(16) NOT NULL,
    source      VARCHAR(32) NOT NULL,
    confidence  VARCHAR(8)  NOT NULL,
    evidence    JSONB       NOT NULL DEFAULT '[]',
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_exposure_assessments_endpoint
    ON api_exposure_assessments (endpoint_id, assessed_at DESC);
-- 留存清理按评估时间删除
CREATE INDEX IF NOT EXISTS idx_api_exposure_assessments_time
    ON api_exposure_assessments (assessed_at);

-- 引擎配置种子（system_settings 组 exposure_engine；接口修改白名单与校验登记于
-- settings.AllowedSettingKeys / settingValueRanges / validateCIDRList / validateServerList）：
--   observation_days    观察窗天数（1-30，默认 7）
--   partner_egress_cidrs 合作方出口网段（逗号分隔 CIDR，≤32 项；空 = 不启用 PARTNER 判定）
--   public_dns_servers  公网视角 DNS 服务器（逗号分隔主机列表，≤4 项；默认 223.5.5.5）
--   min_requests        流量证据请求数阈值（1-100000，默认 50）
--   min_days            流量证据覆盖自然日阈值（1-30，默认 2）
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('exposure_engine', 'observation_days',     '7',          'integer', FALSE, 'API 暴露面判定观察窗天数（1-30，默认 7）'),
('exposure_engine', 'partner_egress_cidrs', '""',         'string',  FALSE, '合作方出口网段（逗号分隔 CIDR，最多 32 项，总长 2048 字节；空 = 不启用 PARTNER 判定）'),
('exposure_engine', 'public_dns_servers',   '"223.5.5.5"','string',  FALSE, '公网视角 DNS 服务器（逗号分隔主机列表，最多 4 项；用于域名公网可解析性判定）'),
('exposure_engine', 'min_requests',         '50',         'integer', FALSE, '暴露面流量证据请求数阈值（1-100000，默认 50）'),
('exposure_engine', 'min_days',             '2',          'integer', FALSE, '暴露面流量证据覆盖自然日阈值（1-30，默认 2）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
