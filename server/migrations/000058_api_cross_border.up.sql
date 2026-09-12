-- 000058 API 数据出境基础（W7-XB / P1-03）：跨境观察事件表 + 生产方水位状态表。
--
-- 语义边界（任务书 §98-99 数据出境第一片）：
--   生产方为 apigeo.Sweeper.SweepOnce：增量扫描 api_runtime_events 中涉敏事件
--   （details_json 含 detector=sensitive_data 明细），对 client_ip 做 GeoIP 归属判定，
--   境外来源（国家码不在 system_settings api_data.home_regions 内）才落库为本表观察记录；
--   本土/内网/未知归属不落库（未知归属不能证明出境，宁可不漏报误报，见包文档）。
--
-- 幂等双保险：
--   1. (source_event_id, direction) 唯一约束 + ON CONFLICT DO NOTHING
--      （同一运行时事件的 REQUEST/RESPONSE 双侧命中各产生一条，方向语义不同不去重）；
--   2. api_cross_border_state 单行水位表记录已扫描到的事件时刻。
--   水位必须独立成表：绝大多数事件因本土/内网归属被跳过、不产生本表行，
--   若沿用 apidata/apiauthz 的「产出表 max(时间) 当水位」模式，水位会永久停滞，
--   每轮清扫都会全量重扫历史涉敏事件（流量以本土为主时该模式不可用）。
--
-- 列说明：
--   client_ip  按既有 maskIP 纪律（securityevents/normalize.go）以 netip 归一化存储，
--              不额外截断（安全事件溯源需要完整 IP，跨境调查同样需要定位来源）；
--   country    ISO 3166-1 alpha-2 国家码（GeoIP 库无 ASN 数据，asn 列预留暂恒 NULL）；
--   direction  OUT = 响应侧涉敏数据流向境外客户端（出境）；IN = 境外客户端提交涉敏数据（入境）；
--   data_types 该方向涉敏命中去重后的数据类型标签（对齐 api_sensitive_data_types.data_type）；
--   risk_level 由 data_types 经 api_sensitive_data_types.level 推导：CORE/IMPORTANT→HIGH，
--              SENSITIVE→MEDIUM，其余/无类型→LOW。
BEGIN;

CREATE TABLE IF NOT EXISTS api_cross_border_events (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at          TIMESTAMPTZ  NOT NULL,                -- 源事件时间（= api_runtime_events.occurred_at）
    client_ip            TEXT         NOT NULL DEFAULT '',       -- netip 归一化客户端 IP（maskIP 纪律）
    country              VARCHAR(8)   NOT NULL DEFAULT '',       -- ISO 3166-1 alpha-2
    asn                  BIGINT,                                 -- 预留：当前 GeoIP 数据源无 ASN，恒 NULL
    endpoint_key         VARCHAR(560) NOT NULL DEFAULT '',
    identity_fingerprint VARCHAR(128) NOT NULL DEFAULT '',       -- 匿名流量为空串（口径同 api_runtime_events）
    data_types           JSONB        NOT NULL DEFAULT '[]',     -- 去重数据类型标签数组
    direction            VARCHAR(4)   NOT NULL,
    risk_level           VARCHAR(8)   NOT NULL DEFAULT 'LOW',
    source_event_id      UUID         NOT NULL,                  -- 幂等锚点：源运行时事件
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT chk_api_cross_border_direction CHECK (direction IN ('OUT','IN')),
    CONSTRAINT chk_api_cross_border_risk CHECK (risk_level IN ('LOW','MEDIUM','HIGH'))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_cross_border_source
    ON api_cross_border_events (source_event_id, direction);
CREATE INDEX IF NOT EXISTS idx_api_cross_border_occurred
    ON api_cross_border_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_cross_border_country
    ON api_cross_border_events (country, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_cross_border_endpoint
    ON api_cross_border_events (endpoint_key, occurred_at DESC);

-- 生产方水位（单行）：记录已扫描到的事件时刻，与事件写入同事务推进
CREATE TABLE IF NOT EXISTS api_cross_border_state (
    id         BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),  -- 单行约束
    watermark  TIMESTAMPTZ,                                  -- NULL = 尚未扫描（首次全量回填）
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO api_cross_border_state (id, watermark) VALUES (TRUE, NULL)
ON CONFLICT (id) DO NOTHING;

-- 本土地区配置（出境判定基准；逗号分隔 ISO 国家码，默认 CN）。
-- 注意：本键当前未加入 settings.AllowedSettingKeys 白名单（settings.go 属其他分片范围），
-- 管理接口暂不可改，由集成方登记白名单后开放编辑。
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)
VALUES ('api_data', 'home_regions', '"CN"', 'string',
        '本土地区国家码（逗号分隔 ISO 3166-1 alpha-2）；数据出境判定基准，境外来源涉敏事件记为跨境观察')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
