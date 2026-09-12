-- 000061 API 文件资产（W8-FILE / P1-04）：文件传输观测落地表 + 批量下载风险阈值种子。
--
-- 语义边界（任务书 §16/§106/§107 子集）：
--   生产方为 apiruntime.FileObsStore.RecordFileObservations：消费网关统一主事件
--   file_observations（multipart 上传 part 元数据 / Content-Disposition 下载观测，
--   仅元数据，文件内容永不落网关内存与库），按去重键 UPSERT 聚合。
--
-- 去重键设计（uq_api_file_assets_dedup）：
--   (endpoint_key, direction, filename, identity_fingerprint) ——同一文件被不同身份
--   传输各成一行（§107 同身份批量下载判定依赖身份维度，跨身份合并会丢失口径）；
--   匿名流量 identity_fingerprint='' 正常参与去重（空串是值不是 NULL）。
--   sha256 不进键：网关观测不含内容哈希（文件不落内存），列预留恒 NULL。
--
-- 列说明：
--   filename          明文截断 128（理由：资产盘点以文件名识别敏感文件流转，哈希会
--                     让 File TOP/敏感统计失去可读性；与 RawPath 同一脱敏纪律）；
--   extension         小写后缀（无点/超长后缀不识别为空串）；
--   mime              主类型小写（参数剥离，聚合口径）；
--   size_bytes        最近一次观测字节数（声明/传输口径，非历史最大）；
--   client_ip_masked  按掩码纪律落库（IPv4 /24、IPv6 /64 前缀，精确关联走事件来源指纹）；
--   sensitive_types   扩展名词表 v1 推导（凭据材料/数据库备份/数据导出；文件内容不可达，
--                     无内容级判定，词表保守只收高置信类别）；
--   transfer_count    近似累计（采集重放/断点回退会重复累计，与 param_obs 同口径）。
BEGIN;

CREATE TABLE IF NOT EXISTS api_file_assets (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id          UUID REFERENCES api_endpoints(id) ON DELETE SET NULL,
    endpoint_key         VARCHAR(560) NOT NULL DEFAULT '',
    direction            VARCHAR(8)   NOT NULL,
    filename             VARCHAR(128) NOT NULL DEFAULT '',
    extension            VARCHAR(16)  NOT NULL DEFAULT '',
    mime                 VARCHAR(128) NOT NULL DEFAULT '',
    size_bytes           BIGINT       NOT NULL DEFAULT 0,
    sha256               TEXT,                        -- 预留：网关观测不含内容哈希，当前恒 NULL
    identity_fingerprint VARCHAR(128) NOT NULL DEFAULT '', -- 匿名流量为空串（口径同 api_runtime_events）
    client_ip_masked     VARCHAR(64)  NOT NULL DEFAULT '',
    sensitive_types      JSONB        NOT NULL DEFAULT '[]',
    first_seen           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    transfer_count       INTEGER      NOT NULL DEFAULT 1,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT chk_api_file_assets_direction CHECK (direction IN ('UPLOAD','DOWNLOAD'))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_file_assets_dedup
    ON api_file_assets (endpoint_key, direction, filename, identity_fingerprint);
CREATE INDEX IF NOT EXISTS idx_api_file_assets_last_seen
    ON api_file_assets (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_api_file_assets_endpoint
    ON api_file_assets (endpoint_key, last_seen DESC);
-- 敏感文件统计口径：sensitive_types 非空（部分索引避免全表扫）
CREATE INDEX IF NOT EXISTS idx_api_file_assets_sensitive
    ON api_file_assets (last_seen DESC) WHERE sensitive_types <> '[]'::jsonb;

-- 文件风险阈值（§107 子集：同身份批量下载判定上限，近 1h 不同文件数超过即产出
-- FILE_BULK_DOWNLOAD 风险发现）。
-- 注意：本键当前未加入 settings.AllowedSettingKeys 白名单（settings.go 属其他分片范围），
-- 管理接口暂不可改，由集成方登记白名单后开放编辑（与 000058 home_regions 同一纪律）。
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)
VALUES ('api_data', 'file_bulk_download_threshold', '50', 'integer',
        '同身份批量下载风险阈值：近1小时同一身份下载不同文件数超过该值记 FILE_BULK_DOWNLOAD 风险发现')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
