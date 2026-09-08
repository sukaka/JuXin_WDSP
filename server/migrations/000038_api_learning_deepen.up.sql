-- 000038 学习闭环加深（P0-01/02）：
-- 1) api_learning_jobs 增加学习质量维度列：unique_ips / unique_identities（accepted
--    样本的去重来源/身份数，落样时重算维护）、first_sample_at（首次落样时间，
--    学习时长条件的真实流量起点）、candidate_version_id（达标自动生成候选后回填，
--    类型对齐 api_model_versions.id，版本删除时置空不级联删任务）。
--    失败原因复用既有 last_error 列（FAILED 写入点见 learningjobs janitor），不新增列。
-- 2) 学习生成条件配置键（system_settings 组 api_learning，字符串数值，消费侧
--    解析+校验+越界回落默认，见 server/internal/learningjobs/conditions.go）：
--    min_valid_samples              有效样本数全局下限（与每任务 sample_target 取 max；
--                                   默认 10=MinSampleTarget，不改变既有默认行为）；
--    min_unique_ips                 去重来源 IP 下限（默认 1：至少一个可识别来源；0=不要求）；
--    min_unique_identities          去重身份下限（默认 0=不要求：身份指纹常缺失）；
--    min_learning_duration_seconds  最短学习时长（默认 0=不要求；起点=首次落样或任务启动）；
--    max_learning_duration_seconds  最长学习时长（默认 604800=7 天；超期未达标 → FAILED+last_error）；
--    minimum_success_ratio          最低成功率（默认 0=不要求；2xx/3xx 计成功，
--                                   无响应状态码的 accepted 样本不计入分母）。
BEGIN;

ALTER TABLE api_learning_jobs
    ADD COLUMN IF NOT EXISTS unique_ips           INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS unique_identities    INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS first_sample_at      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS candidate_version_id UUID REFERENCES api_model_versions(id) ON DELETE SET NULL;

-- 存量 RUNNING 任务回填：样本表按端点归属（非按任务），去重口径与落样维护一致
-- （accepted 且指纹非空；first_sample_at 取该端点全部样本的最早落样时间）。
UPDATE api_learning_jobs j SET
    unique_ips         = s.unique_ips,
    unique_identities  = s.unique_identities,
    first_sample_at    = s.first_sample_at
FROM (
    SELECT api_endpoint_id,
           count(DISTINCT source_fingerprint)   FILTER (WHERE accepted AND source_fingerprint <> '')   AS unique_ips,
           count(DISTINCT identity_fingerprint) FILTER (WHERE accepted AND identity_fingerprint <> '') AS unique_identities,
           min(collected_at) AS first_sample_at
    FROM api_learning_samples
    GROUP BY api_endpoint_id
) s
WHERE j.endpoint_id = s.api_endpoint_id AND j.status = 'RUNNING';

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('api_learning', 'min_valid_samples',              '"10"',    'string', FALSE, '学习达标条件：有效样本数全局下限（与每任务 sample_target 取较大者）'),
('api_learning', 'min_unique_ips',                 '"1"',     'string', FALSE, '学习达标条件：去重来源 IP 数下限（0=不要求）'),
('api_learning', 'min_unique_identities',          '"0"',     'string', FALSE, '学习达标条件：去重身份数下限（0=不要求）'),
('api_learning', 'min_learning_duration_seconds',  '"0"',     'string', FALSE, '学习达标条件：最短学习时长秒数（0=不要求；起点取首次落样或任务启动）'),
('api_learning', 'max_learning_duration_seconds',  '"604800"','string', FALSE, '学习最长时限秒数：超期仍未达标任务置 FAILED 并记录 last_error'),
('api_learning', 'minimum_success_ratio',          '"0"',     'string', FALSE, '学习达标条件：accepted 样本 2xx/3xx 成功率下限（0~1，0=不要求）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
