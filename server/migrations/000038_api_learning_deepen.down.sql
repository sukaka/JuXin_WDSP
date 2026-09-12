-- 000038 回滚：删除学习生成条件配置键与 api_learning_jobs 学习质量维度列。
-- candidate_version_id 的外键约束随列删除一并移除。
BEGIN;

DELETE FROM system_settings WHERE setting_group = 'api_learning' AND setting_key IN (
  'min_valid_samples', 'min_unique_ips', 'min_unique_identities',
  'min_learning_duration_seconds', 'max_learning_duration_seconds', 'minimum_success_ratio'
);

ALTER TABLE api_learning_jobs
    DROP COLUMN IF EXISTS candidate_version_id,
    DROP COLUMN IF EXISTS first_sample_at,
    DROP COLUMN IF EXISTS unique_identities,
    DROP COLUMN IF EXISTS unique_ips;

COMMIT;
