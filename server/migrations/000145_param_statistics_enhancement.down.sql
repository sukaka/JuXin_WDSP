-- 000145 回滚：移除参数微模型统计增强列（观测写入方缺失容忍，回滚不影响既有数据读写；
-- 新统计列在旧表上无落点，仅不持久化）。
BEGIN;

ALTER TABLE api_parameter_statistics
    DROP COLUMN IF EXISTS presence_rate,
    DROP COLUMN IF EXISTS null_rate,
    DROP COLUMN IF EXISTS length_p50,
    DROP COLUMN IF EXISTS length_p90,
    DROP COLUMN IF EXISTS length_p95,
    DROP COLUMN IF EXISTS length_p99,
    DROP COLUMN IF EXISTS value_p50,
    DROP COLUMN IF EXISTS value_p90,
    DROP COLUMN IF EXISTS value_p95,
    DROP COLUMN IF EXISTS value_p99,
    DROP COLUMN IF EXISTS string_entropy,
    DROP COLUMN IF EXISTS common_prefixes,
    DROP COLUMN IF EXISTS common_suffixes,
    DROP COLUMN IF EXISTS numeric_outlier_count;

ALTER TABLE api_parameter_value_obs
    DROP COLUMN IF EXISTS null_count,
    DROP COLUMN IF EXISTS length_reservoir,
    DROP COLUMN IF EXISTS value_reservoir,
    DROP COLUMN IF EXISTS char_histogram,
    DROP COLUMN IF EXISTS prefix_counts,
    DROP COLUMN IF EXISTS suffix_counts;

COMMIT;
