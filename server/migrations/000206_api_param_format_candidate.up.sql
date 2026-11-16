-- 000206 阶段8 §16 字符串微模型固定格式候选。
BEGIN;

ALTER TABLE api_parameter_value_obs
    ADD COLUMN IF NOT EXISTS format_sample_count BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS format_counts       JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN api_parameter_value_obs.format_sample_count IS
    '合格非空字符串格式样本总数；未知格式计入分母，敏感抑制/空值/非字符串不计入';
COMMENT ON COLUMN api_parameter_value_obs.format_counts IS
    '固定格式候选计数 map；键仅 UUID/EMAIL/IPV4/IPV6/DATE/DATETIME，不含明文';

ALTER TABLE api_parameter_statistics
    ADD COLUMN IF NOT EXISTS format_candidate       TEXT,
    ADD COLUMN IF NOT EXISTS format_candidate_ratio DOUBLE PRECISION;

COMMENT ON COLUMN api_parameter_statistics.format_candidate IS
    '至少20个合格字符串样本且唯一最高占比>=0.9时生成；NULL=观测不足/平手/未知';
COMMENT ON COLUMN api_parameter_statistics.format_candidate_ratio IS
    '固定格式候选数/合格字符串格式样本总数；NULL=无候选';

COMMIT;
