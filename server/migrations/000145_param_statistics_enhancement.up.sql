-- 000145 阶段8 §16/§17 参数微模型统计增强。
--
-- 语义：STAGE_8 §16/§17 要求字符串微模型 P50/P90/P95/P99/熵/前后缀、数值微模型
-- 离群计数、参数出现率/空值率等扩展统计。本迁移为两侧补列：
--   1) api_parameter_value_obs（观测数据源）：null_count、长度/数值蓄水池、
--      字符直方图、前后缀计数——由网关脱敏上报经 apiruntime 增量合并写入
--      （写入方挂接为后续工作，列先行落地，旧版网关不上报时保持默认值）；
--   2) api_parameter_statistics（统计画像）：presence_rate/null_rate、长度/数值
--      分位数、字符熵、前后缀 TopN、数值离群计数——由 RefreshParameterStatistics
--      按窗口全量重算回填（幂等覆盖，与既有长度/值域/基数回填语义一致）。
--
-- 空值口径：可空统计列 NULL = 无观测数据源（旧版网关未上报对应观测）；
-- presence_rate 分母为端点 accepted 学习样本数，null_rate 分母为观测样本数；
-- common_prefixes/common_suffixes 仅存脱敏哈希计数 [{key,count},...]，不落明文。
BEGIN;

ALTER TABLE api_parameter_value_obs
    ADD COLUMN IF NOT EXISTS null_count       BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS length_reservoir JSONB  NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS value_reservoir  JSONB  NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS char_histogram   JSONB  NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS prefix_counts    JSONB  NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS suffix_counts    JSONB  NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN api_parameter_value_obs.null_count IS
    '观测中显式 null 值出现次数（网关上上报 null 标记，不落明文）';
COMMENT ON COLUMN api_parameter_value_obs.length_reservoir IS
    '长度观测蓄水池（升序浮点数组，上限见 apimodels.ReservoirCap），用于分位数重算';
COMMENT ON COLUMN api_parameter_value_obs.value_reservoir IS
    '数值观测蓄水池（升序浮点数组，上限见 apimodels.ReservoirCap），用于分位数/离群重算';
COMMENT ON COLUMN api_parameter_value_obs.char_histogram IS
    '字符分布直方图（256 桶计数数组），用于字符香农熵重算；不含明文';
COMMENT ON COLUMN api_parameter_value_obs.prefix_counts IS
    '常见前缀计数（脱敏哈希 → 次数 map），用于 TopN 重算；不含明文';
COMMENT ON COLUMN api_parameter_value_obs.suffix_counts IS
    '常见后缀计数（脱敏哈希 → 次数 map），用于 TopN 重算；不含明文';

ALTER TABLE api_parameter_statistics
    ADD COLUMN IF NOT EXISTS presence_rate         DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS null_rate             DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS length_p50            INTEGER,
    ADD COLUMN IF NOT EXISTS length_p90            INTEGER,
    ADD COLUMN IF NOT EXISTS length_p95            INTEGER,
    ADD COLUMN IF NOT EXISTS length_p99            INTEGER,
    ADD COLUMN IF NOT EXISTS value_p50             DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS value_p90             DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS value_p95             DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS value_p99             DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS string_entropy        DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS common_prefixes       JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS common_suffixes       JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS numeric_outlier_count BIGINT;

COMMENT ON COLUMN api_parameter_statistics.presence_rate IS
    '参数出现率 = 观测样本数 / 端点 accepted 学习样本数（钳制到 [0,1]）；NULL = 无观测';
COMMENT ON COLUMN api_parameter_statistics.null_rate IS
    '空值率 = null_count / 观测样本数；NULL = 无观测';
COMMENT ON COLUMN api_parameter_statistics.length_p50 IS '长度 P50 分位数（蓄水池重算，四舍五入取整）；NULL = 无观测';
COMMENT ON COLUMN api_parameter_statistics.length_p90 IS '长度 P90 分位数；NULL = 无观测';
COMMENT ON COLUMN api_parameter_statistics.length_p95 IS '长度 P95 分位数；NULL = 无观测';
COMMENT ON COLUMN api_parameter_statistics.length_p99 IS '长度 P99 分位数；NULL = 无观测';
COMMENT ON COLUMN api_parameter_statistics.value_p50 IS '数值 P50 分位数（蓄水池重算）；NULL = 无观测';
COMMENT ON COLUMN api_parameter_statistics.value_p90 IS '数值 P90 分位数；NULL = 无观测';
COMMENT ON COLUMN api_parameter_statistics.value_p95 IS '数值 P95 分位数；NULL = 无观测';
COMMENT ON COLUMN api_parameter_statistics.value_p99 IS '数值 P99 分位数；NULL = 无观测';
COMMENT ON COLUMN api_parameter_statistics.string_entropy IS
    '字符香农熵（bits/字符，256 桶直方图精确合并重算）；NULL = 无观测';
COMMENT ON COLUMN api_parameter_statistics.common_prefixes IS
    '常见前缀 TopN（脱敏哈希计数 [{key,count},...]，计数降序键升序）；空数组 = 无观测';
COMMENT ON COLUMN api_parameter_statistics.common_suffixes IS
    '常见后缀 TopN（脱敏哈希计数 [{key,count},...]，计数降序键升序）；空数组 = 无观测';
COMMENT ON COLUMN api_parameter_statistics.numeric_outlier_count IS
    '数值离群计数（IQR 栅栏法，1.5×IQR 外记离群）；NULL = 观测不足（<4 样本）';

COMMIT;
