-- 000036 API 运行时发现（Findings）生产化列补齐（WDSP P0-13 Risk 中心原料 / P0-11 Shadow-Zombie 断链修复）。
--
-- 背景：api_runtime_findings（000018）自建表起无生产写入方，Shadow/Zombie 页与
-- Findings 只读 API 生产恒空。本迁移为采集器物化写入（apiruntime findings.go）
-- 补齐承载列：
--   subject_type/subject_id  风险主体：IDENTITY（身份指纹，仅凭据派生）或
--                            IP（来源指纹；指纹可逆性纪律见 000029，不落明文）；
--   risk_score/risk_level    物化时事件级风险计分与等级（展示与排序用）；
--   count                    同指纹命中次数（NOT NULL DEFAULT 1）；
--   evidence_json            脱敏证据（仅字段名/粗类型词表/约束名，参数值永不落库）；
--   model_version/policy_version  判定所用模型与运行策略版本（溯源「当时生效哪版」）；
--   updated_at               最近一次 upsert 刷新时间；
--   dedup_fingerprint        去重指纹：sha256(endpoint_id + finding_type + subject_id)
--                            （生成与分隔约定见 apiruntime/findings.go 注释）。
-- 唯一索引承载 upsert 的 ON CONFLICT 目标；列可空时 NULL 互不相等（PG 语义），
-- 存量行（无写入方，理论为空）与异常空指纹行互不冲突。
BEGIN;

ALTER TABLE api_runtime_findings
    ADD COLUMN IF NOT EXISTS subject_type       TEXT,
    ADD COLUMN IF NOT EXISTS subject_id         TEXT,
    ADD COLUMN IF NOT EXISTS risk_score         INTEGER,
    ADD COLUMN IF NOT EXISTS risk_level         TEXT,
    ADD COLUMN IF NOT EXISTS count              INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS evidence_json      JSONB,
    ADD COLUMN IF NOT EXISTS model_version      TEXT,
    ADD COLUMN IF NOT EXISTS policy_version     TEXT,
    ADD COLUMN IF NOT EXISTS updated_at         TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS dedup_fingerprint  TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_api_runtime_findings_dedup
    ON api_runtime_findings (dedup_fingerprint);

COMMIT;
