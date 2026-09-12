-- 000054 API 主动扫描发现（W6-D / P1-07）：扫描引擎结论载体。
--
-- 脱敏纪律与 apiruntime/findings.go 同一标准：evidence_json 只落判定规则/状态码/
-- 命中字段名（不落原始数据）；request_sample / response_sample 脱敏截断
-- （authorization/cookie 等凭据头值替换 [redacted]，响应样本超长截断；
-- SENSITIVE_EXPOSURE / BOLA_COMPARE 探针不落响应原文，只落字段名/哈希证据）。
-- 扫描发现不自动改写 api_runtime_findings / api_weaknesses：确认与误报处置走
-- 人工接口；weakness_id 为确认时关联的弱点（复测回写走 apiweakness 已实现状态机）。
BEGIN;

CREATE TABLE IF NOT EXISTS api_scan_findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id          UUID NOT NULL REFERENCES api_scan_jobs(id) ON DELETE CASCADE,
    engine          TEXT         NOT NULL DEFAULT 'builtin', -- 产出引擎（builtin=内置探针引擎；外部引擎以结果导入适配）
    template        TEXT         NOT NULL,                   -- 探针集（AUTH_REQUIRED/DEPRECATED_ALIVE/SENSITIVE_EXPOSURE/SCHEMA_CONFORM/BOLA_COMPARE/METHOD_ENUM）
    endpoint_key    VARCHAR(560) NOT NULL DEFAULT '',        -- 命中端点（"METHOD /path" 归一键）
    category        TEXT         NOT NULL DEFAULT '',        -- AUTHN / AUTHZ / LIFECYCLE / SENSITIVE / SCHEMA
    severity        VARCHAR(32)  NOT NULL DEFAULT 'INFO',    -- INFO / LOW / MEDIUM / HIGH / CRITICAL
    confidence      DOUBLE PRECISION NOT NULL DEFAULT 0,     -- 0~1 探针判定置信度
    evidence_json   JSONB        NOT NULL DEFAULT '{}',      -- 脱敏证据（判定规则/状态码/命中字段名/响应哈希）
    request_sample  TEXT         NOT NULL DEFAULT '',        -- 脱敏截断请求样本（凭据头值 [redacted]）
    response_sample TEXT         NOT NULL DEFAULT '',        -- 脱敏截断响应样本（敏感探针不落原文）
    status          VARCHAR(32)  NOT NULL DEFAULT 'NEW',
    weakness_id     UUID REFERENCES api_weaknesses(id) ON DELETE SET NULL, -- 人工确认时关联的弱点
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT chk_api_scan_findings_status CHECK (status IN ('NEW','CONFIRMED','FALSE_POSITIVE','RETIRED')),
    CONSTRAINT chk_api_scan_findings_severity CHECK (severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL'))
);
CREATE INDEX IF NOT EXISTS idx_api_scan_findings_job ON api_scan_findings (job_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_scan_findings_status ON api_scan_findings (status, severity);

COMMIT;
