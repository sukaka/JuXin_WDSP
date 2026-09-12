-- 000040 API 敏感数据管理面（WDSP 阶段8 P0-19 补全，S5 分片）。
--
-- 背景：api_sensitive_fields（000018:281）建表后无生产写入方；分类分级实体与
-- 脱敏规则整体缺失（docs/API_SECURITY_CURRENT_STATE.md P0-19 节）。本迁移补齐三块：
--   1. api_sensitive_data_types：敏感数据类型（分类分级）实体 + 内置种子；
--   2. api_masking_rules：脱敏规则（列名为跨分片契约，发布分片按此读取下发网关，不得改动）；
--   3. api_sensitive_fields 增加首/末次发现时间、出现次数与来源明细列（SweepOnce 写入方使用）。
--
-- 内置种子与网关词表对应关系：gateway/dynamic_security/detectors/sensitive.go 的
-- defaultSensitivePatterns 仅按字段名匹配，数据类型标签为 phone/email/id_card/bank_card/
-- credential 五类；管理面内置类型将 credential 细分为 password/token/jwt 三类（值级
-- regex 区分），keywords 与网关字段名正则保持同词根。网关当前不做值级检测，
-- regex/validator 列为管理面数据，供后续值级检测与发布分片下发使用。
BEGIN;

-- ==================== 1. 敏感数据类型（分类分级） ====================
CREATE TABLE IF NOT EXISTS api_sensitive_data_types (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name           VARCHAR(128) NOT NULL UNIQUE,
    description    TEXT NOT NULL DEFAULT '',
    category       VARCHAR(64) NOT NULL DEFAULT '',      -- 业务分类（个人信息/金融信息/身份凭证…）
    level          VARCHAR(16) NOT NULL DEFAULT 'GENERAL'
                   CHECK (level IN ('NON_SENSITIVE','GENERAL','SENSITIVE','IMPORTANT','CORE')), -- 五级敏感等级
    data_type      VARCHAR(64) NOT NULL DEFAULT '',      -- 数据类型标签（与网关 evidence.data_type 对齐）
    locations      JSONB NOT NULL DEFAULT '[]',          -- 可能出现位置：query/json/form/xml/header/cookie/path/response_body
    keywords       JSONB NOT NULL DEFAULT '[]',          -- 字段名词根（与网关词表对齐）
    regex          TEXT NOT NULL DEFAULT '',             -- 值级正则（空 = 不做值检测）
    validator      VARCHAR(64) NOT NULL DEFAULT '',      -- 值校验器（'' / luhn，白名单可扩展）
    exclude_fields JSONB NOT NULL DEFAULT '[]',          -- 排除字段名（命中词根但非敏感值）
    status         VARCHAR(16) NOT NULL DEFAULT 'ENABLED'
                   CHECK (status IN ('ENABLED','DISABLED')),
    version        INTEGER NOT NULL DEFAULT 1,           -- 编辑自增（变更追踪）
    is_builtin     BOOLEAN NOT NULL DEFAULT FALSE,       -- 内置类型禁删、名称不可改（handler 层强制）
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_sensitive_data_types_level ON api_sensitive_data_types (level, status);

-- 内置敏感数据类型种子（is_builtin=TRUE；keywords 与网关 sensitive.go 词根一一对应）。
-- password/token 值形态不固定，不配置值级 regex（空串 = 仅字段名级识别）。
INSERT INTO api_sensitive_data_types
    (name, description, category, level, data_type, locations, keywords, regex, validator, exclude_fields, is_builtin) VALUES
('手机号码', '中国大陆手机号（11 位，1 开头）', '个人信息', 'SENSITIVE', 'phone',
 '["query","json","form","xml"]',
 '["phone","mobile","telephone","shouji","tel"]',
 '^1[3-9]\d{9}$', '',
 '["phone_verified","has_phone","is_phone"]', TRUE),
('电子邮箱', '电子邮箱地址', '个人信息', 'GENERAL', 'email',
 '["query","json","form","xml"]',
 '["email","e_mail","mail","youxiang"]',
 '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', '',
 '["email_verified","is_email"]', TRUE),
('身份证号', '中国大陆居民身份证号（18 位，末位可为 X）', '个人信息', 'IMPORTANT', 'id_card',
 '["query","json","form","xml"]',
 '["id_card","idcard","identity","shenfenzheng","sfz"]',
 '^\d{17}[\dXx]$', '',
 '[]', TRUE),
('银行卡号', '银行卡号（13-19 位数字，luhn 校验）', '金融信息', 'IMPORTANT', 'bank_card',
 '["query","json","form","xml"]',
 '["bank_card","card_number","card_no","pan","yinhangka"]',
 '^\d{13,19}$', 'luhn',
 '[]', TRUE),
('密码口令', '登录/支付口令（值形态不固定，仅字段名级识别；对应网关 credential 词表的口令子集）', '身份凭证', 'CORE', 'password',
 '["query","json","form","xml"]',
 '["password","passwd","pwd","mima"]',
 '', '',
 '["password_strength","password_hint"]', TRUE),
('访问令牌', 'API 访问令牌/密钥（值形态不固定，仅字段名级识别；对应网关 credential 词表的令牌子集）', '身份凭证', 'CORE', 'token',
 '["query","json","form","xml","header","cookie"]',
 '["token","api_key","apikey","access_key","secret","private_key"]',
 '', '',
 '["token_type","token_expires_in","expires_in"]', TRUE),
('JWT 令牌', 'JSON Web Token（eyJ 开头三段式；管理面值级扩展，网关词表暂无 jwt 词根）', '身份凭证', 'CORE', 'jwt',
 '["query","json","form","xml","header","cookie"]',
 '["jwt","id_token"]',
 '^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$', '',
 '[]', TRUE)
ON CONFLICT (name) DO NOTHING;

-- ==================== 2. 脱敏规则（列名为跨分片契约，发布分片按此读取下发网关） ====================
CREATE TABLE IF NOT EXISTS api_masking_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    scope           TEXT NOT NULL DEFAULT 'GLOBAL'
                    CHECK (scope IN ('GLOBAL','APPLICATION','ENDPOINT')),
    application_id  UUID REFERENCES applications(id) ON DELETE CASCADE, -- scope=APPLICATION 必填
    endpoint_key    TEXT,                                               -- scope=ENDPOINT 必填（METHOD + 空格 + 路径模板）
    field_path      TEXT NOT NULL DEFAULT '',                           -- 目标字段路径；与 data_type 至少其一
    data_type       TEXT,                                               -- 目标数据类型标签（整类脱敏）
    algorithm       TEXT NOT NULL DEFAULT 'MASK'
                    CHECK (algorithm IN ('MASK','HASH','REMOVE')),
    params_json     JSONB NOT NULL DEFAULT '{}',                        -- 算法参数（如 {"keep_prefix":3,"keep_suffix":4}）
    exclusions_json JSONB NOT NULL DEFAULT '{}',                        -- 排除对象 {"identity":[...],"role":[...],"ip":[...]}
    created_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- 作用域一致性（DB 兜底，handler 层同样校验并给出中文提示）
    CHECK (
        (scope = 'GLOBAL'      AND application_id IS NULL AND endpoint_key IS NULL) OR
        (scope = 'APPLICATION' AND application_id IS NOT NULL AND endpoint_key IS NULL) OR
        (scope = 'ENDPOINT'    AND endpoint_key IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_api_masking_rules_scope ON api_masking_rules (scope) WHERE enabled;
CREATE INDEX IF NOT EXISTS idx_api_masking_rules_endpoint ON api_masking_rules (endpoint_key) WHERE endpoint_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_api_masking_rules_application ON api_masking_rules (application_id) WHERE application_id IS NOT NULL;

-- ==================== 3. api_sensitive_fields 运行时统计列（SweepOnce 写入方使用） ====================
ALTER TABLE api_sensitive_fields
    ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS occurrence_count INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS source_detail JSONB;        -- 最近一次命中摘要 {location, rule_id, request_id, event_id}
-- 存量行回填（该表此前无生产写入方，防御性回填，正常为空表）
UPDATE api_sensitive_fields SET first_seen = created_at, last_seen = updated_at WHERE first_seen IS NULL;
CREATE INDEX IF NOT EXISTS idx_api_sensitive_fields_data_type ON api_sensitive_fields (data_type);
CREATE INDEX IF NOT EXISTS idx_api_sensitive_fields_last_seen ON api_sensitive_fields (last_seen DESC);

COMMIT;
