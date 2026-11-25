-- 000239 域名级 WAF 防护策略绑定：
--   允许为应用下的单个域名（application_domains）独立指定防护策略（protection_policies.id），
--   留空（NULL）表示继承所属应用绑定的防护策略或应用默认防护配置。
BEGIN;

ALTER TABLE application_domains
    ADD COLUMN IF NOT EXISTS policy_id UUID REFERENCES protection_policies(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_app_domains_policy
    ON application_domains (policy_id)
    WHERE policy_id IS NOT NULL;

COMMENT ON COLUMN application_domains.policy_id IS
    '域名级 WAF 防护策略 ID（为空表示继承所属应用的防护策略或应用默认防护配置）';

COMMIT;
