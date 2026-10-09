-- 000167 WAF 规则 CNNVD 兼容性 P1（docs/CNNVD_COMPATIBILITY_DESIGN.md §2）。
--
--   custom_rules / waf_rules 各加 cnnvd_ids、cve_ids（JSONB 字符串数组，NOT NULL
--     DEFAULT '[]'，元素格式由应用层校验：CNNVD ^CNNVD-\d{6}-\d{3,}$、
--     CVE ^CVE-\d{4}-\d{4,}$，大写归一去重）；四列建 GIN 索引支撑按编号反查规则。
--   vuln_refs：漏洞条目本地档案小表（管理员手工维护，cnnvd_id 全局唯一），
--     供认证演示与运营把编号展开为规范名称/官方链接。
--   权限种子 waf_rule.vuln_ref.edit（module 沿用 waf_rules）：档案写操作权限点；
--     读沿用既有 waf_rules.read。三角色按现行口径（000100 再平衡后）：
--     SECURITY_ADMIN 全量授予；AUDIT_ADMIN 为纯审计角色不授予（读写均无）；
--     SYSTEM_ADMIN 对齐既有 WAF 规则权限口径不授予。
BEGIN;

-- ---------- 规则编号字段 ----------
ALTER TABLE custom_rules
    ADD COLUMN IF NOT EXISTS cnnvd_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE custom_rules
    ADD COLUMN IF NOT EXISTS cve_ids   JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE waf_rules
    ADD COLUMN IF NOT EXISTS cnnvd_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE waf_rules
    ADD COLUMN IF NOT EXISTS cve_ids   JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS idx_custom_rules_cnnvd_ids ON custom_rules USING GIN (cnnvd_ids);
CREATE INDEX IF NOT EXISTS idx_custom_rules_cve_ids   ON custom_rules USING GIN (cve_ids);
CREATE INDEX IF NOT EXISTS idx_waf_rules_cnnvd_ids    ON waf_rules    USING GIN (cnnvd_ids);
CREATE INDEX IF NOT EXISTS idx_waf_rules_cve_ids      ON waf_rules    USING GIN (cve_ids);

COMMENT ON COLUMN custom_rules.cnnvd_ids IS 'CNNVD 编号数组（如 ["CNNVD-202401-2345"]），应用层校验格式并大写归一去重';
COMMENT ON COLUMN custom_rules.cve_ids   IS 'CVE 编号数组（如 ["CVE-2024-0001"]），应用层校验格式并大写归一去重';
COMMENT ON COLUMN waf_rules.cnnvd_ids    IS 'CNNVD 编号数组（CRS 目录规则标注挂目录行，随目录版本留痕；P2 批量标注）';
COMMENT ON COLUMN waf_rules.cve_ids      IS 'CVE 编号数组（同 cnnvd_ids）';

-- ---------- 漏洞条目本地档案 ----------
CREATE TABLE IF NOT EXISTS vuln_refs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cnnvd_id     VARCHAR(32)  NOT NULL UNIQUE,
    cve_id       VARCHAR(32)  NOT NULL DEFAULT '',
    title        TEXT         NOT NULL DEFAULT '',
    severity     VARCHAR(16)  NOT NULL DEFAULT '',
    published_at DATE,
    url          TEXT         NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE vuln_refs IS 'CNNVD 漏洞条目本地档案（手工维护小表）：编号 → 规范名称/官方链接，供认证演示与交叉查询';

-- ---------- 权限种子 ----------
INSERT INTO permissions (code, name, module, description) VALUES
('waf_rule.vuln_ref.edit', '维护漏洞档案', 'waf_rules', '创建/修改/删除 CNNVD 漏洞档案（vuln_refs）')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员：全量（写权限点）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('waf_rule.vuln_ref.edit')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员不授写（000100 角色再平衡后其为纯审计角色，读侧 waf_rules.read 亦未持有）；
-- 系统管理员按既有 WAF 规则权限口径不授予（000007 起即无 waf_rules.*）。

COMMIT;
