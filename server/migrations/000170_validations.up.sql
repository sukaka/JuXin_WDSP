-- 000170 无副作用模拟报告（NG-COV-03 管理面；NG-BASE-02 §4.4 / RD_PLAN §5.3）。
--
--   validation_reports：模拟报告落库（创建时 status 恒 COMPLETED；STALE 在读出时
--     求值——读取时与当前策略摘要比较，不一致即响应 STALE，不回写数据库，
--     免写路径恒最新，见 server/internal/validations/service.go）。
--   report_json 存完整报告（verdicts 含 would_block 模拟语义；输入 Finding 批次
--     一并存入以支撑读出时审计复核——脱敏输入，服务端已拒 evidence 原文）。
--   权限种子 api_protection.validate（「创建无副作用模拟」）：创建 = 动作，仅授
--     SECURITY_ADMIN；AUDIT_ADMIN 不授（纯审计角色只读 api_protection.read，
--     000169 已授）；SYSTEM_ADMIN 不授（安全运营域，同 000169 口径）。
BEGIN;

CREATE TABLE IF NOT EXISTS validation_reports (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_digest  VARCHAR(64) NOT NULL,
    corpus_digest  VARCHAR(64) NOT NULL,
    inputs_digest  VARCHAR(64) NOT NULL,
    status         VARCHAR(16) NOT NULL DEFAULT 'COMPLETED',
    report_json    JSONB       NOT NULL,
    created_by     UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE validation_reports IS '无副作用模拟报告（NG-COV-03）：策略/语料/输入摘要绑定；STALE 读出时求值不回写；模拟非 PROTECT 实测，不能单独满足上线条件';

CREATE INDEX IF NOT EXISTS idx_validation_reports_created_at
    ON validation_reports (created_at DESC);

INSERT INTO permissions (code, name, module, description) VALUES
('api_protection.validate', '创建无副作用模拟', 'api_protection', '创建冻结策略+脱敏证据的决策层重放报告（validation_reports；无副作用，非 PROTECT 实测）')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员（创建=动作）；审计管理员/系统管理员不授（口径见头注释）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('api_protection.validate')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
