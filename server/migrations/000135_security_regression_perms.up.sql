-- 000135 安全回归证据登记权限种子（WDSP P1-04 R3）。
--   security_regression.read    查看回归运行/用例差异与门禁策略；
--   security_regression.import  上传受控证据对象并登记已签名的回归报告；
--   security_regression.policy  修改发布门禁模式/要求级别/证据有效期（含降级）。
-- 授权口径照 000129/000126 惯例：只读三角色全授，写权限仅 SYSTEM_ADMIN/SECURITY_ADMIN。
BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('security_regression.read', '查看安全回归证据', 'security', '查看安全回归运行摘要、用例差异与发布门禁策略'),
('security_regression.import', '登记安全回归证据', 'security', '上传受控证据对象并登记已签名的回归报告（不执行测试命令）'),
('security_regression.policy', '管理回归发布门禁', 'security', '修改安全回归发布门禁模式、要求级别与证据有效期')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN'
  AND p.code IN ('security_regression.read', 'security_regression.import', 'security_regression.policy')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN'
  AND p.code IN ('security_regression.read', 'security_regression.import', 'security_regression.policy')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN ('security_regression.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
