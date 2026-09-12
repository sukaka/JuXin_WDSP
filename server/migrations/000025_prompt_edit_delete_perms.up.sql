-- 提示词管理增量权限：编辑与删除（仅系统管理员，与安全管理员只读边界一致）
BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('ai.prompts.edit',   '编辑Prompt',   'ai', '编辑 Prompt 名称等元数据'),
('ai.prompts.delete', '删除Prompt',   'ai', '删除未发布（DRAFT）的 Prompt')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN ('ai.prompts.edit','ai.prompts.delete')
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
