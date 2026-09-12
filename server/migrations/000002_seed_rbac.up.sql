-- 阶段2 种子数据：三权内置角色、权限清单、角色-权限映射
-- 密码与账号不在本文件初始化（由服务首次启动的安全初始化流程创建）

BEGIN;

-- ---------- 权限 ----------
INSERT INTO permissions (code, name, module, description) VALUES
('dashboard.read_basic',   '工作台基础信息', 'dashboard',   '查看工作台基础运行信息'),
('profile.read',           '查看个人资料',   'profile',     '查看自己的资料与权限'),
('profile.update',         '修改个人资料',   'profile',     '修改自己的显示名称与密码'),
('sessions.read_self',     '查看自己的会话', 'sessions',    '查看自己的登录会话'),
('sessions.revoke_self',   '结束自己的会话', 'sessions',    '结束自己的其他会话'),
('sessions.read',          '查看全部会话',   'sessions',    '查看所有用户会话'),
('sessions.revoke',        '强制下线',       'sessions',    '结束任意用户会话'),
('users.read',             '查看用户',       'users',       '查看用户列表与详情'),
('users.read_summary',     '查看用户摘要',   'users',       '查看用户基础摘要信息'),
('users.create',           '创建用户',       'users',       '创建新用户'),
('users.update',           '修改用户',       'users',       '修改用户资料与角色'),
('users.disable',          '启停用户',       'users',       '启用或停用用户'),
('users.reset_password',   '重置密码',       'users',       '重置用户密码生成临时密码'),
('users.unlock',           '解锁用户',       'users',       '解除用户登录锁定'),
('users.force_logout',     '强制用户下线',   'users',       '结束指定用户全部会话'),
('roles.read',             '查看角色',       'roles',       '查看角色及其权限'),
('permissions.read',       '查看权限清单',   'roles',       '查看系统权限清单'),
('system_settings.read',   '查看系统设置',   'system',      '查看系统设置'),
('system_settings.update', '修改系统设置',   'system',      '修改系统设置'),
('login_logs.read',        '查看登录日志',   'login_logs',  '查看全部登录日志'),
('login_logs.read_limited','登录日志摘要',   'login_logs',  '查看账号维护相关登录日志摘要'),
('login_logs.export',      '导出登录日志',   'login_logs',  '导出登录日志'),
('audits.read',            '查看操作审计',   'audits',      '查看全部操作审计'),
('audits.export',          '导出操作审计',   'audits',      '导出操作审计')
ON CONFLICT (code) DO NOTHING;

-- ---------- 三权内置角色 ----------
INSERT INTO roles (code, name, description, is_builtin) VALUES
('SYSTEM_ADMIN',   '系统管理员', '负责用户管理、角色分配、系统参数、网关维护、备份恢复、系统运行维护。不得查看完整安全事件敏感内容，不得删除审计日志。', TRUE),
('SECURITY_ADMIN', '安全管理员', '负责Web应用管理、防护策略、黑白名单、CC防护、规则配置、例外策略、安全事件处置、安全报表。不得管理系统管理员和审计管理员账号。', TRUE),
('AUDIT_ADMIN',    '审计管理员', '负责查看登录日志、操作审计、策略变更记录、配置发布记录，导出审计报告，审查高风险操作。不得修改防护策略和业务配置。', TRUE)
ON CONFLICT (code) DO NOTHING;

-- ---------- 角色-权限映射 ----------
-- 系统管理员
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN (
  'dashboard.read_basic','profile.read','profile.update',
  'users.read','users.create','users.update','users.disable','users.reset_password','users.unlock','users.force_logout',
  'roles.read','permissions.read',
  'system_settings.read','system_settings.update',
  'login_logs.read_limited',
  'sessions.read','sessions.revoke',
  'sessions.read_self','sessions.revoke_self'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 安全管理员（阶段2仅基础工作台能力）
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN (
  'dashboard.read_basic','profile.read','profile.update',
  'sessions.read_self','sessions.revoke_self'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN (
  'dashboard.read_basic','profile.read','profile.update',
  'audits.read','audits.export',
  'login_logs.read','login_logs.export',
  'users.read_summary','roles.read','permissions.read',
  'sessions.read_self','sessions.revoke_self'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
