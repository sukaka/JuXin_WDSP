-- 阶段3 权限种子：应用/域名/源站/证书/配置发布/版本/网关状态
-- 分配给安全管理员（业务操作）、系统管理员（运行维护只读）、审计管理员（审计只读）

BEGIN;

-- ---------- 新增权限 ----------
INSERT INTO permissions (code, name, module, description) VALUES
('applications.read',       '查看应用',     'applications', '查看Web应用列表与详情'),
('applications.create',     '创建应用',     'applications', '创建Web应用'),
('applications.update',     '修改应用',     'applications', '修改Web应用'),
('applications.disable',    '启停应用',     'applications', '启用或停用Web应用'),
('applications.delete',     '删除应用',     'applications', '删除Web应用'),
('applications.publish',    '发布应用配置', 'applications', '发布应用网关配置'),
('applications.rollback',   '回滚应用配置', 'applications', '回滚应用网关配置'),
('domains.read',            '查看域名',     'applications', '查看应用域名'),
('domains.create',          '新增域名',     'applications', '新增应用域名'),
('domains.update',          '修改域名',     'applications', '修改应用域名与监听'),
('domains.delete',          '删除域名',     'applications', '删除应用域名'),
('upstreams.read',          '查看源站',     'upstreams',    '查看源站'),
('upstreams.create',        '新增源站',     'upstreams',    '新增源站'),
('upstreams.update',        '修改源站',     'upstreams',    '修改源站与权重'),
('upstreams.delete',        '删除源站',     'upstreams',    '删除源站'),
('upstreams.test',          '测试源站',     'upstreams',    '源站连通性测试'),
('certificates.read',       '查看证书',     'certificates', '查看证书元数据'),
('certificates.create',     '上传证书',     'certificates', '上传HTTPS证书'),
('certificates.update',     '修改证书',     'certificates', '修改证书信息'),
('certificates.delete',     '删除证书',     'certificates', '删除未使用证书'),
('certificates.bind',       '绑定证书',     'certificates', '证书绑定与替换应用'),
('gateway_configs.preview', '配置预览',     'gateway',      '预览网关配置'),
('gateway_configs.validate','配置校验',     'gateway',      '校验网关配置'),
('gateway_configs.publish', '配置发布',     'gateway',      '发布网关配置'),
('gateway_configs.rollback','配置回滚',     'gateway',      '回滚网关配置'),
('publish_tasks.read',      '查看发布任务', 'gateway',      '查看配置发布任务'),
('config_versions.read',    '查看配置版本', 'gateway',      '查看配置版本与差异'),
('gateway_status.read',     '查看网关状态', 'gateway',      '查看网关运行状态'),
('gateway_runtime.read',    '查看网关运行', 'gateway',      '查看网关运行时详情'),
('certificates.read_metadata','证书元数据', 'certificates', '查看证书元数据(不含私钥)'),
('applications.read_audit', '应用变更审计', 'applications', '查看应用变更记录'),
('upstreams.read_audit',    '源站变更审计', 'upstreams',    '查看源站变更记录'),
('gateway_changes.read',    '网关变更审计', 'gateway',      '查看网关配置变更记录')
ON CONFLICT (code) DO NOTHING;

-- ---------- 安全管理员：业务操作全量 ----------
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN (
  'applications.read','applications.create','applications.update','applications.disable','applications.delete','applications.publish','applications.rollback',
  'domains.read','domains.create','domains.update','domains.delete',
  'upstreams.read','upstreams.create','upstreams.update','upstreams.delete','upstreams.test',
  'certificates.read','certificates.create','certificates.update','certificates.delete','certificates.bind',
  'gateway_configs.preview','gateway_configs.validate','gateway_configs.publish','gateway_configs.rollback',
  'publish_tasks.read','config_versions.read','gateway_status.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- ---------- 系统管理员：运行维护只读 ----------
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN (
  'gateway_status.read','gateway_runtime.read','publish_tasks.read','certificates.read_metadata','config_versions.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- ---------- 审计管理员：审计只读 ----------
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN (
  'applications.read_audit','upstreams.read_audit','certificates.read_metadata',
  'publish_tasks.read','config_versions.read','gateway_changes.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
