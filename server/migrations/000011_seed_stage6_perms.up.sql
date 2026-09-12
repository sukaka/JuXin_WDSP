-- 阶段6 种子：态势/报表/监控/备份/升级/交付权限
-- 安全管理员：态势+统计+报告+安全告警；系统管理员：运行监控+备份+升级+交付；审计管理员：只读+处置类统计

BEGIN;

INSERT INTO permissions (code, name, module, description) VALUES
('dashboard.security.read',   '安全态势查看',   'dashboard', '查看安全态势首页'),
('dashboard.runtime.read',    '运行态势查看',   'dashboard', '查看运行监控态势'),
('dashboard.audit.read',      '审计态势查看',   'dashboard', '查看审计与处置统计态势'),
('analytics.security.read',   '安全统计分析',   'analytics', '查看请求/WAF/CC/访问控制统计'),
('analytics.disposition.read','处置统计分析',   'analytics', '查看事件处置与审计统计'),
('reports.read',              '查看报告',       'reports',   '查看报告任务与预览'),
('reports.create',            '创建报告',       'reports',   '创建日报/周报/月报/自定义报告'),
('reports.download',          '下载报告',       'reports',   '下载报告文件'),
('reports.delete_own',        '删除本人报告',   'reports',   '删除本人创建的报告'),
('reports.read_audit',        '审计查看报告',   'reports',   '审计角色查看报告'),
('reports.download_audit',    '审计下载报告',   'reports',   '审计角色下载报告'),
('report_templates.manage',   '报告模板管理',   'reports',   '管理报告模板'),
('system_health.read',        '运行监控查看',   'monitoring','查看组件运行与存储监控'),
('system_alerts.read',        '系统告警查看',   'monitoring','查看系统告警'),
('system_alerts.read_security','安全告警查看',  'monitoring','查看安全相关系统告警'),
('system_alerts.read_audit',  '审计查看告警',   'monitoring','审计角色查看告警'),
('system_alerts.acknowledge', '告警确认处置',   'monitoring','确认/解决/忽略系统告警'),
('system_alerts.acknowledge_security','安全告警处置','monitoring','确认/解决安全相关告警'),
('backups.read',              '查看备份',       'backup',    '查看备份任务与文件'),
('backups.create',            '创建备份',       'backup',    '创建全量/配置备份'),
('backups.verify',            '验证备份',       'backup',    '执行备份完整性验证'),
('backups.restore',           '执行恢复',       'backup',    '执行隔离恢复与正式恢复'),
('backups.delete',            '删除备份',       'backup',    '删除备份文件'),
('backup_records.read',       '审计查看备份记录','backup',   '审计角色查看备份记录'),
('restore_records.read',      '审计查看恢复记录','backup',   '审计角色查看恢复记录'),
('upgrades.read',             '查看升级',       'upgrade',   '查看升级包与升级任务'),
('upgrades.precheck',         '升级前检查',     'upgrade',   '执行升级前检查'),
('upgrades.execute',          '执行升级',       'upgrade',   '执行系统升级'),
('upgrades.rollback',         '执行回滚',       'upgrade',   '执行升级失败回滚'),
('upgrade_records.read',      '审计查看升级记录','upgrade',  '审计角色查看升级记录'),
('delivery_checks.read',      '查看交付检查',   'delivery',  '查看交付检查结果'),
('delivery_checks.run',       '执行交付检查',   'delivery',  '执行交付检查')
ON CONFLICT (code) DO NOTHING;

-- 安全管理员
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN (
  'dashboard.security.read','analytics.security.read',
  'reports.read','reports.create','reports.download','reports.delete_own','report_templates.manage',
  'system_alerts.read_security','system_alerts.acknowledge_security'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 系统管理员
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN (
  'dashboard.runtime.read','system_health.read',
  'system_alerts.read','system_alerts.acknowledge',
  'backups.read','backups.create','backups.verify','backups.restore','backups.delete',
  'upgrades.read','upgrades.precheck','upgrades.execute','upgrades.rollback',
  'delivery_checks.read','delivery_checks.run'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 审计管理员
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'AUDIT_ADMIN' AND p.code IN (
  'dashboard.audit.read','analytics.disposition.read',
  'reports.read_audit','reports.download_audit',
  'system_alerts.read_audit',
  'backup_records.read','restore_records.read','upgrade_records.read',
  'delivery_checks.read'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

COMMIT;
