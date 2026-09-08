-- 000093 回滚：删除 kill switch 设置种子、apm.diagnostics.manage 权限种子与诊断会话表
-- （部分唯一索引随表删除；不回滚已下发的策略版本——策略为追加式历史记录）
BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'apm_diagnostics' AND setting_key = 'kill_switch';

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code = 'apm.diagnostics.manage'
);
DELETE FROM permissions WHERE code = 'apm.diagnostics.manage';

DROP TABLE IF EXISTS apm_diagnostic_sessions;

COMMIT;
