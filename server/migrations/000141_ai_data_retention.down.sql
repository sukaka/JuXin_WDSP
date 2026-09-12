-- 000141 回滚：删除 ai 组保留期限设置（清理 sweep 回落到代码内置默认值）

BEGIN;

DELETE FROM system_settings WHERE setting_group = 'ai' AND setting_key IN (
  'retention_session_days', 'retention_tool_call_days', 'retention_draft_days',
  'retention_usage_days', 'retention_audit_days'
);

COMMIT;
