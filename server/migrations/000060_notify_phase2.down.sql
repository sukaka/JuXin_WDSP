-- 000060 回滚：删除 notify 组二期阈值设置；渠道类型 CHECK 约束还原为一期词表。
-- 注意：若库中已存在 sms 类型渠道，还原约束会因违反 CHECK 失败，须先删除 sms 渠道。
BEGIN;

DELETE FROM system_settings
WHERE setting_group = 'notify' AND setting_key IN
  ('notify_security_spike_threshold','notify_cc_spike_threshold');

ALTER TABLE notification_channels DROP CONSTRAINT chk_notification_channels_type;
ALTER TABLE notification_channels ADD CONSTRAINT chk_notification_channels_type
  CHECK (type IN ('wecom','feishu','smtp','syslog'));

COMMIT;
