-- 000060 告警通知外发（二期）：短信渠道类型 + 安全事件聚合告警阈值。
--
-- 1. notification_channels.type 词表扩展 'sms'（通用 HTTP 短信网关；
--    config 密值字段 app_secret 由应用层 AES-256-GCM 加密落库，同一期范式）。
-- 2. system_settings notify 组新增 2 个聚合告警阈值键
--    （消费侧为 systemalerts.EvaluateSecuritySpikes，键名同步加入 AllowedSettingKeys 白名单）。
BEGIN;

-- 渠道类型 CHECK 约束扩展（sms）
ALTER TABLE notification_channels DROP CONSTRAINT chk_notification_channels_type;
ALTER TABLE notification_channels ADD CONSTRAINT chk_notification_channels_type
  CHECK (type IN ('wecom','feishu','smtp','syslog','sms'));

-- 安全事件聚合告警阈值（1 分钟窗口内 HIGH/CRITICAL 安全事件条数达阈触发 SECURITY_EVENT_SPIKE）
-- CC 封禁聚合告警阈值（1 分钟窗口内 CC_TEMP_BLOCK_CREATED 条数达阈触发 CC_BAN_SPIKE）
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('notify', 'notify_security_spike_threshold', '10', 'integer', FALSE, '安全事件激增告警阈值（1 分钟内 HIGH/CRITICAL 安全事件条数）'),
('notify', 'notify_cc_spike_threshold',       '20', 'integer', FALSE, 'CC 封禁激增告警阈值（1 分钟内封禁条数）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
