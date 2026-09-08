-- 000057 告警通知外发（一期）：通知渠道表 + 内置 syslog 渠道 + 权限点 + notify 组抑制参数。
--
-- 渠道 config 为 JSONB：密值字段（wecom.webhook_url / feishu.webhook_url / feishu.secret /
-- smtp.password）由应用层 AES-256-GCM 加密后落库（enc:v1: 前缀，见 internal/notify），
-- 接口读出时一律脱敏为 ********，数据库与接口均不出现明文。
BEGIN;

CREATE TABLE IF NOT EXISTS notification_channels (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         VARCHAR(128) NOT NULL,
    type         VARCHAR(16)  NOT NULL,                -- wecom / feishu / smtp / syslog
    enabled      BOOLEAN      NOT NULL DEFAULT TRUE,
    min_severity VARCHAR(16)  NOT NULL DEFAULT 'LOW',  -- 最低通知级别：LOW/MEDIUM/HIGH/CRITICAL
    categories   JSONB        NOT NULL DEFAULT '[]',   -- 订阅告警类别 code 列表；空 = 全部类别
    config       JSONB        NOT NULL DEFAULT '{}',   -- 渠道配置（密值字段加密存储）
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT chk_notification_channels_type CHECK (type IN ('wecom','feishu','smtp','syslog')),
    CONSTRAINT chk_notification_channels_min_severity CHECK (min_severity IN ('LOW','MEDIUM','HIGH','CRITICAL'))
);

-- 内置 syslog 渠道：复用 logging 组 syslog 外发配置（默认停用，启用后按通知层过滤/抑制外发）
INSERT INTO notification_channels (name, type, enabled, min_severity, categories, config)
SELECT '系统 syslog（沿用 logging 配置）', 'syslog', FALSE, 'LOW', '[]', '{}'
WHERE NOT EXISTS (SELECT 1 FROM notification_channels WHERE type = 'syslog');

-- 权限点：三权口径——SYSTEM_ADMIN 全量；SECURITY_ADMIN 只读
INSERT INTO permissions (code, name, module, description) VALUES
('notification.read',   '查看告警通知', 'notification', '查看告警通知渠道与元数据'),
('notification.update', '管理告警通知', 'notification', '新建/修改/删除告警通知渠道'),
('notification.test',   '测试告警通知', 'notification', '发送告警通知渠道测试消息')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN ('notification.read','notification.update','notification.test')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.code = 'SECURITY_ADMIN' AND p.code IN ('notification.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- 通知层风暴抑制参数（system_settings notify 组；键名同步加入 AllowedSettingKeys 白名单）
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('notify', 'notify_rate_limit_per_minute', '10',    'integer', FALSE, '告警通知每渠道每分钟最大发送条数（超出进入聚合摘要）'),
('notify', 'notify_mute_minutes',          '30',    'integer', FALSE, '相同告警指纹（类型+组件）的通知静默期（分钟）'),
('notify', 'notify_group_window_seconds',  '60',    'integer', FALSE, '被限流告警的聚合摘要窗口（秒）'),
('notify', 'notify_resolved',              'false', 'boolean', FALSE, '告警恢复（RESOLVED）时是否发送恢复通知')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
