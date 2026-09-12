-- 阶段2 种子数据：系统默认设置（密码策略、登录策略、会话策略、展示设置）

BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
-- 密码策略
('password', 'min_length',          '12',   'integer', FALSE, '密码最小长度'),
('password', 'require_uppercase',   'true', 'boolean', FALSE, '必须包含大写字母'),
('password', 'require_lowercase',   'true', 'boolean', FALSE, '必须包含小写字母'),
('password', 'require_digit',       'true', 'boolean', FALSE, '必须包含数字'),
('password', 'require_special',     'true', 'boolean', FALSE, '必须包含特殊字符'),
('password', 'history_count',       '5',    'integer', FALSE, '不得与最近N次密码重复'),
('password', 'expire_days',         '90',   'integer', FALSE, '密码有效期（天）'),
('password', 'expire_remind_days',  '7',    'integer', FALSE, '到期前N天提醒'),
('password', 'check_weak',          'true', 'boolean', FALSE, '启用弱口令检查'),
-- 登录策略
('login', 'max_failed_attempts',    '5',    'integer', FALSE, '连续失败N次后锁定'),
('login', 'lock_minutes',           '15',   'integer', FALSE, '锁定时长（分钟）'),
('login', 'captcha_enabled',        'true', 'boolean', FALSE, '是否启用图形验证码'),
('login', 'captcha_expire_seconds', '120',  'integer', FALSE, '验证码有效期（秒）'),
('login', 'captcha_case_sensitive', 'false','boolean', FALSE, '验证码是否区分大小写'),
('login', 'rate_limit_per_minute',  '10',   'integer', FALSE, '登录接口每IP每分钟限速'),
('login', 'allow_multi_session',    'true', 'boolean', FALSE, '是否允许同账号多会话'),
-- 会话策略
('session', 'idle_timeout_minutes',   '30',  'integer', FALSE, '空闲超时（分钟）'),
('session', 'absolute_timeout_hours', '8',   'integer', FALSE, '绝对会话时长（小时）'),
('session', 'revoke_on_password_change', 'true', 'boolean', FALSE, '修改密码后结束其他会话'),
('session', 'max_sessions_per_user',    '5',   'integer', FALSE, '单用户最大会话数'),
('session', 'cookie_samesite',          '"Lax"', 'string', FALSE, 'Cookie SameSite 策略'),
-- 系统展示
('display', 'system_name',     '"九章WEB应用智能防护系统"', 'string', FALSE, '系统名称'),
('display', 'system_short_name', '"九章WAF"',              'string', FALSE, '系统简称'),
('display', 'login_title',     '"九章WEB应用智能防护系统 V2.0"', 'string', FALSE, '登录页标题'),
('display', 'support_info',    '"请联系系统管理员获取技术支持"', 'string', FALSE, '技术支持信息'),
('display', 'default_timezone','"Asia/Shanghai"',         'string', FALSE, '默认时区'),
('display', 'default_language','"zh-CN"',                 'string', FALSE, '默认语言')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
