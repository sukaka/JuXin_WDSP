-- 000235 API 确认资产时自动启动学习默认开关（api_learning 组）
--
--   默认关闭（false），保持既有人工按需触发行为不变；
--   开启后，确认接口为正式资产时（POST /api/v1/api-security/endpoints/confirm）
--   在操作者具备 api_learning.start 权限且未显式取消的前提下，自动为未学习/已暂停的接口启动模型学习，
--   已在学习中或已完成学习的接口自动跳过；学习达标后仍仅产出候选模型，需人工审核确认后生效。
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('api_learning', 'auto_start_on_confirm', 'false', 'boolean', FALSE, '确认 API 接口为正式资产时默认自动启动模型学习（需具备学习启动权限；学习中/已完成接口自动跳过）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
