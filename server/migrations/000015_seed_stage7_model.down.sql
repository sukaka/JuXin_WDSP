-- 阶段7 模型与 Agent 种子回滚

BEGIN;

DELETE FROM system_settings WHERE setting_group = 'ai' AND setting_key IN ('route_simple', 'route_standard', 'route_high');

DELETE FROM ai_agents WHERE code IN
  ('dispatcher', 'security_event', 'log_analysis', 'waf_policy', 'asset', 'ops_diagnostic', 'report', 'knowledge');

DELETE FROM ai_models WHERE id = 'f7a10001-0000-4000-8000-000000000002';
DELETE FROM ai_model_providers WHERE id = 'f7a10001-0000-4000-8000-000000000001';

COMMIT;
