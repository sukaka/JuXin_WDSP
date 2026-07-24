-- 阶段7 增量回滚：删除 AI 自动降噪表与权限种子

BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
  SELECT id FROM permissions WHERE code IN ('ai.noise_reduction.use','ai.noise_reduction.manage')
);
DELETE FROM permissions WHERE code IN ('ai.noise_reduction.use','ai.noise_reduction.manage');

DROP TABLE IF EXISTS ai_noise_sweep_runs;
DROP TABLE IF EXISTS ai_noise_cluster_events;
DROP TABLE IF EXISTS ai_noise_clusters;

COMMIT;
