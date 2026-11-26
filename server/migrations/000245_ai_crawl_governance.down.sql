-- 回滚 000245：移除 ai_crawl 权限种子及 AI 爬虫治理三张表
BEGIN;

DELETE FROM role_permissions
WHERE permission_id IN (SELECT id FROM permissions WHERE code IN ('ai_crawl.read', 'ai_crawl.manage'));

DELETE FROM permissions WHERE code IN ('ai_crawl.read', 'ai_crawl.manage');

DROP TABLE IF EXISTS ai_crawl_policy_versions;
DROP TABLE IF EXISTS ai_crawl_policies;
DROP TABLE IF EXISTS ai_crawler_directories;

COMMIT;
