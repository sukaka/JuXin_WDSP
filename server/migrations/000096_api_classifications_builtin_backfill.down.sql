-- 回退本次回填的说明；编码行本身保留（启发式分类与报表联表依赖目录存在）。
BEGIN;

UPDATE api_classifications SET description = ''
WHERE is_builtin AND code IN (
    'AUTH', 'TRADE', 'FILE', 'ADMIN', 'USER_MGMT', 'QUERY', 'GENERAL',
    'INTERNAL', 'PARTNER', 'PUBLIC'
);

COMMIT;
