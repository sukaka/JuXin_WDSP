-- 000079 回滚：本迁移为存量数据修复（application_id 回填 + attack_type 重算），
-- 属数据订正——被覆盖的旧值本身是缺陷产物，无法也无须回滚。
-- 保留 no-op 语句以满足迁移工具对 down 文件的要求。
BEGIN;

SELECT 1;

COMMIT;
