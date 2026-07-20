-- 回滚 000003_seed_settings

BEGIN;

DELETE FROM system_settings WHERE setting_group IN ('password','login','session','display');

COMMIT;
