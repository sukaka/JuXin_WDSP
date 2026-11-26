-- 回滚 000249：移除 wasm_plugins 权限种子及 Wasm 检测插件两张表
BEGIN;

DELETE FROM role_permissions
WHERE permission_id IN (SELECT id FROM permissions WHERE code IN ('wasm_plugins.read', 'wasm_plugins.manage'));

DELETE FROM permissions WHERE code IN ('wasm_plugins.read', 'wasm_plugins.manage');

DROP TABLE IF EXISTS wasm_plugin_versions;
DROP TABLE IF EXISTS wasm_plugins;

COMMIT;
