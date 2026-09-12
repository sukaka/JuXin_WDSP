-- 回滚 000064：applications.deployment_mode CHECK 约束收回为两值（REVERSE_PROXY/ROUTED）。
-- 前置条件：库中不得存在 MIRROR/TRANSPARENT 应用，否则重建约束将失败（先改回或删除）。
BEGIN;

ALTER TABLE applications DROP CONSTRAINT chk_applications_deployment_mode;

ALTER TABLE applications
    ADD CONSTRAINT chk_applications_deployment_mode
    CHECK (deployment_mode IN ('REVERSE_PROXY', 'ROUTED'));

COMMENT ON COLUMN applications.deployment_mode IS
    '部署模式：REVERSE_PROXY 反向代理（默认）/ ROUTED 路由牵引（docs/NETWORK_MODES_DESIGN.md §4.1）';

COMMIT;
