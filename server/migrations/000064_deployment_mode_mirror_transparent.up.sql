-- 000064 镜像/透明部署模式产品化（docs/NETWORK_MODES_DESIGN.md §4.2/§4.3，PoC 结论 §4.2.1/§4.3.1）：
-- applications.deployment_mode CHECK 约束扩展为四值，新增 MIRROR（镜像旁路检测）与
-- TRANSPARENT（透明串接）。MIRROR 应用发布时不生成内联站点路由（流量经镜像口到达，
-- 不在反代链上），改为发布通道写出 mirrorcap 边车配置；TRANSPARENT 应用保留内联路由
-- （tproxyd 牵引进程将流量经 PROXY 协议送至本机 Caddy），并写出 tproxyd 边车配置。
BEGIN;

ALTER TABLE applications DROP CONSTRAINT chk_applications_deployment_mode;

ALTER TABLE applications
    ADD CONSTRAINT chk_applications_deployment_mode
    CHECK (deployment_mode IN ('REVERSE_PROXY', 'ROUTED', 'MIRROR', 'TRANSPARENT'));

COMMENT ON COLUMN applications.deployment_mode IS
    '部署模式：REVERSE_PROXY 反向代理（默认）/ ROUTED 路由牵引 / MIRROR 镜像旁路 / TRANSPARENT 透明串接（docs/NETWORK_MODES_DESIGN.md §4）';

COMMIT;
