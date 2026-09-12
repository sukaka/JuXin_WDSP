-- WDSP 阶段B 路由牵引模式配置化（docs/NETWORK_MODES_DESIGN.md §4.1，PoC 结论 §4.1.1）：
-- applications 增加部署模式字段。REVERSE_PROXY（默认，现有行为）/ ROUTED（路由牵引）；
-- transparent/mirror 本期不开放（后续阶段）。
-- ROUTED 应用发布时不下发可信代理链（guard JSON trusted_proxies 输出空数组），
-- 网关按直连对端识别真实客户端 IP，不解析任何代理头。
BEGIN;

ALTER TABLE applications
    ADD COLUMN deployment_mode VARCHAR(16) NOT NULL DEFAULT 'REVERSE_PROXY';

ALTER TABLE applications
    ADD CONSTRAINT chk_applications_deployment_mode
    CHECK (deployment_mode IN ('REVERSE_PROXY', 'ROUTED'));

COMMENT ON COLUMN applications.deployment_mode IS
    '部署模式：REVERSE_PROXY 反向代理（默认）/ ROUTED 路由牵引（docs/NETWORK_MODES_DESIGN.md §4.1）';

COMMIT;
