-- LOW-G3 残留对齐：app_header_configs.xff_overwrite 列默认值翻转为 TRUE，
-- 与网关生成器「无头合规配置记录时默认开启 XFF 上一跳覆盖为真实 IP」一致
-- （gatewayconfig/headers.go applyProxyOptions）。存量显式 false 记录语义保留，
-- 仅影响省略该列的新写入。
BEGIN;

ALTER TABLE app_header_configs ALTER COLUMN xff_overwrite SET DEFAULT TRUE;

COMMIT;
