-- 000144 阶段5 §6.5 真实客户端 IP 识别日志字段补齐。
--
-- 语义：docs/tasks/STAGE_5_ACCESS_CONTROL_CC.md §6.5 要求访问日志与访问控制事件
-- 携带 client_ip_source / trusted_proxy_used / forwarded_chain_summary 三字段，
-- 网关 jiuzhang_guard（events.Event / accessLogRecord）自本版本起上报同名 JSON 键
-- （omitempty）。本迁移为 access_logs 与 access_control_events 补列。
--
-- 空值口径：NULL = 旧版网关未上报 / 不适用（直连未走可信代理时 trusted_proxy_used、
-- forwarded_chain_summary 恒空）；client_ip_source 取值口径 CONNECTION /
-- X_FORWARDED_FOR / X_REAL_IP / FORWARDED / CUSTOM_HEADER。
-- 分区表：access_control_events ALTER 父表自动传播到全部分区。
BEGIN;

ALTER TABLE access_logs
    ADD COLUMN IF NOT EXISTS client_ip_source VARCHAR(32),
    ADD COLUMN IF NOT EXISTS trusted_proxy_used VARCHAR(128),
    ADD COLUMN IF NOT EXISTS forwarded_chain_summary VARCHAR(256);

COMMENT ON COLUMN access_logs.client_ip_source IS
    '真实客户端 IP 识别来源（CONNECTION/X_FORWARDED_FOR/X_REAL_IP/FORWARDED/CUSTOM_HEADER）；NULL = 旧版网关未上报';
COMMENT ON COLUMN access_logs.trusted_proxy_used IS
    '命中的可信代理名；NULL/空 = 未经过可信代理解析';
COMMENT ON COLUMN access_logs.forwarded_chain_summary IS
    '截断的代理链摘要（伪造/非法头场景为原始头值截断片段）；NULL = 无代理链';

ALTER TABLE access_control_events
    ADD COLUMN IF NOT EXISTS client_ip_source VARCHAR(32),
    ADD COLUMN IF NOT EXISTS trusted_proxy_used VARCHAR(128),
    ADD COLUMN IF NOT EXISTS forwarded_chain_summary VARCHAR(256);

COMMENT ON COLUMN access_control_events.client_ip_source IS
    '真实客户端 IP 识别来源（CONNECTION/X_FORWARDED_FOR/X_REAL_IP/FORWARDED/CUSTOM_HEADER）；NULL = 旧版网关未上报';
COMMENT ON COLUMN access_control_events.trusted_proxy_used IS
    '命中的可信代理名；NULL/空 = 未经过可信代理解析';
COMMENT ON COLUMN access_control_events.forwarded_chain_summary IS
    '截断的代理链摘要（伪造/非法头场景为原始头值截断片段）；NULL = 无代理链';

COMMIT;
