-- 000075 访问控制/CC 事件补协议版本列（W20-HTTP3 口径对齐）。
--
-- 语义：api_runtime_events 链路已有 proto 可见性（HTTP/1.1 / HTTP/2.0 / HTTP/3），
-- WAF 访问控制/CC 事件链（guard jiuzhang_guard/events → 采集入库 access_control_events）
-- 此前无协议版本字段。本迁移补 proto 列，与网关事件 JSON `proto` 键（omitempty）对应。
--
-- 空值口径：NULL = 不可得/旧版网关未上报（采集端缺失容忍落 NULL）；
-- 非空为 r.Proto 原样（HTTP/1.1 / HTTP/2.0 / HTTP/3）。
-- 分区表：ALTER 父表自动传播到全部分区。
BEGIN;

ALTER TABLE access_control_events
    ADD COLUMN IF NOT EXISTS proto TEXT;

COMMENT ON COLUMN access_control_events.proto IS
    'HTTP 协议版本（HTTP/1.1 / HTTP/2.0 / HTTP/3，r.Proto 原样）；NULL = 不可得/旧版网关未上报';

COMMIT;
