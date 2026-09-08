-- 000076 回滚：移除 api_grpc_descriptors 表（发布通道读取失败 Warn 跳过，
-- 回滚后发布与网关行为回到无描述符的 v1 帧结构校验口径，互不影响既有链路）。
BEGIN;

DROP TABLE IF EXISTS api_grpc_descriptors;

COMMIT;
