-- 000179 回滚：移除 gRPC 描述符 per-app 绑定表（000076 描述符集与全局注册表语义不受影响）。
BEGIN;

DROP TABLE IF EXISTS api_grpc_bindings;

COMMIT;
