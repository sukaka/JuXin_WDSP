-- 000180 回滚：恢复 000179 全小写段 CHECK（含大写服务名的存量行将阻塞回滚——
-- 如实呈现需先清理，不做静默数据改写）。
BEGIN;

ALTER TABLE api_grpc_bindings DROP CONSTRAINT chk_api_grpc_bindings_service;
ALTER TABLE api_grpc_bindings ADD CONSTRAINT chk_api_grpc_bindings_service
  CHECK (service ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$' AND length(service) <= 256);

COMMIT;
