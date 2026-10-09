-- 000180 gRPC 绑定服务名词表放宽（NG-GRPC G1 批次 C 裁决：B1 偏差闭环——
-- server 侧对齐 protobuf 标识符实际规则：包段小写 snake（[a-z][a-z0-9_]*）、
-- 服务名允许大写驼峰（[A-Za-z][A-Za-z0-9_]*，真实主流形态 echo.EchoService）；
-- 收紧项保留：禁空白/禁斜杠以外分隔/禁空段/长度上限 256。
-- 000179 的全小写 CHECK 会误拒真实 proto 服务名（联调阻塞项，裁决放宽）。
BEGIN;

ALTER TABLE api_grpc_bindings DROP CONSTRAINT chk_api_grpc_bindings_service;
ALTER TABLE api_grpc_bindings ADD CONSTRAINT chk_api_grpc_bindings_service
  CHECK (service ~ '^([a-z][a-z0-9_]*\.)*[A-Za-z][A-Za-z0-9_]*$' AND length(service) <= 256);

COMMIT;
