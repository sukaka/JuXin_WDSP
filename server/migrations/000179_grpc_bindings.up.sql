-- 000179 gRPC 描述符 per-app 绑定（NG-GRPC-01/03，设计 docs/nextgen/NG-GRPC-g1-unary.md §1.3/D3）：
-- 应用 × gRPC 服务（pkg.Service）× 描述符集（引用 000076 集名）× 模式。
--
-- 语义边界（设计冻结）：
--   - 空绑定 = 全局可见（现状语义：000076 ENABLED 集全局注册表不变）；
--   - 应用存在任一绑定行时，该应用深检只用其绑定集——同名服务跨应用各自
--     使用各自描述符解码，不错配（设计前置事实登记的错配修复）；
--   - mode：该（应用,服务）深检处置 OBSERVE（缺省只记录）| PROTECT（字段结构
--     违规按设计 §1.6 协议化执行（grpc-status trailers）；含任一 PROTECT 绑定
--     的快照能力门 required detectors.grpc.unary=grpc/2（az/3、flow/1 同纪律）；
--   - 描述符集删除级联删绑定（FK 到 name 唯一索引）；应用删除级联；
--   - version 乐观锁（apiflows 同先例：写操作携带比对，不匹配 409）。
BEGIN;

CREATE TABLE IF NOT EXISTS api_grpc_bindings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id  UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    service         TEXT NOT NULL,
    descriptor_name TEXT NOT NULL REFERENCES api_grpc_descriptors(name) ON DELETE CASCADE,
    mode            TEXT NOT NULL DEFAULT 'OBSERVE',
    version         INTEGER NOT NULL DEFAULT 1,
    created_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_api_grpc_bindings_mode CHECK (mode IN ('OBSERVE','PROTECT')),
    -- 服务名形态（pkg.Service 点路径；与上传解析产出的 services 摘要同词表）：
    -- ^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$，长度 ≤256
    CONSTRAINT chk_api_grpc_bindings_service
        CHECK (service ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$' AND length(service) <= 256)
);
-- 同（应用,服务）恰一条绑定（深检描述符集唯一指派——同服务多集即歧义拒收）
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_grpc_bindings_app_service
    ON api_grpc_bindings (application_id, service);
-- 发布通道读取口径：全行（应用删除级联即空）按应用/服务稳定排序
CREATE INDEX IF NOT EXISTS idx_api_grpc_bindings_service
    ON api_grpc_bindings (service);

COMMENT ON TABLE api_grpc_bindings IS
    'gRPC 描述符 per-app 绑定（NG-GRPC G1）：应用×服务×描述符集×模式；空绑定=全局可见，绑定应用只用绑定集（同名服务跨应用隔离）';

COMMIT;
