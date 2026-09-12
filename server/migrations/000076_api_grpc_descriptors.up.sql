-- 000076 API gRPC 描述符集（W14-DESC / P2-05 深化）：描述符驱动的字段级解析 v1 管理面落地表。
--
-- 语义边界（任务书 P2-05 gRPC 描述符级解析 v1 子集）：
--   管理面登记 protobuf FileDescriptorSet（protoc --descriptor_set_out 产物），
--   发布通道将 ENABLED 行下发网关（guardconfig GRPCDescriptorStore 读取，
--   键 api_grpc_descriptors: [{name, content_base64}]），网关装配期编译为
--   动态消息注册表，按 :path /package.Service/Method 解码请求消息做字段级观测。
--
-- 列说明：
--   name         描述符集名称（管理面展示与网关观测证据 descriptor 字段，唯一）；
--   content      FileDescriptorSet 原始字节（BYTEA；上限 1 MiB，与上传护栏一致）；
--   content_hash content 的 sha256 hex（64 字符；完整性锚点，发布版本戳纳入）；
--   services     服务/方法清单摘要（jsonb：[{service, methods:[{name, input_type,
--                output_type, client_streaming, server_streaming}]}]，上传时由
--                apigrpcdesc 线格式解析产出，供管理面展示，不参与运行时判定）；
--   status       ENABLED / DISABLED（仅 ENABLED 行随发布下发；v1 无启停接口，
--                上传即 ENABLED，删除即下线，列预留状态机扩展）；
--   created_by   上传人用户名（TEXT，与 000040/000043 同口径，非外键）。
BEGIN;

CREATE TABLE IF NOT EXISTS api_grpc_descriptors (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         VARCHAR(128) NOT NULL,
    content      BYTEA NOT NULL,
    content_hash VARCHAR(64) NOT NULL,
    services     JSONB NOT NULL DEFAULT '[]',
    status       VARCHAR(16) NOT NULL DEFAULT 'ENABLED',
    created_by   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_api_grpc_descriptors_status CHECK (status IN ('ENABLED','DISABLED')),
    CONSTRAINT chk_api_grpc_descriptors_content_size
        CHECK (octet_length(content) > 0 AND octet_length(content) <= 1048576),
    CONSTRAINT chk_api_grpc_descriptors_content_hash
        CHECK (content_hash ~ '^[0-9a-f]{64}$')
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_grpc_descriptors_name
    ON api_grpc_descriptors (name);
-- 发布通道读取口径：status='ENABLED' 按 name 稳定排序（部分索引避免全表扫）
CREATE INDEX IF NOT EXISTS idx_api_grpc_descriptors_enabled
    ON api_grpc_descriptors (name) WHERE status = 'ENABLED';

COMMENT ON TABLE api_grpc_descriptors IS
    'gRPC 描述符集（FileDescriptorSet）：描述符驱动字段级解析 v1 的管理面登记；ENABLED 行随发布下发网关';

COMMIT;
