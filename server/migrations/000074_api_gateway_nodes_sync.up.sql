-- 000074 API 网关节点配置面主动同步 v2（W18-SYNC，任务书 §200）。
--
-- 语义：000069 建的是「经事件遥测的节点版本校验」视图；本迁移叠加「配置面主动同步」
-- 登记与结果列——发布通道主节点（现有 Publisher → 单一 Caddy Admin Unix Socket /load）
-- 成功后，同一份最终构建配置扇出到全部登记次要节点（sync_enabled 且 admin_addr 非空），
-- 逐节点回填 last_sync_*。节点行仍由遥测聚合/心跳 upsert 维护（admin_addr 等列不在
-- upsert 列清单中，聚合写入不触碰登记信息）。
--
-- 空值口径（与 000069 一致，不伪造空串占位语义之外的默认值）：
--   admin_addr       '' = 未登记（不参与扇出）；非空时经管理面地址校验
--   sync_enabled     FALSE = 不扇出（默认关闭，登记后须显式开启）
--   last_sync_at     NULL = 从未同步
--   last_sync_result ''  = 从未同步；否则 SUCCESS / FAILED / HASH_MISMATCH
--   last_sync_error  ''  = 无错误
--   last_sync_version_id NULL = 从未同步；否则为最近一次同步尝试的配置版本
--                    （不加外键：版本行清理不阻塞节点视图，语义为「尝试过的版本」引用）
BEGIN;

ALTER TABLE api_gateway_nodes
    ADD COLUMN IF NOT EXISTS admin_addr TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS sync_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS last_sync_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_sync_result TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_sync_error TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_sync_version_id UUID;

COMMENT ON COLUMN api_gateway_nodes.admin_addr IS
    '节点 Caddy Admin 通道标识（部署侧登记）：unix socket 绝对路径 / unix:///path / http(s)://host[:port]，仅内网管理面地址；空串 = 未登记';
COMMENT ON COLUMN api_gateway_nodes.sync_enabled IS
    '是否参与发布扇出（默认关闭，登记 admin_addr 后须显式开启）';
COMMENT ON COLUMN api_gateway_nodes.last_sync_at IS
    '最近一次同步尝试时间（NULL = 从未同步）';
COMMENT ON COLUMN api_gateway_nodes.last_sync_result IS
    '最近一次同步结果：SUCCESS / FAILED / HASH_MISMATCH；空串 = 从未同步';
COMMENT ON COLUMN api_gateway_nodes.last_sync_error IS
    '最近一次同步失败原因（已截断脱敏）；空串 = 无错误';
COMMENT ON COLUMN api_gateway_nodes.last_sync_version_id IS
    '最近一次同步尝试的配置版本（gateway_config_versions.id，无外键约束）；NULL = 从未同步';

COMMIT;
