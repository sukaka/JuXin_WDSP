-- 000045 API 资产生命周期增强（WDSP P0-10/P0-11：Zombie 判定、资产价值评分、服务资产聚合）。
--
-- 背景：asset_status 词表自 000016 建表起仅有 SQL 注释约定
-- （DISCOVERED / CONFIRMED / IGNORED / DEPRECATED），全库无 CHECK 约束，
-- 本迁移按既定口径只更新注释词表、把 ZOMBIE 纳入词表，不新增 CHECK
-- （状态机合法性由 apiassets 包代码保证，与历史迁移一致）。
--
-- 本迁移内容（api_endpoints 新增三列，全部可空，不动存量行）：
--   asset_value          资产价值等级：LOW / MEDIUM / HIGH / CRITICAL（可空 = 未评分）；
--   asset_value_explain  评分可解释明细（jsonb：总分/各维得分与理由/计算时间，
--                        结构见 apiassets/value.go AssetValueScore）；
--   zombie_since         进入 ZOMBIE 态的时间（DEPRECATED 近 N 天仍有流量判定，
--                        见 apiassets/lifecycle.go SweepOnce）；人工 restore 时清空。
BEGIN;

ALTER TABLE api_endpoints
    ADD COLUMN IF NOT EXISTS asset_value         TEXT,
    ADD COLUMN IF NOT EXISTS asset_value_explain JSONB,
    ADD COLUMN IF NOT EXISTS zombie_since        TIMESTAMPTZ;

-- 注释词表纳入 ZOMBIE（原列无 COMMENT，本迁移建立；回滚时重置为 NULL）
COMMENT ON COLUMN api_endpoints.asset_status IS
    'DISCOVERED / CONFIRMED / IGNORED / DEPRECATED / ZOMBIE';
COMMENT ON COLUMN api_endpoints.asset_value IS
    '资产价值等级：LOW / MEDIUM / HIGH / CRITICAL（NULL = 未评分）';
COMMENT ON COLUMN api_endpoints.asset_value_explain IS
    '资产价值评分可解释明细（各维得分/理由/总分/计算时间）';
COMMENT ON COLUMN api_endpoints.zombie_since IS
    '进入 ZOMBIE 态时间（下线后仍有流量判定）；restore 时清空';

COMMIT;
