-- 000067 调用边身份计数（W11-GRAPH）：
-- 1) api_call_edges 增 identity_count 列：走过该边（caller+source+target 自然键）
--    的 distinct 身份数，近似下界口径（首见身份插入计 1，同身份重复经过不增；
--    边观测不携带身份哈希集合，成本低但可能少计，详见
--    server/internal/aggregations/call_edges.go 文件头）；
-- 2) 既有重复行合并去重：000018 建表无自然键唯一约束，派生侧原为
--    UPDATE-未命中-INSERT（靠 advisory lock 单写入方序列化），竞态/历史回填
--    可能留下同键多行；建唯一索引前必须先收敛，否则索引创建失败；
-- 3) 建 (caller_fingerprint, source_endpoint_id, target_endpoint_id) 唯一索引，
--    派生侧 upsert 切 ON CONFLICT，去掉 advisory lock 依赖。
--
-- 去重口径：同键即同身份（caller_fingerprint 是键的一部分），合并后
-- identity_count 保持 1（重复行是同一身份的重复写入，不是多个身份，不求和）；
-- call_count 求和、first/last_seen_at 取极值，观测历史不丢失。
-- source_endpoint_id 可空（端点删除 ON DELETE SET NULL）：唯一索引带
-- NULLS NOT DISTINCT（PG15+），NULL 源行同样受唯一约束、同样参与去重。
BEGIN;

ALTER TABLE api_call_edges ADD COLUMN IF NOT EXISTS identity_count INTEGER NOT NULL DEFAULT 1;

-- 既有重复行合并：先把组内汇总值（count 求和/首末极值）写到组内每一行，
-- 再按自然键保一行（id 最小者存活），冗余行删除。两步同语句顺序执行，
-- 存活行即携带合并结果；identity_count 不动（全组同身份，保持默认 1）。
WITH agg AS (
    SELECT caller_fingerprint, source_endpoint_id, target_endpoint_id,
           sum(call_count)   AS call_count,
           min(first_seen_at) AS first_seen_at,
           max(last_seen_at)  AS last_seen_at
    FROM api_call_edges
    GROUP BY 1, 2, 3
    HAVING count(*) > 1
)
UPDATE api_call_edges e
SET call_count   = a.call_count,
    first_seen_at = a.first_seen_at,
    last_seen_at  = a.last_seen_at
FROM agg a
WHERE e.caller_fingerprint = a.caller_fingerprint
  AND e.source_endpoint_id IS NOT DISTINCT FROM a.source_endpoint_id
  AND e.target_endpoint_id = a.target_endpoint_id;

DELETE FROM api_call_edges e
USING (
    SELECT id, row_number() OVER (
        PARTITION BY caller_fingerprint, source_endpoint_id, target_endpoint_id
        ORDER BY id
    ) AS rn
    FROM api_call_edges
) d
WHERE e.id = d.id AND d.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS uq_api_call_edges_caller_source_target
    ON api_call_edges (caller_fingerprint, source_endpoint_id, target_endpoint_id) NULLS NOT DISTINCT;

COMMENT ON COLUMN api_call_edges.identity_count IS
    '走过该边的 distinct 身份数（近似下界）：首见身份插入计 1，同身份重复经过不增；000067 W11-GRAPH';

COMMIT;
