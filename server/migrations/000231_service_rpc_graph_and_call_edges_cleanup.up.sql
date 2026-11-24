-- 000231: 微服务 RPC 调用图谱索引 + 清理调用边历史 JOIN 扇出伪边
-- 1) agent_http_events 部分索引：加速微服务 gRPC 观测查询（仅覆盖 grpc IS NOT NULL 行）。
-- 2) 清理历史版本 call_edges.go 按 endpoint_key 直接 LEFT JOIN api_endpoints 导致的同应用
--    同名端点伪调用边（源与目标不同 id、同 endpoint_key，且同应用或任一侧无应用归属）。
BEGIN;

CREATE INDEX IF NOT EXISTS idx_agent_http_events_grpc_ts
    ON agent_http_events (ts DESC)
    WHERE grpc IS NOT NULL;

DELETE FROM api_call_edges c
USING api_endpoints s, api_endpoints t
WHERE c.source_endpoint_id = s.id
  AND c.target_endpoint_id = t.id
  AND s.id <> t.id
  AND s.endpoint_key = t.endpoint_key
  AND (
      s.application_id IS NOT DISTINCT FROM t.application_id
      OR s.application_id IS NULL
      OR t.application_id IS NULL
  );

COMMIT;
