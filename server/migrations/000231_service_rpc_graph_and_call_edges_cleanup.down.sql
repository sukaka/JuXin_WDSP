-- 000231 回滚：移除 gRPC 观测部分索引（已清理的扇出伪边不恢复）。
BEGIN;

DROP INDEX IF EXISTS idx_agent_http_events_grpc_ts;

COMMIT;
