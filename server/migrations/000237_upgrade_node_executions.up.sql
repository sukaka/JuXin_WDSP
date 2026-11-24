-- 000237 HA 集群滚动升级执行跟踪：
--   a) upgrade_jobs 新增 cluster_mode（LOCAL 单机 / HA_ROLLING 主备滚动先备后主）
--   b) 新建 upgrade_node_executions 记录每个升级任务下逐节点的传输/执行/验证状态
BEGIN;

-- a) upgrade_jobs.cluster_mode
ALTER TABLE upgrade_jobs
    ADD COLUMN IF NOT EXISTS cluster_mode VARCHAR(16) NOT NULL DEFAULT 'LOCAL';

COMMENT ON COLUMN upgrade_jobs.cluster_mode IS
    '升级集群模式：LOCAL（仅本机）或 HA_ROLLING（主备双机先备后主滚动升级）';

-- b) upgrade_node_executions 逐节点执行明细表
CREATE TABLE IF NOT EXISTS upgrade_node_executions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id        UUID        NOT NULL REFERENCES upgrade_jobs(id) ON DELETE CASCADE,
    node_id       UUID        REFERENCES api_gateway_nodes(id) ON DELETE SET NULL,
    node_name     TEXT        NOT NULL,
    role          VARCHAR(16) NOT NULL,
    seq           INT         NOT NULL,
    status        VARCHAR(24) NOT NULL DEFAULT 'PENDING',
    from_version  TEXT        NOT NULL DEFAULT '',
    to_version    TEXT        NOT NULL DEFAULT '',
    error_code    TEXT        NOT NULL DEFAULT '',
    error_message TEXT        NOT NULL DEFAULT '',
    started_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_upgrade_node_executions_job_seq
    ON upgrade_node_executions (job_id, seq);

COMMENT ON TABLE upgrade_node_executions IS
    'HA 集群滚动升级逐节点执行明细（role: STANDBY/PRIMARY；status: PENDING/TRANSFERRING/APPLYING/VERIFYING/SUCCESS/FAILED/SKIPPED）';

COMMIT;
