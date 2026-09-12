-- 000111 WDSP 流量采集 Agent 机器身份证书（Phase 2-B，契约 docs/agents/WDSP_AGENT_PHASE2_CONTRACT.md §10）。
--
--   1) agents 新增 agent_cert_fingerprint（当前生效证书 SHA-256 hex 指纹，NULL=未持证书，
--      仅 Bearer 模式）与 agent_cert_not_after（当前证书到期时间）；
--   2) agent_cert_revocations：证书指纹撤销/宽限记录——
--      轮换时旧指纹写入并携带 grace_until（now+24h，宽限期内新旧均可认证，过期即视为撤销）；
--      禁用/删除时当前指纹写入且 grace_until=NULL（立即撤销）；
--      not_before 为指纹生效起点（客户端证书 NotBefore；disable/delete 路径无法确知时落 NULL）；
--      随 Agent 删除级联清理（删除后 Agent 行不存在，证书亦无法再认证，语义等价）。
--   认证通过 ⇔ 指纹 == agents.agent_cert_fingerprint（当前），
--            或存在于 revocations 且 grace_until > now()（宽限中）。
BEGIN;

ALTER TABLE agents ADD COLUMN IF NOT EXISTS agent_cert_fingerprint TEXT;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS agent_cert_not_after TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS agent_cert_revocations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    UUID        NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    fingerprint TEXT        NOT NULL,           -- 证书 SHA-256 hex 指纹
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    not_before  TIMESTAMPTZ,                    -- 指纹生效起点（证书 NotBefore；不可确知时 NULL）
    grace_until TIMESTAMPTZ,                    -- 轮换宽限截止；NULL=立即撤销，过期即视为撤销
    reason      TEXT        NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_agent_cert_revocations_fingerprint
    ON agent_cert_revocations (fingerprint);

COMMIT;
