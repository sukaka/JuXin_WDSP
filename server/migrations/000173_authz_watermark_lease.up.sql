-- 000173 撤销水位 / 租约 / 节点 ACK（NG-AZ-02 §4.A 决策链，docs/nextgen/NG-AZ-02-watermark-lease-ack.md）。
--
--   api_authz_manual_revocation_seq：手工撤销通道单调序号（D1；单行 id=1，
--     每次关系废止（RevokeObjectRelation/ExpireObjectRelations/重新授权旧行废止）
--     在同一事务内 seq+1——撤销事实与水位推进原子提交；普通策略回滚只读不写，
--     水位单调不下降）。插入路径只许 seq+1（应用层 GREATEST 语义由调用方事务保证）。
--   api_node_authzacks（D6）：节点授权 ACK（心跳通道回报；node_name PK）。
--     **列名/类型为跨代理冻结契约**（采集/展示实现按此消费，不得改名）。
--   api_object_models.on_lease_expired：per-endpoint 租约过期策略（D5；
--     strict（缺省，安全保守项）| degraded）。
--   applications.authz_lease_seconds：per-app 租约秒数（D5；NULL=不启用租约约束，
--     与 v1 行为一致；配置夹紧 15~300 在读取侧执行）。
BEGIN;

-- ---------- 手工撤销水位（D1） ----------
CREATE TABLE IF NOT EXISTS api_authz_manual_revocation_seq (
    id  SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    seq BIGINT NOT NULL DEFAULT 0 CHECK (seq >= 0)
);
INSERT INTO api_authz_manual_revocation_seq (id, seq) VALUES (1, 0)
ON CONFLICT (id) DO NOTHING;
COMMENT ON TABLE api_authz_manual_revocation_seq IS '手工撤销通道单调水位（NG-AZ-02 D1；撤销事务内只增，回滚不回退）';

-- ---------- 节点授权 ACK（D6；跨代理冻结列契约） ----------
CREATE TABLE IF NOT EXISTS api_node_authz_acks (
    node_name                  TEXT PRIMARY KEY,
    last_ack_at                TIMESTAMPTZ NOT NULL,
    authz_policy_version       TEXT NOT NULL DEFAULT '',
    authz_watermark            JSONB,
    authz_snapshot_expires_at  TIMESTAMPTZ,
    authz_applied_at           TIMESTAMPTZ,
    authz_lease_seconds        INTEGER,
    clock_skew_seconds         BIGINT,
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE api_node_authz_acks IS '节点授权快照 ACK（NG-AZ-02 D6；心跳通道 upsert；列名为跨代理冻结契约）';

-- ---------- 租约配置（D5） ----------
ALTER TABLE api_object_models
    ADD COLUMN IF NOT EXISTS on_lease_expired TEXT NOT NULL DEFAULT 'strict';
ALTER TABLE api_object_models DROP CONSTRAINT IF EXISTS api_object_models_on_lease_expired_check;
ALTER TABLE api_object_models
    ADD CONSTRAINT api_object_models_on_lease_expired_check
    CHECK (on_lease_expired IN ('strict','degraded'));
COMMENT ON COLUMN api_object_models.on_lease_expired IS '租约过期策略（NG-AZ-02 D5）：strict（缺省，UNKNOWN 不放行）| degraded（评估继续全量 OBSERVE 标记）';

ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS authz_lease_seconds INT;
COMMENT ON COLUMN applications.authz_lease_seconds IS 'per-app 授权快照租约秒数（NG-AZ-02 D5；NULL=不启用；读取侧夹紧 15~300）';

COMMIT;
