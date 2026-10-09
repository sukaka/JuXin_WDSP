-- 000184 机器身份绑定与撤销水位（NG-ID g1 批次 B1，设计
-- docs/nextgen/NG-ID-g1-machine-identity.md §1.2/§1.6/D2/D6）：
-- machine_identity_bindings（应用×path selector×模式×proof_required）+
-- machine_identity_revocation_watermark（单行水位，种子 seq=0）。
--
-- 语义边界（设计冻结）：
--   - 绑定：application_id FK CASCADE；path_exact|path_prefix 二选一（jwt selector
--     同形校验——/ 开头、≤512、不含 query/fragment；完整校验在管理面，DB 兜形态）；
--     mode OBSERVE（缺省）|PROTECT；proof_required 缺省 false（绑定命中且 true 时
--     未签名请求=拒绝 401；false=未签名按普通流量继续既有防护）；version 乐观锁；
--     同（应用,path）恰一条绑定（唯一索引）；
--   - 绑定不引用身份：登记册全局生效（请求签名 keyid 做登记册精确查找），绑定仅定义
--     应用端点覆盖范围与处置模式（§1.2 模型与 §1.12 发布段形状一致无身份键）；
--   - 水位：单行哨兵 id=1；seq BIGINT 只增 upsert（apiauthz relations.go:389-390
--     同形）；撤销事实与 seq+1 同一事务原子提交（relations.go:356 同纪律）；
--     水位单调不下降——发布快照水位低于网关已应用水位 → 拒载（fail-closed，
--     普通策略回滚不复活已撤销密钥，§1.6）。
BEGIN;

CREATE TABLE IF NOT EXISTS machine_identity_bindings (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    path_exact     TEXT,
    path_prefix    TEXT,
    mode           VARCHAR(16) NOT NULL DEFAULT 'OBSERVE',
    proof_required BOOLEAN NOT NULL DEFAULT false,
    version        INTEGER NOT NULL DEFAULT 1,
    created_by     TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_machine_identity_bindings_mode CHECK (mode IN ('OBSERVE','PROTECT')),
    CONSTRAINT chk_machine_identity_bindings_selector
        CHECK ((path_exact IS NOT NULL)::int + (path_prefix IS NOT NULL)::int = 1),
    CONSTRAINT chk_machine_identity_bindings_path_exact CHECK (path_exact IS NULL OR
        (path_exact LIKE '/%' AND length(path_exact) <= 512
         AND position('?' IN path_exact) = 0 AND position('#' IN path_exact) = 0)),
    CONSTRAINT chk_machine_identity_bindings_path_prefix CHECK (path_prefix IS NULL OR
        (path_prefix LIKE '/%' AND length(path_prefix) <= 512
         AND position('?' IN path_prefix) = 0 AND position('#' IN path_prefix) = 0))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_machine_identity_bindings_app_path
    ON machine_identity_bindings (application_id, COALESCE(path_exact, path_prefix));

CREATE TABLE IF NOT EXISTS machine_identity_revocation_watermark (
    id  SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    seq BIGINT NOT NULL DEFAULT 0 CHECK (seq >= 0)
);
INSERT INTO machine_identity_revocation_watermark (id, seq) VALUES (1, 0)
ON CONFLICT (id) DO NOTHING;

COMMENT ON TABLE machine_identity_bindings IS '机器身份 per-app 绑定（selector×mode×proof_required；绑定驱动识别；NG-ID g1）';
COMMENT ON TABLE machine_identity_revocation_watermark IS '机器身份撤销单调水位（NG-ID g1 D6；撤销事务内只增，回滚不回退）';

COMMIT;
