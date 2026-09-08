-- 000043 API 授权基线实体（WDSP 阶段8 P0-15 BOLA / P0-16 BFLA 补全，W3-A 分片）。
--
-- 背景：docs/API_SECURITY_CURRENT_STATE.md P0-15/16 节盘点确认 BOLA/BFLA 仅有
-- 网关侧辅助信号（detectors/resource.go 对象标识识别），无任何实体基线表：
-- 无 Identity→Object 权属关系、无 角色×端点×动作 允许基线。本迁移补齐两块实体：
--   1. api_object_ownership：对象权属基线（BOLA 判定的实体依据）。
--      生产方为 apiauthz.SweepOnce：扫描 api_runtime_events（identity_fingerprint
--      非空），用端点 normalized_path 模板匹配 raw_path 提取路径占位符段值
--      （{id}/{uuid}/...）后 upsert（access_count++/last_seen 前移）。
--      权属记录只表达「某身份在本端点访问过某对象」，是评估证据而非定罪结论
--      （纪律：不仅凭 ID 变化定罪，见 apiauthz evaluate 五档结论注释）。
--   2. api_role_baselines：角色功能级基线（BFLA）。source 区分来源：
--      MANUAL 人工登记 / SPEC 规格导入 / OBSERVED 观测学习 / IMPORTED 批量导入；
--      confirmed=FALSE 为候选，人工确认后置 TRUE（handler confirm 动作 + 操作审计）。
BEGIN;

-- ==================== 1. 角色功能级基线（BFLA） ====================
CREATE TABLE IF NOT EXISTS api_role_baselines (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID        NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    role        TEXT        NOT NULL,             -- 角色码（与管理面角色码对齐，自由文本登记）
    method      VARCHAR(16) NOT NULL,             -- HTTP 方法（大写）
    action      TEXT        NOT NULL,             -- 业务动作（READ/WRITE/DELETE/EXPORT…自由词，大写归一）
    allowed     BOOLEAN     NOT NULL DEFAULT FALSE,
    source      TEXT        NOT NULL DEFAULT 'MANUAL'
                CHECK (source IN ('MANUAL','SPEC','OBSERVED','IMPORTED')),
    confidence  NUMERIC(4,3) NOT NULL DEFAULT 0
                CHECK (confidence >= 0 AND confidence <= 1), -- 0..1 置信度
    confirmed   BOOLEAN     NOT NULL DEFAULT FALSE,          -- 人工确认标记（候选 → 基线）
    created_by  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- 同端点同角色同方法同动作唯一（upsert/冲突判定锚点）
    CONSTRAINT uq_api_role_baselines UNIQUE (endpoint_id, role, method, action)
);
CREATE INDEX IF NOT EXISTS idx_api_role_baselines_endpoint ON api_role_baselines (endpoint_id, role);
CREATE INDEX IF NOT EXISTS idx_api_role_baselines_confirmed ON api_role_baselines (confirmed);

-- ==================== 2. 对象权属基线（BOLA） ====================
CREATE TABLE IF NOT EXISTS api_object_ownership (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id          UUID         NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
    identity_fingerprint VARCHAR(128) NOT NULL,             -- 凭据派生 HMAC 指纹（不落明文，口径同 000029）
    object_type          TEXT         NOT NULL,             -- 对象类型（模板占位符的前置静态段/资源名，无则占位符名）
    object_id            TEXT         NOT NULL,             -- 对象标识（路径占位符段值，原样留存）
    first_seen           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    access_count         BIGINT       NOT NULL DEFAULT 1,   -- 权属访问累计（SweepOnce upsert +1）
    -- 同端点同身份同对象唯一（SweepOnce upsert 锚点）
    CONSTRAINT uq_api_object_ownership UNIQUE (endpoint_id, identity_fingerprint, object_type, object_id)
);
-- 评估与权属查询：按身份反查 / 按对象查属主 / 水位扫描
CREATE INDEX IF NOT EXISTS idx_api_object_ownership_identity ON api_object_ownership (identity_fingerprint, endpoint_id);
CREATE INDEX IF NOT EXISTS idx_api_object_ownership_object ON api_object_ownership (endpoint_id, object_type, object_id);
CREATE INDEX IF NOT EXISTS idx_api_object_ownership_last_seen ON api_object_ownership (last_seen DESC);

COMMIT;
