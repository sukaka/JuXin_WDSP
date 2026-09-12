-- 000053 API 主动扫描核心表（W6-D / P1-07）：目标 / 授权 / 任务。
--
-- 语义边界（docs/API_ACTIVE_SCANNING.md）：主动扫描是对已纳管 API 资产的
-- 经授权有限主动验证（非 DAST，不做全量攻击载荷/fuzz/自动渗透）。靶标仅来自
-- 已纳管应用（applications），授权先于一切执行：任务必须凭一张未撤销且未过期的
-- 授权单运行，授权撤销（revoked_at）对该授权下所有在跑任务即刻生效。
BEGIN;

-- 扫描目标：绑定已纳管应用 + base_url + 允许路径白名单（不对未登记目标发包）
CREATE TABLE IF NOT EXISTS api_scan_targets (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    name           VARCHAR(128) NOT NULL,
    base_url       TEXT         NOT NULL,                   -- 探测请求根地址（http/https，主机须落在授权 allowlist 内）
    allowed_paths  JSONB        NOT NULL DEFAULT '[]',      -- 允许探测的路径清单（逐一作为具体路径探测；空 = 不探测任何路径）
    status         VARCHAR(32)  NOT NULL DEFAULT 'ENABLED', -- ENABLED / DISABLED
    created_by     UUID,                                    -- 建标人（与授权人分离，三权口径）
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT chk_api_scan_targets_status CHECK (status IN ('ENABLED','DISABLED'))
);
CREATE INDEX IF NOT EXISTS idx_api_scan_targets_app ON api_scan_targets (application_id, status);

-- 扫描授权单：双人分离（建目标 api_scan.manage / 授权 api_scan.execute 两个权限点）。
-- 生效状态由 expires_at / revoked_at 派生：未撤销且未过期且在 time_window 内即有效，
-- 执行侧每批发包前重查（撤销即刻停发，不依赖任务自行结束）。
CREATE TABLE IF NOT EXISTS api_scan_authorizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id       UUID NOT NULL REFERENCES api_scan_targets(id) ON DELETE CASCADE,
    authorized_by   UUID NOT NULL REFERENCES users(id),
    allowlist       JSONB        NOT NULL DEFAULT '[]',  -- 允许出包的域名/IP 白名单（空 = 仅 base_url 主机自身）
    time_window     JSONB        NOT NULL DEFAULT '{}',  -- {"start":"RFC3339","end":"RFC3339"} 允许扫描时间窗（缺省端不限制）
    max_qps         INTEGER      NOT NULL DEFAULT 5,     -- 速率上限（执行侧限速硬约束）
    max_concurrency INTEGER      NOT NULL DEFAULT 1,     -- 单任务并发上限
    test_profile    TEXT         NOT NULL DEFAULT '',    -- 授权探针集画像（逗号分隔探针集词表；空 = 全部内置探针集）
    expires_at      TIMESTAMPTZ  NOT NULL,               -- 过期授权自动失效（执行前强校验）
    revoked_at      TIMESTAMPTZ,                         -- 撤销时间（撤销立即生效）
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT chk_api_scan_authz_limits CHECK (max_qps > 0 AND max_concurrency > 0)
);
CREATE INDEX IF NOT EXISTS idx_api_scan_authz_target ON api_scan_authorizations (target_id, created_at DESC);

-- 扫描任务：凭授权单发起；probe_set 为逗号分隔探针集（引擎只执行词表内探针，
-- 且必须是授权 test_profile 白名单子集）。progress 记录执行轨迹（不静默吞错：
-- 失败原因落 progress.last_error）。
CREATE TABLE IF NOT EXISTS api_scan_jobs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id        UUID NOT NULL REFERENCES api_scan_targets(id) ON DELETE CASCADE,
    authorization_id UUID NOT NULL REFERENCES api_scan_authorizations(id) ON DELETE RESTRICT,
    probe_set        TEXT         NOT NULL DEFAULT '',   -- 逗号分隔探针集（空 = 授权画像全集）
    status           VARCHAR(32)  NOT NULL DEFAULT 'PENDING',
    progress         JSONB        NOT NULL DEFAULT '{}', -- {"total":n,"done":n,"requests":n,"findings":n,"errors":n,"last_error":"..."}
    started_at       TIMESTAMPTZ,
    finished_at      TIMESTAMPTZ,
    created_by       UUID,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT chk_api_scan_jobs_status CHECK (status IN ('PENDING','RUNNING','PAUSED','STOPPED','COMPLETED','FAILED'))
);
-- 调度取任务：PENDING 按创建序；同目标互斥在 claim 查询内判定
CREATE INDEX IF NOT EXISTS idx_api_scan_jobs_status ON api_scan_jobs (status, created_at);
CREATE INDEX IF NOT EXISTS idx_api_scan_jobs_target ON api_scan_jobs (target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_scan_jobs_authz ON api_scan_jobs (authorization_id) WHERE status IN ('PENDING','RUNNING','PAUSED');

COMMIT;
