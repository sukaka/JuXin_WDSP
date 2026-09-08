-- 000103 攻击活动会话（WDSP AI 自动化渗透防护增强 阶段4，服务端；设计 #16）。
--   attack_session        攻击活动会话：同身份 30 分钟不活跃间隔滑动窗聚合多源安全事件
--                         （identity_behavior_events 主锚 / access_control_events identity_key /
--                         api_runtime_events、security_events 经 request_id 或 IP 反查归属），
--                         由 attacksessions 聚合器异步维护（60s 一轮，设计 #31.3 异步处理）。
--   attack_session_event  事件→会话关联表：UNIQUE(source_table, source_id) 为幂等核心
--                         （采集/聚合失败重放 ON CONFLICT DO NOTHING 不产生重复成员）；
--                         request_id 列支撑 WDSP 双落去重（Coraza SQLi 同落 security_events 与
--                         api_runtime_events waf 明细，按 request_id 只计一次）与会话请求数去重口径。
-- 主键沿用项目 UUID 惯例（设计文档 #16.1 的 BIGINT 为建议稿；identity_id 与
-- client_identity 对齐，身份删除时 SET NULL 保留会话证据）。
BEGIN;

-- ---------- 攻击活动会话 ----------
CREATE TABLE IF NOT EXISTS attack_session (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- 稳定键：sha256(identity_id | 首事件 30min 桶起点) hex，聚合器重放/崩溃重建时幂等
    session_key   VARCHAR(128) NOT NULL UNIQUE,
    identity_id   UUID         REFERENCES client_identity(id) ON DELETE SET NULL,
    identity_key  VARCHAR(128) NOT NULL DEFAULT '',
    start_time    TIMESTAMPTZ  NOT NULL,
    -- end_time 语义 = last_event_at（会话内最近事件时间；滑动窗判定与收口以此为准）
    end_time      TIMESTAMPTZ  NOT NULL,
    request_count BIGINT       NOT NULL DEFAULT 0,
    event_count   BIGINT       NOT NULL DEFAULT 0,
    risk_score    INT          NOT NULL DEFAULT 0,
    risk_level    VARCHAR(32)  NOT NULL DEFAULT 'LOW'
                  CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    attack_stage  VARCHAR(64)  NOT NULL DEFAULT 'UNKNOWN'
                  CHECK (attack_stage IN ('RECON','DISCOVERY','AUTH_PROBE','AUTHORIZATION_PROBE',
                                          'EXPLOIT','DATA_ACCESS','PERSISTENCE','UNKNOWN')),
    status        VARCHAR(32)  NOT NULL DEFAULT 'OPEN'
                  CHECK (status IN ('OPEN','CLOSED')),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);
-- 聚合器热路径：按身份取最新 OPEN 会话（滑动窗并入判定）
CREATE INDEX IF NOT EXISTS idx_attack_session_identity_status_end
    ON attack_session (identity_id, status, end_time DESC);
-- 列表按最近活动倒序 + 收口扫描（status OPEN 且 end_time 超龄）
CREATE INDEX IF NOT EXISTS idx_attack_session_end ON attack_session (end_time DESC);

-- ---------- 事件→会话关联 ----------
CREATE TABLE IF NOT EXISTS attack_session_event (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id   UUID         NOT NULL REFERENCES attack_session(id) ON DELETE CASCADE,
    -- 源表行标识：identity_behavior_events / access_control_events / security_events 行 UUID、
    -- api_runtime_events 行 UUID（task 约定：api_runtime_events 用行 UUID 作 source_id）
    source_table VARCHAR(64)  NOT NULL,
    source_id    VARCHAR(64)  NOT NULL,
    request_id   VARCHAR(128) NOT NULL DEFAULT '',
    occurred_at  TIMESTAMPTZ  NOT NULL,
    stage        VARCHAR(64)  NOT NULL DEFAULT 'UNKNOWN',
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (source_table, source_id)
);
-- 会话事件时间序（详情接口）+ request_id 去重探测（WDSP 双落/request_count 口径）
CREATE INDEX IF NOT EXISTS idx_attack_session_event_session
    ON attack_session_event (session_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_attack_session_event_req
    ON attack_session_event (session_id, request_id) WHERE request_id <> '';
-- 水位线派生（max(occurred_at) per source_table；与采集器同纪律：失败不前移、重放幂等）
CREATE INDEX IF NOT EXISTS idx_attack_session_event_watermark
    ON attack_session_event (source_table, occurred_at DESC);

COMMIT;
