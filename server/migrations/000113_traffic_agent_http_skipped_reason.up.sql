-- 000113 WDSP 流量采集 Agent Phase 3 数据质量补齐：agent_http_events 增加
-- req_skipped_reason / resp_skipped_reason 两列（契约 §3 上报结构本含
-- body_skipped_reason，000112 冻结表结构遗漏；设计 §34/§35/§65 要求如实告诉用户
-- WDSP 到底看到了多少数据——内容类型白名单外不采（content_type）、压缩解码失败/
-- br 不解（encoding）是采集完整性的关键信号，必须持久化而非丢弃）。
--
-- 取值集合与 Agent 侧严格一致（wdsp-agent/internal/httpsensor/body.go：
-- skipContentType="content_type" / skipEncoding="encoding"，空串=正常采集）；
-- 机器端点按该枚举 fail-closed 校验（server/internal/agents/http_events.go）。
-- TEXT NOT NULL DEFAULT ''：PostgreSQL 11+ 快速默认值，加列不重写表；
-- 存量行回填 ''（语义=未跳过，与 000112 期间该信号未采集的口径一致——存量行
-- 的截断标记仍在，skipped 信号自本迁移起完整）。
BEGIN;

ALTER TABLE agent_http_events
    ADD COLUMN IF NOT EXISTS req_skipped_reason  TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS resp_skipped_reason TEXT NOT NULL DEFAULT '';

COMMIT;
