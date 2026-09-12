-- 000030 行为基线画像时段分布 + 运行时事件响应状态码（WDSP 三微模型第二批，访问微模型）。
--
-- 背景：api_behavior_profiles（000018）自建表起无写入方，行为基线管理面不可见。
-- 本迁移为管理面离线画像（docs/API_BEHAVIOR_ANALYSIS.md、docs/API_MICRO_MODELS.md
-- §四第 6 项）补齐两个数据缺口：
--   1) api_behavior_profiles.hour_dist：调用时段分布（访问微模型「访问时间」环境维度），
--      与 status_code_dist 同款 JSONB，键为 UTC 小时桶 "0"-"23"、值为计数，
--      空对象表示尚无样本。选择加列而非并入 status_code_dist：两者语义不同
--      （状态码 vs 时段），混入同一 JSONB 消费方需按键前缀分拣；加列与既有列同款，
--      默认 '{}' 不动存量行，侵入最小。
--   2) api_runtime_events.response_status：网关 api-runtime-events JSONL 本已上报
--      response_status（0 = 网关未采集到状态码），ETL 此前丢弃；落库后供离线画像
--      聚合 status_code_dist（任务书第四十三章成功失败比基线）。
BEGIN;

ALTER TABLE api_behavior_profiles
    ADD COLUMN IF NOT EXISTS hour_dist JSONB NOT NULL DEFAULT '{}';

ALTER TABLE api_runtime_events
    ADD COLUMN IF NOT EXISTS response_status INTEGER NOT NULL DEFAULT 0;

COMMIT;
