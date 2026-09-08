-- 学习自动化闭环（P0-1）：样本幂等约束
-- 注：任务排期时最新迁移为 000021，落笔时仓库已发展到 000026，故本迁移编号 000027。
BEGIN;

-- api_learning_samples 按 (api_endpoint_id, request_id) 幂等：
-- 采集器断点重读/重放同一 request_id 不重复落样、不重复计数。
-- 采用部分唯一索引而非全表 UNIQUE：request_id 缺省为 ''（网关旧版本事件可能缺失），
-- 空 request_id 不参与唯一约束（且采集端对空 request_id 直接不落样，见
-- apiruntime/collector.go recordSample），避免多行 '' 互相冲突。
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_learning_samples_endpoint_request
    ON api_learning_samples (api_endpoint_id, request_id)
    WHERE request_id <> '';

COMMIT;
