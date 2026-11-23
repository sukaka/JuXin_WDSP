-- 000224 敏感字段脱敏样本列 + 内置值级规则启用 response_body 检测 + 清理 sec-ch-ua-mobile 历史误报行。
--
-- 背景：
--   1. api_sensitive_fields 新增 masked_sample 列，保留每个敏感字段最新 1 条网关内存脱敏后的值级样本
--      （如手机号 138****8000；凭据类固定 ******；原始明文永不落事件与库表）。
--   2. 内置带值级 regex 的敏感数据类型（手机号码/电子邮箱/身份证号/银行卡号/JWT 令牌）默认追加
--      response_body 检测位置，捕获接口响应体中返回的真实敏感数据。
--   3. 清理历史因浏览器标准头 Sec-CH-UA-Mobile 命中字段名词根 mobile 产生的运行时误报行。
BEGIN;

ALTER TABLE api_sensitive_fields
    ADD COLUMN IF NOT EXISTS masked_sample VARCHAR(128) NOT NULL DEFAULT '';

UPDATE api_sensitive_data_types
SET locations = locations || '["response_body"]'::jsonb,
    updated_at = now()
WHERE is_builtin = TRUE
  AND regex <> ''
  AND NOT (locations @> '["response_body"]'::jsonb);

DELETE FROM api_sensitive_fields
WHERE structured_path = 'header.sec-ch-ua-mobile'
  AND detection_source = 'RUNTIME'
  AND COALESCE(source_detail->>'rule_id', '') = 'sensitive.field';

COMMIT;
