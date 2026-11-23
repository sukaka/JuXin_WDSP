-- 000224 回滚：移除 api_sensitive_fields.masked_sample 列并撤销内置类型默认追加的 response_body 位置。
BEGIN;

ALTER TABLE api_sensitive_fields
    DROP COLUMN IF EXISTS masked_sample;

UPDATE api_sensitive_data_types
SET locations = COALESCE((
    SELECT jsonb_agg(elem)
    FROM jsonb_array_elements(locations) AS elem
    WHERE elem <> '"response_body"'::jsonb
), '[]'::jsonb),
    updated_at = now()
WHERE is_builtin = TRUE
  AND regex <> ''
  AND locations @> '["response_body"]'::jsonb;

COMMIT;
