-- 000228 清理历史 URL 路径字面段 / 标准协议头敏感字段名误报与无效扫描探测的跨境脏记录。
--
-- 背景：
--   1. 旧版网关对 URL 路径字面段（如扫描器探测的 /mobile.zip、/mailer.zip、/remind_password.zip、
--      /phones.zip）按字段名词根匹配产出了 location=path 的 sensitive.field 误报，并进入
--      api_sensitive_fields 与 api_cross_border_events（表现为境外扫描 IP 的“入境涉敏”）。
--   2. 同步清理 api_cross_border_events 中关联源事件仅含路径/标准协议头字段名噪声、响应体未检诊断
--      （sensitive.response_body_unchecked）、被网关直接阻断（BLOCK/TEMP_BLOCK/RATE_LIMIT）、
--      上游返回 404/405/410 路由不存在，或 NON_API 且无值级实值命中的历史误报行。
--   3. 仅在能通过 source_event_id 关联到源事件并确认无有效涉敏命中时删除；真实路径值级命中
--      （sensitive.value 等）与有效业务接口载荷命中一律保留。
BEGIN;

DELETE FROM api_sensitive_fields
WHERE detection_source = 'RUNTIME'
  AND COALESCE(source_detail->>'rule_id', '') = 'sensitive.field'
  AND COALESCE(masked_sample, '') = ''
  AND (
    structured_path LIKE 'path.%'
    OR lower(structured_path) LIKE 'header.sec-ch-%'
    OR lower(structured_path) LIKE 'header.sec-fetch-%'
    OR lower(structured_path) LIKE 'header.sec-websocket-%'
  );

DELETE FROM api_cross_border_events AS cb
USING api_runtime_events AS ev
WHERE ev.id = cb.source_event_id
  AND (
    UPPER(COALESCE(ev.final_action, '')) IN ('BLOCK', 'TEMP_BLOCK', 'RATE_LIMIT')
    OR COALESCE(ev.response_status, 0) IN (404, 405, 410)
    OR (
      jsonb_typeof(ev.details_json) = 'array'
      AND NOT EXISTS (
        SELECT 1
        FROM jsonb_array_elements(ev.details_json) AS d
        WHERE d->>'detector' = 'sensitive_data'
          AND lower(COALESCE(d->>'rule_id', '')) <> 'sensitive.response_body_unchecked'
          AND (
            (cb.direction = 'OUT' AND UPPER(COALESCE(d->'evidence'->>'direction', 'REQUEST')) = 'RESPONSE')
            OR (cb.direction = 'IN' AND UPPER(COALESCE(d->'evidence'->>'direction', 'REQUEST')) <> 'RESPONSE')
          )
          AND NOT (
            lower(COALESCE(d->>'rule_id', '')) = 'sensitive.field'
            AND lower(COALESCE(d->'evidence'->>'location', '')) = 'path'
          )
          AND NOT (
            lower(COALESCE(d->>'rule_id', '')) = 'sensitive.field'
            AND lower(COALESCE(d->'evidence'->>'location', '')) = 'header'
            AND (
              lower(COALESCE(d->'evidence'->>'field', '')) LIKE 'sec-ch-%'
              OR lower(COALESCE(d->'evidence'->>'field', '')) LIKE 'sec-fetch-%'
              OR lower(COALESCE(d->'evidence'->>'field', '')) LIKE 'sec-websocket-%'
              OR lower(COALESCE(d->'evidence'->>'field', '')) IN (
                'accept','accept-charset','accept-encoding','accept-language','accept-ranges',
                'baggage','cache-control','connection','content-disposition','content-encoding',
                'content-language','content-length','content-range','content-type','date','dnt',
                'etag','expect','forwarded','host','if-match','if-modified-since','if-none-match',
                'if-range','if-unmodified-since','keep-alive','last-modified','max-forwards',
                'origin','pragma','priority','purpose','range','referer','save-data','sec-gpc',
                'sec-purpose','te','traceparent','tracestate','trailer','transfer-encoding',
                'upgrade','upgrade-insecure-requests','user-agent','vary','via',
                'x-forwarded-for','x-forwarded-host','x-forwarded-port','x-forwarded-proto',
                'x-real-ip','x-requested-with'
              )
            )
          )
          AND (
            COALESCE(ev.api_level, '') <> 'NON_API'
            OR lower(COALESCE(d->>'rule_id', '')) IN ('sensitive.value', 'sensitive.value_in_query', 'sensitive.response_value')
          )
      )
    )
  );

COMMIT;
