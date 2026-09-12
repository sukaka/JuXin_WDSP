-- 九章 §55 性能矩阵缺口项（大规模维度）造数脚本
-- 目标库：独立临时库 jiuzhang_perf（127.0.0.1:55432 一次性隔离容器 p0s3-pg），
-- 不触碰 jiuzhang_waf / jiuzhang_waf_test。
-- 规模口径（对齐任务书 §55「API数量10万级 / 参数模型百万级 / 图谱查询性能」）：
--   api_endpoints           100,000（10 应用均布，asset_status 90% CONFIRMED）
--   api_model_versions      120,000（每端点 1 条 FORMAL + 2 万端点额外 1 条 SUPERSEDED，
--                           验证 DISTINCT ON 最近确认版本选取语义）
--   api_parameter_models    1,200,000（每 FORMAL 版本 12 个 REQUEST 参数，
--                           其中约 10/12 满足下发过滤：required 或 confirmed_constraints 非空
--                           或 semantic_type 非空 → 下发面约 1,000,000 条）
--   api_parameter_relations ≈50,000（半数端点 1 条 confirmed REQUIRES）
--   api_call_edges          700,000（三趟不同盐值各 30 万，自然键唯一；实测零冲突）
--   api_runtime_findings    60,000（status='NEW'，供拓扑节点 open_findings_count 聚合）
-- 分批：参数模型按 endpoint_key 哈希分 6 批，每批一个事务约 20 万行；其余每表单语句单事务。
-- 用法：docker exec -i p0s3-pg psql -U jiuzhang -d jiuzhang_perf -f - < 本文件
\set ON_ERROR_STOP on
\timing on

\echo '=== [seed] applications x10 ==='
INSERT INTO applications (code, name, status)
SELECT 'perfapp' || g, '性能应用' || g, 'ONLINE'
FROM generate_series(1, 10) g;

\echo '=== [seed] api_endpoints x100000 ==='
INSERT INTO api_endpoints (application_id, http_method, normalized_path, endpoint_key,
                           api_confidence, asset_status, is_api, hit_count,
                           learning_status, raw_path_example, host)
SELECT a.id,
       m.http_method,
       p.path,
       m.http_method || ' ' || p.path,
       0.9,
       CASE WHEN g % 10 = 0 THEN 'DISCOVERED' ELSE 'CONFIRMED' END,
       true,
       (g * 37) % 1000000,
       'LEARNED',
       replace(p.path, '{id}', '12345'),
       'perf.example.com'
FROM generate_series(1, 100000) g
JOIN LATERAL (SELECT (ARRAY['GET','POST','PUT','DELETE'])[1 + (g % 4)] AS http_method) m ON true
JOIN LATERAL (SELECT '/api/v1/svc' || (g % 1000) || '/resource' || g || '/{id}' AS path) p ON true
JOIN applications a ON a.code = 'perfapp' || (1 + g % 10);

\echo '=== [seed] api_model_versions FORMAL x100000 ==='
INSERT INTO api_model_versions (api_endpoint_id, endpoint_key, status, schema_json, content_hash,
                                version_number, sample_count, valid_sample_count, confidence,
                                created_reason, confirmed_at, activated_at)
SELECT e.id, e.endpoint_key, 'FORMAL',
       jsonb_build_object('id','number','name','string','email','string','age','number',
                          'active','bool','tags','array','address','object',
                          'created_at','string','score','number','note','string'),
       md5(e.endpoint_key), 1, 500, 500, 0.95,
       'learning_threshold', now() - interval '1 day', now() - interval '1 day'
FROM api_endpoints e;

\echo '=== [seed] api_model_versions SUPERSEDED x20000（前 2 万端点的历史版本）==='
INSERT INTO api_model_versions (api_endpoint_id, endpoint_key, status, schema_json, content_hash,
                                version_number, confirmed_at, created_reason)
SELECT e.id, e.endpoint_key, 'SUPERSEDED',
       jsonb_build_object('id','number','name','string'),
       md5(e.endpoint_key || '-old'), 1, now() - interval '10 days', 'manual'
FROM (SELECT id, endpoint_key FROM api_endpoints ORDER BY id LIMIT 20000) e;

\echo '=== [seed] 端点序号映射表（供边/findings 造数索引，收尾删除）==='
CREATE TABLE _perf_ep_map AS
SELECT id, (row_number() OVER (ORDER BY id))::int - 1 AS rn FROM api_endpoints;
CREATE UNIQUE INDEX _perf_ep_map_rn ON _perf_ep_map(rn);

-- 参数模型 1.2M：按 FORMAL 版本 endpoint_key 哈希分 6 批（每批约 20 万行，单批单事务）
\echo '=== [seed] api_parameter_models batch 0/6 ==='
INSERT INTO api_parameter_models (model_version_id, direction, location, structured_path,
                                  parameter_name, base_type, semantic_type, required,
                                  confirmed_constraints)
SELECT v.id, 'REQUEST',
       (ARRAY['QUERY','HEADER','BODY'])[1 + (p % 3)],
       CASE WHEN p % 3 = 2 THEN 'body.field' || p ELSE '' END,
       'param' || p,
       (ARRAY['string','number','bool'])[1 + (p % 3)],
       CASE WHEN p = 0 THEN 'email' ELSE '' END,
       (p % 4 = 0),
       CASE WHEN p % 5 = 0 THEN '{}'::jsonb
            ELSE jsonb_build_object('max_length', 64, 'min_length', 1) END
FROM api_model_versions v
CROSS JOIN generate_series(0, 11) p
WHERE v.status = 'FORMAL' AND mod(hashtextextended(v.endpoint_key, 0) & 4611686018427387903, 6) = 0;

\echo '=== [seed] api_parameter_models batch 1/6 ==='
INSERT INTO api_parameter_models (model_version_id, direction, location, structured_path,
                                  parameter_name, base_type, semantic_type, required,
                                  confirmed_constraints)
SELECT v.id, 'REQUEST',
       (ARRAY['QUERY','HEADER','BODY'])[1 + (p % 3)],
       CASE WHEN p % 3 = 2 THEN 'body.field' || p ELSE '' END,
       'param' || p,
       (ARRAY['string','number','bool'])[1 + (p % 3)],
       CASE WHEN p = 0 THEN 'email' ELSE '' END,
       (p % 4 = 0),
       CASE WHEN p % 5 = 0 THEN '{}'::jsonb
            ELSE jsonb_build_object('max_length', 64, 'min_length', 1) END
FROM api_model_versions v
CROSS JOIN generate_series(0, 11) p
WHERE v.status = 'FORMAL' AND mod(hashtextextended(v.endpoint_key, 0) & 4611686018427387903, 6) = 1;

\echo '=== [seed] api_parameter_models batch 2/6 ==='
INSERT INTO api_parameter_models (model_version_id, direction, location, structured_path,
                                  parameter_name, base_type, semantic_type, required,
                                  confirmed_constraints)
SELECT v.id, 'REQUEST',
       (ARRAY['QUERY','HEADER','BODY'])[1 + (p % 3)],
       CASE WHEN p % 3 = 2 THEN 'body.field' || p ELSE '' END,
       'param' || p,
       (ARRAY['string','number','bool'])[1 + (p % 3)],
       CASE WHEN p = 0 THEN 'email' ELSE '' END,
       (p % 4 = 0),
       CASE WHEN p % 5 = 0 THEN '{}'::jsonb
            ELSE jsonb_build_object('max_length', 64, 'min_length', 1) END
FROM api_model_versions v
CROSS JOIN generate_series(0, 11) p
WHERE v.status = 'FORMAL' AND mod(hashtextextended(v.endpoint_key, 0) & 4611686018427387903, 6) = 2;

\echo '=== [seed] api_parameter_models batch 3/6 ==='
INSERT INTO api_parameter_models (model_version_id, direction, location, structured_path,
                                  parameter_name, base_type, semantic_type, required,
                                  confirmed_constraints)
SELECT v.id, 'REQUEST',
       (ARRAY['QUERY','HEADER','BODY'])[1 + (p % 3)],
       CASE WHEN p % 3 = 2 THEN 'body.field' || p ELSE '' END,
       'param' || p,
       (ARRAY['string','number','bool'])[1 + (p % 3)],
       CASE WHEN p = 0 THEN 'email' ELSE '' END,
       (p % 4 = 0),
       CASE WHEN p % 5 = 0 THEN '{}'::jsonb
            ELSE jsonb_build_object('max_length', 64, 'min_length', 1) END
FROM api_model_versions v
CROSS JOIN generate_series(0, 11) p
WHERE v.status = 'FORMAL' AND mod(hashtextextended(v.endpoint_key, 0) & 4611686018427387903, 6) = 3;

\echo '=== [seed] api_parameter_models batch 4/6 ==='
INSERT INTO api_parameter_models (model_version_id, direction, location, structured_path,
                                  parameter_name, base_type, semantic_type, required,
                                  confirmed_constraints)
SELECT v.id, 'REQUEST',
       (ARRAY['QUERY','HEADER','BODY'])[1 + (p % 3)],
       CASE WHEN p % 3 = 2 THEN 'body.field' || p ELSE '' END,
       'param' || p,
       (ARRAY['string','number','bool'])[1 + (p % 3)],
       CASE WHEN p = 0 THEN 'email' ELSE '' END,
       (p % 4 = 0),
       CASE WHEN p % 5 = 0 THEN '{}'::jsonb
            ELSE jsonb_build_object('max_length', 64, 'min_length', 1) END
FROM api_model_versions v
CROSS JOIN generate_series(0, 11) p
WHERE v.status = 'FORMAL' AND mod(hashtextextended(v.endpoint_key, 0) & 4611686018427387903, 6) = 4;

\echo '=== [seed] api_parameter_models batch 5/6 ==='
INSERT INTO api_parameter_models (model_version_id, direction, location, structured_path,
                                  parameter_name, base_type, semantic_type, required,
                                  confirmed_constraints)
SELECT v.id, 'REQUEST',
       (ARRAY['QUERY','HEADER','BODY'])[1 + (p % 3)],
       CASE WHEN p % 3 = 2 THEN 'body.field' || p ELSE '' END,
       'param' || p,
       (ARRAY['string','number','bool'])[1 + (p % 3)],
       CASE WHEN p = 0 THEN 'email' ELSE '' END,
       (p % 4 = 0),
       CASE WHEN p % 5 = 0 THEN '{}'::jsonb
            ELSE jsonb_build_object('max_length', 64, 'min_length', 1) END
FROM api_model_versions v
CROSS JOIN generate_series(0, 11) p
WHERE v.status = 'FORMAL' AND mod(hashtextextended(v.endpoint_key, 0) & 4611686018427387903, 6) = 5;

\echo '=== [seed] api_parameter_relations confirmed ≈50000 ==='
INSERT INTO api_parameter_relations (model_version_id, source_parameter_id, target_parameter_id,
                                     relation_type, confirmed, confirmed_at)
SELECT v.id, a.id, b.id, 'REQUIRES', true, now()
FROM (SELECT id FROM api_model_versions
      WHERE status = 'FORMAL' AND mod(hashtextextended(endpoint_key, 0) & 4611686018427387903, 2) = 0) v
CROSS JOIN LATERAL (
    SELECT p.id FROM api_parameter_models p
    WHERE p.model_version_id = v.id AND p.direction = 'REQUEST' AND p.location = 'QUERY'
    ORDER BY p.id LIMIT 1
) a
CROSS JOIN LATERAL (
    SELECT p.id FROM api_parameter_models p
    WHERE p.model_version_id = v.id AND p.direction = 'REQUEST' AND p.location = 'QUERY'
    ORDER BY p.id DESC LIMIT 1
) b;

-- 注意：自然键 (caller, source, target) 全部由 g 派生时，单趟 generate_series 只有
-- 100k 个不同三元组（caller=g%5000 与 source=(g*37)%100000 同周期）；
-- 需多趟更换盐值才能得到 70 万唯一边（本次实测三趟均无冲突）。
\echo '=== [seed] api_call_edges pass 1/3 ==='
INSERT INTO api_call_edges (caller_fingerprint, source_endpoint_id, target_endpoint_id,
                            call_count, identity_count, first_seen_at, last_seen_at)
SELECT 'fp-' || (g % 5000),
       CASE WHEN g % 5 = 0 THEN NULL ELSE s.id END,
       t.id, (g % 100000) + 1, 1 + (g % 50),
       now() - make_interval(hours => g % 720), now() - make_interval(hours => g % 24)
FROM generate_series(0, 299999) g
JOIN _perf_ep_map s ON s.rn = (g * 37) % 100000
JOIN _perf_ep_map t ON t.rn = (g * 91 + 7) % 100000
ON CONFLICT (caller_fingerprint, source_endpoint_id, target_endpoint_id) DO NOTHING;

\echo '=== [seed] api_call_edges pass 2/3 ==='
INSERT INTO api_call_edges (caller_fingerprint, source_endpoint_id, target_endpoint_id,
                            call_count, identity_count, first_seen_at, last_seen_at)
SELECT 'fp-' || ((g / 7) % 5000),
       CASE WHEN g % 5 = 1 THEN NULL ELSE s.id END,
       t.id, (g % 90000) + 1, 1 + (g % 50),
       now() - make_interval(hours => g % 720), now() - make_interval(hours => g % 24)
FROM generate_series(300000, 599999) g
JOIN _perf_ep_map s ON s.rn = (g * 37) % 100000
JOIN _perf_ep_map t ON t.rn = (g * 53 + 11) % 100000
ON CONFLICT (caller_fingerprint, source_endpoint_id, target_endpoint_id) DO NOTHING;

\echo '=== [seed] api_call_edges pass 3/3 ==='
INSERT INTO api_call_edges (caller_fingerprint, source_endpoint_id, target_endpoint_id,
                            call_count, identity_count, first_seen_at, last_seen_at)
SELECT 'fp-' || ((g / 13) % 5000),
       CASE WHEN g % 5 = 2 THEN NULL ELSE s.id END,
       t.id, (g % 80000) + 1, 1 + (g % 50),
       now() - make_interval(hours => g % 720), now() - make_interval(hours => g % 24)
FROM generate_series(600000, 899999) g
JOIN _perf_ep_map s ON s.rn = (g * 61) % 100000
JOIN _perf_ep_map t ON t.rn = (g * 29 + 3) % 100000
ON CONFLICT (caller_fingerprint, source_endpoint_id, target_endpoint_id) DO NOTHING;

\echo '=== [seed] api_runtime_findings x60000（status=NEW）==='
INSERT INTO api_runtime_findings (endpoint_id, request_id, finding_type, severity, status, title)
SELECT s.id, '', 'SCHEMA_DEVIATION', 'MEDIUM', 'NEW', 'perf seed finding'
FROM generate_series(0, 59999) g
JOIN _perf_ep_map s ON s.rn = (g * 53) % 100000;

\echo '=== [seed] 收尾：VACUUM ANALYZE + 规模核验 ==='
VACUUM ANALYZE api_endpoints;
VACUUM ANALYZE api_model_versions;
VACUUM ANALYZE api_parameter_models;
VACUUM ANALYZE api_parameter_relations;
VACUUM ANALYZE api_call_edges;
VACUUM ANALYZE api_runtime_findings;

SELECT 'api_endpoints' AS tbl, count(*) FROM api_endpoints
UNION ALL SELECT 'api_model_versions', count(*) FROM api_model_versions
UNION ALL SELECT 'api_model_versions FORMAL', count(*) FROM api_model_versions WHERE status='FORMAL'
UNION ALL SELECT 'api_parameter_models', count(*) FROM api_parameter_models
UNION ALL SELECT 'api_parameter_models 下发过滤命中', count(*) FROM api_parameter_models
  WHERE direction='REQUEST' AND (required OR confirmed_constraints <> '{}'::jsonb OR COALESCE(semantic_type,'') <> '')
UNION ALL SELECT 'api_parameter_relations confirmed', count(*) FROM api_parameter_relations WHERE confirmed
UNION ALL SELECT 'api_call_edges', count(*) FROM api_call_edges
UNION ALL SELECT 'api_runtime_findings', count(*) FROM api_runtime_findings
ORDER BY 1;

SELECT relname, pg_size_pretty(pg_total_relation_size(relid)) AS total_size
FROM pg_catalog.pg_statio_user_tables
WHERE relname IN ('api_endpoints','api_model_versions','api_parameter_models',
                  'api_parameter_relations','api_call_edges','api_runtime_findings')
ORDER BY pg_total_relation_size(relid) DESC;

DROP TABLE _perf_ep_map;
\echo '=== [seed] done ==='
