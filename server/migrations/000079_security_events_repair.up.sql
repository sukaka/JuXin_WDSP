-- 000079 安全事件存量数据修复（配合 securityevents 包两个缺陷修复）。
--
-- a) application_id 回填：
--    早期采集器不做域名→应用解析，历史事件 application_id 全为 NULL。
--    匹配口径与运行时 matchApplication 一致：domain 小写化并剥离端口后，
--    等值匹配 application_domains.normalized_hostname（已软删应用不回填；
--    泛域名无法纯 SQL 等值还原，存量不回填，由新事件按运行时逻辑覆盖）。
--
-- b) attack_type 按「严重度优先」重算：
--    旧逻辑取首个可映射 tag，自定义规则 1000712（attack-scanner，notice，
--    phase 1）总先于 CRS phase-2 的 XSS/SQLi 规则执行，真实攻击被误标
--    SCANNER_DETECTION。新逻辑与 Go 侧一致：候选 = matches.tags 中可映射
--    tag，取 severity 最高者，并列取先出现者。
--    说明一：matches.severity 存在两种写法——采集器写入映射值
--    （HIGH/MEDIUM/LOW/INFO），测试与直写 SQL 写入原始值（CRITICAL 等），
--    CASE 对两者按同一优先级归一（critical/high 同级，以此类推）。
--    说明二：审计消息原始顺序无法从随机 UUID 恢复，同严重度并列时以
--    match id 字典序兜底（与 Go 侧「先出现者」可能不同，可接受）。
BEGIN;

-- a) application_id / application_name_snapshot 回填
UPDATE security_events e
SET application_id = d.application_id,
    application_name_snapshot = a.name
FROM application_domains d
JOIN applications a ON a.id = d.application_id AND a.deleted_at IS NULL
WHERE e.application_id IS NULL
  AND lower(split_part(e.domain, ':', 1)) = d.normalized_hostname;

-- b) attack_type 严重度优先重算（tag 映射与 Go 侧 attackTypeByTag 相同）
WITH cand AS (
  SELECT m.event_id,
         CASE lower(m.severity)
           WHEN 'critical' THEN 4 WHEN 'high' THEN 4
           WHEN 'error' THEN 3 WHEN 'medium' THEN 3
           WHEN 'warning' THEN 2 WHEN 'low' THEN 2
           WHEN 'notice' THEN 1 WHEN 'info' THEN 1
           ELSE 0 END AS sev_rank,
         m.id AS match_id,
         CASE t.tag
           WHEN 'attack-sqli' THEN 'SQL_INJECTION'
           WHEN 'attack-xss' THEN 'XSS'
           WHEN 'attack-rce' THEN 'COMMAND_INJECTION'
           WHEN 'attack-lfi' THEN 'LOCAL_FILE_INCLUSION'
           WHEN 'attack-rfi' THEN 'REMOTE_FILE_INCLUSION'
           WHEN 'attack-php' THEN 'PHP_INJECTION'
           WHEN 'attack-java' THEN 'JAVA_INJECTION'
           WHEN 'attack-protocol' THEN 'PROTOCOL_VIOLATION'
           WHEN 'attack-fixation' THEN 'SESSION_FIXATION'
           WHEN 'attack-scanner' THEN 'SCANNER_DETECTION'
           WHEN 'attack-disclosure' THEN 'INFORMATION_DISCLOSURE'
           WHEN 'attack-injection-generic' THEN 'REMOTE_CODE_EXECUTION'
         END AS atype
  FROM security_event_matches m
  CROSS JOIN LATERAL jsonb_array_elements_text(m.tags) AS t(tag)
),
ranked AS (
  SELECT DISTINCT ON (event_id) event_id, atype
  FROM cand
  WHERE atype IS NOT NULL
  ORDER BY event_id, sev_rank DESC, match_id ASC
)
UPDATE security_events e
SET attack_type = r.atype
FROM ranked r
WHERE e.id = r.event_id AND e.attack_type <> r.atype;

COMMIT;
