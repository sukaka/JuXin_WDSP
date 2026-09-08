-- 000081 回滚：按去重键删除本迁移追加的 webshell 脚本扩展名上传阻断种子行
-- （人工在同键规则上的修订随之移除，与 000073 内置种子回滚同一口径；
-- 000071 既有种子 exe/bat/sh/sql/bak 不动）。
BEGIN;

DELETE FROM api_file_compliance_rules
WHERE direction = 'UPLOAD' AND match_type = 'EXT' AND match_value IN
    ('jsp', 'jspx', 'asp', 'aspx', 'ashx', 'asmx', 'php', 'phtml', 'cer', 'asa', 'shtml', 'war', 'jar');

COMMIT;
