-- 000227 优化文件合规默认种子规则理由文案：
--   将 000071 与 000081 初始化的 18 条默认规则理由统一调整为面向安全运维的清晰中文表述，
--   去除「初始建议：」前缀与「webshell 投递面」「载荷」等内部研发术语。
--
-- 幂等与非侵入语义：
--   仅当 (direction, match_type, match_value) 命中且 reason 仍为原默认文案时更新，
--   不覆盖管理员在界面手工编辑过的理由；重复执行无副作用。
BEGIN;

UPDATE api_file_compliance_rules AS r
SET reason     = v.new_reason,
    updated_at = now()
FROM (VALUES
    ('UPLOAD',   'EXT', 'jsp',   '初始建议：阻断 JSP 脚本上传（webshell 投递面）',                       '禁止上传 JSP 动态脚本，防范 Webshell 植入'),
    ('UPLOAD',   'EXT', 'jspx',  '初始建议：阻断 JSPX 脚本上传（webshell 投递面）',                      '禁止上传 JSPX 动态脚本，防范 Webshell 植入'),
    ('UPLOAD',   'EXT', 'asp',   '初始建议：阻断 ASP 脚本上传（webshell 投递面）',                       '禁止上传 ASP 动态脚本，防范 Webshell 植入'),
    ('UPLOAD',   'EXT', 'aspx',  '初始建议：阻断 ASPX 脚本上传（webshell 投递面）',                      '禁止上传 ASPX 动态脚本，防范 Webshell 植入'),
    ('UPLOAD',   'EXT', 'ashx',  '初始建议：阻断 ASHX 处理程序上传（webshell 投递面）',                  '禁止上传 ASHX 处理程序，防范 Webshell 植入'),
    ('UPLOAD',   'EXT', 'asmx',  '初始建议：阻断 ASMX 服务脚本上传（webshell 投递面）',                  '禁止上传 ASMX 服务脚本，防范 Webshell 植入'),
    ('UPLOAD',   'EXT', 'php',   '初始建议：阻断 PHP 脚本上传（webshell 投递面）',                       '禁止上传 PHP 动态脚本，防范 Webshell 植入'),
    ('UPLOAD',   'EXT', 'phtml', '初始建议：阻断 PHTML 脚本上传（webshell 投递面）',                     '禁止上传 PHTML 脚本，防范 Webshell 植入'),
    ('UPLOAD',   'EXT', 'cer',   '初始建议：阻断 CER 脚本上传（IIS 等同 ASP 执行，webshell 投递面）',    '禁止上传 CER 文件，防范 IIS 按 ASP 解析植入 Webshell'),
    ('UPLOAD',   'EXT', 'asa',   '初始建议：阻断 ASA 脚本上传（IIS 等同 ASP 执行，webshell 投递面）',    '禁止上传 ASA 文件，防范 IIS 按 ASP 解析植入 Webshell'),
    ('UPLOAD',   'EXT', 'shtml', '初始建议：阻断 SHTML 页面上传（SSI 指令可执行，webshell 投递面）',     '禁止上传 SHTML 页面，防范利用 SSI 执行恶意指令'),
    ('UPLOAD',   'EXT', 'war',   '初始建议：阻断 WAR 包上传（可部署 JSP webshell，webshell 投递面）',    '禁止上传 WAR 应用包，防范恶意部署与 Webshell 植入'),
    ('UPLOAD',   'EXT', 'jar',   '初始建议：阻断 JAR 包上传（可携带可执行类载荷，webshell 投递面）',     '禁止上传 JAR 归档包，防范上传恶意可执行程序'),
    ('UPLOAD',   'EXT', 'exe',   '初始建议：阻断可执行程序上传',                                         '禁止上传可执行程序，防范恶意软件植入'),
    ('UPLOAD',   'EXT', 'bat',   '初始建议：阻断批处理脚本上传',                                         '禁止上传批处理脚本，防范恶意命令执行'),
    ('UPLOAD',   'EXT', 'sh',    '初始建议：阻断 shell 脚本上传',                                        '禁止上传 Shell 脚本，防范恶意命令执行'),
    ('DOWNLOAD', 'EXT', 'sql',   '初始建议：数据库导出文件下载观察',                                     '审计监控数据库导出文件下载，防范敏感数据泄露'),
    ('DOWNLOAD', 'EXT', 'bak',   '初始建议：备份文件下载观察',                                           '审计监控备份文件下载，防范敏感文件泄露')
) AS v(direction, match_type, match_value, old_reason, new_reason)
WHERE r.direction   = v.direction
  AND r.match_type  = v.match_type
  AND r.match_value = v.match_value
  AND r.reason      = v.old_reason;

COMMIT;
