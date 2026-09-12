-- 000081 API 文件合规规则种子追加：webshell 可执行脚本扩展名上传阻断（BAS 覆盖基线补强）。
--
-- 背景：000071 初始建议种子仅覆盖 exe/bat/sh 可执行程序后缀，未覆盖各类
--   webshell 脚本后缀（JSP/ASP/PHP 系及 IIS 等价映射后缀）。BAS 入侵攻击模拟
--   基线中 webshell 上传投递为主要覆盖面之一，本迁移向 api_file_compliance_rules
--   追加 UPLOAD 方向 EXT 阻断种子（与 000071 同一"初始建议种子"语义，非强制基线）。
--
-- 纪律（与 000071 一致）：
--   - 以下均为可执行脚本/可部署包后缀，默认 BLOCK；站点确有业务需要上传此类
--     文件时，可按现场在管理面停用（enabled=false）或删除对应行；
--   - ON CONFLICT (direction, match_type, match_value) DO NOTHING：重放幂等，
--     不覆盖人工对同键规则的修订（动作/事由/启停）；
--   - match_value 口径：小写、不含前导点（与 api_file_assets.extension 同口径，
--     均通过管理面 extValuePattern 形态校验）。
BEGIN;

-- 初始建议种子（webshell 投递面，可按现场策略在管理面调整/停用）：
INSERT INTO api_file_compliance_rules (direction, match_type, match_value, action, reason) VALUES
('UPLOAD', 'EXT', 'jsp',   'BLOCK', '初始建议：阻断 JSP 脚本上传（webshell 投递面）'),
('UPLOAD', 'EXT', 'jspx',  'BLOCK', '初始建议：阻断 JSPX 脚本上传（webshell 投递面）'),
('UPLOAD', 'EXT', 'asp',   'BLOCK', '初始建议：阻断 ASP 脚本上传（webshell 投递面）'),
('UPLOAD', 'EXT', 'aspx',  'BLOCK', '初始建议：阻断 ASPX 脚本上传（webshell 投递面）'),
('UPLOAD', 'EXT', 'ashx',  'BLOCK', '初始建议：阻断 ASHX 处理程序上传（webshell 投递面）'),
('UPLOAD', 'EXT', 'asmx',  'BLOCK', '初始建议：阻断 ASMX 服务脚本上传（webshell 投递面）'),
('UPLOAD', 'EXT', 'php',   'BLOCK', '初始建议：阻断 PHP 脚本上传（webshell 投递面）'),
('UPLOAD', 'EXT', 'phtml', 'BLOCK', '初始建议：阻断 PHTML 脚本上传（webshell 投递面）'),
('UPLOAD', 'EXT', 'cer',   'BLOCK', '初始建议：阻断 CER 脚本上传（IIS 等同 ASP 执行，webshell 投递面）'),
('UPLOAD', 'EXT', 'asa',   'BLOCK', '初始建议：阻断 ASA 脚本上传（IIS 等同 ASP 执行，webshell 投递面）'),
('UPLOAD', 'EXT', 'shtml', 'BLOCK', '初始建议：阻断 SHTML 页面上传（SSI 指令可执行，webshell 投递面）'),
('UPLOAD', 'EXT', 'war',   'BLOCK', '初始建议：阻断 WAR 包上传（可部署 JSP webshell，webshell 投递面）'),
('UPLOAD', 'EXT', 'jar',   'BLOCK', '初始建议：阻断 JAR 包上传（可携带可执行类载荷，webshell 投递面）')
ON CONFLICT (direction, match_type, match_value) DO NOTHING;

COMMIT;
