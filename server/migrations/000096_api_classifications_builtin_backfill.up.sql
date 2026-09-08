-- 000096 启发式分类值内置目录回填（api_classifications）。
--
-- 背景：classifyByPath（apiassets/store.go）自动分类产出 7 个用途值
-- （AUTH/TRADE/FILE/ADMIN/USER_MGMT/QUERY/GENERAL）与 3 个暴露面值
-- （INTERNAL/PARTNER/PUBLIC），报表按 code 联表 api_classifications 取名称
-- （reports/api_collect.go）。这批编码长期只靠人工补录进目录，且缺说明。
-- 本迁移将其落成内置目录并补齐说明；已存在且已有说明的行不覆盖
-- （人工可能已修订），仅回填空说明，迁移可安全重放。
BEGIN;

INSERT INTO api_classifications (code, name, description, is_builtin) VALUES
    ('AUTH',      '认证鉴权',   '登录、登出、令牌签发/刷新、验证码等认证会话接口（启发式命中 /login /signin /auth /token /captcha）', TRUE),
    ('TRADE',     '交易支付',   '支付、订单、交易、账务等资金交易接口（启发式命中 /pay /order /trade /billing）', TRUE),
    ('FILE',      '文件传输',   '文件上传、下载、导入导出等文件传输接口（启发式命中 /upload /file /download /export）', TRUE),
    ('ADMIN',     '管理运维',   '后台管理、配置与运维操作接口（启发式命中 /admin /manage）', TRUE),
    ('USER_MGMT', '用户管理',   '用户资料、账户与密保管理等用户生命周期接口（启发式命中 /user /account /profile）', TRUE),
    ('QUERY',     '查询检索',   '搜索、查询、列表等只读检索接口（启发式命中 /search /query /list）', TRUE),
    ('GENERAL',   '通用业务',   '未命中具体类别的一般业务接口（启发式兜底分类）', TRUE),
    ('INTERNAL',  '内部使用',   '仅内部网络或服务间使用、不对公网暴露的接口', TRUE),
    ('PARTNER',   '合作方开放', '面向合作方开放、需合作方凭证访问的接口', TRUE),
    ('PUBLIC',    '公网开放',   '面向公网开放的接口（启发式命中 /public /openapi /webhook /callback）', TRUE)
ON CONFLICT (code) DO UPDATE
SET description = EXCLUDED.description
WHERE api_classifications.description = '';

COMMIT;
