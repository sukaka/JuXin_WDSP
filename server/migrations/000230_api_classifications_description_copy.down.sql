-- 000230 回滚：将仍保持新版纯中文说明文案的 20 条默认用途分类还原为 000073/000087/000095/000096 原文案
-- （管理员手工修订过的说明不受影响）。
BEGIN;

UPDATE api_classifications AS c
SET description = v.old_description
FROM (VALUES
    ('EXTERNAL_INTEGRATION', 'Webhook、回调、第三方开放平台对接接口',                                                               '事件推送、回调、第三方开放平台对接接口'),
    ('AI_INTELLIGENCE',      '模型调用、智能分析、AI 辅助运营接口',                                                                '模型调用、智能分析与智能辅助运营接口'),
    ('PRODUCT_CATALOG',      '商品、服务、SKU、类目与价格管理接口',                                                                '商品、服务、规格库存、类目与价格管理接口'),
    ('DEVELOPER_PLATFORM',   '开放 API、应用凭证、SDK、沙箱与调用配额接口',                                                        '开放接口、应用凭证、开发工具包、沙箱与调用配额接口'),
    ('AUTH',                 '登录、登出、令牌签发/刷新、验证码等认证会话接口（启发式命中 /login /signin /auth /token /captcha）',   '登录、登出、令牌签发/刷新、验证码等认证会话接口'),
    ('TRADE',                '支付、订单、交易、账务等资金交易接口（启发式命中 /pay /order /trade /billing）',                       '支付、订单、交易、账务等资金交易接口'),
    ('FILE',                 '文件上传、下载、导入导出等文件传输接口（启发式命中 /upload /file /download /export）',                 '文件上传、下载、导入导出等文件传输接口'),
    ('ADMIN',                '后台管理、配置与运维操作接口（启发式命中 /admin /manage）',                                           '后台管理、配置与运维操作接口'),
    ('USER_MGMT',            '用户资料、账户与密保管理等用户生命周期接口（启发式命中 /user /account /profile）',                    '用户资料、账户与密保管理等用户生命周期接口'),
    ('QUERY',                '搜索、查询、列表等只读检索接口（启发式命中 /search /query /list）',                                   '搜索、查询、列表等只读检索接口'),
    ('GENERAL',              '未命中具体类别的一般业务接口（启发式兜底分类）',                                                      '未命中具体类别的一般业务接口'),
    ('PUBLIC',               '面向公网开放的接口（启发式命中 /public /openapi /webhook /callback）',                                '面向公网开放的接口')
) AS v(code, old_description, new_description)
WHERE c.code        = v.code
  AND c.is_builtin  = TRUE
  AND c.description = v.new_description;

UPDATE api_custom_taxonomies AS t
SET description = v.old_description
FROM (VALUES
    ('DIRECTION', '第三方回调', '第三方平台回调通知（Webhook/异步通知）',   '第三方平台回调与异步通知'),
    ('AUTH_TYPE', 'Session',    '基于会话 Cookie 的认证',                   '基于浏览器会话凭据的认证'),
    ('AUTH_TYPE', 'API Key',    '基于 API 密钥的认证',                      '基于接口密钥的认证'),
    ('AUTH_TYPE', 'OAuth2',     '基于 OAuth2 授权框架的认证',               '基于开放授权框架的认证'),
    ('AUTH_TYPE', 'JWT',        '基于 JWT 令牌的认证',                      '基于数字签名令牌的认证'),
    ('AUTH_TYPE', '签名',       '基于请求签名（HMAC 等）的认证',             '基于请求摘要签名的认证'),
    ('AUTH_TYPE', 'mTLS',       '基于双向 TLS 客户端证书的认证',             '基于双向客户端证书的认证'),
    ('ENV',       '预发布',     '预发布（staging）环境接口',                 '预发布环境接口')
) AS v(dimension, value, old_description, new_description)
WHERE t.dimension   = v.dimension
  AND t.value       = v.value
  AND t.description = v.new_description;

COMMIT;
