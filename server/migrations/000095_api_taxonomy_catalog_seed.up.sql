-- 000095 API 分类维度值目录种子（api_custom_taxonomies）。
--
-- 背景：用途分类页 DIMENSION_LABELS 已声明 DATA_TYPE / COMPLIANCE_SCOPE 等维度，
-- 但维度值目录长期为空（docs/API_CLASSIFICATION_DESIGN.md §七：DATA_TYPE 暂无写入方）。
-- 本迁移为 8 个维度预置标准取值目录，供人工分类下拉选用；目录与端点维度解耦
-- （无引用完整性约束），不覆盖同 (dimension, value) 的既有条目，迁移可安全重放。
BEGIN;

INSERT INTO api_custom_taxonomies (dimension, value, description) VALUES
    -- 数据类型：接口读写数据的内容类别
    ('DATA_TYPE', '身份信息',   '姓名、证件号、账号标识等可识别个人身份的数据'),
    ('DATA_TYPE', '联系方式',   '手机号、邮箱、地址等联络方式数据'),
    ('DATA_TYPE', '认证凭证',   '口令、令牌、密钥、证书等认证凭据数据'),
    ('DATA_TYPE', '财务数据',   '账户余额、卡号、流水、账单等资金相关数据'),
    ('DATA_TYPE', '位置数据',   '经纬度、轨迹、地理围栏等位置信息数据'),
    ('DATA_TYPE', '设备数据',   '设备标识、指纹、遥测与状态数据'),
    ('DATA_TYPE', '交易数据',   '订单、支付、合同等交易过程数据'),
    -- 操作类型：接口对资源执行的动作
    ('OPERATION', '查询',   '只读检索与详情获取'),
    ('OPERATION', '新增',   '创建资源或记录'),
    ('OPERATION', '修改',   '更新既有资源或记录'),
    ('OPERATION', '删除',   '删除资源或记录'),
    ('OPERATION', '上传',   '客户端向服务端提交文件或数据'),
    ('OPERATION', '下载',   '服务端向客户端下发文件或数据'),
    ('OPERATION', '导入',   '批量数据迁入'),
    ('OPERATION', '导出',   '批量数据迁出'),
    ('OPERATION', '批处理', '批量任务与异步作业'),
    -- 生命周期：接口在其生命周期中的状态（影子/僵尸与资产标记口径一致）
    ('LIFECYCLE', '活跃',     '持续有生产流量的在用接口'),
    ('LIFECYCLE', '废弃',     '已声明下线、不再维护的接口'),
    ('LIFECYCLE', '影子接口', '流量中观测到但不在资产台账中的接口'),
    ('LIFECYCLE', '僵尸接口', '台账中存在但长期无流量的接口'),
    ('LIFECYCLE', '测试接口', '联调、压测或调试用途的接口'),
    -- 调用方向：调用流量的来源与去向
    ('DIRECTION', '入站',       '外部调用方主动调用本系统'),
    ('DIRECTION', '出站',       '本系统主动调用外部服务'),
    ('DIRECTION', '东西向',     '内部服务间横向调用'),
    ('DIRECTION', '第三方回调', '第三方平台回调通知（Webhook/异步通知）'),
    -- 认证方式：接口要求的调用方认证机制
    ('AUTH_TYPE', '无需认证', '匿名可访问，无任何认证要求'),
    ('AUTH_TYPE', 'Session',  '基于会话 Cookie 的认证'),
    ('AUTH_TYPE', 'API Key',  '基于 API 密钥的认证'),
    ('AUTH_TYPE', 'OAuth2',   '基于 OAuth2 授权框架的认证'),
    ('AUTH_TYPE', 'JWT',      '基于 JWT 令牌的认证'),
    ('AUTH_TYPE', '签名',     '基于请求签名（HMAC 等）的认证'),
    ('AUTH_TYPE', 'mTLS',     '基于双向 TLS 客户端证书的认证'),
    -- 环境：接口所属部署环境
    ('ENV', '生产',   '生产环境接口'),
    ('ENV', '预发布', '预发布（staging）环境接口'),
    ('ENV', '测试',   '测试环境接口'),
    ('ENV', '开发',   '开发环境接口'),
    -- 合规范围：接口数据落入的合规监管框架
    ('COMPLIANCE_SCOPE', '网络安全法', '受《网络安全法》监管要求约束'),
    ('COMPLIANCE_SCOPE', '数据安全法', '受《数据安全法》监管要求约束'),
    ('COMPLIANCE_SCOPE', '等保',       '受网络安全等级保护制度要求约束'),
    ('COMPLIANCE_SCOPE', 'GDPR',       '受欧盟《通用数据保护条例》约束'),
    -- 数据跨境：接口数据的跨境流动属性
    ('DATA_CROSS_BORDER', '不涉及', '数据仅在本地处理，无跨境场景'),
    ('DATA_CROSS_BORDER', '境内',   '数据在境内流动与存储'),
    ('DATA_CROSS_BORDER', '跨境',   '数据存在跨境传输或境外访问'),
    ('DATA_CROSS_BORDER', '待确认', '跨境属性尚未评估确认')
ON CONFLICT (dimension, value) DO NOTHING;

COMMIT;
