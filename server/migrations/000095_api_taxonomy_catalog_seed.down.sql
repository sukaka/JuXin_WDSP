-- 回退本次预置的维度值目录条目；同 (dimension, value) 的人工条目不受影响
-- （种子以 ON CONFLICT DO NOTHING 写入，已存在的人工条目未被本迁移创建）。
BEGIN;

DELETE FROM api_custom_taxonomies
WHERE created_by IS NULL AND (dimension, value) IN (
    ('DATA_TYPE', '身份信息'), ('DATA_TYPE', '联系方式'), ('DATA_TYPE', '认证凭证'),
    ('DATA_TYPE', '财务数据'), ('DATA_TYPE', '位置数据'), ('DATA_TYPE', '设备数据'),
    ('DATA_TYPE', '交易数据'),
    ('OPERATION', '查询'), ('OPERATION', '新增'), ('OPERATION', '修改'), ('OPERATION', '删除'),
    ('OPERATION', '上传'), ('OPERATION', '下载'), ('OPERATION', '导入'), ('OPERATION', '导出'),
    ('OPERATION', '批处理'),
    ('LIFECYCLE', '活跃'), ('LIFECYCLE', '废弃'), ('LIFECYCLE', '影子接口'),
    ('LIFECYCLE', '僵尸接口'), ('LIFECYCLE', '测试接口'),
    ('DIRECTION', '入站'), ('DIRECTION', '出站'), ('DIRECTION', '东西向'), ('DIRECTION', '第三方回调'),
    ('AUTH_TYPE', '无需认证'), ('AUTH_TYPE', 'Session'), ('AUTH_TYPE', 'API Key'),
    ('AUTH_TYPE', 'OAuth2'), ('AUTH_TYPE', 'JWT'), ('AUTH_TYPE', '签名'), ('AUTH_TYPE', 'mTLS'),
    ('ENV', '生产'), ('ENV', '预发布'), ('ENV', '测试'), ('ENV', '开发'),
    ('COMPLIANCE_SCOPE', '网络安全法'), ('COMPLIANCE_SCOPE', '数据安全法'),
    ('COMPLIANCE_SCOPE', '等保'), ('COMPLIANCE_SCOPE', 'GDPR'),
    ('DATA_CROSS_BORDER', '不涉及'), ('DATA_CROSS_BORDER', '境内'),
    ('DATA_CROSS_BORDER', '跨境'), ('DATA_CROSS_BORDER', '待确认')
);

COMMIT;
