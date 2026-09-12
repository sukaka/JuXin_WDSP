-- 000148 §34 用途多维识别词表种子（api_custom_taxonomies）。
--
-- 背景：任务书 §34 要求用途多维识别（9 维）+ §34.2 操作动作 43 项词表。
-- 自动分类侧（apiassets classify.go）已新增 ACTION（§34.2 词表）与 BUSINESS_DOMAIN
-- （§34.1 内置 16 项，编码对齐 api_classifications 种子，迁移 000073）两个维度的
-- AUTO 产出。本迁移为这两个维度预置标准取值目录，供人工分类下拉选用（口径同
-- 迁移 000095）；目录与端点维度解耦（无引用完整性约束），不覆盖同 (dimension, value)
-- 的既有条目，迁移可安全重放。
BEGIN;

INSERT INTO api_custom_taxonomies (dimension, value, description) VALUES
    -- §34.2 操作动作 43 项词表
    ('ACTION', 'CREATE',        '创建资源或记录'),
    ('ACTION', 'READ_LIST',     '列表读取'),
    ('ACTION', 'READ_DETAIL',   '详情读取'),
    ('ACTION', 'SEARCH',        '检索查询'),
    ('ACTION', 'COUNT',         '计数统计'),
    ('ACTION', 'UPDATE',        '整体更新'),
    ('ACTION', 'PATCH',         '部分更新'),
    ('ACTION', 'DELETE',        '删除资源或记录'),
    ('ACTION', 'BATCH_CREATE',  '批量创建'),
    ('ACTION', 'BATCH_UPDATE',  '批量更新'),
    ('ACTION', 'BATCH_DELETE',  '批量删除'),
    ('ACTION', 'REGISTER',      '注册'),
    ('ACTION', 'LOGIN',         '登录'),
    ('ACTION', 'LOGOUT',        '登出'),
    ('ACTION', 'TOKEN_ISSUE',   '令牌签发'),
    ('ACTION', 'TOKEN_REFRESH', '令牌刷新'),
    ('ACTION', 'TOKEN_REVOKE',  '令牌吊销'),
    ('ACTION', 'VERIFY',        '校验验证'),
    ('ACTION', 'SUBMIT',        '提交'),
    ('ACTION', 'APPROVE',       '审批通过'),
    ('ACTION', 'REJECT',        '审批驳回'),
    ('ACTION', 'WITHDRAW',      '撤回'),
    ('ACTION', 'ASSIGN',        '分派'),
    ('ACTION', 'TRANSFER',      '转移/转账'),
    ('ACTION', 'PUBLISH',       '发布'),
    ('ACTION', 'UNPUBLISH',     '下线/取消发布'),
    ('ACTION', 'ENABLE',        '启用'),
    ('ACTION', 'DISABLE',       '停用'),
    ('ACTION', 'LOCK',          '锁定'),
    ('ACTION', 'UNLOCK',        '解锁'),
    ('ACTION', 'IMPORT',        '导入'),
    ('ACTION', 'EXPORT',        '导出'),
    ('ACTION', 'UPLOAD',        '上传'),
    ('ACTION', 'DOWNLOAD',      '下载'),
    ('ACTION', 'PREVIEW',       '预览'),
    ('ACTION', 'SYNC',          '同步'),
    ('ACTION', 'CALLBACK',      '回调通知'),
    ('ACTION', 'START',         '启动'),
    ('ACTION', 'STOP',          '停止'),
    ('ACTION', 'RETRY',         '重试'),
    ('ACTION', 'BACKUP',        '备份'),
    ('ACTION', 'RESTORE',       '恢复'),
    ('ACTION', 'EXECUTE',       '执行'),
    ('ACTION', 'CUSTOM',        '自定义动作'),
    -- §34.1 业务领域 16 项内置种子（编码与 api_classifications 对齐）
    ('BUSINESS_DOMAIN', 'IDENTITY_AUTH',        '身份认证'),
    ('BUSINESS_DOMAIN', 'USER_ACCOUNT',         '用户账户'),
    ('BUSINESS_DOMAIN', 'ORG_PERMISSION',       '权限组织'),
    ('BUSINESS_DOMAIN', 'DATA_RESOURCE',        '通用数据资源'),
    ('BUSINESS_DOMAIN', 'PROCESS_APPROVAL',     '流程审批'),
    ('BUSINESS_DOMAIN', 'FILE_CONTENT',         '文件内容'),
    ('BUSINESS_DOMAIN', 'QUERY_ANALYTICS',      '查询分析'),
    ('BUSINESS_DOMAIN', 'IMPORT_EXPORT',        '导入导出'),
    ('BUSINESS_DOMAIN', 'TRANSACTION_FUND',     '交易资金'),
    ('BUSINESS_DOMAIN', 'MESSAGE_NOTIFICATION', '消息通知'),
    ('BUSINESS_DOMAIN', 'EXTERNAL_INTEGRATION', '外部集成'),
    ('BUSINESS_DOMAIN', 'SYSTEM_CONFIG',        '配置管理'),
    ('BUSINESS_DOMAIN', 'SYSTEM_OPS',           '系统运维'),
    ('BUSINESS_DOMAIN', 'DEVICE_IOT',           '设备物联网'),
    ('BUSINESS_DOMAIN', 'AI_INTELLIGENCE',      '人工智能'),
    ('BUSINESS_DOMAIN', 'PRIVACY_COMPLIANCE',   '隐私合规')
ON CONFLICT (dimension, value) DO NOTHING;

COMMIT;
