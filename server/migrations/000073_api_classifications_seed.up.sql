-- 000073 API 安全补全第十六波（W16-TABLES 残余空表生产方）配套 schema。
--
-- 背景：docs/API_SECURITY_CURRENT_STATE.md §5.2 余 4 张 TABLE_ONLY 表，本迁移补齐
-- 生产方所需的表结构/种子/注释（生产方代码见 apiauthz / apiassets 两包）：
--   1. api_object_models + first_seen/last_seen/sample_count：对象模型观测口径，
--      生产方 apiauthz.SweepObjectModelsOnce。first/last_seen 只随事件 occurred_at
--      移动（乱序不回头），last_seen 兼任 sweep 水位列；sample_count 每事件每段 +1。
--   2. api_classifications 内置业务领域分类法种子（任务书 §34.1 通用领域 16 项；
--      「企业自定义」走 api_custom_taxonomies，不在本表）。ON CONFLICT 重放幂等，
--      不覆盖既有行（人工可能已修订名称/描述）。
--   3. api_request_schemas 表注释：保留不用——请求 schema 以
--      api_model_versions.schema_json 内联为权威来源，本表零写入方，不再使用。
--   4. api_endpoint_path_segments 存量端点段形一次性回填（与 apiassets 生产方同口径：
--      去前导斜杠后 0 起段序号，{name} 占位段为变量段；增量由 UpsertDiscovery 首插 /
--      Split 派生写入，Merge 删除端点时随 ON DELETE CASCADE 清理）。
BEGIN;

-- ==================== 1. api_object_models 观测列 ====================
ALTER TABLE api_object_models
    ADD COLUMN IF NOT EXISTS first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS sample_count BIGINT      NOT NULL DEFAULT 0;
COMMENT ON COLUMN api_object_models.first_seen IS '首次观测时间（事件 occurred_at，乱序取小不回头）';
COMMENT ON COLUMN api_object_models.last_seen IS '末次观测时间（事件 occurred_at 取大；兼任 SweepObjectModelsOnce 水位列）';
COMMENT ON COLUMN api_object_models.sample_count IS '观测样本计数（SweepObjectModelsOnce upsert 每事件每段 +1）';

-- ==================== 2. api_classifications 内置业务领域种子 ====================
INSERT INTO api_classifications (code, name, description, is_builtin) VALUES
    ('IDENTITY_AUTH',         '身份认证',   '登录、登出、令牌签发/刷新、验证码、单点登录等认证会话接口', TRUE),
    ('USER_ACCOUNT',          '用户账户',   '用户资料、账户注册/注销、密码与密保管理等账户生命周期接口', TRUE),
    ('ORG_PERMISSION',        '组织权限',   '组织/部门/角色/权限点管理等授权体系接口', TRUE),
    ('DATA_RESOURCE',         '数据资源',   '业务数据对象的通用读写与资源管理接口', TRUE),
    ('PROCESS_APPROVAL',      '流程审批',   '审批流发起/处理/流转与工单类接口', TRUE),
    ('TRANSACTION_FUND',      '交易资金',   '支付、订单、账务、充值提现等资金交易接口', TRUE),
    ('FILE_CONTENT',          '文件内容',   '文件上传/下载/预览与内容管理接口', TRUE),
    ('QUERY_ANALYTICS',       '查询分析',   '检索、统计、报表、分析类只读接口', TRUE),
    ('IMPORT_EXPORT',         '导入导出',   '批量导入/导出、模板下载与任务查询接口', TRUE),
    ('MESSAGE_NOTIFICATION',  '消息通知',   '站内信、短信、邮件、推送与订阅接口', TRUE),
    ('EXTERNAL_INTEGRATION',  '外部集成',   'Webhook、回调、第三方开放平台对接接口', TRUE),
    ('SYSTEM_CONFIG',         '系统配置',   '参数设置、策略配置、字典与开关管理接口', TRUE),
    ('SYSTEM_OPS',            '系统运维',   '监控、日志、任务调度、备份恢复等运维接口', TRUE),
    ('DEVICE_IOT',            '设备物联网', '设备接入、设备影子、遥测与固件管理接口', TRUE),
    ('AI_INTELLIGENCE',       '人工智能',   '模型调用、智能分析、AI 辅助运营接口', TRUE),
    ('PRIVACY_COMPLIANCE',    '隐私合规',   '个人信息、授权记录、数据出境与合规审计接口', TRUE)
ON CONFLICT (code) DO NOTHING;

-- ==================== 3. api_request_schemas 保留注释 ====================
COMMENT ON TABLE api_request_schemas IS '保留：请求 schema 以 api_model_versions.schema_json 为权威来源，本表不再使用（零写入方，待后续版本评估清理）';

-- ==================== 4. api_endpoint_path_segments 存量回填 ====================
-- 位置口径：normalized_path 恒以 / 开头（前导空段 ord=1 跳过），段序号 0 起；
-- 根路径 / 无段；{name} 占位段为变量段（variable_name=name），其余为静态段。
INSERT INTO api_endpoint_path_segments (endpoint_id, position, literal_value, is_variable, variable_name)
SELECT e.id, s.ord - 2,
       CASE WHEN s.seg ~ '^\{[^}]+\}$' THEN '' ELSE left(s.seg, 255) END,
       s.seg ~ '^\{[^}]+\}$',
       CASE WHEN s.seg ~ '^\{[^}]+\}$' THEN left(substring(s.seg from 2 for char_length(s.seg) - 2), 128) ELSE '' END
FROM api_endpoints e
CROSS JOIN LATERAL unnest(string_to_array(e.normalized_path, '/')) WITH ORDINALITY AS s(seg, ord)
WHERE e.normalized_path LIKE '/%'
  AND e.normalized_path <> '/'
  AND s.ord > 1
ON CONFLICT (endpoint_id, position) DO NOTHING;

COMMIT;
