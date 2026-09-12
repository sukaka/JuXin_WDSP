-- 000071 API 文件合规规则 + 文件签名（W13-FSIG-COMP / P2-03 管理面 / P2-02 验证面）：
--   api_file_compliance_rules 表 + 初始建议种子 + 签名有效期设置种子。
--
-- 语义边界：
--   消费方为网关联动分片（下发键 api_file_compliance_rules）：按方向/匹配类型
--   对文件传输观测做合规判定（OBSERVE 仅记录 / BLOCK 阻断）；本分片只负责
--   管理面（表 + CRUD），下发链路与网关判定逻辑不在本迁移范围。
--
-- 列说明：
--   direction   UPLOAD=请求侧上传 / DOWNLOAD=响应侧下载（与 api_file_assets 同枚举）；
--   match_type  EXT=扩展名（规范化：小写、不含前导点，与 api_file_assets.extension 同口径）；
--               MIME=主类型小写（参数剥离，与资产 mime 同口径）；
--               FILENAME_REGEX=文件名正则（RE2 语法，管理面创建时即校验可编译）；
--   match_value 匹配值（按 match_type 各自的规范化形态落库）；
--   action      OBSERVE=命中仅记录 / BLOCK=命中阻断；
--   reason      规则事由（展示与审计用，可空）；
--   created_by  创建人用户 ID（留痕，无外键——与全库 created_by 纪律一致）。
--
-- 去重键（uq_api_file_compliance_rules_dedup）：
--   (direction, match_type, match_value) ——同方向同类型同匹配值的规则重复无意义；
--   种子与管理面创建均依赖该键做幂等/冲突判定。
BEGIN;

CREATE TABLE IF NOT EXISTS api_file_compliance_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    direction   VARCHAR(8)   NOT NULL,
    match_type  VARCHAR(16)  NOT NULL,
    match_value VARCHAR(256) NOT NULL,
    action      VARCHAR(8)   NOT NULL,
    reason      VARCHAR(256) NOT NULL DEFAULT '',
    enabled     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_by  UUID,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT chk_api_file_compliance_direction CHECK (direction IN ('UPLOAD','DOWNLOAD')),
    CONSTRAINT chk_api_file_compliance_match_type CHECK (match_type IN ('EXT','MIME','FILENAME_REGEX')),
    CONSTRAINT chk_api_file_compliance_action CHECK (action IN ('OBSERVE','BLOCK'))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_file_compliance_rules_dedup
    ON api_file_compliance_rules (direction, match_type, match_value);
-- 下发读取口径：启用规则按方向过滤
CREATE INDEX IF NOT EXISTS idx_api_file_compliance_rules_enabled
    ON api_file_compliance_rules (direction) WHERE enabled;

-- 初始建议种子（可按现场策略在管理面调整/停用；非强制基线）：
--   上传方向阻断常见可执行程序后缀（exe/bat/sh——webshell/恶意载荷投递面）；
--   下载方向对数据库备份/导出后缀（sql/bak）仅观察（批量外泄信号，先审计不阻断）。
INSERT INTO api_file_compliance_rules (direction, match_type, match_value, action, reason) VALUES
('UPLOAD',   'EXT', 'exe', 'BLOCK',   '初始建议：阻断可执行程序上传'),
('UPLOAD',   'EXT', 'bat', 'BLOCK',   '初始建议：阻断批处理脚本上传'),
('UPLOAD',   'EXT', 'sh',  'BLOCK',   '初始建议：阻断 shell 脚本上传'),
('DOWNLOAD', 'EXT', 'sql', 'OBSERVE', '初始建议：数据库导出文件下载观察'),
('DOWNLOAD', 'EXT', 'bak', 'OBSERVE', '初始建议：备份文件下载观察')
ON CONFLICT (direction, match_type, match_value) DO NOTHING;

-- 文件签名有效期（P2-02：签名时间戳超过该天数判过期；默认 30 天）。
-- 注意：本键当前未加入 settings.AllowedSettingKeys 白名单（settings.go 属其他分片范围），
-- 管理接口暂不可改，由集成方登记白名单后开放编辑（与 000061 同一纪律）。
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)
VALUES ('api_data', 'file_signature_max_age_days', '30', 'integer',
        '文件签名有效期（天）：验证时签名时间戳早于该天数判为过期')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
