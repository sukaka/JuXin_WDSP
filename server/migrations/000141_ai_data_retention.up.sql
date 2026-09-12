-- 阶段7 §26.4：AI 数据保留期限配置种子（system_settings ai 组）。
-- 分表保留天数由 guardjanitor 的 AI 留存清理 sweep 每次执行时读取，调整即时生效。
-- 审计表（ai_audit_records）因哈希链完整性约束仅归档不物理删除，retention_audit_days 为归档期限口径。

BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('ai', 'retention_session_days',   '90',  'integer', FALSE, 'AI 会话保留天数（超期且未被审计引用的会话自动清理，消息/任务级联）'),
('ai', 'retention_tool_call_days', '90',  'integer', FALSE, 'AI Tool 调用记录保留天数（所属任务被审计引用的不清理）'),
('ai', 'retention_draft_days',     '90',  'integer', FALSE, 'AI 草稿保留天数（已采纳/待审核/被审计引用的草稿不清理）'),
('ai', 'retention_usage_days',     '180', 'integer', FALSE, 'AI 用量记录保留天数'),
('ai', 'retention_audit_days',     '365', 'integer', FALSE, 'AI 审计记录保留天数（哈希链约束，仅归档不物理删除）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
