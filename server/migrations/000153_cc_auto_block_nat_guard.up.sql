-- 000153 阶段5 §十五 共享出口（NAT）风险检查：cc_auto_block 组系统设置种子
--
--   CC 自动临时封禁落点（temporaryblocks.Store.UpsertFromEvent，采集器消费网关
--   CC_TEMP_BLOCK_CREATED 事件）在入库前评估共享出口风险：近 24h 同 IP 关联的
--   不同身份数（identity_ip_history，迁移 000097）达阈即疑似 NAT/代理出口，
--   降档为缩短封禁时长（避免误伤出口后大量用户），并写 CC_TEMP_BLOCK_DOWNGRADED
--   审计事件。保护地址/白名单已在网关请求链短路，不在此重复判定。
--
--   三键消费侧（temporaryblocks/natguard.go）均带默认值与区间校验，非法值回落默认；
--   接口修改白名单登记 settings.AllowedSettingKeys，整数区间登记 settingValueRanges。
BEGIN;

INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description) VALUES
('cc_auto_block', 'nat_guard_enabled',      'true', 'boolean', FALSE, 'CC自动封禁共享出口（NAT）风险检查开关：开启后命中疑似共享出口的自动封禁降档缩短时长'),
('cc_auto_block', 'nat_identity_threshold', '2',    'integer', FALSE, '共享出口判定阈值：近24h同IP关联不同身份数达到该值视为疑似NAT/代理出口（[2,1000]）'),
('cc_auto_block', 'nat_block_minutes',      '15',   'integer', FALSE, '命中共享出口风险时的降档封禁时长上限（分钟，[1,1440]；原时长更短则不延长）')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
