-- 000257 替换已停用的 abuse.ch SSLBL 威胁情报预置源，新增 3 个高体量宽松许可活跃官方预置源：
--   - ipsum_l5       : IPsum 高置信恶意 IP 清单 (Level 5, Unlicense)
--   - spamhaus_drop  : Spamhaus DROP 恶意网段清单 (CIDR /16–/32, Spamhaus DROP Free/Permissive)
--   - et_compromised : Emerging Threats 失陷攻击主机清单 (BSD-3-Clause)
--   - feodo          : 保留 abuse.ch Feodo C2 IP 清单并更新说明（聚焦少量活跃 C2 节点）
-- 所有新增预置源默认 enabled = FALSE，保持纯离线环境零外连基线。

COMMENT ON TABLE threat_intel_feeds IS
    '威胁情报 IP 黑名单多源订阅配置（支持预置宽松许可活跃官方源、自定义内网/商业源及离线快照）';

-- 1. 清理无在册规则的已弃用 sslbl 内置源（上游 abuse.ch SSLBL 已于 2025-01-03 停止维护）
DELETE FROM threat_intel_feeds
WHERE feed_key = 'sslbl'
  AND is_builtin = TRUE
  AND active_rule_count = 0;

-- 若存量环境 sslbl 仍有在册生效规则，不强制删除，改为停用、切为纯离线并标注已弃用
UPDATE threat_intel_feeds
SET enabled = FALSE,
    source_mode = 'OFFLINE_ONLY',
    official_preset = '',
    name = 'abuse.ch SSLBL 恶意 C2 IP 清单（上游已停用）',
    description = '上游 abuse.ch SSLBL 已于 2025-01-03 停止维护，已自动停用并转为纯离线保留历史在册规则',
    updated_at = now()
WHERE feed_key = 'sslbl'
  AND is_builtin = TRUE
  AND active_rule_count > 0;

-- 2. 更新 feodo 内置源说明，明确其仅覆盖少量活跃僵尸网络 C2 节点（通常 1–50 条）
UPDATE threat_intel_feeds
SET description = 'abuse.ch 活跃僵尸网络控制端（C2）精选 IPv4 列表，聚焦高危活跃 C2 节点（通常 1–50 条，CC0-1.0 许可，默认关闭）',
    updated_at = now()
WHERE feed_key = 'feodo'
  AND is_builtin = TRUE;

-- 3. 预置 3 个活跃维护、宽松许可的高体量官方情报源（全部默认关闭，确保离线安全）
INSERT INTO threat_intel_feeds (
    feed_key, name, description, is_builtin, enabled,
    source_mode, official_preset, format, allow_cidr, ttl_days, schedule_cron
) VALUES
(
    'ipsum_l5',
    'IPsum 高置信恶意 IP 清单 (Level 5)',
    '每日更新的高置信恶意 IPv4 清单，收录同时被至少 5 个公开黑名单标记的攻击源（约 3,000+ 条，Unlicense 许可，默认关闭）',
    TRUE, FALSE, 'OFFICIAL', 'ipsum_l5', 'text', FALSE, 7, '0 4 * * *'
),
(
    'spamhaus_drop',
    'Spamhaus DROP 恶意网段清单',
    'Spamhaus 劫持与僵尸网络恶意网段清单（启用 CIDR 仅导入 /16–/32 公网网段，/11–/15 宽网段自动拒绝，约 1,700+ 条，默认关闭）',
    TRUE, FALSE, 'OFFICIAL', 'spamhaus_drop', 'text', TRUE, 30, '0 */12 * * *'
),
(
    'et_compromised',
    'Emerging Threats 失陷攻击主机清单',
    'Emerging Threats 活跃失陷攻击主机 IPv4 列表（约 500+ 条，BSD-3-Clause 许可，默认关闭）',
    TRUE, FALSE, 'OFFICIAL', 'et_compromised', 'text', FALSE, 14, '0 */6 * * *'
)
ON CONFLICT (feed_key) DO NOTHING;
