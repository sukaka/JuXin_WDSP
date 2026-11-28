-- 回滚 000257：移除新增 3 个内置官方预置源并恢复 000256 预置源基线（feodo / sslbl）。

DELETE FROM threat_intel_feeds
WHERE is_builtin = TRUE
  AND feed_key IN ('ipsum_l5', 'spamhaus_drop', 'et_compromised');

UPDATE threat_intel_feeds
SET description = '僵尸网络控制端（C2）推荐封禁 IPv4 列表（CC0 许可，默认关闭）',
    updated_at = now()
WHERE feed_key = 'feodo'
  AND is_builtin = TRUE;

UPDATE threat_intel_feeds
SET name = 'abuse.ch SSLBL 恶意 C2 IP 清单',
    description = '恶意 SSL 证书关联僵尸网络 C2 IPv4 列表（CC0 许可，默认关闭）',
    source_mode = 'OFFICIAL',
    official_preset = 'sslbl',
    updated_at = now()
WHERE feed_key = 'sslbl'
  AND is_builtin = TRUE;

INSERT INTO threat_intel_feeds (
    feed_key, name, description, is_builtin, enabled,
    source_mode, official_preset, format, ttl_days, schedule_cron
) VALUES (
    'sslbl',
    'abuse.ch SSLBL 恶意 C2 IP 清单',
    '恶意 SSL 证书关联僵尸网络 C2 IPv4 列表（CC0 许可，默认关闭）',
    TRUE, FALSE, 'OFFICIAL', 'sslbl', 'text', 30, '0 */6 * * *'
)
ON CONFLICT (feed_key) DO NOTHING;

COMMENT ON TABLE threat_intel_feeds IS
    '威胁情报 IP 黑名单多源订阅配置（支持预置 CC0 官方源、自定义内网/商业源及离线快照）';
