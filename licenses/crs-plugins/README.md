# licenses/crs-plugins — OWASP CRS 官方插件许可证归档

本目录归档 coreruleset 官方插件的 Apache-2.0 许可证文本（LICENSE 取自
coreruleset 官方插件上游仓库；coreruleset 全部官方插件均以 Apache-2.0 发布，
版权头统一为 "Copyright (c) 2022-2026 CRS project. All rights reserved."，
已保留于各规则文件头部）。

## 覆盖组件与对应规则路径（PINNED 锁定版本见各 PINNED 文件）

| 插件 | 规则路径 | 锁定文件 |
|------|---------|---------|
| auto-decoding-plugin 1.0.0 | `gateway/rules/crs/plugins/auto-decoding-plugin/` | 同目录 `PINNED`（commit 6885a972；差异与评估见 JIUZHANG-NOTES.md：剔除 sqlHexDecode 两条规则与 10 行 CRS4 已删规则引用，默认禁用） |
| wordpress-rule-exclusions-plugin 1.2.0 | `gateway/rules/contrib/THIRD_PARTY/wordpress-rule-exclusions-*.conf` | `PINNED-wordpress-rule-exclusions.txt`（commit 5cdb1598） |
| nextcloud-rule-exclusions-plugin | `gateway/rules/contrib/THIRD_PARTY/nextcloud-rule-exclusions-*.conf` | `PINNED-nextcloud-rule-exclusions.txt`（commit 1b41369f） |
| phpmyadmin-rule-exclusions-plugin 1.1.0 | `gateway/rules/contrib/THIRD_PARTY/phpmyadmin-rule-exclusions-*.conf` | `PINNED-phpmyadmin-rule-exclusions.txt`（commit 2057b42d） |
| drupal-rule-exclusions-plugin 1.0.0 | `gateway/rules/contrib/THIRD_PARTY/drupal-rule-exclusions-*.conf` | `PINNED-drupal-rule-exclusions.txt`（commit 93700fdd） |
| dokuwiki-rule-exclusions-plugin 1.0.0 | `gateway/rules/contrib/THIRD_PARTY/dokuwiki-rule-exclusions-*.conf` | `PINNED-dokuwiki-rule-exclusions.txt`（commit 094c5c87） |
| xenforo-rule-exclusions-plugin 1.0.1 | `gateway/rules/contrib/THIRD_PARTY/xenforo-rule-exclusions-*.conf` | `PINNED-xenforo-rule-exclusions.txt`（commit a0ef4833） |

注：fake-bot-plugin 曾随本批评估投递，因其核心检测规则依赖 Coraza 不支持的
Lua rDNS 验证、剔除后插件失去检测能力，已于 2026-10-02 移除（以自建
`contrib/CUSTOM_PACK/fake-bot-claims.conf` 替代，见
docs/WAF_RULE_ENRICHMENT_DESIGN.md §3 P1 表注）。

设计依据：docs/WAF_RULE_ENRICHMENT_DESIGN.md §2（候选源与许可证裁决）。
