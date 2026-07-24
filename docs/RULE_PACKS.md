# 规则包体系（规则量扩展）

> 本文说明 WAF 规则库的多包结构、ID 分配、同步与发布链路、Paranoia Level 使用与 AI 规则生成闭环。

## 包结构与加载顺序

Caddy WAF 配置按以下固定顺序加载（`server/internal/gatewayconfig/generator.go`）：

```text
SecRuleEngine
Include coraza.conf
策略参数注入（blocking_paranoia_level / 阈值）
Include crs/crs-setup.conf
Include crs/plugins/*/plugins/*-config.conf     # CRS 官方插件（配置段）
Include crs/plugins/*/plugins/*-before.conf     # CRS 官方插件（前置规则）
Include exclusions/before-crs.conf + 运行时例外 + 规则覆盖
Include crs/rules/*.conf                        # OWASP CRS 主规则（当前 4.28.0，622 条入库）
Include contrib/*/*.conf                        # 第三方包 + 自建包
Include crs/plugins/*/plugins/*-after.conf      # CRS 官方插件（后置规则）
Include exclusions/after-crs.conf
Include jiuzhang/jiuzhang-custom.conf + 管理面自定义规则
```

| 包 | 位置 | rule_source | 内容 |
|---|---|---|---|
| OWASP CRS 主包 | `gateway/rules/crs/rules/` | `OWASP_CRS` | 4.28.0 全部 REQUEST/RESPONSE 规则 |
| CRS 官方插件 | `gateway/rules/crs/plugins/` | `CRS_PLUGIN` | incubator-plugin（PINNED commit）；antivirus（`@inspectFile`）与 body-decompress（`SecRuleScript` Lua）经实测 Coraza 不支持，已移除 |
| 第三方包 | `gateway/rules/contrib/THIRD_PARTY/` | `THIRD_PARTY` | coreruleset 应用白名单插件（wordpress/nextcloud，Apache-2.0，PINNED-* 记录来源与 commit）；Atomicorp 因许可证禁止再分发不入库 |
| 自建包 | `gateway/rules/contrib/CUSTOM_PACK/` | `CUSTOM_PACK` | cve-emergency（33）/ webshell（34）/ scanner-fingerprints（30）/ cloud-abuse（30）/ api-abuse（30），共 157 条 |

## ID 分配

| 段 | 用途 |
|---|---|
| 900000–999999 | OWASP CRS 与官方插件 |
| 1000000–1000099 | 自建 CVE 应急包 |
| 1000100–1000199 | 自建 WebShell 包 |
| 1000200–1000299 | 自建扫描器指纹包 |
| 1000300–1000399 | 自建云滥用包 |
| 1000400–1000499 | 自建 API 滥用包 |
| 7100000–7199999 | 管理面自定义规则（含 AI 草稿） |

## 同步与评分

- `POST /api/v1/waf-rules/sync` 一次性同步全部来源（OWASP_CRS / CRS_PLUGIN / THIRD_PARTY / CUSTOM_PACK），按 `(rule_id, rule_source, crs_version)` 去重；同步报告分 added/updated/unchanged/missing。
- 自建包评分与 CRS 一致：`block` + `setvar tx.inbound_anomaly_score` 与 `tx.inbound_anomaly_score_pl1`（949 阻断评估读取 PL 分段之和）；CRITICAL(5) 单条即达默认阈值阻断，WARNING/NOTICE 仅累积。扫描器指纹包只 `pass+log` 不计分（只标记不拦截）。
- 不兼容操作符红线：`@inspectFile`（外部程序）、`SecRuleScript`（Lua）、`@rbl`（离线 DNS）、`@pmFromFile` 引用包外数据文件，Coraza 加载即失败，禁止入库。

## Paranoia Level（PL）

- 策略 `paranoia_level` 已内置：宽松/标准 PL=1、严格 PL=2；经发布注入 `blocking_paranoia_level`。
- PL2 会启用 CRS 中更严格的变体规则（命中更多，误报也更多）。建议先在单应用绑定「严格策略」试点 1–2 周，用误报统计与 AI 降噪评估后再推广。

## AI 规则生成闭环

```text
安全事件 → AI 降噪指纹聚类（ai_noise_clusters）
        → 人工在降噪页点「生成草稿」
        → POST /api/v1/ai/noise/clusters/{id}/draft-rule（权限 ai.draft.custom_rule，写审计）
        → DISABLED 自定义规则 + ai_recommendations（DRAFT）
        → 人工在「自定义规则」页审核启用 → 配置发布到网关
```

AI 只产出草稿（RiskDraftOnly），不自动启用、不自动发布；草稿规则操作符走自定义规则白名单（无 `@` 前缀），默认 OBSERVE 动作。

---

Copyright © 聚信得仁
All Rights Reserved.
