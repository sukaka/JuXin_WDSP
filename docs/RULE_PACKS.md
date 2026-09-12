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
Include jiuzhang/post-contrib-blocking.conf    # 二次阻断评估（必须最后加载）
```

| 包 | 位置 | rule_source | 内容 |
|---|---|---|---|
| OWASP CRS 主包 | `gateway/rules/crs/rules/` | `OWASP_CRS` | 4.28.0 全部 REQUEST/RESPONSE 规则 |
| CRS 官方插件 | `gateway/rules/crs/plugins/` | `CRS_PLUGIN` | incubator-plugin（PINNED commit）；antivirus（`@inspectFile`）与 body-decompress（`SecRuleScript` Lua）经实测 Coraza 不支持，已移除 |
| 第三方包 | `gateway/rules/contrib/THIRD_PARTY/` | `THIRD_PARTY` | coreruleset 应用白名单插件（wordpress/nextcloud，Apache-2.0，PINNED-* 记录来源与 commit）；Atomicorp 因许可证禁止再分发不入库 |
| 自建包 | `gateway/rules/contrib/CUSTOM_PACK/` | `CUSTOM_PACK` | 见下表，共 **744** 条（+ 原 CRS 主包） |

自建包明细：

| 文件 | 条数 | 内容 |
|---|---|---|
| cve-emergency | 42 | Log4j/Spring/Confluence/ProxyShell/Struts S2 系列等应急 CVE |
| webshell | 34 | 一句话/冰蝎蚁剑哥斯拉基础特征 |
| scanner-fingerprints | 30 | 扫描器 UA/payload 指纹 |
| cloud-abuse | 30 | 云元数据 SSRF / k8s / docker |
| api-abuse | 30 | GraphQL/JWT/API 滥用 |
| sensitive-exposure | 40 | .git/.env/备份/Actuator 等敏感路径 |
| deserialization-rce | 48 | 反序列化 / SSTI / LOLBins |
| bot-protocol | 35 | 协议滥用 / 上传可执行体 |
| cve-recent | 35 | Tomcat/JBoss/Jenkins/Nacos 等 |
| oss-webapps-cve | 50 | 开源 CMS/OA/框架（CNNVD/CVE 公开利用面） |
| webshell-obfuscation | 39 | 加密/混淆/变种 WebShell |
| attack-coverage | 51 | SSTI 引擎级特征 / JWT kid·jku 头注入 / SSRF 变形 / NoSQL·LDAP 注入 / 补充应急 CVE |
| **attack-variants-evasion** | **99** | **攻击变种/编码绕过增强：双编码·全角·注释拆分·盲注变形·XSS/SVG·命令注入·LFI/RFI·Log4j/Struts 深绕过·XXE/SSRF·CRLF 走私·上传/WebShell 变种·JWT/GraphQL** |
| **webshell-uploads** | **26** | **WebShell 上传通道专项：asp/aspx/war/jar 等可执行扩展名、X-Filename 头双扩展名、%00 截断、图片马/压缩包投递、multipart 解析反规避** |
| **webshell-content** | **30** | **WebShell 文件内容特征：JSP/Java、ASP/VBScript、ASPX/ASHX、CFM、PERL/CGI、Python、SH 及跨语言一句话** |
| **ssrf-protocols** | **23** | **SSRF 专项：jar/netdoc/CORBA 伪协议补充、file://主机形态、协议相对 URL、十进制/十六进制/混合进制 IP 混淆、CJK 句号分隔、内网短格式、元数据合并写法、IPv6 回环/ULA/链路本地、127/8 全网段、命名 URL 参数内网目标、敏感服务端口、短链/嵌套跳转/凭据混淆** |
| **xxe-lfi-variants** | **29** | **XXE 变种（参数实体引用/启发式/SVG·SOAP·CDATA 包裹/双重编码/ARGS 目标）与 LFI·目录穿越变种（PHP 伪协议/编码变体/敏感文件目标/空字节截断）** |
| **injection-variants** | **33** | **SQLi/命令注入/XSS 绕过变种：版本注释/等价函数/盲注变形、IFS·环境变量切片·大括号扩展·八进制编码、模板标签/事件处理器/GBK 宽字节/DOM sink** |
| **ssti-injection** | **16** | **SSTI 专项：Freemarker ?api/方括号语法、Velocity ClassTool/动态指令、Thymeleaf·SpEL 预处理变体、Jinja2 无定界符 dunder 链、Twig 字符串回调过滤器、ERB/Mako/Groovy/EL 补充、探针形态补充** |
| **unauth-access** | **24** | **组件未授权管理面/中间件未授权访问/拖库特征（全部 OBSERVE 级叠加计分，不单条阻断）** |

## ID 分配

| 段 | 用途 |
|---|---|
| 900000–999999 | OWASP CRS 与官方插件 |
| 1000000–1000099 | 自建 CVE 应急包 |
| 1000100–1000199 | 自建 WebShell 包 |
| 1000200–1000299 | 自建扫描器指纹包 |
| 1000300–1000399 | 自建云滥用包 |
| 1000400–1000499 | 自建 API 滥用包 |
| 1000500–1000599 | 自建敏感路径/信息暴露包 |
| 1000600–1000699 | 自建反序列化与跨语言 RCE 包 |
| 1000700–1000799 | 自建协议滥用/Bot/上传包 |
| 1000800–1000899 | 自建近年 CVE/组件利用补充包 |
| 1000900–1000999 | 自建开源 Web 系统 CNNVD/CVE 利用包 |
| 1001000–1001099 | 自建加密/混淆 WebShell 包 |
| 1001100–1001199 | 自建攻击覆盖面扩充包（SSTI/JWT/SSRF 变形/NoSQL/LDAP/补充 CVE） |
| 1001200–1001299 | 自建攻击变种/编码绕过增强包（evasion/polyglot） |
| 1001300–1001399 | 自建 WebShell 上传通道检测包（webshell-uploads） |
| 1001400–1001499 | 自建 WebShell 文件内容特征包（webshell-content） |
| 1001500–1001599 | 自建 SSRF 专项包（ssrf-protocols） |
| 1001600–1001699 | 自建 XXE 与文件包含/目录穿越变种包（xxe-lfi-variants） |
| 1001700–1001799 | 自建注入绕过变种增强包（injection-variants） |
| 1001800–1001899 | 自建 SSTI 服务端模板注入专项包（ssti-injection） |
| 1001900–1001999 | 自建未授权访问/信息泄露/拖库检测包（unauth-access） |
| 9000101–9000104 | 九章二次阻断评估（post-contrib-blocking.conf） |
| 7100000–7199999 | 管理面自定义规则（含 AI 草稿） |

## 同步与评分

- `POST /api/v1/waf-rules/sync` 一次性同步全部来源（OWASP_CRS / CRS_PLUGIN / THIRD_PARTY / CUSTOM_PACK），按 `(rule_id, rule_source, crs_version)` 去重；同步报告分 added/updated/unchanged/missing。
- 自建包评分与 CRS 一致：`block` + `setvar tx.inbound_anomaly_score` 与 `tx.inbound_anomaly_score_pl1`（949 阻断评估读取 PL 分段之和）；CRITICAL(5) 单条即达默认阈值阻断，WARNING/NOTICE 仅累积。扫描器指纹包只 `pass+log` 不计分（只标记不拦截）。
- 不兼容操作符红线：`@inspectFile`（外部程序）、`SecRuleScript`（Lua）、`@rbl`（离线 DNS）、`@pmFromFile` 引用包外数据文件，Coraza 加载即失败，禁止入库。

## 二次阻断评估（post-contrib-blocking.conf）

- 问题：CRS 阻断评估 `REQUEST-949` 位于 `crs/rules/` 内部，晚于它加载的规则（contrib 包、插件 after、after-crs、管理面自定义规则）命中后只累加异常分数，不会再次进入阈值评估——若无二次评估，CUSTOM_PACK 的 CRITICAL 命中在 PROTECT 模式下也只出事件不阻断。
- 修复：`gateway/rules/jiuzhang/post-contrib-blocking.conf` 在全部计分规则之后重新汇总 `tx.inbound_anomaly_score_pl1..pl4` 到独立变量 `tx.jz_blocking_inbound_score`（phase:1/phase:2 各一组，ID 9000101-9000104），达到 `tx.inbound_anomaly_score_threshold` 即 `deny,status:403`；不改动 CRS 任何文件。DetectionOnly（观察模式）下引擎自动把 deny 降级为仅记录。
- 加载位置约束：该文件必须是 WAF 指令链中**最后一条 Include**（生成器 `buildWAFDirectivesWithPolicy` 与静态 `gateway/configs/Caddyfile` 均已固定）；任何新增计分规则包都必须早于它加载，否则其命中仍然无法阻断。

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
