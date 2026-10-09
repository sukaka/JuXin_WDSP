# 九章 WAF 规则体系增强设计（开源防护策略引入）

> 状态：设计基线 v1（2026-10-02）
> 范围：在不改动引擎的前提下，系统性引入许可证合规的开源防护策略，扩充 `gateway/rules/` 的检测与治理覆盖面。
> 红线：不复制雷池或任何商业 WAF 的规则/文案（AGENTS.md 禁止事项）；仅引入 Apache-2.0 / MIT / BSD / CC0 源。

## 1. 现状基线

加载链（server/internal/gatewayconfig/generator.go:492-565，发布配置唯一出口）：

```
coraza.conf → 审计覆盖 → PL/阈值参数 → crs-setup.conf
→ plugins *-config → plugins *-before          （CRS 插件，glob: crs/plugins/*/plugins/*-{config,before,after}.conf）
→ exclusions/before-crs → 运行时例外 → 规则覆盖(DISABLE)
→ CRS 主规则（crs/rules/*.conf，4.28.0）
→ contrib/*/*.conf                              （CUSTOM_PACK 19 包 + THIRD_PARTY 2 包，自动收录）
→ plugins *-after → exclusions/after-crs → jiuzhang-custom → 管理面自定义规则
→ post-contrib-blocking（二次阻断评估，恒为最后）
```

已有资产：

- **CRS 4.28.0**（含 crs-setup、plugins 占位、incubator-plugin）；
- **CUSTOM_PACK 19 个自建包**（ID 段 1000001–1001924）：cve-recent/cve-emergency/oss-webapps-cve、webshell 四件套、injection-variants、ssrf-protocols、ssti、xxe-lfi、scanner-fingerprints、sensitive-exposure、unauth-access、api-abuse、bot-protocol、cloud-abuse、deserialization-rce、attack-coverage、attack-variants-evasion；
- **THIRD_PARTY 2 个 CRS 排除插件**（wordpress/nextcloud，含 PINNED 锁定文件）；
- **管理面规则同步**：wafrules/sync.go 把规则文件元数据解析入 `waf_rules` 表（rule_source 分类），前台按条启停/查状态——新增包自动进入该管理面，无需改代码。

**结论：引入新策略 = 往两个自动收录点投递锁定文件（`crs/plugins/<name>/plugins/` 或 `contrib/*/`），机制零改动。** 增强工作的核心变为：选源、许可证审查、PINNED 锁定、误报与性能治理、生命周期对接。

## 2. 候选源与许可证裁决

| # | 源 | 内容 | 许可证 | 裁决 |
|---|----|------|--------|------|
| A1 | coreruleset/fake-bot-plugin | 识别伪装成知名爬虫（Googlebot 等）的请求 | Apache-2.0 | ~~引入（P1）~~ **移除**：核心检测链依赖 Coraza 不支持的 Lua rDNS，剔除后插件只剩停用开关与孤儿白名单、无检测能力（2026-10-02 评估后移除，以自建 fake-bot-claims.conf 替代） |
| A2 | coreruleset/{phpmyadmin,drupal,dokuwiki,xenforo,phpbb,cpanel}-rule-exclusions-plugin | 应用专属误报排除 | Apache-2.0 | **引入（P1，前 4 个）** |
| A3 | coreruleset/auto-decoding-plugin | 多轮解码抗混淆逃逸 | Apache-2.0 | **已投递（P2 评估完成 2026-10-02）**：剔除 Coraza 不支持的 sqlHexDecode 两条规则与 10 行 CRS4 已删规则引用，**默认禁用**；stage5 实测编码 RCE/双重编码 SQLi 可检出（禁用态漏检）、零误报、PL1 单轮解码 +26% p50 |
| A4 | coreruleset/body-decompress-plugin | 解压 gzip/deflate 请求体再检测 | Apache-2.0 | **放弃（2026-10-02）**：核心解压逻辑经 `SecRuleScript body-decompress.lua` 实现，Coraza 不支持 Lua，无静态替代 |
| B1 | monperrus/crawler-user-agents | ~300+ 爬虫 UA 正则（JSON，持续更新） | MIT | **引入（P1，生成器化）** |
| C1 | abuse.ch Feodo Tracker | 僵尸网络 C2 IP blocklist | CC0（可商用） | 引入（P2，情报导入功能） |
| D1 | NVD API | 近期高分 Web CVE 元数据 | 公共领域 | 引入（P2，CVE 规则生成器） |
| E1 | ai-robots-txt/ai.robots.txt | AI 爬虫 UA 清单 | MIT | **引入（P1，OBSERVE 默认）** |
| F1 | Snort/Suricata ET Open | 网络层攻击规则 | 许可不确定（历史 GPL 争议）+ 语法转换有损 | **放弃** |
| F2 | 雷池 SafeLine 规则 | — | 项目红线（AGENTS.md） | **禁止** |
| F3 | 各类博客/GitHub 零散 webshell/YARA 签名 | — | 多无明确许可 | 放弃（继续自建 webshell-* 演进） |
| F4 | coreruleset/antivirus-plugin | ClamAV 联动 | Apache-2.0 | 缓议（依赖 ClamAV daemon，交付复杂，P3 评估） |

许可证据：CRS 插件（[plugin-registry 标明 Apache-2.0](https://github.com/coreruleset/plugin-registry)）；crawler-user-agents（[MIT LICENSE](https://github.com/monperrus/crawler-user-agents/blob/master/LICENSE)）；Feodo（[官方 blocklist 页声明 CC0 可商用](https://feodotracker.abuse.ch/blocklist/)）；ai.robots.txt（[MIT LICENSE](https://github.com/ai-robots-txt/ai.robots.txt/raw/main/LICENSE)）。
合规动作：全部引入源在 `licenses/` 增补 NOTICE 文本；Apache-2.0 作品保留版权头与许可证副本；文件头注明上游出处与版本（PINNED）。

## 3. 分期实施路线

### P1（本批，低风险纯增量，不加代码）

| 项 | 方式 | 默认状态 |
|----|------|----------|
| fake-bot-plugin → **自建 fake-bot-claims.conf**（13 条，ID 1010201-1010213，替代说明见表注¹） | `contrib/CUSTOM_PACK/fake-bot-claims.conf` | **检测不阻断**（新检测类一律先 OBSERVE 轨道） |
| phpmyadmin / drupal / dokuwiki / xenforo 排除插件 | `contrib/THIRD_PARTY/` 投递 + PINNED（与 wordpress/nextcloud 同模式） | 启用（排除类只减误报） |
| 爬虫 UA 指纹扩充 | `tools/` 新增生成器：crawler-user-agents.json → `contrib/CUSTOM_PACK/scanner-fingerprints-ext.conf`（SecLang，@pmFromFile 或单规则集），PINNED 上游 commit | 检测不阻断 |
| AI 爬虫防护包 | ai.robots.txt 清单 → `contrib/CUSTOM_PACK/ai-crawler-control.conf`（默认 OBSERVE；前台可选启用） | 检测不阻断 |

¹ **fake-bot-plugin 移除说明（2026-10-02）**：该插件唯一检测规则（9504120）以「UA 命中 + `@inspectFile fake-bot.lua` rDNS 复检」链式判定假冒，而 Coraza 不支持 Lua/SecRuleScript；只保留 UA 单条件会把真实 Googlebot/Bingbot 全部误判为假冒且 block+CRITICAL，不可接受。剔除后插件只剩停用开关与孤儿白名单，无检测能力，故整体移除，以自建 `fake-bot-claims.conf`（OBSERVE 只标记「UA 声称是主流搜索引擎爬虫」，供运营交叉分析）替代。真假鉴别本质依赖 rDNS，列入 P2+ 离线情报路径评估，不得在热路径引入 Lua 或网络 IO。

验收：go-ftw 回归全绿；wafrules 同步后 `waf_rules` 出现新 rule_source 行；licenses/ NOTICE 齐备；发布配置 caddy validate 通过。

### P2（功能型，含少量 server 代码）

- **C1 情报导入**：abuse.ch Feodo（CC0）→「系统设置 → 威胁情报」：支持手动上传快照与（有网环境）定时拉取，写入 IP 黑名单（带 `source=feodo`、导入时间、有效期）；离线交付时厂家可在升级包内附带当期快照。注意：abuse.ch 数据授权正向 Spamhaus 迁移（[官方公告](https://abuse.ch/)），CC0 快照可用性需持续跟踪。 **已完成（2026-10-02，本期为手动导入+对账）**：`server/internal/threatintel/` + `POST /api/v1/threat-intel/import`（权限 `access_rules.import`、CSRF/审计同 accessrules 写接口）。解析支持纯文本 IP 清单与 Feodo CSV（实测表头 `first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware`，按表头自适应取 IP 与 family 列，坏行跳过计数、明细前 50、上限 5000 条、仅 IPv4、可剥端口）；与历史导入集合（`source_type=IMPORT` 且 reason 前缀「威胁情报 <feed> 批次」的 GLOBAL DENY 行）集合对账——新 IP 建 ACTIVE 规则（TTL 默认 30 天、0=PERMANENT）、在册刷新有效期与批次、本批消失标 EXPIRED 保留历史；绝不触碰 MANUAL/SECURITY_EVENT/AUTO_BLOCK/SYSTEM 及其他前缀 IMPORT 行，同址人工黑名单冲突跳过；生效集变化触发网关配置发布；导入即 ACTIVE（区别于通用导入的 DRAFT 口径——情报源预先可信，经权限+审计+批次追溯控制）。**留作后续**：有网环境定时拉取与「系统设置 → 威胁情报」设置页 UI。
- **D1 CVE 规则生成器**：~~`tools/` 从 NVD API 拉近 N 天高分 Web CVE~~ **已实现为「策展队列生成器」`tools/rulegen/cve-draft`（2026-10-02）**：拉取 NVD API 2.0（公共领域）近 N 天披露 → CVSS/CWE/关键词三维过滤 → 与 `gateway/rules` 现有 CVE 覆盖去重 → 产出按分排序的评审队列 Markdown（`output/cve-review/cve-queue-<date>.md`），每条附符合 CUSTOM_PACK 约定的规则草稿骨架（TODO(analyst) 标记 + cve-recent 段顺延建议 ID）。**诚实边界**：NVD 元数据不含 payload 级攻击特征，机器不生成检测规则；规则本体由分析师依据公开 PoC 填写后经双轨生命周期（DRAFT → OBSERVE → TP/FP → 审批 → BLOCK）合入，AI/工具产物不得直接进生产阻断。
- **A3/A4 主动解码类插件**：~~性能评估~~ **已完成（2026-10-02）**：A3 auto-decoding 已投递 `crs/plugins/auto-decoding-plugin/`（默认禁用，差异与评估数据见 JIUZHANG-NOTES.md），按站启用前先 OBSERVE；A4 body-decompress 因核心逻辑依赖 Lua 放弃。

### P3（评估项）

- ~~antivirus-plugin（ClamAV 联动）~~ **评估完成（2026-10-02），结论：不引入**——① ClamAV 引擎为 **GPL-2.0**，触碰项目「未经书面批准不得引入 GPL/AGPL 组件」红线；② 病毒库依赖 freshclam 日更，与离线交付天然矛盾（签名到手即过期）；③ 每个上传文件经外部程序 + clamd INSTREAM 扫描，热路径成本与 10s 超时不适合全量流量，仅适合上传点。**附带发现（已实测）**：Coraza v3.7.0 原生实现 `@inspectFile`（执行外部程序、10s 超时、输出首字节 '1' 判命中，见 coraza operators/inspect_file.go），为将来「上传内容扫描」能力预留了合规路径——可自研扫描客户端对接 BSD 许可的 YARA 引擎与许可证干净的签名集；属新功能线，不在本期规则增强范围。
- AI 爬虫行为分析增强（与身份行为观测联动）：已有 ai-crawler-control.conf（180 条 UA 标记）提供入口信号，行为侧增强列入身份行为模块演进，不在本期范围。
- 更多应用排除插件（cpanel/phpbb 等）：机制已就绪（`contrib/THIRD_PARTY/` + PINNED 同模式），按客户实际应用画像按需补充，不盲目堆量。

---

## 6. 三期路线执行总结（2026-10-02 全部完成）

| 期 | 项 | 结果 |
|----|----|------|
| P1 | 4 个应用排除插件（phpmyadmin/drupal/dokuwiki/xenforo） | 已投递启用（143 条，只减误报） |
| P1 | 爬虫 UA 指纹扩展（monperrus，MIT） | 已投递（1501 条 OBSERVE，生成器化） |
| P1 | AI 爬虫管控（ai.robots.txt，MIT） | 已投递（180 条 OBSERVE，生成器化） |
| P1 | 搜索引擎爬虫 UA 声称标记（自建 fake-bot-claims） | 已投递（13 条 OBSERVE；fake-bot-plugin 因 Lua rDNS 依赖移除后以此替代） |
| P2 | auto-decoding-plugin（Apache-2.0） | 修适后投递**默认禁用**（剔除 sqlHexDecode 与 10 行失效引用；stage5 实测编码 RCE/双编码 SQLi 可检出、+26% p50） |
| P2 | body-decompress-plugin | 放弃（核心解压依赖 Lua） |
| P2 | Feodo C2 威胁情报导入（CC0） | 已实现（手动导入+集合对账+自动发布，stage5 全链路实测通过；定时拉取与 UI 留作后续） |
| P2 | NVD 策展队列生成器（公共领域） | 已实现（实跑产出 50 条评审队列；机器不生成规则，分析师经双轨合入） |
| P3 | antivirus-plugin（ClamAV） | 放弃（GPL 红线 + 离线签名过期 + daemon 交付复杂；`@inspectFile` 外部程序机制实测可用，留作自研上传扫描的合规路径） |

共新增/扩展：规则 1839 条（143 排除 + 1501 爬虫 + 180 AI 爬虫 + 13 声称标记 + 2 静态 fake-bot 清理）、投递插件 1 个（默认禁用）、服务端能力 2 项（情报导入、策展生成器）、生成器 3 个（crawler-ua / ai-crawler / cve-draft）、放弃并记录 4 个不兼容/不合规源（fake-bot、body-decompress、ET Open、ClamAV）。

## 4. 工程约束（每批必查）

1. **规则 ID 冲突**：CRS 官方插件占用 9,5xx,xxx 段（registry 分配）；CUSTOM_PACK 现行 1,001,xxx 段；新增自建规则继续顺延 1,002,xxx 起，投递前 `grep -rhoE 'id:[0-9]+' | sort -u` 全库查重。
2. **生命周期**：新检测类规则/插件一律默认「检测不阻断」（OBSERVE 轨道），排除类可直接启用；EMERGENCY 轨道仅用于在野利用确认（双轨决议，见 rules lifecycle 设计）。
3. **性能**：规则总量增长控制在回归阈值内（go-ftw 时长 + test/performance 基线）；单文件规则数 >500 时优先 @pmFromFile 而非逐条 SecRule。
4. **确定性交付**：上游一律 PINNED（URL + commit + sha256），构建期校验；禁止构建时在线拉取未锁定内容。
5. **同步入管理面**：新包投递后跑 wafrules 同步用例（server/internal/wafrules），确认元数据（severity/phase/tags/attack_type/default_state）解析正确，前台可按条管理。

## 5. P1 执行清单（下一步）

1. ~~下载并锁定：fake-bot-plugin（最新 release commit）；phpmyadmin/drupal/dokuwiki/xenforo 排除插件（各自 PINNED）；crawler-user-agents.json（commit + sha256）；ai.robots.txt（commit + sha256）。~~ **完成（2026-10-02）**：phpmyadmin@2057b42d / drupal@93700fdd / dokuwiki@094c5c87 / xenforo@a0ef4833；crawler-user-agents@9345a7ad；ai.robots.txt@987266f3，PINNED 文件均已就位。（fake-bot-plugin@65caf0d4 曾锁定投递，同日评估移除，见 §3 表注¹。）
2. ~~按第 3 节 P1 表投递到 `gateway/rules/`，补 `licenses/` NOTICE。~~ **完成（2026-10-02）**：4 排除插件投递至 `contrib/THIRD_PARTY/`；fake-bot-plugin 移除，以自建 `contrib/CUSTOM_PACK/fake-bot-claims.conf`（13 条，ID 1010201-1010213）替代；NOTICE 归档 `licenses/{crs-plugins,crawler-user-agents,ai-robots-txt}/` 并登记 DEPENDENCY_LICENSES.md / THIRD_PARTY_NOTICES.md。
3. ~~写生成器 `tools/rulegen/crawler-ua/main.go`（输入 JSON、输出 SecLang，确定性输出 + 头部 attribution）。~~ **完成（2026-10-02）**：并同步交付 `tools/rulegen/ai-crawler/main.go`；确定性已验证（连跑两次字节一致）。注：任务建议的 1000300/1000400/1000500 ID 段经全库查重已被 cloud-abuse/api-abuse/sensitive-exposure 占用，依 §4.1 顺延重分配为 crawler-ua 1002001-1003501、ai-crawler 1010001-1010180。
4. ~~跑：规则 ID 查重、wafrules 同步测试、go-ftw 回归、stage5 发布冒烟。~~ **完成（2026-10-02）**：ID 查重（加载链口径无重复）、wafrules 同步测试全绿（CUSTOM_PACK 2425 条/22 文件）、全量规则 caddy validate 通过（dist 裸机 caddy，linux/amd64 alpine 容器）。**stage5 冒烟通过**：shop.example.com 实探针命中——sqlmap UA 命中 1000201+ext、GPTBot 命中 ext+1010062、Googlebot 命中 ext 1002441+1010201、curl 命中 ext (^curl)、浏览器 UA 零误报，全部 OBSERVE 不阻断；`custom-pack-blocking-tests.sh` 13/13 通过。`stage5-gateway-tests.sh` 37/40，3 个失败（forge-xff-ignored / cc-forge-rotation / deny-conn-ip-forge-bypass）经规则移除对照实验证实为**预存问题**（疑似 9-29 真实 IP 改造的工作区改动或应用配置漂移所致，与规则无关，另行排查）。go-ftw 全量套件未单跑（ftw.yaml 指向 stage1；其 CUSTOM_PACK 行为覆盖面与上述集成套件重叠，列为可选补充）。
5. ~~CHANGELOG 与本文档状态更新。~~ **完成（2026-10-02）**。
