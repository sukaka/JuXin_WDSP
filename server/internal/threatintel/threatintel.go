// Package threatintel 提供威胁情报导入（WDSP P2-C1，设计依据
// docs/WAF_RULE_ENRICHMENT_DESIGN.md §3 P2-C1）：Feodo 等 C2 情报快照
// （纯文本 IP 清单 / Feodo CSV）解析为 IPv4 集合，与本功能历史导入集合
// （ip_access_rules 中 source_type=IMPORT、reason 以统一前缀「威胁情报 <feed>」
// 开头的 GLOBAL DENY 行）做集合对账——新增 ACTIVE 规则、在册刷新有效期与批次、
// 本批次消失者标记 EXPIRED（保留历史）；绝不触碰 MANUAL/SECURITY_EVENT/
// AUTO_BLOCK/SYSTEM 来源及其他 reason 前缀的规则。表结构见
// server/migrations/000008_stage5.up.sql 的 ip_access_rules。
package threatintel
