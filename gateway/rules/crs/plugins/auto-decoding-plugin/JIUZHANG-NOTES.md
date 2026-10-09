# JIUZHANG-NOTES — auto-decoding-plugin 投递说明（2026-10-02）

上游：<https://github.com/coreruleset/auto-decoding-plugin> @ `6885a9728d3f657f0a5814fbd7349e71b186a64f`（插件版本 1.0.0，Apache-2.0，PINNED 见同目录）。

## 与上游的差异（均经 caddy validate 实测定位）

1. **before.conf 移除规则 9501260 / 9501560（t:sqlHexDecode）**：Coraza v3.7.0 未实现
   `sqlHexDecode` 变换，保留则整个 WAF 配置加载失败（`invalid transformation name`）。
   该变换仅解码 MySQL hex 字面量（0xNN），属 21 个变换中的小众项；其余 20 个变换
   （base64DecodeExt、cmdLine、cssDecode、hexDecode、htmlEntityDecode、jsDecode、
   normalizePath(Win)、urlDecode(Uni)、utf8toUnicode 等）全部可用并保留。
2. **after.conf 移除 10 行 SecRuleUpdateTargetById**：引用了 CRS 4.x 已删除/重编号的
   规则（913120、932100/101/105/106/110/115/150、942110；932106 原有两行），Coraza
   对不存在规则引用硬校验报 not found。其余 125 条引用在 CRS 4.28 中均存在，原样保留。
   （这 10 行本用于把 tf_ 辅助变量从对应 CRS 规则目标中剔除；目标规则本身已不存在，
   移除无行为差异。）
3. **config.conf 追加九章默认禁用段**（`SecAction id:9501098 ... enabled=0`）：
   上游默认启用；本投递默认禁用（理由见下节评估数据）。启用：将该行值改为 1。

## stage5 评估记录（2026-10-02，shop.example.com，PL1，单轮解码默认）

检测效果：

- `?x=c3lzdGVtKCdiYXNoJyk=`（base64 的 `system('bash')`）：禁用 → 404 漏检；
  启用 → **403，CRS 933160 命中**（解码后变体参与评分）。
- `?x=%2527%2520OR%25201%253D%25271`（双重 URL 编码 `' OR 1='1`）：启用 → **403 命中**。
- 正常业务参数（`q=red+apple&sort=price_desc&page=2`）：两态均放行，**零误报**。

性能（同 payload `a=%2574%2565%2573%2574&b=%2543%2541%2554&c=hello`，n=100）：

| 状态 | p50 | p95 | p99 |
|------|-----|-----|-----|
| 禁用 | 9.9ms | 14.1ms | 16.1ms |
| 启用 | 12.5ms | 16.4ms | 18.1ms |

增量约 **+26% p50 / +16% p95**（小 payload、单轮解码、PL1）。上游自述开销随
参数个数与 PL 线性放大（PL1 每参数 1+3 变体；双轮解码或 PL4 达 1+66），
双轮解码（`auto-decoding-config.conf` 内另行开启）本投递未启用、未评估。

## 结论

默认禁用交付，检测增益已实证、PL1 单轮解码开销可量化；建议仅对高风险应用
由运营方按站启用（enable 后先经 OBSERVE 观察再进 PROTECT）。
