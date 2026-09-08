# P1-04 R2 终验报告：全量语料真实回放 + 前后版本逐例对比 + 性能关联

日期：2026-09-08。范围：任务书 `docs/tasks/wdsp-p1/P1-04_RULE_MODEL_REGRESSION.md` 的 R2 阶段。

## 概要

- 24 条固定语料（18 WAF + 6 Bot）× 双处置档（OBSERVE/PROTECT）= 48 例，在 stage5
  隔离栈上真实回放，**基线 48/48 PASS（退出码 0）**。
- 规则变更对比：禁用自定义规则 7100001（webshell_uploads）并重发布后跑候选轮，
  **候选 47/48**，唯一变化被 compare 如实捕获：WAF-ATK-WEBSHELL-001 OBSERVE 档
  检出归属由 custom_pack/webshell_uploads 丢失（转为 coraza_crs 命中），compare
  结论 FAIL（rc=1），与预测完全一致。
- 基线与候选的请求数、状态码分布、逐 profile 分布、源站到达数完全一致；
  性能分布差异在噪声范围内（见"性能关联"）。

## run_id 清单

| 角色 | run_id | 结果 |
|------|--------|------|
| 基线（全绿） | `20260908T222305-798cfb` | 48/48 PASS，rc=0，证据 10 件齐 |
| 候选（禁用 7100001） | `20260908T222701-b7f86d` | 47/48（WEBSHELL-001 OBSERVE FAIL），rc=1 |
| 前后对比 | `compare-20260908T222932-46b792` | 总判定 FAIL：新增失败 1、丢失检测 1 |

中间轮（崩溃/中间态，保留为诚实痕迹，不作结论依据）：
`20260908T174347-f23b04`（S1 工具层 BLOCKED）、`195428-488b03`（run.sh bash
全角字符粘连崩溃，已修复）、`195548-3cbffc`（apigeo panic 致管理 API 不可达，
证据被污染）、`201119-d66aa3`（事件关联键未修复）、`203034-c88b80` 与
`221719-085b50`（语料/判定口径对齐过程中的 33/15 与 45/3）。

## 回放环境

- 栈：`test/regression/p1/stage5/stack-up.sh` 一键搭建（compose stage5 + wdsp +
  test-license，随机口令、现场签发 license、psql 播种 identity_salt 与
  bot_signing_keys）。描述符 `/tmp/p1reg-env.json`（0600），run-plan 经
  `environment.stage5_env_descriptor` 引用。
- 双应用：`p1reg-observe.local`（OBSERVE=DetectionOnly）与
  `p1reg-protect.local`（PROTECT），均 HTTPS 443 自签证书；回放客户端按
  SNI=站点名、拨号 127.0.0.1、自签不验证。
- 自定义规则 5 条（ID 7100001–7100005，family 入描述符 custom_rule_families）：
  webshell_uploads / cloud_abuse / ssti_injection / xxe_lfi /
  attack_variants_evasion，均 BLOCK phase 2。
- Bot 策略：双 profile 各一份（selector path_exact=/，uri_concentration≥0.5 +
  known_uri_ratio≤0.99 min2 信号组，JS 挑战 difficulty 12，route_reservation
  ENABLED）；OBSERVE 应用 mode=OBSERVE。
- GeoIP：apigeo Sweeper 在 mmdb 缺失时 nil panic 崩 API（产品缺陷，未修），
  stack-up 已 docker cp 注入 `runtime/geoip/country.mmdb` 并重启 api 规避。
- 回放器特性：每用例独立 Cookie jar；Bot PoW 求解（与 Go
  `botchallenge/pow.go` 同构，三档难度向量对拍一致）；UA 携带
  `p1reg/<run_id>/<case_id>` 实现跨 run/跨例身份状态隔离（替代 FLUSH）。

## 执行与判定口径

- 判定请求 = 该用例最后一个 perf 记录（Bot 重试 `-rty` 优先）的
  **响应头 `X-Jiuzhang-Request-ID`**；安全事件按 request_id List 后 Get detail
  取 matches + final_decision。
- 规则归属：7000000–7199999 → custom_pack（family 查描述符）；其余 →
  coraza_crs，族映射 920-921=protocol、930=path、931=rfi、932=rce、933=php、
  934=application_attack、941=xss、942=sqli、944=java_attack；949/959/980/
  9000100–9000199 为评估/二次评估规则，不参与族归属。多族同命中时按
  matched_families 集合成员制判定（实证 930120+932160 会同命中）。
- OBSERVE 档 Bot `BOT_CHALLENGE_OFFERED(action=OBSERVE)` 是假设性流程记录，
  **不算检出**；仅 action=CHALLENGE 计挑战动作。
- 墓碑检测（Bot OFF 后 verify 404/405 + 无源站标记）为响应派生，不做事件轮询。
- UNKNOWN/deferred 用例不进分母（48 例中 6 例 UNKNOWN 被 compare 列为
  TRUTH_UNKNOWN_EXCLUDED，强制分母 42）。

## 语料变化清单（相对 S1 首版）

老例升 case_version=2（truth_reason 附实证注记）：

- SSTI / SSRF / WEBSHELL：PROTECT 档期望改 coraza_crs（族 934=application_attack、
  931=rfi；CRS 949110 相位中断抢占同相位自定义规则，见"产品发现"3）；
  OBSERVE 档保持 custom_pack。
- PATH / PROTO：双 profile rule_family 置空——phase-1 聚合评分阻断（9000102），
  逐族证据不可得。
- BEN-FORM：bio 字段全角标点（原 ASCII 引号+括号触发 942100 libinjection 真误报）；
  callback 改相对路径 `/done?s=1`（绝对 URL 触发 contrib 1001227）。
- XXE：truth 改 UNKNOWN，双 profile 期望 none/PASS/reached，作行为绊线不进分母
  （Coraza 无 XML 体处理器，见"产品发现"4）。

新例保持 case_version=1：BOT-BEN-NAV-001 OBSERVE 期望回退 none/PASS；
BOT-UNK-SCRIPT-001 OBSERVE 期望改 none/PASS（OBSERVE 档 offer 不算检出）。

manifest 最终 sha256=`feaadc81c3ddae79eba4eec192315f612b48856cbbbbc81615c714e5512a025b`，
两处 run-plan 示例已同步；201 单测全绿。

## 逐例计数与对比结论

基线：executed=48/48，PASS=48，incomplete=0，HTTP 请求 74 个。
候选：executed=48/48，PASS=47、FAIL=1（WAF-ATK-WEBSHELL-001 OBSERVE：
expected custom_pack/webshell_uploads，实际 custom_pack 检出丢失、仅
coraza_crs 命中），incomplete=0。

compare（`compare-20260908T222932-46b792`）：可配对有效样本 42（正常 18、
攻击 24），前后一致且通过 41，新增失败 1（2.38%），丢失检测 1（4.17%），
新增误报 0、动作变化 0、源站变化 0，总判定 FAIL——**正是回归要捕获的信号**：
禁用一条自定义规则后，对应 OBSERVE 档检出归属丢失被逐例配对精确定位。
（PROTECT 档不受影响：该例在 PROTECT 本就被 CRS 934200/949110 抢占阻断。）

## 性能关联

perf.jsonl 逐请求聚合（两轮各 74 请求）：

| 指标 | 基线 | 候选 |
|------|------|------|
| p50 (ms) | 11.31 | 11.25 |
| p95 (ms) | 16.46 | 18.12 |
| p99 (ms) | 25.63 | 30.19 |
| max (ms) | 49.68 | 46.62 |
| mean (ms) | 12.02 | 12.20 |
| 状态码分布 | 200×52 / 403×16 / 204×2 / 405×2 / 404×2 | 相同 |
| origin_reached | 52 | 52 |

结论：禁用一条 phase-2 自定义规则对延迟分布在噪声范围内（p95 差 ~1.7ms，
单容器隔离栈、样本 74，不作统计显著性主张）；处置面无任何状态码/源站到达
变化——该规则在 OBSERVE 档本就只观测，PROTECT 档被 CRS 抢占，与预期一致。

## 篡改验证（任务书 §141「生成报告后修改任一必需文件必须导致摘要校验失败」）

在证据目录的 /tmp 副本上实验：

1. **内容篡改**：改 cases.jsonl 一行 PASS→FAIL 后 `write-report` **静默接受**
   ——manifest 无逐文件 files_sha256，内容完整性按任务书 §145 由离线签名服务
   （Ed25519 + 版本化 manifest）承担，该服务不属于 R2 范围。如实披露：当前
   本地工具层对"同路径同结构的内容改写"无检出能力。
2. **文件删除**：删除 cases.jsonl 后完整性检查**捕获**——报告标 ❌、总体
   NOT_PASSED，并附带检出 manifest.run_id 与目录名不一致。

## 产品发现（全部真实栈实证；本次未改产品代码）

1. **事件关联键**：配置生成器（`server/.../headers.go:272` 生成的网关配置）用
   set 把 X-Request-Id 覆盖为 `{http.request.uuid}`，客户端注入的关联键进不了
   事件管道；唯一可信关联 = 响应头 `X-Jiuzhang-Request-ID`。
2. **`escapeSecLangArg` 转义 bug**（`server/internal/customrules/customrules.go:203`）：
   `\` → `\\` 且 Coraza 不解回，含 `\s/\w/\{/\.` 的反斜杠正则全部不命中。
   stack-up 的 5 条规则已改用无反斜杠写法（`[[:space:]]`、`[.]`、`[{]`）规避；
   建议产品侧立项修复。
3. **CRS 949110 相位中断抢占**：PROTECT 档 CRS 达阈后 949110 deny，同相位后续
   自定义规则不执行（实证 SSTI `{{7*7}}`：934200 命中而 7100003 缺席）；
   OBSERVE（DetectionOnly）无中断，自定义规则正常命中。规则编排/文档需明确
   此语义。
4. **Coraza v3.7 无 XML 体处理器**：原始 `application/xml` XXE 双 profile 无检出
   直达源站（已知缺口）；语料中该例转 UNKNOWN 行为绊线，若未来启用 XML 解析
   会立即翻红提示。
5. **apigeo Sweeper nil panic**：mmdb 缺失时每周期 panic 崩 API
   （mmdb.go:146 ← sweep.go:160 ← main.go:306），建议产品侧加 nil  guard 与
   就绪门控。
6. **CRS 族归属修正**：949/959/980/9000100-199 为评估规则，不应计入检出族；
   931=rfi、933=php、934=application_attack、944=java_attack（旧映射有误已修）。
7. OBSERVE Bot offer 事件（BOT_CHALLENGE_OFFERED/action=OBSERVE）语义为流程
   记录而非 finding，对账层已按此口径区分。

## 限制与未覆盖项

- JWT 信任链、Agent、APM 类用例语料仍缺（manifest description 已标注待补充）。
- 墓碑检测为响应派生，无事件对账；OBSERVE offer 同理不入检出分母。
- UNKNOWN 用例（6 例）不进分母；XXE 已转 UNKNOWN。
- 报告内容级防篡改依赖 §145 签名服务（未交付，不属 R2）；本地工具层只能
  检出文件缺失/结构异常，不能检出同结构内容改写。
- 单轮 74 请求的性能数据只作关联参考，不构成性能门禁结论。
- 规则变更对比后已将 7100001 重新启用并重发布（发布任务 SUCCESS，探针实证
  7100001 恢复命中），栈不停留在禁用态。
