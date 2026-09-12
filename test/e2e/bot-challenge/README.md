# P1-02 B4 Bot 挑战浏览器/自动化基准（BOT-004 / BOT-005 / BOT-021）

真实网关基准：stage5 独立编排（postgres/valkey/api/gateway/testorigin）+ 自签 HTTPS
应用 + Bot 策略 PROTECT，三组分别如实报告，不混分母、不用请求重试数扩大通过率。

## 运行

```bash
bash test/e2e/bot-challenge/run.sh
```

依赖：docker（compose 插件）、curl、openssl、python3（含 `cryptography` 包）、
node/npx（Playwright 复用 `web/` 的 `@playwright/test`——run.sh 在本目录建
`node_modules → web/node_modules` 软链供 import 解析，`.gitignore` 已覆盖；
浏览器二进制缺失时 `cd web && npx playwright install chromium`）。

环境不满足时对应组如实输出 `BLOCKED/ENVIRONMENT_UNAVAILABLE`（退出码 3），不伪造通过。

## 三组与验收映射

| 组 | 驱动 | 覆盖 | 如实报告口径 |
|---|---|---|---|
| http-script | curl（不能执行 JS） | BOT-021 普通 HTTP 自动化、BOT-005（HEAD/POST/JSON 不返回 HTML 挑战）、verify 伪造/错误方法/未知子路径 | 挑战即阻断，通行率 0；不适用原因准确 |
| browser | Playwright Chromium（tag `@browser`） | BOT-004：挑战 → 页内 JS 求解 → verify 204 → 最多一次自动刷新 → 源站 REACHED_ORIGIN；clearance Cookie；通行后再次导航直达 | 挑战前导航次数、求解耗时、最终状态逐条记录 |
| automation-js | Playwright headless Chromium（tag `@automation-js`） | BOT-021 能执行 JS 的自动化浏览器 | 如实记录 `navigator.webdriver=true` 且可通过 PoW——挑战只增加自动化成本，不证明真人 |

## 基准策略（run.sh 内固化，判定可复算）

- 选择器：`path_exact=/`（仅 GET 浏览器文档导航）。
- 信号：`uri_concentration ≥ 0.5`（request_behavior）+ `known_uri_ratio ≤ 0.99`
  （access_sequence），`min_independent_groups=2`——Peek 只读快照不含本次请求
  记账（Observe 在请求收束时记账），前两次导航建立观测基线，第三次导航评估时
  双组达阈提出挑战。
- 挑战：`difficulty=12`（基准用值，合法区间 10..18 内，缩短求解时间）、
  nonce TTL 90s、clearance TTL 900s、最多 3 次验证。
- 密钥：每轮随机 HMAC 密钥，经 `JIUZHANG_MASTER_KEY`（同样每轮随机）AES-256-GCM
  加密后由 psql 夹具通道播种 `gateway_runtime:bot_signing_keys`（管理面密钥写入
  入口属 B5 工作）；身份指纹盐同通道播种；两者退出即随临时栈销毁。

## 证据

每次运行写入 `runs/<run_id>/`：`status.json`（PASS/FAIL/BLOCKED 词表与
p0bench 一致）、`preflight.json`、`group-http-script/*`（原始响应与头）、
`group-browser.result.json` / `group-automation-js.result.json`（链路指标）、
`group-*.playwright.json`（Playwright JSON 报告），失败时附 `stack-dump/`。
临时栈、口令与密钥材料随脚本退出清理（compose down -v + mktemp 目录删除）。

## 已知限制

- run.sh 基准的 browser 组固定 Chromium 通道（`--project=chromium`）；Firefox/
  WebKit/移动浏览器维度由 run-browsers.sh 覆盖（见下节），慢设备/键盘维度由
  run-browsers.sh 的 @a11y 组覆盖；读屏（屏幕阅读器）实测仍 NOT_RUN。
- 信号判定依赖 identity_behavior 窗口计数，run.sh 已启用全局行为策略；
  若 B3 网关接入（bot_step）尚未合入，挑战不触发，相关断言如实 FAIL 并注明缺口。

## 当前实测状态（2026-09-08，最终轮 run_id=20260908T184056-940230）

**PASS 27/27，verdict=PASS**（主代理读 status.json 确认）：三组全部链路断言通过，
证据 `runs/20260908T184056-940230/`。此前 run `20260908T175427-0a85b3` 的 BLOCKED
（certificates store.go JOIN 歧义）已由主代理修复（certColumnsC 限定列 +
stage5-gateway-certs 卷 + 两 Dockerfile 预建证书目录），首轮 BLOCKED 证据保留作
发布失败 fail-hard 可读性的正面证据（BOT-023）。

## BOT-024 升级/关闭/回退演练（B5）

```bash
bash test/e2e/bot-challenge/rollback-drill.sh
```

同一 stage5 真实栈夹具，相位化演练（不依赖 Playwright，curl + python3 现场求解
PoW）：A 工作树正式构建镜像升级栈 → B PROTECT 基线挑战与完整通行 → C 发布 OFF
（RESERVED_TOMBSTONE 墓碑）后挑战主动行为停止、墓碑 404/405、SQLi 仍 CRS 403、
历史 BOT 事件 API 可读 → D 回退 PROTECT 挑战恢复、旧 clearance 按 policy_epoch
代次撤销不复活。三次发布的任务状态/节点结果 JSON 全量留证。
最终轮 run `20260908T185148-7b707a`：23/23 PASS（证据 `runs/20260908T185148-7b707a/`）。

## BOT-004/006 多浏览器与无障碍补证（run-browsers.sh）

```bash
bash test/e2e/bot-challenge/run-browsers.sh
```

同一 stage5 真实栈夹具，基准应用额外登记第二域名 `bot-bench.localhost`
（macOS/Linux 系统解析器将 `*.localhost` 解析到 127.0.0.1；Chromium 通道另以
`--host-resolver-rules` 对照）：

- 五通道 @browser 组（BOT-004）：chromium / firefox / webkit /
  mobile-safari（iPhone 14 视口+UA）/ mobile-chrome（Pixel 7 视口+UA），
  逐通道记录 nav 达阈次数、求解耗时、verify/clearance/REACHED_ORIGIN，
  汇总落盘 `channels-summary.json`。
- @a11y 组（BOT-006，chromium 通道）：慢设备（CDP CPU 6× 节流，页内
  setTimeout(0) 主线程探针经 sessionStorage 采样）与键盘导航（自动聚焦重试、
  焦点环可见、Tab/Shift+Tab 循环、Enter 重试→verify 204→源站，aria snapshot 落盘）。

依赖 firefox/webkit 浏览器二进制（`cd web && npx playwright install`）。
最终轮 run `20260909T224253-3040ab`：23/23 PASS（证据
`runs/20260909T224253-3040ab/`）。

## BOT-018 洪峰与资源受控实测（flood-bench.sh）

```bash
bash test/e2e/bot-challenge/flood-bench.sh
```

同一 stage5 真实栈夹具（curl + xargs 并发，不依赖 Playwright）：

- 洪峰A 签发洪峰：c50×200 / c200×400 合格导航，断言三维限速受控拒绝（429）
  或无 5xx、服务存活。
- 洪峰B 验证洪峰 + 假会话制造：120 并发三类伪造（合法会话+错误解答 /
  伪造会话 / 未知 challenge_id），断言零 204、零 clearance 签发、无 5xx、
  网关日志无 panic。
- 洪峰C 慢请求：HTTP/1.1 慢速 body 与 chunked 滴注，断言请求时限有界（≤8s，
  verifyReadTimeout=2s 对 h1 确定生效）且不签发通行。
- 影响对比：洪峰期间合法 clearance 通行与选择器外 POST /login 逐条计时，
  与基线对比落盘 `impact/impact-summary.json`。
- 资源：全程 2s 周期采样 docker stats + Valkey dbsize + bot 键数
  （`resource-samples.tsv`），断言键数峰值 << 在途上限 10000、网关零重启零 OOM。

最终轮 run `20260909T231820-d1f76b`：25/25 PASS（证据
`runs/20260909T231820-d1f76b/`）。
