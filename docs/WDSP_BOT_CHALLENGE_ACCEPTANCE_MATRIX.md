# Bot 挑战强制验收矩阵（BOT-001～024，P1-02 交付基线）

**日期：2026-09-08；2026-09-09 增补：BOT-004/006/018 真实环境补证完成（WORKLOG「S3 增补记录」）。上游：docs/tasks/wdsp-p1/P1-02_BOT_CHALLENGE.md §8；阶段记录：docs/tasks/wdsp-p1/WORKLOG.md S3 各条。**

本表逐项核对任务书 §8 强制验收清单的当前证据状态。状态词表（与 WORKLOG 冻结一致）：
PASS / BLOCKED_ENV / NOT_SUPPORTED（范围外能力如实标注）/ PARTIAL（组件层通过但真实环境证据
缺口已注明）/ NOT_RUN（未执行，不得冒充通过）。每格引用具体测试函数 / run_id / 路径，
第三方可按引用复核。表内「预期」未作为测试结果填回。

**状态计数：PASS 23 / PARTIAL 1 / BLOCKED_ENV 0 / NOT_SUPPORTED 0（FAIL 0）。**
PARTIAL 项：BOT-013（移动网络实测）——缺口见该格与 §3。
（2026-09-09 前为 PASS 20 / PARTIAL 4；BOT-004/006/018 已经 run-browsers.sh 与
flood-bench.sh 真实栈补证翻 PASS，残留缺口在各格内如实注明。）

## 1. 验收清单逐项状态

| ID | 状态 | 证据（测试函数 / run_id / 路径） |
|---|---|---|
| BOT-001 三模式语义 | PASS | OFF 不初始化依赖且请求链零变化：`bot_step_test.go:TestBotStepOffZeroChange`；OBSERVE 只记录不实断：`TestBotStepObserveRecordOnly`；PROTECT 仅合格范围挑战：`TestBotStepProtectChallengeVerifyFlow`、`TestBotStepNoSignalNoChallenge`；装配语义（OFF 保留段供墓碑/OBSERVE 降级 Warn/PROTECT 缺依赖 fail-closed 拒载）：`bot_policy_test.go:TestBotPolicyAssemble` |
| BOT-002 弱声明不独立处置、阈值可复算 | PASS | 客户端声明组（UA/TLS hint）为可伪造弱信号，挑战须 ≥2 独立组且 ≥1 行为组：`bot_step.go:evaluateBotSignals` 与 `TestBotStepNoSignalNoChallenge`（未达阈不挑战）；判定口径可复算：B4 基准 run `20260908T184056-940230`（uri_concentration≥0.5 数学上第 3 次导航首次达阈，实跑精确命中 nav=3，见该 run status.json 与 run.sh 头部口径注释） |
| BOT-003 路径匹配与冲突拒绝发布 | PASS | 选择器词法/前缀边界：`bot_policy_test.go:TestBotPolicySelectors`；保留命名空间与 L7/既有应用路径/路径转发/保护地址冲突预检 FAIL 且 publishable=false：`server/tests/stage_bot_policy_test.go:TestBotPolicyPreflightConflicts`；OFF+RELEASED 不抢占业务路径：`bot_step_test.go:TestBotStepOffZeroChange` |
| BOT-004 真实浏览器挑战链 | **PASS** | 五通道真实栈实证（2026-09-09 补证）：run `20260909T224253-3040ab`（23/23 PASS，`run-browsers.sh`，stage5 真实栈 + 基准应用第二域名 bot-bench.localhost 走系统解析器）——chromium / firefox / webkit / mobile-safari(iPhone 14 视口+UA) / mobile-chrome(Pixel 7 视口+UA) 五通道均：nav_attempts_before_challenge=3 精确达阈、页内 JS 求解 2–107ms、verify 204、clearance 落 Cookie、终态 200 REACHED_ORIGIN（逐通道 channels-summary.json）。原 Chromium 单通道证据保留：B4 browser 组 run `20260908T184056-940230` |
| BOT-005 不适用请求不返回 HTML 挑战 | PASS | HEAD/POST/JSON 真实栈实证：B4 http-script 组 run `20260908T184056-940230`（HEAD 200 非 HTML、POST /login 直达源站 REACHED_ORIGIN、Accept: application/json 直达）；单测 `bot_step_test.go:TestBotStepIneligiblePassThrough`（HEAD/POST/JSON/X-Requested-With）；WebSocket（Upgrade 头）/gRPC（POST+非文档 Accept）按同一合格性判定不适用（组件层，非单独 e2e）；不重放业务写（挑战只在请求时本地生成，无业务重放路径） |
| BOT-006 降级可读与无障碍 | **PASS** | JS 关闭/禁 Cookie：B4 http-script 组实证（不能执行 JS → 挑战即阻断，静态失败页可读，通行率 0 如实报告）；挑战页错误态/重试/JS 不可用文案静态核对：`web/src/pages/applications/__tests__/BotPolicyTab.test.tsx`「挑战页预览」用例；渲染安全（CSP nonce/no-store）：`botchallenge/render_test.go:TestRenderChallengeHeaders`。**慢设备与键盘实测（2026-09-09 补证）**：run `20260909T224253-3040ab` @a11y 组（`specs/challenge-a11y.spec.ts`）——CPU 6× 节流下求解 102ms 完成、挑战页主线程 setTimeout(0) 探针最大 gap 91ms（预算 2000ms，页内探针 sessionStorage 采样留证）；键盘：焦点自动落重试按钮、焦点环可见（outline auto 1px）、Tab/Shift+Tab 循环、Enter 触发重试→verify 204→REACHED_ORIGIN、aria snapshot 落盘。**残留缺口：读屏（屏幕阅读器）实测 NOT_RUN**（无辅助技术环境，建议立项人工审计） |
| BOT-007 篡改与超限严格拒绝 | PASS | 正文 8KiB 上限/坏 JSON/未知字段/非法 challenge_id/超长 solution：`botchallenge/verify_test.go:TestVerifyBodyBounds`；解答词形与难度由服务端状态决定（请求无难度字段）：`pow_test.go:TestPowInputValidation/TestPowSolutionBounds`；错误解答计数与耗尽作废：`verify_test.go:TestVerifyBadSolutionAndExhaustion`；无 panic、无 clearance 签发（伪造提交实证见 B4 http-script 组 verify-forged.headers 无 clearance Set-Cookie） |
| BOT-008 并发原子消费与重放 | PASS | 同 nonce 重放至多一次成功：`verify_test.go:TestVerifyReplay`；两节点（两 Store 实例共享状态）并发消费原子性：`store_test.go:TestStoreConcurrentConsumeTwoNodes`、`service_test.go:TestCrossNodeConcurrentVerify`（语义感知 fake Valkey）；真实 Valkey Lua 原子性由 B3 真实栈集成测试同脚本路径覆盖（`caddy_bot_integration_test.go:TestCaddyBotMiddlewareOrder`，verify 单 Lua 往返）；重放有明确结构化归因（CONSUMED/EXPIRED 事件） |
| BOT-009 过期/伪造/未知 key_id 拒绝归因 | PASS | 过期 nonce：`verify_test.go:TestVerifyExpiredChallenge`；过期 clearance：`service_test.go:TestClearanceLifecycle`；伪造签名/未知 key_id：`verify_test.go`（ forged clearance/cookie 用例）、`token_test.go:TestTokenSignVerify`；密钥仅来自配置密钥环（无路径/网络加载）：`keyring` 装配 `TestKeyringValidation`、`TestKeyRefBinding`；拒绝均带结构化 reason 归因 |
| BOT-010 跨范围不可移植 | PASS | 题目绑定 app/Host（摘要参与哈希）：`pow_test.go:TestPowBinding`；会话绑定（verify 强制 Cookie 摘要一致）：`verify_test.go:TestVerifySessionBinding`；跨应用 clearance 拒绝：`verify_test.go`（跨应用/伪造用例）；状态按应用隔离（键命名空间含 appID）：`store_test.go:TestStoreLifecycleAndKeys`；server 侧跨应用隔离：`stage_bot_policy_test.go:TestBotPolicyCrossAppIsolation` |
| BOT-011 同源与嵌入防护 | PASS | 缺 Origin 拒绝/跨域拒绝/Fetch Metadata 强校验：`verify_test.go:TestVerifyOriginAndFetchMetadata`；会话+nonce+Origin 联合校验链路：`TestOfferVerifyHappyPath`；挑战页 CSP 严格策略（nonce、防嵌入）：`render_test.go:TestRenderChallengeHeaders` 与 B4 http-script 组响应头实证（CSP nonce、Cache-Control no-store） |
| BOT-012 XSS/缓存安全 | PASS | 页面渲染转义（含脚本 URL/错误文本注入）：`render_test.go:TestRenderEscaping`；CSP nonce 每次唯一：`TestRenderCSPNonceUnique`；挑战页与 Cookie 不进共享缓存（no-store + __Host- Secure Cookie）：`TestRenderChallengeHeaders`、B4 组响应头实证；无 open redirect（verify 固定路径，无重定向参数） |
| BOT-013 移动网络/NAT 共存 | **PARTIAL** | 速率三维（会话/IP/应用），不以 IP 直接等同用户：`service.go:allowRate` 与 `verify_test.go:TestVerifyRateLimited`、`service_test.go:TestOfferRateLimited`；clearance 不绑定客户端 IP（IP 变化不影响既有通行，设计契约）。**缺口：真实移动网络 IP 漂移与多人共享 NAT 实测 BLOCKED_ENV（无对应网络环境），不得以单测冒充实测** |
| BOT-014 clearance 不升级身份 | PASS | 真实栈实证：`caddy_bot_integration_test.go:TestCaddyBotMiddlewareOrder` 相位⑤（持 clearance 发 SQLi 仍被真实 CRS 403 且非挑战页、源站计数不增）；B5 演练相位 C（OFF 后 SQLi 仍 403）run `20260908T185148-7b707a`；clearance 只过 Bot 步骤、后续 API/JWT/WAF 链完整：`bot_step.go:serveNextViaBot`（RecordStep 后 serveNext）；不能以挑战通过升级身份（无身份写路径） |
| BOT-015 既有优先级不变、白名单不跳过 | PASS | 人工封禁/黑名单/CC 优先：`bot_step_test.go:TestBotStepPriorDenialsWin`；白名单/保护地址/L7 allow 仍挑战：`TestBotStepAllowlistStillChallenged` + 真实栈热更新加白名单仍挑战（`TestCaddyBotMiddlewareOrder` 相位⑦）；链序文档化：AGENTS.md 请求处理顺序段 |
| BOT-016 命名空间固定本地处理与墓碑 | PASS | verify 错误方法 405/未知子路径 404 均本地：`bot_step_test.go:TestBotStepNamespaceLocal` + 真实栈相位⑥；OFF 墓碑：`TestBotStepTombstone` + B5 演练相位 C（OFF 后 verify POST 404/GET 405/未知 404，旧提交不落源站）run `20260908T185148-7b707a`；B4 http-script 组同口径实证 |
| BOT-017 依赖故障语义 | PASS | Store/限速器故障 PROTECT fail-closed 503：`bot_step_test.go:TestBotStepStoreFailureProtect503`、`service_test.go:TestStateUnavailableFailClosed/TestStoreFailureSemantics/TestAllowRateFailure`；OBSERVE 依赖缺失降级继续（装配期 Warn）：`bot_policy_test.go:TestBotPolicyAssemble`；容量上限不静默签发：`TestOfferCapacityExceeded/TestStoreCapacity`；密钥缺失 PROTECT 拒载：`TestBotPolicyProvisionRejectsInvalid`、preflight `signing_key` FAIL（`stage_bot_policy_test.go:TestBotPolicyPreflightSigningKey`） |
| BOT-018 洪峰与资源受控 | **PASS** | 真实栈洪峰实测（2026-09-09 补证）：run `20260909T231820-d1f76b`（25/25 PASS，`flood-bench.sh`，stage5 真实栈）——洪峰A 签发：c50×200 档 429×39 受控拒绝（签发三维限速生效）、c200×400 档全 200（身份行为窗口演化信号不再达阈，如实记录，非限速失效）；洪峰B 验证洪峰 120 并发三类伪造（合法会话+错误解答 429/409/403 分布与会话维 12/分钟+max_attempts=3 语义自洽、伪造会话 30×403 SESSION_INVALID、未知 challenge_id 429/409）零 204 零 clearance 签发、无 5xx、网关日志无 panic；洪峰C 慢请求：HTTP/1.1 慢速 body 6.02s 有界 400、chunked 滴注 2.04s 有界 400（verifyReadTimeout=2s 对 h1 确定生效），均不签发；影响：洪峰（c200）期间合法 clearance 通行 20/20、选择器外 POST /login 10/10 全 200（p95 0.75s vs 基线 0.018s，如实记录）；资源：全程 2s 周期采样 37 行（resource-samples.tsv），Valkey bot 键数峰值 60（<< 在途上限 10000）、网关 RestartCount=0/OOMKilled=false。组件层证据保留：在途容量有界（`TestOfferCapacityExceeded/TestStoreCapacity`）、三维限速（`TestOfferRateLimited/TestVerifyRateLimited`）、正文 8KiB 上限（`TestVerifyBodyBounds`）、存储 300ms 超时（store.go opTimeout）、会话绑定（`TestVerifySessionBinding`）。**残留口径**：503 容量语义本环境未触发（IP 维限速先行，容量上限由组件层覆盖）；压测在开发机 macOS arm64 Docker Desktop 执行，非专用压测硬件 |
| BOT-019 轮换/代次撤销/部分节点如实 | PASS | 密钥轮换旧通行按代次失效：`service_test.go:TestClearanceRotation`、`token_test.go:TestTokenRotation`；policy_epoch 撤销真实栈实证：`TestCaddyBotMiddlewareOrder` 相位⑧（版本 1→2 旧 clearance 重新挑战）与 B5 演练相位 D（v1→v3 旧双 Cookie 403 不复活）run `20260908T185148-7b707a`；节点未就绪不假报成功：发布任务 FAILED/LOCK_BUSY 如实状态（`stage5-setup.sh:s5_publish` 重试口径 + B4 首轮 BLOCKED 证据 run `20260908T175427-0a85b3` publish-tasks.json）；多节点扇出在无登记次要节点时 node_capability=SKIP 如实（preflight.json） |
| BOT-020 权限/CSRF/并发/审计 | PASS | 无权限读写 403：`stage_bot_policy_test.go:TestBotPolicyPermissions`；CSRF 由 stage 框架统一强制（全部变更请求带 X-CSRF-Token，缺失 403 见 stage 公共断言）；并发修改旧版本 409：`TestBotPolicyLifecycle`（乐观锁 expected_version）；审计不含秘密（摘要引用 key_ref 名称非密钥材料）：`TestBotPolicyLifecycle` 审计断言 + `guardconfig:TestRedactBotSigningKeys` |
| BOT-021 两组自动化分别报告 | PASS | B4 基准 run `20260908T184056-940230`（27/27，三组不混分母）：http-script 组（curl，不能执行 JS → 通行率 0 如实）；automation-js 组（headless Chromium，`navigator.webdriver=true` 如实记录且可通过 PoW——挑战只增加自动化成本，不证明真人）；证据 test/e2e/bot-challenge/runs/20260908T184056-940230/ |
| BOT-022 final_decision 与统计口径 | PASS | CHALLENGE/BOT 枚举增量：`disposition.go` + `disposition_test.go:TestDispositionLifecycle_Terminal`；条件补全 SQL（两处 NOT IN 加 CHALLENGE，挑战与业务成功分开聚合）：`securityevents/store.go`、`apiruntime/events.go` 及对应包测试；web 映射与未知值安全回退：`web/src/pages/security-events/__tests__/EventDetailDrawer.test.tsx`（CHALLENGE/BOT 展示 + FUTURE_ACTION_X 原样回退）；重试关联 flowID（单向脱敏）：`botchallenge:TestFlowID`；stage 终态契约：`server/tests/stage_final_decision_test.go` |
| BOT-023 草稿/失败/部分生效状态可区分 | PASS | 草稿/已发布版本差异与恢复入口：`stage_bot_policy_test.go:TestBotPolicyLifecycle` + `web/src/pages/applications/__tests__/BotPolicyTab.test.tsx`（草稿待发布态/部分节点未生效态/409 冲突/预检逐检查项/只读权限/GET 403 共 11 用例）；发布失败 fail-hard 可读无半发布：B4 首轮 run `20260908T175427-0a85b3`（SNAPSHOT_FAILED 如实留证，修复后复跑 27/27）；XSS 纯文本与未知值回退：同 BotPolicyTab 用例 |
| BOT-024 升级/关闭/回退真实流量 | PASS | B5 演练 run `20260908T185148-7b707a`（23/23，证据 test/e2e/bot-challenge/runs/20260908T185148-7b707a/，脚本 test/e2e/bot-challenge/rollback-drill.sh）：相位 A 工作树正式构建镜像升级栈（build.log/images.txt/health.json）；相位 B PROTECT 基线挑战+完整求解通行；相位 C 发布 OFF（墓碑）后挑战主动行为停止（4 次合格导航全 200 直达）、verify POST 404/GET 405/未知 404、SQLi 仍 CRS 403、历史 BOT 事件 API 可读（BOT_CHALLENGE_OFFERED total=2）；相位 D 回退 PROTECT 挑战恢复、旧 clearance 按 policy_epoch 撤销不复活、新挑战完整通行；三次发布任务状态/节点结果 publish-*.json 留证 |

## 2. 缺口与后续工作（如实登记）

| 项 | 缺口 | 建议 |
|---|---|---|
| BOT-006 | 读屏（屏幕阅读器）实测 NOT_RUN（慢设备/键盘已于 2026-09-09 补证 PASS） | 读屏属人工无障碍审计，建议立项 |
| BOT-013 | 移动网络 IP 漂移/共享 NAT 实测 BLOCKED_ENV | 需可切换出口 IP 的网络环境（如双 WAN/移动热点轮换）；会话维度限速已有组件层证据 |
| BOT-018 | 503 容量语义未在真实栈触发（IP 维限速先行）；压测环境为开发机非专用硬件 | 如需容量语义真实栈证据，建议在专用压测环境调低在途上限复测 |

## 3. 证据归档索引

- 单元/集成测试（网关）：`gateway/modules/jiuzhang_guard`（`go test -race ./...` 17 包全绿，2026-09-08）——botchallenge 39 个测试函数、bot_step 10 用例、bot_policy 10 用例、`caddy_bot_integration_test.go:TestCaddyBotMiddlewareOrder`（真实 Caddy v2.11.4 + coraza-caddy v2.5.0 + 真实 CRS + docker Valkey）。
- stage 测试（server，真实 PG/Valkey 容器）：`server/tests/stage_bot_policy_test.go` 8/8 PASS（迁移/生命周期/权限/跨应用/预检冲突/预检密钥/guard 清单/迁移回滚）。
- web 组件测试：`web/src/pages/applications/__tests__/BotPolicyTab.test.tsx`（11 用例）、`web/src/pages/security-events/__tests__/EventDetailDrawer.test.tsx`（14 用例）。
- B4 浏览器/自动化基准：run `20260908T184056-940230`（27/27 PASS）与首轮 BLOCKED 证据 run `20260908T175427-0a85b3`，目录 test/e2e/bot-challenge/runs/。
- B5 升级/关闭/回退演练：run `20260908T185148-7b707a`（23/23 PASS），脚本 test/e2e/bot-challenge/rollback-drill.sh。
- BOT-004/006 多浏览器+无障碍补证（2026-09-09）：run `20260909T224253-3040ab`（23/23 PASS），脚本 test/e2e/bot-challenge/run-browsers.sh（chromium/firefox/webkit/mobile-safari/mobile-chrome 五通道 @browser 组 + @a11y 慢设备/键盘组，channels-summary.json 逐通道指标）。
- BOT-018 洪峰与资源受控实测（2026-09-09）：run `20260909T231820-d1f76b`（25/25 PASS），脚本 test/e2e/bot-challenge/flood-bench.sh（签发/验证洪峰+慢请求+业务影响+资源采样）。两个补证 run 的栈镜像构建自 HEAD 干净 worktree 的原因见各 run environment.txt 与 WORKLOG S3 增补记录。
- 配置与运维文档：docs/BOT_CHALLENGE_OPERATIONS.md（默认关闭/语义/限制/配置示例/密钥登记/部署配套）。
- 任务书与阶段记录：docs/tasks/wdsp-p1/P1-02_BOT_CHALLENGE.md、docs/tasks/wdsp-p1/WORKLOG.md（S3 各条）。
