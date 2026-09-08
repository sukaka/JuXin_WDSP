# Bot 挑战配置与运维手册（WDSP P1-02）

**适用版本：P1-02 交付基线（2026-09-08）。验收证据：docs/WDSP_BOT_CHALLENGE_ACCEPTANCE_MATRIX.md。**

本文面向部署与运营：默认状态、模式语义、已知限制、保留命名空间、配置示例、
签署密钥登记步骤与部署配套要求。设计契约见任务书
docs/tasks/wdsp-p1/P1-02_BOT_CHALLENGE.md；请求链位置见 AGENTS.md「请求处理顺序」。

## 1. 默认状态与模式语义

- **默认 OFF**：`bot_policy` 配置段不下发即 OFF。OFF 不初始化挑战依赖（不构造
  挑战服务、不连接存储、不发事件），请求链零行为变化。
- **OBSERVE**：只记录不实断。评估结果以 Bot 事件（OFFERED 假设会挑战/INELIGIBLE
  等）落事件中心，业务请求一律放行。挑战依赖缺失时降级为仅日志观测（装配期 Warn，
  不影响请求）。
- **PROTECT**：对「显式选择器路径 + HTTPS GET + 浏览器文档导航」且多信号达阈的
  请求签发 JS 挑战（403 挑战页）；verify 通过签发 clearance Cookie 放行。
  **依赖故障 fail-closed**：存储/限速器/密钥缺失时挑战与 verify 返回 503
  （STATE_UNAVAILABLE），不静默签发、不静默放行；配置发布期缺 Valkey 或签名密钥
  直接拒绝加载/拒绝发布（与发布门禁同口径）。
- 挑战成功**只通过 Bot 步骤**：不绕过 JWT 信任链、API 动态防护、请求检查与
  Coraza WAF（BOT-014 实证）；人工封禁/黑名单/L7 拒绝/CC 等既有拒绝优先于 Bot
  （BOT-015）；白名单/保护地址/L7 allow 不跳过 Bot。

## 2. 已知限制（如实登记，不得当作缺陷瞒报）

1. **`method_ratio` 指标恒 UNAVAILABLE**：行为窗口计数无每方法计数源（仅有
   (identity,uri) distinct method 集合），配置该指标不计触发、不计权重。
2. **identity_behavior 未启用时 PROTECT 不挑战**：行为组信号依赖身份行为观测窗口
   计数，未启用/读取失败按 UNKNOWN 处理（不当零风险也不当高风险）。PROTECT 策略
   必须配套启用 `identity_behavior`（见 §5）。
3. **status_family_ratio 为近似**：4xx≈401+403+404+405、5xx≈500 既有计数；
   2xx/3xx 无计数源按 UNAVAILABLE。
4. **规则窗口映射档**：`window_seconds` ≤90→1m、≤450→5m、≤1800→30m、否则→24h
   （对齐行为观测固定窗口，非任意窗口）。
5. **信号评估不含本次请求**：PeekSnapshot 只读快照不含请求收束时的本次记账。
   例：uri_concentration≥0.5 对单 URI 恒等访问，数学上第 3 次导航才首次达阈。
6. **counters.Eval 数字串语义（共享客户端）**：经 Lua 读 HGETALL 数字字段的消费者
   会收到 int64 而非字符串（botchallenge Store 已做两型兼容修复；其他消费者存在
   同类潜在风险，排查见验收矩阵 BOT-017 行）。
7. **挑战只增加自动化成本，不证明真人**：能执行 JS 的自动化浏览器（含
   webdriver=true）可通过 PoW（BOT-021 如实记录）。难度区间 10..18 bit。
8. **移动端/无障碍/洪峰实测缺口**：见验收矩阵 §2（BOT-004/006/013/018 PARTIAL）。

## 3. 保留命名空间

| 路径 | 行为 |
|---|---|
| `/_wdsp/bot/v1/verify` | 固定协议端点：POST 校验（204/4xx/429/503）；非 POST → 405 |
| `/_wdsp/bot/v1/` 其他子路径 | 本地 404 |
| OFF + `RESERVED_TOMBSTONE` | 墓碑：verify POST→404、非 POST→405、未知→404（均本地，旧挑战提交不落入源站） |
| OFF + `RELEASED` | 不抢占业务路径（首次 OFF 且从未启用的应用） |

全部命名空间响应本地生成，**永不反向代理**（BOT-016）。命名空间与 L7 规则/既有
应用路径/路径转发/保护地址冲突时预检 FAIL 拒绝发布。

Cookie：`__Host-wdsp-bot-session` / `__Host-wdsp-bot-clearance`
（Secure/HttpOnly/Path=/，不进共享缓存；挑战页 Cache-Control: no-store）。

## 4. 策略配置示例

管理接口：`PUT /api/v1/applications/{app_id}/bot-policy`（乐观锁
`expected_version`；预检 `POST .../bot-policy/preflight`；发布后随配置下发网关）。

```json
{
  "mode": "PROTECT",
  "expected_version": 0,
  "selectors": [{"path_prefix": "/docs"}],
  "signal_rules": {
    "min_independent_groups": 2,
    "require_behavior_group": true,
    "rules": [
      {"id": "uc", "group": "request_behavior", "metric": "uri_concentration",
       "window_seconds": 300, "weight": 1, "threshold": 0.5},
      {"id": "known", "group": "access_sequence", "metric": "known_uri_ratio",
       "window_seconds": 300, "weight": 1, "threshold": 0.99},
      {"id": "ua", "group": "client_claim", "metric": "ua_class_match",
       "params": {"class": "BOT"}, "window_seconds": 300, "weight": 1}
    ]
  },
  "challenge": {"type": "JS", "nonce_ttl_seconds": 90, "clearance_ttl_seconds": 900,
                "difficulty": 12, "max_attempts": 3, "key_ref": "bot-hmac-2026"},
  "route_reservation": {"state": "ENABLED", "namespace": "/_wdsp/bot/v1/"},
  "reason": "启用文档区 Bot 挑战"
}
```

要点：

- `min_independent_groups` ≥2 且建议 `require_behavior_group=true`——客户端声明组
  （UA/TLS hint）为可伪造弱信号，不允许单独构成挑战依据（BOT-002）。
- `difficulty` 合法区间 10..18（基准用值 12）；`nonce_ttl_seconds`/`clearance_ttl_seconds`
  见 schema 边界校验；`max_attempts` 耗尽作废挑战。
- 从已启用状态关闭：PUT `{"mode":"OFF","route_reservation":{"state":"RESERVED_TOMBSTONE",
  "namespace":"/_wdsp/bot/v1/"},...}`（保留墓碑防旧提交落源站）；首次 OFF 且从未启用
  可用 `RELEASED`。
- 每次 PUT 版本 +1；**版本递增即 policy_epoch 递增，旧 clearance 按代次撤销**
  （BOT-019，回退演练实证）。

## 5. 部署配套要求（PROTECT 缺一不可，发布门禁同口径）

1. **共享 Valkey**：网关 `counter_backend=valkey`（挑战状态/限速/在途计量）且
   `behavior_store=valkey`（行为窗口计数跨节点共享）。单节点亦要求——PROTECT 缺
   Valkey 拒绝加载。
2. **identity_behavior 启用**：`identity_behavior.enabled=true` 并配置身份指纹盐
   （`system_settings` 的 `gateway_runtime:identity_salt`）。未启用时行为组信号
   不可用，PROTECT 永不挑战（限制 §2.2）。
3. **Bot 签名密钥登记**（`key_ref` 必须命中）：
   - 密钥材料：32 字节随机值的 hex（64 字符），按 `{"<key_ref>": "<hex>"}` 组成 JSON；
   - 加密登记：用部署侧 `JIUZHANG_MASTER_KEY` 经 AES-256-GCM 加密后写入
     `system_settings` 的 `gateway_runtime:bot_signing_keys`（string，密文）；
   - 下发：发布通道读取并解密下发网关密钥环（`guardconfig.NewBotSigningKeysLoader`），
     预检 `signing_key` 与发布门禁逐 key_ref 核对就绪，未就绪 PROTECT 拒绝发布；
   - **管理面写入入口现状**：暂无独立 UI/API，经系统设置通道登记（夹具示例见
     test/e2e/bot-challenge/run.sh 的播种段）；轮换 = 新 key_ref 登记 + 策略换
     key_ref 重新发布（旧 key 保留至旧 clearance 全部过期再移除）。
4. **TLS**：挑战仅覆盖 HTTPS 导航（`r.TLS != nil` 合格性要求）；应用须绑定证书
   并启用 HTTPS 域名。

## 6. 事件与排障

- Bot 事件落 access_control_events（六类：CHALLENGE_OFFERED/CLEARANCE_ISSUED/
  VERIFY_REJECTED/CHALLENGE_EXPIRED/CLEARANCE_REJECTED/STATE_UNAVAILABLE），
  PROTECT 终止事件带 final_decision（CHALLENGE/BOT）；挑战与业务成功分开聚合
  （BOT-022）。会话/IP/应用三维限速 429 带 Retry-After；依赖故障 503 带
  STATE_UNAVAILABLE 结构化错误。
- 排障速查：挑战不出现→查 identity_behavior 是否启用与 Valkey 计数；verify 恒
  503→查 bot_signing_keys 密文与 Valkey 连通；旧 clearance 失效→确认是否发布过
  新版本（代次撤销为预期行为）。
