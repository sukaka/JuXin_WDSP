# jiuzhang_guard 模块设计（阶段5）

## 定位

`jiuzhang_guard` 是九章自主开发的 Caddy HTTP 处理器模块（模块 ID `http.handlers.jiuzhang_guard`），
负责真实客户端IP识别、可信代理判断、保护地址、IP黑白名单、CIDR匹配、CC计数限速、
临时封禁、自定义429/403响应与访问控制事件输出。代码独立（`gateway/modules/jiuzhang_guard`，
独立 go.mod），不复制任何商业 WAF 代码，仅引入 Apache-2.0/BSD 依赖（caddy v2、valkey-go v1.0.76）。

## 构建

```bash
docker build -t jiuzhang-gateway:stage5 gateway/
# Dockerfile 内：xcaddy build v2.11.4 \
#   --with github.com/corazawaf/coraza-caddy/v2@v2.5.0 \
#   --with github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard=/src/modules/jiuzhang_guard
```

兼容版本：Caddy v2.11.x（当前锁定 v2.11.4），Go 1.25。

## 请求处理顺序

```text
headers（生成 Request ID）
  ↓
jiuzhang_guard
  ├─ 提取连接源 IP（RemoteAddr）
  ├─ 连接源是否可信代理？（可信才解析代理头，否则完全忽略）
  ├─ 解析真实客户端 IP（XFF / X-Real-IP / Forwarded / 自定义头）
  ├─ 伪造检测（带代理头但连接源不可信 → TRUSTED_PROXY_INVALID 事件）
  ├─ 改写 RemoteAddr / X-Real-Ip（下游 WAF/日志/代理统一使用真实IP）
  ├─ 保护地址检查（命中直接放行，永不封禁，仍过 WAF）
  ├─ 全局白 → 应用白 → 全局黑 → 应用黑（首层命中定动作）
  ├─ 临时封禁查询（内存缓存，命中 403）
  └─ CC 限速（按优先级逐策略；LOG/OBSERVE 只记录，REJECT 429，TEMP_BLOCK 429+封禁）
  ↓
coraza_waf → reverse_proxy
```

白名单默认绕过黑名单和 CC，不绕过协议校验与 WAF。

## 目录结构

```text
gateway/modules/jiuzhang_guard/
├── module.go          # Guard 模块（配置/Provision/ServeHTTP/429响应/事件发射）
├── cidr/              # IP/CIDR 解析、规范化（v4映射v6归一）、匹配器（精确map+CIDR扫描）
├── clientip/          # 真实IP解析（四种头、链遍历、超长链、非法回退）
├── trustedproxy/      # 可信代理集合（优先级匹配、头类型校验）
├── accesscontrol/     # 黑白名单分层评估（时间窗生效）
├── ratelimit/         # 令牌桶/滑动窗口（内存+Valkey Lua 两后端）
├── counters/          # 有界 LRU 内存 Map、Valkey 客户端、键哈希
├── temporaryblock/    # 临时封禁 Valkey 存储 + 网关内存缓存轮询
├── events/            # JSONL 事件输出（字段截断、控制字符剥离）
└── go.mod             # 独立模块（caddy v2.11.4、valkey-go v1.0.76）
```

## 配置 JSON（由管理后端配置生成器按应用路由注入）

```json
{
  "handler": "jiuzhang_guard",
  "app_id": "uuid", "app_code": "shop",
  "trusted_proxies": [{"name":"lb","cidr":"10.0.0.0/8","header_type":"X_FORWARDED_FOR","priority":10}],
  "max_proxy_chain": 16,
  "protected_addresses": ["127.0.0.1"],
  "global_allow": [{"id":"r1","address":"192.0.2.1","priority":10}],
  "global_deny":  [{"id":"r2","address":"203.0.113.0/24","priority":10,"effective_until":"2026-08-01T00:00:00Z"}],
  "app_allow": [], "app_deny": [],
  "rate_limits": [{"id":"p1","dimension":"CLIENT_IP","algorithm":"TOKEN_BUCKET",
    "uri_match_type":"PREFIX","uri_pattern":"/api/","requests_limit":100,"window_seconds":60,
    "burst_capacity":20,"action":"REJECT","priority":10}],
  "counter_backend": "valkey",
  "max_counter_keys": 100000,
  "valkey": {"address":"valkey:6379","password":"***","db":0},
  "fail_open": true,
  "events_log": "/var/log/caddy/guard-events.log",
  "gateway_node": "gateway-stage5-01"
}
```

规则/策略携带 `effective_from/effective_until`（RFC3339），网关按当前时间评估，
临时规则到期无需重新发布即停止执行。

## 运行时架构

- **共享引擎（进程级单例）**：Valkey 连接、限速器、临时封禁缓存（1s 轮询）、
  引擎错误告警节流（每策略每分钟最多 1 条 RATE_LIMIT_ENGINE_ERROR 事件）。
  配置重载（发布）不重置计数与封禁缓存。
- **临时封禁协议**：Valkey HASH `jiuzhang:guard:tempblocks`，
  field = `sha256(长度前缀(ip)+长度前缀(appID))` 前 32 hex（与服务器 `temporaryblocks.BlockFieldKey` 一致），
  value = JSON（含 expires_at）。网关自动封禁写 Valkey + 本地缓存；
  管理平台解封/延期写 DB + Valkey，网关 1s 内轮询生效；到期本地判定失效。
- **事件输出**：JSONL 文件（默认 `/var/log/caddy/guard-events.log`），
  由管理后端采集器断点续传入库（`access_control_events`）。

## 429 响应

`HTTP 429` + `Retry-After` + `X-Jiuzhang-Request-ID`；Accept 含 `application/json` 返回 JSON，
否则静态 HTML。不返回内部阈值、当前计数、算法、节点信息；不反射任何用户输入
（Request ID 为服务端生成 UUID，仍做 HTML 转义）。

## 单元测试

9 个包全部覆盖：直接访问/伪造XFF/单级/多级/混合链/IPv6/映射归一/非法IP/超长链/
重复头/自定义头/分层优先级/临时到期/令牌桶/滑动窗口/突发/键隔离/故障传播/
封禁存取/过期/轮询同步/事件脱敏/429无内部信息/白名单绕过CC/保护地址/故障 Fail-open·closed。

```bash
cd gateway/modules/jiuzhang_guard && go test -race ./...
```
