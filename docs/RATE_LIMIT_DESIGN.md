# CC防护（限速）设计（阶段5）

## 模型

| 字段 | 说明 |
|------|------|
| scope_type | GLOBAL / APPLICATION / URI（URI 级必须选应用） |
| dimension | CLIENT_IP / APPLICATION / CLIENT_IP_AND_URI / CLIENT_IP_AND_APPLICATION |
| algorithm | TOKEN_BUCKET / SLIDING_WINDOW |
| uri_match_type | ALL / EXACT / PREFIX / REGEX（REGEX 限长 256，Go RE2 线性时间天然防 ReDoS） |
| requests_limit / window_seconds / burst_capacity | 正整数校验（禁负数、零窗口；burst=0 取 limit） |
| action | LOG / OBSERVE / REJECT / TEMP_BLOCK（TEMP_BLOCK 必须 block_duration_seconds ∈ [60, 30天]） |
| observe_only | 观察模式（超限只记录不阻断） |
| priority / effective_from / effective_until | 评估顺序与生效时间窗 |

## 算法

**令牌桶（实时限速推荐）**：容量 = burst（缺省 limit），速率 = limit/window 匀速补充；
允许短突发，单请求一次判定。

**滑动窗口（封禁判断推荐）**：
- Valkey 后端：ZSET 存请求时间戳，Lua 原子完成「清窗外 → 计数 → 准入 → PEXPIRE」，精确窗口；
- 内存后端：双固定窗口加权近似（`curr + prev×(1-elapsed/window)`，标准 sliding window counter）。

**维度键**：`{policy_id}:{sha256(维度)}`。
CLIENT_IP_AND_URI 使用**策略的 URI 模式**而非具体路径（策略即 URI 分组；
若用具体路径，攻击者随机化路径即可绕过并造成键爆炸——已在设计层面消除随机URI键攻击）。
键一律哈希，禁止拼接完整 URI 与未处理用户输入。

## 复杂度与时间精度

- 匹配：URI 匹配 O(策略数)（前缀/精确为字符串比较，RE2 线性）；计数单次 O(1)；
- Valkey 路径：单请求 1 次 Lua 原子往返（本地 <1ms）；
- 时间精度：毫秒（单节点进程时钟）。

## 计数器设计

**Valkey（默认）**：多进程共享、临时封禁、限流窗口、管理平台可见；键带 TTL（窗口2倍+60s）自动过期。

**内存（可配 `counter_backend=memory`）**：并发安全 LRU Map，
最大键数（默认 100000，超限淘汰最久未用），防随机 IP 无限建键；暴露键数量指标。

## 故障策略

- **Fail-open（默认，`GUARD_FAIL_OPEN=true`）**：Valkey 故障时放行 + `RATE_LIMIT_ENGINE_ERROR` 告警事件（每策略每分钟≤1条）；
- **Fail-closed（高安全应用可选，`GUARD_FAIL_OPEN=false`）**：Valkey 故障时按 429 拒绝 + 同样告警；
- 策略经配置发布下发到每个 guard 实例（`fail_open` 字段），发布即可切换，无需重启网关；
- 任何故障不得静默关闭防护（告警事件入访问控制事件中心）。

## 动作语义

| 动作 | 行为 |
|------|------|
| LOG / OBSERVE | 超限生成 `CC_THRESHOLD_EXCEEDED` 事件，不阻断 |
| REJECT | `HTTP 429` + `Retry-After` + `X-Jiuzhang-Request-ID`，生成 `CC_REQUEST_REJECTED` |
| TEMP_BLOCK | 触发请求 429；创建临时封禁（`CC_TEMP_BLOCK_CREATED`），封禁期内请求 403；到期自动解除；支持人工提前解封（解封后 CC 窗口仍在，再次超限会重新封禁，属预期防护行为） |

429 响应不返回内部阈值/计数/算法/节点；API 应用返回 JSON，浏览器返回静态 HTML，不反射用户输入。

## 自动封禁安全约束

封禁前检查：白名单命中跳过 CC（白名单按设计绕过 CC）；保护地址直接放行永不可封；
临时封禁仅临时（不得自动永久）；共享 NAT 风险由人工在事件处置与转永久时确认。

## 管理端模拟测试

`POST /api/v1/rate-limit-policies/{id}/test`：纯 Go 干跑模拟（与网关同语义的令牌桶/滑动窗口实现），
对 N 个模拟请求返回 allowed/rejected/first_reject_at/retry_after/dimension_note，不真实打流。
