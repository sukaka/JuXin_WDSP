# 九章 WDSP 分布式流量采集 Agent — Phase 4 实施契约（智能采集：定向提升与背压降级）

**版本：V1.0（Phase 4 冻结契约，增量于 Phase 1/2/3，不修改既有契约任何条目）**
**上游设计：docs/agents/WDSP_DISTRIBUTED_AGENT_DESIGN.md（§10 自适应采集策略、§18 背压机制、§52 网络带宽保护、§56 审计、§59 Phase 4）**
**基线：Phase 1/2/3 契约继续有效；L0-L3 采集等级语义以 Phase 3 契约 §2 为准**

## 1. 范围

- 定向采集提升：管理端按 Agent 下发动态采集规则（匹配条件 + 目标等级 + TTL），Agent 对命中流量提升采集等级。
- 背压自动降级链：队列高水位/带宽饱和时 Agent 自动逐级降级（L3→L2→L1→L0→采样），恢复后逐级回升。
- 明确不做：按 Tag 的规则扇出（设计 §28 标签体系后续）、K8s/Gateway 形态、自适应 AI 调参。

## 2. 定向采集规则（capture overrides）

### 2.1 数据模型（迁移 000114_traffic_agent_capture_overrides）

`agent_capture_overrides`：`id uuid pk` / `agent_id`（FK → agents.agent_id，CASCADE）/ `match jsonb`（§2.2）/ `capture_level`（L0|L1|L2|L3）/ `note text` / `created_by` / `created_at` / `expires_at timestamptz`；索引 `(agent_id, expires_at)`。

### 2.2 匹配条件（match JSON，全部可选，多字段 AND）

```json
{ "dst_ip": "10.10.20.30", "dst_port": 8443, "host": "api.example.com", "uri_prefix": "/api/payment" }
```

- `dst_ip`：单个 IP 或 CIDR（v4/v6）；`dst_port`：1-65535；`host`：精确匹配（大小写不敏感）；`uri_prefix`：URI 前缀（≤512 字节，以 `/` 开头）。
- 四字段全空的规则非法（管理端 400）；至少一个字段。
- 方向语义：匹配以"server 端"为准（与 flow 方向归一化一致：命中采集端口的一侧为 dst/server）。

### 2.3 管理端点（统一信封，审计 HIGH，module=traffic-agents，action 含 override）

- `GET /api/v1/traffic/agents/{agent_id}/overrides`（view）→ `{items:[...],total}`，含派生 `active`（未过期）。
- `POST /api/v1/traffic/agents/{agent_id}/overrides`（manage）`{"match": {...}, "capture_level": "L2", "ttl_minutes": 30, "note": "排障"}` → 201。`ttl_minutes` 范围 1-1440（默认 30）。
- `DELETE /api/v1/traffic/agents/{agent_id}/overrides/{override_id}`（manage）→ 204。
- 创建/删除联动 `agents.config_version+1`（驱动 Agent 重拉配置）。
- 过期规则服务端无需主动删除（Agent 按 expires_at 忽略；管理端列表标注 inactive；保留 30 天后由 http sweeper 同周期顺带清理——删除 expires_at 早于 30 天的规则）。

### 2.4 配置下发与 Agent 应用

- `GET /api/v1/agents/{id}/config` 响应新增顶层字段 `overrides`（数组，未过期规则全量；无规则为空数组；字段恒在）。旧 Agent 忽略该字段不受影响。
- Agent 规则求值：
  - 每个 flow 的生效等级 = `max(基础等级, 命中规则等级)`（max 按 L0<L1<L2<L3；规则只升不降——设计 §10 语义为"提升"）。
  - 多条命中取最高等级；过期（now > expires_at）规则即时忽略并惰性清理。
  - `dst_ip/dst_port` 在 flow 首包即可求值；`host/uri_prefix` 在请求行嗅探成功时求值并即时提升该流后续采集（L0 流被提升到 L1/L2 后，从当前请求起按新等级采集——此前已过的 Header/Body 不补）。
  - 规则变化经 config 热更生效，不重启抓包。

## 3. 背压自动降级链（Agent 侧，设计 §18/§52）

### 3.1 触发与阶梯

- 水位指标：内存队列深度（flow+http 事件合计占硬上限 10000 的比例）与限速桶饱和（连续 N 秒无法足额发送）。高水位 70%、危急水位 90%、恢复水位 <50%（持续 30s）。
- 降级阶梯（逐级）：当前生效上限 L3 → L2 → L1 → L0 → 采样（sampling rate=0.1，确定性哈希 flow_id 采样，同流一致）→ 保底（仅心跳，等价既有自我保护停抓）。
- 每水位档触发只降一级（防抖），每 10s 最多降一级；恢复时每 30s 最多升一级。
- 降级是"等级上限帽"：生效等级 = min(策略/规则等级, 降级帽)。降级帽变化不修改策略、不产生 config ACK 失败。
- 状态上报：降级帽 < L3 时心跳 status=DEGRADED，metrics 增加 `backpressure_cap`（当前帽等级字符串）与 `backpressure_events`（累计降级次数，omitempty）；恢复 L3 后 status 回 ONLINE。
- 与既有自我保护（CPU/内存停抓）的关系：自我保护触发直接到保底档；背压链是资源正常但出口拥塞时的平滑降级。

### 3.2 服务端

- 无需新端点：`backpressure_cap`/`backpressure_events` 经 metrics jsonb 透存；健康评分复用既有 DEGRADED 档扣分，不新增公式。
- 管理端详情展示来自 last_metrics 的这两个字段（前端只读展示）。

## 4. 采样（policy.sampling 落地）

- 策略 `sampling: {"enabled": true, "rate": 0.1}` 自本阶段起生效：rate ∈ (0,1]，flow 级确定性采样（SHA-256(flow_id) 前 8 字节映射 [0,1) < rate 则采集），采样外 flow 仅保留 flow_end 计数事件（统计不丢量），HTTP 记录不产生。
- rate=1 等价关闭；rate ≤0 或 >1 管理端 400。
- 背压链的采样档临时覆盖策略采样（退避结束后恢复策略值）。

## 5. 兼容性

- 机器端：config 响应加法字段；旧 Agent 忽略 overrides；新 Agent 对旧服务端（无 overrides 字段）按空数组处理。
- 管理端/DB：纯增量迁移；无破坏性变更。
- 契约冲突点：无（Phase 3 §2 等级语义不变，本阶段只增加"上限帽"与"规则提升"两个调制维度）。
