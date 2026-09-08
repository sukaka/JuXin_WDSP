# 九章 WDSP 分布式流量采集 Agent — Phase 2 实施契约（策略版本化与回滚 / 健康评分）

**版本：V1.0（Phase 2 冻结契约，增量于 Phase 1，不修改 Phase 1 契约任何条目）**
**上游设计：docs/agents/WDSP_DISTRIBUTED_AGENT_DESIGN.md（§54 健康评分、§68.13-14 策略版本化与回滚、§23 时间同步、§26-27 策略中心）**
**基线：docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md（§3/§4/§5 继续有效）**

本文件只记录 Phase 2 新增的端点、字段、公式与迁移；与 Phase 1 冲突时以 Phase 1 为准的部分不存在（纯增量）。

## 1. 迁移（000110_traffic_agent_policy_versions）

- 新表 `agent_policy_versions`：`id` / `policy_id`（FK → agent_policies，ON DELETE CASCADE）/ `version` / `config`（jsonb，全量快照）/ `created_by` / `created_at`；`(policy_id, version)` 唯一，索引 `(policy_id, version DESC)`。
- 回填：迁移执行时为既有 `agent_policies` 按**当前版本**补一行快照（`INSERT ... SELECT`，`ON CONFLICT DO NOTHING`）；此前无历史留存，如实只补当前版。
- `agents` 新增列 `last_clock_offset_ms BIGINT NULL`：最近一次心跳的时钟偏移（毫秒，signed，定义见 §2）。

## 2. 时钟偏移记录（机器端行为增量）

- 心跳 `POST /api/v1/agents/{agent_id}/heartbeat`（Phase 1 §3.2）处理时，服务端计算
  `clock_offset_ms = 服务端收包时间 − 请求体 timestamp × 1000`（毫秒，signed；正值表示 Agent 时钟偏慢），写入 `agents.last_clock_offset_ms`。
- `timestamp` 缺失或 ≤ 0 时不覆盖既有记录（保留上次有效偏移）。
- 心跳请求/响应线格式不变（Phase 1 §3.2 冻结）；`/metrics` 端点不含 timestamp，不记录偏移。
- 心跳 metrics 快照新增两个加法字段（omitempty，缺省不出现）：`capture_backend`（当前抓包后端标识）、`backend_fallback_reason`（后端回退原因，无回退缺省）。服务端 `agents.last_metrics` 为 jsonb 透存，无需服务端变更；旧版 wdsp-agent 不上报即缺省，兼容。

## 3. 策略版本化与回滚（管理端点，会话 + RBAC）

快照时机：策略**创建**、每次 **PUT**、每次**回滚**，均在同一事务向 `agent_policy_versions` 写入一行（`created_by` 为操作人用户名）。历史版本不可变。

> **勘误（2026-09，实现口径）**：与 Phase 1 §2 末附注同口径——本节管理端点实际线格式为仓库统一信封 `response.Body{code,message,data,request_id}`，本节所示响应结构（版本列表 `{ "items", "total" }`、回滚后的策略对象）承载于信封 `data` 字段；错误响应同样为信封（`code` 取仓库统一错误码，如 404 → `RESOURCE_NOT_FOUND`、400 → `INVALID_ARGUMENT`），HTTP 状态码语义不变。机器端点保持 Phase 1 §3 裸 JSON 不变。

### GET /api/v1/traffic/policies/{id}/versions（traffic.agents.view）

响应 `200`：`{ "items": [...], "total": n }`，item：

```json
{
  "version": 3,
  "config": { "name": "production-web", "...": "（Phase 1 §3.3 policy JSON 全量快照）" },
  "created_by": "secops",
  "created_at": "RFC3339",
  "current": true
}
```

- `version` 倒序；`current` 标记是否为当前生效版本（`agent_policies.version`）。
- 策略不存在 → 404 `{"error":{"code":"NOT_FOUND","message":"策略不存在"}}`。

### POST /api/v1/traffic/policies/{id}/rollback（traffic.agents.manage）

请求：`{ "version": 1 }`（目标历史版本号，正整数，否则 400）。

语义：以目标历史版本的 `config` 生成**新版本**（`version+1`），同一事务快照新版本、并把绑定该策略的全部 Agent `config_version+1`（驱动重新拉取）。回滚自身也是一次版本演进，历史链不可变；回滚不还原 `name`。

响应 `200`：更新后的策略对象（同 Phase 1 §4 GET 策略详情）。

错误：策略不存在 / 历史版本不存在 → 404；`version` 非法 → 400。

审计：HIGH 级，`module=traffic-agents`，`action=rollback`，`object_type=agent_policy`；
`before = {"from_version": <操作前当前版本>}`，`after = {"to_version": <新版本>, "rolled_back_from": <目标历史版本>}`。

## 4. 健康评分（health_score / health_reasons / clock_offset_ms）

`GET /api/v1/traffic/agents`（列表 item）与 `GET /api/v1/traffic/agents/{agent_id}`（详情）新增字段：

- `health_score`：0-100 整数，**查询时计算，不落库**；summary 端点不变。
- `health_reasons`：扣分原因码数组（恒为数组，满分时为 `[]`；机读码，前端映射展示文案）。
- `clock_offset_ms`：最近一次心跳时钟偏移（毫秒，signed；未上报为 `null`）。

### 评分公式（唯一事实源 = server/internal/agents/health.go，改动必须双向同步）

- 派生状态 `DISABLED` → 固定 **0** 分，`["agent_disabled"]`；
- 派生状态 `OFFLINE` → 固定 **10** 分，`["agent_offline"]`；
- 其余以 100 起扣（可叠加，下限 0；阈值均为严格大于，恰等于阈值不触发该档）：

| 档位 | 条件 | 扣分 | 原因码 |
|------|------|------|--------|
| 自报 ERROR | status=ERROR | −20 | `status_error` |
| 自报 DEGRADED | status=DEGRADED | −10 | `status_degraded` |
| CPU 超限 | cpu_percent > CPU 阈值 | −25 | `cpu_over_limit` |
| CPU 偏高 | cpu_percent > 80% × CPU 阈值 | −10 | `cpu_high` |
| 内存超限 | memory_mb > limits.memory_mb（无绑定策略不评） | −25 | `memory_over_limit` |
| 内存偏高 | memory_mb > 80% × limits.memory_mb | −10 | `memory_high` |
| 丢包率严重 | dropped/(received+1) > 10% | −25 | `drop_rate_critical` |
| 丢包率偏高 | dropped/(received+1) > 1% | −10 | `drop_rate_high` |
| 队列积压严重 | queue_depth > 5000 | −20 | `queue_overflow` |
| 队列积压 | queue_depth > 1000 | −10 | `queue_high` |
| 缓存接近上限 | buffer_bytes > 90% × 缓存上限 | −20 | `buffer_near_full` |
| 缓存偏高 | buffer_bytes > 75% × 缓存上限 | −10 | `buffer_high` |
| 时钟偏移超阈 | \|clock_offset_ms\| > 5000（设计 §23） | −15 | `clock_drift` |
| 时钟偏移偏大 | \|clock_offset_ms\| > 2000 | −5 | `clock_skew` |
| 配置未同步 | applied_config_version ≠ config_version | −15 | `config_not_synced` |

参数口径：

- CPU 阈值 = 绑定策略 `limits.cpu_percent`；无绑定/缺省取 **80**（%）。
- 内存阈值 = 绑定策略 `limits.memory_mb`；无绑定/缺省时**跳过内存档**（无基线不扣）。
- 缓存上限 = 绑定策略 `buffer.max_size_mb`；无绑定/缺省取 **512**（MB，Phase 1 §6 磁盘缓存默认上限）。
- metrics 快照缺省（从未上报）时跳过 CPU/内存/丢包/队列/缓存档；`clock_offset_ms` 为 null 时跳过时钟档。
- 丢包率分母 `received+1` 防除零；`received=0 且 dropped>0` 如实落入严重档。

明确不做（设计 §55 属后续）：告警通知、独立 alerts 表、Agent 版本过期扣分、WDSP RTT 档（Phase 1 无 RTT 数据源）。

## 5. 前端口径（web）

- 列表页新增「健康分」列：Badge 按分档着色（≥80 绿 / 60-79 黄 / 40-59 橙 / <40 红 / 0 灰），Tooltip 展示扣分项（原因码 → 中文文案，映射见 `web/src/pages/traffic-agents/meta.ts`）。
- 详情抽屉：健康分 + 扣分项明细 + 时钟偏移（正=偏慢/负=偏快）。
- 策略面板：「历史」按钮打开版本历史 Modal（倒序、当前版本标记）；非当前版本提供「回滚」操作（Popconfirm 二次确认，`traffic.agents.manage` 权限显隐）。

## 6. 兼容性声明

- 机器端线格式零变更（仅服务端多记一列）；旧版 wdsp-agent 无需升级。
- 管理端列表/详情 item 纯增量字段，旧前端忽略新字段不受影响。
- 权限点复用 Phase 1 的 `traffic.agents.view` / `traffic.agents.manage`，无新增权限种子。

------------------------------------------------------------------------

# Phase 2-B：机器身份证书与 PoP 认证（mTLS 等价，冻结契约 V1.0）

设计依据：上游设计 §14-16（Agent 身份/注册/安全通信，推荐 mTLS、避免 API KEY 长期裸奔）、§42（升级）、§56（审计）。
实现选型说明：仓库已有经审计的同构先例 `server/internal/apm/agentapi_handler.go`（一次性令牌 + CSR + 证书 PoP）。传输层 mTLS（TLS 握手校验客户端证书）依赖部署层 TLS 终止方式，作为部署选项保留；本节冻结的是**应用层证书 PoP**——安全目标等价（私钥不出 Agent、请求级签名防重放、证书可撤销可轮换），且与部署拓扑无关（HTTP/反代/直连均可用）。

## 7. 内部 CA 与证书签发

- 服务端维护独立 "traffic-agent CA"（ECDSA P-256 自签根，与 APM CA 相互独立）；CA 私钥经服务端既有加密服务（encSvc）加密后落系统设置，复用 `apm.LoadOrCreateAgentCA` 的加载/创建模式（新建 agents 包自己的等价实现，不跨包复用 APM 私有类型）。
- 客户端证书：ECDSA P-256，CN = agent_id，TTL 90 天。
- 注册增量（Phase 1 §3.1）：enroll 请求新增可选字段 `csr_pem`（Agent 本地生成 P-256 密钥对 + CSR，CN 留空由服务端填 agent_id）；响应新增 `agent_cert_pem`、`ca_cert_pem`、`cert_expires_at`（RFC3339）。`csr_pem` 缺省时这三个字段为 null，Agent 退化为 Bearer 模式（过渡期兼容，见 §8）。
- credential（`wda_`）照旧签发——Bearer 仍是回退通道。

## 8. 请求级 PoP 认证（机器端点）

已持证书的 Agent 对全部机器端点（heartbeat/metrics/config/ack/flows/packets/rotate-cert）携带三个头：

- `X-WDSP-Agent-Cert`：客户端证书 DER 的 base64（标准编码）。
- `X-WDSP-Agent-Timestamp`：Unix 秒。
- `X-WDSP-Agent-Signature`：base64 签名，内容为 ECDSA/SHA256 对如下串的签名（与 APM 同构）：
  `POP\n<METHOD>\n<PATH>\n<TS>\n<hex(SHA256(body))>`（空 body 的 SHA256 为空串哈希）。

服务端校验（全部失败 → 401，不降级到 Bearer 除非 PoP 头完全缺失）：

1. 证书能链到 traffic-agent CA 且在有效期内；
2. 证书指纹（SHA-256 of DER）存在于该 Agent 的已签发指纹集合且未撤销；
3. 证书 CN == 路径 `{agent_id}`；
4. 时间戳与服务器时差 ≤ 300s；
5. 签名验证通过。

兼容与优先级：PoP 头存在但校验失败 → 401（防降级攻击）；PoP 头完全缺失 → 回退 Bearer 校验（Phase 2 过渡期保留，服务端对 Bearer 认证成功记 metrics/日志以便后续收紧；Phase 3 将提供部署级"仅证书"开关）。

## 9. 证书轮换

`POST /api/v1/agents/{agent_id}/rotate-cert`，请求 `{ "csr_pem": "..." }`：

- 仅接受 PoP 认证（Bearer 不可轮换证书）；
- 签发新证书（新指纹），旧指纹进入 24 小时宽限期（新旧均可认证），宽限后自动撤销；
- 响应 `{ "agent_cert_pem", "ca_cert_pem", "cert_expires_at" }`；
- Agent 职责：证书存活期过半（45 天）后自动轮换；轮换失败按心跳退避重试，旧证书到期前持续可用。

## 10. 数据库（迁移 000111_traffic_agent_certs）

- `agents` 新增列：`agent_cert_fingerprint TEXT NULL`（当前生效指纹，SHA-256 hex）、`agent_cert_not_after TIMESTAMPTZ NULL`。
- 新表 `agent_cert_revocations`：`id` / `agent_id`（FK → agents.agent_id，CASCADE）/ `fingerprint TEXT` / `revoked_at TIMESTAMPTZ` / `not_before TIMESTAMPTZ`（指纹生效起点）/ `grace_until TIMESTAMPTZ NULL`（轮换宽限截止，过期即视为撤销）/ `reason TEXT`；`fingerprint` 建索引。
- 语义：认证通过 ⇔ 指纹 == agents.agent_cert_fingerprint（当前），或存在于 revocations 且 grace_until > now()（宽限中）。

## 11. 审计与管理面增量

- Agent 详情（管理端 GET）新增字段：`cert_fingerprint`、`cert_not_after`（无证书为 null）；列表不变。
- 吊销即禁用：现有 disable/DELETE 同时把当前指纹写入 revocations（grace_until=null，立即撤销）。
- 轮换不记审计（机器自动行为，量大）；enroll 签发证书不新增审计（enroll 本身已有 token 消费记录）。

## 12. Agent 本地行为

- 私钥存 `/var/lib/wdsp-agent/agent.key`（0600，ECDSA P-256 PEM）；证书存 `agent.crt`；CA 存 `ca.crt`（用于校验服务端 TLS——若 server 为 http 则仅用于未来 https 切换，不强制）。
- enroll 子命令自动生成密钥对+CSR；已有 agent.json 无证书的老 Agent，`run` 启动时检测并自动执行一次带内补注册（用 credential 调 rotate-cert 不支持 Bearer——因此老 Agent 补注册走"重新 enroll"？否：老 Agent 无 token。结论：Phase 2 老 Agent 保持 Bearer 模式运行，由管理员在 UI 触发重新注册或等待 Phase 3 迁移工具；文档如实说明此限制）。
- 签名在 transport 层统一注入；时钟偏差导致 401 时按心跳退避重试并 WARN（配合 §2 时钟偏移监控）。
