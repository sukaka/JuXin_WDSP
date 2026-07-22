# 访问控制事件设计（阶段5）

## 事件类型

`IP_ALLOW_MATCH`、`IP_DENY_MATCH`、`CC_THRESHOLD_EXCEEDED`、`CC_REQUEST_REJECTED`、
`CC_TEMP_BLOCK_CREATED`、`CC_TEMP_BLOCK_EXPIRED`、`CC_TEMP_BLOCK_RELEASED`、
`TRUSTED_PROXY_INVALID`、`FORWARDED_HEADER_INVALID`、`FORWARDED_CHAIN_TOO_LONG`、`RATE_LIMIT_ENGINE_ERROR`。

## 字段

`id, request_id, occurred_at, application_id, application_code, client_ip, connection_ip,
domain, request_method, request_path, event_type, action, policy_id, access_rule_id,
current_count, limit_value, window_seconds, block_expires_at, response_status, gateway_node_id,
message, created_at`

## 统一事件中心

访问控制/CC 事件接入阶段4建立的统一事件体系（同一菜单组「事件中心」、同一权限模型、
同一采集-入库-查询-导出链路），事件来源区分 WAF（`security_events`）与
ACCESS_CONTROL/CC_PROTECTION/SYSTEM（`access_control_events`），不建立割裂的第二套中心。

## 产生与采集

```text
jiuzhang_guard（网关）
  │  JSONL 追加（字段截断 path≤512/domain≤255/message≤512，控制字符剥离，单行）
  ▼
/var/log/caddy/guard-events.log（共享日志卷，API 只读挂载）
  ▼
accesscontrolevents.Collector（2s 轮询，断点续传）
  ├─ 完整行解析 + INET 规范化（netip）+ 批量入库（access_control_events，按月分区）
  ├─ checkpoint：可写数据目录（guard-events.checkpoint，tmp+rename 原子写）
  ├─ 轮转检测：inode 变化或文件变短 → offset 归零
  ├─ 坏行 → .errors 错误文件（不静默丢弃）
  ├─ CC_TEMP_BLOCK_CREATED → temporary_blocks 幂等 upsert（CC_AUTO）
  ├─ access_rule_id 命中 → ip_access_rules.hit_count/last_hit_at
  └─ 按策略聚合 → rate_limit_runtime_summaries
```

**已知教训**：checkpoint 必须放可写目录；曾误放只读日志卷导致每 2s 全量重放（已修复并验证增量稳定）。

## 到期与解封

- 网关本地判定封禁到期即失效（Valkey JSON 内 expires_at）；
- 管理平台 `MarkExpired` 批量标记 EXPIRED（release_type=AUTO_EXPIRE）；
- 人工解封/延期/转永久写 DB + Valkey，网关 1s 轮询生效；
- CC_TEMP_BLOCK_EXPIRED / CC_TEMP_BLOCK_RELEASED 由管理平台侧状态变更与审计体现。

## 接口

`GET /api/v1/access-control-events`（多条件筛选）、`/{id}`、`/export`
（CSV，防公式注入；导出走独立 10000 上限路径，不受分页大小截断）。

## Request ID 关联

事件 `request_id` 与 Caddy 访问日志、WAF 安全事件、阻断页一致（同一 UUID 全链路）。
