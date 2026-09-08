# 九章 WDSP 分布式流量采集 Agent — Phase 3 实施契约（HTTP Sensor）

**版本：V1.0（Phase 3 冻结契约，增量于 Phase 1/2，不修改既有契约任何条目）**
**上游设计：docs/agents/WDSP_DISTRIBUTED_AGENT_DESIGN.md（§9.2 HTTP_STREAM、§10 采集等级、§30 API 联动、§33 数据脱敏、§34 Body 限制、§35 文件上传、§57 隐私、§59 Phase 3）**
**基线：Phase 1 契约（机器端点线格式/认证）、Phase 2 契约（PoP、策略版本）继续有效**

## 1. 范围

- Agent：TCP 双向流重组 + HTTP/1.1 完整解析（请求+响应）、Request/Response 关联（状态码、时延）、L0/L1/L2 采集等级、Body 硬上限、Header/参数脱敏（离主机前）。
- Server：Full HTTP 事件入库、管理端查看、API 资产联动（source=AGENT）。
- Web：HTTP 事件查看、策略脱敏与采集等级配置。
- 明确不做：HTTP/2、gRPC、WebSocket 帧解析（设计 §36-38 后续）、multipart 文件本体上传（§35 只取元数据）、L3 RAW Session（已有 RAW 包通道等价物）。

## 2. 采集等级语义（冻结，替换 Phase 1 §3.3 中"L2/L3 按 L1 处理"的过渡口径）

- `L0`：仅 flow 元数据事件（request 事件仅含请求行三元组，无 Header/Body）——Phase 1 行为。
- `L1`：L0 + 请求/响应 Header（脱敏后），无 Body。
- `L2`：L1 + Body（受 §4 上限与内容类型约束）。
- `L3`：L2 + RAW 包通道（等价 output.mode=FLOW_RAW）。Agent 收到 L3 视为 L2 + 开启 RAW，不再降级为 L1。

## 3. HTTP 事件上报（机器端点）

`POST /api/v1/agents/{agent_id}/http`，认证同 Phase 1/2（Bearer 或 PoP）。Content-Type: application/json。

```json
{
  "records": [
    {
      "flow_id": "<同 Phase 1 §3.4>",
      "request_ts": 1788256800.123,
      "response_ts": 1788256800.156,
      "latency_ms": 33,
      "src_ip": "10.1.1.10", "src_port": 51234,
      "dst_ip": "10.1.2.20", "dst_port": 8080,
      "direction": "ingress",
      "tls_visibility": "PLAINTEXT",
      "request": {
        "method": "POST", "scheme": "http", "host": "api.example.com", "uri": "/api/login",
        "headers": { "content-type": "application/json", "authorization": "********" },
        "body": "{\"user\":\"alice\",\"password\":\"********\"}",
        "body_truncated": false, "original_body_size": 42, "body_skipped_reason": ""
      },
      "response": {
        "status": 200,
        "headers": { "content-type": "application/json", "set-cookie": "********" },
        "body": "{\"token\":\"********\"}",
        "body_truncated": false, "original_body_size": 31, "body_skipped_reason": ""
      }
    }
  ]
}
```

- 每批 ≤ 100 条 且序列化后 ≤ 8MB，超限 Agent 分批；响应 `202 {"accepted": n}`，入库失败整体 500（Agent 落本地缓存补传）。
- `response` 可为 null（响应未捕获/超时）；`response_ts`/`latency_ms` 同步为 null。
- 一对请求/响应只上报一次（关联完成后）；长连接多对请求各自成记录。
- `request_ts/response_ts` 为 Unix 秒浮点（毫秒精度）。
- 仅 `tls_visibility=PLAINTEXT` 可含 headers/body；密文流不产生 HTTP 记录（仍走 flow 事件通道）。
- 同一 flow 的 `event_type=request` 旧事件与 http 记录可同时存在（前者是早期轻量信号）；capture_level ≥ L1 的流 Agent 可停发旧 request 事件避免重复（服务端对两种来源都接受）。

## 4. Body 采集约束（硬红线）

- 单方向 Body 上限 = 策略 `limits.max_body_size`（默认 262144=256KB，硬上限 10485760=10MB，策略超硬上限按 10MB 截）。
- 超限：`body` 截断到上限、`body_truncated=true`、`original_body_size` 记录原始长度（Content-Length 或实际重组长度）。
- 内容类型白名单才采集 Body：`application/json`、`application/x-www-form-urlencoded`、`text/*`、`application/xml`、`application/javascript`、`application/graphql`；其余（含 multipart/form-data、二进制）不采集，`body_skipped_reason="content_type"`，`original_body_size` 照记。
- multipart/form-data（§35）：不采集本体；Agent 尽力解析头部边界提取 `filename`/`content-type`/各 part 大小与表单字段名值（字段值同样过脱敏），放入 `body` 的 JSON 摘要（如 `{"multipart":{"fields":{...},"files":[{"filename":"a.png","content_type":"image/png","size":1024}]}}`），解析失败则 body_skipped_reason="content_type"。
- 压缩响应（Content-Encoding: gzip/br/deflate）：Agent 尝试解压 gzip/deflate 后按白名单处理（br 不解压直接 skipped）；解压失败 `body_skipped_reason="encoding"`。

## 5. 脱敏（离主机前，Agent 侧强制执行）

策略新增 `masking` 段（缺省 = 下列默认值）：

```json
"masking": {
  "headers": { "mode": "MASK", "names": ["authorization","cookie","set-cookie","x-api-key","proxy-authorization"] },
  "params":  { "mode": "MASK", "names": ["password","passwd","pwd","token","access_token","refresh_token","secret","api_key","apikey"] }
}
```

- `mode`：`NONE`（不脱敏）| `MASK`（值替换为 `********`）| `HASH`（值替换为 `sha256:<hex 前16位>`）| `DROP`（Header 整行删除/参数删除）。
- headers 匹配大小写不敏感；params 匹配 query string、form 字段、JSON Body 一级字段（大小写不敏感）；嵌套 JSON 不递归（Phase 3 限制，文档注明）。
- 脱敏在 Agent 内完成，服务端收到的即为脱敏后数据；服务端/前端不再二次脱敏但按既有日志纪律不落敏感值。
- 策略校验：mode 非法或 names 非数组 → 管理端 PUT 400。

## 6. 服务端存储与 API 联动

迁移 `000112_traffic_agent_http_events`：

- 新表 `agent_http_events`：`id bigserial` / `agent_id` / `flow_id` / `ts`（request_ts）/ `latency_ms int null` / 五元组与 direction / `tls_visibility` / `method` / `scheme` / `host` / `uri` / `status int null` / `request_headers jsonb` / `response_headers jsonb` / `request_body text null` / `response_body text null` / `req_truncated bool` / `resp_truncated bool` / `req_original_size bigint` / `resp_original_size bigint` / `created_at`；索引 `(agent_id, ts DESC)`、`(host, uri)`。
- 增量（2026-09，迁移 `000113_traffic_agent_http_skipped_reason`）：补 `req_skipped_reason` / `resp_skipped_reason`（TEXT NOT NULL DEFAULT ''）——§3 上报结构本含 `body_skipped_reason`，000112 表结构遗漏，自 000113 起持久化（取值与 Agent 侧一致：`''`/`content_type`/`encoding`；存量行回填 ''）。
- 保留清理：服务端 sweeper 每日删除 `created_at` 早于 7 天的记录（硬上限防无限增长，设计 §68.9； retention 常量写进代码注释）。

API 资产联动（设计 §30）：

- http 记录入库时，按（host, method, uri 模板化）upsert API 资产，标记 `source=AGENT`（或现有 source 枚举的等价值）+ agent_id；URI 模板化规则跟随 apiassets 模块既有惯例（先读该模块再实现），无惯例则用简单数字/UUID 段归一化。
- 若 apiassets 已有从流量事件建资产的现成入口，复用之；没有则在 agents 包内实现最小 upsert 并声明。
- 联动失败不得阻断 http 事件入库（记录 Warn）。

管理端点（信封口径同 Phase 2 勘误）：

- `GET /api/v1/traffic/agents/{agent_id}/http-events?page=&page_size=&host=&method=`（view）→ 分页 `{items,total}`，ts 倒序。
- `GET /api/v1/traffic/agents/{agent_id}/http-events/{id}`（view）→ 单条全量（含 headers/body）。
- 勘误（2026-09，实现口径）：两个端点的响应记录结构同 §3 嵌套记录（顶层追加 `id`、`agent_id`；`request_ts`/`response_ts` 为 Unix 秒浮点毫秒精度，`response_ts` 由 `request_ts + latency_ms` 派生；`response` 未捕获时 `"response": null` 且 `response_ts`/`latency_ms` 为 null）。列表项保持轻量：`request`/`response` 的 `headers` 置空对象、`body` 置空串，`body_truncated`/`original_body_size`/`body_skipped_reason` 标志位如实保留（`body_skipped_reason` 自迁移 000113 起持久化，输出真实值）；详情给全量。

## 7. 策略 schema 增量（管理端校验 + Agent 应用）

- `capture_level`：接受 `L0|L1|L2|L3`（§2 语义）。
- 新增 `masking` 段（§5，可整体缺省）。
- 既有策略无 masking 段 → 服务端校验视为缺省值；config 拉取响应中服务端**不补齐**缺省段（Agent 本地默认即可，避免版本噪音）。

## 8. Agent 行为增量

- TCP 重组：client→server 与 server→client 双向；HTTP/1.1 keep-alive 多对请求按序关联（不支持 pipelining 乱序——按到达顺序配对，文档注明）；解析失败/协议违例的流回退为 flow 元数据事件，不报错。
- 流完成判定：响应完整接收（Content-Length/ chunked 结束）或连接关闭或空闲超时；长 Body 达上限即截断但继续跟踪至响应结束。
- 资源红线延续：重组流表沿用 flow 上限；Body 缓冲计入内存保护；大 Body 流不阻塞其他流。
- L1/L2 的 HTTP 记录与 flow_end 独立；http 记录经同一限速/缓存/补传管道（限速桶满时优先级：flow 事件 > http 记录 > RAW）。

## 9. 前端口径

- Agent 详情新增「HTTP 事件」Tab：分页表（时间、method/host/uri、status、latency、truncated 标记），行展开/抽屉看 headers 与 body（截断与 skipped 标记明示）。
- 策略编辑：采集等级 L0-L3 选择、masking 段表单（mode + names 列表，headers/params 两组）。
- 文案遵循既有中文风格；脱敏值原样展示（已是脱敏结果，界面不标"明文"）。

## 10. 兼容性

- 机器端纯加法端点；旧 Agent 不发 http 记录，服务端空转；旧服务端无此端点时新 Agent 收到 404 → 降级为 L0 行为并 WARN（不进入缓存补传死循环）。
- 管理端/DB 迁移增量，无破坏性变更。
