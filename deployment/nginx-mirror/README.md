# Nginx TLS 终止后 mirror 接入模板（WDSP Agent mirrorsrc，P1-03 G2）

适用范围：业务前置 Nginx 已终止 TLS，希望把解密后的**请求**（默认仅元数据）镜像给
同机 wdsp-agent 做被动安全观测的场景。本接入是**旁路观测**，不具备任何在线阻断能力；
Agent 不反向代理任何业务请求。

## 采集位置与数据范围

```text
客户端 ──TLS──▶ Nginx（TLS 终止）──▶ 业务源站
                   │
                   └─ mirror 子请求副本 ──Unix Socket/loopback──▶ wdsp-agent mirrorsrc
```

- 采集内容：原请求方法、Host、路径与 query（敏感参数脱敏）、允许的 Header
  （Authorization/Cookie 等按策略脱敏）、可选有限正文（按路径显式开启、有大小上限）。
- **不可见**：业务源站响应、真实业务延迟。记录中 `response/response_ts/latency_ms`
  恒为 null，缺失原因 `SOURCE_REQUEST_ONLY`；镜像接收器返回任何状态码都不影响
  该口径（Nginx mirror 本就忽略子请求响应）。
- 记录字段：`source_type=NGINX_MIRROR`、`source_instance`（固定采集实例标识）、
  `source_epoch`（重启代次）、`tls_visibility=DECRYPTED`（仅当按本模板锁定可信
  终止点拓扑时）、`observed_http_version`（Nginx→适配器子请求协议）。
  原客户端协议不可可靠获取，`original_http_version=null`（不从 Header/UA 推断）。
- 脱敏：与被动 HTTP/1 采集同一策略出口（httpsensor），离主机前完成；
  磁盘缓存只存已脱敏记录。

## 组件与版本锁定

| 组件 | 锁定 |
|---|---|
| Nginx | `nginx:1.28.0-alpine@sha256:30f1c0d78e0ad60901648be663a710bdadf19e4c10ac6782c235200619158284`（容器部署时；裸机部署锁定发行版包版本） |
| wdsp-agent | 随交付版本（mirror 适配器需 Agent ≥ 本能力引入版本；服务端需支持 HTTP 事件 schema v2，未协商时镜像记录丢弃计数、不降级误标） |

## 部署步骤（裸机/同机容器同构）

1. **预建 socket 目录**：`install -d -m 0700 /var/run/wdsp-agent`（属主 root；
   适配器进程以自身身份创建 socket）。
2. **agent.json 启用 mirror 段**（文件 0600；`instance_token` 为随机 ≥32 字节 hex，
   与 Nginx 配置一致，属共享秘密）：

   ```json
   {
     "mirror": {
       "enabled": true,
       "socket_path": "/var/run/wdsp-agent/nginx-mirror.sock",
       "socket_mode": 432,
       "socket_group": "nginx",
       "source_instance": "nginx-prod-1",
       "instance_token": "<随机令牌>",
       "tls_terminated_upstream": true,
       "body_enabled": false,
       "max_body_bytes": 65536,
       "max_conns": 64
     }
   }
   ```

   - `socket_mode` 432 = 0660（八进制）；配合 `socket_group=nginx` 使 Nginx worker
     可写。更严可用 0600 + 同用户运行，按部署身份模型取舍。
   - `tls_terminated_upstream` 是**部署断言**：仅当本接收器按本模板只接同机可信
     TLS 终止点后镜像时置 true（→ DECRYPTED）。不得由外部 Header 决定。
   - 回环 TCP 备选：`"listen_addr": "127.0.0.1:9080"`（与 socket_path 互斥；
     非回环地址一律被拒绝启动）。
3. **Nginx 配置**（见 `nginx.mirror.conf.example`；关键点）：
   - 业务 server 内 `mirror /__wdsp_mirror;`；默认**仅元数据**（不预读正文）。
   - 正文按路径显式开启：`mirror_request_body on` + `client_max_body_size` 限额。
     注意：开启后 Nginx 预读请求正文，会增加上传/流式业务的代理时延与磁盘缓冲
     （实测数据见 test/wdsp-agent-e2e/mirror/runs/ 证据）。
   - mirror location 必须 `internal`，且：
     - `proxy_set_header X-WDSP-Mirror-Instance "<实例令牌>"` —— 覆盖客户端同名
       伪造头（mirror 子请求继承原请求头，必须显式覆盖）；
     - 元数据镜像 location 必须 `proxy_set_header Content-Length "";`，否则接收端
       会按继承的头等待不存在的正文；
     - `proxy_set_header X-Forwarded-For $remote_addr;` —— 覆盖客户端伪造值
       （适配器侧仍不采信外部头做身份/拓扑判定，双保险）。
4. **资源上限**（适配器侧默认）：连接数 64（硬上限 1024）、Header 存储 16KB/消息、
   线上头部块 64KB、正文 64KB（硬上限 10MB，且不超过采集策略 max_body_size）、
   读头 5s/读 60s/写 5s/空闲 30s。超限即拒（503）或截断标记，不影响业务。

## 验证

1. 业务请求经 Nginx（https）正常返回；镜像记录出现在管理端 HTTP 事件列表，
   `source_type=NGINX_MIRROR`、`response=null`。
2. 伪造检查：`curl --unix-socket /var/run/wdsp-agent/nginx-mirror.sock http://x/`
   （不带令牌）应 403；适配器日志/计数 `forbidden` 增加。
3. 故障隔离：停止 wdsp-agent 的 mirror 接收器，业务请求不受影响（Nginx mirror
   忽略子请求失败）。

## 停止采集与回退

1. agent.json 置 `"mirror": {"enabled": false}`（或删除整段）并重启 wdsp-agent；
   socket 文件随停机清理。
2. Nginx 移除各 `mirror` 指令与 `__wdsp_mirror*` internal location，`nginx -s reload`。
   业务面零依赖，回退不影响业务流量。
3. 已入库历史记录保留可读（`source_type=NGINX_MIRROR` 可筛）；无新增。
4. 轮换令牌：同时更新 agent.json `instance_token` 与 Nginx `proxy_set_header`
   后各自 reload；窗口期内镜像被拒（403 计数），业务不受影响。

## 明确不支持（本期边界）

- 不解析 WebSocket 帧、gRPC 正文、HTTP/2 原生帧；原客户端为 HTTP/2 时镜像侧仅见
  Nginx 终止后的 HTTP/1.1 子请求，`original_http_version=null`。
- 无业务响应与真实延迟；不做在线阻断；不以镜像接收器状态冒充业务结果。
