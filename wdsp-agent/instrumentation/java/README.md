# WDSP Java API Observation Agent

## 边界

- Java 17+；首个正式框架为 Spring 6 / Spring MVC 与 `RestTemplate`。
- 通过 `-javaagent` 做进程内采集，不需要透明代理、流量镜像或中心 Kafka 地址。
- 请求/响应 Body 仅以有界副本进入本机 Unix Socket；中心、日志和普通异常中不输出原文。
- 本机 `wdsp-agent` 负责 JSON 字段提取、敏感识别、HMAC、PoP、批量发送和磁盘补传。
- 探针失败只丢弃遥测，不改变业务状态码、响应字节或业务异常。

## 构建

```bash
wdsp-agent/instrumentation/java/build.sh
```

构建使用锁定 Maven 镜像，产物为 `target/wdsp-api-agent-1.0.0.jar`。

## 业务侧启动

```bash
java \
  -javaagent:/opt/wdsp/wdsp-api-agent-1.0.0.jar \
  -Dwdsp.api.socket=/run/wdsp-agent/api.sock \
  -Dwdsp.service.name=order-service \
  -Dwdsp.service.instance=order-service-01 \
  -Dwdsp.service.environment=prod \
  -Dwdsp.application.binding.id=<管理面签发的绑定ID> \
  -Dwdsp.application.binding.version=1 \
  -jar app.jar
```

环境变量与系统属性等价：`WDSP_API_SOCKET`、`WDSP_SERVICE_NAME`、`WDSP_SERVICE_INSTANCE`、`WDSP_SERVICE_ENVIRONMENT`、`WDSP_APPLICATION_BINDING_ID`、`WDSP_APPLICATION_BINDING_VERSION`。

`wdsp-agent` 本地配置：

```json
{
  "api_observation": {
    "enabled": true,
    "socket_path": "/run/wdsp-agent/api.sock",
    "socket_mode": 384,
    "hmac_key_id": "key-1",
    "hmac_key_env": "WDSP_API_OBSERVATION_HMAC_KEY"
  }
}
```

`384` 是八进制 `0600`。HMAC 密钥通过 `WDSP_API_OBSERVATION_HMAC_KEY` 注入本地 Agent，不写入仓库或普通日志。未配置密钥时仍输出字段类型，但不输出值级传播指纹。

## 采集限制

- 每方向默认最多 256 KiB，可经 `wdsp.api.max.body.bytes` / `WDSP_API_MAX_BODY_BYTES` 调整，硬上限 1 MiB。
- 本地批量最多 100 条、HTTP 请求最多 4 MiB、连接数最多 64、远程字段最多 256 个。
- 当前只解析 JSON 族 Body；其他内容类型只保留 API 元数据和质量状态。
- 仅 Spring MVC Server 与 RestTemplate Client 被插桩；自研 HTTP 客户端需要补充专门 instrumentation，不能宣称自动覆盖。
- Trace ID/Span ID 从当前 OpenTelemetry Context 获取；无 OTel 时为空，不伪造父子关系。
- SERVER 分别输出 `peer_address=request.getRemoteAddr()`、`client_address=request.getRemoteAddr()`、`client_address_source=DIRECT_PEER` 与 `server_address=request.getLocalAddr()`。真实候选客户端、直接对端和服务端本地地址分开保存；当前 Java 默认只提供 `DIRECT_PEER` 证据。
- `DIRECT_PEER` 只证明 Servlet 连接的直接对端。代理或 NAT 后，`peer_address/client_address` 可能是中间设备地址，不能据此声称识别终端真实用户；证据不足时下游边界必须保持 `UNKNOWN`。
- 不读取或信任 `Forwarded`、`X-Forwarded-For` 等转发 Header，不从 Header 或服务名推断公网/内网。`TRUSTED_PROXY`、`GATEWAY` 只能由经过配置和验证的信任链产生，当前 Java 插桩不会生成这两种来源。
- 性能采样与 API 安全采集独立，互不复用采样率。
- Spring 6 的 `RestTemplate` 仅对实际执行请求的五参数 `doExecute` 插桩，避免旧四参数委托方法被重复采集。
- 插桩失败保持业务请求不变，失败计数只输出异常类别，首条及每 100 条记录一次；不记录 Body 或字段值。

## 真实验收

需要 Docker、Go、Java 17+、Node.js 24、Python 3 和 `openssl`。首次执行浏览器验收前安装项目锁定 Playwright 对应的 Chromium：

```bash
(cd web && npx playwright install chromium)
```

```bash
# Java 单元测试、真实 Spring MVC/RestTemplate、Unix Socket、脱敏边界
wdsp-agent/instrumentation/java/build.sh
test/cloud-agent-e2e/run.sh

# 独立临时 PostgreSQL/Valkey/Kafka/ClickHouse + 真实 API + Chromium 主流程
test/cloud-agent-e2e/run-full-stack.sh
```

完整验收脚本使用随机临时口令和端口，结束后清理自己创建的容器和网络；成功时清理浏览器产物，失败时仅保留临时截图与 Trace 供排障。不需要停止既有开发环境。第二个脚本验证管理面查询与页面；进程内原始 Body 的脱敏边界由第一个脚本直接验证，两者不以配置或静态数据代替真实链路。
