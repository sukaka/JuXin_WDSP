# ADR：WDSP API Observation Kafka 事件总线

> 状态：Accepted，实施边界随 `docs/tasks/KAFKA_CLOUD_AGENT_DATA_FLOW_EXECUTION_PLAN.md` 第一阶段交付。

## 决策

新增 API Observation 的中心接入采用 Kafka。业务 Agent 只访问 WDSP Receiver；Receiver 完成认证、绑定和契约校验后生产到 `wdsp.api.observations.v1`。API 投影、数据流构建和质量统计使用独立 Consumer Group。

一期不迁移既有 Agent HTTP v1/v2，不改变网关 JSONL 采集，不改变 APM OTLP、trace ID 路由和尾采样主链路。

## 组件锁定

- Apache Kafka `4.1.2`，KRaft，Apache-2.0；开发单 Broker，生产三 Broker，不部署 ZooKeeper。
- 镜像 index digest：`sha256:5cc2a2fd93fa2687b44015eee04fb2c3edd9e526bd64bf8bec5ff1e268772e0e`。
- linux/amd64：`sha256:d50ab7b5df612b3c303f9d8afe8fee59626a5de798addfd626fe1924e3205965`。
- linux/arm64：`sha256:4a07b91bf81b35fcc2aaabf3ab6e72aba68d3bb782bce95baba826270c3648da`。
- Go 客户端仅使用 `github.com/twmb/franz-go v1.21.0`，BSD-3-Clause；该版本声明 Go 1.25.0，与仓库 Go 1.25.6 兼容。更高版本不作为本次隐式升级。

## 投递语义

采用 at-least-once。生产者启用幂等和全副本确认，按 `agent_id` 分区。Receiver 只有在 Kafka 确认后返回 202。消费者完成存储后提交 Offset；PostgreSQL 唯一约束、ClickHouse `event_id` 去重和投影水位共同防止重复计数。永久非法消息进入 `wdsp.api.observations.dlq.v1`。

不宣称 Kafka、PostgreSQL、ClickHouse 跨系统 exactly-once。

## 数据与保留

`wdsp.api.observations.v1` 初始保留 72 小时，DLQ 初始保留 7 天，最终以容量压测为准。Topic 不含原始 Body、凭据或消息原文。Kafka 是短期事件缓冲，不是备份或永久事实源。

## 可用性与安全

生产 Topic 复制因子 3、`min.insync.replicas=2`。Broker 仅位于中心私网，启用 TLS 和 SASL 或 mTLS，生产者/消费者使用独立最小权限身份。Kafka 故障时 Receiver 返回可重试错误，Agent 有界缓存；不得静默绕过 Kafka 写数据库，不得影响业务请求。

## 后果

- 增加 Broker 运维、容量、TLS/ACL 和 Lag 监控成本。
- API 资产和数据流投影变为异步，页面需要展示数据新鲜度。
- 可通过独立消费者扩展资产、风险、数据流和质量分析，并在故障后重放。
- 既有 WAF/APM/Agent 主链路保持兼容，降低首期迁移风险。
