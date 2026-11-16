# WDSP Kafka 事件总线部署

## 边界

Kafka 只承载已经脱敏的 API Observation 和 DLQ，不承载完整 Body、Token、Cookie 或业务 Kafka 消息原文。业务 Agent 不直接访问 Broker。PostgreSQL 和 ClickHouse 才是事实存储，Kafka 保留期不能当备份。

## 开发/集成测试

单 Broker 仅用于开发和 CI，不具备高可用：

```bash
docker compose -f deployment/kafka/docker-compose.kafka.yml up -d --wait
docker compose -f deployment/kafka/docker-compose.kafka.yml ps
```

Broker 仅映射 `127.0.0.1:9092`，容器内地址为 `kafka:29092`。Topic 由 `topic-init` 创建，禁止自动创建业务 Topic。

## 生产三节点

1. 在 `deployment/kafka/pki/` 准备私有 CA 签发的 Broker/Client PKCS12 密钥库和信任库，目录只放部署秘密，不提交 Git。
2. 通过秘密管理设施注入所有 `KAFKA_*PASSWORD`；生产启用 mTLS 和 StandardAuthorizer，按证书 Principal 配置最小 ACL。
3. 将三个 Broker 分配到不同故障域，确认持久卷与磁盘告警。
4. 启动：

```bash
docker compose -f deployment/kafka/docker-compose.kafka-ha.yml up -d
```

生产 Compose 网络为 `internal: true`，不向宿主机或公网映射端口。Receiver 和消费者必须接入该私网。

## Topic

- `wdsp.api.observations.v1`：初始 72 小时保留。
- `wdsp.api.observations.dlq.v1`：初始 7 天保留。

生产复制因子为 3，`min.insync.replicas=2`。分区数须根据目标消费者并行度和实测单分区吞吐确定，不能把示例中的 12 当作容量承诺。

## 故障与恢复

- 单 Broker 故障：观察 ISR 和 Under-replicated Partitions；只有 ISR 满足 `min.insync.replicas` 才允许生产。
- Consumer 故障：事件保留在 Kafka，监控 Lag 和最老消息年龄；恢复后从已提交 Offset 继续。
- 永久非法消息：进入 DLQ，修复后经权限和审计重放，禁止直接删除来掩盖问题。
- Broker 数据卷损坏：按 Kafka 运维流程恢复副本。Kafka 不是备份，不能替代 PostgreSQL/ClickHouse 备份。

## 升级

镜像 tag、index digest 和 amd64/arm64 子摘要均已锁定。升级前重新检查许可证、KRaft 兼容性、客户端协议、Topic 配置和双架构摘要，并执行生产/消费、故障和回放回归。
